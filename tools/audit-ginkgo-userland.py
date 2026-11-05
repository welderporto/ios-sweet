#!/usr/bin/env python3
"""Read-only macOS audit of pinned iOS userland; emit metadata, never binaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import zipfile

BUILD = '20H392'
IPSW_SHA1 = '5606c298c1d908f8a48f617f0ceaf71f2a9f0193'


def digest(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def audit_file(path, label, isa):
    data = path.read_bytes()
    arch = 'arm64'
    if data.startswith(b'dyld_v'):
        arch = data[:16].rstrip(b'\0').decode().split()[-1]
        ranges = isa.shared_cache_exec_ranges(data)
    else:
        if data[:4] == b'\xcf\xfa\xed\xfe' and struct.unpack_from('<I', data, 8)[0] & 0xffffff == 2:
            arch = 'arm64e'
        ranges = (entry for offset in isa.thin_slices(data)
                  for entry in isa.macho_exec_ranges(data, offset))
    counts, samples, words = {}, {}, 0
    for name, address, blob in ranges:
        words += isa.scan(blob, counts, samples, address, name)
    return {'file': label, 'sha256': hashlib.sha256(data).hexdigest(),
            'bytes': len(data), 'architecture': arch, 'instructionWords': words,
            'candidateCounts': counts, 'samples': samples,
            'assessment': 'requires-review' if counts or arch != 'arm64' else
                          ('no-detected-extension' if words else 'no-executable-mapping')}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('ipsw', type=Path)
    ap.add_argument('work', type=Path)
    ap.add_argument('report', type=Path)
    args = ap.parse_args()
    assert digest(args.ipsw, 'sha1') == IPSW_SHA1, 'Unexpected IPSW SHA-1'
    args.work.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('isa', Path(__file__).with_name('check-isa.py'))
    isa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isa)
    report = {'build': BUILD, 'ipswSha1': IPSW_SHA1, 'images': [], 'files': [],
              'limitations': ['Linear scan candidates can be embedded data or optional CPU paths.',
                              'No hits is not proof of physical runtime compatibility.',
                              'arm64e cannot execute natively on this ARMv8.0 device.']}
    with zipfile.ZipFile(args.ipsw) as archive:
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        assert manifest['ProductBuildVersion'] == BUILD
        identity = next(i for i in manifest['BuildIdentities']
                        if i['Info']['DeviceClass'] == 'd22ap')
        for role in ('OS', 'Cryptex1,SystemOS'):
            member = identity['Manifest'][role]['Info']['Path']
            target = args.work / Path(member).name
            # zipfile verifies the ZIP CRC while extracting. No untrusted path extraction.
            with archive.open(member) as source, target.open('wb') as dest:
                while chunk := source.read(8 << 20):
                    dest.write(chunk)
            record = {'role': role, 'member': member, 'sha256': digest(target)}
            report['images'].append(record)
            mount = args.work / ('os' if role == 'OS' else 'systemos')
            mount.mkdir(exist_ok=True)
            print(f'Mounting {role} read-only', flush=True)
            attached = False
            try:
                subprocess.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-owners', 'off',
                                '-mountpoint', str(mount), str(target)], check=True)
                attached = True
                paths = ([mount / 'sbin/launchd', mount / 'usr/lib/dyld'] if role == 'OS' else
                         sorted((mount / 'System/Library/Caches/com.apple.dyld').glob('dyld_shared_cache_arm64*')))
                assert paths, f'No audit inputs in {role}'
                for path in paths:
                    assert path.is_file(), f'Missing required file: {path}'
                    # .symbols is metadata, not executable code.
                    if path.name.endswith('.symbols'):
                        continue
                    label = role + '/' + path.relative_to(mount).as_posix()
                    print(f'Scanning {label}', flush=True)
                    record = audit_file(path, label, isa)
                    report['files'].append(record)
                    print(json.dumps(record), flush=True)
            finally:
                if attached:
                    subprocess.run(['hdiutil', 'detach', str(mount)], check=True)
    assert all(f['instructionWords'] > 0 for f in report['files'][:2]), 'Missing startup code'
    assert any(f['architecture'] == 'arm64' and f['instructionWords'] > 0 and
               f['file'].startswith('Cryptex1,SystemOS/') for f in report['files']), 'Missing arm64 cache code'
    report['assessment'] = ('requires-review' if any(f['candidateCounts'] or f['architecture'] != 'arm64'
                                                   for f in report['files']) else 'no-detected-extension')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
