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
_code_spec = importlib.util.spec_from_file_location('userland_code', Path(__file__).with_name('userland-code.py'))
code = importlib.util.module_from_spec(_code_spec)
_code_spec.loader.exec_module(code)


def digest(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def audit_file(path, label, isa, scanner=None):
    data = path.read_bytes()
    arch = 'arm64'
    if data.startswith(b'dyld_v'):
        arch = data[:16].rstrip(b'\0').decode().split()[-1]
        ranges = isa.shared_cache_exec_ranges(data)
    else:
        if data[:4] == b'\xcf\xfa\xed\xfe' and struct.unpack_from('<I', data, 8)[0] & 0xffffff == 2:
            arch = 'arm64e'
        ranges = ((name, address, data[base + offset:base + offset + size])
                  for base in isa.thin_slices(data)
                  for name, address, size, offset in code.sections(data[base:]))
    counts, samples, words = {}, {}, 0
    for name, address, blob in ranges:
        words += (scanner or code.Scanner(isa)).scan(blob, counts, samples, address, name)
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
    ap.add_argument('--native', type=Path)
    ap.add_argument('--review', action='store_true')
    args = ap.parse_args()
    assert digest(args.ipsw, 'sha1') == IPSW_SHA1, 'Unexpected IPSW SHA-1'
    args.work.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('isa', Path(__file__).with_name('check-isa.py'))
    isa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isa)
    scanner = code.Scanner(isa, args.native)
    reviewer = review_module = None
    if args.review:
        review_spec = importlib.util.spec_from_file_location('review', Path(__file__).with_name('review-userland-code.py'))
        review_module = importlib.util.module_from_spec(review_spec)
        review_spec.loader.exec_module(review_module)
        reviewer = review_module.make_reviewer(code, isa)
    report = {'build': BUILD, 'ipswSha1': IPSW_SHA1, 'images': [], 'files': [],
              'limitations': ['Linear scan candidates can be embedded data or optional CPU paths.',
                              'No hits is not proof of physical runtime compatibility.',
                              'arm64e cannot execute natively on this ARMv8.0 device.']}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    def checkpoint(stage):
        report['stage'] = stage
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(stage, flush=True)
    checkpoint('IPSW digest verified; extracting selected images')
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
            checkpoint(f'{role}: extracted with ZIP CRC verification')
            mount = args.work / ('os' if role == 'OS' else 'systemos')
            mount.mkdir(exist_ok=True)
            print(f'Mounting {role} read-only', flush=True)
            attached = False
            try:
                subprocess.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-owners', 'off',
                                '-mountpoint', str(mount), str(target)], check=True, timeout=180)
                attached = True
                paths = ([mount / 'sbin/launchd', mount / 'usr/lib/dyld'] if role == 'OS' else
                         sorted((mount / 'System/Library/Caches/com.apple.dyld').glob('dyld_shared_cache_arm64*')))
                assert paths, f'No audit inputs in {role}'
                if role == 'Cryptex1,SystemOS':
                    paths = [p for p in paths if not p.name.endswith('.symbols')]
                    sources, records = code.cache_audit(paths, scanner, reviewer)
                    report['cacheSources'] = sources
                    for record in records:
                        record['file'] = role + '/' + record['file'].lstrip('/')
                    report['files'].extend(records)
                    checkpoint(f'Cache: {len(records)} library instruction sections scanned')
                    paths = []
                for path in paths:
                    assert path.is_file(), f'Missing required file: {path}'
                    # .symbols is metadata, not executable code.
                    if path.name.endswith('.symbols'):
                        continue
                    label = role + '/' + path.relative_to(mount).as_posix()
                    print(f'Scanning {label}', flush=True)
                    record = audit_file(path, label, isa, scanner)
                    if review_module:
                        data = path.read_bytes()
                        record['knownTables'] = []
                        for base in isa.thin_slices(data):
                            for _, address, size, offset in code.sections(data[base:]):
                                record['knownTables'].extend(review_module.known_tables(data[base + offset:base + offset + size], address))
                    report['files'].append(record)
                    checkpoint(f'{label}: scanned')
                    print(json.dumps(record), flush=True)
            finally:
                if attached:
                    subprocess.run(['hdiutil', 'detach', str(mount)], check=True, timeout=60)
    assert all(f['instructionWords'] > 0 for f in report['files'][:2]), 'Missing startup code'
    assert any(f['architecture'] == 'arm64' and f['instructionWords'] > 0 and
               f['file'].startswith('Cryptex1,SystemOS/') for f in report['files']), 'Missing arm64 cache code'
    if args.review:
        reviewed = [f for f in report['files'] if 'review' in f]
        assert len(reviewed) == 4, 'Missing core-library review'
        assert sum(len(f['review']['selectedAPIs']) for f in reviewed) > 0, 'No exported APIs resolved'
    report['assessment'] = ('requires-review' if any(f['candidateCounts'] or f['architecture'] != 'arm64'
                                                   for f in report['files']) else 'no-detected-extension')
    checkpoint('complete')


if __name__ == '__main__':
    main()
