#!/usr/bin/env python3
"""macOS-only research HFSX root for QEMU. Accepts a new directory, never a device.

Apple components remain private and are fetched from the pinned Apple IPSW.
Sources mount read-only; only the newly created research image is modified.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import zipfile

URL = 'https://updates.cdn-apple.com/2025FallFCS/fullrestores/122-77006/1158E502-D76D-4226-AA06-ED5E30CD1111/iPhone10,3,iPhone10,6_16.7.16_20H392_Restore.ipsw'
IMAGES = [
    ('OS', '087-86698-044.dmg', '80f426d5b8fca8552f95be427434f1911dbb4c2c6d28aad94f2426ddd0c92483'),
    ('SystemOS', '087-86593-047.dmg', '9cd738f3b0169055549df84ad6d8d13e50a2da39af618ce0522ca4e06df86849'),
    ('AppOS', '087-86715-047.dmg', '391f2df322c3172b021b2874f6da5c3e78b70b3df8f502e1a4af2b1d715c4608')]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RemoteZip(io.RawIOBase):
    def __init__(self, fetch):
        super().__init__()
        self.fetch, self.length, self.position = fetch, fetch.size_of(URL), 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset
        if not 0 <= position <= self.length:
            raise ValueError('Remote ZIP seek outside source')
        self.position = position
        return position

    def read(self, size=-1):
        size = self.length - self.position if size < 0 else min(size, self.length - self.position)
        if size > 64 << 20:
            raise ValueError('Unexpected large remote ZIP read')
        if not size:
            return b''
        data = self.fetch.get(URL, self.position, self.position + size - 1, tries=3)
        self.position += len(data)
        return data


def safe(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Path escapes research volume: {relative}')
    return path


def create_image(path, size='16g'):
    # Blank size-based images use hdiutil's default writable UDIF format.
    # -format is restricted to source-folder/device creation on this macOS.
    subprocess.run(['hdiutil', 'create', '-size', size, '-layout', 'NONE', '-nospotlight',
                    '-fs', 'HFSX', '-volname', 'GinkgoResearch', str(path)], check=True, timeout=180)


def strip_udrw(path):
    """Accept an exact raw HFSX volume or strip a verified zero-offset UDIF fork."""
    with path.open('r+b') as image:
        length_on_disk = image.seek(0, 2)
        image.seek(-512, 2)
        trailer = image.read(512)
        image.seek(1024)
        header = image.read(512)
        assert header[:2] == b'HX', 'Expected raw case-sensitive HFSX volume'
        block, count = struct.unpack_from('>2I', header, 40)
        assert 512 <= block <= 1 << 20 and block & (block - 1) == 0
        size = block * count
        if trailer[:4] == b'koly':
            offset, length = struct.unpack_from('>2Q', trailer, 24)
            assert offset == 0, 'Data fork is not a raw prefix'
            assert 2048 < size <= length, 'Volume exceeds uncompressed data fork'
        else:
            assert size == length_on_disk and size > 2048, 'Not an exact flat HFSX image'
        image.truncate(size)
    return size


def image_device(attachment, registry, path):
    entries = attachment['system-entities']
    assert not any(e.get('mount-point') for e in entries), 'Filesystem unexpectedly mounted'
    devices = [e['dev-entry'] for e in entries if re.fullmatch(r'/dev/disk[0-9]+', e.get('dev-entry', ''))]
    assert len(devices) == 1, 'Expected one unpartitioned image device'
    device = devices[0]
    assert any(Path(image.get('image-path', '')).resolve() == path.resolve()
               and any(e.get('dev-entry') == device for e in image.get('system-entities', []))
               for image in registry.get('images', [])), 'Device does not belong to the research image'
    return device


def verify_hfs_image(path, repair=False):
    """Use only the virtual device proven to be backed by this regular image."""
    assert path.is_file() and os.geteuid() == 0
    attachment = plistlib.loads(subprocess.check_output(['hdiutil', 'attach', '-nomount', '-plist', str(path)], timeout=180))
    registry = plistlib.loads(subprocess.check_output(['hdiutil', 'info', '-plist'], timeout=30))
    device = image_device(attachment, registry, path)
    raw_device = device.replace('/dev/disk', '/dev/rdisk', 1)
    try:
        check = subprocess.run(['/sbin/fsck_hfs', '-fn', raw_device], timeout=240)
        if check.returncode and repair:
            subprocess.run(['/sbin/fsck_hfs', '-fy', raw_device], timeout=240)
            subprocess.run(['/sbin/fsck_hfs', '-fn', raw_device], check=True, timeout=240)
        else:
            check.check_returncode()
    finally:
        subprocess.run(['hdiutil', 'detach', '-force', device], check=True, timeout=180)


def seed(root):
    # Follow the existing research-root layout, preserving the real Setup UI.
    cache = safe(root, 'System/Library/Caches/com.apple.dyld')
    cache.mkdir(parents=True, exist_ok=True)
    for source in safe(root, 'private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld').iterdir():
        target = cache / source.name
        if not os.path.lexists(target):
            os.link(source, target)
    for role in ('OS', 'App'):
        source = safe(root, 'private/preboot/Cryptexes/' + role)
        for directory, dirs, files in os.walk(source, followlinks=False):
            for name in files + [n for n in dirs if (Path(directory) / n).is_symlink()]:
                path = Path(directory) / name
                relative = path.relative_to(source)
                if relative.as_posix().startswith('System/Library/Caches/com.apple.dyld/'):
                    continue
                target = root / relative
                if os.path.lexists(target):
                    continue
                safe(root, relative.parent).mkdir(parents=True, exist_ok=True)
                if path.is_symlink():
                    target.symlink_to(os.readlink(path))
                else:
                    os.link(path, target)
    for relative, mode in (('diagnostics', 0o751), ('uuidtext', 0o755), ('diagnostics/timesync', 0o755)):
        directory = safe(root, 'private/var/db/' + relative)
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, mode); os.chown(directory, 272, 272)
        marker = directory / '.migrated';marker.touch();os.chmod(marker, 0o644);os.chown(marker, 272, 272)
    keybag = safe(root, 'private/var/keybags')
    keybag.mkdir(parents=True, exist_ok=True);os.chmod(keybag, 0o700)
    (keybag / 'systembag.kb').write_bytes(plistlib.dumps({'KeyBagKeys': b'SWEET'}))
    os.chmod(keybag / 'systembag.kb', 0o600)
    tweaks = load('tweaks', 'sweet-root-tweaks.py')
    tweaks.launchd(str(root));tweaks.containers(str(root));tweaks.audio(str(root))
    prefs = safe(root, 'private/var/mobile/Library/Preferences')
    prefs.mkdir(parents=True, exist_ok=True);os.chown(prefs, 501, 501)
    tweaks.merge_pref(str(root), 'com.apple.migration', {'LastSystemVersion': '20H392',
        'DMUserDataDisposition': {'SyntheticDidUpgrade': False, 'buildVersion': '20H392'}})
    tweaks.merge_pref(str(root), 'com.apple.springboard', {'BKNoWatchdogs': True})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('work', type=Path)
    ap.add_argument('report', type=Path)
    ap.add_argument('--ipsw', type=Path, help='local complete IPSW; verified before extraction')
    ap.add_argument('--rsync', type=Path, required=True, help='absolute GNU rsync binary path')
    args = ap.parse_args()
    assert sys.platform == 'darwin' and os.geteuid() == 0, 'Needs macOS and root for image ownership'
    work = args.work.resolve()
    assert not work.exists(), 'Refusing to overwrite an existing research directory'
    work.mkdir(parents=True)
    assert args.rsync.is_absolute() and args.rsync.is_file(), 'GNU rsync executable required'
    subprocess.run([str(args.rsync), '--version'], check=True)
    image, root = work / 'ginkgo-root.dmg', work / 'root'
    root.mkdir()
    subprocess.run(['df', '-h', str(work)], check=True)
    create_image(image)
    subprocess.run(['hdiutil', 'attach', '-nobrowse', '-owners', 'on', '-mountpoint', str(root), str(image)], check=True, timeout=180)
    (root / '.metadata_never_index').touch()
    fetch = load('fetch', 'ipsw-fetch.py')
    sources = []
    try:
        if args.ipsw:
            print('Verifying pinned complete IPSW', flush=True)
            digest = hashlib.sha1()
            with args.ipsw.open('rb') as stream:
                while chunk := stream.read(8 << 20):
                    digest.update(chunk)
            assert digest.hexdigest() == '5606c298c1d908f8a48f617f0ceaf71f2a9f0193', 'Unexpected complete IPSW'
            source_zip = args.ipsw.open('rb')
        else:
            source_zip = RemoteZip(fetch)
        with source_zip as remote, zipfile.ZipFile(remote) as archive:
            for role, member, digest in IMAGES:
                target = work / member
                print(f'Fetching pinned {role}', flush=True)
                hash_ = hashlib.sha256()
                with archive.open(member) as source, target.open('wb') as destination:
                    while chunk := source.read(8 << 20):
                        hash_.update(chunk);destination.write(chunk)
                assert hash_.hexdigest() == digest, f'{role} digest mismatch'
                mount = work / ('source-' + role);mount.mkdir()
                subprocess.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-owners', 'on',
                                '-mountpoint', str(mount), str(target)], check=True, timeout=180)
                try:
                    destination = root if role == 'OS' else safe(root, 'private/preboot/Cryptexes/' + ('OS' if role == 'SystemOS' else 'App'))
                    destination.mkdir(parents=True, exist_ok=True)
                    print(f'Copying {role} without filesystem compression attributes', flush=True)
                    subprocess.run([str(args.rsync), '-aH', '--whole-file', '--numeric-ids', '--info=progress2,stats2',
                                    '--exclude=/.fseventsd', '--exclude=/.Trashes', str(mount) + '/',
                                    str(destination) + '/'], check=True, timeout=1200)
                finally:
                    subprocess.run(['hdiutil', 'detach', str(mount)], check=True, timeout=60)
                target.unlink()  # exact downloaded workspace file, after detach
                sources.append({'role': role, 'member': member, 'sha256': digest})
        seed(root)
        assert (safe(root, 'sbin/launchd')).is_file()
        assert (safe(root, 'usr/lib/dyld')).is_file()
        subprocess.run(['df', '-h', str(root)], check=True)
    finally:
        # This is the newly created research volume only. Background macOS
        # observers can keep it busy after the copy; flush before closing them.
        subprocess.run(['sync'], check=True, timeout=180)
        subprocess.run(['hdiutil', 'detach', '-force', str(root)], check=True, timeout=180)
    size = strip_udrw(image)
    raw = work / 'ginkgo-root.img'
    image.rename(raw)
    verify_hfs_image(raw, repair=True)
    report = {'build': '20H392', 'image': str(raw), 'bytes': size, 'sources': sources,
              'sourceMethod': 'pinned-complete-ipsw' if args.ipsw else 'pinned-components-over-ranges',
              'scope': 'QEMU-only private HFSX research root; no phone partition destination',
              'setup': 'Original Setup UI retained; no activation or account state seeded'}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
