#!/usr/bin/env python3
"""Exercise ISA reporting with synthetic code, without Apple firmware or mounts."""
import importlib.util
from pathlib import Path
import struct
import os
import random
import tempfile
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


isa = load('isa', 'check-isa.py')
audit = load('audit', 'audit-ginkgo-userland.py')


class AuditTests(unittest.TestCase):
    def fixture(self, path, instruction, subtype=0):
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, subtype, 2, 1, 152, 0, 0)
        segment = struct.pack('<2I16s4Q4I', 0x19, 152, b'__TEXT', 0x100000000,
                              4, 184, 4, 5, 5, 1, 0)
        section = struct.pack('<16s16s2Q8I', b'__text', b'__TEXT', 0x100000000, 4,
                              184, 2, 0, 0, 0x80000400, 0, 0, 0)
        path.write_bytes(header + segment + section + struct.pack('<I', instruction))
        return audit.audit_file(path, 'synthetic', isa)

    def test_baseline_and_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'code'
            baseline = self.fixture(path, 0xd503201f)  # NOP
            self.assertEqual(baseline['instructionWords'], 1)
            self.assertEqual(baseline['assessment'], 'no-detected-extension')
            extension = self.fixture(path, 0xc8a07c00)  # CAS, LSE
            self.assertEqual(extension['candidateCounts'], {'lse': 1})
            self.assertEqual(extension['assessment'], 'requires-review')

    def test_arm64e_never_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.fixture(Path(tmp) / 'code', 0xd503201f, 0x80000002)
            self.assertEqual(result['architecture'], 'arm64e')
            self.assertEqual(result['assessment'], 'requires-review')

    def test_non_executable_mapping_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cache'
            data = bytearray(68)
            data[:16] = b'dyld_v1   arm64\0'
            struct.pack_into('<2I', data, 16, 32, 1)
            struct.pack_into('<3Q2I', data, 32, 0x100000000, 4, 64, 1, 1)
            struct.pack_into('<I', data, 64, 0xc8a07c00)
            path.write_bytes(data)
            result = audit.audit_file(path, 'cache', isa)
            self.assertEqual(result['instructionWords'], 0)
            self.assertEqual(result['assessment'], 'no-executable-mapping')
            self.assertFalse(result['candidateCounts'])

    def test_strings_in_executable_segment_are_not_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'code'
            self.fixture(path, 0xc8a07c00)
            data = bytearray(path.read_bytes())
            struct.pack_into('<I', data, 104 + 64, 0x40000000)  # S_ATTR_NO_TOC is not code
            path.write_bytes(data)
            result = audit.audit_file(path, 'strings', isa)
            self.assertEqual(result['instructionWords'], 0)
            self.assertFalse(result['candidateCounts'])

    def test_commands_after_code_segment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'code'
            self.fixture(path, 0xd503201f)
            original = path.read_bytes()
            data = bytearray(original[:184] + struct.pack('<2I16s', 0x1b, 24, b'UUID-control') + original[184:])
            struct.pack_into('<2I', data, 16, 2, 176)
            struct.pack_into('<I', data, 104 + 48, 208)
            path.write_bytes(data)
            result = audit.audit_file(path, 'multiple commands', isa)
            self.assertEqual(result['instructionWords'], 1)
            self.assertFalse(result['candidateCounts'])

    def test_split_cache_resolves_image_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / 'image'
            self.fixture(image, 0xc8a07c00)
            header = bytearray(image.read_bytes())
            # Section is in a second cache, not in the Mach-O header's file.
            struct.pack_into('<Q', header, 104 + 32, 0x200000000)
            main = bytearray(8192)
            main[:16] = b'dyld_v1   arm64\0'
            struct.pack_into('<2I', main, 16, 0x180, 1)
            struct.pack_into('<3Q2I', main, 0x180, 0x100000000, len(main), 0, 5, 5)
            struct.pack_into('<2Q', main, 0x88, 0x200, 1)
            struct.pack_into('<Q2I', main, 0x210, 0x100001000, 4, 0x300)
            main[0x300:0x30a] = b'/lib/test\0'
            main[4096:4096 + len(header)] = header
            path = root / 'dyld_shared_cache_arm64'; path.write_bytes(main)
            sub = bytearray(4096); sub[:16] = b'dyld_v1   arm64\0'
            struct.pack_into('<2I', sub, 16, 0x180, 1)
            struct.pack_into('<3Q2I', sub, 0x180, 0x200000000, len(sub), 0, 5, 5)
            # Keep the code separate from its cache metadata.
            struct.pack_into('<Q', header, 104 + 32, 0x200000400)
            main[4096:4096 + len(header)] = header; path.write_bytes(main)
            struct.pack_into('<I', sub, 0x400, 0xc8a07c00)
            second = root / 'dyld_shared_cache_arm64.01'; second.write_bytes(sub)
            sources, records = audit.code.cache_audit([path, second], audit.code.Scanner(isa))
            self.assertEqual(len(sources), 2)
            self.assertEqual(records[0]['instructionWords'], 1)
            self.assertEqual(records[0]['candidateCounts'], {'lse': 1})

    @unittest.skipUnless(os.environ.get('ISA_SCAN_LIBRARY'), 'native scanner needs host C compiler')
    def test_native_matches_python(self):
        rng = random.Random(1947)
        blob = b''.join(struct.pack('<I', rng.getrandbits(32)) for _ in range(200000))
        expected, samples, actual, fast_samples = {}, {}, {}, {}
        isa.scan(blob, expected, samples, 0, 'control')
        native = audit.code.Scanner(isa, os.environ['ISA_SCAN_LIBRARY'])
        self.assertEqual(native.scan(blob, actual, fast_samples, 0, 'control'), len(blob) // 4)
        self.assertEqual(actual, expected)
        self.assertEqual(fast_samples, samples)


if __name__ == '__main__':
    unittest.main()
