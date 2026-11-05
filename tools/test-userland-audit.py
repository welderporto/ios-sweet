#!/usr/bin/env python3
"""Exercise ISA reporting with synthetic code, without Apple firmware or mounts."""
import importlib.util
from pathlib import Path
import struct
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
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, subtype, 2, 1, 72, 0, 0)
        segment = struct.pack('<2I16s4Q4I', 0x19, 72, b'__TEXT', 0x100000000,
                              4, 104, 4, 5, 5, 0, 0)
        path.write_bytes(header + segment + struct.pack('<I', instruction))
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


if __name__ == '__main__':
    unittest.main()
