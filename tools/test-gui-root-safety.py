#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

s = importlib.util.spec_from_file_location('root_builder', Path(__file__).with_name('mk-ginkgo-gui-root.py'))
builder = importlib.util.module_from_spec(s)
s.loader.exec_module(builder)


class SafetyTests(unittest.TestCase):
    def test_strip_only_verified_hfs_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'research.dmg'
            image = bytearray(8192 + 512)
            image[1024:1026] = b'HX'
            struct.pack_into('>2I', image, 1024 + 40, 512, 16)
            image[-512:-508] = b'koly'
            struct.pack_into('>2Q', image, len(image) - 512 + 24, 0, 8192)
            path.write_bytes(image)
            self.assertEqual(builder.strip_udrw(path), 8192)
            self.assertEqual(path.stat().st_size, 8192)

    def test_nonzero_data_offset_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'research.dmg';image = bytearray(4096)
            image[-512:-508] = b'koly'
            struct.pack_into('>2Q', image, len(image) - 512 + 24, 512, 2048)
            path.write_bytes(image)
            with self.assertRaises(AssertionError):
                builder.strip_udrw(path)
            self.assertEqual(path.stat().st_size, 4096)

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                builder.safe(Path(tmp), '../outside')


if __name__ == '__main__':
    unittest.main()
