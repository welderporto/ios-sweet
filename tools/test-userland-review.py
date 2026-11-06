#!/usr/bin/env python3
"""Synthetic export, function-boundary, instruction and literal review controls."""
import importlib.util
from pathlib import Path
import struct
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


review = load('review', 'review-userland-code.py')
code = load('code', 'userland-code.py')
isa = load('isa', 'check-isa.py')


class ReviewTests(unittest.TestCase):
    def test_uleb_and_truncation(self):
        self.assertEqual(review.uleb(b'\x80\x08', 0), (1024, 2))
        with self.assertRaises(ValueError):
            review.uleb(b'\x80', 0)

    def test_exact_table_only(self):
        table = review.sha256_table()
        self.assertEqual(table[:4], bytes.fromhex('982f8a42'))
        self.assertEqual(review.known_tables(table, 4096)[0]['address'], 4096)
        changed = bytearray(table); changed[-1] ^= 1
        self.assertFalse(review.known_tables(changed, 4096))
        self.assertFalse(review.known_tables(bytes.fromhex('6f63a578'), 4096))

    def test_export_cycle_rejected(self):
        with self.assertRaises(AssertionError):
            review.exports(b'\x00\x01x\x00\x00', 0x1000)

    def test_exported_api_with_inline_lse(self):
        name = b'_dispatch_group_enter'
        root = b'\x00\x01' + name + b'\x00'
        trie = root + bytes([len(root) + 1]) + b'\x03\x00\x80\x08\x00'
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 4, 256, 0, 0)
        text = struct.pack('<2I16s4Q4I', 0x19, 152, b'__TEXT', 0x1000, 0x1000, 0, 0x1000, 5, 5, 1, 0)
        section = struct.pack('<16s16s2Q8I', b'__text', b'__TEXT', 0x1400, 8,
                              0x400, 2, 0, 0, 0x80000400, 0, 0, 0)
        link = struct.pack('<2I16s4Q4I', 0x19, 72, b'__LINKEDIT', 0x3000, 256, 0x2000, 256, 1, 1, 0, 0)
        commands = struct.pack('<4I', 0x26, 16, 0x2000, 3) + struct.pack('<4I', 0x80000033, 16, 0x2020, len(trie))
        header += text + section + link + commands
        linkdata = bytearray(256);linkdata[:3] = b'\x80\x08\x00';linkdata[32:32 + len(trie)] = trie
        instructions = struct.pack('<2I', 0xb8200041, 0xd65f03c0)  # LDADD; RET
        def read(address, size):
            if 0x3000 <= address < 0x3100:
                return bytes(linkdata[address - 0x3000:address - 0x3000 + size])
            assert address == 0x1400 and size == 8
            return instructions
        result = review.make_reviewer(code, isa)('/usr/lib/system/libdispatch.dylib', 0x1000, header, read)
        self.assertEqual(result['functionStarts'], 1)
        self.assertEqual(result['selectedAPIs'][0]['name'], name.decode())
        self.assertEqual(result['selectedAPIs'][0]['lseBeforeFirstBranch'], [0x1400])
        self.assertTrue(result['lseSites'][0]['decodedLSE'])
        self.assertEqual(result['lseSites'][0]['exportNames'], [name.decode()])


if __name__ == '__main__':
    unittest.main()
