#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

s = importlib.util.spec_from_file_location('model', Path(__file__).with_name('model-userland-resolver.py'))
model = importlib.util.module_from_spec(s)
s.loader.exec_module(model)


def reg(name):
    return {'type': 'reg', 'reg': name}


def imm(value, shift=0):
    return {'type': 'imm', 'value': value, 'shift': {'type': 1 if shift else 0, 'value': shift}}


def program(alias32=False):
    specs = [('movz', [reg('x8'), imm(0xc020 if alias32 else 0xc010)]),
             ('movk', [reg('x8'), imm(0xffff, 16)]),
             ('movk', [reg('x8'), imm(0xf, 32)]),
             ('ldr', [reg('w9' if alias32 else 'x9'), {'type': 'mem', 'base': 'x8', 'index': None, 'disp': 0}]),
             ('tst', [reg('x9'), imm(model.LSE)]),
             ('adr', [reg('x10'), imm(0x2000)]),
             ('adr', [reg('x11'), imm(0x3000)]),
             ('csel', [reg('x0'), reg('x10'), reg('x11')]),
             ('ret', [])]
    return [{'address': 0x1000 + i * 4, 'mnemonic': name, 'detail': detail, 'cc': 1}
            for i, (name, detail) in enumerate(specs)]


class ModelTests(unittest.TestCase):
    def test_capabilities_select_baseline_and_lse(self):
        for alias in (False, True):
            for caps, target in ((0, 0x2000), (model.LSE, 0x3000),
                                 (model.MASK ^ model.LSE, 0x2000), (model.MASK, 0x3000)):
                result = model.simulate(program(alias), caps)
                self.assertEqual(result['status'], 'resolved', result)
                self.assertEqual(result['target'], target)
                self.assertEqual(result['testedCapabilityBits'], [25])

    def test_unknown_memory_fails_closed(self):
        p = program();p[0]['detail'][1] = imm(0x1234)
        self.assertEqual(model.simulate(p, 0)['status'], 'unresolved')

    def test_calls_fail_closed(self):
        p = program();p[0]['mnemonic'] = 'bl'
        self.assertEqual(model.simulate(p, 0)['status'], 'unresolved')

    def test_branch_cycle_is_bounded(self):
        result = model.simulate([{'address': 0x1000, 'mnemonic': 'b', 'detail': [imm(0x1000)]}], 0)
        self.assertEqual(result['status'], 'unresolved')
        self.assertIn('limit', result['reason'])


if __name__ == '__main__':
    unittest.main()
