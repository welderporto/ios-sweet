#!/usr/bin/env python3
"""Check product extraction with synthetic trees; no Apple fixture in git."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt

spec = importlib.util.spec_from_file_location('gui_adt', Path(__file__).with_name('ginkgo-qemu-gui-adt.py'))
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)


def node(name, props=(), children=()):
    result = adt.Node()
    result.props = [('name', 0, name.encode() + b'\0')] + list(props)
    result.children = list(children)
    return result


class ProductTests(unittest.TestCase):
    def test_discards_placeholder_and_handle(self):
        product = node('product', [('public-property', 0, b'value'),
                                  ('serial-placeholder', 1, b'empty'),
                                  ('AAPL,phandle', 0, b'1234')])
        raw = adt.serialize(node('root', children=[product]))
        self.assertEqual(gui.product_properties(raw), [('public-property', b'value')])

    def test_missing_or_duplicate_node_rejected(self):
        product = node('product', [('public-property', 0, b'value')])
        for children in ([], [product, product]):
            with self.assertRaises(AssertionError):
                gui.product_properties(adt.serialize(node('root', children=children)))

    def test_wrong_component_rejected_before_decompression(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'wrong.im4p'
            path.write_bytes(b'not the pinned component')
            with self.assertRaises(AssertionError):
                gui.load_product(path)


if __name__ == '__main__':
    unittest.main()
