#!/usr/bin/env python3
"""QEMU-only 2 GiB memory map for GUI research; never use on the phone."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt

PRODUCT_IM4P_SHA256 = '480e8b0888949b4128b7aa2cd254497581c69e1bafa596a760b2fa955a8a6368'


def product_properties(raw):
    root, end = adt.parse(raw)
    assert not any(raw[end:]), 'Unexpected trailing ADT data'
    products = [node for node in root.children if node.name == 'product']
    assert len(products) == 1, 'Expected exactly one product node'
    # Match mkadt.d22ap_product: discard iBoot-populated placeholders and handles.
    props = [(name, value) for name, flags, value in products[0].props
             if not flags and name not in ('name', 'AAPL,phandle')]
    assert props and len({name for name, _ in props}) == len(props), 'Empty/duplicate product properties'
    return props


def load_product(path):
    wrapped = path.read_bytes()
    assert hashlib.sha256(wrapped).hexdigest() == PRODUCT_IM4P_SHA256, 'Unexpected product component'
    raw, info = adt.im4p_payload(wrapped)
    assert not info['encrypted'] and info['type'] == 'dtre', 'Expected plaintext device tree'
    props = product_properties(raw)
    return props, {'componentSha256': PRODUCT_IM4P_SHA256,
                   'rawSha256': hashlib.sha256(raw).hexdigest(),
                   'propertyNames': [name for name, _ in props],
                   'scope': 'Pinned D22AP product identity for private QEMU GUI test only'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output', type=Path)
    ap.add_argument('--product-im4p', type=Path)
    ap.add_argument('--identity-report', type=Path)
    args = ap.parse_args()
    spec = importlib.util.spec_from_file_location('mkadt', Path(__file__).with_name('mkadt.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if args.product_im4p:
        props, report = load_product(args.product_im4p)
        module.d22ap_product = lambda: props
    else:
        assert not args.identity_report, 'Identity report requires pinned product input'
    module.GINKGO_PHYS_BASE = 0x80000000
    module.GINKGO_MEM_SIZE = 0x80000000
    root = module.build(board='ginkgo', qemu=True, seed=bytes(range(64)))
    args.output.write_bytes(adt.serialize(root))
    if args.identity_report:
        args.identity_report.write_text(json.dumps(report, indent=2) + '\n')
    print('QEMU ONLY: 2 GiB at 0x80000000; not a physical ginkgo memory map')


if __name__ == '__main__':
    main()
