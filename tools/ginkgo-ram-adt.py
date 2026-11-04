#!/usr/bin/env python3
"""Build the RAM-only ginkgo ADT with a conservative 1 GiB DRAM window.

This conservative experiment uses only a subset of the board's RAM.
Validate the window against the target's FDT before any physical boot.
No proprietary firmware or device dumps are included.
"""
import argparse
import importlib.util
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('output')
ap.add_argument('--qemu', action='store_true')
args = ap.parse_args()
spec = importlib.util.spec_from_file_location('mkadt', Path(__file__).with_name('mkadt.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.GINKGO_PHYS_BASE = 0x80000000
module.GINKGO_MEM_SIZE = 0x40000000
root = module.build(board='ginkgo', qemu=args.qemu, seed=bytes(range(64)))
Path(args.output).write_bytes(adt.serialize(root))
print(f'{args.output}: RAM 0x80000000..0xc0000000, ginkgo, qemu={args.qemu}')
