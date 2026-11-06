#!/usr/bin/env python3
"""QEMU-only 2 GiB memory map for GUI research; never use on the phone."""
import importlib.util
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt

spec = importlib.util.spec_from_file_location('mkadt', Path(__file__).with_name('mkadt.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.GINKGO_PHYS_BASE = 0x80000000
module.GINKGO_MEM_SIZE = 0x80000000
root = module.build(board='ginkgo', qemu=True, seed=bytes(range(64)))
Path(sys.argv[1]).write_bytes(adt.serialize(root))
print('QEMU ONLY: 2 GiB at 0x80000000; not a physical ginkgo memory map')
