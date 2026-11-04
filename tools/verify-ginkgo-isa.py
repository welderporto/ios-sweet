#!/usr/bin/env python3
"""Gate ARMv8.0 kernels; permit instruction-shaped SHA-256 constants only."""
import argparse
import hashlib
import importlib.util
from math import isqrt
from pathlib import Path
import struct

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('kernel', type=Path)
ap.add_argument('sha256')
args = ap.parse_args()
data = args.kernel.read_bytes()
assert hashlib.sha256(data).hexdigest() == args.sha256.lower(), 'Kernel digest mismatch'
spec = importlib.util.spec_from_file_location('isa', Path(__file__).with_name('check-isa.py'))
isa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isa)


def icbrt(number):
    low, high = 0, 1 << 35
    while low + 1 < high:
        middle = (low + high) // 2
        if middle ** 3 <= number:
            low = middle
        else:
            high = middle
    return low


primes = [n for n in range(2, 312) if all(n % d for d in range(2, isqrt(n) + 1))][:64]
table = struct.pack('<64I', *(icbrt(p << 96) & 0xffffffff for p in primes))
ignored, failures, words = [], [], 0
for offset in isa.thin_slices(data):
    for name, address, blob in isa.macho_exec_ranges(data, offset):
        table_start = blob.find(table)
        for position in range(0, len(blob) - 3, 4):
            words += 1
            word, = struct.unpack_from('<I', blob, position)
            feature = isa.classify(word)
            if feature:
                entry = (name, hex(address + position), feature, hex(word))
                if table_start >= 0 and table_start <= position < table_start + len(table):
                    ignored.append(entry)
                else:
                    failures.append(entry)
assert words > 0, 'No executable arm64 instructions found'
assert not failures, f'Post-ARMv8.0 instructions need review: {failures}'
print(f'PASS: {words} arm64 instruction words checked; {len(ignored)} exact SHA-256 data pattern(s) excluded')
for entry in ignored:
    print(entry)
