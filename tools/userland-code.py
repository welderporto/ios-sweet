"""Instruction-section readers for thin Mach-O and split dyld caches.

dyld_cache_image_text_info layout: Apple's include/mach-o/dyld_cache_format.h.
Sections use S_ATTR_PURE_INSTRUCTIONS / S_ATTR_SOME_INSTRUCTIONS, never __cstring.
"""
from contextlib import ExitStack
import ctypes
import hashlib
import mmap
import struct

CLASSES = ('lse', 'rcpc', 'pan', 'pauth', 'rdm', 'dotprod', 'fp16')


def sections(header):
    magic, cpu, _, _, ncmds, size, _, _ = struct.unpack_from('<8I', header)
    assert magic == 0xfeedfacf and cpu == 0x100000c, 'Expected arm64 Mach-O'
    assert 32 + size <= len(header), 'Truncated Mach-O commands'
    p = 32
    for _ in range(ncmds):
        cmd, length = struct.unpack_from('<2I', header, p)
        assert length >= 8 and p + length <= 32 + size
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', header, p + 64)[0]
            assert length >= 72 + 80 * nsects
            for i in range(nsects):
                q = p + 72 + i * 80
                name = header[q:q + 16].split(b'\0')[0].decode()
                address, size, offset = struct.unpack_from('<2QI', header, q + 32)
                flags = struct.unpack_from('<I', header, q + 64)[0]
                if flags & 0x80000400 and size:
                    yield name, address, size, offset
        p += length


class Scanner:
    def __init__(self, isa, library=None):
        self.isa = isa
        self.native = ctypes.CDLL(str(library)).isa_scan if library else None
        if self.native:
            self.native.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
                                    ctypes.POINTER(ctypes.c_uint32)]
            self.native.restype = None

    def scan(self, blob, counts, samples, address, label):
        if not self.native:
            return self.isa.scan(blob, counts, samples, address, label)
        counters = (ctypes.c_uint64 * 7)()
        offsets = (ctypes.c_uint64 * 21)()
        words = (ctypes.c_uint32 * 21)()
        self.native(blob, len(blob), counters, offsets, words)
        for c, count in enumerate(counters):
            if not count:
                continue
            name = CLASSES[c]
            counts[name] = counts.get(name, 0) + count
            target = samples.setdefault(name, [])
            for n in range(min(count, 3)):
                if len(target) < 3:
                    target.append((label, address + offsets[c * 3 + n], words[c * 3 + n]))
        return len(blob) // 4


def cache_audit(paths, scanner):
    """Resolve each image and code section across every subcache by VM address."""
    with ExitStack() as stack:
        mappings, sources = [], []
        main = None
        for path in paths:
            stream = stack.enter_context(path.open('rb'))
            data = stack.enter_context(mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ))
            assert data[:6] == b'dyld_v', path.name
            arch = data[:16].rstrip(b'\0').decode().split()[-1]
            assert arch == 'arm64', 'Expected plain arm64 cache'
            source = {'file': path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            sources.append(source)
            if path.name == 'dyld_shared_cache_arm64':
                main = data
            offset, count = struct.unpack_from('<2I', data, 16)
            assert offset + count * 32 <= len(data)
            for i in range(count):
                address, size, fileoff, _, _ = struct.unpack_from('<3Q2I', data, offset + 32 * i)
                assert fileoff + size <= len(data)
                mappings.append((address, address + size, fileoff, data))
        assert main is not None
        mappings.sort(key=lambda m: m[0])

        def read(address, size):
            chunks = []
            while size:
                match = next((m for m in mappings if m[0] <= address < m[1]), None)
                assert match is not None, f'Unmapped cache address {address:x}'
                start, end, offset, data = match
                take = min(size, end - address)
                chunks.append(data[offset + address - start:offset + address - start + take])
                address += take
                size -= take
            return b''.join(chunks)

        # Stable header fields imagesTextOffset / imagesTextCount at 0x88/0x90.
        offset, count = struct.unpack_from('<2Q', main, 0x88)
        assert count and offset + count * 32 <= len(main), 'Missing image text table'
        results, seen = [], set()
        for i in range(count):
            address, _, pathoff = struct.unpack_from('<Q2I', main, offset + i * 32 + 16)
            if address in seen:
                continue
            seen.add(address)
            assert pathoff < len(main)
            end = main.find(b'\0', pathoff)
            assert end >= pathoff
            label = main[pathoff:end].decode()
            header = read(address, 32)
            command_bytes = struct.unpack_from('<I', header, 20)[0]
            header = read(address, 32 + command_bytes)
            counts, samples, words = {}, {}, 0
            for name, section_address, size, _ in sections(header):
                words += scanner.scan(read(section_address, size), counts, samples,
                                      section_address, name)
            results.append({'file': label, 'architecture': 'arm64', 'instructionWords': words,
                            'candidateCounts': counts, 'samples': samples})
        assert sum(r['instructionWords'] for r in results) > 0
        return sources, results
