"""Bounded metadata review of LSE sites, exported entry points and literal tables."""
from bisect import bisect_right
from math import isqrt
import struct

CORE = ('/libdispatch.dylib', '/libsystem_pthread.dylib',
        '/libsystem_platform.dylib', '/libsystem_malloc.dylib')
APIS = {'_dispatch_retain', '_dispatch_release', '_dispatch_async_f', '_dispatch_once_f',
        '_dispatch_group_enter', '_dispatch_group_leave', '_pthread_create',
        '_pthread_mutex_lock', '_pthread_mutex_unlock', '_pthread_once',
        '_os_unfair_lock_lock', '_os_unfair_lock_unlock', '_malloc', '_free', '_calloc'}
LSE_MNEMONICS = ('cas', 'swp', 'ldadd', 'ldclr', 'ldeor', 'ldset', 'ldsmax',
                 'ldsmin', 'ldumax', 'ldumin', 'stadd', 'stclr', 'steor', 'stset',
                 'stsmax', 'stsmin', 'stumax', 'stumin')


def uleb(data, offset):
    value, shift = 0, 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
        shift += 7
    raise ValueError('Truncated or oversized ULEB128')


def exports(data, base):
    result = []
    def walk(offset, prefix, ancestors):
        assert offset not in ancestors, 'Export trie cycle'
        terminal_size, p = uleb(data, offset)
        children = p + terminal_size
        assert children < len(data)
        if terminal_size:
            flags, q = uleb(data, p)
            if not flags & 8:  # reexports have no code entry in this image
                value, q = uleb(data, q)
                address = value if flags & 3 == 2 else base + value
                result.append({'name': prefix, 'address': address, 'flags': flags})
        n = data[children]
        p = children + 1
        for _ in range(n):
            end = data.find(b'\0', p)
            assert end >= p
            edge = data[p:end].decode()
            target, p = uleb(data, end + 1)
            walk(target, prefix + edge, ancestors | {offset})
    if data:
        walk(0, '', set())
    return result


def sha256_table():
    def root(n):
        lo, hi = 0, 1 << 35
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if mid ** 3 <= n:
                lo = mid
            else:
                hi = mid
        return lo
    primes = [n for n in range(2, 312) if all(n % p for p in range(2, isqrt(n) + 1))][:64]
    return struct.pack('<64I', *(root(p << 96) & 0xffffffff for p in primes))


def known_tables(blob, address):
    table = sha256_table()
    found, position = [], 0
    while True:
        offset = blob.find(table, position)
        if offset < 0:
            return found
        if offset % 4 == 0:
            found.append({'kind': 'exact-sha256-k256', 'address': address + offset, 'bytes': len(table)})
        position = offset + 1


def function_metadata(header, base, read):
    p, linkedit, function_data, export_data = 32, None, None, None
    for _ in range(struct.unpack_from('<I', header, 16)[0]):
        cmd, length = struct.unpack_from('<2I', header, p)
        if cmd == 0x19 and header[p + 8:p + 24].split(b'\0')[0] == b'__LINKEDIT':
            vmaddr, _, fileoff, filesize = struct.unpack_from('<4Q', header, p + 24)
            linkedit = (vmaddr, fileoff, filesize)
        if cmd == 0x26:
            function_data = struct.unpack_from('<2I', header, p + 8)
        if cmd == 0x80000033:
            export_data = struct.unpack_from('<2I', header, p + 8)
        if cmd in (0x22, 0x80000022) and not export_data:
            export_data = struct.unpack_from('<2I', header, p + 40)
        p += length
    def payload(record):
        if not record or not record[1]:
            return b''
        assert linkedit is not None, 'Missing LINKEDIT mapping'
        vmaddr, fileoff, filesize = linkedit
        offset, size = record
        assert fileoff <= offset and offset + size <= fileoff + filesize
        return read(vmaddr + offset - fileoff, size)
    data, offset, address, starts = payload(function_data), 0, base, []
    while offset < len(data):
        delta, offset = uleb(data, offset)
        if not delta:
            break
        address += delta
        starts.append(address)
    return starts, exports(payload(export_data), base)


def make_reviewer(code, isa):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    def review(label, base, header, read):
        if not label.endswith(CORE):
            return None
        starts, symbols = function_metadata(header, base, read)
        names = {}
        for symbol in symbols:
            names.setdefault(symbol['address'], []).append(symbol['name'])
        records, sites, tables = [], [], []
        for section, address, size, _ in code.sections(header):
            blob = read(address, size)
            tables.extend(known_tables(blob, address))
            for offset, (word,) in enumerate(struct.iter_unpack('<I', blob[:len(blob) // 4 * 4])):
                if isa.classify(word) != 'lse':
                    continue
                pc = address + offset * 4
                decoded = list(disassembler.disasm(struct.pack('<I', word), pc))
                instruction = decoded[0] if decoded else None
                index = bisect_right(starts, pc) - 1
                function = starts[index] if index >= 0 else None
                sites.append({'address': pc, 'word': hex(word), 'function': function,
                              'exportNames': names.get(function, []),
                              'mnemonic': instruction.mnemonic if instruction else 'invalid',
                              'decodedLSE': bool(instruction and instruction.mnemonic.startswith(LSE_MNEMONICS)),
                              'operands': instruction.op_str if instruction else '',
                              'knownData': any(t['address'] <= pc < t['address'] + t['bytes'] for t in tables)})
            records.append((address, address + size, blob))
        entries = []
        for symbol in symbols:
            if symbol['name'] not in APIS:
                continue
            address = symbol['address']
            match = next((r for r in records if r[0] <= address < r[1]), None)
            if match is None:
                continue
            index = bisect_right(starts, address)
            end = min(match[1], starts[index] if index < len(starts) else match[1])
            blob = match[2][address - match[0]:end - match[0]]
            prefix = list(disassembler.disasm(blob[:40], address))
            branch, before = False, []
            for instruction in disassembler.disasm(blob, address):
                mnemonic = instruction.mnemonic
                if mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', 'b', 'br', 'ret'):
                    branch = True
                if (not branch and instruction.mnemonic.startswith(LSE_MNEMONICS)
                        and not any(t['address'] <= instruction.address < t['address'] + t['bytes'] for t in tables)):
                    before.append(instruction.address)
            entries.append({**symbol, 'end': end, 'boundsFromFunctionStarts': bool(starts),
                            'resolverExport': bool(symbol['flags'] & 16),
                            'lseBeforeFirstBranch': before,
                            'entryInstructions': [{'address': i.address, 'mnemonic': i.mnemonic,
                                                   'operands': i.op_str} for i in prefix]})
        return {'functionStarts': len(starts), 'exports': len(symbols), 'lseSites': sites,
                'knownTables': tables, 'selectedAPIs': entries,
                'limits': 'Decoding is not runtime execution. Resolver exports and outer CPU dispatch require review.'}
    return review
