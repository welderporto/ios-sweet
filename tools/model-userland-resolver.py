"""Fail-closed interpretation of small CPU resolvers from captured instruction metadata.

Only commpage capability loads are modeled. No arbitrary cached globals, calls,
stack memory or runtime fixups are assumed initialized. Dependencies track the
capability bits tested by branches/selection; this is not a process emulator.
"""
CAPABILITIES = 0xfffffc010
CAPABILITIES32 = 0xfffffc020
LSE = 1 << 25  # xnu-8796 osfmk/arm/cpu_capabilities.h
MASK = (1 << 64) - 1


def simulate(instructions, capabilities):
    code = {i['address']: i for i in instructions}
    registers, dependencies, tested = {}, {}, set()
    zero, flag_dependencies = None, set()
    pc = instructions[0]['address'] if instructions else 0

    def key(reg):
        return {'fp': 'x29', 'lr': 'x30'}.get(reg, 'x' + reg[1:] if reg.startswith('w') else reg)

    def get(reg):
        if reg in ('xzr', 'wzr'):
            return 0, {}
        name = key(reg)
        if name not in registers:
            raise ValueError(f'Unknown register {reg}')
        width = 32 if reg.startswith('w') else 64
        return registers[name] & ((1 << width) - 1), {b: d for b, d in dependencies[name].items() if b < width}

    def put(reg, value, deps):
        if reg in ('xzr', 'wzr'):
            return
        width = 32 if reg.startswith('w') else 64
        registers[key(reg)] = value & ((1 << width) - 1)
        dependencies[key(reg)] = {b: d for b, d in deps.items() if 0 <= b < width and d}

    def operand(op):
        if op['type'] == 'imm':
            value, deps = op['value'] & MASK, {}
        elif op['type'] == 'reg':
            value, deps = get(op['reg'])
        else:
            raise ValueError('Unsupported operand')
        shift = op.get('shift', {}).get('value', 0)
        if shift:
            if op['shift']['type'] != 1:  # ARM64_SFT_LSL
                raise ValueError('Unsupported operand shift')
            value, deps = (value << shift) & MASK, {b + shift: d for b, d in deps.items() if b + shift < 64}
        return value, deps

    def union(deps):
        return set().union(*deps.values()) if deps else set()

    def condition(cc):
        if zero is None or cc not in (1, 2):  # EQ / NE
            raise ValueError('Unknown or unsupported condition')
        tested.update(flag_dependencies)
        return zero if cc == 1 else not zero

    try:
        for steps in range(max(32, len(code) * 4)):
            if pc not in code:
                raise ValueError(f'Control leaves captured resolver at {pc:x}')
            ins = code[pc]
            mnemonic, ops = ins['mnemonic'], ins.get('detail', [])
            following = pc + 4
            if mnemonic in ('adr', 'adrp', 'mov', 'movz', 'movn'):
                value, deps = operand(ops[1])
                put(ops[0]['reg'], ~value if mnemonic == 'movn' else value, deps)
            elif mnemonic == 'movk':
                old, deps = get(ops[0]['reg'])
                shift = ops[1].get('shift', {}).get('value', 0)
                mask = 0xffff << shift
                value = (ops[1]['value'] & 0xffff) << shift
                put(ops[0]['reg'], (old & ~mask) | value, {b: d for b, d in deps.items() if not mask >> b & 1})
            elif mnemonic in ('ldr', 'ldur', 'ldrb', 'ldrh'):
                mem = ops[1]
                assert mem['type'] == 'mem'
                address, deps = get(mem['base'])
                if mem.get('index') or deps:
                    raise ValueError('Unknown/dependent load address')
                address += mem['disp']
                width = (1 if mnemonic == 'ldrb' else 2 if mnemonic == 'ldrh' else
                         4 if ops[0]['reg'].startswith('w') else 8)
                region = (CAPABILITIES if CAPABILITIES <= address and address + width <= CAPABILITIES + 8
                          else CAPABILITIES32 if CAPABILITIES32 <= address and address + width <= CAPABILITIES32 + 4
                          else None)
                if region is None:
                    raise ValueError(f'Load outside modeled commpage capabilities: {address:x}')
                shift = (address - region) * 8
                put(ops[0]['reg'], capabilities >> shift, {b: {b + shift} for b in range(width * 8)})
            elif mnemonic in ('and', 'ands', 'orr', 'eor', 'tst'):
                a, da = operand(ops[0] if mnemonic == 'tst' else ops[1])
                b, db = operand(ops[1] if mnemonic == 'tst' else ops[2])
                value = a & b if mnemonic in ('and', 'ands', 'tst') else a | b if mnemonic == 'orr' else a ^ b
                deps = {}
                for bit in range(64):
                    d = da.get(bit, set()) | db.get(bit, set())
                    if not db and mnemonic in ('and', 'ands', 'tst') and not b >> bit & 1:
                        d = set()
                    if not db and mnemonic == 'orr' and b >> bit & 1:
                        d = set()
                    if d:
                        deps[bit] = d
                if mnemonic != 'tst':
                    put(ops[0]['reg'], value, deps)
                if mnemonic in ('ands', 'tst'):
                    zero, flag_dependencies = value == 0, union(deps)
            elif mnemonic in ('add', 'sub', 'cmp'):
                a, da = operand(ops[0] if mnemonic == 'cmp' else ops[1])
                b, db = operand(ops[1] if mnemonic == 'cmp' else ops[2])
                deps = union(da) | union(db)
                value = a + b if mnemonic == 'add' else a - b
                if mnemonic != 'cmp':
                    put(ops[0]['reg'], value, {bit: deps for bit in range(64)} if deps else {})
                else:
                    zero, flag_dependencies = a == b, deps
            elif mnemonic in ('lsr', 'lsl', 'ubfx'):
                value, deps = operand(ops[1])
                shift = ops[2]['value']
                if mnemonic == 'lsl':
                    value, deps = value << shift, {b + shift: d for b, d in deps.items()}
                else:
                    value, deps = value >> shift, {b - shift: d for b, d in deps.items() if b >= shift}
                    if mnemonic == 'ubfx':
                        width = ops[3]['value']
                        value &= (1 << width) - 1
                        deps = {b: d for b, d in deps.items() if b < width}
                put(ops[0]['reg'], value, deps)
            elif mnemonic in ('tbz', 'tbnz', 'cbz', 'cbnz'):
                value, deps = operand(ops[0])
                if mnemonic.startswith('tb'):
                    bit = ops[1]['value']
                    tested.update(deps.get(bit, set()))
                    take = bool(value >> bit & 1) == (mnemonic == 'tbnz')
                else:
                    tested.update(union(deps))
                    take = bool(value) == (mnemonic == 'cbnz')
                if take:
                    following = ops[-1]['value']
            elif mnemonic in ('b.eq', 'b.ne'):
                if condition(1 if mnemonic == 'b.eq' else 2):
                    following = ops[0]['value']
            elif mnemonic == 'b':
                following = ops[0]['value']
            elif mnemonic == 'csel':
                value, deps = operand(ops[1] if condition(ins['cc']) else ops[2])
                put(ops[0]['reg'], value, deps)
            elif mnemonic in ('nop', 'bti'):
                pass
            elif mnemonic == 'ret':
                value, deps = get('x0')
                return {'status': 'resolved', 'target': value, 'testedCapabilityBits': sorted(tested | union(deps)), 'steps': steps + 1}
            else:
                raise ValueError(f'Unsupported instruction {mnemonic}')
            pc = following
        raise ValueError('Resolver step limit reached')
    except (ValueError, KeyError, AssertionError) as error:
        return {'status': 'unresolved', 'reason': str(error), 'address': pc}


def main():
    import argparse
    import json
    from pathlib import Path
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('review', type=Path)
    ap.add_argument('output', type=Path)
    args = ap.parse_args()
    report, results = json.loads(args.review.read_text()), []
    assert report['build'] == '20H392' and report['stage'] == 'complete'
    for library in report['files']:
        if 'review' not in library:
            continue
        detail = library['review']
        for api in detail['selectedAPIs']:
            if not api['resolverExport']:
                continue
            cases = []
            for caps in (0, LSE, MASK ^ LSE, MASK):
                result = simulate(api.get('resolverInstructions', []), caps)
                assert result['status'] == 'resolved', (api['name'], result)
                assert result['target'] in detail['functionStartAddresses']
                assert result['testedCapabilityBits'] == [25]
                sites = [s for s in detail['lseSites'] if s['function'] == result['target']
                         and s['decodedLSE'] and not s['knownData']]
                cases.append({**result, 'capabilities': hex(caps), 'selectedFunctionLSE': len(sites)})
            assert cases[0]['target'] == cases[2]['target']
            assert cases[1]['target'] == cases[3]['target']
            assert cases[0]['target'] != cases[1]['target']
            assert cases[0]['selectedFunctionLSE'] == 0
            results.append({'library': library['file'], 'api': api['name'], 'cases': cases})
    assert len(results) == 10, 'Incomplete expected core API coverage'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'status': 'selected-entry-functions-validated', 'cases': results,
        'limitations': 'Selected entry functions only; transitive calls and runtime initialization are not certified.'}, indent=2) + '\n')
    print('PASS: 10 resolvers select non-LSE entry functions when capability bit 25 is clear')


if __name__ == '__main__':
    main()
