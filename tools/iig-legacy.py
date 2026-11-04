#!/usr/bin/env python3
"""Use modern IIG with xnu-8796's four-field IORPC message ABI.

Modern generated code already contains the original contiguous Mach-message
path as its non-kernel alternative. Select that path only in the recognized
message-layout blocks, preserving all other kernel/non-kernel conditionals.
No IORPC headers, layouts, or dispatch signatures are changed.
"""
import os
from pathlib import Path
import re
import subprocess
import sys


def legacy_cpp(text):
    lines = text.splitlines(keepends=True)
    position = 0
    changes = 0

    def sequence():
        nonlocal position, changes
        result, direct = [], []
        while position < len(lines):
            line = lines[position]
            if re.match(r'^\s*#\s*(else|elif|endif)\b', line):
                break
            if re.match(r'^\s*#\s*(if|ifdef|ifndef)\b', line):
                opening = line
                position += 1
                first, first_direct = sequence()
                alternatives = []
                while position < len(lines) and re.match(r'^\s*#\s*(else|elif)\b', lines[position]):
                    middle = lines[position]
                    position += 1
                    body, body_direct = sequence()
                    alternatives.append((middle, body, body_direct))
                if position >= len(lines) or not re.match(r'^\s*#\s*endif\b', lines[position]):
                    raise ValueError('Unbalanced preprocessor conditional in IIG output')
                closing = lines[position]
                position += 1
                kernel = re.match(r'^\s*#\s*ifdef\s+KERNEL\s*(?://.*)?$', opening.strip())
                known_fields = 'kernelContent' in first_direct or 'messageContent' in first_direct
                known_message_pointer = ('_Msg_With_Content' in ''.join(a[2] for a in alternatives)
                                         and re.search(r'\bmessage\s*;', first_direct))
                if kernel and (known_fields or known_message_pointer):
                    if alternatives and (len(alternatives) != 1 or not re.match(r'^\s*#\s*else\b', alternatives[0][0])):
                        raise ValueError('Unexpected IIG message-layout alternatives')
                    result.append(alternatives[0][1] if alternatives else '')
                    changes += 1
                else:
                    result.extend([opening, first])
                    for middle, body, _ in alternatives:
                        result.extend([middle, body])
                    result.append(closing)
            else:
                result.append(line)
                direct.append(line)
                position += 1
        return ''.join(result), ''.join(direct)

    output, _ = sequence()
    if position != len(lines):
        raise ValueError('Unexpected top-level preprocessor terminator')
    if 'kernelContent' in output or 'messageContent' in output:
        raise ValueError('Unrecognized modern IIG content-pointer use; refusing ABI conversion')
    return output, changes


def main():
    real = os.environ['REAL_IIG']
    subprocess.check_call([real, *sys.argv[1:]])
    if '--impl' not in sys.argv:
        return
    path = Path(sys.argv[sys.argv.index('--impl') + 1])
    output, changes = legacy_cpp(path.read_text())
    temporary = path.with_suffix(path.suffix + '.legacy.tmp')
    temporary.write_text(output)
    temporary.replace(path)
    print(f'IIG legacy ABI: {path.name}, {changes} message-layout blocks converted', file=sys.stderr)


if __name__ == '__main__':
    main()
