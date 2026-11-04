#!/usr/bin/env python3
"""Check the IIG adapter against a four-field ABI fixture and real output."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('iig_legacy', Path(__file__).with_name('iig-legacy.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fixture = r'''
#include <cstdint>
struct Message { uint32_t value; };
struct Foo_Msg { uint32_t header; };
struct Foo_Msg_With_Content { uint32_t header; Message content; };
struct IORPC { void *message; void *reply; uint32_t sendSize; uint32_t replySize; };
union Invocation { IORPC rpc; struct {
#ifdef KERNEL
Foo_Msg *message;
#else
Foo_Msg_With_Content *message;
#endif
void *reply; uint32_t sendSize; uint32_t replySize;
#ifdef KERNEL
Message *kernelContent;
#endif
}; };
#ifdef KERNEL
#define MESSAGE_CONTENT(field) (messageContent->field)
#else
#define MESSAGE_CONTENT(field) (message->content.field)
#endif
#if KERNEL
constexpr bool is_kernel = true;
#else
constexpr bool is_kernel = false;
#endif
int main() {
static_assert(is_kernel);
static_assert(sizeof(Invocation) == sizeof(IORPC));
Foo_Msg_With_Content input{12, {42}};
#ifdef KERNEL
IORPC rpc{.message=&input, .reply=nullptr, .sendSize=sizeof(input), .replySize=0, .kernelContent=&input.content};
#else
IORPC rpc{.message=&input, .reply=nullptr, .sendSize=sizeof(input), .replySize=0};
#endif
Invocation inv{rpc}; auto message = inv.message;
return MESSAGE_CONTENT(value) == 42 ? 0 : 1;
}
'''
converted, count = module.legacy_cpp(fixture)
assert count == 4
assert module.legacy_cpp(converted)[0] == converted, 'Adapter must be idempotent'
try:
    module.legacy_cpp('auto bad = rpc.kernelContent;\n')
except ValueError:
    pass
else:
    raise AssertionError('Unrecognized pointer use must be rejected')
if '--compile' in sys.argv:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / 'fixture.cpp'
        executable = Path(directory) / 'fixture'
        source.write_text(converted)
        subprocess.check_call(['clang++', '-std=c++20', '-DKERNEL=1', str(source), '-o', str(executable)])
        subprocess.check_call([str(executable)])
for argument in sys.argv[1:]:
    if argument == '--compile':
        continue
    path = Path(argument)
    output, count = module.legacy_cpp(path.read_text())
    assert count > 0, 'Real modern IIG output should require conversion'
    print(f'PASS: {path.name}, {count} recognized ABI blocks converted')
print('PASS: original IORPC layout/content, kernel conditional preserved, idempotence and unsafe-input rejection')
