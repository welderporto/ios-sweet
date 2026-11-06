#!/usr/bin/env python3
"""Run ginkgo's minimal mockfs init in QEMU and require PID 1 + heartbeat."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import re
import sys
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('image')
ap.add_argument('payload')
ap.add_argument('outdir')
ap.add_argument('--require-gic-rearm', action='store_true')
ap.add_argument('--cpu', choices=('cortex-a76', 'cortex-a35'), default='cortex-a76')
ap.add_argument('--require-text', help='additional guest-console marker required for success')
args = ap.parse_args()
out = Path(args.outdir).resolve()
out.mkdir(parents=True, exist_ok=True)
shim = load('qemu_shim', 'qemu-shim.py')
msg = load('qemu_msg', 'qemu-msgbuf.py')
msg.RAM, msg.RAM_SIZE = 0x80000000, 0x10000000
mon = str(out / 'qmp.sock')
Path(mon).unlink(missing_ok=True)
command = ['qemu-system-aarch64', '-M', 'virt,gic-version=3', '-cpu', args.cpu,
           '-smp', '17', '-m', '3G', '-nographic', '-nic', 'none', '-serial', 'none',
           '-monitor', 'none', '-qmp', f'unix:{mon},server,nowait', '-no-reboot',
           '-d', 'guest_errors,unimp', '-D', str(out / 'qemu.log'),
           '-kernel', str(Path(args.image).resolve()), '-initrd', str(Path(args.payload).resolve())]
process = subprocess.Popen(command, stdin=subprocess.DEVNULL)
log = out / 'kernel.txt'
passed = False
try:
    for attempt in range(18):
        time.sleep(5)
        if process.poll() is not None:
            raise RuntimeError(f'QEMU exited: {process.returncode}')
        sys.argv = ['qemu-msgbuf.py', mon, str(log)]
        try:
            msg.main()
        except SystemExit:
            pass
        text = log.read_text(errors='replace') if log.exists() else ''
        # /dev/console writes need not enter the kernel's message ring.
        # Capture and OCR the actual guest screen as independent evidence.
        shim.qmp(mon, ('pmemsave', {'val': shim.FB_BASE,
                 'size': shim.FB_STRIDE * shim.FB_H, 'filename': str(out / 'fb.raw')}))
        shim.write_png(str(out / 'fb.png'), (out / 'fb.raw').read_bytes())
        ocr = subprocess.check_output(['tesseract', str(out / 'fb.png'), 'stdout', '--psm', '6'],
                                      text=True, stderr=subprocess.DEVNULL)
        (out / 'screen.txt').write_text(ocr)
        evidence = text + '\n' + ocr
        if re.search(r'init running as PID\s*1', evidence, re.I) and 'still alive' in evidence.lower():
            if args.require_text and args.require_text.lower() not in evidence.lower():
                raise RuntimeError(f'Missing required console marker: {args.require_text}')
            if 'panic(cpu' in text:
                raise RuntimeError('Kernel panic in QEMU')
            if args.require_gic_rearm:
                rearm = re.search(r'GINKGO GIC rearm: before=([0-9a-f]+) after=([0-9a-f]+) required=([0-9a-f]+)', text, re.I)
                if not rearm:
                    raise RuntimeError('Registered CPU did not report the GIC rearm')
                enabled, required = (int(rearm.group(i), 16) for i in (2, 3))
                if not required or enabled & required != required:
                    raise RuntimeError('GIC readback does not enable the required sources')
                print('PASS: registered CPU GIC rearm/readback observed')
            print(evidence)
            passed = True
            break
    shim.qmp(mon, ('stop', {}), ('pmemsave', {'val': shim.FB_BASE,
             'size': shim.FB_STRIDE * shim.FB_H, 'filename': str(out / 'fb.raw')}))
    shim.write_png(str(out / 'fb.png'), (out / 'fb.raw').read_bytes())
    (out / 'fb.raw').unlink()
finally:
    process.kill()
    process.wait()
if not passed:
    raise SystemExit('FAIL: PID 1 and heartbeat not both observed; inspect kernel.txt and fb.png')
print('PASS: QEMU PID 1 and heartbeat (does not validate physical phone hardware)')
