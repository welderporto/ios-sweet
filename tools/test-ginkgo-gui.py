#!/usr/bin/env python3
"""Run a private research root in QEMU and retain diagnostic frames, never the disk."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def update_evidence(result, log):
    # Kernel rings wrap during daemon startup; retain already observed events.
    for key, marker in (('rootMounted', 'BSD root: vblk0'),
                        ('appleLaunchdAttempted', 'load_init_program: attempting to load /sbin/launchd'),
                        ('kernelPanic', 'panic(cpu')):
        result[key] = bool(result.get(key)) or marker in log


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('shim', type=Path)
    ap.add_argument('payload', type=Path)
    ap.add_argument('disk', type=Path)
    ap.add_argument('output', type=Path)
    ap.add_argument('--seconds', type=int, default=900)
    args = ap.parse_args()
    out = args.output.resolve();out.mkdir(parents=True, exist_ok=True)
    assert args.disk.is_file() and not str(args.disk).startswith('/dev/'), 'Only a regular research image is accepted'
    shim, msg = load('shim', 'qemu-shim.py'), load('msg', 'qemu-msgbuf.py')
    msg.RAM, msg.RAM_SIZE, msg.TMP = 0x80000000, 0x10000000, str(out / 'msgbuf-chunk.tmp')
    mon = str(out / 'qmp.sock');Path(mon).unlink(missing_ok=True)
    command = ['qemu-system-aarch64', '-M', 'virt,gic-version=3', '-accel', 'tcg,thread=multi',
        '-cpu', 'cortex-a35', '-smp', '17', '-m', '3G', '-nographic', '-nic', 'none', '-serial', 'none',
        '-monitor', 'none', '-qmp', f'unix:{mon},server,nowait', '-no-reboot',
        '-d', 'guest_errors,unimp', '-D', str(out / 'qemu.log'),
        '-kernel', str(args.shim.resolve()), '-initrd', str(args.payload.resolve()),
        '-global', 'virtio-mmio.force-legacy=false', '-drive', f'file={args.disk.resolve()},if=none,format=raw,id=d0',
        '-device', 'virtio-blk-device,drive=d0', '-device', 'virtio-tablet-device,id=touch',
        '-device', 'virtio-keyboard-device,id=keys']
    result = {'cpu': 'cortex-a35', 'scope': 'QEMU-only; physical drivers not validated',
              'status': 'running', 'frames': [], 'kernelPanic': False}
    with (out / 'host.log').open('w') as host:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=host, stderr=host)
        started = time.monotonic()
        try:
            candidates = 0
            while time.monotonic() - started < args.seconds:
                time.sleep(30 if result.get('appleLaunchdAttempted') else 5)
                elapsed = int(time.monotonic() - started)
                if process.poll() is not None:
                    raise RuntimeError(f'QEMU exited {process.returncode}')
                sys.argv = ['qemu-msgbuf.py', mon, str(out / 'kernel.txt')]
                try:
                    msg.main()
                except SystemExit:
                    pass
                log = (out / 'kernel.txt').read_text(errors='replace') if (out / 'kernel.txt').exists() else ''
                (out / f'kernel-{elapsed:04d}.txt').write_text(log)
                raw = out / 'frame.raw';frame = out / f'frame-{elapsed:04d}.png'
                replies = shim.qmp(mon, ('pmemsave', {'val': shim.FB_BASE, 'size': shim.FB_STRIDE * shim.FB_H, 'filename': str(raw)}))
                assert not any('error' in reply for reply in replies), replies
                shim.write_png(str(frame), raw.read_bytes());raw.unlink()
                text = subprocess.check_output(['tesseract', str(frame), 'stdout', '--psm', '11'], text=True, stderr=subprocess.DEVNULL)
                (out / f'frame-{elapsed:04d}.txt').write_text(text)
                candidate = bool(re.search(r'press\s+home|swipe\s+up|quick\s+start|country\s+or\s+region|\bhello\b', text, re.I))
                candidates = candidates + 1 if candidate else 0
                result['frames'].append({'seconds': elapsed, 'file': frame.name, 'guiTextCandidate': candidate})
                update_evidence(result, log)
                print(json.dumps(result['frames'][-1]), flush=True)
                (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                if result['kernelPanic']:
                    raise RuntimeError('Kernel panic; inspect preserved log and frame')
                if candidates >= 2 and result['rootMounted'] and result['appleLaunchdAttempted']:
                    result['status'] = 'gui-text-candidate-requires-visual-review'
                    break
            else:
                result['status'] = 'no-gui-text-confirmation-within-budget'
        except Exception as error:
            result['status'], result['error'] = 'failed', str(error)
            raise
        finally:
            if process.poll() is None:
                process.kill();process.wait()
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            qemu_log = out / 'qemu.log'
            if qemu_log.exists():
                with qemu_log.open('rb') as stream:
                    stream.seek(max(0, qemu_log.stat().st_size - (1 << 20)))
                    (out / 'qemu-tail.log').write_bytes(stream.read())
                qemu_log.unlink()
    print(json.dumps(result), flush=True)
    return 0 if result['status'] == 'gui-text-candidate-requires-visual-review' else 1


if __name__ == '__main__':
    raise SystemExit(main())
