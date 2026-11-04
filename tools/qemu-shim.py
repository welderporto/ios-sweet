#!/usr/bin/env python3
"""Boot the diagnostic shim (BOARD=qemu shim/build.sh) on QEMU virt and save its screen.

The shim is entered like a Linux Image (EL1, x0 = DTB, initrd in /chosen),
as ABL does on the phone. Without a SWEETXNU payload it runs its
diagnostics; with --cpu cortex-a53 the ISA line must read lse=0 pan=0.

  qemu-shim.py shim/out/Image OUTDIR [--cpu cortex-a53] [--smp 8] [--secs 8] [--initrd FILE] [--live PORT]
               [--test-payload]

--test-payload (needs aarch64-linux-gnu-as/objcopy): instead of xnu, a tiny
SWEETXNU payload that paints a green band through boot_args->Video and
stores the MPIDR of the core it runs on; checks the loader and the
BOARD_XNU_MPIDR hand-off end to end.
"""
import argparse, json, os, socket, struct, subprocess, sys, tempfile, time, zlib

FB_BASE, FB_W, FB_H = 0x5c000000, 1080, 2340
FB_STRIDE = FB_W * 4

TEST_PHYS = 0x80000000
TEST_CODE_OFF, TEST_ADT_OFF, TEST_MARK = 0x1000, 0x2000, 0x800
TEST_ASM = f"""
	ldr	x1, [x0, #40]		// boot_args->Video.v_baseAddr
	mrs	x2, mpidr_el1
	movz	w3, #0xff00
	movk	w3, #0xff00, lsl #16	// green
	ldr	x4, ={FB_W * 200}
1:	str	w3, [x1], #4
	subs	x4, x4, #1
	b.ne	1b
	ldr	x5, ={TEST_PHYS + TEST_MARK}
	orr	x2, x2, #(1 << 63)
	str	x2, [x5]
	str	x0, [x5, #8]
2:	wfe
	b	2b
	.ltorg
"""


def test_payload(path):
    """SWEETXNU v1 payload (tools/mkpayload.py layout) around TEST_ASM."""
    with tempfile.TemporaryDirectory() as d:
        open(f'{d}/t.S', 'w').write(TEST_ASM)
        subprocess.check_call(['aarch64-linux-gnu-as', '-o', f'{d}/t.o', f'{d}/t.S'])
        subprocess.check_call(['aarch64-linux-gnu-objcopy', '-O', 'binary', '-j', '.text', f'{d}/t.o', f'{d}/t.bin'])
        code = open(f'{d}/t.bin', 'rb').read()
    assert len(code) <= TEST_MARK
    hdr = b'SWEETXNU' + struct.pack('<2I7Q', 1, 1, TEST_PHYS, TEST_PHYS, TEST_ADT_OFF, 16,
                                    TEST_PHYS + 0x4000, TEST_PHYS, 0x10000000)
    hdr += b'test'.ljust(608, b'\0') + struct.pack('<4Q', TEST_PHYS, 0x4000, TEST_CODE_OFF, len(code))
    blob = hdr.ljust(TEST_CODE_OFF, b'\0') + code
    blob = blob.ljust(TEST_ADT_OFF, b'\0') + b'\0' * 16
    open(path, 'wb').write(blob)


LIVE_HTML = b'''<!doctype html><meta charset="utf-8"><title>ginkgo QEMU screen</title>
<body style="margin:0;background:#222;display:flex;justify-content:center">
<img id="s" src="fb.png" style="height:100vh;image-rendering:auto">
<script>
const s = document.getElementById('s');
setInterval(() => { const n = new Image(); n.onload = () => { s.src = n.src; };
  n.src = 'fb.png?' + Date.now(); }, 1000);
</script>'''


def serve_live(out, port, interactive):
    """Serve OUT/fb.png on 0.0.0.0:PORT; with a disk (iOS), the page also takes mouse touches (tools/qemu-live.py)."""
    import functools, http.server, importlib.util, threading
    if interactive:
        spec = importlib.util.spec_from_file_location('qemu_live', os.path.join(os.path.dirname(__file__), 'qemu-live.py'))
        live = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(live)
        live.serve(out, port)
        return
    open(f'{out}/index.html', 'wb').write(LIVE_HTML)

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def end_headers(self):
            self.send_header('Cache-Control', 'no-store')
            super().end_headers()

    srv = http.server.ThreadingHTTPServer(('0.0.0.0', port), functools.partial(Quiet, directory=out))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f'live screen: http://localhost:{port}/', file=sys.stderr)


def write_png(path, raw, level=6):
    rows = []
    for y in range(FB_H):
        line = raw[y * FB_STRIDE:(y + 1) * FB_STRIDE]
        rgb = bytearray(FB_W * 3)  # a8r8g8b8 little endian = B G R A in memory
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rows.append(b'\0' + bytes(rgb))
    chunk = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', FB_W, FB_H, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(b''.join(rows), level)) + chunk(b'IEND', b'')
    open(path + '.tmp', 'wb').write(png)
    os.replace(path + '.tmp', path)


def qmp(sock_path, *cmds):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    f = s.makefile('rw')
    f.readline()

    def call(execute, **args):
        f.write(json.dumps({'execute': execute, 'arguments': args}) + '\n')
        f.flush()
        while True:
            r = json.loads(f.readline())
            if 'return' in r or 'error' in r:
                return r

    call('qmp_capabilities')
    out = [call(c, **a) for c, a in cmds]
    s.close()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('image')
    ap.add_argument('outdir')
    ap.add_argument('--cpu', default='cortex-a53')
    ap.add_argument('--smp', type=int, default=8)
    ap.add_argument('--mem', default='4G', help='guest RAM (ginkgo ADT DRAM ends at 0xf3000000: 3G covers it)')
    ap.add_argument('--secs', type=float, default=8)
    ap.add_argument('--initrd', help='ramdisk (default: none; the shim then reports "no initrd")')
    ap.add_argument('--test-payload', action='store_true', help='boot a tiny test payload instead of xnu')
    ap.add_argument('--live', type=int, metavar='PORT',
                    help='serve the screen at http://localhost:PORT/, refreshed every second (no exception log)')
    ap.add_argument('--disk', help='raw image attached as virtio-blk (boot xnu with rd=vblk0)')
    ap.add_argument('--read-memory', nargs=3, metavar=('ADDRESS', 'SIZE', 'FILE'),
                    help='save a physical memory range with the final snapshot (test reports)')
    a = ap.parse_args()

    out = os.path.abspath(a.outdir)
    os.makedirs(out, exist_ok=True)
    if a.test_payload:
        a.initrd = f'{out}/test-payload.bin'
        test_payload(a.initrd)
    mon = f'{out}/qmp.sock'
    if os.path.exists(mon):
        os.unlink(mon)
    cmd = ['qemu-system-aarch64', '-M', 'virt,gic-version=3', '-cpu', a.cpu, '-smp', str(a.smp), '-m', a.mem,
           '-nographic', '-nic', 'none', '-serial', 'none', '-monitor', 'none', '-qmp', f'unix:{mon},server,nowait',
           '-d', 'guest_errors,unimp' if a.live else 'int,guest_errors,unimp', '-D', f'{out}/qemu.log',
           '-no-reboot', '-kernel', a.image]
    if a.initrd:
        cmd += ['-initrd', a.initrd]
    if a.disk:
        cmd += ['-global', 'virtio-mmio.force-legacy=false',
                '-drive', f'file={a.disk},if=none,format=raw,id=d0', '-device', 'virtio-blk-device,drive=d0',
                '-device', 'virtio-tablet-device,id=touch', '-device', 'virtio-keyboard-device,id=keys',
                '-netdev', 'user,id=n0', '-device', 'virtio-net-device,netdev=n0']
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
    try:
        if a.live:
            serve_live(out, a.live, bool(a.disk))
        t0 = time.time()
        # pmemsave runs under QEMU's global lock; a slow (host-shared) OUT stalls vCPUs waiting for it
        live_raw = os.path.join(tempfile.gettempdir(), f'qemu-live-{os.getpid()}.raw')
        while p.poll() is None and time.time() - t0 < a.secs:
            if a.live:
                time.sleep(1)
                if os.path.exists(mon):
                    qmp(mon, ('pmemsave', {'val': FB_BASE, 'size': FB_STRIDE * FB_H, 'filename': live_raw}))
                    write_png(f'{out}/fb.png', open(live_raw, 'rb').read(), level=1)
            else:
                time.sleep(0.2)
        if p.poll() is not None:
            print(f'qemu exited early: {p.returncode}', file=sys.stderr)
            return 1
        requests = [('stop', {}), ('human-monitor-command', {'command-line': 'info registers -a'}),
                    ('pmemsave', {'val': FB_BASE, 'size': FB_STRIDE * FB_H, 'filename': f'{out}/fb.raw'}),
                    ('pmemsave', {'val': TEST_PHYS + TEST_MARK, 'size': 16, 'filename': f'{out}/mark.raw'})]
        if a.read_memory:
            address, size, filename = a.read_memory
            requests.append(('pmemsave', {'val': int(address, 0), 'size': int(size, 0),
                                         'filename': os.path.abspath(filename)}))
        results = qmp(mon, *requests)
        for result in results:
            if 'error' in result:
                raise RuntimeError(f'QMP snapshot failed: {result["error"]}')
        _, regs, _, _ = results[:4]
        open(f'{out}/regs.txt', 'w').write(regs.get('return', str(regs)))
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    write_png(f'{out}/fb.png', open(f'{out}/fb.raw', 'rb').read())
    os.unlink(f'{out}/fb.raw')
    mpidr, x0 = struct.unpack('<2Q', open(f'{out}/mark.raw', 'rb').read())
    os.unlink(f'{out}/mark.raw')
    rc = 0
    if a.test_payload:
        if mpidr >> 63:
            print(f'test payload ran on MPIDR {mpidr & 0xffffff:#x} with x0 (boot_args) = {x0:#x}')
        else:
            print('test payload did not run')
            rc = 1
    print(f'{out}/fb.png  {out}/regs.txt  {out}/qemu.log', file=sys.stderr)
    return rc


if __name__ == '__main__':
    sys.exit(main())
