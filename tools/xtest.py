#!/usr/bin/env python3
"""Run X clients from the root against the stub X server (tools/xstub.py) and check that
they drew: xclock must paint its hands (FillPoly), xterm must show text (ImageText8).

    python3 tools/xtest.py [-r ROOT] [--cpu rust] [-o DIR]

The framebuffer images are left in DIR (default: the scratch directory /tmp/hpuxemu-xtest)
as xclock.png and xterm.png."""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402
DISPLAY = 19


def run_client(root, cpu, args, seconds, out, env_extra=()):
    stub = subprocess.Popen([sys.executable, os.path.join(HERE, 'xstub.py'), '-d', str(DISPLAY), '-o', out, '-t', str(seconds + 4)],
                            stderr=subprocess.PIPE, text=True)
    time.sleep(1)
    env = dict(os.environ, HPUX_ROOT=root)
    cmd = emulator(cpu) + ['-e', 'DISPLAY=:%d' % DISPLAY, '-e', 'HOME=/'] + list(env_extra) + args
    client = subprocess.Popen(cmd, cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        client.wait(seconds)
    except subprocess.TimeoutExpired:
        client.kill()
    _, log = stub.communicate()
    cerr = client.stderr.read() if client.stderr else ''
    requests = {}
    for line in log.splitlines():
        if line.startswith('xstub: requests:'):
            for item in line.split(':', 2)[2].split(','):
                name, _, n = item.strip().rpartition(' ')
                if name:
                    requests[name] = int(n)
    return requests, cerr


def main(argv):
    root = os.environ.get('HPUX_ROOT')
    cpu = default_cpu()
    out = '/tmp/hpuxemu-xtest'
    i = 1
    while i < len(argv):
        if argv[i] == '-r':
            i += 1
            root = argv[i]
        elif argv[i] == '--cpu':
            i += 1
            cpu = argv[i]
        elif argv[i] == '-o':
            i += 1
            out = argv[i]
        i += 1
    if not root:
        sys.path.insert(0, REPO)
        from hpuxemu import rootdir
        root = rootdir.default_root()
    os.makedirs(out, exist_ok=True)
    ok = True
    req, err = run_client(root, cpu, ['/usr/bin/X11/xclock', '-geometry', '200x200+10+10'], 8, os.path.join(out, 'xclock.png'))
    good = req.get('FillPoly', 0) > 0 and req.get('PolyLine', 0) > 0
    print('xclock: %s (%s)' % ('ok' if good else 'FAILED', ', '.join('%s %d' % kv for kv in sorted(req.items(), key=lambda kv: -kv[1])[:6])))
    if not good:
        print(err[-800:])
    ok &= good
    req, err = run_client(root, cpu, ['/usr/bin/X11/xterm', '-geometry', '80x24+10+10', '-e', '/usr/bin/sh', '-c', 'echo hello from xterm; ls /; sleep 30'],
                          20, os.path.join(out, 'xterm.png'))
    good = req.get('ImageText8', 0) + req.get('PolyText8', 0) > 0
    print('xterm: %s (%s)' % ('ok' if good else 'FAILED', ', '.join('%s %d' % kv for kv in sorted(req.items(), key=lambda kv: -kv[1])[:6])))
    if not good:
        print(err[-800:])
    ok &= good
    print('xtest: %s; images in %s' % ('ok' if ok else 'FAILED', out))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
