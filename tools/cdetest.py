#!/usr/bin/env python3
"""Start a CDE session (dtsession) against the stub X server and check that it came up:
the RPC portmapper and ToolTalk's ttsession must be running, the TT_SESSION property set
on the root window, and dtwm, dtfile and dthelpview must have created their windows.

    python3 tools/cdetest.py [-r ROOT] [--cpu rust] [-o DIR] [-t SECONDS]

The session runs with HOME=/tmp/cdetest inside the root (removed first); the framebuffer
is left in DIR/cde.png. HP-UX's own /usr/sbin/portmap (11.00: rpcbind) is started if nothing answers on
port 111 (ttsession registers with it) and stopped again at the end."""

import os
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402
DISPLAY = 23
HOME = '/tmp/cdetest'


def portmapper_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(('127.0.0.1', 111))
        return True
    except OSError:
        return False
    finally:
        s.close()


def emu_pids(root):
    """pids of the emulator processes of this root (the process table it publishes)"""
    d = os.path.join(root, 'var/run/hpuxemu')
    out = []
    if os.path.isdir(d):
        for n in os.listdir(d):
            try:
                out.append(int(n))
            except ValueError:
                pass
    return out


def main(argv):
    root = os.environ.get('HPUX_ROOT')
    cpu = default_cpu()
    out = '/tmp/hpuxemu-xtest'
    seconds = 60
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
        elif argv[i] == '-t':
            i += 1
            seconds = int(argv[i])
        i += 1
    if not root:
        sys.path.insert(0, REPO)
        from hpuxemu import rootdir
        root = rootdir.default_root()
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, HPUX_ROOT=root)
    emu = emulator(cpu)
    before = set(emu_pids(root))
    started_portmap = False
    if not portmapper_up():
        # 10.20's portmap; 11.00 has rpcbind instead (TLI over the STREAMS daemon's
        # /dev/udp and /dev/tcp, tools/mkstrd.py), which takes a few seconds to come up
        binder = '/usr/sbin/portmap' if os.path.exists(os.path.join(root, 'usr/sbin/portmap')) else '/usr/sbin/rpcbind'
        subprocess.run(emu + [binder], cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if portmapper_up():
                break
            time.sleep(0.5)
        started_portmap = portmapper_up()
        print('portmap: %s' % ('started' if started_portmap else 'FAILED to start'))
    shutil.rmtree(os.path.join(root, HOME.lstrip('/')), ignore_errors=True)
    os.makedirs(os.path.join(root, HOME.lstrip('/')), exist_ok=True)
    ctl = os.path.join(out, 'cde.ctl')
    # the stub's log goes to a file: through a pipe read only at the end it would fill
    # the pipe, block the stub, and the control socket with it
    logpath = os.path.join(out, 'cde-xstub.log')
    logf = open(logpath, 'w')
    stub = subprocess.Popen([sys.executable, os.path.join(HERE, 'xstub.py'), '-d', str(DISPLAY), '-o', os.path.join(out, 'cde.png'),
                             '-t', str(seconds + 120), '-v', '-c', ctl], stderr=logf, text=True)
    time.sleep(1)
    cmd = emu + ['-e', 'DISPLAY=:%d' % DISPLAY, '-e', 'HOME=' + HOME, '-e', 'PATH=/usr/dt/bin:/usr/bin:/usr/bin/X11', '-e', 'LANG=C',
                 '/usr/dt/bin/dtsession']
    client = subprocess.Popen(cmd, cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + seconds
    while time.time() < deadline and client.poll() is None:
        time.sleep(1)
    # the session is up: click the front panel's Text Editor control, which goes
    # dtwm -> dtaction -> ToolTalk -> dtpad, and wait for the editor's window
    launched = False
    logged_out = False
    print('session up; clicking the front panel', flush=True)
    try:
        sys.path.insert(0, HERE)
        from xdrive import Drive
        d = Drive(ctl, timeout=5)
        panel = d.find('Dtwm')
        if panel and panel[1] > 500:
            x, y = panel[3] + 220, panel[4] + 48      # the fourth control from the left
            d.click(x, y)
            launched = d.wait_for('Dtpad', 40) is not None
            d.snap(os.path.join(out, 'cde-dtpad.png'))
        # log out: EXIT on the front panel, then "Continue logout" in dtsession's dialog;
        # dtsession saves the session (asking every client with WM_SAVE_YOURSELF and
        # waiting for their WM_COMMAND, which takes PropertyNotify) and exits
        if panel and panel[1] > 500:
            d.click(panel[3] + 625, panel[4] + 55)
            dialog = d.wait_for('Dtsession', 20)
            if dialog:
                d.click(dialog[3] + 69, dialog[4] + 167)
                t0 = time.time()
                while time.time() - t0 < 30 and client.poll() is None:
                    time.sleep(1)
                logged_out = client.poll() is not None
                print('logout took %.0f s' % (time.time() - t0) if logged_out else 'logout: dtsession still running after 30 s', flush=True)
        d.close()
    except Exception as e:
        print('front panel click: %s' % e)
    print('editor %s; waiting for the stub to finish' % ('appeared' if launched else 'did not appear'), flush=True)
    stub.wait()
    logf.close()
    log = open(logpath, errors='replace').read()
    try:
        client.kill()
    except OSError:
        pass
    cerr = client.stderr.read() if client.stderr else ''
    # the session's processes die with the display; what is left (ttsession, portmap) is ours to stop
    time.sleep(2)
    for pid in set(emu_pids(root)) - before:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    classes = set()
    tt = False
    for line in log.splitlines():
        if 'property WM_CLASS' in line:
            classes.add(line.split("b'")[1].split('\\x00')[1] if "b'" in line and '\\x00' in line else '?')
        if 'property TT_SESSION' in line:
            tt = True
    checks = [('ttsession registered its session (TT_SESSION on the root window)', tt),
              ('dtwm', 'Dtwm' in classes), ('dtfile', 'Dtfile' in classes), ('dthelpview', 'Dthelpview' in classes),
              ('front panel click starts the Text Editor (dtaction, ToolTalk, dtpad)', launched),
              ('EXIT and Continue logout end dtsession within 30 s', logged_out)]
    ok = True
    for what, good in checks:
        print('%-70s %s' % (what, 'ok' if good else 'FAILED'))
        ok &= good
    errlog = os.path.join(root, HOME.lstrip('/'), '.dt/errorlog')
    if not ok:
        print(cerr[-1500:])
        if os.path.exists(errlog):
            print(open(errlog, errors='replace').read()[-1500:])
    print('cdetest: %s; clients seen: %s; image in %s' % ('ok' if ok else 'FAILED', ' '.join(sorted(classes)), os.path.join(out, 'cde.png')))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
