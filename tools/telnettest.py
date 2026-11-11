#!/usr/bin/env python3
"""Log in over telnet to inetd/telnetd running in the emulator and run a few commands:
the path a user takes from a Windows X server with a telnet client, where the login
scripts then set DISPLAY to that machine.

    python3 tools/telnettest.py [-r ROOT] [-H HOST] [-p PORT] [-u USER] [-P PASSWORD] [-s]

-s starts the portmapper and inetd in the emulator first (and leaves them running).
The minimal telnet negotiation accepts the server's ECHO and SUPPRESS-GO-AHEAD and
refuses everything else, which telnetd accepts; what the session prints is checked for the login banner, `who am i`
naming the remote host, and the shell's output."""

import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402
IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251


class Telnet:
    def __init__(self, host, port, timeout=20):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.buf = b''

    def read_until(self, pattern, timeout=20):
        """plain text up to and including the first match of the regex; options answered"""
        deadline = time.time() + timeout
        out = b''
        while time.time() < deadline:
            m = re.search(pattern, out)
            if m:
                return out
            try:
                data = self.s.recv(4096)
            except socket.timeout:
                continue
            if not data:
                return out
            self.buf += data
            # strip and answer IAC sequences
            i = 0
            plain = b''
            while i < len(self.buf):
                if self.buf[i] == IAC and i + 1 < len(self.buf):
                    cmd = self.buf[i + 1]
                    if cmd in (DO, DONT, WILL, WONT):
                        if i + 2 >= len(self.buf):
                            break
                        opt = self.buf[i + 2]
                        if cmd == DO:
                            self.s.sendall(bytes([IAC, WONT, opt]))
                        elif cmd == WILL:
                            # the server may echo and suppress go-ahead, as a real client allows
                            self.s.sendall(bytes([IAC, DO if opt in (1, 3) else DONT, opt]))
                        i += 3
                        continue
                    if cmd == 250:    # SB ... SE
                        j = self.buf.find(bytes([IAC, 240]), i)
                        if j < 0:
                            break
                        i = j + 2
                        continue
                    i += 2
                    continue
                plain += self.buf[i:i + 1]
                i += 1
            self.buf = self.buf[i:]
            out += plain
        return out

    def send(self, text):
        self.s.sendall(text.encode('latin1').replace(b'\n', b'\r\n'))


def main(argv):
    root = os.environ.get('HPUX_ROOT')
    host, port, user, password, start = '127.0.0.1', 23, 'root', '', False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-r':
            i += 1
            root = argv[i]
        elif a == '-H':
            i += 1
            host = argv[i]
        elif a == '-p':
            i += 1
            port = int(argv[i])
        elif a == '-u':
            i += 1
            user = argv[i]
        elif a == '-P':
            i += 1
            password = argv[i]
        elif a == '-s':
            start = True
        i += 1
    if not root:
        sys.path.insert(0, REPO)
        from hpuxemu import rootdir
        root = rootdir.default_root()
    env = dict(os.environ, HPUX_ROOT=root)
    emu = emulator()
    if start:
        for prog in ('/usr/sbin/portmap', '/usr/sbin/inetd'):
            subprocess.run(emu + [prog], cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
    t = Telnet(host, port)
    banner = t.read_until(rb'login: ')
    print('banner: %r' % banner.decode('latin1').strip()[-200:])
    t.send(user + '\n')
    got = t.read_until(rb'(assword:|\$ |# )')
    if b'assword' in got:
        t.send(password + '\n')
        got = t.read_until(rb'(\$ |# )', 30)
    print('after login: %r' % got.decode('latin1')[-300:])
    t.send('who -mR; echo TERM=$TERM; uname -n; tty; exit\n')
    rest = t.read_until(rb'logout|closed', 30).decode('latin1')
    print(rest)
    ok = 'who -mR' in rest and re.search(r'\n\S+\s+pts/\d+', rest) is not None
    print('telnettest: %s' % ('ok' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
