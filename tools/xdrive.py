#!/usr/bin/env python3
"""Drive the stub X server's input (tools/xstub.py -c SOCKET): move and click the
pointer, type, take a screenshot, list the windows, from a test script or by hand.

    python3 tools/xdrive.py SOCKET COMMAND...      one command per argument, e.g.
    python3 tools/xdrive.py /tmp/xs.ctl "click 100 200" "type ls\\n" "snap /tmp/a.png" windows

As a module: Drive(path).cmd('click 10 10'), .windows() -> [(wid, w, h, x, y, label)],
.wait_for('Dtpad', seconds) -> the window or None, .find('xterm')."""

import socket
import sys
import time


class Drive:
    def __init__(self, path, timeout=30):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.time() + timeout
        while True:
            try:
                self.sock.connect(path)
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.2)
        self.f = self.sock.makefile('rw')

    def cmd(self, line):
        self.f.write(line + '\n')
        self.f.flush()
        answer = self.f.readline().rstrip('\n')
        if answer.startswith('error'):
            raise RuntimeError('%s: %s' % (line, answer))
        return answer[3:]

    def windows(self):
        out = []
        for item in self.cmd('windows').split():
            wid, geom, label = item.split(',', 2)
            size, x, y = geom.split('+')
            w, h = size.split('x')
            out.append((int(wid, 16), int(w), int(h), int(x), int(y), label))
        return out

    def find(self, label):
        for win in self.windows():
            if win[5].lower() == label.lower():
                return win
        return None

    def wait_for(self, label, seconds=20):
        deadline = time.time() + seconds
        while time.time() < deadline:
            win = self.find(label)
            if win:
                return win
            time.sleep(0.5)
        return None

    def click(self, x, y, button=1):
        return self.cmd('click %d %d %d' % (x, y, button))

    def type(self, text):
        return self.cmd('type ' + text.replace('\n', '\\n').replace('\t', '\\t'))

    def key(self, name):
        return self.cmd('key ' + name)

    def snap(self, path):
        return self.cmd('snap ' + path)

    def close(self):
        self.sock.close()


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    d = Drive(argv[1], timeout=5)
    for cmd in argv[2:]:
        print(d.cmd(cmd))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
