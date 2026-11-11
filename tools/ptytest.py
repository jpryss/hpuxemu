#!/usr/bin/env python3
"""Drive an interactive guest shell on a pseudo-terminal and check what it does with
job control and terminal signals.

    python3 tools/ptytest.py [-r ROOT] [--cpu rust|python] [--shell /usr/bin/sh] [-v]

Each step sends keystrokes and waits for an expected string (with a timeout); the
transcript is printed on failure or with -v."""

import os
import pty
import select
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from emucmd import emulator, default_cpu      # noqa: E402


class Term:
    def __init__(self, argv, env, verbose=False):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(REPO)
            os.execvpe(argv[0], argv, env)
        self.buf = b''
        self.verbose = verbose
        self.log = b''

    def expect(self, text, timeout=20):
        want = text.encode()
        end = time.time() + timeout
        while True:
            i = self.buf.find(want)
            if i >= 0:
                self.buf = self.buf[i + len(want):]
                return True
            left = end - time.time()
            if left <= 0:
                return False
            r, _, _ = select.select([self.fd], [], [], min(left, 1))
            if r:
                try:
                    d = os.read(self.fd, 4096)
                except OSError:
                    return False
                if not d:
                    return False
                self.buf += d
                self.log += d
                if self.verbose:
                    sys.stdout.write(d.decode(errors='replace'))
                    sys.stdout.flush()

    def send(self, s):
        os.write(self.fd, s.encode() if isinstance(s, str) else s)

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass


def main(argv):
    root = os.environ.get('HPUX_ROOT')
    cpu = default_cpu()
    shell = '/usr/bin/sh'
    verbose = False
    i = 1
    while i < len(argv):
        if argv[i] == '-r':
            i += 1
            root = argv[i]
        elif argv[i] == '--cpu':
            i += 1
            cpu = argv[i]
        elif argv[i] == '--shell':
            i += 1
            shell = argv[i]
        elif argv[i] == '-v':
            verbose = True
        i += 1
    env = dict(os.environ)
    if root:
        env['HPUX_ROOT'] = root
    env['TERM'] = 'vt100'
    # sh names jobs from its history file, which it opens only when HISTFILE is set
    extra = ['-e', 'HISTFILE=/tmp/.sh_history_%d' % os.getpid()]
    t = Term(emulator(cpu) + ['-e', 'PS1=emu$ '] + extra + [shell, '-i'], env, verbose)
    steps = [
        ('', 'emu$ '),
        ('echo hello\r', 'hello'),
        ('', 'emu$ '),
        ('tty\r', '/dev/pts/'),
        ('', 'emu$ '),
        # Ctrl-C interrupts a foreground command and the shell survives
        ('sleep 30\r', ''),
        (b'\x03', 'emu$ '),
        ('echo after\r', 'after'),
        ('', 'emu$ '),
        # a background job, jobs, wait
        ('sleep 1 &\r', 'emu$ '),
        ('wait; echo waited\r', 'waited'),
        ('', 'emu$ '),
        # Ctrl-Z stops, fg resumes (job control)
        ('sleep 2\r', ''),
        (b'\x1a', 'emu$ '),
        ('jobs\r', 'sleep 2'),
        ('', 'emu$ '),
        ('fg\r', 'sleep 2'),
        ('', 'emu$ '),
        # a pipeline in the foreground, then exit
        ('echo a b | wc -w\r', '2'),
        ('', 'emu$ '),
        ('exit\r', ''),
    ]
    ok = True
    for send, exp in steps:
        if send:
            time.sleep(0.2)
            t.send(send)
        if exp and not t.expect(exp):
            print('FAILED waiting for %r after sending %r' % (exp, send))
            ok = False
            break
    if not ok and not verbose:
        print('--- transcript ---')
        print(t.log.decode(errors='replace'))
    t.close()
    print('ptytest: %s' % ('ok' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
