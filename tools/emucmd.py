#!/usr/bin/env python3
"""emucmd.py - the emulator's command line, for the tools.

    python3 tools/emucmd.py [bin|rust|python]      prints it (for shell scripts)

'bin' is the Rust emulator (rust/hpuxemu: $HPUXEMU, else its release build), 'rust' the
Python emulator on the Rust CPU, 'python' the Python emulator on its own CPU. Without
an argument: the Rust emulator when it is built (or $HPUXEMU names one), else 'rust';
HPUXEMU=python keeps the Python emulator."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILT = os.path.join(REPO, 'rust', 'hpuxemu', 'target', 'release', 'hpuxemu')


def default_cpu():
    b = os.environ.get('HPUXEMU')
    if b == 'python':
        return 'rust'
    return 'bin' if b or os.path.exists(BUILT) else 'rust'


def emulator(cpu=None):
    cpu = cpu or default_cpu()
    if cpu == 'bin':
        b = os.environ.get('HPUXEMU')
        return [b if b and b != 'python' else BUILT]
    return [sys.executable, '-m', 'hpuxemu.emu', '--cpu', cpu]


if __name__ == '__main__':
    print(' '.join(emulator(sys.argv[1] if len(sys.argv) > 1 else None)))
