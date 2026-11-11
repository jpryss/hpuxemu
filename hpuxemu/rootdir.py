"""rootdir.py - where the HP-UX root is when none is given: $HPUX_ROOT, else ./hpuxroot,
else ../hpuxroot, else `hpuxroot` next to this repository, else inside it."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def default_root():
    env = os.environ.get('HPUX_ROOT')
    if env:
        return env
    for cand in ('hpuxroot', '../hpuxroot', os.path.join(os.path.dirname(REPO), 'hpuxroot'),
                 os.path.join(REPO, 'hpuxroot')):
        if os.path.isdir(cand):
            return os.path.abspath(cand)
    return os.path.join(os.path.dirname(REPO), 'hpuxroot')
