# Measurements

All numbers from one machine: a virtual machine with two cores of an Intel Xeon at
2.1 GHz, Linux 6.18, Python 3.13, Rust 1.97, built with `--release`. They are wall-clock
times, the best of a few runs, repeatable to about 10%.

## The CPU core

`rust/hppa32-jit/examples/bench.rs` runs a hand-assembled six-instruction loop (add,
load, add, store, compare-and-branch, add in the delay slot) with no system calls:

| CPU | rate |
|---|---|
| Rust, JIT (the default) | 2,080 M instructions/s |
| Rust, interpreted | 110 M instructions/s |
| Python (`hpuxemu/cpu.py`) | 0.6 M instructions/s |

(`cargo run --release --example bench 30000000` interprets; `BENCH_JIT=10,64` in the
environment turns the JIT on.)

`examples/bench.c`, a loop of integer arithmetic, byte loads, and a double-precision
division every eighth iteration, compiled with HP's bundled `cc` inside the emulator;
20 million iterations are 2.46 billion PA-RISC instructions:

| CPU | time | rate |
|---|---|---|
| Rust, JIT | 1.7 s | 1,450 M instructions/s |
| Rust, interpreted (`HPUXEMU_JIT=off`) | 27.1 s | 91 M instructions/s |

For scale, the HP 9000/715 workstations of 1993-95 ran their 50-100 MHz PA-7100 at
roughly as many instructions per second as the interpreter does here: without the JIT
programs feel much as they did on the hardware they were written for, and with it
CPU-bound ones run an order of magnitude faster.

## Programs

Whole commands, including process start-up (loading `dld.sl` and `libc.1`: about
250,000 instructions before `main`), on the emulator (`rust/hpuxemu`) and on the Python
reference emulator with the same CPU crate:

| command | hpuxemu | Python emulator |
|---|---|---|
| `/usr/bin/true`, `uname -a` | 4 ms | 37 ms |
| `ls -l /usr/bin` (about 400 entries) | 25 ms | 75 ms |
| `man ls` (`nroff`) | 0.12 s | 0.19 s |
| `find /usr/lib -name '*.sl' \| wc -l` | 0.05 s | 0.30 s |
| `cc -o bench bench.c` (the compiler, then `ld`) | 0.06 s | 0.12 s |
| a million system calls (`getpid`, `lseek`+`read`, `stat`) | 0.33 s | 3.8 s |
| `tools/sweep.py` (66 commands, several of them compiling) | 7 s | 10 s |

A host `/bin/true` takes 1 ms on this machine, so the emulator adds 3 ms to a short
command: the 4 GB address space reservation, and `dld.sl` bringing in libc.

What decides the speed of a large application's start is usually `dld.sl` binding its
libraries' symbols; the routines it spends that time in run natively
([DESIGN.md](DESIGN.md) §5, `HPUXEMU_NATIVE=0` to compare without).

## The root build

`build.py` on the two 10.20 CD images (`.iso` files on local disk): 71 s for the core
CD alone (274 filesets, 400 MB), a few minutes with the OS enhancements CD, the 88 ACE
patches and the control scripts (304 filesets, 475 MB). `python3 -m hpuxemu.adopt` on a
470 MB tar or cpio archive of a machine takes a few seconds.

## Where a program's time goes

Set `HPUXEMU_STATS` to a file and every emulated process appends where its time went
(host CPU, time inside the guest CPU, each system call, PC samples, the JIT's counters);
`tools/stats.py` sums it up:

    $ HPUXEMU_STATS=/tmp/run.jsonl hpuxemu /usr/bin/sh -c 'cc -o /tmp/bench /tmp/bench.c'
    $ python3 tools/stats.py /tmp/run.jsonl --dld ../hpuxroot/usr/lib/dld.sl
