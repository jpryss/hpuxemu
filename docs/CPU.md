# The CPU: model, fuzzer, and the undefined corners

Two interpreters implement the same PA-RISC model: `hpuxemu/cpu.py` (Python, the
reference, written to be read) and `rust/hppa32-jit` (Rust, the one to run). This file is
their shared specification, the way they are checked against each other, and the
decisions taken where the architecture leaves a result undefined - which both
implement identically, so that a program's behaviour does not depend on the CPU chosen.

## 1. The model

**Instruction set**: PA-RISC 1.1 as a user program sees it, plus the PA 2.0
instructions a 32-bit program may use (the `,dw`/`,*` doubleword forms of the
arithmetic and compare instructions, `extrd`/`depd`/`shrpd`, `ldd`/`std`, `bve`,
`mtsarcm`, `fmpyfadd`/`fmpynfadd`, `fid`). The decoder (`decode.py`, `decode.rs`)
follows QEMU's `translate.c` for hppa in structure and names each instruction class
after the corresponding `trans_*` function, so that the three can be read side by side;
it was checked against the GNU assembler's hppa test suite (`tools/test_decode.py`:
2,305 instructions from binutils' `gas/testsuite/gas/hppa/basic`, the disassembler's
output compared with the source lines; the 497 residual differences are spelling -
symbolic branch targets, PA 2.0 completer names, the quad formats and the system,
coprocessor and multimedia instructions a user-mode emulator leaves undecoded - and
the test fails on anything else).

**Registers**: 32 general registers of 64 bits (PA 2.0 width; a 32-bit program only
ever sees the low 32 bits, and the doubleword instructions are available to it), 32
floating-point registers of 64 bits where `frXL` is the high word and `frXR` the low
word, the shift amount register `sar`, and the instruction queue `iaoq_f`/`iaoq_b`
(front and back: the current instruction and the next; a branch sets the back entry,
which is how the delay slot comes about) with the privilege level in the low two bits
(always 3). Of the PSW only the bits a user program can observe are kept: the nullify
bit `psw_n`, and the carry/borrow bits, held as QEMU does in `psw_cb` (bit k set when
there was a carry into bit k of the last arithmetic result) and `psw_cb_msb` (the carry
out of the top), plus `psw_v` for `ds` (divide step). Control registers: `cr11` is sar,
`cr26`/`cr27` are readable and writable (thread pointers), `cr16` (the interval timer)
reads the instruction count; the rest are privileged.

**Space registers** are not modelled: `mfsp` gives 0, `mtsp` does nothing, `ldsid`
gives 0, and every space is the same flat 32-bit address space.

**Memory**: 4 GB with a protection byte (read/write/execute) per 4 KB page. The Rust
CPU reserves 4 GB of host address space and maps pages as the guest does, checking the
protection byte before each access, so that a fault is reported with the exact address
and without any host signal handling; the Python CPU keeps a dictionary of pages.
Unaligned loads and stores are allowed (the HP-UX kernel would fix them up; nothing
in the tested programs needs the trap), except `ldcw`, which must be aligned to its
size and faults as a *write* when the word is not writable.

**Execution**: `run(max)` interprets until a system call (the pc reaches the gateway
page at 0xC0000000), a fault, `break`, an illegal or privileged instruction, a
conditional trap, an overflow trap (`,tsv`), a hook address, or the instruction budget.
Nullification follows the architecture: a conditional branch nullifies the delay slot
when taken forward or not taken backward with `,n`; an unconditional branch with `,n`
always; the arithmetic instructions' conditions nullify the next instruction. The
link register of a branch is `iaoq_b + 4`. `gr0` reads as zero whatever is written.

## 2. The differential fuzzer

`tools/fuzz.py` is how the two implementations and the JIT are kept the same:

    python3 tools/fuzz.py -n 1000000 -j 8          # a million sequences on 8 cores
    python3 tools/fuzz.py -n 10000 --only fcnv,fcmp  # one instruction class
    python3 tools/fuzz.py -n 5000 --write vectors.jsonl   # record the reference's results
    python3 tools/fuzz.py --check vectors.jsonl           # replay them on the Rust CPU

Each sequence is 2 to 7 random instruction words that decode to user-level
instructions (no system control, no `break`, no register-indirect branches, whose
targets would leave the code page), placed at 0x1800 in a page of `nop`s, with every
general register, floating-point register, `sar` and the carry bits random and a 64 KB
data page of random contents. Register values are biased: a third are addresses into
the data page (so that loads and stores hit), some are small, some 32-bit, some 64-bit
patterns, some the extreme values; floating-point registers get doubles, pairs of
singles, integers, the special values (zeros, infinities, NaNs of both kinds, 2^52
boundaries). The generator balances the instruction classes (it keeps counts and
rejects a word whose class is far ahead of the median), builds the floating-point
formats from fields because their many must-be-zero bits make random words miss them,
and keeps branch displacements inside the page. Both CPUs run the sequence for at most
12 instructions (so loops end), and then the exit, every register, `psw_n`, the carry
bits, `psw_v`, `sar`, the instruction queue and the whole data page must agree.

The bar for a change to the CPU is a million sequences without a difference (seed 100
takes 430 s on two cores).

The `--write` file has one JSON object per line: `pa20`, `code` (the address), `words`
(hex), `max_steps`, `in` (`gr`, `fr`, `sar`, `psw_cb`, `psw_cb_msb`, `psw_v` and
`data_seed`: the data page is block i = SHA-256 of the 8 bytes seed, i, both 32-bit
big-endian, for i = 0..2047) and `out` (the same plus `psw_n`, `iaoq_f`, `iaoq_b`, the
`exit` and `data_diff`, the 8-byte words that changed). This is what to run against
QEMU's hppa or any other implementation.

## 3. Where the architecture leaves things open

These are the choices, taken from QEMU's hppa target where it has one, so that a
program sees the same thing it would under QEMU:

- **Floating-point NaNs**: PA-RISC's signalling NaN has the fraction's most significant
  bit *set*; quieting one clears it and sets the next bit. An operation with NaN
  operands returns the first signalling one quieted, else the first NaN; an operation
  that creates a NaN (0×∞, ∞−∞, √−1) returns the *default NaN* 0x7FF4000000000000
  (single: 0x7FA00000). No exceptions are raised; the status register's flags are not
  set.
- **Float to integer** (`fcnv,t`, `fcnv` with rounding): a NaN gives the maximum
  integer; infinities and out-of-range values saturate; a negative value converted to
  unsigned gives 0. `fcnv` without `,t` rounds to nearest-even.
- **Fused multiply-add**: the product is exact; only an infinite operand makes it
  infinite, so (huge × huge) + (−∞) is −∞, not NaN. The result is rounded once in the
  target precision (the Python CPU computes it exactly with rationals and rounds
  itself; Rust uses the host's `mul_add`).
- **Single-precision arithmetic** is done in single precision (not in double and
  rounded, which would differ for the fused operations).
- **`extrw`/`depw` with a length past the word**: the length is clipped to the word.
- **`shrpw` with the same register twice** is a rotate.
- **`ldcw` on an unaligned address** traps (the "unaligned" exit); it faults as a
  write when the page is not writable.
- **`mfctl` of a register other than sar, cr16, cr26, cr27** and `mtctl` of anything
  but sar are privileged (the "priv" exit, which the OS layer turns into SIGILL).
- **`probe`** answers from the page protection bytes.
- **`fid`** sets the status register's model and revision to 0x000F0800 (a PA 1.1
  FPU; 0x00130800 in PA 2.0 mode).
- **`break`** with any immediates ends the run (the OS layer makes it SIGTRAP).
- **`fmpyadd`/`fmpysub`'s format bit** (bit 5) is 1 for single precision, as HP's
  assembler encodes `,sgl` (the gas test suite and binutils' disassembler agree);
  QEMU's `insns.decode` has it inverted. In the single form the five-bit register
  fields mean fr16-fr31 with the field's top bit selecting the right half
  (`(r & 16) * 2 + 16 + (r & 15)`).

The cache flushes a user program may issue (`fdc`, `fdce`, `fic`, `fice`, `pdc`) are
no-ops but for the base register update of their `,m` forms: the emulator has no
caches, and code it has written is fetched afresh. `fic` and `fice` in their
instruction-space form have a 3-bit space field (bits 16-18) and the opcode in bits
19-25.

Not emulated at all: the PSW's other bits, interrupts, TLB, caches, the privilege
levels (everything runs at level 3 and the gateway page is the only crossing), and
the space registers.

## 4. Speed

The Rust interpreter runs about 100 million instructions per second on one core of a
2.1 GHz Xeon (`cargo run --release --example bench` in `rust/hppa32-jit` runs a
hand-assembled six-instruction loop; `tools/sweep.py` and the compiler tests are the
real-program measure); the Python one about 1 million. Numbers in
[BENCHMARK.md](BENCHMARK.md).

The JIT (DESIGN.md §5) runs the same loop at about 2,000 million instructions per
second, twenty times the interpreter. Its correctness rests on the fuzzers: `tools/fuzz.py --jit N`
compiles each sequence's first block at once (at most N instructions, so that blocks of
every length, hand-overs mid-block and nullification across the block's end all occur)
and compares it with the Python CPU as always, with lengths 2-12 and in PA 2.0 mode. The
crate has a fuzzer of its own as well (`rust/hppa32-jit/examples/fuzz.rs`, the JIT against
the Rust interpreter, no Python needed; `cargo test` runs a short one), whose registers
also point into the code being run. The sweeps compare the
Rust CPU, JIT included, with the Python one on whole programs; `HPUXEMU_JIT=0,64`
compiles nearly everything and is the hard setting to run them with. Shapes that random
sequences rarely produce get a run of their own: `--only` with a list of instruction
classes (the branches alone put a branch in a delay slot in most sequences; the
floating-point classes alone exercise NaNs and conversions out of range).

`HPPA_JIT_TRACE=1` (in the environment) makes a process print, when it exits, the 25
addresses the interpreter executed most often while the JIT was on: what the compiler
refused or handed over. That is where to look before compiling more.
