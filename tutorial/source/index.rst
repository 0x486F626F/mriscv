.. role:: author

Minimum RISC-V System From Scratch
==================================

:author:`Ted Yin`

So, we'll make a RISC-V system! It may sound "mission impossible" to build this
kind of thing from scratch in a relatively short time, without prior background
in hardware designs.  But it really isn't as magical as it seems. I hope this
tutorial could serve as a tiny but inspiring guide to those programmers who
know little about hardware like I did to have a better understanding of how a
computer system works from the ground up, and for those who know a bit about
different pieces of the story but can't put them together.

Nothing is better than having a playable example that is both small and
functional.  This repo already contains a RISC-V processor core implementation
that is synthesizable by itself, but also directly works with a minimal
emulator (Verilator-based) code with a realistic system setup. The processor
implements RV32I instruction set with major part of CSR Mode-M, while the
emulator emulates the cache/memory, serial console output, video output and
keyboard input. The applications are built with standard gcc/Rust RISC-V
toolchains and directly run on the processor.

The whole repo is simply divided into three parts:

- Processor core implementation in SystemVerilog: `core.sv`_ (1.2K loc) and
  `csr.sv`_ (182 loc).

- System emulator: `sim.cpp`_ (423 loc).

- Example applications that directly runs on ``sim``: ``apps/*.c`` and
  ``apps/mriscv-rs/examples/*.rs``.

This tutorial is organized in two parts: the implementation of the processor
core with SystemVerilog and the building of the final system/applications.

.. include:: processor.rst
.. include:: system.rst

.. _core.sv: https://github.com/Determinant/mriscv/blob/main/core.sv
.. _csr.sv: https://github.com/Determinant/mriscv/blob/main/csr.sv
.. _sim.cpp: https://github.com/Determinant/mriscv/blob/main/sim.cpp
