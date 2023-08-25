# An universal memory prover in Zero-Knowledge Proof

## Overview

The idea is to create an independent module that can be used by any zkVM. You might aware that the memory can be constructed as a simple state machine with $2$ instructions `READ` and `WRITE`, and configurable `WORD_SIZE`. Our memory state machine is only able access the exactly `WORD_SIZE` for every executed instruction. That is, if you want to access arbitrary data size, it must be translated to multiple accesses.

These instructions need to be satisfied following conditions:

- **`READ` instruction**
  - `READ` on a memory was not wrote should return `0`
  - Every`READ` access for the same location, must have the value to be equal to the previous `WRITE`.
- **`WRITE` instruction**
  - Every `WRITE` access must write on writable memory chunks _(some areas of the memmory might be read only)_.

## Features

### Configurable Word Size

For now we support `U256`, `u64`, and `u32` word size.

- `U256` word size with this feature it can be generate the execution trace for the following for zkEVM.
- `u64` and `u32` word size allow us to emulate wide range of VM namely RISC-V, x86, ARM, etc.

### Simulate Stack

## Memory Layout
