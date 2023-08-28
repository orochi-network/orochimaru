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

### Memory Layout

The memory layout is configurable with `ConfigArgs::head_layout`, the `buffer` was used to prevent the memory access out of bound. The `buffer` size is configurable with `ConfigArgs::buffer_size`.

Head layout:

```text
┌──────────────────┐ ┌──────┐ ┌──────────────────┐ ┌──────┐ ┌──────────────────┐
│  Stack Section   │ │Buffer│ │ Register Section │ │Buffer│ │  Memory Section  │
└──────────────────┘ └──────┘ └──────────────────┘ └──────┘ └──────────────────┘
```

Tail layout:

```text
┌──────────────────┐ ┌──────┐ ┌──────────────────┐ ┌──────┐ ┌──────────────────┐
│  Memory Section  │ │Buffer│ │  Stack Section   │ │Buffer│ │ Register Section │
└──────────────────┘ └──────┘ └──────────────────┘ └──────┘ └──────────────────┘
```

### Simulate Stack

```text
                 ┌─────────┐
               ┌─┤Stack Ptr│
               │ └─────────┘
               │
┌───────────┐ ┌▼──────────┐ ┌───────────┐
│Memory Cell│ │Memory Cell│ │Memory Cell│
└───────────┘ └───────────┘ └───────────┘
```

We use memory cell and stack pointer to simulate the stack. We defined two new instruction to simulate the stack `PUSH` and `POP`.

- The `PUSH` instruction will write the value to the memory cell pointed by the stack pointer, and then increment the stack pointer.
- The `POP` instruction will decrement the stack pointer, and then read the value from the memory cell pointed by the stack pointer.

These two instructions should be consider as aliases of `WRITE` and `READ` instructions, the differences are these read and write are always happen on the stack memory area and bound to `stack_depth` and `stack_ptr`.

### Simulate Register

An section of memory will be reserved to simulate the register. Each memory cell will be mapped to a register by method `RegisterMachine::register(register_index);`.

```rust
/// Register Machine with 3 simple opcodes (mov, set, get)
pub trait RegisterMachine<K, V, const S: usize>
where
    K: Base<S>,
{
    /// Get address for a register
    fn register(&self, register_index: usize) -> Result<Register<K, S>, Error>;
    /// Move a value from one register to another
    fn mov(&mut self, to: Register<K, S>, from: Register<K, S>) -> Result<(), Error>;
    /// Set a value to a register
    fn set(&mut self, register: Register<K, S>, value: V) -> Result<(), Error>;
    /// Read a value from a register
    fn get(&mut self, register: Register<K, S>) -> Result<V, Error>;
}
```

## For more detail check `64bits-machine` example

In this example we tried to simulate a 64bits machine with 64bits word size with 4 registers (`r0`, `r1`, `r2`, `r3`).

```text
cargo run --example 64bits-machine
```
