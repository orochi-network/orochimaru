# An universal memory prover in Zero-Knowledge Proof

## Testing and Coverage

You can run the tests with:

```text
cargo test
```

And also check the code coverage with:

```text
$ cargo install cargo-llvm-cov
$ cargo llvm-cov --html --open
```

Right now, our code coverage is `80%`:

```text
running 17 tests
test tests::sm256_read_empty_cell ... ok
test tests::sm256_write_one_cell_read_two_cell ... ok
test tests::sm256_write_read_one_cell ... ok
test tests::sm256_write_two_cell_read_one_cell ... ok
test tests::sm32_read_empty_cell ... ok
test tests::sm32_read_prohibited_cell - should panic ... ok
test tests::sm32_write_one_cell_read_two_cells ... ok
test tests::sm32_write_read_one_cell ... ok
test tests::sm32_write_two_cells_read_one_cells ... ok
test tests::u256_arithmetic_test ... ok
test tests::u256_test ... ok
test tests::u32_register_functional ... ok
test tests::u32_stack_functional ... ok
test tests::u32_stack_overflow - should panic ... ok
test tests::u32_stack_underflow - should panic ... ok
test tests::u32_test ... ok
test tests::u64_test ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

Filename                      Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
base.rs                            18                 0   100.00%          18                 0   100.00%          54                 0   100.00%           0                 0         -
config.rs                          14                 5    64.29%           9                 4    55.56%          55                22    60.00%           0                 0         -
error.rs                           13                11    15.38%           4                 3    25.00%          13                12     7.69%           0                 0         -
lib.rs                             87                 1    98.85%          34                 0   100.00%         172                 1    99.42%           0                 0         -
machine.rs                         74                24    67.57%          25                 8    68.00%         144                25    82.64%           0                 0         -
memory.rs                          18                 2    88.89%           9                 2    77.78%          91                 4    95.60%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                             224                43    80.80%          99                17    82.83%         529                64    87.90%           0                 0         -
```

## Overview

The idea is to create an independent module that can be used by any zkVM. You might aware that the memory can be constructed as a simple state machine with `2` instructions `READ` and `WRITE`, and configurable `WORD_SIZE`. Our memory state machine is only able access the exactly `WORD_SIZE` for every executed instruction. That is, if you want to access arbitrary data size, it must be translated to multiple accesses.

These instructions need to be satisfied following conditions:

- **`READ` instruction**
  - `READ` on a memory was not wrote should return `0`
  - Every`READ` access for the same location, must have the value to be equal to the previous `WRITE`.
- **`WRITE` instruction**
  - Every `WRITE` access must write on writable memory chunks _(some areas of the memory might be read only)_.

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

## Code coverage

```text
cargo llvm-cov --html --open
```

## For more detail check `256bits-machine` example

In this example we tried to simulate a 256bits machine with 256bits word size.

```text
cargo run --example 256bits-machine.rs
```

## License

This project licensed under the [Apache License, Version 2.0](LICENSE).

_build with ❤️ and 🦀_
