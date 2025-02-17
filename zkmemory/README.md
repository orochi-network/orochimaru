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

Right now, our code line coverage is `96.10%`:

```text
running 86 tests
test constraints::original_memory_circuit::tests::also_test_invalid_time_order - should panic ... ok
test constraints::original_memory_circuit::tests::test_identical_trace - should panic ... ok
test constraints::original_memory_circuit::tests::test_invalid_time_order - should panic ... ok
test constraints::original_memory_circuit::tests::test_multiple_traces ... ok
test constraints::original_memory_circuit::tests::test_one_trace ... ok
test constraints::original_memory_circuit::tests::test_wrong_starting_time - should panic ... ok
test constraints::permutation_circuit::tests::check_permutation_with_trace_records ... ok
test constraints::permutation_circuit::tests::check_trace_record_mapping ... ok
test constraints::permutation_circuit::tests::check_wrong_permutation - should panic ... ok
test constraints::permutation_circuit::tests::test_functionality ... ok
test constraints::permutation_circuit::tests::test_inequal_lengths - should panic ... ok
test constraints::sorted_memory_circuit::test::equal_address_and_time_log - should panic ... ok
test constraints::sorted_memory_circuit::test::invalid_read - should panic ... ok
test constraints::sorted_memory_circuit::test::invalid_read2 - should panic ... ok
test constraints::sorted_memory_circuit::test::invalid_read3 - should panic ... ok
test constraints::sorted_memory_circuit::test::non_first_write_access_for_two_traces - should panic ... ok
test constraints::sorted_memory_circuit::test::test_error_invalid_instruction - should panic ... ok
...

test result: ok. 85 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6738.79s

```

| Filename | Function Coverage | Line Coverage | Region Coverage |
| :---: | :---: | :---: | :---: |
| poseidon/src/circuit.rs | 78.79 \%(52/66) | 82.55 \%(388/470) | 79.33 \%(165/208)|
| poseidon/src/gadgets.rs | 80.70 \%(46/57) | 91.54 \%(292/319) | 81.10 \%(133/164)|
| poseidon/src/poseidon hash.rs | 92.00 \%(23/25) | 87.68 \%(178/203) | 92.05 \%(81/88) |
| zkmemory/src/base.rs | 100.00% (30/30) | 100.00% (94/94) | 100.00% (30/30) |
| zkmemory/src/commitment/extends.rs | 100.00% (2/2) | 100.00% (17/17) | 100.00% (6/6) |
| zkmemory/src/commitment/kzg.rs | 95.83% (23/24) | 99.45% (364/366) | 94.52% (69/73) |
| zkmemory/src/commitment/merkle tree.rs | 84.06% (58/69) | 96.33% (473/491) | 84.83% (151/178) |
| zkmemory/src/commitment/verkle tree.rs | 85.71% (48/56) | 96.37% (478/496) | 84.93% (124/146) |
| zkmemory/src/config.rs | 100.00% (10/10) | 100.00% (117/117) | 100.00% (31/31) |
| zkmemory/src/constraints/consistency check circuit.rs | 80.00% (4/5) | 96.97% (96/99) | 82.61% (19/23) |
| zkmemory/src/constraints/gadgets.rs | 95.24% (40/42) | 99.40% (331/333) | 95.41% (104/109) |
| zkmemory/src/constraints/helper.rs | 100.00% (13/13) | 99.70% (336/337) | 94.74% (18/19) |
| zkmemory/src/constraints/original memory circuit. rs | 69.23% (27/39) | 95.87% (325/339) | 76.56 \%(98/128) |
| zkmemory/src/constraints/permutation circuit.rs | 83.33% (35/42) | 97.09% (334/344) | 84.85% (112/132) |
| zkmemory/src/constraints/sorted memory circuit.rs | 75.81% (47/62) | 97.01% (551/568) | 80.54% (149/185) |
| zkmemory/src/error.rs | 100.00% (2/2) | 100.00% (34/34) | 100.00% (17/17) |
| zkmemory/src/lib.rs | 100.00% (4/4) | 100.00% (119/119) | 100.00% (47/47) |
| zkmemory/src/machine.rs | 100.00% (48/48) | 96.98% (545/562) | 90.30% (149/165) |
| zkmemory/src/nova/memory consistency circuit.rs | 71.05% (27/38) | 94.95% (207/218) | 89.11% (90/101) |
| zkmemory/src/nova/poseidon parameters.rs | 100.00% (4/4) | 100.00% (16/16) | 100.00% (4/4) |
| zkmemory/src/nova/testcases.rs | 100.00% (12/12) | 100.00% (513/513) | 100.00% (37/37) |
| zkmemory/src/supernova/memory consistency circuit.rs | 75.00% (42/56) | 95.79% (341/356) | 89.80% (132/147) |
| zkmemory/src/supernova/poseidon_parameter.rs | 100.00% (4/4) | 100.00% (16/16) | 100.00% (4/4) |
| zkmemory/src/supernova/testcases.rs | 100.00% (7/7) | 99.69% (318/319) | 97.62% (41/42) |
| Totals | 84.91% (608/716) | 96.10% (6483/6746) | 86.90% (1811/2084) |

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
