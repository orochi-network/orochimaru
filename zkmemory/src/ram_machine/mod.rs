/// Base trait for generic type
pub mod base;
/// Define all configuration of [StateMachine](crate::machine::StateMachine) and [RawMemory](crate::memory::RawMemory)
pub mod config;
/// Define all errors of [StateMachine](crate::machine::StateMachine) and [RawMemory](crate::memory::RawMemory)
pub mod error;
/// A state machine with two instructions [Write](crate::machine::Instruction::Write) and [Read](crate::machine::Instruction::Read).
/// This machine have configurable word size and address size. This crate provide following aliases:
/// - [StateMachine256](crate::machine::StateMachine256) with 256 bits address and word size
/// - [StateMachine64](crate::machine::StateMachine64) with 64 bits address and word size
/// - [StateMachine32](crate::machine::StateMachine32) with 32 bits address and word size
pub mod machine;
/// Raw memory as a key-value store base on [RBTree](rbtree::RBTree) that mapping address to value
pub mod memory;
