//! This crate provides a simple RAM machine for use in the zkVM
#![recursion_limit = "256"]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    unused,
    warnings,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs,
    unused_imports
)]
#![forbid(unsafe_code)]

/// Base trait for generic type
pub mod base;
/// Define all configuration of [StateMachine](crate::machine::StateMachine) and [RawMemory](crate::memory::RawMemory)
pub mod config;
/// Define all errors of [StateMachine](crate::machine::StateMachine) and [RawMemory](crate::memory::RawMemory)
pub mod error;
/// Definition of abstract machine (instruction, trace and context)
pub mod machine;
/// A simple state machine used for testing and for building examples
pub mod state_machine;
/// A KZG Polynomial Commitment scheme used for the memory of the RAM
pub mod kzg;

#[cfg(test)]
mod tests {
    use crate::base::{B256, B64, B32, B128, Base};
    use crate::config::{DefaultConfig, Config, ConfigArgs};
    use crate::machine::{AbstractMachine, AbstractMemoryMachine};
    use crate::state_machine::{StateMachine, Instruction};

    #[test]
    fn u256_struct_test() {
        let chunk_zero = B256::zero();
        let bytes1 = [9u8; 32];
        let chunk1 = B256::from(bytes1);
        let bytes_convert: [u8; 32] = chunk1.try_into().unwrap();
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());
    }

    #[test]
    fn u256_arithmetic_test() {
        let chunk_1 = B256::from([34u8; 32]);
        let chunk_2 = B256::from([17u8; 32]);
        let chunk_3 = B256::from(5);
        let chunk_4 = B256::from(156);
        assert_eq!(chunk_1 + chunk_2, B256::from([51u8; 32]));
        assert_eq!(chunk_1 - chunk_2, B256::from([17u8; 32]));
        assert_eq!(chunk_4 * chunk_3, B256::from(156 * 5));
        assert_eq!(chunk_4 / chunk_3, B256::from(156 / 5));
        assert_eq!(chunk_4 % chunk_3, B256::from(156 % 5));
    }

    #[test]
    fn sm256_write_read_one_cell() {
        // Test sm256 write to one cell
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        let chunk = B256::from([8u8; 32]);
        let base_addr = sm256.base_address();
        let write_addr = base_addr + B256::from(96);
        sm256.exec(&Instruction::Write(write_addr, chunk));
        let read_result = sm256.dummy_read(write_addr);
        assert_eq!(chunk, read_result);
    }

    #[test]
    fn sm256_read_empty_cell() {
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        let chunk = B256::zero();
        let base_addr = sm256.base_address();
        let read_result = sm256.dummy_read(base_addr);
        assert_eq!(chunk, read_result);
    }

    #[test]
    fn sm256_write_read_two_cells() {
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        let chunk_hi = [132u8; 18];
        let chunk_lo = [7u8; 14];
        let base_addr = sm256.base_address();
        let write_addr = base_addr + B256::from(78);
        let write_chunk: [u8; 32] = [chunk_hi.as_slice(), chunk_lo.as_slice()]
                                    .concat()
                                    .try_into()
                                    .unwrap();
        let expected_hi: [u8; 32] = [[0u8; 14].as_slice(), chunk_hi.as_slice()]
                                    .concat()
                                    .try_into()
                                    .unwrap();
        let expected_lo: [u8; 32] = [chunk_lo.as_slice(), [0u8; 18].as_slice()]
                                    .concat()
                                    .try_into()
                                    .unwrap();
        sm256.exec(&Instruction::Write(B256::from(write_addr), B256::from(write_chunk)));
        sm256.exec(&Instruction::Read(base_addr + B256::from(78)));
        let read_chunk_hi = sm256.dummy_read(base_addr + B256::from(64));
        let read_chunk_lo = sm256.dummy_read(base_addr + B256::from(96));
        assert_eq!(B256::from(expected_hi), read_chunk_hi);
        assert_eq!(B256::from(expected_lo), read_chunk_lo);
    }

    /// This test is not completed yet
    #[test]
    #[should_panic]
    fn sm256_read_prohibited_cell() {
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        sm256.show_sections_maps();
        sm256.exec(&Instruction::Read(B256::from(32784)));
    }

    #[test]
    fn sm256_stack_functional_test() {
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        //let base_addr = sm256.base_address();
        sm256.exec(&Instruction::Push(B256::from([8u8; 32])));
        assert_eq!(sm256.get_stack_depth(), 1);
        sm256.exec(&Instruction::Push(B256::from([19u8; 32])));
        assert_eq!(sm256.get_stack_depth(), 2);
        sm256.exec(&Instruction::Push(B256::from([109u8; 32])));
        assert_eq!(sm256.get_stack_depth(), 3);
        sm256.exec(&Instruction::Pop(B256::from(1)));
        assert_eq!(sm256.get_stack_depth(), 2);
    }

    #[test]
    #[should_panic]
    fn sm256_stack_underflow() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        sm.exec(&Instruction::Pop(sm.base_address()));
    }

    #[test]
    #[should_panic]
    fn sm256_stack_overflow() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        for _ in 0..1024 {
            sm.exec(&Instruction::Push(B256::from(1)));
        }
        assert_eq!(sm.get_stack_depth(), 1024);
        sm.exec(&Instruction::Push(B256::from(1)));
        
    }

    #[test]
    fn sm256_register_memory_functional_test() {

        // Resigter - Memory test
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        let base_addr = sm256.base_address();
        sm256.exec(&Instruction::Write(base_addr, B256::from(12880)));
        sm256.exec(&Instruction::Load(sm256.r0, base_addr));
        sm256.exec(&Instruction::Save(base_addr + B256::from(32), sm256.r0));
        let read_chunk = sm256.dummy_read(base_addr + B256::from(32));
        assert_eq!(read_chunk, B256::from(12880));
    }

    #[test]
    fn sm256_register_register_functional_test() {

        // Resigter - Register test
        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        let base_addr = sm256.base_address();
        sm256.exec(&Instruction::Write(base_addr, B256::from(12880)));
        sm256.exec(&Instruction::Write(base_addr + B256::from(32), B256::from(87120)));
        sm256.exec(&Instruction::Load(sm256.r0, base_addr));
        sm256.exec(&Instruction::Load(sm256.r1, base_addr + B256::from(32)));
        sm256.exec(&Instruction::Add(sm256.r0, sm256.r1));
        sm256.exec(&Instruction::Mov(sm256.r3, sm256.r0));
        sm256.exec(&Instruction::Save(base_addr + B256::from(64), sm256.r3));
        let read_chunk = sm256.dummy_read(base_addr + B256::from(64));
        assert_eq!(read_chunk, B256::from(100000));
    }

    #[test]
    fn sm256_register_stack_functional_test() {

        let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
        let chunk = B256::from([85u8; 32]);
        let base_addr = sm256.base_address();
        sm256.exec(&Instruction::Push(chunk));
        sm256.exec(&Instruction::Swap(sm256.r0));
        sm256.exec(&Instruction::Save(base_addr, sm256.r0));
        let read_chunk = sm256.dummy_read(base_addr);
        assert_eq!(read_chunk, chunk);
    }

    #[test]
    fn u128_struct_test() {
        let chunk_zero = B128::zero();
        let bytes1 = [9u8; 16];
        let chunk1 = B128::from(bytes1);
        let bytes_convert: [u8; 16] = chunk1.try_into().unwrap();
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());
    }

    #[test]
    fn u128_arithmetic_test() {
        let chunk_1 = B128::from([19u8; 16]);
        let chunk_2 = B128::from([5u8; 16]);
        let chunk_3 = B128::from(7i32);
        let chunk_4 = B128::from(34u64);
        assert_eq!(chunk_1 + chunk_2, B128::from([24u8; 16]));
        assert_eq!(chunk_1 - chunk_2, B128::from([14u8; 16]));
        assert_eq!(chunk_4 * chunk_3, B128::from(34 * 7));
        assert_eq!(chunk_4 / chunk_3, B128::from(34 / 7));
        assert_eq!(chunk_4 % chunk_3, B128::from(34 % 7));
    }


    #[test]
    fn u64_struct_test() {
        let chunk_zero = B64::zero();
        let bytes1 = [1u8; 8];
        let chunk1 = B64::from(bytes1);
        let bytes_convert: [u8; 8] = chunk1.try_into().unwrap();
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());
    }

    #[test]
    fn u64_arithmetic_test() {
        let chunk_1 = B64::from([61u8; 8]);
        let chunk_2 = B64::from([16u8; 8]);
        let chunk_3 = B64::from(12);
        let chunk_4 = B64::from(99);
        assert_eq!(chunk_1 + chunk_2, B64::from([77u8; 8]));
        assert_eq!(chunk_1 - chunk_2, B64::from([45u8; 8]));
        assert_eq!(chunk_4 * chunk_3, B64::from(99 * 12));
        assert_eq!(chunk_4 / chunk_3, B64::from(99 / 12));
        assert_eq!(chunk_4 % chunk_3, B64::from(99 % 12));
    }

    #[test]
    fn u32_struct_test() {
        let chunk_zero = B64::zero();
        let bytes1 = [59u8; 8];
        let chunk1 = B64::from(bytes1);
        let bytes_convert: [u8; 8] = chunk1.try_into().unwrap();
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());
    }

    #[test]
    /// The testcases above already covered Add, Sub and Rem. This test case covers Div
    fn u32_arithmetic_test() {
        let chunk_1 = B32::from([34u8; 4]);
        let chunk_2 = B32::from([17u8; 4]);
        let chunk_3 = B32::from(5);
        let chunk_4 = B32::from(156);
        assert_eq!(chunk_1 + chunk_2, B32::from([51u8; 4]));
        assert_eq!(chunk_1 - chunk_2, B32::from([17u8; 4]));
        assert_eq!(chunk_4 * chunk_3, B32::from(156 * 5));
        assert_eq!(chunk_4 / chunk_3, B32::from(156 / 5));
        assert_eq!(chunk_4 % chunk_3, B32::from(156 % 5));
    }

    #[test]
    fn ram_size_test() {

        // Test default config
        let default_config = Config::new(B256::from(32), DefaultConfig::default());
        assert_eq!(default_config.calc_ram_size(), B256::MAX);

        // Test custom config
        let config = Config::<B256, 32>::new_custom(
            B256::from(32), 
            ConfigArgs {
            head_layout: false,
            stack_depth: B256::from(1024),
            no_register: B256::from(32),
            buffer_size: B256::from(32)
        }, B256::from(32));

        assert_eq!(config.calc_ram_size(), B256::from(34880));
    }
}
