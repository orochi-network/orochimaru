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
pub mod simple_state_machine;

#[cfg(test)]
mod tests {
    use crate::base::{B256, B64, B32, B128, Base};
    use crate::config::DefaultConfig;
    use crate::machine::{AbstractMachine, AbstractMemoryMachine};
    use crate::simple_state_machine::{StateMachine, Instruction};
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
        sm256.exec(&Instruction::Read(B256::from(32784)));
    }

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
        let chunk_3 = B128::from(7);
        let chunk_4 = B128::from(34);
        assert_eq!(chunk_1 + chunk_2, B128::from([24u8; 16]));
        assert_eq!(chunk_1 - chunk_2, B128::from([14u8; 16]));
        assert_eq!(chunk_4 * chunk_3, B128::from(34 * 7));
        assert_eq!(chunk_4 / chunk_3, B128::from(34 / 7));
        assert_eq!(chunk_4 % chunk_3, B128::from(34 % 7));
    }


    #[test]
    fn u64_struct_test() {
        let chunk_zero = B64::zero();
        let bytes1 = [9u8; 8];
        let chunk1 = B64::from(bytes1);
        let bytes_convert: [u8; 8] = chunk1.try_into().unwrap();
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());
    }

    #[test]
    fn u64_arithmetic_test() {
        let chunk_1 = B64::from([34u8; 8]);
        let chunk_2 = B64::from([17u8; 8]);
        let chunk_3 = B64::from(5);
        let chunk_4 = B64::from(156);
        assert_eq!(chunk_1 + chunk_2, B64::from([51u8; 8]));
        assert_eq!(chunk_1 - chunk_2, B64::from([17u8; 8]));
        assert_eq!(chunk_4 * chunk_3, B64::from(156 * 5));
        assert_eq!(chunk_4 / chunk_3, B64::from(156 / 5));
        assert_eq!(chunk_4 % chunk_3, B64::from(156 % 5));
    }

    #[test]
    fn u32_struct_test() {
        let chunk_zero = B64::zero();
        let bytes1 = [9u8; 8];
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

    // #[test]
    // fn u32_stack_functional() {
    //     let mut sm = StateMachine32::new(DefaultConfig::default());

    //     assert!(sm.push(0x01020304).is_ok());
    //     assert!(sm.push(0xaabbccdd).is_ok());
    //     assert!(sm.stack_depth() == 2);

    //     assert_eq!(sm.pop().unwrap(), 0xaabbccdd);
    //     assert_eq!(sm.pop().unwrap(), 0x01020304);
    //     assert!(sm.stack_depth() == 0);
    // }

    // #[test]
    // #[should_panic]
    // fn u32_stack_underflow() {
    //     let mut sm = StateMachine32::new(DefaultConfig::default());
    //     sm.pop().unwrap();
    // }

    // #[test]
    // #[should_panic]
    // fn u32_stack_overflow() {
    //     let mut sm = StateMachine32::new(ConfigArgs {
    //         head_layout: true,
    //         stack_depth: 2,
    //         no_register: 0,
    //         buffer_size: 64,
    //     });
    //     assert!(sm.push(0x01020304).is_ok());
    //     assert!(sm.push(0x01020304).is_ok());
    //     assert!(sm.push(0x01020304).is_ok());
    //     assert!(sm.push(0x01020304).is_ok());
    // }

    // #[test]
    // fn u32_register_functional() {
    //     let mut sm = StateMachine32::new(DefaultConfig::default());

    //     let r0 = sm.register(0).unwrap();
    //     let r1 = sm.register(1).unwrap();

    //     assert!(sm.set(r0, 0x01020304).is_ok());
    //     assert!(sm.set(r1, 0xaabbccdd).is_ok());

    //     assert_eq!(sm.get(r0).unwrap(), 0x01020304);
    //     assert_eq!(sm.get(r1).unwrap(), 0xaabbccdd);

    //     assert!(sm.mov(r0, r1).is_ok());

    //     assert!(sm.get(r0).unwrap() == 0xaabbccdd);
    // }
}
