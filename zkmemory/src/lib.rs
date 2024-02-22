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
/// A commitment module that commit to the memory trace through the execution trace
/// Currently supports: KZG, Merkle Tree, and Verkle Tree.
pub mod commitment;
/// Define all configuration of [StateMachine](crate::machine::StateMachine) and [RawMemory](crate::memory::RawMemory)
pub mod config;
/// A module that implements arithmetic circuits
/// Currently supports: Permutation check and Lexicographical ordering check
pub mod constraints;
/// Define all errors of [StateMachine](crate::machine::StateMachine) and [RawMemory](crate::memory::RawMemory)
pub mod error;
/// Definition of abstract machine (instruction, trace and context)
pub mod machine;

#[cfg(test)]
mod tests {
    use crate::base::{Base, B128, B256, B32, B64};

    #[test]
    fn u256_struct_test() {
        let chunk_zero = B256::zero();
        let bytes1 = [9u8; 32];
        let chunk1 = B256::from(bytes1);
        let bytes_convert: [u8; 32] = chunk1
            .try_into()
            .expect("Cannot convert from B256 to bytes");
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
        let bytes_convert: [u8; 16] = chunk1
            .try_into()
            .expect("Cannot convert from B128 to bytes");
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
        let bytes_convert: [u8; 8] = chunk1.try_into().expect("Cannot convert from B64 to bytes");
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
        let bytes_convert: [u8; 8] = chunk1.try_into().expect("Cannot convert from B64 to bytes");
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
}
