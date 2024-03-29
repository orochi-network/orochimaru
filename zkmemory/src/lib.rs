//! This crate provides a simple RAM machine for use in the zkVM
#![recursion_limit = "256"]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
  //  unused,
  //  warnings,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
  //  missing_docs,
  //  unused_imports
)]
#![forbid(unsafe_code)]

/// Base trait for generic type
pub mod base;
/// A commitment module that commit to the memory trace through the execution trace
/// Currently supports: KZG, Merkle Tree, Verkle Tree.
pub mod commitment;
/// Define all configuration of `StateMachine`
pub mod config;
/// Constraints for checking the lexicographic ordering
pub mod constraints;
/// Define all errors of `StateMachine`
pub mod error;
/// Definition of abstract machine (instruction, trace and context)
pub mod machine;

#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::base::{Base, B128, B256, B32, B64};
    use alloc::format;

    #[test]
    fn base_struct_test() {
        // u256 test
        let chunk_zero = B256::zero();
        let bytes1 = [9u8; 32];
        let chunk1 = B256::from(bytes1);
        let bytes_convert: [u8; 32] = chunk1
            .try_into()
            .expect("Cannot convert from B256 to bytes");
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());

        // u128 test
        let chunk_zero = B128::zero();
        let bytes1 = [9u8; 16];
        let chunk1 = B128::from(bytes1);
        let bytes_convert: [u8; 16] = chunk1
            .try_into()
            .expect("Cannot convert from B128 to bytes");
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());

        // u64 test
        let chunk_zero = B64::zero();
        let bytes1 = [1u8; 8];
        let chunk1 = B64::from(bytes1);
        let bytes_convert: [u8; 8] = chunk1.try_into().expect("Cannot convert from B64 to bytes");
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());

        // u32 test
        let chunk_zero = B64::zero();
        let bytes1 = [59u8; 8];
        let chunk1 = B64::from(bytes1);
        let bytes_convert: [u8; 8] = chunk1.try_into().expect("Cannot convert from B64 to bytes");
        assert_eq!(bytes_convert, bytes1);
        assert!(chunk_zero.is_zero());
        assert!(!chunk1.is_zero());
    }

    #[test]
    fn base_arithmetic_test() {
        // u256 test
        let chunk_1 = B256::from([34u8; 32]);
        let chunk_2 = B256::from([17u8; 32]);
        let chunk_3 = B256::from(5);
        let chunk_4 = B256::from(156);
        assert_eq!(chunk_1 + chunk_2, B256::from([51u8; 32]));
        assert_eq!(chunk_1 - chunk_2, B256::from([17u8; 32]));
        assert_eq!(chunk_4 * chunk_3, B256::from(156 * 5));
        assert_eq!(chunk_4 / chunk_3, B256::from(156 / 5));
        assert_eq!(chunk_4 % chunk_3, B256::from(156 % 5));

        // u128 test
        let chunk_1 = B128::from([19u8; 16]);
        let chunk_2 = B128::from([5u8; 16]);
        let chunk_3 = B128::from(7i32);
        let chunk_4 = B128::from(34u64);
        assert_eq!(chunk_1 + chunk_2, B128::from([24u8; 16]));
        assert_eq!(chunk_1 - chunk_2, B128::from([14u8; 16]));
        assert_eq!(chunk_4 * chunk_3, B128::from(34 * 7));
        assert_eq!(chunk_4 / chunk_3, B128::from(34 / 7));
        assert_eq!(chunk_4 % chunk_3, B128::from(34 % 7));

        // u64 test
        let chunk_1 = B64::from([61u8; 8]);
        let chunk_2 = B64::from([16u8; 8]);
        let chunk_3 = B64::from(12);
        let chunk_4 = B64::from(99);
        assert_eq!(chunk_1 + chunk_2, B64::from([77u8; 8]));
        assert_eq!(chunk_1 - chunk_2, B64::from([45u8; 8]));
        assert_eq!(chunk_4 * chunk_3, B64::from(99 * 12));
        assert_eq!(chunk_4 / chunk_3, B64::from(99 / 12));
        assert_eq!(chunk_4 % chunk_3, B64::from(99 % 12));

        // u32 test
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
    fn base_display_test() {
        let chunk = B32::from([0x23u8; 4]);
        assert_eq!(format!("{}", chunk), "589505315");
    }

    #[test]
    fn base_conversion_test() {
        // Test From<u256> traits
        let left = 5;
        let chunk1 = B256::from(5_usize);
        let right1 = i32::from(chunk1);
        let right2 = usize::from(chunk1);
        let right3 = u64::from(chunk1);
        assert_eq!(left, right1 as u64);
        assert_eq!(left, right2 as u64);
        assert_eq!(left, right3);

        // Test From<u256> traits
        let left = 5;
        let chunk1 = B128::from(5_usize);
        let right1 = i32::from(chunk1);
        let right2 = usize::from(chunk1);
        let right3 = u64::from(chunk1);
        assert_eq!(left, right1 as u64);
        assert_eq!(left, right2 as u64);
        assert_eq!(left, right3);

        // Test endianess of B256
        let num = B256::from(5);
        let chunk_be = {
            let mut buffer = [0u8; 32];
            buffer[31] = 5u8;
            buffer
        };
        let chunk_le = {
            let mut buffer = [0u8; 32];
            buffer[0] = 5u8;
            buffer
        };
        assert_eq!(num.fixed_be_bytes(), chunk_be);
        assert_eq!(num.fixed_le_bytes(), chunk_le);

        // Test endianess of B32
        let num = B32::from(10);
        let chunk_be = {
            let mut buffer = [0u8; 32];
            buffer[31] = 10u8;
            buffer
        };
        let chunk_le = {
            let mut buffer = [0u8; 32];
            buffer[0] = 10u8;
            buffer
        };
        assert_eq!(num.fixed_be_bytes(), chunk_be);
        assert_eq!(num.fixed_le_bytes(), chunk_le);
    }
}
