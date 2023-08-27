/// This crate provides a simple RAM machine for use in the zkVM
#[deny(warnings, unused, nonstandard_style, missing_docs, unsafe_code)]

/// A state machine with two instructions [Write](crate::machine::Instruction::Write) and [Read](crate::machine::Instruction::Read).
mod ram_machine;
pub use ram_machine::*;

#[cfg(test)]
mod tests {
    use crate::base::{Base, UsizeConvertible, U256};
    use crate::config::{ConfigArgs, DefaultConfig};
    use crate::machine::{
        RAMMachine, RegisterMachine, StackMachine, StateMachine256, StateMachine32,
    };

    #[test]
    fn sm256_write_read_one_cell() {
        let mut sm = StateMachine256::new(DefaultConfig::default());
        let chunk = U256::from_bytes([5u8; 32]);
        assert!(sm.write(sm.base_address(), chunk).is_ok());
        let read_result = sm.read(sm.base_address());
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), chunk);
    }

    #[test]
    fn sm256_read_empty_cell() {
        let mut sm = StateMachine256::new(DefaultConfig::default());
        let chunk = U256::from_bytes([0u8; 32]);
        let read_result = sm.read(sm.base_address());
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), chunk);
    }

    #[test]
    fn sm256_write_one_cell_read_two_cell() {
        let mut sm = StateMachine256::new(DefaultConfig::default());
        let chunk_1 = U256::from_bytes([5u8; 32]);
        let chunk_2 = U256::from_bytes([10u8; 32]);
        let base_addr = sm.base_address().to_usize();

        let expected: [u8; 32] = [[5u8; 17].as_slice(), [10u8; 15].as_slice()]
            .concat()
            .try_into()
            .unwrap();

        assert!(sm.write(U256::from_usize(base_addr), chunk_1).is_ok());
        assert!(sm.write(U256::from_usize(base_addr + 32), chunk_2).is_ok());
        let read_result = sm.read(U256::from_usize(base_addr + 15));
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), U256::from_bytes(expected));
    }

    #[test]
    fn sm256_write_two_cell_read_one_cell() {
        let mut sm = StateMachine256::new(DefaultConfig::default());
        let base_addr = sm.base_address().to_usize();

        let chunk = U256::from_bytes([1u8; 32]);
        assert!(sm.write(U256::from_usize(base_addr + 23), chunk).is_ok());
        let expected_lo: [u8; 32] = [[0u8; 23].as_slice(), [1u8; 9].as_slice()]
            .concat()
            .try_into()
            .unwrap();
        let expected_hi: [u8; 32] = [[1u8; 23].as_slice(), [0u8; 9].as_slice()]
            .concat()
            .try_into()
            .unwrap();

        let read_result_lo = sm.read(U256::from_usize(base_addr));
        let read_result_hi = sm.read(U256::from_usize(base_addr + 32));

        assert!(read_result_lo.is_ok());
        assert!(read_result_hi.is_ok());
        assert_eq!(read_result_lo.unwrap(), U256::from_bytes(expected_lo));
        assert_eq!(read_result_hi.unwrap(), U256::from_bytes(expected_hi));
    }

    #[test]
    #[should_panic]
    fn sm32_read_prohibited_cell() {
        let mut sm = StateMachine32::new(DefaultConfig::default());
        assert_eq!(sm.read(64).unwrap(), 0u32);
    }

    #[test]
    fn sm32_read_empty_cell() {
        let mut sm = StateMachine32::new(DefaultConfig::default());
        assert_eq!(sm.read(sm.base_address() + 64).unwrap(), 0u32);
    }

    #[test]
    fn sm32_write_read_one_cell() {
        let mut sm = StateMachine32::new(DefaultConfig::default());
        let chunk = 12u32;
        assert!(sm.write(sm.base_address(), chunk).is_ok());
        assert_eq!(sm.read(sm.base_address()).unwrap(), 12u32);
    }

    #[test]
    fn sm32_write_one_cell_read_two_cells() {
        let mut sm = StateMachine32::new(DefaultConfig::default());
        let chunk_1 = u32::from_bytes([7u8; 4]);
        let chunk_2 = u32::from_bytes([10u8; 4]);
        assert!(sm.write(sm.base_address(), chunk_1).is_ok());
        assert!(sm.write(sm.base_address() + 4u32, chunk_2).is_ok());
        assert_eq!(
            sm.read(sm.base_address() + 3u32).unwrap(),
            u32::from_be_bytes([7u8, 10, 10, 10])
        );
    }

    #[test]
    fn sm32_write_two_cells_read_one_cells() {
        let mut sm = StateMachine32::new(DefaultConfig::default());
        let chunk = u32::from_bytes([3u8; 4]);
        assert!(sm.write(sm.base_address() + 2u32, chunk).is_ok());
        assert_eq!(sm.read(sm.base_address()).unwrap(), 0x00000303u32);
        assert_eq!(sm.read(sm.base_address() + 4u32).unwrap(), 0x03030000u32);
    }

    #[test]
    fn u256_test() {
        let chunk_1 = U256::from_bytes([9u8; 32]);
        let chunk_2 = U256::from_usize(10);
        assert_eq!(chunk_1.to_bytes(), [9u8; 32]);
        assert_eq!(U256::zero(), U256::from_bytes([0u8; 32]));
        assert_eq!(chunk_2.to_usize(), 10 as usize);
        assert!(!chunk_1.is_zero());
    }

    #[test]
    /// The testcases above already covered Add, Sub and Rem. This test case covers Div
    fn u256_arithmetic_test() {
        let chunk_1 = U256::from_bytes([34u8; 32]);
        let chunk_2 = U256::from_bytes([17u8; 32]);
        assert_eq!(chunk_1 / chunk_2, U256::from_usize(2));
    }

    #[test]
    fn u32_test() {
        let chunk_1 = u32::from_bytes([73u8; 4]);
        let chunk_2 = u32::from_usize(103);
        assert_eq!(chunk_1.to_bytes(), [73u8; 4]);
        assert_eq!(u32::zero(), u32::from_bytes([0u8; 4]));
        assert_eq!(chunk_2.to_usize(), 103 as usize);
        assert!(!chunk_1.is_zero());
    }

    #[test]
    fn u64_test() {
        let chunk_1 = u64::from_bytes([15u8; 8]);
        let chunk_2 = u64::from_usize(235);
        assert_eq!(chunk_1.to_bytes(), [15u8; 8]);
        assert_eq!(u64::zero(), u64::from_bytes([0u8; 8]));
        assert_eq!(chunk_2.to_usize(), 235 as usize);
        assert!(!chunk_1.is_zero());
    }

    #[test]
    fn u32_stack_functional() {
        let mut sm = StateMachine32::new(DefaultConfig::default());

        assert!(sm.push(0x01020304).is_ok());
        assert!(sm.push(0xaabbccdd).is_ok());
        assert!(sm.stack_depth() == 2);

        assert_eq!(sm.pop().unwrap(), 0xaabbccdd);
        assert_eq!(sm.pop().unwrap(), 0x01020304);
        assert!(sm.stack_depth() == 0);
    }

    #[test]
    #[should_panic]
    fn u32_stack_underflow() {
        let mut sm = StateMachine32::new(DefaultConfig::default());
        sm.pop().unwrap();
    }

    #[test]
    #[should_panic]
    fn u32_stack_overflow() {
        let mut sm = StateMachine32::new(ConfigArgs {
            head_layout: true,
            stack_depth: 2,
            no_register: 0,
            buffer_size: 64,
        });
        assert!(sm.push(0x01020304).is_ok());
        assert!(sm.push(0x01020304).is_ok());
        assert!(sm.push(0x01020304).is_ok());
        assert!(sm.push(0x01020304).is_ok());
    }

    #[test]
    fn u32_register_functional() {
        let mut sm = StateMachine32::new(DefaultConfig::default());

        let r0 = sm.register(0).unwrap();
        let r1 = sm.register(1).unwrap();

        assert!(sm.set(r0, 0x01020304).is_ok());
        assert!(sm.set(r1, 0xaabbccdd).is_ok());

        assert_eq!(sm.get(r0).unwrap(), 0x01020304);
        assert_eq!(sm.get(r1).unwrap(), 0xaabbccdd);

        assert!(sm.mov(r0, r1).is_ok());

        assert!(sm.get(r0).unwrap() == 0xaabbccdd);
    }
}
