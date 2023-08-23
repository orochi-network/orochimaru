use zkmemory::base::{Base, U256};
use zkmemory::machine::{RAMMachine, StateMachine256, StateMachine32};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {
    // Test the state machine of Uint256 values
    let mut sm = StateMachine256::new(256);

    sm.write(U256::from_usize(0), U256::from_be_bytes([1u8; 32]))
        .unwrap();
    sm.write(U256::from_usize(32), U256::from_be_bytes([2u8; 32]))
        .unwrap();

    sm.write(U256::from_usize(6), U256::from_be_bytes([3u8; 32]))
        .unwrap();

    println!("{:?}", sm.read(U256::from_usize(7)).unwrap());

    println!("{:?}", sm.read(U256::from_usize(0)).unwrap());

    println!("{:?}", sm.read(U256::from_usize(32)).unwrap());

    // Check the memory trace
    println!("{:#064x?}", sm);

    // Test the state machine of u32 values
    let mut sm = StateMachine32::new(32);

    sm.write(0, u32::from_be_bytes([1u8; 4])).unwrap();
    sm.write(4, u32::from_be_bytes([2u8; 4])).unwrap();
    sm.write(6, u32::from_be_bytes([3u8; 4])).unwrap();

    println!("{:#08x}", sm.read(2).unwrap());
    println!("{:#08x}", sm.read(3).unwrap());
    println!("{:#08x}", sm.read(7).unwrap());

    // Check the memory trace
    println!("{:#08?}", sm);
}
