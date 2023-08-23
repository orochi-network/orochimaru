use zkmemory::base::{UsizeConvertible, U256};
use zkmemory::config::ConfigArgs;
use zkmemory::machine::{RAMMachine, StackMachine, StateMachine256, StateMachine32};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {
    // Test the state machine of Uint256 values
    let mut sm = StateMachine256::new(ConfigArgs::new(0, 1024, 32, 64, 32));

    const BASE_ADDRESS: usize = 1024 * 1024 * 10;
    sm.write(
        U256::from_usize(BASE_ADDRESS),
        U256::from_be_bytes([1u8; 32]),
    )
    .unwrap();
    sm.write(
        U256::from_usize(BASE_ADDRESS + 32),
        U256::from_be_bytes([2u8; 32]),
    )
    .unwrap();

    sm.write(
        U256::from_usize(BASE_ADDRESS + 6),
        U256::from_be_bytes([3u8; 32]),
    )
    .unwrap();

    println!("{:?}", sm.read(U256::from_usize(BASE_ADDRESS + 7)).unwrap());

    println!("{:?}", sm.read(U256::from_usize(BASE_ADDRESS + 0)).unwrap());

    println!(
        "{:?}",
        sm.read(U256::from_usize(BASE_ADDRESS + 32)).unwrap()
    );

    sm.push(U256::from_usize(123)).unwrap();

    sm.pop().unwrap();

    // Check the memory trace
    println!("{:#064x?}", sm);
}
