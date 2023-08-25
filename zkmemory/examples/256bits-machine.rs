use zkmemory::base::{UsizeConvertible, U256};
use zkmemory::config::ConfigArgs;
use zkmemory::machine::{RAMMachine, RegisterMachine, StackMachine, StateMachine256};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {
    // Test the state machine of Uint256 values
    let mut sm = StateMachine256::new(ConfigArgs::new(0, 1024, 32, 64, 32));

    let base_address: usize = sm.base_address().to_usize();
    sm.write(
        U256::from_usize(base_address),
        U256::from_be_bytes([1u8; 32]),
    )
    .unwrap();
    sm.write(
        U256::from_usize(base_address + 32),
        U256::from_be_bytes([2u8; 32]),
    )
    .unwrap();

    sm.write(
        U256::from_usize(base_address + 6),
        U256::from_be_bytes([3u8; 32]),
    )
    .unwrap();

    println!("{:?}", sm.read(U256::from_usize(base_address + 7)).unwrap());

    println!("{:?}", sm.read(U256::from_usize(base_address + 0)).unwrap());

    println!(
        "{:?}",
        sm.read(U256::from_usize(base_address + 32)).unwrap()
    );

    sm.push(U256::from_usize(123)).unwrap();

    sm.pop().unwrap();

    let r0 = sm.register(0);
    let r1 = sm.register(1);

    sm.set(r1, U256::from_be_bytes([9u8; 32])).unwrap();
    sm.mov(r0, r1).unwrap();

    // Check the memory trace
    println!("{:#064x?}", sm);

    let trace = sm.trace();

    println!("{:#064x?}", trace);
}
