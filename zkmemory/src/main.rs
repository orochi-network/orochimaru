use zkmemory::machine::{RAMMachine, StateMachine256};
use zkmemory::memory::{Base, Uint256};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {
    // Test the state machine of Uint256 values
    let mut sm = StateMachine256::new(256);

    sm.write(Uint256::from_usize(0), Uint256::from_bytes_be([1u8; 32]));
    sm.write(Uint256::from_usize(32), Uint256::from_bytes_be([2u8; 32]));

    sm.write(Uint256::from_usize(6), Uint256::from_bytes_be([3u8; 32]));

    println!("{:?}", sm.read(Uint256::from_usize(7)));

    println!("{:?}", sm.read(Uint256::from_usize(0)));

    println!("{:?}", sm.read(Uint256::from_usize(32)));

    // Check the memory trace
    println!("{:#064x?}", sm);
}
