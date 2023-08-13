use zkmemory::machine::{RAMMachine, StateMachine};
use zkmemory::memory::{GenericMemory, RawMemory, Uint256};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {
    let mut raw_mem = RawMemory::<Uint256, Uint256>::new(256);

    // @note: Uint256 is big endian
    raw_mem.write(Uint256::from(0), Uint256::from(1));

    println!("{:?}", raw_mem.read(Uint256::from(0)));

    let mut raw_mem64 = RawMemory::<u64, u64>::new(64);

    raw_mem64.write(0, 1);
    raw_mem64.write(8, 2);

    println!("{:?}", raw_mem64.read(8));

    // @note: It's usual to little endian
    let a = 0x0102030405060708u64;

    println!("{:?}", a.to_ne_bytes());
    println!("{:?}", a.to_be_bytes());
    println!("{:?}", a.to_le_bytes());

    let mut sm = StateMachine::<Uint256, Uint256>::new(256);

    sm.write(Uint256::from(0), Uint256::from(0));
    sm.write(Uint256::from(0), Uint256::from(0));

    println!("{:?}", sm);
}
