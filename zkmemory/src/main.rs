use zkmemory::machine::{RAMMachine, StateMachine};
use zkmemory::memory::{GenericMemory, RawMemory, Uint256, Base};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {

    // Test with memory of U256 values
    let mut raw_mem = RawMemory::<Uint256, Uint256>::new(256);

    // @note: Uint256 is big endian
    let chunk: Vec<u8> = vec![184u8, 158, 144, 148, 154, 194, 135, 141, 167, 96, 216, 98, 3, 116, 190, 138, 58, 206, 129, 0, 203, 177, 221, 222, 3, 3, 114, 237, 104, 15, 164, 194];
    let value = Uint256::from_bytes_be(chunk);
    println!("Debug chunk : {:?}", value);

    // Case 1 : Write in one cell
    println!("Case 1 : Write in one cell");
    raw_mem.write(Uint256::from(0), value);
    println!("{:#064x?}", raw_mem.read(Uint256::from(0)));

    // Case 2 : Write between two cells
    println!("Case 2 : Write between two cells");
    raw_mem.write(Uint256::from(50), value);

    // Case 3 : Read in one cell
    println!("Cell 1 : {:#064x?}", raw_mem.read(Uint256::from(32)));
    println!("Cell 2 : {:#064x?}", raw_mem.read(Uint256::from(64)));

    // Case 4 : Read between two cells
    println!("Between 2 cells : {:#064x?}", raw_mem.read(Uint256::from(50)));

    // Test with memory of u64 values
    let mut raw_mem64 = RawMemory::<u64, u64>::new(64);

    // Case 1 : Write in one cell
    raw_mem64.write(8, 0xaabbccddeeff0011u64);

    // Case 2 : Write between two cells
    raw_mem64.write(13, 0x3948765324985599u64);

    // Case 3 : Read in one cell
    println!("{:#016x?}", raw_mem64.read(8));
    println!("{:#016x?}", raw_mem64.read(24)); // Read an unwritten cell

    // Case 4 : Read between two cells
    println!("{:#016x?}", raw_mem64.read(13));

    // @note: It's usual to little endian
    // let a = 0x0102030405060708u64;

    // println!("{:?}", a.to_ne_bytes());
    // println!("{:?}", a.to_be_bytes());
    // println!("{:?}", a.to_le_bytes());

    // Test the state machine of U256 values

    let mut sm = StateMachine::<Uint256, Uint256>::new(256);

    sm.write(Uint256::from(0), Uint256::from(0x0102030405060708u64));
    sm.write(Uint256::from(32), Uint256::from(0x090a0b0c0d0e0f00u64));
    sm.write(Uint256::from(50), value);
    sm.read(Uint256::from(50));
    sm.read(Uint256::from(0));
    sm.read(Uint256::from(32));

    // Check the memory trace
    println!("{:#064x?}", sm);

}
