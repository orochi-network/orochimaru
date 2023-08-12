//use std::os::raw;

use zkmemory::memory::{Address256, GenericMemory, RawMemory, Value256};
// type inference lets us omit an explicit type signature (which
// would be `RBTree<&str, &str>` in this example).

fn main() {
    let mut raw_mem = RawMemory::<Address256, Value256>::new(256);
    println!("{:#016x?}", raw_mem.cell_size());
    // @note: Uint256 is big endian
    // raw_mem.write(
    //     Address256::from(0),
    //     Value256::from(vec![0x0102030405060708u64, 0u64, 0u64, 0u64]),
    // );

    // Write between 2 cells
    raw_mem.write(
        Address256::from(60),
        Value256::from(vec![0xaaaaaaaaaaaaaaaau64, 0xbbbbbbbbbbbbbbbbu64, 0xccccccccccccccccu64, 0xddddddddddddddddu64]),
    );

    // println!("{}", type_of(raw_mem));

    // Iterative print to debug
    for i in 0..10 {
        println!("{}, {:?}", i*32, raw_mem.read(Address256::from(i*32)));
    }

    // let mut raw_mem64 = RawMemory::<u64, u64>::new(64);

    // raw_mem64.write(
    //     Address256::from(256),
    //     Uint256::from_limbs(vec![0xffu64, 0x0u64, 0x0u64, 0u64]),
    // );

    // // Iterative print to debug
    // for i in 0..64 {
    //     println!("{}, {:?}", i*8, raw_mem64.read(Address256::from(i*8)));
    // }

    // // raw_mem64.write(0, 1);
    // // raw_mem64.write(8, 2);
    // // raw_mem64.write(12, 0x199a993f);

    // // println!("{:#032x?}", raw_mem64.read(16));
    // // println!("{:#032x?}", raw_mem64.read(8));

    // // @note: It's usual to little endian
    let a = 0x0102030405060708u64;

    println!("{:?}", a.to_ne_bytes());
    println!("{:?}", a.to_be_bytes());
    println!("{:?}", a.to_le_bytes());

}
