use zkmemory::config::ConfigArgs;
use zkmemory::machine::{RAMMachine,  StateMachine256, StateMachine64, StateMachine32};
use zkmemory::base::{UsizeConvertible, U256};
use zkmemory::kzg::KZGMemoryCommitment;
fn main() {

    // Define the state machine with 512 cells in the memory section
    let mut sm256 = StateMachine256::new_custom(ConfigArgs { 
        head_layout: false, 
        stack_depth: U256::from_usize(64), 
        no_register: U256::from_usize(4), 
        buffer_size: U256::from_usize(32) }, 32 as usize);

    // Series of write
    let base = sm256.base_address().to_usize();
    sm256.write(U256::from_usize(base), U256::from_be_bytes([1u8; 32])).unwrap();
    sm256.write(U256::from_usize(base + 32), U256::from_be_bytes([2u8; 32])).unwrap();
    sm256.write(U256::from_usize(base + 64), U256::from_be_bytes([3u8; 32])).unwrap();
    sm256.write(U256::from_usize(base + 96), U256::from_be_bytes([4u8; 32])).unwrap();

    // Define the KZG scheme for the state machine
    let mut kzg_scheme = KZGMemoryCommitment::init(5u32, sm256);

    // Commit the current memory state
    println!("{:?}", kzg_scheme.commit_memory_state());

    // Verify poly
    let commitment = kzg_scheme.commit_memory_state();
    println!("{:?}", kzg_scheme.verify_poly(commitment));


    let mut sm64 = StateMachine64::new_custom(ConfigArgs { 
        head_layout: false, 
        stack_depth: u64::from_usize(64), 
        no_register: u64::from_usize(4), 
        buffer_size: u64::from_usize(32) }, 32 as usize);
    
    let base = sm64.base_address();

    // Series of write
    sm64.write(base, 459u64).unwrap();
    sm64.write(base + 8, 7015u64).unwrap();
    sm64.write(base + 16, 993u64).unwrap();
    sm64.write(base + 24, 1053u64).unwrap();
    sm64.write(base + 32, 667293u64).unwrap();

    let mut kzg_scheme_64 = KZGMemoryCommitment::init(5u32, sm64);

    // Commit the memory state
    println!("{:?}", kzg_scheme_64.commit_memory_state());

    
    let mut sm32 = StateMachine32::new_custom(ConfigArgs { 
        head_layout: false, 
        stack_depth: u32::from_usize(64), 
        no_register: u32::from_usize(4), 
        buffer_size: u32::from_usize(32) }, 32 as usize);
    
    let base = sm32.base_address();

    // Series of write
    sm32.write(base, 10000u32).unwrap();
    sm32.write(base + 4, 7015u32).unwrap();
    sm32.write(base + 8, 993u32).unwrap();
    sm32.write(base + 12, 1053u32).unwrap();
    sm32.write(base + 16, 6673u32).unwrap();

    let mut kzg_scheme_32 = KZGMemoryCommitment::init(5u32, sm32);

    // Commit the memory state
    println!("{:?}", kzg_scheme_32.commit_memory_state());

}