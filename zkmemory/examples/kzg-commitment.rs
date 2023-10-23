use zkmemory::config::ConfigArgs;
use zkmemory::machine::{RAMMachine,  StateMachine256};
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

    // Commit the current memory state in 2 ways
    println!("{:?}", kzg_scheme.commit_memory_state());
    println!("{:?}", kzg_scheme.commit_memory_state_2());

}