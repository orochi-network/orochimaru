use zkmemory::base::B256;
use zkmemory::config::{DefaultConfig, Config, ConfigArgs};
use zkmemory::machine::AbstractMachine;
use zkmemory::state_machine::{StateMachine, Instruction};
use zkmemory::kzg::KZGMemoryCommitment;

fn main() {

    let config = ConfigArgs {
        head_layout: false,
        stack_depth: B256::from(1024),
        no_register: B256::from(32),
        buffer_size: B256::from(32),
    };
    
    let mut sm = StateMachine::<B256, B256, 32, 32>::new_custom(config, B256::from(32));

    let base = sm.base_address();

    let program = vec![
        Instruction::Write(base, B256::from(1025)),
        Instruction::Write(base + B256::from(32), B256::from(1025)),
        Instruction::Write(base + B256::from(64), B256::from(33527)),
        Instruction::Write(base + B256::from(96), B256::from(3253453)),
        Instruction::Write(base + B256::from(128), B256::from(456546)),
        Instruction::Write(base + B256::from(160), B256::from(3534534)),
    ];

    // Execute the program
    for instruction in program {
        sm.exec(&instruction);
    }

    let mut kzg_scheme = KZGMemoryCommitment::init(5u32, sm);

    let commitment = kzg_scheme.commit_memory_state();

    println!("{:#?}", commitment);

}