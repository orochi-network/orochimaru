// Example: 256-bits RAM program using Halo2 proof engine
extern crate alloc;
use alloc::vec;
use ethnum::U256;
use rand::Rng;
use zkmemory::{
    base::B256, config::DefaultConfig, constraints::helper::build_and_test_circuit,
    default_state_machine::StandardStateMachine,
};

use zkmemory::{base::Base, default_state_machine::StandardInstruction, machine::AbstractMachine};
type CustomStateMachine = StandardStateMachine<B256, B256, 32, 32>;
type Instruction = StandardInstruction<CustomStateMachine, B256, B256, 32, 32>;

fn main() {
    // Define the desired machine configuration
    let mut machine = CustomStateMachine::new(DefaultConfig::default_config());

    // Show the section map
    let sections = machine.get_sections_maps();
    for (i, (start, end)) in sections.iter().enumerate() {
        let section_name = match i {
            0 => "Memory",
            1 => "Register",
            2 => "Stack",
            _ => "Unknown",
        };
        println!("{}: ({}, {})", section_name, start, end);
    }

    assert_eq!(sections.len(), 3);

    //   Memory section: (33856, 115792089237316195423570985008687907853269984665640564039457584007913129639935)
    assert_eq!(sections[0].0, B256::from(33856));
    assert_eq!(
        sections[0].1,
        B256::from(
            U256::from_str_radix(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                10
            )
            .unwrap()
            .to_be_bytes()
        )
    );
    // Register section: (32800, 33824)
    assert_eq!(sections[1].0, B256::from(32800));
    assert_eq!(sections[1].1, B256::from(33824));
    // Stack section: (0, 32768)
    assert_eq!(sections[2].0, B256::zero());
    assert_eq!(sections[2].1, B256::from(32768));

    // Get the base address of the memory section
    let base = machine.base_address();
    println!("Base address of memory: {}", base);

    let mut randomize = rand::thread_rng();
    randomize.gen_range(u64::MAX / 2..u64::MAX);
    // Define your desired program
    let program = vec![
        Instruction::Write(
            base + B256::from(16),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Write(
            base + B256::from(48),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Write(
            base + B256::from(80),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Write(
            base + B256::from(112),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Write(
            base + B256::from(320),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Read(base + B256::from(16)),
        Instruction::Write(
            base + B256::from(10000),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Read(base + B256::from(48)),
        Instruction::Read(base + B256::from(320)),
        Instruction::Write(
            base + B256::from(10016),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Write(
            base + B256::from(10032),
            B256::from(randomize.gen_range(u64::MAX / 2..u64::MAX)),
        ),
        Instruction::Read(base + B256::from(16)),
        Instruction::Read(base + B256::from(48)),
        Instruction::Push(B256::from(777)),
        Instruction::Swap(machine.r0),
        Instruction::Mov(machine.r1, machine.r0),
        Instruction::Write(base + B256::from(16), B256::from(1025)),
        Instruction::Write(base + B256::from(48), B256::from(1111)),
        Instruction::Write(base + B256::from(80), B256::from(1000)),
        Instruction::Write(base + B256::from(112), B256::from(9999)),
        Instruction::Load(machine.r0, base + B256::from(16)),
        Instruction::Push(B256::from(3735013596u64)),
        Instruction::Swap(machine.r1),
    ];
    let mut trace_record = vec![];
    // Execute the program
    for instruction in program {
        println!("Intruction: {:?}", instruction);
        machine.exec(&instruction);
    }
    // Print the trace record (prettified), sorted by time in ascending order by default
    for x in machine.trace().into_iter() {
        println!("{:?}", x);
        trace_record.push(x);
    }

    // If build_and_test_circuit does not panic, then the trace is valid.
    build_and_test_circuit(trace_record, 10);
}
