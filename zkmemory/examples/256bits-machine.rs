use zkmemory::base::B256;
use zkmemory::config::DefaultConfig;
use zkmemory::machine::{AbstractMachine,AbstractMemoryMachine};
use zkmemory::simple_state_machine::{StateMachine, Instruction};

fn main() {

    // Define the desired machine configuration
    let mut machine = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());

    // Define your desired program
    let program = vec![
        Instruction::Write(B256::from(16), B256::from(1025)),
        Instruction::Load(machine.r0, B256::from(16)),
        Instruction::Push(B256::from(3735013596u64)),
        Instruction::Swap(machine.r1),
        Instruction::Add(machine.r0, machine.r1),
        Instruction::Save(B256::from(24), machine.r0),
    ];

    // Execute the program
    for instruction in program {
        machine.exec(&instruction);
    }

    // Print the trace record (prettified), sorted by ascending address by default
    for x in machine.trace().into_iter() {
        println!("{:?}", x);
    }

    machine.exec(&Instruction::Read(B256::from(32776)));


}
