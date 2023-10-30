use zkmemory::base::B256;
use zkmemory::config::DefaultConfig;
use zkmemory::machine::AbstractMachine;
use zkmemory::simple_state_machine::{StateMachine, Instruction};

fn main() {

    // Define the desired machine configuration
    let mut machine = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());

    // Show the section map
    machine.show_sections_maps();

    // Get the base address of the memory section
    let base = machine.base_address();
    println!("{}", base);

    // Define your desired program
    let program = vec![
        Instruction::Write(base + B256::from(16), B256::from(1025)),
        Instruction::Load(machine.r0, base + B256::from(16)),
        Instruction::Push(B256::from(3735013596u64)),
        Instruction::Swap(machine.r1),
        Instruction::Add(machine.r0, machine.r1),
        Instruction::Save(base + B256::from(24), machine.r0),
    ];

    // Execute the program
    for instruction in program {
        machine.exec(&instruction);
    }

    // Print the trace record (prettified), sorted by ascending address by default
    for x in machine.trace().into_iter() {
        println!("{:?}", x);
    }

    println!("------------");

    let mut sm256 = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default());
    let chunk = B256::from([85u8; 32]);
    let base_addr = sm256.base_address();
    sm256.exec(&Instruction::Push(chunk));
    sm256.exec(&Instruction::Swap(sm256.r0));
    sm256.exec(&Instruction::Save(base_addr, sm256.r0));

    for x in sm256.trace().into_iter() {
        println!("{:?}", x);
    }
}
