use zkmemory::base::Base;
use zkmemory::config::ConfigArgs;
use zkmemory::machine::{
    RAMMachine, Register, RegisterMachine, StackMachine, StateMachine, TraceRecord,
};

/// Define a 64 bits machine
pub enum My64Instruction<R, K, V> {
    Write(K, V),
    Read(K),
    Push(V),
    Pop,
    Mov(R, R),
    Load(R, K),
    Save(K, R),
    Add(R, R),
}

pub struct My64Machine<K, V, const S: usize>
where
    K: Base<S>,
    V: Base<S>,
{
    sm: StateMachine<K, V, S>,
    pub r0: Register<K, S>,
    pub r1: Register<K, S>,
    pub r2: Register<K, S>,
    pub r3: Register<K, S>,
}

impl My64Machine<u64, u64, 8> {
    pub fn new() -> Self {
        let sm = StateMachine::new(ConfigArgs {
            head_layout: false,
            stack_depth: 1024,
            no_register: 4,
            buffer_size: 16,
        });
        let r0 = sm.register(0).expect("Unable to create new register r0");
        let r1 = sm.register(1).expect("Unable to create new register r1");
        let r2 = sm.register(2).expect("Unable to create new register r2");
        let r3 = sm.register(3).expect("Unable to create new register r3");
        Self { sm, r0, r1, r2, r3 }
    }

    pub fn trace(&self) -> &Vec<TraceRecord<u64, u64, 8>> {
        self.sm.trace()
    }

    pub fn execution(&mut self, program: Vec<My64Instruction<Register<u64, 8>, u64, u64>>) {
        for instruction in program {
            match instruction {
                My64Instruction::Write(address, value) => {
                    self.sm
                        .write(address, value)
                        .expect("Unable to write to memory");
                }
                My64Instruction::Read(address) => {
                    let value = self.sm.read(address).expect("Unable to read from memory");
                    println!("Read value: {:#018x}", value);
                }
                My64Instruction::Push(value) => {
                    self.sm.push(value).expect("Unable to push to stack");
                }
                My64Instruction::Pop => {
                    let value = self.sm.pop().expect("Unable to pop from stack");
                    println!("Pop value: {:#018x}", value);
                }
                My64Instruction::Mov(dst, src) => {
                    self.sm
                        .mov(dst, src)
                        .expect("Unable to move value in src register to dst register");
                }
                My64Instruction::Load(dst, address) => {
                    let value = self
                        .sm
                        .read(address)
                        .expect("Unable to read value from memory to dst register");
                    self.sm
                        .set(dst, value)
                        .expect("Unable to set value to dst register");
                }
                My64Instruction::Save(address, src) => {
                    let value = self
                        .sm
                        .get(src)
                        .expect("Unable to get value from src register");
                    self.sm
                        .write(address, value)
                        .expect("Unable to write to memory");
                }
                My64Instruction::Add(ir0, ir1) => {
                    let ir0v = self
                        .sm
                        .get(ir0)
                        .expect("Unable to get value from ir0 register");
                    let ir1v = self
                        .sm
                        .get(ir1)
                        .expect("Unable to get value from ir1 register");
                    self.sm
                        .set(ir0, ir0v + ir1v)
                        .expect("Unable to set value to ir0 register");
                }
            }
        }
    }
}

fn main() {
    let mut my64 = My64Machine::new();

    my64.execution(vec![
        My64Instruction::Write(0x08, 0x0102030405060708),
        My64Instruction::Load(my64.r0, 0x8),
        My64Instruction::Write(0x00, 0x090a0b0c0d0e0f10),
        My64Instruction::Load(my64.r1, 0x00),
        My64Instruction::Add(my64.r0, my64.r1),
        My64Instruction::Save(0x10, my64.r0),
        My64Instruction::Push(0x0102),
        My64Instruction::Push(0x0304),
        My64Instruction::Push(0x0506),
        My64Instruction::Pop,
        My64Instruction::Read(0x10),
    ]);
    println!("Execution record format is: Instruction(address, time_log, stack_depth, value)");
    for record in my64.trace() {
        println!("\t{:016x?}", record);
    }
}
