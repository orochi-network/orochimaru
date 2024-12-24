extern crate alloc; // Import the alloc crate
use alloc::vec::Vec;

use crate::{
    base::Base,
    config::{AllocatedSection, Config, ConfigArgs},
    error::Error,
    impl_register_machine, impl_stack_machine, impl_state_machine,
    machine::{
        AbstractContext, AbstractInstruction, AbstractMachine, CellInteraction, Register,
        TraceRecord,
    },
};
use core::marker::PhantomData;
use rbtree::RBTree;

/// My instruction set for the machine
#[derive(Debug, Clone, Copy)]
pub enum StandardInstruction<M, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Read from memory
    Read(K),
    /// Write to memory
    Write(K, V),
    /// Push to stack
    Push(V),
    /// Pop from stack
    Pop(V),
    /// Move from register to register (Mov(r2, r1) moves the value of r1 to r2)
    Mov(Register<K>, Register<K>),
    /// Swap value from top stack  to register
    Swap(Register<K>),
    /// Load from memory to register
    Load(Register<K>, K),
    /// Save from register to memory
    Save(K, Register<K>),
    /// Invalid instruction
    Invalid(PhantomData<M>),
    /// Add two registers, register 1 = register 1 + register 2
    Add(Register<K>, Register<K>),
}

/// RAM Machine
#[derive(Debug, Clone)]
pub struct StandardStateMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    // Memory
    memory: RBTree<K, V>,
    memory_allocated: AllocatedSection<K>,
    word_size: K,
    time_log: u64,

    // Stack
    stack_allocated: AllocatedSection<K>,
    max_stack_depth: u64,
    stack_depth: u64,
    stack_ptr: K,

    // Register
    register_allocated: AllocatedSection<K>,

    /// Register r0
    pub r0: Register<K>,
    /// Register r1
    pub r1: Register<K>,
    /// Register r2
    pub r2: Register<K>,
    /// Register r3
    pub r3: Register<K>,

    // Trace
    execution_trace: RBTree<TraceRecord<K, V, S, T>, PhantomData<()>>,
}

impl<M, K, V, const S: usize, const T: usize> AbstractContext<M, K, V>
    for StandardStateMachine<K, V, S, T>
where
    Self: core::fmt::Debug
        + Sized
        + AbstractMachine<K, V, Context = M::Context, Instruction = M::Instruction>,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V, Machine = StandardStateMachine<K, V, S, T>>,
{
    fn set_stack_depth(&mut self, stack_depth: u64) {
        self.stack_depth = stack_depth;
    }

    fn stack_depth(&self) -> u64 {
        self.stack_depth
    }

    fn stack_ptr(&self) -> K {
        self.stack_ptr
    }

    fn time_log(&self) -> u64 {
        self.time_log
    }

    fn set_time_log(&mut self, time_log: u64) {
        self.time_log = time_log;
    }

    fn set_stack_ptr(&mut self, stack_ptr: K) {
        self.stack_ptr = stack_ptr;
    }

    fn memory(&mut self) -> &'_ mut RBTree<K, V> {
        &mut self.memory
    }
}

impl<M, K, V, const S: usize, const T: usize> AbstractInstruction<M, K, V>
    for StandardInstruction<M, K, V, S, T>
where
    Self: core::fmt::Debug + Sized,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V, Machine = StandardStateMachine<K, V, S, T>>,
{
    fn exec(&self, machine: &mut M::Machine) {
        match self {
            StandardInstruction::Invalid(_) => {
                panic!("Invalid instruction")
            }
            StandardInstruction::Read(addr) => {
                if !machine.memory_allocated.contain(*addr) {
                    panic!("{}", Error::MemoryAccessDeinied);
                } else {
                    machine.read(*addr).expect("Unable to read to memory");
                }
            }
            StandardInstruction::Write(addr, val) => {
                if !machine.memory_allocated.contain(*addr) {
                    panic!("{}", Error::MemoryAccessDeinied);
                } else {
                    machine
                        .write(*addr, *val)
                        .expect("Unable to write to memory");
                }
            }
            StandardInstruction::Push(value) => {
                machine.push(*value).expect("Unable to push value to stack");
            }
            StandardInstruction::Pop(_) => {
                machine.pop().expect("Unable to pop value from stack");
            }
            StandardInstruction::Mov(reg1, reg2) => {
                match machine.get(*reg2).expect("Unable to access register 1") {
                    CellInteraction::SingleCell(_, _, value) => {
                        machine.set(*reg1, value).expect("Unable to set register 2");
                    }
                    _ => panic!("Register unable to be two cells"),
                }
                // Mov value from register 2 to register 1
            }
            StandardInstruction::Swap(reg) => {
                match machine.pop().expect("Unable to pop value from stack") {
                    (_, CellInteraction::SingleCell(_op, _addr, value)) => {
                        machine
                            .push(value)
                            .expect("Unable to push register's value to stack");
                        machine.set(*reg, value).expect("Unable to set register");
                    }
                    _ => panic!("Stack unable to be two cells"),
                };
            }
            StandardInstruction::Load(reg, addr) => {
                match machine.read(*addr).expect("Unable to read memory") {
                    CellInteraction::SingleCell(_, _, value) => {
                        machine.set(*reg, value).expect("Unable to set register");
                    }
                    CellInteraction::DoubleCell(_, _, cvalue, _, _, _, _) => {
                        machine.set(*reg, cvalue).expect("Unable to set register");
                    }
                };
            }
            StandardInstruction::Save(address, reg) => {
                match machine.get(*reg).expect("Unable to access register") {
                    CellInteraction::SingleCell(_, _, value) => {
                        machine
                            .write(*address, value)
                            .expect("Unable to write to memory");
                    }
                    _ => panic!("Register unable to be two cells"),
                }
            }
            StandardInstruction::Add(reg1, reg2) => {
                match machine.get(*reg1).expect("Unable to access register 1") {
                    CellInteraction::SingleCell(_, _, value1) => {
                        match machine.get(*reg2).expect("Unable to access register 2") {
                            CellInteraction::SingleCell(_, _, value2) => {
                                machine
                                    .set(*reg1, value1 + value2)
                                    .expect("Unable to set register 1");
                            }
                            _ => panic!("Register unable to be two cells"),
                        }
                    }
                    _ => panic!("Register unable to be two cells"),
                }
            }
        }
    }
}

impl<K, V, const S: usize, const T: usize> StandardStateMachine<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Create a new RAM machine
    pub fn new(config: ConfigArgs<K>) -> Self {
        let config = Config::new(K::WORD_SIZE, config);
        Self {
            // Memory section
            memory: RBTree::new(),
            memory_allocated: config.memory,
            word_size: config.word_size,
            time_log: 0,

            // Stack
            stack_allocated: config.stack,
            max_stack_depth: config.stack_depth.into(),
            stack_depth: 0,
            stack_ptr: K::zero(),

            // Register
            register_allocated: config.register,
            r0: config.create_register(0),
            r1: config.create_register(1),
            r2: config.create_register(2),
            r3: config.create_register(3),

            // Execution trace
            execution_trace: RBTree::new(),
        }
    }
    /// Show address maps of memory, stack and registers sections
    pub fn get_sections_maps(&self) -> [(K, K); 3] {
        [
            (self.memory_allocated.low(), self.memory_allocated.high()),
            (
                self.register_allocated.low(),
                self.register_allocated.high(),
            ),
            (self.stack_allocated.low(), self.stack_allocated.high()),
        ]
    }
}

impl<K, V, const S: usize, const T: usize> AbstractMachine<K, V>
    for StandardStateMachine<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    type Machine = Self;
    type Context = Self;
    type Instruction = StandardInstruction<Self, K, V, S, T>;
    type TraceRecord = TraceRecord<K, V, S, T>;

    fn context(&mut self) -> &'_ mut Self::Context {
        self
    }

    fn word_size(&self) -> K {
        self.word_size
    }

    fn register_start(&self) -> K {
        self.register_allocated.low()
    }

    fn ro_context(&self) -> &'_ Self::Context {
        self
    }

    fn track(&mut self, trace: Self::TraceRecord) {
        self.execution_trace.insert(trace, PhantomData);
    }

    fn trace(&self) -> Vec<Self::TraceRecord> {
        self.execution_trace.keys().copied().collect()
    }

    fn exec(&mut self, instruction: &Self::Instruction) {
        instruction.exec(self);
    }

    fn base_address(&self) -> K {
        self.memory_allocated.low()
    }

    fn get_memory_address(&self) -> (K, K) {
        (self.memory_allocated.low(), self.memory_allocated.high())
    }

    fn get_stack_depth(&self) -> u64 {
        self.ro_context().stack_depth
    }

    fn max_stack_depth(&self) -> u64 {
        self.ro_context().max_stack_depth
    }
}

impl_register_machine!(StandardStateMachine);
impl_stack_machine!(StandardStateMachine);
impl_state_machine!(StandardStateMachine);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{base::B256, config::DefaultConfig, constraints::helper::build_and_test_circuit};
    use alloc::vec;
    use ethnum::U256;
    use rand::Rng;

    #[test]
    fn base_struct_test() {
        // Define the desired machine configuration
        type MyMachine = StandardStateMachine<B256, B256, 32, 32>;
        type Instruction = StandardInstruction<MyMachine, B256, B256, 32, 32>;
        let mut machine = MyMachine::new(DefaultConfig::default_config());

        // Show the section map
        let sections = machine.get_sections_maps();

        assert_eq!(sections.len(), 3);

        //   Memory section: (33856, 115792089237316195423570985008687907853269984665640564039457584007913129639935)
        assert_eq!(sections[0].0, B256::from(33856));
        assert_eq!(
            sections[0].1,
            B256::from(U256::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10).unwrap().to_be_bytes())
        );
        // Register section: (32800, 33824)
        assert_eq!(sections[1].0, B256::from(32800));
        assert_eq!(sections[1].1, B256::from(33824));
        // Stack section: (0, 32768)
        assert_eq!(sections[2].0, B256::zero());
        assert_eq!(sections[2].1, B256::from(32768));

        // Get the base address of the memory section
        let base = machine.base_address();

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
            machine.exec(&instruction);
        }
        // Print the trace record (prettified), sorted by ascending time by default
        for x in machine.trace().into_iter() {
            trace_record.push(x);
        }

        // If build_and_test_circuit does not panic, then the trace is valid.
        build_and_test_circuit(trace_record, 10);
    }
}
