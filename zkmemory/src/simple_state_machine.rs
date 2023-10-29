use rbtree::RBTree;
extern crate std;
use std::marker::PhantomData;
use std::println;
use crate::base::{Base, B256};
use crate::config::{AllocatedSection, Config, ConfigArgs};
use crate::machine::{CellInteraction, TraceRecord};
use crate::{
    impl_register_machine, impl_stack_machine, impl_state_machine,
    machine::{AbstractContext, AbstractInstruction, AbstractMachine, Register},
};
extern crate alloc;
use alloc::vec::Vec;

/// My instruction set for the machine
#[derive(Debug, Clone, Copy)]
pub enum MyInstruction<M, K, V, const S: usize, const T: usize>
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
    /// Move from register to register
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

/// Type alias Instruction
pub type Instruction = MyInstruction<StateMachine<B256, B256, 32, 32>, B256, B256, 32, 32>;

/// RAM Machine
#[derive(Debug)]
pub struct StateMachine<K, V, const S: usize, const T: usize>
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

impl<M, K, V, const S: usize, const T: usize> AbstractContext<M, K, V> for StateMachine<K, V, S, T>
where
    Self: core::fmt::Debug
        + Sized
        + AbstractMachine<K, V, Context = M::Context, Instruction = M::Instruction>,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V, Machine = StateMachine<K, V, S, T>>,
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
    for MyInstruction<M, K, V, S, T>
where
    Self: core::fmt::Debug + Sized,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V, Machine = StateMachine<K, V, S, T>>,
{
    fn exec(&self, machine: &mut M::Machine) {
        match self {
            MyInstruction::Invalid(_) => {
                panic!("Invalid instruction")
            }
            MyInstruction::Read(addr) => {
                machine.read(*addr).expect("Unable to read to memory");
            }
            MyInstruction::Write(addr, val) => {
                machine
                    .write(*addr, *val)
                    .expect("Unable to write to memory");
            }
            MyInstruction::Push(value) => {
                machine.push(*value).expect("Unable to push value to stack");
            }
            MyInstruction::Pop(_) => {
                machine.pop().expect("Unable to pop value from stack");
            }
            MyInstruction::Mov(reg1, reg2) => {
                match machine.get(*reg2).expect("Unable to access register 1") {
                    CellInteraction::SingleCell(_, _, value) => {
                        machine.set(*reg1, value).expect("Unable to set register 2");
                    }
                    _ => panic!("Register unable to be two cells"),
                }
                // Mov value from register 2 to register 1
            }
            MyInstruction::Swap(reg) => {
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
            MyInstruction::Load(reg, addr) => {
                match machine.read(*addr).expect("Unable to read memory") {
                    CellInteraction::SingleCell(_, _, value) => {
                        machine.set(*reg, value).expect("Unable to set register");
                    }
                    CellInteraction::DoubleCell(_, _, cvalue, _, _, _, _) => {
                        machine.set(*reg, cvalue).expect("Unable to set register");
                    }
                };
            }
            MyInstruction::Save(_, reg) => {
                match machine.get(*reg).expect("Unable to access register") {
                    CellInteraction::SingleCell(_, addr, value) => {
                        machine
                            .write(addr, value)
                            .expect("Unable to write to memory");
                    }
                    _ => panic!("Register unable to be two cells"),
                }
            }
            MyInstruction::Add(reg1, reg2) => {
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
                    },
                    _ => panic!("Register unable to be two cells"),
                }
            }
        }
    }
}

impl<K, V, const S: usize, const T: usize> StateMachine<K, V, S, T>
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
            stack_depth: config.stack_depth.into(),
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
    pub fn show_sections_maps(&self) -> () {
        println!("Memory section map: from {} to {}", 
        self.memory_allocated.low(), self.memory_allocated.high());
        println!("Register section map: from {} to {}", 
        self.register_allocated.low(), self.register_allocated.high());
        println!("Stack section map: from {} to {}", 
        self.stack_allocated.low(), self.stack_allocated.high());
    }
}

impl<K, V, const S: usize, const T: usize> AbstractMachine<K, V> for StateMachine<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    type Machine = Self;
    type Context = Self;
    type Instruction = MyInstruction<Self, K, V, S, T>;
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
        self.execution_trace.keys().map(|x| x.clone()).collect()
    }

    fn exec(&mut self, instruction: &Self::Instruction) {
        instruction.exec(self);
    }
}

impl_register_machine!(StateMachine);
impl_stack_machine!(StateMachine);
impl_state_machine!(StateMachine);

