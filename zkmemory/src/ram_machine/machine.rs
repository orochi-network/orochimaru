use crate::base::{Base, U256};
use crate::config::{Config, ConfigArgs};
use crate::error::Error;
use crate::memory::{GenericMemory, RawMemory};

/// RAM machine instruction set
#[derive(Debug)]
pub enum Instruction<K, V> {
    /// Invalid instruction
    Invalid,
    /// Write instruction (time_log, address, value)
    Write(u64, K, V),
    /// Read instruction (time_log, address, value)
    Read(u64, K, V),
}

/// RAM machine execution trace record
#[derive(Debug)]
pub enum TraceRecord<K, V, const S: usize> {
    /// Write instruction (address, time_log, stack_depth, value)
    Write(K, u64, usize, V),
    /// Read instruction (address, time_log, stack_depth, value)
    Read(K, u64, usize, V),
    /// Push instruction (address, time_log, stack_deep, value)
    Push(K, u64, usize, V),
    /// Pop instruction (address, time_log, stack_deep, value)
    Pop(K, u64, usize, V),
}

impl<K, V, const S: usize> TraceRecord<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    fn from(instruction: Instruction<K, V>, stack_depth: usize) -> Self {
        match instruction {
            Instruction::Write(time_log, address, value) => {
                Self::Write(address, time_log, stack_depth, value)
            }
            Instruction::Read(time_log, address, value) => {
                Self::Read(address, time_log, stack_depth, value)
            }
            _ => panic!("Invalid instruction type"),
        }
    }

    fn from_stack_op(instruction: Instruction<K, V>, stack_depth: usize) -> Self {
        match instruction {
            Instruction::Write(time_log, address, value) => {
                Self::Push(address, time_log, stack_depth, value)
            }
            Instruction::Read(time_log, address, value) => {
                Self::Pop(address, time_log, stack_depth, value)
            }
            _ => panic!("Invalid instruction type"),
        }
    }
}

/// Represents the interaction between a RAM machine and a memory cell.
#[derive(Debug)]
pub enum CellInteraction<K, V> {
    /// Invalid cell insteraction
    Invalid,
    /// Interactive with single Cell (adress, value)
    Cell(Instruction<K, V>),
    /// Interactive with two Cells (adress, value)
    TwoCell(Instruction<K, V>, Instruction<K, V>),
}

/// Random Access Memory Machine
pub trait RAMMachine<K, V> {
    /// Create a new instance of RAM machine
    fn new(config_arugments: ConfigArgs<K>) -> Self;
    /// Write a value to a memory address
    fn write(&mut self, address: K, value: V) -> Result<(), Error>;
    /// Read a value from a memory address
    fn read(&mut self, address: K) -> Result<V, Error>;
}

/// Stack Machine with two simple opcode (push, pop)
pub trait StackMachine<V> {
    /// Push a value to the stack
    fn push(&mut self, value: V) -> Result<(), Error>;

    /// Pop a value from the stack
    fn pop(&mut self) -> Result<V, Error>;

    /// Get the stack depth
    fn stack_depth(&self) -> usize;
}

/// Virtual register structure
#[derive(Debug, Clone, Copy)]
pub struct Register<K: Base<S>, const S: usize>(usize, K);

impl<K, const S: usize> Register<K, S>
where
    K: Base<S>,
{
    /// Create a new register
    pub fn new(register_index: usize, register_address: K) -> Self {
        Self(register_index, register_address)
    }

    /// Get the register address
    pub fn address(&self) -> K {
        self.1
    }

    /// Get the register index
    pub fn index(&self) -> usize {
        self.0
    }
}

/// Register Machine with 3 simple opcodes (mov, set, get)
pub trait RegisterMachine<K, V, const S: usize>
where
    K: Base<S>,
{
    /// Get address for a register
    fn register(&self, register_index: usize) -> Result<Register<K, S>, Error>;
    /// Move a value from one register to another
    fn mov(&mut self, to: Register<K, S>, from: Register<K, S>) -> Result<(), Error>;
    /// Set a value to a register
    fn set(&mut self, register: Register<K, S>, value: V) -> Result<(), Error>;
    /// Read a value from a register
    fn get(&mut self, register: Register<K, S>) -> Result<V, Error>;
}

/// State Machine with 256 bits address and word size
pub type StateMachine256 = StateMachine<U256, U256, 32>;

/// State Machine with 64 bits address and word size
pub type StateMachine64 = StateMachine<u64, u64, 8>;

/// State Machine with 32 bits address and 32 bits word size
pub type StateMachine32 = StateMachine<u32, u32, 4>;

/// State Machine
#[derive(Debug)]
pub struct StateMachine<K, V, const S: usize>
where
    K: Base<S>,
{
    memory: RawMemory<K, V, S>,
    trace: Vec<TraceRecord<K, V, S>>,
    config: Config<K, S>,
    stack_ptr: K,
    stack_depth: usize,
}

impl<K, V, const S: usize> StateMachine<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    /// Base address of memory
    pub fn base_address(&self) -> K {
        self.config.memory.low()
    }

    /// Get memory execution trace
    pub fn trace(&self) -> &Vec<TraceRecord<K, V, S>> {
        self.trace.as_ref()
    }

    fn write_cell(&mut self, address: K, value: V) -> Result<(), Error> {
        match self.memory.write(address, value) {
            CellInteraction::Cell(instruction) => {
                self.trace
                    .push(TraceRecord::from(instruction, self.stack_depth));
                Ok(())
            }
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace
                    .push(TraceRecord::from(instruction1, self.stack_depth));
                self.trace
                    .push(TraceRecord::from(instruction2, self.stack_depth));
                Ok(())
            }
            _ => Err(Error::MemoryInvalidInteraction),
        }
    }

    fn read_cell(&mut self, address: K) -> Result<V, Error> {
        let (value, interaction) = self.memory.read(address);
        match interaction {
            CellInteraction::Cell(instruction) => {
                self.trace
                    .push(TraceRecord::from(instruction, self.stack_depth));
                Ok(value)
            }
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace
                    .push(TraceRecord::from(instruction1, self.stack_depth));
                self.trace
                    .push(TraceRecord::from(instruction2, self.stack_depth));
                Ok(value)
            }
            _ => Err(Error::MemoryInvalidInteraction),
        }
    }
}

/// Implementation of RAMMachine for StateMachine
impl<K, V, const S: usize> RAMMachine<K, V> for StateMachine<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    fn new(config_arugments: ConfigArgs<K>) -> Self {
        let config = Config::<K, S>::new(K::from_usize(K::CELL_SIZE), config_arugments);
        Self {
            memory: RawMemory::<K, V, S>::new(config.cell_size),
            trace: Vec::new(),
            config,
            stack_ptr: config.stack.low(),
            stack_depth: 0,
        }
    }

    fn write(&mut self, address: K, value: V) -> Result<(), Error> {
        if !self.config.memory.contain(address) {
            return Err(Error::MemoryAccessDeinied);
        }
        self.write_cell(address, value)
    }

    fn read(&mut self, address: K) -> Result<V, Error> {
        if !self.config.memory.contain(address) {
            return Err(Error::MemoryAccessDeinied);
        }
        self.read_cell(address)
    }
}

impl<K, V, const S: usize> StackMachine<V> for StateMachine<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    fn stack_depth(&self) -> usize {
        self.stack_depth
    }

    fn push(&mut self, value: V) -> Result<(), Error> {
        if !self.config.stack.contain(self.stack_ptr) {
            return Err(Error::StackOverflow);
        }
        self.stack_ptr = self.stack_ptr + self.config.cell_size;
        self.stack_depth += 1;
        match self.memory.write(self.stack_ptr, value) {
            CellInteraction::Cell(instruction) => {
                self.trace
                    .push(TraceRecord::from_stack_op(instruction, self.stack_depth));
                Ok(())
            }
            CellInteraction::TwoCell(_, _) => {
                println!("TwoCell");
                Ok(())
            }
            _ => Err(Error::MemoryInvalidInteraction),
        }
    }

    fn pop(&mut self) -> Result<V, Error> {
        if !self.config.stack.contain(self.stack_ptr) {
            return Err(Error::StackUnderflow);
        }
        let address = self.stack_ptr;
        self.stack_ptr = self.stack_ptr - self.config.cell_size;
        self.stack_depth -= 1;
        let (value, interaction) = self.memory.read(address);
        match interaction {
            CellInteraction::Cell(instruction) => {
                self.trace
                    .push(TraceRecord::from_stack_op(instruction, self.stack_depth));
                Ok(value)
            }
            _ => Err(Error::MemoryInvalidInteraction),
        }
    }
}

impl<K, V, const S: usize> RegisterMachine<K, V, S> for StateMachine<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    fn mov(&mut self, to: Register<K, S>, from: Register<K, S>) -> Result<(), Error> {
        let register_value = self.read_cell(from.address());
        if register_value.is_ok() {
            match self.write_cell(to.address(), register_value.unwrap()) {
                Ok(_) => return Ok(()),
                Err(_) => return Err(Error::RegisterUnableToWrite),
            }
        } else {
            Err(Error::RegisterUnableToRead)
        }
    }

    fn set(&mut self, register: Register<K, S>, value: V) -> Result<(), Error> {
        match self.write_cell(register.address(), value) {
            Ok(_) => Ok(()),
            _ => Err(Error::RegisterUnableToWrite),
        }
    }

    fn get(&mut self, register: Register<K, S>) -> Result<V, Error> {
        match self.read_cell(register.address()) {
            Ok(value) => Ok(value),
            _ => Err(Error::RegisterUnableToRead),
        }
    }

    fn register(&self, register_index: usize) -> Result<Register<K, S>, Error> {
        let register_address =
            self.config.register.low() + (K::from_usize(register_index) * self.config.cell_size);
        if register_address > self.config.register.high() {
            Err(Error::RegisterUnableToAssign)
        } else {
            Ok(Register::new(register_index, register_address))
        }
    }
}
