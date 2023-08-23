use crate::base::{Base, U256};
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

/// RAM machine instruction set
#[derive(Debug)]
pub enum ExtendInstruction<R, K, V> {
    /// Invalid instruction
    Invalid,
    /// Push instruction
    Push(V),
    /// Pop instruction
    Pop,
    /// Move value from one register to another (to, from)
    Move(R, R),
    /// Set value to a register (register, value)
    Set(R, V),
    /// Get value from a register to an address (address, register)
    Get(K, R),
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
    fn new(word_size: usize) -> Self;
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
}

/// Register Machine with two simple opcode (mov)
pub trait RegisterMachine<R, V> {
    /// Move a value from one register to another
    fn mov(&mut self, to: R, from: R) -> Result<(), Error>;
    /// Set a value to a register
    fn set(&mut self, register: R, value: V) -> Result<(), Error>;
    /// Read a value from a register
    fn get(&mut self, register: R) -> Result<V, Error>;
}

/// Virtual Register trait
pub trait Register<K> {
    /// Create a new instance of register
    fn new(address: K) -> Self;
    /// Get the underlying address of register
    fn address(&self) -> K;
}

/// State Machine with 256 bits address and word size
pub type StateMachine256 = StateMachine<32, U256, U256>;

/// State Machine with 64 bits address and word size
pub type StateMachine64 = StateMachine<8, u64, u64>;

/// State Machine with 32 bits address and 32 bits word size
pub type StateMachine32 = StateMachine<4, u32, u32>;

/// State Machine
#[derive(Debug)]
pub struct StateMachine<const S: usize, K, V>
where
    K: Base<S>,
{
    memory: RawMemory<S, K, V>,
    trace: Vec<Instruction<K, V>>,
    stack_ptr: K,
    cell_size: K,
    memory_base: K,
}

impl<const S: usize, K, V> StateMachine<S, K, V>
where
    K: Base<S>,
    V: Base<S>,
{
    fn write_cell(&mut self, address: K, value: V) -> Result<(), Error> {
        match self.memory.write(address, value) {
            CellInteraction::Cell(instruction) => {
                self.trace.push(instruction);
                Ok(())
            }
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace.push(instruction1);
                self.trace.push(instruction2);
                Ok(())
            }
            _ => Err(Error::MemoryInvalidInteraction),
        }
    }

    fn read_cell(&mut self, address: K) -> Result<V, Error> {
        let (value, interaction) = self.memory.read(address);
        match interaction {
            CellInteraction::Cell(instruction) => {
                self.trace.push(instruction);
                Ok(value)
            }
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace.push(instruction1);
                self.trace.push(instruction2);
                Ok(value)
            }
            _ => Err(Error::MemoryInvalidInteraction),
        }
    }
}

/// Implementation of RAMMachine for StateMachine
impl<const S: usize, K, V> RAMMachine<K, V> for StateMachine<S, K, V>
where
    K: Base<S>,
    V: Base<S>,
{
    fn new(word_size: usize) -> Self {
        Self {
            memory: RawMemory::<S, K, V>::new(word_size),
            trace: Vec::new(),
            stack_ptr: K::zero(),
            cell_size: K::from_usize(word_size / 8),
            memory_base: K::from_usize(10240), // @toto: make it configurable
        }
    }

    fn write(&mut self, address: K, value: V) -> Result<(), Error> {
        if address <= self.memory_base {
            return Err(Error::MemoryAccessDeinied);
        }
        self.write_cell(address, value)
    }

    fn read(&mut self, address: K) -> Result<V, Error> {
        if address <= self.memory_base {
            return Err(Error::MemoryAccessDeinied);
        }
        self.read_cell(address)
    }
}

impl<const S: usize, K, V> StackMachine<V> for StateMachine<S, K, V>
where
    K: Base<S>,
    V: Base<S>,
{
    fn push(&mut self, value: V) -> Result<(), Error> {
        self.stack_ptr = self.stack_ptr + self.cell_size;
        self.write(self.stack_ptr, value)
    }

    fn pop(&mut self) -> Result<V, Error> {
        let address = self.stack_ptr;
        self.stack_ptr = self.stack_ptr - self.cell_size;
        self.read(address)
    }
}

impl<const S: usize, K, V, R> RegisterMachine<R, V> for StateMachine<S, K, V>
where
    K: Base<S>,
    V: Base<S>,
    R: Register<K>,
{
    fn mov(&mut self, to: R, from: R) -> Result<(), Error> {
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

    fn set(&mut self, register: R, value: V) -> Result<(), Error> {
        match self.write_cell(register.address(), value) {
            Ok(_) => return Ok(()),
            _ => return Err(Error::RegisterUnableToWrite),
        }
    }

    fn get(&mut self, register: R) -> Result<V, Error> {
        match self.read_cell(register.address()) {
            Ok(value) => return Ok(value),
            _ => return Err(Error::RegisterUnableToRead),
        }
    }
}
