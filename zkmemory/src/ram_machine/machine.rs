use crate::memory::*;

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
    fn write(&mut self, address: K, value: V);
    /// Read a value from a memory address
    fn read(&mut self, address: K) -> V;
}

/// State Machine with 256 bits address and word size
pub type StateMachine256 = StateMachine<32, Uint256, Uint256>;

/// State Machine with 64 bits address and word size
pub type StateMachine64 = StateMachine<8, u64, u64>;

/// State Machine with 32 bits address and 64 bits word size
pub type StateMachineWasm32 = StateMachine<8, u32, u64>;

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
        }
    }

    fn write(&mut self, address: K, value: V) {
        match self.memory.write(address, value) {
            CellInteraction::Cell(instruction) => self.trace.push(instruction),
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace.push(instruction1);
                self.trace.push(instruction2);
            }
            _ => panic!("Invalid memory interaction"),
        }
    }

    fn read(&mut self, address: K) -> V {
        let (value, interaction) = self.memory.read(address);
        match interaction {
            CellInteraction::Cell(instruction) => self.trace.push(instruction),
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace.push(instruction1);
                self.trace.push(instruction2);
            }
            _ => panic!("Invalid memory interaction"),
        }
        value
    }
}
