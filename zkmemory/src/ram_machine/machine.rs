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
    fn new(word_size: u64) -> Self;
    /// Write a value to a memory address
    fn write(&mut self, address: K, value: V);
    /// Read a value from a memory address
    fn read(&mut self, address: K);
}

/// State Machine
#[derive(Debug)]
pub struct StateMachine<K, V>
where
    K: Base,
{
    memory: RawMemory<K, V>,
    trace: Vec<Instruction<K, V>>,
}

/// Implementation of RAMMachine for StateMachine
impl<K, V> RAMMachine<K, V> for StateMachine<K, V>
where
    K: Base,
    V: Base,
{
    fn new(word_size: u64) -> Self {
        Self {
            memory: RawMemory::<K, V>::new(word_size),
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

    fn read(&mut self, address: K) {
        match self.memory.read(address) {
            CellInteraction::Cell(instruction) => self.trace.push(instruction),
            CellInteraction::TwoCell(instruction1, instruction2) => {
                self.trace.push(instruction1);
                self.trace.push(instruction2);
            }
            _ => panic!("Invalid memory interaction"),
        }
    }
}