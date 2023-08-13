use crate::memory::*;

#[derive(Debug)]
pub enum Instruction<K, V> {
    InVid,
    // time_log, K, value
    Write(u64, K, V),
    Read(u64, K, V),
}

#[derive(Debug)]
pub enum CellInteraction<K, V> {
    InVid,
    Cell(Instruction<K, V>),
    TwoCell(Instruction<K, V>, Instruction<K, V>),
}

pub trait RAMMachine<K, V> {
    fn new(word_size: u64) -> Self;
    fn write(&mut self, address: K, value: V);
}

#[derive(Debug)]
pub struct StateMachine<K, V>
where
    K: Base,
{
    memory: RawMemory<K, V>,
    trace: Vec<Instruction<K, V>>,
}

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
}
