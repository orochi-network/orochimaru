use std::{
    borrow::Borrow,
    sync::{Arc, Mutex},
};

pub mod memory;
/*
/// Configuration for zk memory
#[derive(Debug, Clone)]
pub struct Config {
    /// Word size in bits, it's always dived by 8
    word_size: usize,
}

/// Public enum of instructions
#[derive(Debug, Clone)]
pub enum MemoryInstruction {
    Init,
    Read,
    Write,
}

/// Public structure of the context of memory
#[derive(Debug, Clone)]
pub struct MemoryContext {
    /// Time log for the memory trace, it will increase 1 every memory operation
    time_log: Arc<Mutex<u64>>,
    /// Base address
    base_address: Arc<Mutex<usize>>,
    /// Capacity address
    cap_address: Arc<Mutex<usize>>,
}

impl MemoryContext {
    pub fn new() -> Self {
        Self {
            time_log: Arc::new(Mutex::new(0)),
            base_address: Arc::new(Mutex::new(0)),
            cap_address: Arc::new(Mutex::new(0)),
        }
    }

    pub fn inc_time(&mut self) {
        let m = Arc::clone(&self.time_log);
        let mut current_time = m.lock().unwrap();
        *current_time = *current_time + 1;
    }

    pub fn get_time(&self) -> u64 {
        let m = Arc::clone(&self.time_log);
        let result = *m.lock().unwrap();
        result
    }

    pub fn get_base_address(&self) -> usize {
        let m = Arc::clone(&self.base_address);
        let result = *m.lock().unwrap();
        result
    }

    pub fn get_cap_address(&self) -> usize {
        let m = Arc::clone(&self.cap_address);
        let result = *m.lock().unwrap();
        result
    }

    pub fn inc_cap_address(&mut self, addition_size: usize) {
        let m = Arc::clone(&self.cap_address);
        let mut new_size = m.lock().unwrap();
        *new_size = *new_size + addition_size
    }
}

/// Memory cell
pub struct MemoryCell<'memory>(&'memory [u8]);

/// Memory trace record
#[derive(Debug, Clone)]
pub struct MemoryTrace {
    address: usize,
    time_log: u64,
    instruction: MemoryInstruction,
    value: Vec<u8>,
}

/// Public trait of zkMemory
pub trait Memory<'memory, DummyCommitmentScheme> {
    fn init(&mut self, address: usize, value: &'memory [u8]);
    fn write(&mut self, address: usize, value: &'memory [u8]);
    fn read(&mut self, address: usize) -> &[u8];
}

/// ZK memory structure
#[derive(Debug, Clone)]
pub struct ZKMemory<DummyCommitmentScheme> {
    ctx: MemoryContext,
    /// Raw memory that may contain
    raw_memory: Vec<u8>,
    /// Word size in bytes
    word_size: usize,
    /// Commitment scheme
    commitment: DummyCommitmentScheme,
    /// Memory trace
    trace: Vec<MemoryTrace>,
}

impl<C: DummyCommitmentScheme> ZKMemory<C> {
    pub fn default() -> Self {
        Self {
            ctx: MemoryContext::new(),
            raw_memory: Vec::new(),
            word_size: 8,
            commitment: C::new(),
            trace: Vec::new(),
        }
    }
    fn internal_read(&self, address: usize) -> Vec<u8> {
        self.raw_memory[address..(address + self.word_size)].to_owned()
    }

    pub fn get_trace(&self) -> &Vec<MemoryTrace> {
        self.trace.borrow()
    }
}

impl<'memory, C: DummyCommitmentScheme> Memory<'memory, C> for ZKMemory<C> {
    fn init(&mut self, address: usize, value: &'memory [u8]) {
        self.ctx.inc_cap_address(address + self.word_size);

        if self.ctx.get_cap_address() > self.raw_memory.len() {
            self.raw_memory.resize(self.ctx.get_cap_address(), 0);
        }
        self.ctx.inc_time();
        self.raw_memory.copy_from_slice(value);
        self.trace.push(MemoryTrace {
            address,
            time_log: self.ctx.get_time(),
            instruction: MemoryInstruction::Init,
            value: self.internal_read(address),
        });
    }

    fn read(&mut self, address: usize) -> &[u8] {
        self.ctx.inc_time();
        self.trace.push(MemoryTrace {
            address,
            time_log: self.ctx.get_time(),
            instruction: MemoryInstruction::Read,
            value: self.internal_read(address),
        });
        self.raw_memory[address..(address + self.word_size)].borrow()
    }

    fn write(&mut self, address: usize, value: &'memory [u8]) {
        self.ctx.inc_time();
        if address > self.ctx.get_base_address() || address < self.ctx.get_cap_address() {
            self.raw_memory[address..].copy_from_slice(value);
            self.trace.push(MemoryTrace {
                address,
                time_log: self.ctx.get_time(),
                instruction: MemoryInstruction::Write,
                value: self.internal_read(address),
            });
        } else {
            panic!("Write to non initiated memory");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut zk_memory_instance = ZKMemory::<DummyCommitment>::default();
        zk_memory_instance.init(0, &(0x0u64).to_be_bytes());
        zk_memory_instance.write(0, &(0xbbccdd1122334455u64).to_be_bytes());
        zk_memory_instance.read(0);
        println!("{:#?}", zk_memory_instance.get_trace());
    }
}
*/
