use crate::base::Base;
use rbtree::RBTree;

/// Context of machine
pub trait AbstractContext<M, K, V>
where
    K: Ord,
    Self: core::fmt::Debug + Sized,
    M: AbstractMachine<K, V>,
{
    /// Set the stack depth
    fn set_stack_depth(&mut self, stack_depth: usize);

    /// Get the stack depth
    fn get_stack_depth(&self) -> usize;

    /// Get the time log
    fn get_time_log(&self) -> usize;

    /// Set the time log
    fn set_time_log(&mut self, time_log: usize);

    /// Get the stack pointer
    fn stack_ptr(&self) -> K;

    /// Apply an instruction to the context
    fn apply(&'static mut self, instruction: &M::Instruction);
}

/// Public trait for all instructions.
pub trait AbstractInstruction<M, K, V>
where
    K: Ord,
    Self: core::fmt::Debug + Sized,
    M: AbstractMachine<K, V>,
{
    /// Execute the instruction on the context
    fn exec(&self, context: &'static mut M::Context);
}

/// Trace record
pub trait AbstractTraceRecord<M: AbstractMachine<K, V>, K, V>
where
    K: Ord,
    Self: Ord,
{
    /// Create new instance of [TraceRecord](AbstractMachine::TraceRecord) from [AbstractMachine::Instruction]
    fn from_instruction(instruction: M::Instruction) -> Self;

    /// Get instruction details
    fn instruction(&self) -> M::Instruction;

    /// Get context details at this time
    fn context(&self) -> M::Context;
}

/// The abstract machine that will be implemented by particular machine
pub trait AbstractMachine<K, V>
where
    Self: Sized,
    K: Ord,
{
    /// Context of machine
    type Context: AbstractContext<Self, K, V>;

    /// Instruction set
    type Instruction: AbstractInstruction<Self, K, V>;

    /// Get the context of abstract machine
    fn context(&mut self) -> &'_ mut Self::Context;

    /// Get the memory
    fn memory(&mut self) -> &'_ mut RBTree<K, V>;

    /// Get the WORD_SIZE of the addresss pace
    fn word_size(&self) -> K;
}

/// Abstract RAM machine
pub trait AbstractStateMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractMachine<K, V>,
{
    /// Read from memory
    fn read(&mut self, address: K) -> V {
        let remain = address % self.word_size();
        if remain.is_zero() {
            // Read on a cell
            self.dummy_read(address)
        } else {
            // Get the address of 2 cells
            let (addr_lo, addr_hi) = self.compute_address(address, remain);

            // Get the 2 cells
            let val_lo = self.dummy_read(addr_lo);
            let val_hi = self.dummy_read(addr_hi);
            let cell_size = self.word_size().to_usize();
            let part_lo = (address - addr_lo).to_usize();
            let part_hi = cell_size - part_lo;
            let mut buf = [0u8; T];

            // Write the value into the buffer
            buf[part_hi..cell_size].copy_from_slice(&val_hi.to_bytes()[0..part_lo]);
            buf[0..part_hi].copy_from_slice(&val_lo.to_bytes()[part_lo..cell_size]);

            V::from_bytes(buf)
        }
    }

    /// Write to memory
    fn write(&mut self, address: K, value: V) {
        let remain = address % self.word_size();
        if remain.is_zero() {
            // Write on a cell
            self.memory().insert(address, value);
        } else {
            // Get the address of 2 cells
            let (addr_lo, addr_hi) = self.compute_address(address, remain);
            // Calculate memory address and offset
            let cell_size = self.word_size().to_usize();
            let part_lo = (address - addr_lo).to_usize();
            let part_hi = cell_size - part_lo;

            let val = value.to_bytes();

            // Write the low part of value to the buffer
            let mut buf = self.dummy_read(addr_lo).to_bytes();
            buf[part_lo..cell_size].copy_from_slice(&val[0..part_hi]);
            let val_lo = V::from_bytes(buf);

            // Write the high part of value to the buffer
            let mut buf = self.dummy_read(addr_hi).to_bytes();
            buf[0..part_lo].copy_from_slice(&val[part_hi..cell_size]);
            let val_hi = V::from_bytes(buf);

            self.memory().replace_or_insert(addr_lo, val_lo);
            self.memory().replace_or_insert(addr_hi, val_hi);
        }
    }

    /// Read from memory
    fn dummy_read(&mut self, address: K) -> V {
        match self.memory().get(&address) {
            Some(r) => r.clone(),
            None => V::zero(),
        }
    }

    /// Compute the addresses
    fn compute_address(&self, address: K, remain: K) -> (K, K) {
        let base = address - remain;
        (base, base + self.word_size())
    }
}

/// Abstract stack machine
pub trait AbstractStackMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractStateMachine<K, V, S, T>,
{
    /// Push the value to the stack and return stack_depth
    fn push(&mut self, value: V) -> usize {
        let mut stack_depth = self.context().get_stack_depth();
        stack_depth += 1;
        self.context().set_stack_depth(stack_depth);
        let address = self.context().stack_ptr();
        self.write(address, value);

        stack_depth
    }

    /// Get value from the stack and return stack_depth and value
    fn pop(&mut self) -> (usize, V) {
        let mut stack_depth = self.context().get_stack_depth();
        stack_depth -= 1;
        self.context().set_stack_depth(stack_depth);
        let address = self.context().stack_ptr();
        let value = self.read(address);

        (stack_depth, value)
    }
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

/// Abstract register machine
pub trait AbstractRegisterMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractStateMachine<K, V, S, T>,
{
    /// Set the value of the register
    fn set(&mut self, register: Register<K, S>, value: V) {
        self.write(register.address(), value);
    }

    /// Get the value of the register
    fn get(&mut self, register: Register<K, S>) -> V {
        self.read(register.address())
    }
}

#[macro_export]
/// Export macro for implementing [AbstractStateMachine](crate::state_machine::AbstractStateMachine) trait
macro_rules! impl_state_machine {
    ($machine_struct: ident) => {
        use zkmemory::machine::AbstractStateMachine;

        impl<K, V, const S: usize, const T: usize> AbstractStateMachine<K, V, S, T>
            for $machine_struct<K, V, S, T>
        where
            K: Base<S>,
            V: Base<T>,
            Self: AbstractMachine<K, V>,
        {
        }
    };
}

#[macro_export]
/// Export macro for implementing [AbstractRegisterMachine](crate::register_machine::AbstractRegisterMachine) trait
macro_rules! impl_register_machine {
    ($machine_struct: ident) => {
        use zkmemory::machine::AbstractRegisterMachine;

        impl<K, V, const S: usize, const T: usize> AbstractRegisterMachine<K, V, S, T>
            for $machine_struct<K, V, S, T>
        where
            K: Base<S>,
            V: Base<T>,
            Self: AbstractStateMachine<K, V, S, T>,
        {
        }
    };
}

#[macro_export]
/// Export macro for implementing [AbstractStackMachine](crate::stack_machine::AbstractStackMachine) trait
macro_rules! impl_stack_machine {
    ($machine_struct: ident) => {
        use zkmemory::machine::AbstractStackMachine;

        impl<K, V, const S: usize, const T: usize> AbstractStackMachine<K, V, S, T>
            for $machine_struct<K, V, S, T>
        where
            K: Base<S>,
            V: Base<T>,
            Self: AbstractStateMachine<K, V, S, T>,
        {
        }
    };
}
