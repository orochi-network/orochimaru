use crate::base::Base;

/// Context of machine
pub trait AbstractContext<M, K, V, const S: usize, const T: usize>
where
    Self: core::fmt::Debug + Sized,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V, S, T, Context = Self>,
{
    /// Set the stack depth
    fn set_stack_depth(&mut self, stack_depth: usize);

    /// Get the stack depth
    fn get_stack_depth(&self) -> usize;

    /// Get the stack pointer
    fn stack_ptr(&self) -> K;

    /// Get the time log
    fn get_time_log(&self) -> usize;

    /// Set the time log
    fn set_time_log(&mut self, time_log: usize);

    /// Apply an instruction to the context
    fn apply(&'static mut self, instruction: &M::Instruction);
}

/// Public trait for all instructions.
pub trait AbstractInstruction<M, K, V, const S: usize, const T: usize>
where
    Self: core::fmt::Debug + Sized,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V, S, T, Instruction = Self>,
{
    /// Execute the instruction on the context
    fn exec(&self, context: &'static mut M::Context);
}

/// Trace record
pub trait AbstractTraceRecord<M: AbstractMachine<K, V, S, T>, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: Ord + PartialOrd + PartialEq + Eq + Sized,
{
    /// Create new instance of [TraceRecord](AbstractMachine::TraceRecord) from [AbstractMachine::Instruction]
    fn from_instruction(instruction: M::Instruction) -> Self;

    /// Get instruction details
    fn instruction(&self) -> M::Instruction;

    /// Get context details at this time
    fn context(&self) -> M::Context;
}

/// The abstract machine that will be implemented by particular machine
pub trait AbstractMachine<K, V, const S: usize, const T: usize>
where
    Self: Sized,
    K: Base<S>,
    V: Base<T>,
{
    /// Context of machine
    type Context: AbstractContext<Self, K, V, S, T>;

    /// Instruction set
    type Instruction: AbstractInstruction<Self, K, V, S, T>;
}
