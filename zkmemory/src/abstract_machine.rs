/// Context of machine
pub trait AbstractContext<M, K, V>
where
    Self: core::fmt::Debug + Sized,
    M: AbstractMachine<K, V>,
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
pub trait AbstractInstruction<M, K, V>
where
    Self: core::fmt::Debug + Sized,
    M: AbstractMachine<K, V>,
{
    /// Execute the instruction on the context
    fn exec(&self, context: &'static mut M::Context);
}

/// Trace record
pub trait AbstractTraceRecord<M: AbstractMachine<K, V>, K, V>
where
    Self: Ord + PartialOrd + PartialEq + Eq + Sized + core::fmt::Debug,
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
{
    /// Context of machine
    type Context: AbstractContext<Self, K, V>;

    /// Instruction set
    type Instruction: AbstractInstruction<Self, K, V>;
}
