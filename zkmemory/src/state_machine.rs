use crate::abstract_machine::AbstractMachine;
use crate::base::Base;

/// Abstract RAM machine
pub trait AbstractStateMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractMachine<K, V, S, T>,
{
    /// Create a new instance of [AbstractStateMachine]
    fn new() -> Self;

    /// Read from memory
    fn dummy_read(&self, address: K) -> V;

    /// Compute the addresses
    fn compute_address(&self, address: K, remain: K) -> (K, K);

    /// Write to memory
    fn write(&mut self, address: K, value: V);

    /// Read from memory
    fn read(&self, address: K) -> V;

    /// Get the context
    fn context(&mut self) -> &'_ mut <Self as AbstractMachine<K, V, S, T>>::Context;
}
