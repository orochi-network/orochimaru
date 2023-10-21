use crate::abstract_machine::AbstractMachine;

/// Abstract RAM machine
pub trait AbstractStateMachine<K, V>
where
    Self: AbstractMachine<K, V>,
{
    /// Read from memory
    fn dummy_read(&self, address: K) -> V;

    /// Compute the addresses
    fn compute_address(&self, address: K, remain: K) -> (K, K);

    /// Write to memory
    fn write(&mut self, address: K, value: V);

    /// Read from memory
    fn read(&self, address: K) -> V;

    /// Get the context
    fn context(&mut self) -> &'_ mut <Self as AbstractMachine<K, V>>::Context;
}
