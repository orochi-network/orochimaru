use crate::{base::Base, state_machine::AbstractStateMachine};

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
    Self: AbstractStateMachine<K, V>,
{
    /// Set the value of the register
    fn set(&mut self, register: Register<K, S>, value: V) {
        self.write(register.address(), value);
    }

    /// Get the value of the register
    fn get(&self, register: Register<K, S>) -> V {
        self.read(register.address())
    }
}
