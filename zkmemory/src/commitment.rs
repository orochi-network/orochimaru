extern crate alloc;
use crate::{base::Base, machine::AbstractTraceRecord};
use alloc::vec::Vec;

/// Commitment scheme trait
/// We going to support: KZG, verkle, merkle
pub trait AbstractCommitmentScheme<R, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    R: AbstractTraceRecord<K, V>,
{
    /// Output type, it may be a intermediate values for circuit
    type Output;

    /// Prove the execution trace then generate the output
    fn prove(&self, execution_trace: &Vec<R>) -> Self::Output;
}
