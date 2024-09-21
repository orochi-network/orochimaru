extern crate alloc;
use alloc::vec::Vec;
use arecibo::{supernova::*};
use bellpepper_core::{num::AllocatedNum, SynthesisError};
use nova_snark::traits::Group;
#[derive(Copy,Clone)]
/// the trace record struct
pub struct TraceRecord<G: Group> {
    address: G::Scalar,
    instruction: G::Scalar,
    value: G::Scalar,
}
#[derive(Clone)]
/// 
pub struct SuperNovaMemoryConsistencyCircuit<G: Group> {
    memory_len: usize,
    trace_record: Vec<TraceRecord<G>>,
    circuit_index: usize,
}

impl<G: Group> StepCircuit<G::Scalar> for SuperNovaMemoryConsistencyCircuit<G> {
    fn arity(&self) -> usize {
        2
    }
    fn circuit_index(&self) -> usize {
        self.circuit_index
    }
    fn synthesize<CS: bellpepper_core::ConstraintSystem<G::Scalar>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<G::Scalar>>,
        z: &[AllocatedNum<G::Scalar>],
    ) -> Result<
        (
            Option<AllocatedNum<G::Scalar>>,
            Vec<AllocatedNum<G::Scalar>>,
        ),
        SynthesisError,
    > {
        let rom_index = &z[1];
        let allocated_rom = &z[2..];
    }
}
