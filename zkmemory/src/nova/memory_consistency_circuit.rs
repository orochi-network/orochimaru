extern crate alloc;
use core::marker::PhantomData;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
/// Reference to be added later.
use nova_snark::traits::{circuit::StepCircuit, Group};

use crate::poseidon::poseidon_hash::ConstantLength;
use crate::poseidon::poseidon_hash::Hash;
use crate::poseidon::poseidon_hash::Spec;

#[derive(Copy, Clone)]
/// the trace record struct
pub struct TraceRecord<G: Group> {
    address: G::Scalar,
    instruction: G::Scalar,
    value: G::Scalar,
}

#[derive(Clone)]
/// memory consistency circuit in one step
pub struct NovaMemoryConsistencyCircuit<
    G: Group,
    S: Spec<G::Scalar, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,
> {
    memory_len: usize,
    num_iters_per_step: usize,
    trace_record: Vec<TraceRecord<G>>,
    _marker: PhantomData<S>,
}

impl<
        G: Group,
        S: Spec<G::Scalar, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > StepCircuit<G::Scalar> for NovaMemoryConsistencyCircuit<G, S, W, R>
{
    fn arity(&self) -> usize {
        self.memory_len + 1
    }

    fn synthesize<CS: ConstraintSystem<G::Scalar>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<G::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
        assert!(z_in.len() == self.memory_len + 1);
        // z_i is the i-th state of memory: The first memory_len elements are the memory cells.
        // the final element of z_i is the Merkle root of the cells.
        // trace_record is the execution trace from z_i to z_{i+1}
        // meaning that if instruction=0 then the value of trace_record must be equal to
        // z_i[address]. Also we need the merkle root in z_i

        // The ZERO variable
        let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(G::Scalar::ZERO))
            .expect("unable to get ZERO value");

        // The ONE variable
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(G::Scalar::ONE))
            .expect("unable to get ONE value");

        let mut z_out = z_in.to_vec();

        // Get the current state of the memory
        for j in 0..self.num_iters_per_step {
            let mut memory: Vec<AllocatedNum<G::Scalar>> = vec![];
            for i in z_out.iter().take(self.memory_len) {
                memory.push(i.clone())
            }

            // The value variable
            let value = AllocatedNum::alloc(cs.namespace(|| format!("value {j}")), || {
                Ok(self.trace_record[j].value)
            })
            .expect("unable to get value");

            // The instruction variable
            let instruction =
                AllocatedNum::alloc(cs.namespace(|| format!("instruction {j}")), || {
                    Ok(self.trace_record[j].instruction)
                })
                .expect("unable to get instruction");

            let instruction_minus_one = AllocatedNum::alloc(
                cs.namespace(|| format!("instruction {j} minus one")),
                || Ok(self.trace_record[j].instruction - G::Scalar::ONE),
            )
            .expect("unable to get instruction_minus_one");

            // Get memory[address]
            let memory_address =
                AllocatedNum::alloc(cs.namespace(|| "get memory[address]"), || {
                    Ok(self
                        .clone()
                        .get_memory_address(memory.clone(), self.trace_record[j].address))
                })
                .expect("unable to get memory[address]");

            // create the Merkle commitment of the tree
            let commitment =
                AllocatedNum::alloc(cs.namespace(|| format!("merkle root {j}")), || {
                    Ok(self.clone().merkle_tree_commit(memory.clone()))
                })
                .expect("unable to get commitment");

            // commitment to the memory must be valid
            cs.enforce(
                || "commitment to the memory must be valid",
                |lc| lc + commitment.get_variable(),
                |lc| lc + one.get_variable(),
                |lc| lc + z_out[self.memory_len].get_variable(),
            );

            // if instruction = 0 then memory[address]=value
            cs.enforce(
                || "if instruction=0 then memory[address] = value",
                |lc| lc + instruction_minus_one.get_variable(),
                |lc| lc + memory_address.get_variable() - value.get_variable(),
                |lc| lc + zero.get_variable(),
            );

            // instruction must be read or write
            cs.enforce(
                || "operation is read or write",
                |lc| lc + instruction.get_variable(),
                |lc| lc + instruction_minus_one.get_variable(),
                |lc| lc + zero.get_variable(),
            );

            // create the output, which includes the memory and the Merkle
            // tree commitment of the memory
            z_out = (0..self.memory_len).map(|_| zero.clone()).collect();
            for (i, item) in memory.iter().enumerate().take(self.memory_len) {
                let tmp = AllocatedNum::alloc(cs.namespace(|| "get new memory state"), || {
                    Ok(self.clone().get_new_memory_cell(
                        item.clone(),
                        value.clone(),
                        G::Scalar::from(i as u64),
                        self.trace_record[j].address,
                    ))
                })
                .expect("unable to get new memory cells");
                z_out[i] = tmp;
            }
            // commitment to the new updated memory
            let new_commitment = AllocatedNum::alloc(
                cs.namespace(|| format!("merkle root in iteration {j}")),
                || Ok(self.clone().merkle_tree_commit(z_out.clone())),
            )
            .expect("unable to get new commitment");

            z_out.push(new_commitment);
            assert!(z_out.len() == self.memory_len + 1);
        }

        Ok(z_out)
    }
}

impl<
        G: Group,
        S: Spec<G::Scalar, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > NovaMemoryConsistencyCircuit<G, S, W, R>
{
    /// Create a new trace_record
    pub fn new(
        memory_len: usize,
        num_iters_per_step: usize,
        address: Vec<u64>,
        instruction: Vec<u64>,
        value: Vec<u64>,
    ) -> Self {
        let mut trace_record = vec![];
        for i in 0..num_iters_per_step {
            trace_record.push(TraceRecord::<G> {
                address: G::Scalar::from(address[i]),
                instruction: G::Scalar::from(instruction[i]),
                value: G::Scalar::from(value[i]),
            })
        }
        Self {
            memory_len,
            num_iters_per_step,
            trace_record,
            _marker: PhantomData,
        }
    }

    /// compute the merkle root of the memory
    pub fn merkle_tree_commit(self, memory: Vec<AllocatedNum<G::Scalar>>) -> G::Scalar {
        let mut root: Vec<G::Scalar> = memory
            .into_iter()
            .map(|x| x.get_value().expect("unable to get memory values"))
            .collect();
        let hash = Hash::<G::Scalar, S, ConstantLength<2>, W, R>::init();
        let mut size = root.len();
        while size > 1 {
            let mut root_size = size;
            while root_size > 1 {
                let left = root.pop().expect("unable to get left");
                let right = root.pop().expect("unable to get right");
                // TODO: replace "out" with a hash function
                let out = hash.clone().hash([left, right]);
                // End TODO
                root.push(out);
                root_size -= 2;
            }
            size = root.len();
        }
        root[0]
    }

    fn get_new_memory_cell(
        self,
        item: AllocatedNum<G::Scalar>,
        value: AllocatedNum<G::Scalar>,
        i: G::Scalar,
        address: G::Scalar,
    ) -> G::Scalar {
        let item = item.get_value().expect("unable to get tmp1");
        let value = value.get_value().expect("unable to get value");
        let d = (i - address).is_zero().unwrap_u8();
        G::Scalar::from((1 - d) as u64) * item + G::Scalar::from(d as u64) * value
    }

    fn get_memory_address(
        self,
        memory: Vec<AllocatedNum<G::Scalar>>,
        address: G::Scalar,
    ) -> G::Scalar {
        let mut tmp = G::Scalar::ZERO;
        let mut tmp2: u8;
        for (i, item) in memory.iter().enumerate() {
            tmp2 = (G::Scalar::from(i as u64) - address).is_zero().unwrap_u8();
            tmp += G::Scalar::from(tmp2 as u64) * item.get_value().unwrap();
        }
        tmp
    }
}
