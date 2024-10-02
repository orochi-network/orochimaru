//! The inplementation uses the Supernova iMpleMentation of
//! [here](https://github.com/argumentcomputer/arecibo/tree/dev/src)
//! The idea is similar to our Nova's implementation
//! [here](https://github.com/orochi-network/orochimaru/blob/main/zkmemory/src/nova/memory_consistency_circuit.rs)
//! We let z_i to be the memory and each circuit Read or Write has
//! a witness, which is the i-th trace (addr_i,val_i)
//! The read circuit checks if z_i[add_i] == val_i, while the write
//! circuit updates  z_i[add_i] := val_i
extern crate alloc;
use alloc::vec::Vec;
use arecibo::{
    supernova::*,
    traits::{CurveCycleEquipped, Dual, Engine},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use poseidon::poseidon_hash::ConstantLength;
use poseidon::poseidon_hash::Hash;
use poseidon::poseidon_hash::Spec;
extern crate std;
use core::marker::PhantomData;

#[derive(Copy, Debug, Clone)]
/// the trace record struct
pub struct TraceRecord<F: PrimeField> {
    address: F,
    value: F,
}

#[derive(Debug, Clone)]
/// The read circuit, used when the instruction equal to 0
pub struct ReadCircuit<
    F: PrimeField,
    S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,
> {
    trace: Option<TraceRecord<F>>,
    next_instruction: Option<F>,
    memory_size: Option<usize>,
    _marker: PhantomData<S>,
}

impl<
        F: PrimeField,
        S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > StepCircuit<F> for ReadCircuit<F, S, W, R>
{
    fn arity(&self) -> usize {
        self.memory_size
            .expect("failed to get arity of read circuit")
            + 1
    }
    fn circuit_index(&self) -> usize {
        0
    }
    fn synthesize<CS: bellpepper_core::ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        _pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let trace = self.trace.expect("cannot unwrap trace");
        let memory_size = self.memory_size.expect("cannot unwrap memory size");
        assert_eq!(z.len(), memory_size + 1);
        // get lookup result to check whether address in 0..memory_len
        let mut lookup_res = 0;
        for i in 0..memory_size {
            lookup_res += (F::from(i as u64) - trace.address).is_zero().unwrap_u8();
        }
        let lookup_res_alloc = AllocatedNum::alloc(cs.namespace(|| "lookup result"), || {
            Ok(F::from(lookup_res as u64))
        })
        .expect("unable to get lookup result");

        // Get memory[address]
        let memory_address = AllocatedNum::alloc(cs.namespace(|| "get memory[address]"), || {
            Ok(self
                .clone()
                .get_memory_address(z.to_vec(), memory_size, trace.address))
        })
        .expect("unable to get memory[address]");

        // The value variable
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(trace.value))
            .expect("unable to get value");

        // get the Merkle commitment of the tree. We only do this in the
        // read circuit, since later we 1) Always start with the read circuit
        // 2) In the write circuit, we ALWAYS update a valid commitment.
        // So by induction, we can prove that the commitments are valid in
        // all steps.

        let commitment = AllocatedNum::alloc(cs.namespace(|| "merkle root"), || {
            Ok(self.clone().merkle_tree_commit(z[0..memory_size].to_vec()))
        })
        .expect("unable to get commitment");

        // commitment to the memory must be valid
        cs.enforce(
            || "commitment to the memory must be valid",
            |lc| lc + commitment.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[memory_size].get_variable(),
        );

        // address must be in 0..memory_len
        cs.enforce(
            || "address must be in 0..memory_len",
            |lc| lc + lookup_res_alloc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        // if instruction = 0 then memory[address]=value
        cs.enforce(
            || "if instruction=0 then memory[address] = value",
            |lc| lc + CS::one(),
            |lc| lc + memory_address.get_variable(),
            |lc| lc + value.get_variable(),
        );

        let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || {
            self.next_instruction
                .expect("unable to get next instruction")
        });

        Ok((Some(pc_next), z.to_vec()))
    }
}

impl<
        F: PrimeField,
        S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > ReadCircuit<F, S, W, R>
{
    fn get_memory_address(self, memory: Vec<AllocatedNum<F>>, memory_size: usize, address: F) -> F {
        let mut tmp = F::ZERO;
        let mut tmp2: u8;
        for (i, item) in memory.iter().take(memory_size).enumerate() {
            tmp2 = (F::from(i as u64) - address).is_zero().unwrap_u8();
            tmp += F::from(tmp2 as u64) * item.get_value().expect("unable to get result");
        }
        tmp
    }

    /// compute the merkle root of the memory
    pub fn merkle_tree_commit(self, memory: Vec<AllocatedNum<F>>) -> F {
        let mut root: Vec<F> = memory
            .into_iter()
            .map(|x| x.get_value().expect("unable to get memory values"))
            .collect();
        let hash = Hash::<F, S, ConstantLength<2>, W, R>::init();
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
}

#[derive(Debug, Clone)]
/// The write circuit, used when instruction equal to 1
pub struct WriteCircuit<
    F: PrimeField,
    S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,
> {
    trace: Option<TraceRecord<F>>,
    next_instruction: Option<F>,
    memory_size: Option<usize>,
    _marker: PhantomData<S>,
}

impl<
        F: PrimeField,
        S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > StepCircuit<F> for WriteCircuit<F, S, W, R>
{
    fn arity(&self) -> usize {
        self.memory_size
            .expect("failed to get arity of write circuit")
            + 1
    }
    fn circuit_index(&self) -> usize {
        1
    }
    fn synthesize<CS: bellpepper_core::ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        _pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let trace = self.trace.expect("cannot unwrap trace");
        let memory_size = self.memory_size.expect("cannot unwrap memory size");
        assert_eq!(z.len(), memory_size + 1);
        // get lookup result to check whether address in 0..memory_len
        let mut lookup_res = 0;
        for i in 0..memory_size {
            lookup_res += (F::from(i as u64) - trace.address).is_zero().unwrap_u8();
        }
        let lookup_res_alloc = AllocatedNum::alloc(cs.namespace(|| "lookup result"), || {
            Ok(F::from(lookup_res as u64))
        })
        .expect("unable to get lookup result");

        // The value variable
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(trace.value))
            .expect("unable to get value");

        // address must be in 0..memory_len
        cs.enforce(
            || "address must be in 0..memory_len",
            |lc| lc + lookup_res_alloc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        let mut z_out = z.to_vec();
        let memory = z_out.to_vec();
        z_out = (0..memory_size).map(|i| memory[i].clone()).collect();
        for (i, item) in memory.iter().enumerate().take(memory_size) {
            let tmp = AllocatedNum::alloc(cs.namespace(|| "get new memory state"), || {
                Ok(self.clone().get_new_memory_cell(
                    item.clone(),
                    value.clone(),
                    F::from(i as u64),
                    trace.address,
                ))
            })
            .expect("unable to get new memory cells");

            z_out[i] = tmp;
        }

        // commitment to the new updated memory
        let new_commitment = AllocatedNum::alloc(cs.namespace(|| "new merkle root"), || {
            Ok(self.clone().merkle_tree_commit(z_out.clone()))
        })
        .expect("unable to get new commitment");

        z_out.push(new_commitment);
        assert_eq!(z_out.len(), memory_size + 1);

        let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || {
            self.next_instruction
                .expect("unable to get next instruction")
        });

        Ok((Some(pc_next), z_out))
    }
}

impl<
        F: PrimeField,
        S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > WriteCircuit<F, S, W, R>
{
    fn get_new_memory_cell(
        self,
        item: AllocatedNum<F>,
        value: AllocatedNum<F>,
        i: F,
        address: F,
    ) -> F {
        let item = item.get_value().expect("unable to get tmp1");
        let value = value.get_value().expect("unable to get value");
        let d = (i - address).is_zero().unwrap_u8();
        F::from((1 - d) as u64) * item + F::from(d as u64) * value
    }

    /// compute the merkle root of the memory
    pub fn merkle_tree_commit(self, memory: Vec<AllocatedNum<F>>) -> F {
        let mut root: Vec<F> = memory
            .into_iter()
            .map(|x| x.get_value().expect("unable to get memory values"))
            .collect();
        let hash = Hash::<F, S, ConstantLength<2>, W, R>::init();
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
}

/// The MeMory consistency circuit, consisting of a read circuit
/// and a write circuit, depends on the current instruction
#[derive(Debug, Clone)]
pub enum MemoryConsistencyCircuit<
    F: PrimeField,
    S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,
> {
    /// The read circuit
    Read(ReadCircuit<F, S, W, R>),
    /// The write circuit
    Write(WriteCircuit<F, S, W, R>),
}

impl<
        F: PrimeField,
        S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > MemoryConsistencyCircuit<F, S, W, R>
{
    /// Create the list of circuits to be proved
    pub fn new(
        z_primary: &[F],
        address: Vec<u64>,
        value: Vec<u64>,
        instruction: Vec<u64>,
        num_steps: usize,
        memory_size: usize,
    ) -> Vec<Self> {
        // the instructions in the traces along with a terMination instruction
        assert_eq!(instruction.len(), address.len() + 1);

        // final instruction Must be terMination, which is equal to 2
        assert_eq!(instruction[address.len()], 2);

        let mut circuits = Vec::new();
        // for some reason, their implementation need the first circuit index
        // to be 0. So technically, we can view trace_list[0] to be a dummy
        //  trace, and trace_list[1..] is  the true trace record we want

        circuits.push(Self::Read(ReadCircuit {
            trace: Some(TraceRecord {
                address: F::from(0),
                value: z_primary[0],
            }),
            next_instruction: Some(F::from(instruction[0])),
            memory_size: Some(memory_size),
            _marker: PhantomData,
        }));

        for i in 0..num_steps {
            if instruction[i] == 0 {
                circuits.push(Self::Read(ReadCircuit {
                    trace: Some(TraceRecord {
                        address: F::from(address[i]),
                        value: F::from(value[i]),
                    }),
                    next_instruction: Some(F::from(instruction[i + 1])),
                    memory_size: Some(memory_size),
                    _marker: PhantomData,
                }));
            // actually no need to check instruction[i]==1 here. The prove_step()
            // algorithM in supernova will do it anyway (line 772)
            } else {
                circuits.push(Self::Write(WriteCircuit {
                    trace: Some(TraceRecord {
                        address: F::from(address[i]),
                        value: F::from(value[i]),
                    }),
                    next_instruction: Some(F::from(instruction[i + 1])),
                    memory_size: Some(memory_size),
                    _marker: PhantomData,
                }));
            }
        }
        circuits
    }
}

impl<
        F: PrimeField,
        S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > StepCircuit<F> for MemoryConsistencyCircuit<F, S, W, R>
{
    fn arity(&self) -> usize {
        match self {
            Self::Read(x) => x.arity(),
            Self::Write(x) => x.arity(),
        }
    }

    fn circuit_index(&self) -> usize {
        match self {
            Self::Read(x) => x.circuit_index(),
            Self::Write(x) => x.circuit_index(),
        }
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        match self {
            Self::Read(x) => x.synthesize(cs, pc, z),
            Self::Write(x) => x.synthesize(cs, pc, z),
        }
    }
}

impl<
        E1,
        S: Spec<E1::Scalar, W, R> + Clone + core::marker::Sync + core::marker::Send,
        const W: usize,
        const R: usize,
    > NonUniformCircuit<E1> for MemoryConsistencyCircuit<E1::Scalar, S, W, R>
where
    E1: CurveCycleEquipped,
{
    type C1 = Self;
    type C2 = TrivialSecondaryCircuit<<Dual<E1> as Engine>::Scalar>;

    fn num_circuits(&self) -> usize {
        2
    }

    fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
        match circuit_index {
            0 => MemoryConsistencyCircuit::Read(ReadCircuit {
                trace: Some(TraceRecord {
                    address: E1::Scalar::from(0_u64),
                    value: E1::Scalar::from(0_u64),
                }),
                next_instruction: Some(E1::Scalar::from(1_u64)),
                memory_size: Some(4),
                _marker: PhantomData,
            }),
            1 => MemoryConsistencyCircuit::Write(WriteCircuit {
                trace: Some(TraceRecord {
                    address: E1::Scalar::from(0_u64),
                    value: E1::Scalar::from(0_u64),
                }),
                next_instruction: Some(E1::Scalar::from(0_u64)),
                memory_size: Some(4),
                _marker: PhantomData,
            }),
            _ => unreachable!(),
        }
    }

    fn secondary_circuit(&self) -> Self::C2 {
        TrivialSecondaryCircuit::<E1::Base>::default()
    }
}
