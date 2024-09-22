extern crate alloc;
use alloc::format;
use alloc::vec::Vec;
use arecibo::{
    supernova::*,
    traits::{CurveCycleEquipped, Dual, Engine},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

// Idea is simple: Create two circuits read and write such that:
// Circuit receives two 


#[derive(Copy, Debug, Clone)]
/// the trace record struct
pub struct TraceRecord<F: PrimeField> {
    address: F,
    value: F,
}

#[derive(Debug, Clone)]
///
pub struct ReadCircuit<F: PrimeField> {
    next_instruction: Option<usize>,
    trace: Option<TraceRecord<F>>,
    memory_size: Option<usize>,
}

impl<F: PrimeField> StepCircuit<F> for ReadCircuit<F> {
    fn arity(&self) -> usize {
        self.memory_size.expect("failed to get arity of read circuit")
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
          let trace=self.trace.expect("cannot unwrap trace");
        let memory_size=self.memory_size.expect("cannot unwrap memory size");
        let next_instruction=self.next_instruction.expect("cannot unwrap next_instruction");
        // get lookup result to check whether address in 0..memory_len
        let mut lookup_res = 0;
        for i in 0..memory_size {
            lookup_res += (F::from(i as u64) - trace.address)
                .is_zero()
                .unwrap_u8();
        }
        let lookup_res_alloc = AllocatedNum::alloc(cs.namespace(|| "lookup result"), || {
            Ok(F::from(lookup_res as u64))
        })
        .expect("unable to get lookup result");

        // Get memory[address]
        let memory_address = AllocatedNum::alloc(cs.namespace(|| "get memory[address]"), || {
            Ok(self
                .clone()
                .get_memory_address(z.to_vec(), trace.address))
        })
        .expect("unable to get memory[address]");

        // The value variable
        let value = AllocatedNum::alloc(cs.namespace(|| format!("value")), || {
            Ok(trace.value)
        })
        .expect("unable to get value");

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
            |lc| lc + memory_address.get_variable() ,
            |lc| lc +value.get_variable(),
        );

        let z_out = z.to_vec();
        let memory = z_out.to_vec();
      
      // dummy alloc to make the two circuit having equal alloc() calls
      // otherwise, the program will return a InvalidWitnessLength error.
        for (_, _) in memory.iter().enumerate().take(memory_size) {
            let _ = AllocatedNum::alloc(cs.namespace(|| "get new memory state"), || {
                Ok(F::ZERO)
            })
            .expect("unable to get dummy witness");
        }


        let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || {
            F::from(next_instruction as u64)
        });

        Ok((Some(pc_next), z_out))
    }
}

impl<F: PrimeField> ReadCircuit<F> {
    fn get_memory_address(self, memory: Vec<AllocatedNum<F>>, address: F) -> F {
        let mut tmp = F::ZERO;
        let mut tmp2: u8;
        for (i, item) in memory.iter().enumerate() {
            tmp2 = (F::from(i as u64) - address).is_zero().unwrap_u8();
            tmp += F::from(tmp2 as u64) * item.get_value().expect("unable to get result");
        }
        tmp
    }
}

#[derive(Debug, Clone)]
///
pub struct WriteCircuit<F: PrimeField> {
    next_instruction: Option<usize>,
    trace: Option<TraceRecord<F>>,
    memory_size: Option<usize>,
}

impl<F: PrimeField> StepCircuit<F> for WriteCircuit<F> {
    fn arity(&self) -> usize {
       self.memory_size.expect("failed to get arity of write circuit")
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
         let trace=self.trace.expect("cannot unwrap trace");
        let memory_size=self.memory_size.expect("cannot unwrap memory size");
        let next_instruction=self.next_instruction.expect("cannot unwrap next_instruction");
        // get lookup result to check whether address in 0..memory_len
        let mut lookup_res = 0;
        for i in 0..memory_size {
            lookup_res += (F::from(i as u64) - trace.address)
                .is_zero()
                .unwrap_u8();
        }
        let lookup_res_alloc = AllocatedNum::alloc(cs.namespace(|| "lookup result"), || {
            Ok(F::from(lookup_res as u64))
        })
        .expect("unable to get lookup result");

         // again, get dummy alloc
        let _ = AllocatedNum::alloc(cs.namespace(|| "get dummy alloc"), || {
            Ok(self
                .clone()
                .get_memory_address(z.to_vec(), trace.address))
        })
        .expect("unable to get dummy alloc");

        // The value variable
        let value = AllocatedNum::alloc(cs.namespace(|| format!("value")), || {
            Ok(trace.value)
        })
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
        z_out = (0..memory_size)
            .map(|i| memory[i].clone())
            .collect();
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
        

        let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || {
            F::from(next_instruction as u64)
        });

        Ok((Some(pc_next), z_out))

    }
}

impl<F: PrimeField> WriteCircuit<F> {
    fn get_memory_address(self, memory: Vec<AllocatedNum<F>>, address: F) -> F {
        let mut tmp = F::ZERO;
        let mut tmp2: u8;
        for (i, item) in memory.iter().enumerate() {
            tmp2 = (F::from(i as u64) - address).is_zero().unwrap_u8();
            tmp += F::from(tmp2 as u64) * item.get_value().expect("unable to get result");
        }
        tmp
    }

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



}

#[derive(Debug, Clone)]
enum MemoryConsistencyCircuit<F: PrimeField> {
    Read(ReadCircuit<F>),
    Write(WriteCircuit<F>),
}

impl<F: PrimeField> MemoryConsistencyCircuit<F> {
    ///
    pub fn new(
        trace_list: Vec<TraceRecord<F>>,
        instructions: Vec<usize>,
        num_steps: usize,
        memory_size: usize,
    ) -> Vec<Self> {
        assert!(instructions.len() == num_steps+1);
        let mut circuits = Vec::new();
        for i in 0..num_steps {
            if instructions[i] == 0 {
                circuits.push(Self::Read(ReadCircuit {
                    next_instruction: Some(instructions[i + 1]),
                    trace: Some(trace_list[i]),
                    memory_size: Some(memory_size),
                }));
            } else {
                circuits.push(Self::Write(WriteCircuit {
                    next_instruction: Some(instructions[i + 1]),
                    trace: Some(trace_list[i]),
                    memory_size: Some(memory_size),
                }));
            }
        }
        circuits
    }
}

impl<F: PrimeField> StepCircuit<F> for MemoryConsistencyCircuit<F> {
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

impl<E1> NonUniformCircuit<E1> for MemoryConsistencyCircuit<E1::Scalar>
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
                next_instruction: Some(0),
                trace: Some(TraceRecord{address:E1::Scalar::from(0_64),value:E1::Scalar::from(0_64)}),
                memory_size: Some(4),
            }),
            1 => MemoryConsistencyCircuit::Write(WriteCircuit {
                next_instruction: Some(0),
                trace: Some(TraceRecord{address:E1::Scalar::from(0_64),value:E1::Scalar::from(0_64)}),
                memory_size: Some(4),
            }),
            _ => panic!("unsupported primary circuit index"),
        }
    }

    fn secondary_circuit(&self) -> Self::C2 {
        Default::default()
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::println;

    use abomonation::Abomonation;
    use arecibo::{
        provider::Bn256EngineKZG,
        supernova::{PublicParams, RecursiveSNARK, TrivialSecondaryCircuit},
        traits::{snark::default_ck_hint, CurveCycleEquipped, Dual, Engine},
    };
    use ff::{Field, PrimeField};
    extern crate alloc;
    use alloc::vec;

    use super::{MemoryConsistencyCircuit, TraceRecord};

    pub fn test_memory_consistency_with<E1>()
    where
        E1: CurveCycleEquipped,
        // this is due to the reliance on Abomonation
        <<E1 as Engine>::Scalar as PrimeField>::Repr: Abomonation,
        <<Dual<E1> as Engine>::Scalar as PrimeField>::Repr: Abomonation,
    {
        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();
        let trace = TraceRecord {
            address: E1::Scalar::from(0_u64),
            value: E1::Scalar::from(3_u64),
        };
        let trace_list = vec![trace];
        let num_steps = 1;
        let memory_size = 4;
        let instructions = vec![1, 2];
        let circuits =
            MemoryConsistencyCircuit::new(trace_list, instructions, num_steps, memory_size);
        let z0_secondary = vec![<Dual<E1> as Engine>::Scalar::ZERO];

        let pp = PublicParams::<E1>::setup(&circuits[0], &*default_ck_hint(), &*default_ck_hint());
        let circuit_primary = &circuits[0];

        let mut recursive_snark = RecursiveSNARK::<E1>::new(
            &pp,
            circuit_primary,
            circuit_primary,
            &circuit_secondary,
            &[
                <E1 as Engine>::Scalar::from(2_u64),
                <E1 as Engine>::Scalar::from(0_u64),
                <E1 as Engine>::Scalar::from(0_u64),
                <E1 as Engine>::Scalar::from(0_u64),
            ],
            &z0_secondary,
        )
        .expect("cannot run setup");

        for circuit_primary in circuits.iter().take(num_steps) {
            let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        }
        // verify the recursive SNARK
        let res=recursive_snark
            .verify(
                &pp,
                &[
                    <E1 as Engine>::Scalar::from(2_u64),
                    <E1 as Engine>::Scalar::from(0_u64),
                    <E1 as Engine>::Scalar::from(0_u64),
                    <E1 as Engine>::Scalar::from(0_u64),
                ],
                &z0_secondary,
            )
            .expect("cannot verify");
        println!("{:?}",res);
    }

    #[test]
    fn test_nivc_nondet() {
        test_memory_consistency_with::<Bn256EngineKZG>();
    }
}
