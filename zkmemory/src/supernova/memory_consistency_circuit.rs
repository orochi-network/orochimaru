extern crate alloc;
use abomonation::Abomonation;
//use alloc::format;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use arecibo::provider::Bn256EngineKZG;
use arecibo::{
    supernova::*,
    traits::{snark::default_ck_hint, CurveCycleEquipped, Dual, Engine},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};
use poseidon::poseidon_hash::Spec;
extern crate std;
use core::marker::PhantomData;
use std::println;

use crate::supernova::poseidon_parameter::OrchardNullifierScalar;

#[derive(Copy, Debug, Clone)]
/// the trace record struct
pub struct TraceRecord<F: PrimeField> {
    address: F,
    value: F,
}

#[derive(Debug, Clone)]
///
pub struct ReadCircuit<F: PrimeField, S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,> {
    trace: Option<TraceRecord<F>>,
    next_instruction: Option<F>,
    memory_size: Option<usize>,
    _marker: PhantomData<S>,
}

impl<F: PrimeField, S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,> StepCircuit<F> for ReadCircuit<F,S,W,R> {
    fn arity(&self) -> usize {
        self.memory_size
            .expect("failed to get arity of read circuit")
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
            Ok(self.clone().get_memory_address(z.to_vec(), memory_size, trace.address))
        })
        .expect("unable to get memory[address]");

        // The value variable
        let value = AllocatedNum::alloc(cs.namespace(|| format!("value")), || Ok(trace.value))
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

impl<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,> ReadCircuit<F,S,W,R> {
    fn get_memory_address(self, memory: Vec<AllocatedNum<F>>,memory_size:usize, address: F) -> F {
        let mut tmp = F::ZERO;
        let mut tmp2: u8;
        for (i, item) in memory.iter().take(memory_size).enumerate() {
            tmp2 = (F::from(i as u64) - address).is_zero().unwrap_u8();
            tmp += F::from(tmp2 as u64) * item.get_value().expect("unable to get result");
        }
        tmp
    }
}

#[derive(Debug, Clone)]
///
pub struct WriteCircuit<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize,> {
    trace: Option<TraceRecord<F>>,
    next_instruction: Option<F>,
    memory_size: Option<usize>,
    _marker: PhantomData<S>
}

impl<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize> StepCircuit<F> for WriteCircuit<F,S,W,R> {
    fn arity(&self) -> usize {
        self.memory_size
            .expect("failed to get arity of write circuit")
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
        let value = AllocatedNum::alloc(cs.namespace(|| format!("value")), || Ok(trace.value))
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

        let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || {
            self.next_instruction
                .expect("unable to get next instruction")
        });

        println!("{:?}", z_out);

        Ok((Some(pc_next), z_out))
    }
}

impl<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize> WriteCircuit<F,S,W,R> {
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
enum MemoryConsistencyCircuit<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize> {
    Read(ReadCircuit<F,S,W,R>),
    Write(WriteCircuit<F,S,W,R>),
}

impl<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize> MemoryConsistencyCircuit<F,S,W,R> {
    ///
    pub fn new(
        trace_list: Vec<TraceRecord<F>>,
        instruction: Vec<usize>,
        num_steps: usize,
        memory_size: usize,
    ) -> Vec<Self> {
        // the instructions in the traces along with a terMination instruction
        assert_eq!(instruction.len(),trace_list.len()+1);
        // final instruction Must be terMination, which is equal to 2
        assert_eq!(instruction[trace_list.len()],2);

        let mut circuits = Vec::new();
        for i in 0..num_steps {
            if instruction[i] == 0 {
                circuits.push(Self::Read(ReadCircuit {
                    trace: Some(trace_list[i]),
                    next_instruction: Some(F::from(instruction[i + 1] as u64)),
                    memory_size: Some(memory_size),
                    _marker : PhantomData
                }));
            } else {
                circuits.push(Self::Write(WriteCircuit {
                    trace: Some(trace_list[i]),
                    next_instruction: Some(F::from(instruction[i + 1] as u64)),
                    memory_size: Some(memory_size),
                    _marker: PhantomData
                }));
            }
        }
        circuits
    }
}

impl<F: PrimeField,S: Spec<F, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize> StepCircuit<F> for MemoryConsistencyCircuit<F,S,W,R> {
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

impl<E1,S: Spec<E1::Scalar, W, R> + Clone + core::marker::Sync + core::marker::Send,
    const W: usize,
    const R: usize> NonUniformCircuit<E1> for MemoryConsistencyCircuit<E1::Scalar,S,W,R>
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
                    address: E1::Scalar::from(0_64),
                    value: E1::Scalar::from(0_64),
                }),
                next_instruction: Some(E1::Scalar::from(1_64)),
                memory_size: Some(4),
                 _marker: PhantomData
            }),
            1 => MemoryConsistencyCircuit::Write(WriteCircuit {
                trace: Some(TraceRecord {
                    address: E1::Scalar::from(0_64),
                    value: E1::Scalar::from(0_64),
                }),
                next_instruction: Some(E1::Scalar::from(0_64)),
                memory_size: Some(4),
                 _marker: PhantomData
            }),
            _ => unreachable!(),
        }
    }

    fn secondary_circuit(&self) -> Self::C2 {
        TrivialSecondaryCircuit::<E1::Base>::default()
    }
}

///

type E1 = Bn256EngineKZG;
type FF = <E1 as arecibo::traits::Engine>::Scalar;
/// 
   #[test]
pub fn test_memory_consistency()
{
    let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();
    let trace = TraceRecord {
        address: FF::from(0_u64),
        value: FF::from(2_u64),
    };

    let trace2 = TraceRecord {
        address: FF::from(0_u64),
        value: FF::from(3_u64),
    };

    let trace3 = TraceRecord {
        address: FF::from(2_u64),
        value: FF::from(5_u64),
    };

    let trace4 = TraceRecord {
        address: FF::from(2_u64),
        value: FF::from(5_u64),
    };


   let trace5 = TraceRecord {
        address: FF::from(3_u64),
        value: FF::from(0_u64),
    };

    let trace6 = TraceRecord {
        address: FF::from(3_u64),
        value: FF::from(7_u64),
    };

     let trace7 = TraceRecord {
        address: FF::from(1_u64),
        value: FF::from(4_u64),
    };

     let trace8 = TraceRecord {
        address: FF::from(1_u64),
        value: FF::from(4_u64),
    };

     let trace9 = TraceRecord {
        address: FF::from(0_u64),
        value: FF::from(7_u64),
    };

     let trace10 = TraceRecord {
        address: FF::from(1_u64),
        value: FF::from(4_u64),
    };
   
    let instruction = vec![0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 2];

    let trace_list = vec![trace, trace2, trace3, trace4, trace5, trace6, trace7, trace8, trace9, trace10];
    let memory_size = 4;
    let num_steps = trace_list.len();
    let circuits = MemoryConsistencyCircuit::<<E1 as Engine>::Scalar,OrchardNullifierScalar,3,2>::new(trace_list, instruction, num_steps, memory_size);
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
    .expect("cannot setup");

    for circuit_primary in circuits.iter().take(num_steps) {
        let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
    }
    // verify the recursive SNARK
    let res = recursive_snark
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
    println!("{:?}", res);
}



//pub fn test_mm_nivc_nondet() {
 //   test_memory_consistency_with::<Bn256EngineKZG>();
    //     test_memory_consistency_in_two_steps_with::<Bn256EngineKZG>();
//}
