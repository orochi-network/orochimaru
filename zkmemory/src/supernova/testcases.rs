#[cfg(test)]
mod test {
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use arecibo::provider::Bn256EngineKZG;
    use arecibo::supernova::TrivialSecondaryCircuit;
    use arecibo::traits::Dual;
    use arecibo::traits::Engine;
use arecibo::{
    supernova::*,
    traits::{snark::default_ck_hint},
};
use crate::supernova::memory_consistency_circuit::MemoryConsistencyCircuit;
extern crate std;
use std::println;
use ff::Field;
type E1 = Bn256EngineKZG;
type FF = <E1 as arecibo::traits::Engine>::Scalar;
use crate::supernova::poseidon_parameter::OrchardNullifierScalar;
use poseidon::poseidon_hash::ConstantLength;
use poseidon::poseidon_hash::Hash;

fn merkle_tree_commit(memory: Vec<FF>) -> FF {
    let mut root: Vec<FF> = memory;

    let hash = Hash::<FF, OrchardNullifierScalar, ConstantLength<2>, 3, 2>::init();
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

///
#[test]
pub fn test_memory_consistency() {

    let memory =[
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
             ];
    let commit=merkle_tree_commit(memory.to_vec());
    let mut z0=memory.to_vec();
    z0.push(commit);
    let z0_primary=z0.as_slice();

    let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

    let address = vec![
        0_u64, 0_u64, 2_u64, 2_u64, 3_u64, 3_u64, 1_u64, 1_u64, 0_u64, 1_u64,
    ];
    let value = vec![
        0_u64, 3_u64, 5_u64, 5_u64, 0_u64, 7_u64, 4_u64, 4_u64, 7_u64, 4_u64,
    ];
    let instruction = vec![
        1_u64, 1_u64, 1_u64, 0_u64, 0_u64, 1_u64, 1_u64, 0_u64, 1_u64, 0_u64, 2_u64,
    ];

    let memory_size = 4;
    let num_steps = address.len();
    let circuits =
        MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
            z0_primary,
            address,
            value,
            instruction,
            num_steps,
            memory_size,
        );
    let z0_secondary = vec![<Dual<E1> as Engine>::Scalar::ZERO];

    let pp = PublicParams::<E1>::setup(&circuits[0], &*default_ck_hint(), &*default_ck_hint());
    let circuit_primary = &circuits[0];

    let mut recursive_snark = RecursiveSNARK::<E1>::new(
        &pp,
        circuit_primary,
        circuit_primary,
        &circuit_secondary,
        z0_primary,
        &z0_secondary,
    )
    .expect("cannot setup");

    for circuit_primary in circuits.iter().take(num_steps) {
        let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary).expect("cannot prove");
    }
    // verify the recursive SNARK
    let res = recursive_snark
        .verify(
            &pp,
            z0_primary,
            &z0_secondary,
        )
        .expect("cannot verify");
    println!("{:?}", res);
}

}