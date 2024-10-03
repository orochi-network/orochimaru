#[cfg(test)]
mod test {
    extern crate alloc;
    use crate::supernova::memory_consistency_circuit::MemoryConsistencyCircuit;
    use alloc::vec;
    use alloc::vec::Vec;
    use arecibo::provider::Bn256EngineKZG;
    use arecibo::supernova::TrivialSecondaryCircuit;
    use arecibo::traits::Dual;
    use arecibo::traits::Engine;
    use arecibo::{supernova::*, traits::snark::default_ck_hint};
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

    // For simplicity, I will show a sample of a valid testcase
    // in the testcase, you will have to input your initial memory
    // and the list of trace record, as mentioned in memory_consistency.rs
    // of both Nova and Supernova. It will be shown in the test right below
    #[test]
    fn test_memory_consistency() {
        // input your initial memory here. Need its size to be a power
        // of 2.
        let memory = [
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
        ];
        let commit = merkle_tree_commit(memory.to_vec());
        let mut z0 = memory.to_vec();
        z0.push(commit);
        let z0_primary = z0.as_slice();

        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

        // input your trace record here, consisting of addr_i, val_i, instruction_i
        let address = vec![
            0_u64, 0_u64, 2_u64, 2_u64, 3_u64, 3_u64, 1_u64, 1_u64, 0_u64, 1_u64,
        ];
        let value = vec![
            0_u64, 3_u64, 5_u64, 5_u64, 0_u64, 7_u64, 4_u64, 4_u64, 7_u64, 4_u64,
        ];
        // remember that the final instruction must be equal to 2, which is
        // the terminating instruction. We do check that.
        let instruction = vec![
            1_u64, 1_u64, 1_u64, 0_u64, 0_u64, 1_u64, 1_u64, 0_u64, 1_u64, 0_u64, 2_u64,
        ];

        // input the size of the memory here, and let the SNARK
        // do the rest
        let memory_size = memory.len();
        let num_steps = address.len();
        let circuits = MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
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

        for circuit_primary in circuits.iter().take(num_steps + 1) {
            let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        }
        // verify the recursive SNARK
        let res = recursive_snark.verify(&pp, z0_primary, &z0_secondary);
        assert!(res.is_ok());
    }

    #[test]
    fn test_memory_consistency_read_only() {
        let memory = [
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
        ];
        let commit = merkle_tree_commit(memory.to_vec());
        let mut z0 = memory.to_vec();
        z0.push(commit);
        let z0_primary = z0.as_slice();

        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

        let address = vec![0_u64, 0_u64, 1_u64, 2_u64, 3_u64];
        let value = vec![0_u64, 0_u64, 0_u64, 0_u64, 0_u64];
        let instruction = vec![0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 2_u64];

        let memory_size = memory.len();
        let num_steps = address.len();
        let circuits = MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
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

        for circuit_primary in circuits.iter().take(num_steps + 1) {
            let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        }
        // verify the recursive SNARK
        let res = recursive_snark.verify(&pp, z0_primary, &z0_secondary);
        assert!(res.is_ok());
    }

    #[test]
    fn test_memory_consistency_write_only() {
        let memory = [
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
        ];
        let commit = merkle_tree_commit(memory.to_vec());
        let mut z0 = memory.to_vec();
        z0.push(commit);
        let z0_primary = z0.as_slice();

        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

        let address = vec![0_u64, 3_u64, 1_u64, 2_u64];
        let value = vec![4_u64, 5_u64, 6_u64, 7_u64];
        let instruction = vec![1_u64, 1_u64, 1_u64, 1_u64, 2_u64];

        let memory_size = memory.len();
        let num_steps = address.len();
        let circuits = MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
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

        for circuit_primary in circuits.iter().take(num_steps + 1) {
            let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        }
        // verify the recursive SNARK
        let res = recursive_snark.verify(&pp, z0_primary, &z0_secondary);
        assert!(res.is_ok());
    }

    #[test]
    fn test_invalid_read() {
        let memory = [
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
        ];
        let commit = merkle_tree_commit(memory.to_vec());
        let mut z0 = memory.to_vec();
        z0.push(commit);
        let z0_primary = z0.as_slice();

        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

        let address = vec![0_u64, 0_u64];
        let value = vec![4_u64, 3_u64];
        let instruction = vec![1_u64, 0_u64, 2_u64];

        let memory_size = memory.len();
        let num_steps = address.len();
        let circuits = MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
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

        for circuit_primary in circuits.iter().take(num_steps + 1) {
            let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        }
        // verify the recursive SNARK
        let res = recursive_snark.verify(&pp, z0_primary, &z0_secondary);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_commitment() {
        let memory = [
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
        ];
        let commit = <E1 as Engine>::Scalar::from(0_u64);
        let mut z0 = memory.to_vec();
        z0.push(commit);
        let z0_primary = z0.as_slice();

        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

        let address = vec![0_u64];
        let value = vec![4_u64];
        let instruction = vec![0_u64, 2_u64];

        let memory_size = memory.len();
        let num_steps = address.len();
        let circuits = MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
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

        for circuit_primary in circuits.iter().take(num_steps + 1) {
            let _ = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        }
        // verify the recursive SNARK
        let res = recursive_snark.verify(&pp, z0_primary, &z0_secondary);
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    fn test_invalid_instruction() {
        let memory = [
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
            <E1 as Engine>::Scalar::from(0_u64),
        ];
        let commit = <E1 as Engine>::Scalar::from(0_u64);
        let mut z0 = memory.to_vec();
        z0.push(commit);
        let z0_primary = z0.as_slice();

        let circuit_secondary = TrivialSecondaryCircuit::<<Dual<E1> as Engine>::Scalar>::default();

        let address = vec![0_u64];
        let value = vec![4_u64];
        let instruction = vec![2_u64, 2_u64];

        let memory_size = memory.len();
        let num_steps = address.len();
        let circuits = MemoryConsistencyCircuit::<FF, OrchardNullifierScalar, 3, 2>::new(
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

        let mut res = Vec::new();
        for circuit_primary in circuits.iter().take(num_steps + 1) {
            res.push(recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary));
        }
        assert!(res[1].is_err());
    }
}
