#[cfg(test)]
mod test {

    use ff::Field;
    use nova_snark::{
        provider::{Bn256EngineKZG, GrumpkinEngine},
        traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
        PublicParams, RecursiveSNARK,
    };

    use crate::nova::memory_consistency_circuit::NovaMemoryConsistencyCircuit;
    type E1 = Bn256EngineKZG;
    type E2 = GrumpkinEngine;
    type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
    type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK
    #[test]
    // test correct memory consistency in one step
    fn test_memory_consistency_in_one_step() {
        let address = [0 as u64].to_vec();
        let instruction = [1 as u64].to_vec();
        let value = [1292001 as u64].to_vec();
        // let num_steps = 10;
        let circuit_primary = NovaMemoryConsistencyCircuit::<<E1 as Engine>::GE>::new(
            4,
            1,
            address,
            instruction,
            value,
        );
        let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

        type C1 = NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>;
        type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

        let pp = PublicParams::<
            E1,
            E2,
            NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>,
            TrivialCircuit<<E2 as Engine>::Scalar>,
        >::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S1::ck_floor(),
            &*S2::ck_floor(),
        )
        .expect("unable to setup");

        let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::zero()],
        )
        .expect("unable to prove");

        let _ = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
        // assert!(res.is_ok());
        // println!("{:?}", res);

        let res = recursive_snark.verify(
            &pp,
            1,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::ZERO],
        );
        assert_eq!(res.is_ok(), true);
    }

    // for simolicity we experiment with a memory of size 4
    // test memory consistency in two steps
    #[test]
    fn test_memory_consistency_in_two_steps() {
        let address = [0 as u64, 0 as u64].to_vec();
        let instruction = [1 as u64, 0 as u64].to_vec();
        let value = [1292001 as u64, 1292001 as u64].to_vec();
        // let num_steps = 10;
        let circuit_primary = NovaMemoryConsistencyCircuit::<<E1 as Engine>::GE>::new(
            4,
            2,
            address,
            instruction,
            value,
        );
        let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

        type C1 = NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>;
        type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

        let pp = PublicParams::<
            E1,
            E2,
            NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>,
            TrivialCircuit<<E2 as Engine>::Scalar>,
        >::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S1::ck_floor(),
            &*S2::ck_floor(),
        )
        .expect("unable to setup");

        let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::zero()],
        )
        .expect("unable to prove");

        let _ = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
        // assert!(res.is_ok());
        // println!("{:?}", res);

        let res = recursive_snark.verify(
            &pp,
            1,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::ZERO],
        );
        assert_eq!(res.is_ok(), true);
    }

    #[test]
    // test invalid instruction in trace record
    fn test_invalid_instruction() {
        let address = [0 as u64].to_vec();
        let instruction = [2 as u64].to_vec();
        let value = [1292001 as u64].to_vec();
        // let num_steps = 10;
        let circuit_primary = NovaMemoryConsistencyCircuit::<<E1 as Engine>::GE>::new(
            4,
            1,
            address,
            instruction,
            value,
        );
        let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

        type C1 = NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>;
        type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

        let pp = PublicParams::<
            E1,
            E2,
            NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>,
            TrivialCircuit<<E2 as Engine>::Scalar>,
        >::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S1::ck_floor(),
            &*S2::ck_floor(),
        )
        .expect("unable to setup");

        let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::zero()],
        )
        .expect("unable to prove");

        let _ = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
        //assert!(res.is_ok());
        //  println!("{:?}", res);

        let res = recursive_snark.verify(
            &pp,
            1,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::ZERO],
        );
        assert_ne!(res.is_ok(), true);
    }

    #[test]
    // test invalid read
    fn test_invalid_read() {
        let address = [0 as u64].to_vec();
        let instruction = [0 as u64].to_vec();
        let value = [1292001 as u64].to_vec();
        // let num_steps = 10;
        let circuit_primary = NovaMemoryConsistencyCircuit::<<E1 as Engine>::GE>::new(
            4,
            1,
            address,
            instruction,
            value,
        );
        let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

        type C1 = NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>;
        type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

        let pp = PublicParams::<
            E1,
            E2,
            NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>,
            TrivialCircuit<<E2 as Engine>::Scalar>,
        >::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S1::ck_floor(),
            &*S2::ck_floor(),
        )
        .expect("unable to setup");

        let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::zero()],
        )
        .expect("unable to prove");

        let _ = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
        //assert!(res.is_ok());
        //  println!("{:?}", res);

        let res = recursive_snark.verify(
            &pp,
            1,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(3 as u64),
            ],
            &[<E2 as Engine>::Scalar::ZERO],
        );
        assert_ne!(res.is_ok(), true);
    }

    #[test]
    // test invalid commitment
    fn test_invalid_commitment() {
        let address = [0 as u64].to_vec();
        let instruction = [0 as u64].to_vec();
        let value = [1292001 as u64].to_vec();
        // let num_steps = 10;
        let circuit_primary = NovaMemoryConsistencyCircuit::<<E1 as Engine>::GE>::new(
            4,
            1,
            address,
            instruction,
            value,
        );
        let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

        type C1 = NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>;
        type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

        let pp = PublicParams::<
            E1,
            E2,
            NovaMemoryConsistencyCircuit<<E1 as Engine>::GE>,
            TrivialCircuit<<E2 as Engine>::Scalar>,
        >::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S1::ck_floor(),
            &*S2::ck_floor(),
        )
        .expect("unable to setup");

        let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(99 as u64),
            ],
            &[<E2 as Engine>::Scalar::zero()],
        )
        .expect("unable to prove");

        let _ = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
        //assert!(res.is_ok());
        //  println!("{:?}", res);

        let res = recursive_snark.verify(
            &pp,
            1,
            &[
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::zero(),
                <E1 as Engine>::Scalar::from(99 as u64),
            ],
            &[<E2 as Engine>::Scalar::ZERO],
        );
        assert_ne!(res.is_ok(), true);
    }
}
