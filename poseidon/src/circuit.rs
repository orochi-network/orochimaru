//! The poseidon circuit, with most details based from
//! [Zcash implementation](https://github.com/summa-dev/halo2/blob/main/halo2_gadgets/src/poseidon/pow5.rs).
//! We originally wanted to import the implementation from Zcash's library directly.
//! However, since we are using the Halo2 version from PSE, we need to
//! clone many functions and fix some details so that the implementation
//! will be compatible with our implementation.
extern crate alloc;
use core::marker::PhantomData;

use alloc::{format, vec::Vec};
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, ProvingKey
    },
    poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand_core::OsRng;

use super::gadgets::{Hash};
use super::poseidon_hash::{ConstantLength, Domain, Spec};
use super::chip::{PoseidonConfig, PoseidonChip};

#[derive(Debug, Clone)]
pub struct PoseidonCircuit<
    S: Spec<F, T, R> + Clone,
    F: PrimeField,
    D: Domain<F, R> + Clone,
    const T: usize,
    const R: usize,
    const L: usize,
> {
    pub message: [F; L],
    // For the purpose of this test, witness the result.
    // TODO: Move this into an instance column.
    pub output: F,
    pub _marker: PhantomData<D>,
    pub _marker2: PhantomData<S>,
}
impl<
        S: Spec<F, T, R> + Clone,
        F: PrimeField,
        D: Domain<F, R> + Clone,
        const T: usize,
        const R: usize,
        const L: usize,
    > Circuit<F> for PoseidonCircuit<S, F, D, T, R, L>
{
    type Config = PoseidonConfig<F, T, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: [F::ZERO; L],
            output: F::ZERO,
            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, T, R> {
        let state = (0..T)
            .map(|_| meta.advice_column())
            .collect::<Vec<Column<Advice>>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..T)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        let rc_b = (0..T)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        meta.enable_constant(rc_b[0]);

        let chip = PoseidonChip::configure::<S>(
                meta,
                state.clone().try_into().expect("could not load state"),
                partial_sbox,
                rc_a.clone().try_into().expect("could not load rc_a"),
                rc_b.clone().try_into().expect("could not load rc_b"),
            );

        chip.config
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, T, R>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = PoseidonChip::new(config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = Value::known(self.message[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.state[i],
                        0,
                        || value,
                    )
                };
                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().expect("cannot unwrap message"))
            },
        )?;

        let hasher = Hash::<F, S, ConstantLength<L>, T, R>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_var = region.assign_advice(
                    || "load output",
                    config.state[0],
                    0,
                    || Value::known(self.output),
                )?;
                region.constrain_equal(output.cell(), expected_var.cell())
            },
        )
    }
}

pub struct PoseidonProver<S, D, const T: usize, const R: usize, const L: usize>
where
    S: Spec<Fr, T, R> + Clone,
    D: Domain<Fr, R> + Clone,
{
    params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
    circuit: PoseidonCircuit<S, Fr, D, T, R, L>,
    expected: bool,
}

impl<S, D, const T: usize, const R: usize, const L: usize> PoseidonProver<S, D, T, R, L>
where
    S: Spec<Fr, T, R> + Clone,
    D: Domain<Fr, R> + Clone,
{
    /// initialize the parameters for the prover
    pub fn new(k: u32, circuit: PoseidonCircuit<S, Fr, D, T, R, L>, expected: bool) -> Self {
        let params = ParamsKZG::<Bn256>::setup(k, OsRng); // TODO add production level trusted setup
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize proving key");
        Self {
            params,
            pk,
            circuit,
            expected,
        }
    }

    /// Create proof for the permutation circuit
    pub fn create_proof(&mut self) -> Vec<u8> {
        let mut transcript =
            Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            OsRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            PoseidonCircuit<S, Fr, D, T, R, L>,
        >(
            &self.params,
            &self.pk,
            &[self.circuit.clone()],
            &[&[]],
            OsRng,
            &mut transcript,
        )
        .expect("Fail to create proof.");
        transcript.finalize()
    }

    /// Verify the proof (by comparing the result with expected value)
    pub fn verify(&mut self, proof: Vec<u8>) -> bool {
        let strategy = SingleStrategy::new(&self.params);
        let mut transcript =
            Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(&proof[..]);
        let result = verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &self.params,
            self.pk.get_vk(),
            strategy,
            &[&[]], // NOTE
            &mut transcript,
        );
        match result {
            Ok(()) => self.expected,
            Err(_) => !self.expected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_hash::{Hash, OrchardNullifier};
    use alloc::vec;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand::rngs::OsRng;
    #[test]
    fn poseidon_hash() {
        let rng = OsRng;

        let message = [Fr::random(rng), Fr::random(rng)];
        let output = Hash::<Fr, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let k = 6;
        let circuit = PoseidonCircuit::<OrchardNullifier, Fr, ConstantLength<2>, 3, 2, 2> {
            message,
            output,
            _marker: PhantomData,
            _marker2: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).expect("cannot prove");
        assert_eq!(prover.verify(), Ok(()))
    }
}
