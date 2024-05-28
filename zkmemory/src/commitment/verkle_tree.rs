//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;
extern crate std;
use crate::{
    constraints,
    poseidon::poseidon_hash::{ConstantLength, Hash, Spec},
};
use alloc::{vec, vec::Vec};
use constraints::gadgets::Table;
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::CurveAffineExt,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
            strategy::AccumulatorStrategy,
        },
        Rotation,
    },
    transcript::{Blake2bRead, Challenge255},
};

use super::kzg::verify_kzg_proof;

#[derive(Clone, Copy, Debug)]
/// Verkle tree config
pub struct VerkleTreeConfig<const A: usize> {
    advice: [Column<Advice>; 2],
    check: Column<Advice>,
    pub instance: Column<Instance>,
    indices: Column<Advice>,
    selector: Column<Fixed>,
    selector_check: Selector,
    table: Table<A>,
}
impl<const A: usize> VerkleTreeConfig<A> {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        instance: Column<Instance>,
        table: Table<A>,
    ) -> Self {
        let advice = [0; 2].map(|_| meta.advice_column());
        let check = meta.advice_column();
        let selector = meta.fixed_column();
        let selector_check = meta.selector();
        let indices = meta.advice_column();
        for i in advice {
            meta.enable_equality(i);
        }

        table.range_check(meta, "indices must be in 0..k", |meta| {
            meta.query_advice(indices, Rotation::cur())
        });

        meta.create_gate("previous commit is equal to current", |meta| {
            let advice_cur = advice.map(|x| meta.query_advice(x, Rotation::cur()));
            let advice_prev = advice.map(|x| meta.query_advice(x, Rotation::prev()));
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![selector * (advice_prev[1].clone() - advice_cur[0].clone())]
        });

        meta.create_gate("verification result should be valid", |meta| {
            let check = meta.query_advice(check, Rotation::cur());
            let selector_check = meta.query_selector(selector_check);
            vec![selector_check * (check - Expression::Constant(Fr::ONE))]
        });

        VerkleTreeConfig {
            advice,
            check,
            instance,
            indices,
            selector,
            selector_check,
            table,
        }
    }
}
///

pub(crate) struct VerkleTreeCircuit<
    S: Spec<Fr, W, R>,
    const W: usize,
    const R: usize,
    const A: usize,
> {
    pub(crate) leaf: Fr,
    pub(crate) commitment: Vec<G1Affine>,
    pub(crate) proof: Vec<u8>,
    pub(crate) non_leaf_elements: Vec<Fr>,
    pub(crate) indices: Vec<Fr>,
    pub(crate) params: ParamsKZG<Bn256>,
    _marker: PhantomData<S>,
}

impl<S: Spec<Fr, W, R>, const W: usize, const R: usize, const A: usize> Circuit<Fr>
    for VerkleTreeCircuit<S, W, R, A>
{
    type Config = VerkleTreeConfig<A>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Fr::ZERO,
            commitment: vec![G1Affine::generator()],
            proof: vec![0],
            non_leaf_elements: vec![Fr::ZERO],
            indices: vec![Fr::ZERO],
            params: ParamsKZG::<Bn256>::new(1),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let table = Table::<A>::construct(meta);
        VerkleTreeConfig::<A>::configure(meta, instance, table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        assert_eq!(self.indices.len(), self.non_leaf_elements.len());

        let leaf_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| {
                region.assign_advice(
                    || "assign leaf",
                    config.advice[0],
                    0,
                    || Value::known(self.leaf),
                )
            },
        )?;

        layouter.assign_region(
            || "Verkle proof",
            |mut region| {
                for i in 0..self.non_leaf_elements.len() {
                    if i == 0 {
                        self.assign(
                            self.leaf,
                            self.commitment[i],
                            self.indices[i],
                            &mut region,
                            config,
                            i,
                        )?;
                    } else {
                        self.assign(
                            self.non_leaf_elements[i - 1],
                            self.commitment[i],
                            self.indices[i],
                            &mut region,
                            config,
                            i,
                        )?;
                    }
                }
                config.table.load(&mut region)?;
                Ok(())
            },
        )?;

        let mut poly_list = vec![];
        poly_list.push(self.leaf);
        for i in 0..self.non_leaf_elements.len() - 1 {
            poly_list.push(self.non_leaf_elements[i]);
        }

        let b = verify_kzg_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&'_ [u8], G1Affine, Challenge255<G1Affine>>,
            AccumulatorStrategy<'_, Bn256>,
        >(
            &self.params,
            self.indices.clone(),
            poly_list,
            self.commitment.clone(),
            self.proof.as_slice(),
        );
        let b = Fr::from(b);

        layouter.assign_region(
            || "assign check result",
            |mut region| {
                config.selector_check.enable(&mut region, 0)?;
                region.assign_advice(
                    || "assign check result",
                    config.check,
                    0,
                    || Value::known(b),
                )
            },
        )?;

        let root = layouter.assign_region(
            || "assign root",
            |mut region| {
                region.assign_advice(
                    || "assign root",
                    config.advice[0],
                    0,
                    || Value::known(self.non_leaf_elements[self.non_leaf_elements.len() - 1]),
                )
            },
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(root.cell(), config.instance, 1)?;
        Ok(())
    }
}

impl<S: Spec<Fr, W, R>, const W: usize, const R: usize, const A: usize>
    VerkleTreeCircuit<S, W, R, A>
{
    fn assign(
        &self,
        cur_value: Fr,
        commitment: G1Affine,
        index: Fr,
        region: &mut Region<'_, Fr>,
        config: VerkleTreeConfig<A>,
        offset: usize,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "value of the current node",
            config.advice[0],
            offset,
            || Value::known(cur_value),
        )?;
        let (x, y) = commitment.into_coordinates();
        let x_fr = Fr::from_bytes(&x.to_bytes()).unwrap();
        let y_fr = Fr::from_bytes(&y.to_bytes()).unwrap();
        let next_value = Hash::<Fr, S, ConstantLength<2>, W, R>::init().hash([x_fr, y_fr]);

        region.assign_advice(
            || "value of the next node",
            config.advice[1],
            offset,
            || Value::known(next_value),
        )?;

        region.assign_advice(
            || "the index of the layer",
            config.indices,
            offset,
            || Value::known(index),
        )?;

        if offset != 0 {
            region.assign_fixed(
                || "selector",
                config.selector,
                offset,
                || Value::known(Fr::ONE),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::kzg::create_kzg_proof,
        poseidon::{
            poseidon_constants::{MDS_FR, MDS_INV_FR, ROUND_CONSTANTS_FR},
            poseidon_hash::*,
        },
    };
    use alloc::vec;
    use core::marker::PhantomData;
    use group::Curve;
    use halo2_proofs::{
        arithmetic::lagrange_interpolate,
        dev::MockProver,
        halo2curves::CurveAffineExt,
        poly::{
            commitment::Blind, kzg::multiopen::ProverSHPLONK, Coeff, EvaluationDomain, Polynomial,
        },
        transcript::Blake2bWrite,
    };
    use rand_core::OsRng;
    ///
    pub struct KZGTest {
        kzg_params: ParamsKZG<Bn256>,
        domain: EvaluationDomain<Fr>,
    }

    impl KZGTest {
        /// Initialize KZG parameters
        pub fn new(k: u32) -> Self {
            Self {
                kzg_params: ParamsKZG::<Bn256>::new(k),
                domain: EvaluationDomain::new(1, k),
            }
        }

        pub fn poly_from_evals(&self, evals: [Fr; 4]) -> Polynomial<Fr, Coeff> {
            // Use Lagrange interpolation
            self.domain.coeff_from_vec(lagrange_interpolate(
                &[Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)],
                &evals,
            ))
        }

        pub fn commit(&self, evals: [Fr; 4]) -> G1Affine {
            self.kzg_params
                .commit(&self.poly_from_evals(evals), Blind(Fr::random(OsRng)))
                .to_affine()
        }

        pub fn create_proof(
            &self,
            point: Vec<Fr>,
            polynomial: Vec<Polynomial<Fr, Coeff>>,
            commitment: Vec<G1Affine>,
        ) -> Vec<u8> {
            create_kzg_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            >(&self.kzg_params, point, polynomial, commitment)
        }

        pub fn group_to_scalar<S: Spec<Fr, W, R>, const W: usize, const R: usize>(
            &self,
            g: G1Affine,
        ) -> Fr {
            let (x, y) = g.into_coordinates();
            let x_fr = Fr::from_bytes(&x.to_bytes()).unwrap();
            let y_fr = Fr::from_bytes(&y.to_bytes()).unwrap();
            Hash::<Fr, S, ConstantLength<2>, W, R>::init().hash([x_fr, y_fr])
        }
    }

    #[derive(Clone, Debug)]
    pub struct OrchardNullifier;

    impl Spec<Fr, 3, 2> for OrchardNullifier {
        fn full_rounds() -> usize {
            8
        }

        fn partial_rounds() -> usize {
            56
        }

        fn sbox(val: Fr) -> Fr {
            val.pow_vartime([5])
        }

        fn constants() -> (Vec<[Fr; 3]>, Mtrx<Fr, 3>, Mtrx<Fr, 3>) {
            (ROUND_CONSTANTS_FR[..].to_vec(), MDS_FR, MDS_INV_FR)
        }
    }

    #[test]

    fn test_valid_verkle_tree() {
        let kzg = KZGTest::new(2);
        let leaf = Fr::from(1);
        let indices = vec![Fr::from(1)];
        let evals = [Fr::from(3), leaf, Fr::from(7), Fr::from(15)];
        let poly0 = vec![kzg.poly_from_evals(evals)];
        let commit = kzg.commit(evals);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commit);
        let non_leaf_elements = vec![root];
        let commitment = vec![commit];
        let proof = kzg.create_proof(vec![Fr::from(1)], poly0, commitment.clone());

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment,
            proof,
            non_leaf_elements,
            indices,
            params: kzg.kzg_params,
            _marker: PhantomData,
        };

        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_verkle_root() {
        let kzg = KZGTest::new(2);
        let leaf = Fr::from(1);
        let indices = vec![Fr::from(0)];
        let evals = [leaf, Fr::from(0), Fr::from(0), Fr::from(0)];
        let poly0 = vec![kzg.poly_from_evals(evals)];
        let commit = kzg.commit(evals);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commit);
        let non_leaf_elements = vec![Fr::from(0)];
        let commitment = vec![commit];
        let proof = kzg.create_proof(vec![Fr::from(0)], poly0, commitment.clone());

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment,
            proof,
            non_leaf_elements,
            indices,
            params: kzg.kzg_params,
            _marker: PhantomData,
        };

        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_opening_index() {
        let kzg = KZGTest::new(2);
        let leaf = Fr::from(1);
        let indices = vec![Fr::from(0)];
        let evals = [leaf, Fr::from(0), Fr::from(0), Fr::from(0)];
        let poly0 = vec![kzg.poly_from_evals(evals)];
        let commit = kzg.commit(evals);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commit);
        let non_leaf_elements = vec![root];
        let commitment = vec![commit];
        let proof = kzg.create_proof(vec![Fr::from(1)], poly0, commitment.clone());

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment,
            proof,
            non_leaf_elements,
            indices,
            params: kzg.kzg_params,
            _marker: PhantomData,
        };

        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_verkle_tree_2() {
        let kzg = KZGTest::new(2);
        let leaf = Fr::from(1);
        let indices = vec![Fr::from(0), Fr::from(1)];
        let evals = [leaf, Fr::from(1), Fr::from(3), Fr::from(5)];
        let poly0 = kzg.poly_from_evals(evals);
        let commit_0 = kzg.commit(evals);
        let non_leaf_0 = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commit_0);
        let evals_1 = [Fr::from(0), non_leaf_0, Fr::from(3), Fr::from(5)];
        let poly1 = kzg.poly_from_evals(evals_1);
        let commit_1 = kzg.commit(evals_1);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commit_1);

        let non_leaf_elements = vec![non_leaf_0, root];
        let commitment = vec![commit_0, commit_1];
        let proof = kzg.create_proof(
            vec![Fr::from(0), Fr::from(1)],
            vec![poly0, poly1],
            commitment.clone(),
        );

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment,
            proof,
            non_leaf_elements,
            indices,
            params: kzg.kzg_params,
            _marker: PhantomData,
        };

        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }
}
