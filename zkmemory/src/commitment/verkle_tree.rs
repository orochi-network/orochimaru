//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;
use ethnum::U256;
use group::Curve;
extern crate std;
use crate::{
    base::{Uint, B256},
    constraints,
    poseidon::poseidon_hash::{ConstantLength, Hash, OrchardNullifier, Spec},
};
use alloc::{vec, vec::Vec};
use constraints::gadgets::Table;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::{bn256::G2Affine, pairing::Engine, CurveAffine},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::{
        commitment::{Blind, CommitmentScheme, Params, ParamsProver, Prover},
        kzg::commitment::ParamsKZG,
        EvaluationDomain, Rotation,
    },
};
use halo2curves::pasta::pallas::{Affine, Scalar};
use rand_core::OsRng;
use std::println;

#[derive(Clone, Copy, Debug)]
/// Verkle tree config
pub struct VerkleTreeConfig<const A: usize> {
    advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    indices: Column<Advice>,
    selector: Column<Fixed>,
    selector_zero: Selector,
}
impl<const A: usize> VerkleTreeConfig<A> {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        instance: Column<Instance>,
        table: Table<A>,
    ) -> Self {
        let advice = [0; 2].map(|_| meta.advice_column());
        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
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

        VerkleTreeConfig {
            advice,
            instance,
            indices,
            selector,
            selector_zero,
        }
    }
}
///
#[derive(Default)]
pub(crate) struct VerkleTreeCircuit<const A: usize> {
    pub(crate) leaf: Fr,
    pub(crate) commitment: Vec<G1Affine>,
    pub(crate) proof: Vec<G1Affine>,
    pub(crate) non_leaf_elements: Vec<Fr>,
    pub(crate) indices: Vec<Fr>,
}

impl<const A: usize> Circuit<Fr> for VerkleTreeCircuit<A> {
    type Config = VerkleTreeConfig<A>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Fr::ZERO,
            commitment: vec![G1Affine::generator()],
            proof: vec![G1Affine::generator()],
            non_leaf_elements: vec![Fr::ZERO],
            indices: vec![Fr::ZERO],
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
        let mut v = vec![self.leaf];

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
                            self.proof[i],
                            self.non_leaf_elements[i],
                            self.indices[i],
                            &mut region,
                            config,
                            i,
                        )?;
                    } else {
                        self.assign(
                            self.non_leaf_elements[i - 1],
                            self.commitment[i],
                            self.proof[i],
                            self.non_leaf_elements[i],
                            self.indices[i],
                            &mut region,
                            config,
                            i,
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        let root = layouter.assign_region(
            || "assign root",
            |mut region| {
                region.assign_advice(
                    || "assign root",
                    config.advice[0],
                    0,
                    || Value::known(v[self.indices.len()]),
                )
            },
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(root.cell(), config.instance, 1)?;
        Ok(())
    }
}

impl<const A: usize> VerkleTreeCircuit<A> {
    fn vec_commit<S: Spec<Fr, W, R> + Clone, const W: usize, const R: usize>(
        child: [Fr; A],
        omega_power: &[Fr],
        params: ParamsKZG<Bn256>,
        k: u32,
    ) -> Fr {
        let domain = EvaluationDomain::new(1, k);
        let poly = domain.coeff_from_vec(lagrange_interpolate(omega_power, &child));
        let blind = Blind::<Fr>::new(&mut OsRng);
        let commit = params.commit(&poly, blind).to_affine();
        let coordinates = commit.coordinates().unwrap();
        let x: [u8; 32] = coordinates.x().to_bytes();
        let y = coordinates.y().to_bytes();
        let x_fr = Fr::from(B256::from(x));
        let y_fr = Fr::from(B256::from(y));
        let hash = Hash::<Fr, S, ConstantLength<2>, W, R>::init().hash([x_fr, y_fr]);
        hash
    }

    fn assign(
        &self,
        cur_value: Fr,
        commitment: G1Affine,
        proof: G1Affine,
        next_value: Fr,
        index: Fr,
        region: &mut Region<'_, Fr>,
        config: VerkleTreeConfig<A>,
        offset: usize,
    ) -> Result<Fr, Error> {
        region.assign_advice(
            || "value of the current node",
            config.advice[0],
            offset,
            || Value::known(cur_value),
        )?;

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

        region.assign_fixed(
            || "selector",
            config.selector,
            offset,
            || Value::known(Fr::ONE),
        )?;

        let e1 = Bn256::pairing(&commitment, &G2Affine::generator());
        let e2 = Bn256::pairing(&proof, &G2Affine::generator());
        let e3 = Bn256::pairing(&G1Affine::generator(), &G2Affine::generator());

        config.selector_zero.enable(region, offset)?;
        Ok((Fr::ZERO))
    }
}
