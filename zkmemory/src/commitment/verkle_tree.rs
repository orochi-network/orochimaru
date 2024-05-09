//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;
use group::Curve;
extern crate std;
use crate::{
    constraints,
    poseidon::poseidon_hash::{ConstantLength, Hash, OrchardNullifier, Spec},
};
use alloc::{vec, vec::Vec};
use constraints::gadgets::Table;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::{pairing::Engine, CurveAffine},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::{
        commitment::{Blind, CommitmentScheme, Params, ParamsProver, Prover},
        kzg::commitment::ParamsKZG,
        EvaluationDomain, Rotation,
    },
};
use halo2curves::pasta::{
    pallas::{Affine, Scalar},
    Fp,
};
use rand::thread_rng;
use rand_core::OsRng;
use std::println;

#[derive(Clone, Copy, Debug)]
/// Verkle tree config
pub struct VerkleTreeConfig<F: Field + PrimeField, const A: usize> {
    advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    indices: Column<Advice>,
    selector: Column<Fixed>,
    selector_zero: Selector,
    _marker: PhantomData<F>,
    table: Table<A>,
}
impl<F: Field + PrimeField, const A: usize> VerkleTreeConfig<F, A> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
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
            _marker: PhantomData,
            table,
        }
    }
}
///
#[derive(Default)]
pub(crate) struct VerkleTreeCircuit<F: Field + PrimeField, Scheme: CommitmentScheme, const A: usize>
{
    pub(crate) leaf: F,
    pub(crate) non_leaf_elements: Vec<F>,
    pub(crate) indices: Vec<F>,
    _marker: PhantomData<Scheme>,
}

impl<F: Field + PrimeField, Scheme: CommitmentScheme, const A: usize> Circuit<F>
    for VerkleTreeCircuit<F, Scheme, A>
{
    type Config = VerkleTreeConfig<F, A>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            leaf: F::ZERO,
            non_leaf_elements: vec![F::ZERO],
            indices: vec![F::ZERO],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let table = Table::<A>::construct(meta);
        VerkleTreeConfig::<F, A>::configure(meta, instance, table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
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

impl<
        'params,
        F: Field + PrimeField + WithSmallOrderMulGroup<3>,
        Scheme: CommitmentScheme,
        const A: usize,
    > VerkleTreeCircuit<F, Scheme, A>
where
    Scheme::Scalar: Field + PrimeField + WithSmallOrderMulGroup<3>,
{
    fn vec_commit<
        S: Spec<Scheme::Scalar, W, R> + Clone,
        P: Prover<'params, Scheme>,
        const W: usize,
        const R: usize,
    >(
        child: [Scheme::Scalar; A],
        omega_power: &[Scheme::Scalar],
        params: &'params Scheme::ParamsProver,
        k: u32,
    ) -> F {
        let rng = thread_rng();
        let domain = EvaluationDomain::new(1, k);
        let poly = domain.coeff_from_vec(lagrange_interpolate(omega_power, &child));
        let blind = Blind::<Scheme::Scalar>::new(&mut OsRng);
        let commit: Scheme::Curve = params.commit(&poly, blind).to_affine();
        let coordinates = commit.coordinates().unwrap();
        let x = coordinates.x();
        let y = coordinates.y();
        // TODO: try to convert x,y from Scheme::Curve::Base into Scheme::Scalar type
        Hash::<Scheme::Scalar, S, ConstantLength<2>, W, R>::init().hash([x, y])
    }
    fn assign(
        &self,
        value: F,
        region: &mut Region<'_, F>,
        config: VerkleTreeConfig<F, A>,
        offset: usize,
    ) -> Result<F, Error> {
        region.assign_advice(
            || "value of the verious node",
            config.advice[0],
            offset,
            || Value::known(value),
        )?;
        region.assign_fixed(
            || "selector",
            config.selector,
            offset,
            || Value::known(F::ONE),
        )?;
        config.selector_zero.enable(region, offset)?;
        Ok((F::ZERO))
    }
}
