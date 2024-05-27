//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;
use group::Curve;
extern crate std;
use crate::{
    base::B256,
    constraints,
    poseidon::poseidon_hash::{ConstantLength, Hash, Spec},
};
use alloc::{vec, vec::Vec};
use constraints::gadgets::Table;
use ff::{Field, PrimeField, PrimeFieldBits, WithSmallOrderMulGroup};
use halo2_proofs::{
    arithmetic::lagrange_interpolate,
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::{
        bn256::{Fq12, G2Affine, Gt},
        pairing::Engine,
        CurveAffine,
    },
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
    check: Column<Advice>,
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
        let check = meta.advice_column();
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

        meta.create_gate("verification result should be valid", |meta| {
            let check = meta.query_advice(check, Rotation::cur());
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![selector * (check - Expression::Constant(Fr::ONE))]
        });

        VerkleTreeConfig {
            advice,
            check,
            instance,
            indices,
            selector,
            selector_zero,
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
    pub(crate) proof: Vec<G1Affine>,
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
            proof: vec![G1Affine::generator()],
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
                            self.proof[i],
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
    fn vec_commit(child: [Fr; A], omega_power: &[Fr], k: u32, params: ParamsKZG<Bn256>) -> Fr {
        let domain = EvaluationDomain::new(1, k);
        let poly = domain.coeff_from_vec(lagrange_interpolate(omega_power, &child));
        let blind = Blind::<Fr>::new(&mut OsRng);
        let commit = params.commit(&poly, blind).to_affine();
        let coordinates = commit.coordinates().unwrap();
        let x = coordinates.x().to_bytes();
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

        let coordinates = commitment.coordinates().unwrap();
        let x = coordinates.x().to_bytes();
        let y = coordinates.y().to_bytes();
        let x_fr = Fr::from(B256::from(x));
        let y_fr = Fr::from(B256::from(y));
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

        region.assign_fixed(
            || "selector",
            config.selector,
            offset,
            || Value::known(Fr::ONE),
        )?;

        let e1 = Bn256::pairing(&commitment, &G2Affine::generator());

        let g2 = self.params.s_g2() - &self.mul_g2(index);
        let g2 = halo2_proofs::halo2curves::bn256::G2Affine::from(g2);
        let e2 = Bn256::pairing(&proof, &g2);

        let g3 = self.mul_g2(cur_value);
        let e3 = Bn256::pairing(&G1Affine::generator(), &g3);

        let sub = e1 - e2 - e3;
        let b = Fr::from(sub.eq(&Gt::identity()));

        region.assign_advice(
            || "result of verification",
            config.check,
            offset,
            || Value::known(b),
        )?;

        config.selector_zero.enable(region, offset)?;
        Ok(())
    }

    fn mul_g2(&self, scalar: Fr) -> G2Affine {
        let g2 = G2Affine::generator();
        let mut sum = G2Affine::generator();
        let bits = to_bin(scalar.to_bytes());
        for i in 1..bits.len() {
            if bits[i] == 0 {
                sum = (sum.clone() + sum.clone()).into();
            } else {
                sum = (sum.clone() + sum.clone() + g2).into();
            }
        }
        sum
    }
}

fn to_bin(v: [u8; 32]) -> [u8; 256] {
    let mut bin = [0; 256];
    for i in 0..32 {
        let mut tmp = v[31 - i];
        for j in 0..8 {
            bin[8 * (32 - i) - 1 - j] = tmp % 2;
            tmp = tmp / 2;
        }
    }
    bin
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::poseidon_hash::*;
    use alloc::vec;
    use core::marker::PhantomData;
    use rand::{thread_rng, Rng};
    use std::println;
    #[test]

    fn test_1() {
        let leaf = Fr::from(0u64);
        let k = 10;
        let non_leaf_elements = vec![
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];
        let params = ParamsKZG::<Bn256>::new(3);
        let commitment = vec![G1Affine::generator(); 4];
        let proof = vec![G1Affine::generator(); 4];
        let indices = vec![
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];

        let mut rng = thread_rng();
        let mut chunk = [0u8; 32];
        for e in chunk.iter_mut() {
            *e = rng.gen_range(u8::MIN..u8::MAX);
        }
        chunk[31] = 0u8;
        let fr = Fr::from_bytes(&chunk).expect("Unable to convert to Fr");
        let chunk_fr: [u8; 32] = fr.try_into().expect("Cannot convert from Fr to bytes");

        assert_eq!(chunk_fr, chunk);
    }
}
