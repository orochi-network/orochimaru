extern crate alloc;
extern crate std;
use crate::poseidon::{
    poseidon::{ConstantLength, HashTest, Spec},
};
use alloc::{vec, vec::Vec};
use core::fmt::Debug;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use std::println;

#[derive(Clone, Copy, Debug)]
/// Merkle tree config
pub struct MerkleTreeConfig<F: Field + PrimeField> {
    advice: [Column<Advice>; 3],
    indices: Column<Advice>,
    pub instance: Column<Instance>,
    selector: Column<Fixed>,
    // the selectors
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> MerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> Self {
        let advice = [0; 3].map(|_| meta.advice_column());
        let indices = meta.advice_column();
        let selector = meta.fixed_column();
        for i in 0..3 {
            meta.enable_equality(advice[i]);
        }
        let one = Expression::Constant(F::ONE);
        meta.create_gate("xxxx", |meta| {
            let advice_cur = advice.map(|x| meta.query_advice(x, Rotation::cur()));
            let advice_prev = advice.map(|x| meta.query_advice(x, Rotation::prev()));
            let indices = meta.query_advice(indices, Rotation::cur());
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![
                selector
                    * ((one - indices.clone()) * (advice_cur[0].clone() - advice_prev[2].clone())
                        + indices * (advice_cur[1].clone() - advice_prev[2].clone())),
            ]
        });

        MerkleTreeConfig {
            advice,
            indices,
            instance,
            selector,
            _marker: PhantomData,
        }
    }
}

#[derive(Default)]
/// circuit for verifying the correctness of the opening
pub struct MemoryTreeCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
> {
    leaf: F,
    elements: Vec<F>,
    indices: Vec<F>,
    _marker: PhantomData<S>,
}
impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize> Circuit<F>
    for MemoryTreeCircuit<S, F, W, R>
{
    type Config = MerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: F::ZERO,
            elements: vec![F::ZERO],
            indices: vec![F::ZERO],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        MerkleTreeConfig::<F>::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        assert_eq!(self.indices.len(), self.elements.len());
        let mut v = vec![self.leaf];

        layouter.assign_region(
            || "Merkle proof",
            |mut region| {
                for i in 0..self.indices.len() {
                    let digest = self.assign(v[i], &mut region, config, i);
                    v.push(digest.unwrap());
                }

                println!("{:?}", v[self.indices.len()]);
                Ok(())
            },
        )?;

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

        let digest = layouter.assign_region(
            || "assign root",
            |mut region| {
                region.assign_advice(
                    || "assign leaf",
                    config.advice[0],
                    0,
                    || Value::known(v[self.indices.len()]),
                )
            },
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.clone().instance, 0)?;
        layouter.constrain_instance(digest.cell(), config.clone().instance, 1)?;
        Ok(())
    }
}

impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize>
    MemoryTreeCircuit<S, F, W, R>
{
    pub fn assign(
        &self,
        digest: F,
        region: &mut Region<'_, F>,
        config: MerkleTreeConfig<F>,
        offset: usize,
    ) -> Result<F, Error> {
        if offset != 0 {
            region.assign_fixed(
                || "selector",
                config.selector,
                offset,
                || Value::known(F::ONE),
            )?;
        }
        let hash: F;
        region.assign_advice(
            || "indices",
            config.indices,
            offset,
            || Value::known(self.indices[offset]),
        )?;

        if self.indices[offset] == F::ZERO {
            region.assign_advice(
                || "left input",
                config.advice[0],
                offset,
                || Value::known(digest),
            )?;
            region.assign_advice(
                || "right input",
                config.advice[1],
                offset,
                || Value::known(self.elements[offset]),
            )?;
            hash = HashTest::<F, S, ConstantLength<2>, W, R>::init()
                .hash([digest, self.elements[offset]]);

            region.assign_advice(|| "output", config.advice[2], offset, || Value::known(hash))?;
        } else {
            region.assign_advice(
                || "left input",
                config.advice[0],
                offset,
                || Value::known(self.elements[offset]),
            )?;
            region.assign_advice(
                || "right input",
                config.advice[1],
                offset,
                || Value::known(digest),
            )?;
            hash = HashTest::<F, S, ConstantLength<2>, W, R>::init()
                .hash([self.elements[offset], digest]);
            region.assign_advice(|| "output", config.advice[2], offset, || Value::known(hash))?;
        }
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;
    use core::marker::PhantomData;
    use std::println;

    use crate::poseidon::poseidon::*;
    use crate::poseidon::poseidon_constants::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use ff::Field;
    use halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};

    use super::MemoryTreeCircuit;

    ///
    #[derive(Clone, Debug)]
    pub struct OrchardNullifier;

    impl Spec<Fp, 3, 2> for OrchardNullifier {
        fn full_rounds() -> usize {
            8
        }

        fn partial_rounds() -> usize {
            56
        }

        fn sbox(val: Fp) -> Fp {
            val.pow_vartime([5])
        }

        fn secure_mds() -> usize {
            unimplemented!()
        }
        fn constants() -> (Vec<[Fp; 3]>, [[Fp; 3]; 3], [[Fp; 3]; 3]) {
            (ROUND_CONSTANTS[..].to_vec(), MDS, MDS_INV)
        }
    }

    fn compute_merkle_root(leaf: &u64, elements: &Vec<u64>, indices: &Vec<u64>) -> Fp {
        let k = elements.len();
        let mut digest = Fp::from(leaf.clone());
        let mut message: [Fp; 2];
        for i in 0..k {
            if indices[i] == 0 {
                message = [digest, Fp::from(elements[i])];
            } else {
                message = [Fp::from(elements[i]), digest];
            }
            digest =
                HashTest::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
        }
        digest
    }

    #[test]
    fn test_correct_merkle_proof() {
        let leaf = 0u64;
        let k = 10;
        let indices = vec![0u64, 0u64];
        let elements = vec![3u64, 4u64];
        let root = compute_merkle_root(&leaf, &elements, &indices);
        let leaf_fp = Fp::from(leaf);
        let indices = indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }
}
