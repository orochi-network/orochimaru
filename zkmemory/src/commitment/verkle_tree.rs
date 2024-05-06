//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;
extern crate std;
use std::println;

use crate::poseidon::poseidon_hash::{ConstantLength, Hash, OrchardNullifier, Spec};
use alloc::{vec, vec::Vec};
use ff::{Field, PrimeField};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use halo2curves::pasta::{pallas::Affine, Fp};

#[derive(Clone, Copy, Debug)]
/// Verkle tree config
pub struct VerkleTreeConfig<F: Field + PrimeField> {
    advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    indices: Column<Advice>,
    selector: Column<Fixed>,
    selector_zero: Selector,
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> VerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> Self {
        let advice = [0; 2].map(|_| meta.advice_column());
        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
        let indices = meta.advice_column();
        for i in advice {
            meta.enable_equality(i);
        }

        let one = Expression::Constant(F::ONE);

        // for i=0 indices[i] is equal to zero or one
        // we handle i=0 seperately with selector_zero, since we are using
        // a common selector for the other gates.
        meta.create_gate("indices must be 0 or 1", |meta| {
            let selector_zero = meta.query_selector(selector_zero);
            let indices = meta.query_advice(indices, Rotation::cur());
            vec![selector_zero * indices.clone() * (one.clone() - indices)]
        });

        // for all i>=1 indices[i] is equal to zero or one
        meta.create_gate("indices must be 0 or 1", |meta| {
            let indices = meta.query_advice(indices, Rotation::cur());
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![selector * indices.clone() * (one.clone() - indices)]
        });

        VerkleTreeConfig {
            advice,
            instance,
            indices,
            selector,
            selector_zero,
            _marker: PhantomData,
        }
    }
}
///
#[derive(Default)]
pub(crate) struct VerkleTreeCircuit<F: Field + PrimeField> {
    pub(crate) leaf: F,
    pub(crate) non_leaf_elements: Vec<F>,
    pub(crate) indices: Vec<F>,
}

impl<F: Field + PrimeField> Circuit<F> for VerkleTreeCircuit<F> {
    type Config = VerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerkleTreeConfig::<F>::configure(meta, instance)
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

// verkle tree prove and verify function
fn hash_commit(commit: &C) -> Fp {
    let preimage = commit.to_bytes();
    let preimage_fp = preimage.map(|x| Fp::from(x));
    Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(preimage_fp)
}

fn vec_commit(v: &[Fp], bases: &[Affine]) -> C {
    unimplemented!()
}

struct NonLeafNode<const A: usize> {
    poly_coeffs: Vec<Fp>,
    commit: C,
    commit_digest: Fp,
}

struct VerkleTree<const A: usize> {
    leafs: Vec<Fp>,
    non_leaf_layers: Vec<Vec<NonLeafNode<A>>>,
    root: C,
}

impl<const A: usize> VerkleTree<A> {
    fn new(leafs: Vec<Fp>, pedersen_bases: &[Affine]) -> Self {
        let num_leafs = leafs.len();

        assert!(A.is_power_of_two() && A != 1);
        assert!(num_leafs.is_power_of_two() && num_leafs >= A);
        assert_eq!(pedersen_bases.len(), A);

        let log2_arity = A.trailing_zeros() as usize;
        let log2_leafs = num_leafs.trailing_zeros() as usize;
        let height = log2_leafs / log2_arity;

        let interp_domain: Vec<Fp> = (0..A as u64).map(Fp::from).collect();

        let mut cur_layer = leafs.clone();
        let mut non_leaf_layers = Vec::<Vec<NonLeafNode<A>>>::with_capacity(height);

        for _ in 0..height {
            let next_layer: Vec<NonLeafNode<A>> = cur_layer
                .chunks(A)
                .map(|sibs| {
                    let poly_coeffs = lagrange_interpolate(&interp_domain, sibs);
                    debug_assert_eq!(poly_coeffs.len(), A);
                    let commit = vec_commit(&poly_coeffs, pedersen_bases);
                    let commit_digest = hash_commit(&commit);
                    NonLeafNode {
                        poly_coeffs,
                        commit,
                        commit_digest,
                    }
                })
                .collect();
            cur_layer = next_layer.iter().map(|node| node.commit_digest).collect();
            non_leaf_layers.push(next_layer);
        }

        debug_assert_eq!(non_leaf_layers.last().unwrap().len(), 1);
        let root = non_leaf_layers[height - 1][0].commit;

        VerkleTree {
            leafs,
            non_leaf_layers,
            root,
        }
    }

    fn root(&self) -> &C {
        &self.root
    }

    fn prove(&self, mut challenge: usize) -> VerkleProof<A> {
        debug_assert!(challenge < self.leafs.len());
        let leaf = self.leafs[challenge];
        let polys = self
            .non_leaf_layers
            .iter()
            .map(|layer| {
                challenge /= A;
                layer[challenge].poly_coeffs.to_vec()
            })
            .collect::<Vec<Vec<Fp>>>();
        VerkleProof { leaf, polys }
    }
}

#[derive(Debug)]
struct VerkleProof<const A: usize> {
    leaf: Fp,
    polys: Vec<Vec<Fp>>,
}

impl<const A: usize> VerkleProof<A> {
    fn verify(&self, mut challenge: usize, root: &C, pedersen_bases: &[Affine]) -> bool {
        let arity_bit_len = A.trailing_zeros() as usize;

        // Check `poly_0(X)` evaluates to provided leaf.
        let mut height = 0;
        let mut x = Fp::from((challenge % A) as u64);
        let mut y = eval_polynomial(&self.polys[0], x);
        if y != self.leaf {
            println!("error: poly_{}(x) != leaf", height);
            return false;
        }
        let mut commit = vec_commit(&self.polys[0], pedersen_bases);

        // Check `poly_i(X)` evaluates to the previous polynomial's commitment digest.
        for poly in &self.polys[1..] {
            height += 1;
            let commit_digest = hash_commit(&commit);
            challenge >>= arity_bit_len;
            x = Fp::from((challenge % A) as u64);
            y = eval_polynomial(poly, x);
            if y != commit_digest {
                println!("error: poly_{}(x) != commit(poly_{})", height, height - 1);
                return false;
            }
            commit = vec_commit(poly, pedersen_bases);
        }

        commit == *root
    }
}
