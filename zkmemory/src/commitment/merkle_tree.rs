// this is based on the implementation of https://github.com/DrPeterVanNostrand/halo2-merkle
extern crate alloc;
use alloc::{format, vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
struct PoseidonChipConfig {
    a_col: Column<Advice>,
    sbox_out_col: Column<Advice>,
    mds_out_col: Column<Advice>,
    pre_key_col: Column<Fixed>,
    post_key_col: Column<Fixed>,
    mds_cols: Vec<Column<Fixed>>,
    s_sbox_pre_post: Selector,
    s_sbox_post: Selector,
    s_sbox_no_add: Selector,
    s_mds: Vec<Selector>,
    perm_output_to_input: Permutation,
    perm_output_to_sbox_output: Permutation,
}

impl Chip<Fp> for PoseidonChip {
    type Config = PoseidonChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl PoseidonChip {
    fn new(config: PoseidonChipConfig) -> Self {
        PoseidonChip { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        digest_col: Column<Advice>,
    ) -> PoseidonChipConfig {
        let a_col = meta.advice_column();
        let sbox_out_col = meta.advice_column();
        let mds_out_col = digest_col;
        let pre_key_col = meta.fixed_column();
        let post_key_col = meta.fixed_column();
        let mds_cols = vec![
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let s_sbox_pre_post = meta.selector();
        let s_sbox_post = meta.selector();
        let s_sbox_no_add = meta.selector();
        let s_mds = vec![meta.selector(), meta.selector(), meta.selector()];

        meta.create_gate("s_sbox_pre_post", |meta| {
            let a = meta.query_advice(a_col, Rotation::cur());
            let pre_key = meta.query_fixed(pre_key_col, Rotation::cur());
            let post_key = meta.query_fixed(post_key_col, Rotation::cur());
            let sbox_out = meta.query_advice(sbox_out_col, Rotation::cur());
            let s_sbox_pre_post = meta.query_selector(s_sbox_pre_post, Rotation::cur());
            // (a + pre_key)^5 + post_key = out
            let a_plus_pre = a + pre_key;
            s_sbox_pre_post
                * (a_plus_pre.clone()
                    * a_plus_pre.clone()
                    * a_plus_pre.clone()
                    * a_plus_pre.clone()
                    * a_plus_pre
                    + post_key
                    - sbox_out)
        });

        meta.create_gate("s_sbox_post", |meta| {
            let a = meta.query_advice(a_col, Rotation::cur());
            let post_key = meta.query_fixed(post_key_col, Rotation::cur());
            let sbox_out = meta.query_advice(sbox_out_col, Rotation::cur());
            let s_sbox_post = meta.query_selector(s_sbox_post, Rotation::cur());
            // a^5 + post_key = b
            s_sbox_post * (a.clone() * a.clone() * a.clone() * a.clone() * a + post_key - sbox_out)
        });

        meta.create_gate("s_sbox_no_add", |meta| {
            let a = meta.query_advice(a_col, Rotation::cur());
            let sbox_out = meta.query_advice(sbox_out_col, Rotation::cur());
            let s_sbox_no_add = meta.query_selector(s_sbox_no_add, Rotation::cur());
            // a^5 = b
            s_sbox_no_add * (a.clone() * a.clone() * a.clone() * a.clone() * a - sbox_out)
        });

        // Calculates the dot product of the sbox outputs with column `0` of the MDS matrix. Note
        // that `s_mds_0` is enabled in the first MDS row.
        meta.create_gate("s_mds_0", |meta| {
            let sbox_out_0 = meta.query_advice(sbox_out_col, Rotation::cur());
            let sbox_out_1 = meta.query_advice(sbox_out_col, Rotation::next());
            let sbox_out_2 = meta.query_advice(sbox_out_col, Rotation(2));
            let mds_out_0 = meta.query_advice(mds_out_col, Rotation::cur());
            let s_mds_0 = meta.query_selector(s_mds[0], Rotation::cur());

            // The first MDS column.
            let m_0 = meta.query_fixed(mds_cols[0], Rotation::cur());
            let m_1 = meta.query_fixed(mds_cols[0], Rotation::next());
            let m_2 = meta.query_fixed(mds_cols[0], Rotation(2));

            // Dot product of sbox outputs with the first MDS column.
            s_mds_0 * (sbox_out_0 * m_0 + sbox_out_1 * m_1 + sbox_out_2 * m_2 - mds_out_0)
        });

        // Calculates the dot product of the sbox outputs with column `1` of the MDS matrix. Note
        // that `s_mds_1` is enabled in the second MDS row.
        meta.create_gate("s_mds_1", |meta| {
            let sbox_out_0 = meta.query_advice(sbox_out_col, Rotation::prev());
            let sbox_out_1 = meta.query_advice(sbox_out_col, Rotation::cur());
            let sbox_out_2 = meta.query_advice(sbox_out_col, Rotation::next());
            let mds_out_1 = meta.query_advice(mds_out_col, Rotation::cur());
            let s_mds_1 = meta.query_selector(s_mds[1], Rotation::cur());

            // The second MDS column.
            let m_0 = meta.query_fixed(mds_cols[1], Rotation::prev());
            let m_1 = meta.query_fixed(mds_cols[1], Rotation::cur());
            let m_2 = meta.query_fixed(mds_cols[1], Rotation::next());

            // Dot product of the sbox outputs with the second MDS column.
            s_mds_1 * (sbox_out_0 * m_0 + sbox_out_1 * m_1 + sbox_out_2 * m_2 - mds_out_1)
        });

        // Calculates the dot product of the sbox outputs with column `2` of the MDS matrix. Note
        // that `s_mds_2` is enabled in the third MDS row.
        meta.create_gate("s_mds_2", |meta| {
            let sbox_out_0 = meta.query_advice(sbox_out_col, Rotation(-2));
            let sbox_out_1 = meta.query_advice(sbox_out_col, Rotation::prev());
            let sbox_out_2 = meta.query_advice(sbox_out_col, Rotation::cur());
            let mds_out_2 = meta.query_advice(mds_out_col, Rotation::cur());
            let s_mds_2 = meta.query_selector(s_mds[2]);

            // The third MDS column.
            let m_0 = meta.query_fixed(mds_cols[2], Rotation(-2));
            let m_1 = meta.query_fixed(mds_cols[2], Rotation::prev());
            let m_2 = meta.query_fixed(mds_cols[2], Rotation::cur());

            // Dot product of the sbox outputs with the third MDS column.
            s_mds_2 * (sbox_out_0 * m_0 + sbox_out_1 * m_1 + sbox_out_2 * m_2 - mds_out_2)
        });

        // Copies a round's MDS output into the next round's state.
        let perm_output_to_input = Permutation::new(meta, &[mds_out_col.into(), a_col.into()]);

        // Copies a round's MDS output into the next round's sbox output.
        let perm_output_to_sbox_output =
            Permutation::new(meta, &[mds_out_col.into(), sbox_out_col.into()]);

        PoseidonChipConfig {
            a_col,
            sbox_out_col,
            mds_out_col,
            pre_key_col,
            post_key_col,
            mds_cols,
            s_sbox_pre_post,
            s_sbox_post,
            s_sbox_no_add,
            s_mds,
            perm_output_to_input,
            perm_output_to_sbox_output,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Poseidon config
pub struct PoseidonConfig<F: Field + PrimeField> {
    path: Column<Advice>,
    sibling: Column<Advice>,
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> PoseidonConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        path: Column<Advice>,
        sibling: Column<Advice>,
        selector: Column<Fixed>,
    ) -> Self {
        meta.create_gate("parent value equals to hash of children's values", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur_path = meta.query_advice(path, Rotation::cur());
            let prev_path = meta.query_advice(path, Rotation::prev());
            let prev_sibling = meta.query_advice(sibling, Rotation::prev());
            // TODO: insert the constraints for poseidon hash here
            vec![cur_path * prev_path * prev_sibling]
        });

        PoseidonConfig {
            path,
            sibling,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Merkle tree config
pub struct MerkleTreeConfig<F: Field + PrimeField> {
    // the root of the merkle tree
    root: Column<Instance>,
    // the path from the leaf to the root of the tree
    path: Column<Advice>,
    // the sibling nodes of each node in the path
    sibling: Column<Advice>,
    // the config for checking poseidon constraints
    poseidon_config: PoseidonConfig<F>,
    // the selectors
    selector: Column<Fixed>,
    selector_root: Selector,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> MerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let selector = meta.fixed_column();
        let root = meta.instance_column();
        let path = meta.advice_column();
        let sibling = meta.advice_column();
        let selector_root = meta.selector();
        meta.enable_equality(root);

        // checking if the final value is equal to the root of the tree
        meta.create_gate("public instance", |meta| {
            let path = meta.query_advice(path, Rotation::cur());
            let root = meta.query_instance(root, Rotation::cur());
            let selector_root = meta.query_selector(selector_root);
            vec![selector_root * (path - root)]
        });

        // poseidon constraints
        let poseidon_config = PoseidonConfig::<F>::configure(meta, path, sibling, selector);

        MerkleTreeConfig {
            root,
            path,
            sibling,
            poseidon_config,
            selector,
            selector_root,
            _marker: PhantomData,
        }
    }
}

#[derive(Default)]
/// circuit for verifying the correctness of the opening
pub struct MemoryTreeCircuit<F: Field + PrimeField> {
    path: Vec<F>,
    sibling: Vec<F>,
}
impl<F: Field + PrimeField> Circuit<F> for MemoryTreeCircuit<F> {
    type Config = MerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MerkleTreeConfig::<F>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let size = self.path.len() - 1;
        let root = layouter.assign_region(
            || "merkle tree commitment",
            |mut region| {
                for i in 0..size {
                    self.assign(config, &mut region, i)?;
                }

                config.selector_root.enable(&mut region, size)?;
                let root = region.assign_advice(
                    || format!("the {}-th node of the path", size),
                    config.path,
                    size,
                    || Value::known(self.path[size]),
                )?;

                Ok(root.cell())
            },
        )?;
        layouter.constrain_instance(root, config.root, 0)?;
        Ok(())
    }
}

impl<F: Field + PrimeField> MemoryTreeCircuit<F> {
    fn assign(
        &self,
        config: MerkleTreeConfig<F>,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "selector",
            config.selector,
            offset,
            || Value::known(F::ONE),
        )?;

        region.assign_advice(
            || format!("the {}-th node of the path", offset),
            config.path,
            offset,
            || Value::known(self.path[offset]),
        )?;

        region.assign_advice(
            || format!("the {}-th sibling node", offset),
            config.sibling,
            offset,
            || Value::known(self.sibling[offset]),
        )?;

        Ok(())
    }
}
