//! Circuit for proving the correctness of the Verkle tree commitment.
//! The label of a parent node is the commitment of the messages in all its children.
//! We choose KZG as the polynomial commitment scheme for committing the messages in the children.
//! Right now, the circuit could only support committing messages in the field Fr of Bn256, not in all finite fields.
extern crate alloc;
use alloc::{vec, vec::Vec};
use constraints::gadgets::Table;
use core::marker::PhantomData;
use ff::Field;
use group::Curve;
use halo2_proofs::{
    arithmetic::lagrange_interpolate,
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Fixed, Instance, ProvingKey, Selector, VerifyingKey,
    },
    poly::{
        commitment::{Blind, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, SingleStrategy},
        },
        Coeff, EvaluationDomain, Polynomial, Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use poseidon::poseidon_hash::{ConstantLength, Hash, Spec};
use poseidon::{
    poseidon_constants::{MDS_FR, MDS_INV_FR, ROUND_CONSTANTS_FR},
    poseidon_hash::Mtrx,
};
use rand::thread_rng;
use rand_core::OsRng;

use zkmemory::commitment::kzg::{create_kzg_proof, verify_kzg_proof};
use zkmemory::constraints;

pub(crate) const OMEGA_POWER: [Fr; 5] = [
    Fr::from_raw([0x01, 0, 0, 0]),
    Fr::from_raw([0x07, 0, 0, 0]),
    Fr::from_raw([0x31, 0, 0, 0]),
    Fr::from_raw([0x0157, 0, 0, 0]),
    Fr::from_raw([0x0961, 0, 0, 0]),
];

#[derive(Clone, Copy)]
/// Verkle tree config
/// A is the number of children in each parent node
pub struct VerkleTreeConfig<const A: usize> {
    /// advice has 2 columns, the first element is the current node in the opening path,
    /// and the second element is the direct parent of the current node
    advice: [Column<Advice>; 2],
    /// the verification result of the opening of the path
    check: Column<Advice>,
    /// the instance of the config, consists of the leaf and root nodes
    pub instance: Column<Instance>,
    /// the indices in the opening path of the tree
    indices: Column<Advice>,
    /// the selector
    selector: Column<Fixed>,
    selector_check: Selector,
    /// the lookup table. indices are required to be in the lookup
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

        table.range_check(meta, "indices must be in 0..A", |meta| {
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

#[derive(Debug, Clone)]
/// Verkle tree circuit
pub struct VerkleTreeCircuit<S: Spec<Fr, W, R>, const W: usize, const R: usize, const A: usize> {
    /// The leaf element in the opening path
    pub leaf: Fr,
    /// The KZG commitment for each parent node
    pub commitment: Vec<G1Affine>,
    /// The proof of the valid opening path
    pub proof: Vec<u8>,
    /// The other element in the opening paths, including the root and excluding the leaf
    pub path_elements: Vec<Fr>,
    /// The indices of the opening paths
    pub indices: Vec<Fr>,
    /// The KZG parameter params
    pub params: ParamsKZG<Bn256>,
    pub _marker: PhantomData<S>,
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
            path_elements: vec![Fr::ZERO],
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
        assert_eq!(self.indices.len(), self.path_elements.len());

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
            || "verkle proof",
            |mut region| {
                for i in 0..self.path_elements.len() {
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
                            self.path_elements[i - 1],
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

        let mut poly_list = vec![self.leaf];
        poly_list.extend(&self.path_elements[..self.path_elements.len() - 1]);

        let point_list = self
            .indices
            .iter()
            .map(|x| OMEGA_POWER[x.to_bytes()[0] as usize])
            .collect();

        // assign the verification result of the opening, it should be True
        let b = Fr::from(verify_kzg_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&'_ [u8], G1Affine, Challenge255<G1Affine>>,
            AccumulatorStrategy<'_, Bn256>,
        >(
            &self.params,
            point_list,
            poly_list,
            self.commitment.clone(),
            self.proof.as_slice(),
        ));

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

        // assign the root value
        let root = layouter.assign_region(
            || "assign root",
            |mut region| {
                region.assign_advice(
                    || "assign root",
                    config.advice[0],
                    0,
                    || Value::known(self.path_elements[self.path_elements.len() - 1]),
                )
            },
        )?;

        // constraints the leaf and the root being equal to the public instances
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

        // hash the commitment into a scalar value. We use Poseidon hash function
        let x_fr = Fr::from_bytes(&commitment.x.to_bytes()).unwrap();
        let y_fr = Fr::from_bytes(&commitment.y.to_bytes()).unwrap();
        let next_value = Hash::<Fr, S, ConstantLength<2>, W, R>::init().hash([x_fr, y_fr]);

        // assign the current path node
        region.assign_advice(
            || "value of the next node",
            config.advice[1],
            offset,
            || Value::known(next_value),
        )?;

        // assign the next path node
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

#[derive(Clone)]
/// The constants in Fr for Poseidon hash
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

/// A KZG struct for the purpose of testing the correctness of the Verkle tree circuit
#[derive(Clone, Debug)]
pub struct KZGStruct {
    pub kzg_params: ParamsKZG<Bn256>,
    domain: EvaluationDomain<Fr>,
}

impl KZGStruct {
    /// Initialize KZG parameters
    pub fn new(k: u32) -> Self {
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(k),
            domain: EvaluationDomain::new(1, k),
        }
    }

    /// Convert a given list into a polynomial
    pub fn poly_from_evals(&self, evals: [Fr; 4]) -> Polynomial<Fr, Coeff> {
        // Use Lagrange interpolation
        self.domain
            .coeff_from_vec(lagrange_interpolate(&OMEGA_POWER[0..4], &evals))
    }

    /// Commit the polynomial
    pub fn commit(&self, evals: [Fr; 4]) -> G1Affine {
        self.kzg_params
            .commit(&self.poly_from_evals(evals), Blind(Fr::random(OsRng)))
            .to_affine()
    }

    /// Create proof for multiple polynomial openings
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

    /// Hash a group element to an element in Fr
    pub fn group_to_scalar<S: Spec<Fr, W, R>, const W: usize, const R: usize>(
        &self,
        commitment: G1Affine,
    ) -> Fr {
        let x_coordinate_fr =
            Fr::from_bytes(&commitment.x.to_bytes()).expect("Cannot convert x into Fr");
        let y_coordinate_fr =
            Fr::from_bytes(&commitment.y.to_bytes()).expect("Cannot convert y into Fr");
        Hash::<Fr, S, ConstantLength<2>, W, R>::init().hash([x_coordinate_fr, y_coordinate_fr])
    }
}

/// Create a valid verkle tree proof for the purpose of testing
pub fn create_verkle_tree_proof(
    leaf: Fr,
    indices: Vec<usize>,
) -> (VerkleTreeCircuit<OrchardNullifier, 3, 2, 4>, Fr) {
    let rng = thread_rng();
    let kzg = KZGStruct::new(2);
    let mut commitment_list: Vec<G1Affine> = vec![];
    let mut poly_list: Vec<Polynomial<Fr, Coeff>> = vec![];
    let mut path_elements: Vec<Fr> = vec![];
    let mut temp = leaf;
    for i in 0..indices.len() {
        let mut evals = [0; 4].map(|_| Fr::random(rng.clone()));
        evals[indices[i]] = temp;
        // compute the polynomial for each parent node
        let poly = kzg.poly_from_evals(evals);
        // compute the commitment of the polynomial
        let commitment = kzg.commit(evals);
        poly_list.push(poly);
        commitment_list.push(commitment);
        // hash the group to scalar
        temp = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);
        path_elements.push(temp);
    }
    // the root node of the tree
    let root = temp;
    // convert the indices to Fr
    let indices_fr: Vec<Fr> = indices.iter().map(|x| Fr::from(*x as u64)).collect();
    let point_list: Vec<Fr> = indices.iter().map(|x| OMEGA_POWER[*x]).collect();
    // create the proof of correct opening
    let proof = kzg.create_proof(point_list, poly_list, commitment_list.clone());
    let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
        leaf,
        commitment: commitment_list,
        proof,
        path_elements,
        indices: indices_fr,
        params: kzg.kzg_params,
        _marker: PhantomData,
    };
    (circuit, root)
}

pub struct VerkleTreeVerifier {
    params: ParamsKZG<Bn256>,
    pub vk: VerifyingKey<G1Affine>,
    expected: bool,
}

impl VerkleTreeVerifier {
    /// initialize the verfier
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>, expected: bool) -> Self {
        Self {
            params,
            vk,
            expected,
        }
    }

    /// Verify the proof (by comparing the result with expected value)
    pub fn verify(&mut self, proof: Vec<u8>, leaf: Fr, root: Fr) -> bool {
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
            &self.vk,
            strategy,
            &[&[&[leaf, root]]],
            &mut transcript,
        );
        match result {
            Ok(()) => self.expected,
            Err(_) => !self.expected,
        }
    }
}

pub struct VerkleTreeProver<S: Spec<Fr, W, R>, const W: usize, const R: usize, const A: usize> {
    params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
    circuit: VerkleTreeCircuit<S, W, R, A>,
    expected: bool,
}

impl<S: Spec<Fr, W, R>, const W: usize, const R: usize, const A: usize>
    VerkleTreeProver<S, W, R, A>
{
    /// initialize the prover
    pub fn new(k: u32, circuit: VerkleTreeCircuit<S, W, R, A>, expected: bool) -> Self {
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize proving key");

        Self {
            params,
            pk,
            circuit,
            expected,
        }
    }

    // params to create VerkleTreeVerifier
    pub fn get_verifier_params(&self) -> (ParamsKZG<Bn256>, VerifyingKey<G1Affine>) {
        (self.params.clone(), self.pk.get_vk().clone())
    }

    /// Create proof for the permutation circuit
    pub fn create_proof(&mut self, leaf: Fr, root: Fr) -> Vec<u8> {
        let mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> =
            Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            OsRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            VerkleTreeCircuit<S, W, R, A>,
        >(
            &self.params,
            &self.pk,
            &[self.circuit.clone()],
            &[&[&[leaf, root]]],
            OsRng,
            &mut transcript,
        )
        .expect("Fail to create proof.");
        transcript.finalize()
    }

    /// Verify the proof (by comparing the result with expected value)
    pub fn verify(&mut self, proof: Vec<u8>, leaf: Fr, root: Fr) -> bool {
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
            &[&[&[leaf, root]]],
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
    use alloc::vec;
    use core::marker::PhantomData;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_valid_verkle_tree() {
        let leaf = Fr::from(25234512);
        let indices = vec![0];
        let (circuit, root) = create_verkle_tree_proof(leaf, indices);
        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_verkle_root() {
        let leaf = Fr::from(341231);
        let indices = vec![0, 1];
        let (circuit, _) = create_verkle_tree_proof(leaf, indices);
        let prover = MockProver::run(10, &circuit, vec![vec![leaf, Fr::from(0)]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_verkle_leaf() {
        let leaf = Fr::from(341231);
        let indices = vec![0, 1];
        let (circuit, root) = create_verkle_tree_proof(leaf, indices);
        let prover = MockProver::run(10, &circuit, vec![vec![Fr::from(0), root]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_proof() {
        let kzg = KZGStruct::new(2);
        let leaf = Fr::from(1);

        let indices = vec![Fr::from(0)];
        // the right 'polynomial'
        let evals = [leaf, Fr::from(0), Fr::from(0), Fr::from(0)];
        // the wrong 'polynomial'
        let false_evals = [Fr::from(2), Fr::from(0), Fr::from(0), Fr::from(0)];
        // commit to the right polynomial
        let commitment = kzg.commit(evals);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);
        let path_elements = vec![root];
        let commitment_list = vec![commitment];

        // wrong proof here
        let proof = kzg.create_proof(
            vec![OMEGA_POWER[0]],
            vec![kzg.poly_from_evals(false_evals)],
            commitment_list.clone(),
        );

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment: commitment_list,
            proof,
            path_elements,
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
        let kzg = KZGStruct::new(2);
        let leaf = Fr::from(1);

        // the original index
        let indices = vec![Fr::from(0)];
        let evals = [leaf, Fr::from(0), Fr::from(0), Fr::from(0)];
        let commitment = kzg.commit(evals);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);
        let path_elements = vec![root];
        let commitment_list = vec![commitment];

        // wrong opening index here, should be OMEGA_POWER[0]
        let proof = kzg.create_proof(
            vec![OMEGA_POWER[1]],
            vec![kzg.poly_from_evals(evals)],
            commitment_list.clone(),
        );

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment: commitment_list,
            proof,
            path_elements,
            indices,
            params: kzg.kzg_params,
            _marker: PhantomData,
        };
        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn invalid_opening_index_range() {
        let kzg = KZGStruct::new(2);
        let leaf = Fr::from(1);
        let evals = [leaf, Fr::from(0), Fr::from(0), Fr::from(0)];
        let commitment = kzg.commit(evals);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);
        let path_elements = vec![root];
        let commitment_list = vec![commitment];

        //  invalid index range here, should be in [0..3]
        let indices = vec![Fr::from(4)];
        let proof = kzg.create_proof(
            vec![OMEGA_POWER[4]],
            vec![kzg.poly_from_evals(evals)],
            commitment_list.clone(),
        );

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment: commitment_list,
            proof,
            path_elements,
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
        let leaf = Fr::from(4213);
        let indices = vec![0, 1, 2, 3];
        let (circuit, root) = create_verkle_tree_proof(leaf, indices);
        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_verkle_path() {
        let kzg = KZGStruct::new(2);
        let leaf = Fr::from(1);
        // indices
        let indices = vec![Fr::from(0), Fr::from(1)];
        // create the first polynomial
        let evals_0 = [leaf, Fr::from(1), Fr::from(3), Fr::from(5)];
        let poly_0 = kzg.poly_from_evals(evals_0);
        let commitment_0 = kzg.commit(evals_0);
        let non_leaf_0 = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment_0);
        // create the second polynomial
        let evals_1 = [Fr::from(0), non_leaf_0, Fr::from(3), Fr::from(5)];
        let poly_1 = kzg.poly_from_evals(evals_1);
        let commitment_1 = kzg.commit(evals_1);
        let root = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment_1);
        // wrong path here, the first element should be non_leaf_0, but now it is equal to 0
        let path_elements = vec![Fr::from(0), root];
        let commitment_list = vec![commitment_0, commitment_1];
        let proof = kzg.create_proof(
            vec![OMEGA_POWER[0], OMEGA_POWER[1]],
            vec![poly_0, poly_1],
            commitment_list.clone(),
        );

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf,
            commitment: commitment_list,
            proof,
            path_elements,
            indices,
            params: kzg.kzg_params,
            _marker: PhantomData,
        };
        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_verkle_tree_3() {
        let leaf = Fr::from(34213);
        let indices = vec![0, 1, 2, 1, 3, 1, 2, 0, 3];
        let (circuit, root) = create_verkle_tree_proof(leaf, indices);
        let prover =
            MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }
}
