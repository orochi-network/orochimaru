extern crate alloc;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use halo2_proofs::{
    halo2curves::pasta::Fp,
};
use poseidon::poseidon_hash::{
    ConstantLength, Domain, Hash, OrchardNullifier, Spec,
};
use crate::commitment::commitment_scheme::CommitmentScheme;
use crate::commitment::merkle_tree::{MerkleTreeCircuit, MerkleWitness};

/// Compute the root of a merkle tree given the path and the sibling nodes
pub fn merkle_tree_commit_fp(leaf: &u64, elements: &[u64], indices: &[u64]) -> Fp {
    let k = elements.len();
    let mut digest = Fp::from(*leaf);
    let mut message: [Fp; 2];
    for i in 0..k {
        if indices[i] == 0 {
            message = [digest, Fp::from(elements[i])];
        } else {
            message = [Fp::from(elements[i]), digest];
        }
        digest = Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
    }
    digest
}

impl<
    S: Spec<Fp, T, R> + Clone,
    D: Domain<Fp, R> + Clone,
    const T: usize,
    const R: usize,
    > CommitmentScheme<Fp>
    for MerkleTreeCircuit<S, Fp, D, T, R>
{
    type Commitment = Fp;
    type Opening = Vec<u64>;
    type Witness = MerkleWitness;
    type PublicParams = ();

    fn setup(_k: Option<u32>) -> Self {
        let witness = MerkleWitness::new(0u64, vec![0u64; 4], vec![0u64; 4]);
        let (lefts, rights, outputs, indices) = witness.to_circuit_format();
        Self {
            lefts,
            rights,
            outputs,
            indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        }
    }

    fn commit(&self, witness: Self::Witness) -> Self::Commitment {
        merkle_tree_commit_fp(&witness.leaf, &witness.elements, &witness.indices)
    }

    fn open(&self, witness: Self::Witness) -> Self::Opening {
        witness.elements
    }

    fn verify(
        &self,
        commitment: Self::Commitment,
        opening: Self::Opening,
        witness: Self::Witness,
    ) -> bool {
        opening == witness.elements
            && commitment == merkle_tree_commit_fp(&witness.leaf, &opening, &witness.indices)
    }
}


#[cfg(test)]
mod tests {
    use super::MerkleTreeCircuit;
    use crate::commitment::commitment_scheme::CommitmentScheme;
    use crate::commitment::merkle_tree::{MerkleWitness};
    use halo2_proofs::{halo2curves::pasta::Fp};
    use poseidon::poseidon_hash::*;

    #[test]
    fn test_correct_merkle_proof_commitment_scheme_trait() {
        let leaf = 0u64;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let witness = MerkleWitness::new(leaf, elements, indices);

        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2>::setup(None);
        let commitment = circuit.commit(witness.clone());
        let opening = circuit.open(witness.clone());
        let is_valid = circuit.verify(commitment, opening, witness);

        assert!(is_valid, "Verification should succeed for valid opening");
    }
}