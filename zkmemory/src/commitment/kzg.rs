extern crate std;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use group::Curve;
use rand_core::OsRng;

use crate::{
    base::Base,
    machine::TraceRecord,
    machine::MemoryInstruction,
};
use halo2_proofs::{
    arithmetic::lagrange_interpolate,
    poly::{
        commitment::{Blind, ParamsProver},
        kzg::commitment::ParamsKZG,
        {Coeff, EvaluationDomain, Polynomial},
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

/// A KZG module that commit to the memory trace through the execution trace
#[derive(Debug, Clone)]
pub struct KZGMemoryCommitment<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    // Params: generators, crs, etc
    kzg_params: ParamsKZG<Bn256>,
    // Domain used for creating polynomials
    domain: EvaluationDomain<Fr>,

    // Phantom data for K and V
    _marker_k: PhantomData<K>,
    _marker_v: PhantomData<V>,
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Initialize KZG parameters
    /// K = 3 since we need the poly degree to be 2^3 = 8
    pub fn setup() -> Self {
        const K: u32 = 3;
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(K),
            domain: EvaluationDomain::new(1, K),
            _marker_k: PhantomData::<K>,
            _marker_v: PhantomData::<V>,
        }
    }

    /// Commit a trace record in an execution trace
    /// The RBtree in the struct also updates the records
    pub fn commit(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
        let field_tuple = self.trace_to_field(trace);
        let poly = self.get_trace_poly(field_tuple);
        let alpha = Blind(Fr::random(OsRng));
        let commitment = self.kzg_params.commit(&poly, alpha);
        commitment.to_affine()
    }

    // Convert a trace record to 8 field elements
    // The last 3 elements will be ZERO
    fn trace_to_field(&self, trace: TraceRecord<K, V, S, T>) -> [Fr; 8] {
        let (t, s, i, l, d) = trace.get_tuple();

        // Encode instruction to number : 1 for Write, 0 for Read
        match i {
            MemoryInstruction::Read => [
                Fr::from(t),
                Fr::from(s),
                Fr::ZERO,
                self.be_bytes_to_field(l.zfill32().as_mut_slice()),
                self.be_bytes_to_field(d.zfill32().as_mut_slice()),
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
            ],
            MemoryInstruction::Write => [
                Fr::from(t),
                Fr::from(s),
                Fr::ONE,
                self.be_bytes_to_field(l.zfill32().as_mut_slice()),
                self.be_bytes_to_field(d.zfill32().as_mut_slice()),
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
            ],
        }
    }

    // Convert 8 field elements of a trace record
    // into a polynomial
    fn get_trace_poly(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff> {
        let mut points_arr = [Fr::ONE; 8];
        let mut current_point = Fr::ONE;

        // We use successive powers of primitive roots as points
        // We use elements in trace record to be the evals
        // 3 last evals should be ZERO
        for i in 1..8 as usize {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            points_arr[i] = current_point;
        }
        self.domain.coeff_from_vec(lagrange_interpolate(
            points_arr.as_slice(),
            evals.as_slice(),
        ))
    }

    // Convert 32 bytes number to field elements
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner = [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }
}

#[cfg(test)]
mod test {

    
}
