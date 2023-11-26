extern crate std;
use core::marker::PhantomData;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use group::Curve;
use rand_core::OsRng;
use std::vec;
use std::vec::Vec;

use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    plonk::Error,
    poly::{
        commitment::{Blind, CommitmentScheme, ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
        {Coeff, EvaluationDomain, Polynomial, ProverQuery, VerificationStrategy, VerifierQuery},
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};

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
    _marker1: PhantomData<K>,
    _marker2: PhantomData<V>,
}

impl<K, V, const S: usize, const T: usize> Default for KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Initialize KZG parameters
    /// K = 3 since we need the poly degree to be 2^3 = 8
    pub fn new() -> Self {
        const K: u32 = 3;
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(K),
            domain: EvaluationDomain::new(1, K),
            _marker1: PhantomData::<K>,
            _marker2: PhantomData::<V>,
        }
    }

    /// Commit a trace record in an execution trace
    /// This function, given input a trace record,
    /// outputs the commitment of the trace
    pub fn commit(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
        // Convert trace record into polynomial
        let poly = self.poly_from_trace(trace);

        // Commit the polynomial using Halo2's code
        let alpha = Blind(Fr::random(OsRng));
        self.kzg_params.commit(&poly, alpha).to_affine()
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

    // Convert the trace record into a polynomial
    fn poly_from_trace(&self, trace: TraceRecord<K, V, S, T>) -> Polynomial<Fr, Coeff> {
        self.poly_from_evals(self.trace_to_field(trace))
    }

    // Convert 8 field elements of a trace record into a polynomial
    fn poly_from_evals(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff> {
        let mut current_point = Fr::ONE;

        // We use successive powers of primitive roots as points
        // We use elements in trace record to be the evals
        // 3 last evals should be ZERO
        let points_arr: Vec<_> = (1..=8)
            .map(|_| {
                let point = current_point;
                current_point *= Fr::MULTIPLICATIVE_GENERATOR;
                point
            })
            .collect();

        // Use Lagrange interpolation
        self.domain.coeff_from_vec(lagrange_interpolate(
            points_arr.as_slice(),
            evals.as_slice(),
        ))
    }

    // Convert 32 bytes number to field elements
    // This is made compatible with the Fr endianess
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let inner = [0, 8, 16, 24].map(|i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }

    // Create the list of proof for KZG openings
    // More specifially, this function, given a list of points x_1,x_2,...,x_n
    // and polynomials p_1(x),p_2(x),...,p_n(x),
    // create a witness for the value p_1(x_1), p_2(x_2),...,p_n(x_n).
    // Used as a misc function to create the proof of the trace record
    fn create_kzg_proof<
        'params,
        Scheme: CommitmentScheme,
        P: Prover<'params, Scheme>,
        E: EncodedChallenge<Scheme::Curve>,
        TW: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
    >(
        &self,
        params: &'params Scheme::ParamsProver,
        // a list of point x_1,x_2,...x_n
        points_list: Vec<Scheme::Scalar>,
        // a list of polynomials p_1(x), p_2(x),...,p_n(x)
        polynomial_list: Vec<Polynomial<Scheme::Scalar, Coeff>>,
        // the list of commitment of p_1(x),p_2(x),...,p_n(x)
        commitment_list: Vec<Scheme::Curve>,
    ) -> Vec<u8>
    where
        Scheme::Scalar: WithSmallOrderMulGroup<3>,
    {
        assert_eq!(
            (points_list.len(), polynomial_list.len()),
            (points_list.len(), commitment_list.len())
        );

        let mut transcript = TW::init(Vec::new());
        let blind = Blind::new(&mut OsRng);

        // Add the commitment the polynomial p_i(x) to transcript
        for item in commitment_list.iter() {
            transcript.write_point(*item).unwrap();
        }

        // Evaluate the values p_i(x_i) for i=1,2,...,n and add to the transcript
        for (poly, point) in polynomial_list.iter().zip(&points_list) {
            transcript
                .write_scalar(eval_polynomial(poly, *point))
                .unwrap();
        }

        // This query is used to list all the values p_1(x_1), p_2(x_2),...,p_n(x_n)
        // in the query list of SHPLONK prover
        let mut queries = Vec::new();
        for (point, poly) in points_list.iter().zip(polynomial_list.iter()) {
            queries.push(ProverQuery::new(*point, poly, blind));
        }

        // Create the proof
        let prover = P::new(params);
        prover
            .create_proof(&mut OsRng, &mut transcript, queries)
            .unwrap();
        transcript.finalize()
    }

    // Verify KZG openings
    // This function, given the list of points x_1,x_2,...,x_n,
    // a list of openings p_1(x_1),p_2(x_2),...,p_n(x_n)
    // and a list of commitment c_1,c_2,..c_n
    // then returns True or False to determine the correctness of the opening.
    // Used as a misc function to help verifying the trace record
    fn verify_kzg_proof<
        'a,
        'params,
        Scheme: CommitmentScheme,
        Vr: Verifier<'params, Scheme>,
        E: EncodedChallenge<Scheme::Curve>,
        Tr: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
        Strategy: VerificationStrategy<'params, Scheme, Vr, Output = Strategy>,
    >(
        &self,
        params: &'params Scheme::ParamsVerifier,
        // A list of points x_1,x_2,...x_n
        points_list: Vec<Scheme::Scalar>,
        // The evaluation of p_1(x_1),p_2(x_2),...,p_n(x_n)
        eval: Vec<Scheme::Scalar>,
        // The commitments of the polynomials p_1(x),p_2(x),...,p_n(x)
        commitment: Vec<Scheme::Curve>,
        // The proof of opening
        proof: &'a [u8],
    ) -> bool {
        let verifier = Vr::new(params);
        let mut transcript = Tr::init(proof);
        let mut check = true;

        // Read commitment list from transcript
        let commitment_list: Vec<_> = (0..points_list.len())
            .map(|_| transcript.read_point().unwrap())
            .collect();

        // Check if commitment list input matches the commitment list from the Prover's proof
        for (c, c_l) in commitment.iter().zip(&commitment_list) {
            check = check && (*c == *c_l);
        }

        // Read the eval list list from transcript
        let eval_list: Vec<_> = (0..points_list.len())
            .map(|_| transcript.read_scalar().unwrap())
            .collect();

        // Check if eval list input matches the eval list from the Prover's proof
        for (e, e_l) in eval.iter().zip(&eval_list) {
            check = check && (*e == *e_l);
        }

        // Add the queries
        let mut queries = Vec::new();
        for (c, (p, e)) in commitment_list
            .iter()
            .zip(points_list.iter().zip(eval_list.iter()))
        {
            queries.push(VerifierQuery::new_commitment(c, *p, *e));
        }

        // Apply the verify function from SHPLONK to return the result
        let strategy = Strategy::new(params);
        let strategy = strategy
            .process(|msm_accumulator| {
                verifier
                    .verify_proof(&mut transcript, queries.clone(), msm_accumulator)
                    .map_err(|_| Error::Opening)
            })
            .unwrap();

        check && strategy.finalize()
    }

    /// Open all fields from the trace record
    /// The function, given input a trace record and its commitment,
    /// outputs a proof of correct opening
    pub fn prove_trace_record(
        &self,
        trace: TraceRecord<K, V, S, T>,
        commitment: <KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve,
    ) -> Vec<u8> {
        // Convert the trace to a polynomial p(x)
        let poly = self.poly_from_trace(trace);

        // Create the point list [x_1,x_2,x_3,x_4,x_5] of opening
        let mut current_point = Fr::ONE;
        let points_list: Vec<_> = (1..=5)
            .map(|_| {
                let point = current_point;
                current_point *= Fr::MULTIPLICATIVE_GENERATOR;
                point
            })
            .collect();

        // Initialize the vector of commitments
        let commitment_list = vec![commitment; 5];

        // Initialize the vector of polynomials.
        // In our case, since we want to open the values p(x_1),...,p(x_5),
        // the polynomial list is equal to [p(x);5]
        let polynomial_list = vec![poly; 5];

        // Create the proof
        self.create_kzg_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_,_>,
        _, Blake2bWrite<_, _, Challenge255<_>>>(
        &self.kzg_params,
        points_list.clone(),
        polynomial_list,
        commitment_list)
    }

    /// Verify the correctness of the trace record
    /// This function, given input a trace record,
    /// it commitment and the proof of correctness opening,
    /// returns True or False to determine the correctness of the opening
    pub fn verify_trace_record(
        &self,
        trace: TraceRecord<K, V, S, T>,
        commitment: <KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve,
        proof: Vec<u8>,
    ) -> bool {
        // Create the commitment list of the trace
        let commitment_list = vec![commitment; 5];

        // Create the point list [x_1,x_2,x_3,x_4,x_5] of opening
        let mut current_point = Fr::ONE;
        let points_list: Vec<_> = (1..=5)
            .map(|_| {
                let point = current_point;
                current_point *= Fr::MULTIPLICATIVE_GENERATOR;
                point
            })
            .collect();

        // Create the evaluations p(x_1),p(x_2),...,p(x_5)
        // for the polynomial p(x) converted from the trace
        let eval = Vec::from(self.trace_to_field(trace));

        // Finally, verify the correctness of the trace record
        self.verify_kzg_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_,_>,
        _,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<'_,_>,
        >(&self.kzg_params, points_list.clone(),
        eval,
        commitment_list,
        proof.as_slice())
    }
}

#[cfg(test)]
mod test {
    //use std::println;

    use super::*;
    use crate::{base::B256, machine::AbstractTraceRecord};
    use halo2_proofs::arithmetic::eval_polynomial;
    use rand::{thread_rng, Rng};

    // Generate a trace record
    fn generate_trace_record() -> TraceRecord<B256, B256, 32, 32> {
        let mut rng = rand::thread_rng();

        TraceRecord::<B256, B256, 32, 32>::new(
            rng.gen_range(0..u64::MAX),
            rng.gen_range(0..u64::MAX),
            MemoryInstruction::Read,
            B256::from(rng.gen_range(std::i32::MIN..std::i32::MAX)),
            B256::from(rng.gen_range(std::i32::MIN..std::i32::MAX)),
        )
    }

    #[test]
    fn test_conversion_fr() {
        let kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();

        let mut rng = thread_rng();

        // Create a 32-bytes array repr of Base 256
        let mut chunk = [0u8; 32];
        for e in chunk.iter_mut() {
            *e = rng.gen_range(0..255);
        }
        // Clean the first byte to make sure it is not too big
        chunk[0] = 0u8;

        // Convert the array to  Fr
        let fr = kzg_scheme.be_bytes_to_field(chunk.as_mut_slice());

        // Convert back to bytes
        let chunk_fr: [u8; 32] = fr.try_into().unwrap();

        assert_eq!(chunk_fr, chunk);
    }
    #[test]
    fn test_record_polynomial_conversion() {
        let kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();

        // Initialize a random trace record
        let trace = generate_trace_record();

        // Get the polynomial
        let poly_trace = kzg_scheme.poly_from_trace(trace);

        // Get only the evals, which is the trace record's elements converted to field elements
        let poly_evals = kzg_scheme.trace_to_field(trace);

        // Test each eval values
        let mut base_index = Fr::ONE;
        for e in poly_evals {
            assert_eq!(eval_polynomial(&poly_trace, base_index), e);
            base_index *= Fr::MULTIPLICATIVE_GENERATOR;
        }
    }

    #[test]
    fn test_correct_trace_opening() {
        let mut kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();

        // Initialize a random trace record
        let trace = generate_trace_record();

        //Commit the trace
        let commitment = kzg_scheme.commit(trace);

        //Open the trace
        let proof = kzg_scheme.prove_trace_record(trace, commitment);

        //Verify the correctness of the trace, should return True
        assert!(kzg_scheme.verify_trace_record(trace, commitment, proof));
    }

    // Check that two different trace records cannot have the same commitment
    #[test]
    fn test_false_trace_opening() {
        let mut kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();

        // Initialize a random trace record
        let trace = generate_trace_record();

        // Commit the initial trace
        let commitment = kzg_scheme.commit(trace);

        // Given the "commitment", the Prover attempts to find a false trace hoping that it would also
        // has the same commitment output like the initial trace
        let false_trace = generate_trace_record();
        let false_proof = kzg_scheme.prove_trace_record(false_trace, commitment);

        // Verify the correctness of the false trace given the commitment "commitment", should return False
        assert!(!kzg_scheme.verify_trace_record(false_trace, commitment, false_proof));
    }
}
