//! Commit to the trace record using KZG commitment scheme.
//! We convert the trace into a polynomial and apply the algorithms in
//! [PSE 's KZG implementation](https://github.com/privacy-scaling-explorations/halo2/tree/main/halo2_backend/src/poly/kzg) to commit, open and verify the polynomial

extern crate alloc;
use crate::commitment::commitment_scheme::CommitmentScheme as CommitmentSchemeTrait;
use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::{Field, WithSmallOrderMulGroup};
use group::Curve;
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::Error,
    poly::{
        commitment::{Blind, CommitmentScheme, Params, ParamsProver, Prover, Verifier},
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
use rand_core::OsRng;

/// Omega power omega^0 to omega^7
const OMEGA_POWER: [Fr; 8] = [
    Fr::from_raw([0x01, 0, 0, 0]),
    Fr::from_raw([0x07, 0, 0, 0]),
    Fr::from_raw([0x31, 0, 0, 0]),
    Fr::from_raw([0x0157, 0, 0, 0]),
    Fr::from_raw([0x0961, 0, 0, 0]),
    Fr::from_raw([0x041a7, 0, 0, 0]),
    Fr::from_raw([0x01cb91, 0, 0, 0]),
    Fr::from_raw([0x0c90f7, 0, 0, 0]),
];

/// A KZG module that commit to the memory trace through the execution trace
#[derive(Debug, Clone)]
pub struct KZGMemoryCommitment<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Params: consists of the tuple (g,g^s,g^(s^2),...,g^(s^d)) where
    /// g is the generatorr and s is a secret value
    kzg_params: ParamsKZG<Bn256>,
    /// Domain used for creating polynomials
    domain: EvaluationDomain<Fr>,
    phantom_data: PhantomData<(K, V)>,
}

impl<K, V, const S: usize, const T: usize> Default for KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
    halo2_proofs::halo2curves::bn256::Fr: From<K>,
    halo2_proofs::halo2curves::bn256::Fr: From<V>,
{
    fn default() -> Self {
        // K = 3 since we need the poly degree to be 2^3 = 8
        Self::new(3)
    }
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
    halo2_proofs::halo2curves::bn256::Fr: From<K>,
    halo2_proofs::halo2curves::bn256::Fr: From<V>,
{
    /// Initialize KZG parameters
    pub fn new(k: u32) -> Self {
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(k),
            domain: EvaluationDomain::new(1, k),
            phantom_data: PhantomData,
        }
    }

    /// Commit a trace record in an execution trace
    /// This function, given input a trace record,
    /// outputs the commitment of the trace
    pub fn commit_trace(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
        self.kzg_params
            .commit(&self.poly_from_trace(trace), Blind(Fr::random(OsRng)))
            .to_affine()
    }

    // Convert a trace record to 8 field elements
    // The last 3 elements will be ZERO
    fn trace_to_field(&self, trace: TraceRecord<K, V, S, T>) -> [Fr; 8] {
        let (time_log, stack_depth, instruction, address, value) = trace.get_tuple();
        // Encode instruction to number : 1 for Write, 0 for Read
        match instruction {
            MemoryInstruction::Read => [
                Fr::from(time_log),
                Fr::from(stack_depth),
                Fr::ZERO,
                Fr::from(address),
                Fr::from(value),
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
            ],
            MemoryInstruction::Write => [
                Fr::from(time_log),
                Fr::from(stack_depth),
                Fr::ONE,
                Fr::from(address),
                Fr::from(value),
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
        // Use Lagrange interpolation
        self.domain
            .coeff_from_vec(lagrange_interpolate(&OMEGA_POWER, &evals))
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

        // Initialize the vector of commitments
        let commitment_list = vec![commitment; 5];

        // Initialize the vector of polynomials.
        // In our case, since we want to open the values p(1),p(omega),...,p(omega^4),
        // the polynomial list is equal to [p(x);5]
        let polynomial_list = vec![poly; 5];

        // Create the proof
        // I use the anonymous lifetime parameter '_ here, since currently
        // I do not know how to add a specific life time parameter in the script.
        create_kzg_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        >(
            &self.kzg_params,
            OMEGA_POWER[0..5].to_vec(),
            polynomial_list,
            commitment_list,
        )
    }

    /// Verify the correctness of the trace record.
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

        // Create the evaluations p(1),p(omega),...,p(omega^4)
        // for the polynomial p(x) converted from the trace
        let eval = Vec::from(self.trace_to_field(trace));
        // Finally, verify the correctness of the trace record
        verify_kzg_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&'_ [u8], G1Affine, Challenge255<G1Affine>>,
            AccumulatorStrategy<'_, Bn256>,
        >(
            &self.kzg_params,
            OMEGA_POWER[0..5].to_vec(),
            eval,
            commitment_list,
            proof.as_slice(),
        )
    }
}

/// Create the list of proof for KZG openings
/// More specifially, this function, given a list of points x_1,x_2,...,x_n
/// and polynomials p_1(x),p_2(x),...,p_n(x),
/// create a witness for the value p_1(x_1), p_2(x_2),...,p_n(x_n).
/// Used as a misc function to create the proof of the trace record
pub fn create_kzg_proof<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    TW: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
>(
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
    for commitment in &commitment_list {
        // Add the commitment of the polynomial p_i(x) to transcript
        transcript
            .write_point(*commitment)
            .expect("Unable to write point")
    }

    let mut queries: Vec<ProverQuery<'_, <Scheme as CommitmentScheme>::Curve>> = Vec::new();
    for (i, point) in points_list.iter().enumerate() {
        // Evaluate the values p_i(x_i) for i=1,2,...,n and add to the transcript
        transcript
            .write_scalar(eval_polynomial(&polynomial_list[i], *point))
            .expect("Unable to write scalar to transcript");

        // This query is used to list all the values p_1(x_1), p_2(x_2),...,p_n(x_n)
        // in the query list of SHPLONK prover
        queries.push(ProverQuery::new(*point, &polynomial_list[i], blind));
    }

    // Create the proof
    P::new(params)
        .create_proof(&mut OsRng, &mut transcript, queries)
        .expect("Unable to create proof");
    transcript.finalize()
}

/// Verify KZG openings
/// This function, given the list of points x_1,x_2,...,x_n,
/// a list of openings p_1(x_1),p_2(x_2),...,p_n(x_n)
/// and a list of commitment c_1,c_2,..c_n
/// then returns True or False to determine the correctness of the opening.
/// Used as a misc function to help verifying the trace record
pub fn verify_kzg_proof<
    'a,
    'params,
    Scheme: CommitmentScheme,
    Vr: Verifier<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    Tr: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
    Strategy: VerificationStrategy<'params, Scheme, Vr, Output = Strategy>,
>(
    params: &'params Scheme::ParamsVerifier,
    // A list of points x_1,x_2,...x_n
    points_list: Vec<Scheme::Scalar>,
    // The evaluation of p_1(x_1),p_2(x_2),...,p_n(x_n)
    eval: Vec<Scheme::Scalar>,
    // The commitments of the polynomials p_1(x),p_2(x),...,p_n(x)
    commitments: Vec<Scheme::Curve>,
    // The proof of opening
    proof: &'a [u8],
) -> bool {
    let verifier = Vr::new(params);
    let mut transcript = Tr::init(proof);
    let mut check = true;
    let mut eval_list = Vec::new();
    let mut queries = Vec::new();

    let commitment_list: Vec<<Scheme as CommitmentScheme>::Curve> = points_list
        .iter()
        .map(|_| transcript.read_point().expect("Unable to read point"))
        .collect();

    for (i, point) in points_list.iter().enumerate() {
        // Check if commitment list input matches the commitment list from the Prover's proof
        check = check && (commitments[i] == commitment_list[i]);

        // Read the eval list from transcript
        eval_list.push(transcript.read_scalar().expect("Unable to read scalar"));

        // Check if eval list input matches the eval list from the Prover's proof
        check = check && (eval[i] == eval_list[i]);

        queries.push(VerifierQuery::new_commitment(
            &commitment_list[i],
            *point,
            eval[i],
        ));
    }

    // Apply the verify function from SHPLONK to return the result
    check
        && Strategy::new(params)
            .process(|msm_accumulator| {
                verifier
                    .verify_proof(&mut transcript, queries, msm_accumulator)
                    .map_err(|_| Error::Opening)
            })
            .expect("Unable to verify proof")
            .finalize()
}

impl<K, V, const S: usize, const T: usize> CommitmentSchemeTrait<Fr>
    for KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
    Fr: From<K>,
    Fr: From<V>,
{
    type Commitment = G1Affine;
    type Opening = Vec<u8>;
    type Witness = TraceRecord<K, V, S, T>;
    type PublicParams = ParamsKZG<Bn256>;

    fn setup(_k: Option<u32>) -> Self {
        Self::default()
    }

    fn commit(&self, witness: Self::Witness) -> Self::Commitment {
        let mut kzg = Self {
            kzg_params: self.kzg_params.clone(), // TODO clone or not?
            domain: EvaluationDomain::new(1, Params::k(&self.kzg_params)),
            phantom_data: PhantomData,
        };
        kzg.commit_trace(witness)
    }

    fn open(&self, witness: Self::Witness) -> Self::Opening {
        let mut kzg = Self {
            kzg_params: self.kzg_params.clone(),
            domain: EvaluationDomain::new(1, Params::k(&self.kzg_params)),
            phantom_data: PhantomData,
        };
        let commitment = kzg.commit_trace(witness);
        kzg.prove_trace_record(witness, commitment)
    }

    fn verify(
        &self,
        commitment: Self::Commitment,
        opening: Self::Opening,
        _witness: Self::Witness,
    ) -> bool {
        let kzg = Self {
            kzg_params: self.kzg_params.clone(),
            domain: EvaluationDomain::new(1, Params::k(&self.kzg_params)),
            phantom_data: PhantomData,
        };
        kzg.verify_trace_record(_witness, commitment, opening.clone())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{base::B256, machine::AbstractTraceRecord};
    use ff::PrimeField;
    use rand::{thread_rng, Rng};

    // Generate a trace record
    fn generate_trace_record() -> TraceRecord<B256, B256, 32, 32> {
        let mut rng = rand::thread_rng();
        let instruction = if rng.gen() {
            MemoryInstruction::Read
        } else {
            MemoryInstruction::Write
        };

        TraceRecord::<B256, B256, 32, 32>::new(
            rng.gen_range(0..u64::MAX),
            rng.gen_range(0..u64::MAX),
            instruction,
            B256::from(rng.gen_range(i32::MIN..i32::MAX)),
            B256::from(rng.gen_range(i32::MIN..i32::MAX)),
        )
    }

    #[test]
    fn test_conversion_fr() {
        let mut rng = thread_rng();

        // Create a 32-bytes array repr of Base 256
        let mut chunk = [0u8; 32];
        for e in chunk.iter_mut() {
            *e = rng.gen_range(u8::MIN..u8::MAX);
        }
        // Clean the first byte to make sure it is not too big
        chunk[31] = 0u8;

        // Convert the array to  Fr
        let fr = Fr::from_bytes(&chunk).expect("Unable to convert to Fr");

        // Convert back from Fr to bytes
        let chunk_fr: [u8; 32] = fr.into();

        assert_eq!(chunk_fr, chunk);
    }
    #[test]
    fn test_record_polynomial_conversion() {
        let kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::default();

        // Initialize a random trace record
        let trace = generate_trace_record();

        // Get the polynomial
        let poly_trace = kzg_scheme.poly_from_trace(trace);

        // Get only the evals, which is the trace record's elements converted to field elements
        let poly_evals = kzg_scheme.trace_to_field(trace);

        // Test each eval values
        let mut base_index = Fr::ONE;
        for (i, eval) in poly_evals.iter().enumerate() {
            assert_eq!(eval_polynomial(&poly_trace, base_index), *eval);
            assert_eq!(base_index, OMEGA_POWER[i]);
            base_index *= Fr::MULTIPLICATIVE_GENERATOR;
        }
    }

    #[test]
    fn test_correct_trace_opening() {
        let mut kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::default();

        // Initialize a random trace record
        let trace = generate_trace_record();

        //Commit the trace
        let commitment = kzg_scheme.commit_trace(trace);

        //Open the trace
        let proof = kzg_scheme.prove_trace_record(trace, commitment);

        //Verify the correctness of the trace, should return True
        assert!(kzg_scheme.verify_trace_record(trace, commitment, proof));
    }

    // Check that two different trace records cannot have the same commitment
    #[test]
    fn test_false_trace_opening() {
        let mut kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::default();

        // Initialize a random trace record
        let trace = generate_trace_record();

        // Commit the initial trace
        let commitment = kzg_scheme.commit_trace(trace);

        // Given the "commitment", the Prover attempts to find a false trace hoping that it would also
        // has the same commitment output like the initial trace
        let false_trace = generate_trace_record();
        let false_proof = kzg_scheme.prove_trace_record(false_trace, commitment);

        // Verify the correctness of the false trace given the commitment "commitment", should return False
        assert!(!kzg_scheme.verify_trace_record(false_trace, commitment, false_proof));
    }

    #[test]
    fn test_kzg_commitment_scheme() {
        // Setup
        let kzg_commitment_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::setup(None);

        // Generate a random trace record
        let trace = generate_trace_record();

        // Commit
        let commitment =
            KZGMemoryCommitment::<B256, B256, 32, 32>::commit(&kzg_commitment_scheme, trace);

        // Open
        let opening =
            KZGMemoryCommitment::<B256, B256, 32, 32>::open(&kzg_commitment_scheme, trace);

        // Verify
        let is_valid = KZGMemoryCommitment::<B256, B256, 32, 32>::verify(
            &kzg_commitment_scheme,
            commitment,
            opening.clone(),
            trace,
        );
        assert!(is_valid, "Verification should succeed for valid opening");

        // Test with incorrect trace
        let incorrect_trace = generate_trace_record();
        let is_invalid = KZGMemoryCommitment::<B256, B256, 32, 32>::verify(
            &kzg_commitment_scheme,
            commitment,
            opening.clone(),
            incorrect_trace,
        );
        assert!(!is_invalid, "Verification should fail for invalid trace");
    }

    #[test]
    fn test_kzg_commitment_scheme_different_commitments() {
        let kzg_commitment_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::setup(None);

        let trace1 = generate_trace_record();
        let trace2 = generate_trace_record();

        let commitment1 =
            KZGMemoryCommitment::<B256, B256, 32, 32>::commit(&kzg_commitment_scheme, trace1);
        let commitment2 =
            KZGMemoryCommitment::<B256, B256, 32, 32>::commit(&kzg_commitment_scheme, trace2);

        assert_ne!(
            commitment1, commitment2,
            "Different traces should produce different commitments",
        );
    }
}
