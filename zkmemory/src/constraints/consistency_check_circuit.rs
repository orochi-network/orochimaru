//! The grand circuit for checking memory consistency
extern crate alloc;
use crate::{
    base::B256,
    constraints::{
        common::CircuitExtension,
        gadgets::{ConvertedTraceRecord, LookUpTables, Table, TraceRecordWitnessTable},
        original_memory_circuit::{OriginalMemoryCircuit, OriginalMemoryConfig},
        permutation_circuit::{PermutationCircuit, ShuffleChip, ShuffleConfig},
        sorted_memory_circuit::{SortedMemoryCircuit, SortedMemoryConfig},
    },
    machine::TraceRecord,
};
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, FromUniformBytes, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Fixed, ProvingKey,
    },
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::CurveAffine;
use rand_core::OsRng;

/// Config for consistency check circuit
#[derive(Clone)]
pub(crate) struct ConsistencyConfig<F: Field + PrimeField> {
    // the config of the original memory
    pub(crate) original_memory_config: OriginalMemoryConfig<F>,
    // the config of the sorted memory
    pub(crate) sorted_memory_config: SortedMemoryConfig<F>,
    // the config of permutation check
    pub(crate) permutation_config: ShuffleConfig,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> ConsistencyConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        shuffle_input: (Column<Fixed>, Column<Advice>),
        original_trace_record: TraceRecordWitnessTable<F>,
        sorted_trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        Self {
            original_memory_config: OriginalMemoryConfig::<F>::configure(
                meta,
                original_trace_record,
                lookup_tables,
                alpha_power.clone(),
            ),

            sorted_memory_config: SortedMemoryConfig::<F>::configure(
                meta,
                sorted_trace_record,
                lookup_tables,
                alpha_power,
            ),
            permutation_config: ShuffleChip::<F>::configure(meta, shuffle_input.0, shuffle_input.1),
            _marker: PhantomData,
        }
    }
}

/// Fixed challenge for the random-linear-combination gates of the composed
/// circuit, and fixed compression seeds for its permutation sub-argument.
///
/// This reference circuit uses **compile-time constant** challenges rather
/// than Fiat–Shamir challenges (a known soundness caveat, shared by the
/// `MockProver`-based [`crate::backend::Halo2Backend`]). Sampling them per
/// `configure`/`synthesize` — as the original code did with `F::random` —
/// makes the two independent `configure` calls of `keygen_vk` and `keygen_pk`
/// (and the fixed-vs-advice column assignments) disagree, so a *real* proof
/// never verifies. Pinning them to constants keeps `MockProver` behaviour
/// identical while letting [`MemoryConsistencyProver`] produce a real,
/// verifiable IPA proof. Production use still requires a real challenge phase.
const RLC_CHALLENGE: u64 = 0x1f2e_3d4c_5b6a_7981;
/// Fixed permutation-compression seeds; see [`RLC_CHALLENGE`].
const PERMUTATION_SEEDS: [u64; 5] = [
    0x9e37_79b9_7f4a_7c15,
    0xbf58_476d_1ce4_e5b9,
    0x94d0_49bb_1331_11eb,
    0x2545_f491_4f6c_dd1d,
    0x1234_5678_90ab_cdef,
];

/// Define the memory consistency circuit
#[derive(Default)]
pub(crate) struct MemoryConsistencyCircuit<F: Field + PrimeField + From<B256>> {
    /// input_trace: Array of trace records before sorting (sorted by time_log)
    pub(crate) input: Vec<TraceRecord<B256, B256, 32, 32>>,
    /// shuffle_trace: Array after permutations (sorted by address and time_log)
    pub(crate) shuffle: Vec<TraceRecord<B256, B256, 32, 32>>,
    /// A marker since these fields do not use trait F
    pub(crate) marker: PhantomData<F>,
}

/// Implement the circuit extension for memory consistency circuit
impl<F: Field + PrimeField + From<B256>> CircuitExtension<F> for MemoryConsistencyCircuit<F> {
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let permutation_circuit = PermutationCircuit::<F>::new_with_seeds::<B256, B256, 32, 32>(
            self.input.clone(),
            self.shuffle.clone(),
            PERMUTATION_SEEDS,
        );
        permutation_circuit.synthesize_with_layouter(config.permutation_config, layouter)?;
        let mut sorted_trace_record = vec![];
        for trace in self.shuffle.clone() {
            sorted_trace_record.push(ConvertedTraceRecord::<F>::from(trace));
        }
        let mut original_trace_record = vec![];
        for trace in self.input.clone() {
            original_trace_record.push(ConvertedTraceRecord::<F>::from(trace));
        }
        let original_memory_circuit = OriginalMemoryCircuit {
            original_trace_record,
            _marker: PhantomData,
        };
        let sorted_memory_circuit = SortedMemoryCircuit {
            sorted_trace_record,
            _marker: PhantomData,
        };
        sorted_memory_circuit.synthesize_with_layouter(config.sorted_memory_config, layouter)?;
        original_memory_circuit
            .synthesize_with_layouter(config.original_memory_config, layouter)?;
        Ok(())
    }
}

impl<F: Field + PrimeField + From<B256>> Circuit<F> for MemoryConsistencyCircuit<F> {
    type Config = ConsistencyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Method: without_witness: return the circuit that has no witnesses
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    // configure the circuit
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // the elements of the trace record
        let original_trace_record = TraceRecordWitnessTable::<F>::new(meta);
        let sorted_trace_record = TraceRecordWitnessTable::<F>::new(meta);

        // lookup tables
        let lookup_tables = LookUpTables {
            size256_table: Table::<256>::construct(meta),
            size40_table: Table::<40>::construct(meta),
            size2_table: Table::<2>::construct(meta),
        };
        // The random-linear-combination challenge. Fixed (not sampled) so
        // that key generation is reproducible and a real proof verifies; see
        // [`RLC_CHALLENGE`].
        let alpha = Expression::Constant(F::from(RLC_CHALLENGE));
        let mut tmp = Expression::Constant(F::ONE);
        let mut alpha_power: Vec<Expression<F>> = vec![tmp.clone()];
        for _ in 0..40 {
            tmp = tmp * alpha.clone();
            alpha_power.push(tmp.clone());
        }
        let input = meta.fixed_column();
        let shuffle = meta.advice_column();
        Self::Config::configure(
            meta,
            (input, shuffle),
            original_trace_record,
            sorted_trace_record,
            lookup_tables,
            alpha_power,
        )
    }

    /// Forward to the synthesize_with_layouter method
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.synthesize_with_layouter(config, &mut layouter)
    }
}

/// A real (non-mock) Halo2 prover for the composed
/// [`MemoryConsistencyCircuit`], using the transparent inner-product argument
/// (IPA) commitment scheme — no trusted setup.
///
/// Unlike [`crate::backend::Halo2Backend`], which only checks the circuit
/// under `halo2_proofs::dev::MockProver`, this generates a genuine,
/// transferable proof and verifies it, so the Halo2 backend can be compared
/// like-for-like against the transferable Zinc+ proof (proving time,
/// verification time, proof size). Parameters and proving/verifying keys are
/// generated once in [`Self::new`] (one-time setup, amortized across proofs)
/// and reused by [`Self::create_proof`] and [`Self::verify`]. The
/// [`Self::create_proof`] output is the proof transcript bytes.
pub struct MemoryConsistencyProver<C: CurveAffine>
where
    C::Scalar: FromUniformBytes<64> + From<B256>,
{
    params: ParamsIPA<C>,
    pk: ProvingKey<C>,
    circuit: MemoryConsistencyCircuit<C::Scalar>,
}

impl<C: CurveAffine> MemoryConsistencyProver<C>
where
    C::Scalar: FromUniformBytes<64> + From<B256>,
{
    /// Generate the IPA parameters and proving/verifying keys for a `2^k`-row
    /// circuit proving that `input` — the time-ordered execution trace — is
    /// memory-consistent, witnessed by its `(address, time_log)`-sorted
    /// permutation `shuffle`. `k` must satisfy `2^k > trace length + blinding
    /// rows` (and cover the fixed 256-entry lookup table).
    pub fn new(
        k: u32,
        input: Vec<TraceRecord<B256, B256, 32, 32>>,
        shuffle: Vec<TraceRecord<B256, B256, 32, 32>>,
    ) -> Self {
        let circuit = MemoryConsistencyCircuit {
            input,
            shuffle,
            marker: PhantomData,
        };
        let params = ParamsIPA::<C>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("cannot generate the verifying key");
        let pk = keygen_pk(&params, vk, &circuit).expect("cannot generate the proving key");
        Self {
            params,
            pk,
            circuit,
        }
    }

    /// Produce a proof transcript for the configured circuit.
    pub fn create_proof(&self) -> Vec<u8> {
        let mut transcript = Blake2bWrite::<Vec<u8>, C, Challenge255<C>>::init(vec![]);
        create_proof::<
            IPACommitmentScheme<C>,
            ProverIPA<'_, C>,
            Challenge255<C>,
            OsRng,
            Blake2bWrite<Vec<u8>, C, Challenge255<C>>,
            MemoryConsistencyCircuit<C::Scalar>,
        >(
            &self.params,
            &self.pk,
            core::slice::from_ref(&self.circuit),
            &[&[]],
            OsRng,
            &mut transcript,
        )
        .expect("cannot create the proof");
        transcript.finalize()
    }

    /// Verify a proof transcript produced by [`Self::create_proof`]. Returns
    /// `true` iff the proof is accepted.
    pub fn verify(&self, proof: &[u8]) -> bool {
        let strategy = AccumulatorStrategy::new(&self.params);
        let mut transcript = Blake2bRead::<&[u8], C, Challenge255<C>>::init(proof);
        verify_proof(
            &self.params,
            self.pk.get_vk(),
            strategy,
            &[&[]],
            &mut transcript,
        )
        .map(|strategy| strategy.finalize())
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::machine::{AbstractTraceRecord, MemoryInstruction};
    use core::cmp::Ordering;
    use halo2curves::pasta::EqAffine;

    fn record(
        time_log: u64,
        instruction: MemoryInstruction,
        address: u64,
        value: u64,
    ) -> TraceRecord<B256, B256, 32, 32> {
        TraceRecord::new(
            time_log,
            0,
            instruction,
            B256::from(address),
            B256::from(value),
        )
    }

    fn sorted(trace: &[TraceRecord<B256, B256, 32, 32>]) -> Vec<TraceRecord<B256, B256, 32, 32>> {
        let mut s = trace.to_vec();
        s.sort_by(|a, b| match a.address().cmp(&b.address()) {
            Ordering::Equal => a.time_log().cmp(&b.time_log()),
            ord => ord,
        });
        s
    }

    /// A real IPA proof of the composed circuit round-trips (prove → verify).
    #[test]
    fn real_ipa_proof_round_trips() {
        let trace = vec![
            record(0, MemoryInstruction::Write, 0x00, 1368),
            record(1, MemoryInstruction::Write, 0x20, 979),
            record(2, MemoryInstruction::Read, 0x00, 1368),
            record(3, MemoryInstruction::Read, 0x20, 979),
        ];
        let prover = MemoryConsistencyProver::<EqAffine>::new(10, trace.clone(), sorted(&trace));
        let proof = prover.create_proof();
        assert!(prover.verify(&proof), "an honest proof must verify");
        // A byte-tampered proof must be rejected.
        let mut bad = proof.clone();
        bad[0] ^= 0x01;
        assert!(!prover.verify(&bad), "a tampered proof must not verify");
    }
}
