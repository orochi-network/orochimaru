//! Benchmark: Zinc+ vs. Halo2 memory-consistency backends on equal-size
//! traces — an apples-to-apples comparison of two *real* proof systems.
//!
//! Run with (default sizes 200 and 900):
//!
//! ```sh
//! cargo run -p zkmemory --example backend-benchmark --features zinc --release
//! ```
//!
//! Pass trace sizes on the command line to sweep larger problems (this is how
//! the scaling table in `src/zincplus/README.md` was produced):
//!
//! ```sh
//! cargo run -p zkmemory --example backend-benchmark --features zinc --release \
//!     -- 200 900 2000 4000 8000 16000
//! ```
//!
//! Both sides generate a genuine, transferable proof and verify it:
//!
//! * **Halo2** uses [`MemoryConsistencyProver`], a real inner-product-argument
//!   (IPA) prover for the composed `MemoryConsistencyCircuit` — transparent,
//!   no trusted setup. (This is distinct from `zkmemory::backend::Halo2Backend`,
//!   which only checks the circuit under `MockProver` and emits no proof.)
//! * **Zinc+** uses the transparent post-quantum SNARK backend.
//!
//! Zinc+'s prover fails on large traces — its Zip+ code lives over `F_65537`,
//! whose NTT overflows around `num_vars = 13` and whose parameters cannot even
//! be built at `num_vars >= 14` (see `src/zincplus/README.md`). Rather than let
//! that abort the whole run, each backend's measurement is isolated: a failure
//! is caught and reported as `fails` so the rest of the sweep still completes.

use std::cmp::Ordering;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use halo2curves::pasta::EqAffine;

use zkmemory::backend::{MemoryConsistencyBackend, ZincPlusBackend};
use zkmemory::base::B256;
use zkmemory::constraints::consistency_check_circuit::MemoryConsistencyProver;
use zkmemory::machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord};

/// Build one `record`.
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

/// A consistent trace of exactly `n` records: `ceil(n/2)` writes to distinct
/// 32-byte-aligned addresses, then `floor(n/2)` reads that return each written
/// value. `time_log`s start at 0 and strictly increase, satisfying the
/// original-trace contract both backends require.
fn consistent_trace(n: usize) -> Vec<TraceRecord<B256, B256, 32, 32>> {
    let writes = n.div_ceil(2);
    let mut trace = Vec::with_capacity(n);
    let mut t = 0u64;
    for i in 0..writes {
        trace.push(record(
            t,
            MemoryInstruction::Write,
            (i as u64) * 32,
            1000 + i as u64,
        ));
        t += 1;
    }
    for i in 0..(n - writes) {
        trace.push(record(
            t,
            MemoryInstruction::Read,
            (i as u64) * 32,
            1000 + i as u64,
        ));
        t += 1;
    }
    trace
}

/// Sort a trace by `(address, time_log)` — the witness order the composed
/// circuit's sorted sub-circuit expects.
fn sort_by_address_time(
    trace: &[TraceRecord<B256, B256, 32, 32>],
) -> Vec<TraceRecord<B256, B256, 32, 32>> {
    let mut sorted = trace.to_vec();
    sorted.sort_by(|a, b| match a.address().cmp(&b.address()) {
        Ordering::Equal => a.time_log().cmp(&b.time_log()),
        ordering => ordering,
    });
    sorted
}

/// Smallest circuit exponent `k` for a trace, or `None` if none in range fits.
///
/// The composed circuit stacks its permutation, sorted and original
/// sub-regions plus a 256-entry lookup table, so the row budget is well above
/// the record count. Probe *key generation only* (which fails when the rows
/// overflow `2^k`) — much cheaper than a full prove — starting near the
/// expected size.
fn min_k(
    trace: &[TraceRecord<B256, B256, 32, 32>],
    shuffle: &[TraceRecord<B256, B256, 32, 32>],
) -> Option<u32> {
    let start = (2 * trace.len() as u32)
        .next_power_of_two()
        .trailing_zeros()
        .max(9);
    (start..=20).find(|&k| {
        catch_unwind(AssertUnwindSafe(|| {
            let _ = MemoryConsistencyProver::<EqAffine>::new(k, trace.to_vec(), shuffle.to_vec());
        }))
        .is_ok()
    })
}

/// `log2` of the padded row count Zinc+ uses for `n` records (`>= 3`).
fn zinc_num_vars(n: usize) -> usize {
    ((n + 1).next_power_of_two().trailing_zeros() as usize).max(3)
}

/// Best (minimum) wall-clock time of `runs` invocations of `f`.
fn timed<T>(runs: u32, mut f: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut last = None;
    for _ in 0..runs {
        let start = Instant::now();
        let out = f();
        best = best.min(start.elapsed());
        last = Some(out);
    }
    (best, last.expect("at least one run"))
}

/// Halo2 measurement: `(k, setup, prove, verify, proof_bytes)`, or `None` if
/// the circuit does not fit or proving/verification fails.
type Halo2Row = (u32, Duration, Duration, Duration, usize);

fn measure_halo2(
    trace: &[TraceRecord<B256, B256, 32, 32>],
    shuffle: &[TraceRecord<B256, B256, 32, 32>],
    runs: u32,
) -> Option<Halo2Row> {
    let k = min_k(trace, shuffle)?;
    catch_unwind(AssertUnwindSafe(|| {
        let (setup, prover) = timed(runs, || {
            MemoryConsistencyProver::<EqAffine>::new(k, trace.to_vec(), shuffle.to_vec())
        });
        let (prove, proof) = timed(runs, || prover.create_proof());
        let (verify, accepted) = timed(runs, || prover.verify(&proof));
        assert!(accepted, "the Halo2 proof must verify");
        (k, setup, prove, verify, proof.len())
    }))
    .ok()
}

/// Zinc+ measurement: `(prove, verify, proof_bytes)`, or `None` if the prover
/// fails (a graceful error or a panic inside the Zip+ code).
fn measure_zinc(
    trace: &[TraceRecord<B256, B256, 32, 32>],
    runs: u32,
) -> Option<(Duration, Duration, usize)> {
    catch_unwind(AssertUnwindSafe(|| {
        let zinc = ZincPlusBackend;
        let (prove, proof) = timed(runs, || zinc.prove(trace).expect("Zinc+ accepts the trace"));
        let (verify, ()) = timed(runs, || zinc.verify(&proof).expect("Zinc+ proof verifies"));
        (
            prove,
            verify,
            proof.to_bytes().expect("serialize proof").len(),
        )
    }))
    .ok()
}

fn ms(d: Duration) -> String {
    format!("{:.0} ms", d.as_secs_f64() * 1000.0)
}

fn size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

fn main() {
    // Sizes from the command line, or the two README defaults.
    let sizes: Vec<usize> = {
        let args: Vec<usize> = std::env::args()
            .skip(1)
            .filter_map(|a| a.parse().ok())
            .collect();
        if args.is_empty() {
            vec![200, 900]
        } else {
            args
        }
    };

    // Silence the expected key-generation / prover panics we catch below.
    std::panic::set_hook(Box::new(|_| {}));

    println!(
        "{:>7} | {:>3} {:>9} {:>9} {:>9} {:>9} | {:>3} {:>9} {:>9} {:>9}",
        "records",
        "k",
        "h2-setup",
        "h2-prove",
        "h2-verify",
        "h2-proof",
        "v",
        "z+-prove",
        "z+-verify",
        "z+-proof",
    );
    println!("{}", "-".repeat(92));

    for &n in &sizes {
        // Best of three for small traces; a single (slow) run above that.
        let runs = if n <= 1000 { 3 } else { 1 };
        let trace = consistent_trace(n);
        let shuffle = sort_by_address_time(&trace);

        let h2 = measure_halo2(&trace, &shuffle, runs);
        let zinc = measure_zinc(&trace, runs);
        let v = zinc_num_vars(n);

        let (k, h2s, h2p, h2v, h2sz) = match h2 {
            Some((k, s, p, vf, sz)) => (format!("{k:>3}"), ms(s), ms(p), ms(vf), size(sz)),
            None => (
                "  —".into(),
                "fails".into(),
                "fails".into(),
                "fails".into(),
                "—".into(),
            ),
        };
        let (zp, zv, zsz) = match zinc {
            Some((p, vf, sz)) => (ms(p), ms(vf), size(sz)),
            None => ("fails".into(), "fails".into(), "—".into()),
        };

        println!(
            "{n:>7} | {k} {h2s:>9} {h2p:>9} {h2v:>9} {h2sz:>9} | {v:>3} {zp:>9} {zv:>9} {zsz:>9}"
        );
    }
}
