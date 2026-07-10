//! Benchmark: Zinc+ vs. Halo2 memory-consistency backends on equal-size
//! traces — an apples-to-apples comparison of two *real* proof systems.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p zkmemory --example backend-benchmark --features zinc --release
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
//! For each trace size the example builds one consistent execution trace
//! (writes to distinct addresses followed by reads that return the written
//! values) and reports, per backend: one-time key/parameter setup, proving
//! time, verification time, and proof size. Zinc+ needs no key setup (its
//! parameters are derived transparently and cheaply inside `prove`), so its
//! setup column is left blank.

use std::cmp::Ordering;
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

/// Smallest circuit exponent `k` for `n` records. The composed circuit stacks
/// its permutation, sorted and original sub-regions plus a 256-entry lookup
/// table, so the row budget is well above the record count; find it by
/// building the keys and proving once, growing `k` until it succeeds.
fn min_k(trace: &[TraceRecord<B256, B256, 32, 32>]) -> u32 {
    let shuffle = sort_by_address_time(trace);
    for k in 9..=20 {
        let ok = std::panic::catch_unwind(|| {
            let prover =
                MemoryConsistencyProver::<EqAffine>::new(k, trace.to_vec(), shuffle.clone());
            prover.verify(&prover.create_proof())
        })
        .unwrap_or(false);
        if ok {
            return k;
        }
    }
    panic!("no k in 9..=20 fits {} records", trace.len());
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
    // Trace sizes to benchmark; 200 and 900 match the README performance notes.
    let sizes = [200usize, 900];
    // Best-of this many runs for the per-proof numbers (setup runs once).
    let runs = 3;

    // Silence the expected keygen/prove overflow panics while probing `k`.
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
        let trace = consistent_trace(n);
        let shuffle = sort_by_address_time(&trace);

        // Halo2 — real IPA proof (transparent, no trusted setup).
        let k = min_k(&trace);
        let (h2_setup, prover) = timed(runs, || {
            MemoryConsistencyProver::<EqAffine>::new(k, trace.clone(), shuffle.clone())
        });
        let (h2_prove, proof) = timed(runs, || prover.create_proof());
        let (h2_verify, accepted) = timed(runs, || prover.verify(&proof));
        assert!(accepted, "the Halo2 proof must verify");
        let h2_proof = proof.len();

        // Zinc+ — real transparent post-quantum SNARK.
        let zinc = ZincPlusBackend;
        let (z_prove, zproof) = timed(runs, || {
            zinc.prove(&trace).expect("Zinc+ accepts the trace")
        });
        let (z_verify, ()) = timed(runs, || zinc.verify(&zproof).expect("Zinc+ proof verifies"));
        let z_proof = zproof.to_bytes().expect("serialize proof").len();
        let v = zinc_num_vars(n);

        println!(
            "{:>7} | {:>3} {:>9} {:>9} {:>9} {:>9} | {:>3} {:>9} {:>9} {:>9}",
            n,
            k,
            ms(h2_setup),
            ms(h2_prove),
            ms(h2_verify),
            size(h2_proof),
            v,
            ms(z_prove),
            ms(z_verify),
            size(z_proof),
        );
    }
}
