# Zinc+ memory-consistency backend

This module integrates [Zinc+](https://github.com/NethermindEth/zinc-plus)
(NethermindEth) as an **optional proof-system backend** for zkMemory's
memory-consistency argument, alongside the existing Halo2 (PLONK) circuits in
[`src/constraints`](../constraints). It is gated behind the `zinc` cargo
feature and follows the multi-backend layout established by
[`src/nova`](../nova) and [`src/supernova`](../supernova).

```text
zkmemory/src/zincplus/
├── mod.rs        module root, public re-exports
├── types.rs      concrete Zinc+ protocol type parameters (field, codes, widths)
├── uair.rs       the memory-consistency UAIR + witness builder
├── benes.rs      Beneš-network routing for the permutation argument
├── prover.rs     prove / verify entry points, proof (de)serialization, errors
├── testcases.rs  positive and negative (soundness) tests
└── README.md     this file
```

## Quick start

```rust
use zkmemory::zincplus::{prove_memory_consistency, verify_memory_consistency};

let trace = machine.trace();                    // time-ordered execution trace
let proof = prove_memory_consistency(&trace)?;  // succinct, transparent SNARK
verify_memory_consistency(&proof)?;
let bytes = proof.to_bytes()?;                  // transferable proof bytes
```

Or through the backend-agnostic seam, which lets code switch between Halo2
and Zinc+ without changing how traces are produced:

```rust
use zkmemory::backend::{Halo2Backend, MemoryConsistencyBackend, ZincPlusBackend};

let halo2 = Halo2Backend { k: 10 };
halo2.verify(&halo2.prove(&trace)?)?;

let zinc = ZincPlusBackend;
zinc.verify(&zinc.prove(&trace)?)?;
```

The input trace must satisfy the same contract the Halo2
`OriginalMemoryCircuit` places on the original trace: records in execution
order, `time_log[0] = 0`, strictly increasing `time_log`s (gaps allowed).
Traces produced by [`machine.trace()`](../machine.rs) satisfy this by
construction.

Build with `cargo build -p zkmemory --features zinc`. The feature requires a
`std` environment and Rust ≥ 1.85 (Zinc+ is an edition-2024 workspace); the
repository toolchain is pinned accordingly in [`rust-toolchain`](../../../rust-toolchain).

## What Zinc+ is

Zinc+ ([eprint 2026/855](https://eprint.iacr.org/2026/855)) is a
**transparent, plausibly post-quantum SNARK for polynomial rings**. Instead
of embedding all constraints into one prime field, it expresses them over
`Q[X]`, `Z[X]` and several `F_q[X]` rings simultaneously, avoiding the
witness inflation of single-field SNARKs. Constraints are written in a
univariate-AIR (UAIR) dialect: per-row expressions over three column kinds
(binary polynomials, arbitrary polynomials, integers) with fixed row shifts
for transition constraints, compiled down to sumchecks and the Brakedown-style
Zip+ polynomial commitment scheme (Merkle trees + linear codes). There is
**no trusted setup**; all challenges — including the random ~192-bit prime
modulus the constraints are projected into — derive from a Blake3
Fiat-Shamir transcript.

## The statement proven

The proof attests knowledge of a witness containing *two orderings of the
same trace* — the time-ordered original trace `O` and its
`(address, time_log)`-sorted permutation `S`, each padded to `2^num_vars`
rows — satisfying all three sub-statements of the composed Halo2
`MemoryConsistencyCircuit`:

| sub-statement | Halo2 circuit | Zinc+ constraints |
|---------------|---------------|-------------------|
| original-trace consistency: `time_log[0] = 0`, `time_log[i] < time_log[i+1]` | `OriginalMemoryCircuit` | `is_first` pins row 0's time limbs; a one-hot limb selector + slack limb enforce the strict `u64` increase |
| sorted-trace consistency: `(address, time_log)` strictly increases, first access (overall and per address) is a write, instructions boolean, reads return the previous value at the address | `SortedMemoryCircuit` | the lookup-free lexicographic comparison and read-check constraints described in [`uair.rs`](uair.rs) |
| `S` is a permutation of `O` | `PermutationCircuit` (PLONK shuffle) | a **Beneš switching network**: `2v - 1` layers of boolean-selected conditional swaps between rows `i` and `i + 2^k`, carrying the full record payload from `S` (network input) to `O` (network output) |

Both traces are witnesses; like the composed Halo2 circuit, the statement
has no trace-dependent public inputs (the verifier reconstructs the fixed
`is_first` and bit-indicator selector columns itself).

Randomized permutation arguments (PLONK shuffle, LogUp) are not expressible
in Zinc+ — there is no lookup layer yet, no verifier-randomness columns, and
committed cells are small integers fixed before the random prime is sampled,
so a grand-product accumulator over the proof field cannot even be
materialized. The Beneš network sidesteps randomness entirely: switch
equations are cell-exact, so each network state is *exactly* a permutation
of the previous one, and `multiset(O) = multiset(S)` holds with no soundness
error beyond the (negligible) probability that a small nonzero integer
vanishes mod the ~192-bit Fiat-Shamir-sampled prime. Routing bits are free
witnesses: a malicious router can only fail to prove, never prove a false
statement. This is the established deterministic RAM-checking technique of
challenge-less proof systems (Pantry, Buffet, xJsnark).

Addresses, values, `time_log`s and `stack_depth`s live in *binary
polynomial* columns: `BinaryPoly<32>` cells whose 32 coefficients are proven
boolean by Zinc+'s built-in booleanity argument, so every limb is
range-checked to `u32` for free — no lookup tables are needed anywhere.

Zinc+ exempts the very last row from constraints (its built-in last-row
selector); the witness builder therefore always keeps at least one padding
row, so **no real record ever occupies the exempt row**. Padding rows replay
the last *sorted* record as reads with `time_log`s continuing past the
global maximum, which satisfies both orderings' constraints and keeps the
two padded multisets equal. The exemption opens no hole in the network
either: row `2^v - 1` has every index bit set, so it is never the anchor
(upper) row of any switch, and all constraints binding it are anchored at
non-exempt rows.

## Security status — differences from the Halo2 backend

Users must understand two deliberate limitations of this integration:

1. **No zero-knowledge.** Zinc+ currently provides succinctness and
   transparency but no hiding: witness columns are committed and opened
   without masking. Treat the proof as potentially revealing the entire
   trace. Use the Halo2 backend when privacy is required.

2. **Research-grade upstream.** Zinc+ is unaudited and marked by its authors
   as for research/educational use. The dependency is pinned to one reviewed
   revision (see `[workspace.dependencies]`), and the security parameters in
   [`types.rs`](types.rs) (repetition factor 8, 100 column openings, 192-bit
   sampled prime) are the upstream research defaults, not audited production
   parameters.

The earlier v1 limitation — no in-SNARK permutation link between the sorted
and original traces — is **resolved**: the Beneš network enforces the full
composed Halo2 statement. The constraint-by-constraint soundness argument is
documented in [`uair.rs`](uair.rs) (module docs) and exercised by negative
tests in [`testcases.rs`](testcases.rs), including direct witness-tampering
attacks on the network states, switch bits, both trace orderings and the
transition slacks.

## Performance notes

The deterministic permutation argument is paid for in trace width: the
network adds `2v` states of 21 binary columns each (plus one switch column
per layer), so the committed trace has `~42v + 2` binary columns instead of
the ~20 of the consistency-only v1 backend. Linear-code commitments have
large constants, so proofs are far bigger than pairing-based SNARK proofs,
and the verifier additionally pays `O(2^{v-1})` field operations per
large-stride shifted column when evaluating Zinc+'s shift predicates.

[`MAX_NUM_VARS`](uair.rs) is declared as 16 (`≤ 65 535` records), but that is
an over-optimistic upper bound: with the current parameters the backend can
only *prove* up to `num_vars = 12` (`≤ 4 095` records) before the Zip+ code
fails — see [Scaling limits](#scaling-limits--where-zinc-stops) below.

### Zinc+ vs. Halo2 on the same trace

Both backends prove the *same* composed statement, so they can be timed
head-to-head — with **two real, transferable proofs**. The
[`backend-benchmark`](../../examples/backend-benchmark.rs) example pairs the
Zinc+ SNARK against a transparent inner-product-argument (IPA) proof of the
composed `MemoryConsistencyCircuit`, produced by
[`MemoryConsistencyProver`](../constraints/consistency_check_circuit.rs)
(a genuine prover, distinct from `Halo2Backend`, which only runs
`MockProver`). Neither side uses a trusted setup. Release mode,
single-threaded, Apple-silicon laptop; best of three runs up to 900 records,
a single run above:

| records (`v` / `k`)    | Zinc+ prove | Zinc+ verify | Zinc+ proof | Halo2 prove | Halo2 verify | Halo2 proof |
|-----------------------:|------------:|-------------:|------------:|------------:|-------------:|------------:|
| 200 (`v8` / `k10`)     |      1.2 s  |      119 ms  |   8.69 MiB  |      1.7 s  |       15 ms  |   35.4 KiB  |
| 900 (`v10` / `k11`)    |      5.8 s  |      200 ms  |  10.92 MiB  |      3.1 s  |       19 ms  |   35.5 KiB  |
| 2 000 (`v11` / `k12`)  |     17.9 s  |      344 ms  |  12.12 MiB  |      5.7 s  |       25 ms  |   35.6 KiB  |
| 4 000 (`v12` / `k13`)  |     54.6 s  |      743 ms  |  13.44 MiB  |     10.7 s  |       36 ms  |   35.6 KiB  |
| 8 000 (`v13` / `k14`)  |  **fails**  |          —   |         —   |     20.4 s  |       50 ms  |   35.7 KiB  |
| 16 000 (`v14` / `k15`) |  **fails**  |          —   |         —   |     40.8 s  |       81 ms  |   35.8 KiB  |

Halo2's one-time key/parameter setup — amortized across all proofs, with no
Zinc+ equivalent (Zinc+ derives its parameters transparently inside `prove`) —
grows from 0.3 s at 200 records to 13 s at 16 000.

```text
cargo run -p zkmemory --example backend-benchmark --features zinc --release \
    -- 200 900 2000 4000 8000 16000
```

Reading the numbers:

- **Proof size** is Halo2-IPA's decisive win: a near-constant ~35 KiB versus
  Zinc+'s 9–13 MiB and climbing. The Halo2 proof is dominated by one
  commitment per circuit column (a fixed count) plus a logarithmic opening, so
  it barely grows; Zip+'s Brakedown-style linear-code commitments have large
  constants.
- **Verification** always favours Halo2-IPA (15–81 ms vs 119–743 ms), and the
  gap widens — Zinc+'s verifier pays `O(2^{v-1})` per shifted column.
- **Proving crosses over almost immediately.** Zinc+ is faster only at 200
  records; its prover then grows ~3× per doubling of the trace (1.2 → 5.8 →
  17.9 → 54.6 s) — the `~42v` network columns over a super-linear code — while
  Halo2-IPA grows ~linearly (1.7 → 3.1 → 5.7 → 10.7 → 20.4 → 40.8 s). By 4 000
  records Zinc+ is already ~5× slower.

<a name="scaling-limits--where-zinc-stops"></a>

#### Scaling limits — where Zinc+ stops

Zinc+ does not just get slow; it **hits a hard wall well below the declared
`MAX_NUM_VARS = 16`**. Its Zip+ commitment uses an IPRS code over the small
field **`F_65537`** ([`types.rs`](types.rs)), whose NTT has only `2^16` usable
points, and two failures follow as the trace grows:

- **`num_vars = 13` (~8 000 records): the prover panics** — the radix-8 NTT
  butterfly overflows while encoding the folded, `~42v`-column trace.
- **`num_vars ≥ 14` (~16 000+ records): the parameters cannot even be built** —
  the codeword length exceeds the number of field elements (`InvalidPcsParam:
  "Codeword length is more than the number of elements in the field"`).

So the **largest trace this backend can actually prove is `num_vars = 12`
(≤ 4 095 records)**, not the 65 535 the constant advertises; the code
arithmetic — not verification time — is the binding constraint. (The example
catches these failures and reports `fails` rather than aborting the sweep, but
`prove_memory_consistency` itself still panics on an oversized trace instead of
returning a clean error.) Halo2-IPA proves every one of these sizes and keeps
going, with smooth cost and a small proof. Lifting Zinc+'s ceiling needs a
larger code field or the upstream lookup layer that would retire the `~42v`
network columns (see the migration plan below); until then this backend is
best suited to small traces.

What Zinc+ buys with the larger proofs and slower verification is **plausible
post-quantum security** — its Zip+ commitments rest on hashes and linear
codes, whereas this Halo2 proof is an IPA over the Pasta curves and is **not**
post-quantum (its security is discrete-log). Two caveats stop even this from
being a production verdict: Zinc+ is **not zero-knowledge** (above), while
Halo2 proofs are; and the Halo2 side proves the *reference* circuit, which
uses **compile-time-constant challenges** for its shuffle and
random-linear-combination gates rather than Fiat–Shamir ones (see
[`consistency_check_circuit.rs`](../constraints/consistency_check_circuit.rs)
`RLC_CHALLENGE`). That is faithful for measuring proof-system *cost* — the
circuit dimensions are identical — but is not a production-sound proof; a
hardened prover with real challenge phases would keep essentially the same
cost profile.

The upstream `parallel` (rayon) and `simd` features can be forwarded later
if throughput becomes a concern.

## Migration plan (tracking upstream Zinc+ maturity)

This integration deliberately isolates everything Zinc+-specific behind
`zkmemory::backend::MemoryConsistencyBackend` and this module, so upstream
progress can be adopted incrementally:

- **When Zinc+ gains zero-knowledge** (witness masking): bump the pinned
  revision, enable the hiding mode in `types.rs`/`prover.rs`; the UAIR and
  the public API stay unchanged.
- **When Zinc+ lands its lookup/LogUp layer**: replace the Beneš network
  with a randomized multiset argument to reclaim the `~40v` extra committed
  columns and lift `MAX_NUM_VARS`; the statement and public API stay
  unchanged.
- **When upstream publishes audited parameters**: update `types.rs`
  accordingly (`REP_FACTOR`, `NUM_COLUMN_OPENINGS`, field size).
- **Halo2 parity work in the other direction**: the
  [`MemoryConsistencyProver`](../constraints/consistency_check_circuit.rs) now
  produces a real, transferable IPA proof of the composed circuit (used by the
  benchmark above), but `Halo2Backend` still checks it with `MockProver` — the
  backend keeps the reject-at-prove-time semantics its tests rely on. Wiring
  the real prover behind the trait (and replacing the reference circuit's
  compile-time-constant challenges with real Fiat–Shamir challenge phases)
  would make the two backends fully interchangeable and the Halo2 proof
  production-sound.
