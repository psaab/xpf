# Claude SMR plan-review r4 — convergent PLAN-KILL

**VERDICT: PLAN-KILL.**

Round 4 of hostile review against plan v4 (commit
`031fb7ba54044da791b2c7aa4093448a1dab542a`). This round is informed
by AGY r3's verdict on v4
(`adversarial-review-mpnnu0cr-h4vt3w` — PLAN-KILL) plus three
deterministic Codex infra failures across rounds 1+2+3
(`task-mpnmsryo-txokre`, `task-mpnnbx8x-ze7vyo`,
`task-mpnntgtw-njh67s` — all "codex-linux-sandbox spawn arg0"). Per
project memory `feedback_codex_infra_must_retry`, three retries
exhausted; methodology proceeds on 3-of-4 with the
Codex-infra-blocked exception.

The two surviving reviewers (AGY + Claude SMR) converge to
PLAN-KILL on plan v4 of the **architectural plan as written**.
This carries through to plan-kill of the entire Phase 4 umbrella
unless re-scoped.

## What AGY r3 caught that I missed

### Critical miss #1 — Wire protocol pre-expands address-books

AGY r3 finding #5 is correct. I verified at SMR r4 time:

```rust
// userspace-dp/src/protocol/security.rs:63-66 (and :150-153)
#[serde(rename = "source_addresses", default)]
pub source_addresses: Vec<String>,
#[serde(rename = "destination_addresses", default)]
pub destination_addresses: Vec<String>,
```

```rust
// userspace-dp/src/policy.rs:325-344
for prefix in &snap.source_addresses {
    parse_address(prefix, &mut src_v4, &mut src_v6);
}
...
source_v4: PrefixSetV4::from_prefixes(src_v4),
```

The Go control plane sends per-rule literal CIDR string lists. The
Rust dataplane has no notion of "address-book reference" — each
rule independently builds its own `PrefixSet`. CoW Arc-sharing
across rules (plan v4 §5 "Hidden invariants" mitigation) is
**structurally impossible** without a wire-protocol redesign.

At 100k rules × 16 MB DIR-24-8 = **1.6 TB of RAM**. Plan v4's
~10 GB memory math was wrong — it assumed Arc-sharing across rules
which the protocol doesn't allow.

**This is a load-bearing kill finding.**

### Critical miss #2 — Linear-scan over indices is the actual cliff

AGY r3 finding #1 is correct. Walking
`policy.rs:430-442`:

```rust
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(result) = try_match_rule(...) {
            return result;
        }
    }
}
```

The dominant cost at 1M policies in a single hot zone-pair is the
linear scan of the **indices vector**, NOT the per-rule address
match. Plan v4's first cut (4b.0 + 4b.3 LPM) replaces the per-rule
address match but leaves the linear scan intact. At 1M indices ×
3 ns short-circuit = 3 ms/packet = 0.0003 Mpps. Even if the LPM
inside each rule were free, **4b.3 alone doesn't move the needle**.

To actually address the cliff, 4b.1 (protocol stage) + 4b.2 (port
bucketing) + 4b.4 (bucket scan) must ship together to **replace
the linear scan with the DAG walk**. The plan's "ship 4b.3 alone"
trim is therefore not a viable first cut — it's a regression
(more memory, no perf gain).

**This is also a load-bearing kill finding.**

### Critical miss #3 — 49 Mpps line-rate target is unsupported

AGY r3 finding #8 is correct. The architecture doc shows 23 Gbps
at 1500 B (1.92 Mpps); per-worker ~320 kpps. AGY cites internal
measurements showing max ~5.91 Mpps/worker on the WARM path; cold
path has never been shown to sustain even 5 Mpps/worker. 49 Mpps
× 6 workers = 294 Mpps aggregate — physically impossible on this
mlx5 VF + AF_XDP zero-copy stack.

The coordinator's 270 ns/packet budget is derived from 25 Gbps +
64 B = 49 Mpps. Without empirical evidence that the hardware can
sustain 49 Mpps at ANY policy load, the budget is hypothetical.

Plan v4 §"Open question 1" calls this out as a 4b.0 deliverable,
which is correct — but a plan that depends on resolving this
question can't be PLAN-READY until the question is answered. The
4b.0 microbench is therefore THE first deliverable, not a
side-step.

**This deepens my SMR r3 F3 — the 270 ns budget is not just
"check this" but "design depends on the answer".**

## Where r4 lands

The architecture documented in plan v4 (multi-stage DAG: protocol
1B array + per-protocol interval tree + per-bucket LPM + bucket
scan + cold-path rate-limit + micro-cache) is **directionally
correct**. The 1M-policies-at-line-rate target is a real
production need. But:

1. The wire-protocol restructure (Go pre-expansion → reference
   IDs) is **a hard prerequisite for the memory budget**. Without
   it, no Phase 4b implementation fits the memory budget.
2. The 49 Mpps hardware ceiling is **unverified**. The
   methodology cannot commit to a 270 ns budget without
   measurement.
3. The "trim to 4b.0 + 4b.3" approach is a regression, not a
   first cut. The trim must include 4b.1 + 4b.2 + 4b.4 to
   actually replace the linear scan.

PLAN-KILL of plan v4 specifically (not of the underlying problem)
is correct.

## What should happen next

PLAN-KILL with conditional follow-up:

1. **#1605 stays open** with `plan-kill` label on the Phase 4
   Cranelift narrow scope, and a comment summarising the kill
   verdict + the architectural prerequisites uncovered.
2. **Phase 4a (Cranelift per-flow rewrite JIT)**: hard kill.
   Doc-coherency update flips the row to KILLED with rationale.
3. **Phase 4b prerequisites that must land BEFORE any 1M-policy
   work**:
   - **Prerequisite A**: wire-protocol restructure to carry
     address-book IDs + CIDR table separately. This is a
     Go-side + Rust-side change. New issue.
   - **Prerequisite B**: empirical measurement of cold-path
     pps ceiling on the mlx5 VF at 64 B + various policy loads.
     New issue, owns the synthetic-policy generator.
4. **Phase 4b core (multi-stage DAG)** waits for prereqs A and B
   to land. After they're in, re-plan Phase 4b with measured
   numbers in hand.
5. **Phase 4c (cold-path hardening)**: file as a child issue
   anyway, scoped to "rate-limit cold-path policy eval" + "small
   micro-cache" — orthogonal to the DAG design and can ship
   independently against the existing linear-scan path. It
   limits the blast radius if no 4b plan ever ships.

## Self-correction note

r1: F5 wrong (PrefixTrie dead-code claim) — corrected in r2.
r2: methodology wrong (had to incorporate Q8-Q13) — corrected in r3.
r3: scope wrong (10 sub-PRs trimmed to 4b.0+4b.3) — but I missed
that 4b.3 alone is a regression, not a first cut. **AGY r3 caught
this; SMR r4 records the self-correction.**
r4: also missed the wire-protocol pre-expansion (AGY r3 #5). **I
read `policy.rs:325-344` in r3 but didn't connect it to the
"CoW Arc-share" mitigation in plan v4 §5.** Self-correction
accepted.

The methodology worked: AGY caught what I missed, just like AGY
r1 caught my prefix_set F5 error. Reviewer independence is
load-bearing.

## Self-spot-check against AGY r3 (per coordinator's hallucination-check rule)

I read AGY r3's most concrete claims and grep'd HEAD before
accepting them:

- AGY #5 (`source_addresses: Vec<String>` per-rule, no
  address-book IDs): VERIFIED at
  `userspace-dp/src/protocol/security.rs:63-66` and
  `userspace-dp/src/policy.rs:325`. AGY's quote-line evidence
  exact.
- AGY #1 (linear scan at `policy.rs:430-442`): VERIFIED at
  `userspace-dp/src/policy.rs:429-442`. Quote exact.
- AGY #2 (`PrefixTrieV4::contains` at `prefix_set.rs:209-222`,
  32 Box derefs): VERIFIED at `userspace-dp/src/prefix_set.rs:204-222`.
- AGY #3 (DIR-24-8 16 MB TBL24 × 10k books = 160 GB × 6 snapshots
  = 960 GB): math correct given finding #5; the multiplication
  follows.
- AGY #4 (`PREFIX_SET_LINEAR_MAX = 16` triggers DIR-24-8 at 17
  CIDRs): I should verify the threshold value. Reading
  `prefix_set.rs:32` — let me confirm in r5 if needed; AGY's
  number is plausible and the structural argument doesn't
  depend on the exact threshold.

No hallucinations detected in AGY r3's load-bearing findings. The
verdict is sound.

## Bottom line for r4

PLAN-KILL on plan v4 as the architectural plan.
PLAN-KILL on Phase 4a Cranelift rewrite JIT (carried).
Phase 4b is structurally blocked on the wire-protocol restructure
+ hardware-ceiling measurement; cannot proceed until those land.
Phase 4c can ship independently as cold-path hardening.

Recommendation: close out the Phase 4 JIT narrow scope on #1605
with `plan-kill`, file separate sub-issues for the wire-protocol
restructure and the hardware-ceiling measurement, defer the
1M-policy DAG decision until those prerequisites land.
