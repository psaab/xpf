# Claude SMR plan-review r3 — 1M policies @ line rate (extended Q1-Q13)

**VERDICT: PLAN-NEEDS-MAJOR.** Verdict-shift from r2 (NEEDS-MAJOR
on the v2 framing) is because v3 introduces a substantially
larger scope (10-sub-PR program) and several open architectural
gaps that need a second reviewer pass before the program commits.
v3 is the right *direction*, but the plan is not yet ready to
ratify as PLAN-READY — too many concrete numbers in v3 are
estimates that need verification, and the 10-PR sequencing is too
optimistic about methodology overhead.

This round reviews plan v3 through three hats: dataplane SMR
(AF_XDP/UMEM physics, TCP/UDP semantics, HA portability), CPU
architecture (cache, branch, BTB, L1-i, MESI), and software
design patterns.

## Verdict-shift rationale

r1 (narrow Phase 4 = rewrite JIT): **PLAN-KILL** (still valid for
4a).
r2 (1M policies, no coordinator Q8-Q13): **PLAN-NEEDS-MAJOR**
(needed Phase 4a/4b split + scope reframe; cancelled mid-review).
r3 (Q1-Q13 + cold-path line-rate target): **PLAN-NEEDS-MAJOR**
(scope is right; numerical claims need verification; sequencing is
optimistic).

## Findings on v3

### F1 (RATIFY): Phase 4a stays killed under the new framing

Coordinator's framing (cold path at line rate) actively
disqualifies Phase 4a. The rewrite arm runs ONLY on flow-cache
hit; cold-path traffic (SYN flood, port scan, randomized-src
attacks) misses the cache by definition. Cranelift cannot
accelerate the cold path because the descriptor doesn't even exist
yet at miss time. Carry v1/v2 PLAN-KILL.

### F2 (RATIFY): Existing uncompressed binary trie is structurally
dead for 1M-policy line rate

Walked `userspace-dp/src/prefix_set.rs:158-261`. The `PrefixTrieV4`
is uncompressed: each `TrieNode` holds `[Option<Box<TrieNode>>; 2]`
and `contains` walks up to 32 hops, dereferencing a `Box` (heap
load) per hop. Worst case is **32 cache-line hops per IPv4
address lookup × 2 addresses per packet = 64 hops**. At ~3 ns per
L2 hit / ~10 ns L3 hit, that's 192-640 ns just for address match
PER PACKET. Far over the 270 ns budget.

v3's 4b.3 (DIR-24-8 replacement) is necessary. Plan is correct.

### F3 (CRITICAL): The 270 ns budget is for 25 Gbps + 64 B,
but the cluster has only demonstrated 23 Gbps + 1500 B (1.92 Mpps)

Open Q1 in plan v3 calls this out, but it's load-bearing enough
that the plan should resolve it before committing the program.

The architecture doc's "Throughput Profile (23 Gbps, 12 streams)"
section uses 1500 B MTU. Converting to 64 B frames: 25 Gbps ÷
(64×8) ≈ 49 Mpps. The deployed mlx5 VF + 6 workers has NOT
been shown to sustain 49 Mpps with ANY policy load. The
project's `pkg/dataplane/userspace/` and `userspace-dp/` are
known to be **payload-bound** at large frames (memcpy 8%), but
small-frame pps performance has different bottlenecks (per-packet
syscall/NAPI/descriptor overhead).

**Recommendation:** plan v3 must include a measurement task in
4b.0 (synthetic-policy gen + microbench) that establishes the
actual line-rate pps ceiling at 64 B on this hardware, BEFORE
designing the 270 ns/packet decision DAG. If the hardware ceiling
is e.g. 12 Mpps at 64 B, the budget becomes ~1100 ns/packet and
the DAG design has 4× more headroom — Stage 3 LPM may not even
need DIR-24-8, the existing trie may be passable.

This is the single most important verification gap in v3.

### F4 (CRITICAL): Memory footprint claim needs interning analysis

Plan v3 §"Hidden invariants" item 5 claims 1.2 GB → ~250 MB via
interning. This requires that:

- Address-book references ARE shared across rules (probably
  true — `set security address-book foo` referenced by many
  policies).
- Port-range tuples ARE shared (LESS LIKELY — each rule may
  carry a unique port spec; HTTP/HTTPS/SSH ranges might dedupe
  but port-range space is large).
- Per-rule metadata (action, policy_id, hit_counter) is NOT
  intern-able (each rule has unique counters).

Realistic dedup:
- Address-books: ~10k unique tables × ~250 KB each = ~2.5 GB.
  Wait — at 1M CIDRs per address-book × 16 B per LPM entry =
  16 MB per table. 10k tables × 16 MB = 160 GB. **Not feasible.**
- Address-book references in rules: 1M rules × 8 B Arc =
  8 MB. Trivial.
- Per-rule struct: 1M × 32 B = 32 MB per snapshot.
- 6 snapshots × (LPM tables shared as Arc + 32 MB per-rule) =
  ~32 MB rules × 6 (each snapshot has new rule indices) +
  160 GB LPM (NOT shared because each snapshot can mutate).

Wait — ArcSwap pattern means old snapshot's LPM is dropped when
no refs remain. But during config-apply, both old and new are
live. At 160 GB LPM per snapshot × 2 = 320 GB. **Plan v3's
"interning brings 1.2 GB to 250 MB" is structurally optimistic.**

OR: the LPM is built INCREMENTALLY (CoW per address-book change)
and only the changed delta lives in the new snapshot. That works
but adds significant complexity.

**Recommendation:** Plan v3 must add a concrete interning sketch
with realistic numbers, OR fold "memory footprint at 1M
address-book entries × 6 snapshots" into 4b.0's microbench to be
measured before 4b.3 commits to a representation.

### F5 (MEDIUM): Cold-path micro-cache (4c.2) hit-rate claim is
not defensible from first principles

Plan v3 claims "95% hit on SYN-floods because attackers sample a
small key-space". This is hand-wavy. A modern SYN flood with
spoofed sources samples 2^32 IPv4 src-IPs uniformly; the
micro-cache keyed on src/24 has 2^24 distinct keys × 95%-hit on
64k LRU = 0.4% hit (not 95%). Real SYN floods that DO hit a
small key space (botnets with 10k unique src/24s) are a SUBSET of
adversarial traffic — the 95% claim only holds for "small-botnet
SYN-flood" not "large-botnet SYN-flood".

The mitigation still has value (small-botnet hit-rate is
genuinely high), but the framing should be honest: 4c.2
**reduces cold-path cost for the small-botnet class of attacks**,
not "95% hit on SYN-floods".

### F6 (MEDIUM): The 10-PR sequencing in v3 §"Phase 4b sub-PRs"
under-counts methodology overhead

Each sub-PR is its own:

- Plan-review cycle (Codex + AGY + SMR, 3-5 rounds typical) =
  ~1-2 weeks per PR per project velocity history.
- Smoke matrix (30 measurements on the loss userspace cluster
  per Pass A + Pass B).
- Copilot review + iterate.
- 4-of-4 merge gate.

10 sub-PRs × 1-2 weeks = 2.5-5 months. That's a real cost. The
plan should either:

- (a) commit to the full timeline with an honest schedule and
  visible milestones, OR
- (b) ship the smallest concrete win first (4b.3 DIR-24-8 LPM
  standalone) and re-plan based on measurements.

Plan v3 §"Open question 9" calls this out. r3 recommends
**option (b)**: ship 4b.0 (gen + bench) and 4b.3 (LPM) as a
pair, measure, then decide whether 4b.1-4b.2 + 4b.4 are
necessary or whether the LPM alone moves the needle to within
budget.

### F7 (RATIFY): Cranelift remains correctly rejected even at
1M-policy scale

Plan v3 §"Why Cranelift is still wrong here" makes the L1-i +
BTB capacity argument. r3 agrees: a 1M-policy match cascade
emitted as machine code is ~16 MB of `.text` per zone-pair.
Sapphire Rapids has 32 KB L1-i and ~6 KB BTB. The JIT'd code
falls out of L1 on every cold-path packet, blowing the cache
budget. Cranelift's per-flow specialisation also doesn't help
because cold-path packets DON'T HAVE A FLOW YET.

Plan v3 is consistent: kill Phase 4a Cranelift, kill 4b
Cranelift, use plain-Rust DAG.

### F8 (LOW): Stage 0 hash collision risk

Plan v3 §Stage 0 reuses `zone_pair_index: FxHashMap<u32, ...>`
from Phase 2. FxHash is non-cryptographic; an attacker who
controls zone-pair IDs can in principle force HashMap
collisions. But zone-pair IDs are derived from operator config
(not attacker-controlled), so this is benign. **No action.**

### F9 (MEDIUM): Build-time DAG construction at 5 s claim
under-specified

Plan v3 caps config-apply latency at 5 s for 1M rules. The
existing config-apply path in `pkg/configstore/` is much faster
(low milliseconds) for the policy state today. Going to 5 s is
a 1000× slowdown. The plan should explicitly note that
config-apply is a control-plane path and the operator-facing
commit-confirm window allows for 5-10 s without breaking the
operator UX. But it should also confirm that during construction,
the **old** PolicyState is still serving traffic via ArcSwap, so
there's no service interruption.

This is a doc-coherency issue more than a design issue.

## Domain-specific checks

### Hot-path allocation rule
Plan respects it (DAG construction is at config-apply, not
per-packet). **PASS.**

### Lock ordering / ArcSwap semantics
Plan reuses existing ArcSwap pattern for PolicyState. **PASS.**

### HA sync portability
Question 5 (HA at 1M policies) is open — needs the explicit
"DAG ships over the wire, secondary doesn't rebuild" verification
against pkg/cluster/. r3 marks this as a v4 deliverable.

### Numerical / counter overflow
Per-rule hit-counter is `add(packet_len)` on u64; at 100 Gbps
sustained = 12.5 GB/s = ~1.3 × 10^10 B/s. u64 wraps at
~1.8 × 10^19 → ~44 years. **PASS.**

### Verifier / kernel-API constraints
AF_XDP UMEM constraints unchanged. **PASS.**

### Adversarial-frame safety
Plan v3 reuses `try_match_rule` at the bucket leaf, which is
the same code that runs today. Differential tests against the
linear-scan reference must cover adversarial inputs (VLAN
overlap, IPv6 ext headers, fragmented IPv4). Plan §10 includes
this. **PASS-CONDITIONAL on the test plan being followed.**

## Self-correction note (continued from r2)

r1 F5 was wrong about `PrefixTrieV4/V6` being dead code. r2
self-corrected. r3 carries the correction forward. Phase 3 IS
shipped at the binary-trie level; r3 additionally finds that the
shipped binary trie is **structurally inadequate for 1M-policy
line rate** (F2). So the v1 Phase 3 question morphs from
"is Phase 3 shipped?" (yes) to "is the shipped Phase 3 enough?"
(no — 4b.3 DIR-24-8 supersedes).

No new self-correction this round; just elaboration of the prior
correction.

## What plan v4 should change

1. Resolve F3: include the 64 B line-rate pps measurement (or
   defer it explicitly to 4b.0) before committing to 270 ns per
   packet as the design target.
2. Resolve F4: rewrite the §"Hidden invariants" memory footprint
   with realistic numbers (1M CIDRs per address-book ⇒ 16 MB
   LPM per book ⇒ ~160 GB across 10k books — interning at the
   "address-book reference" level only saves 8 MB, not 950 MB).
   Either change the dedup target or change the memory budget.
3. Resolve F5: rephrase 4c.2 micro-cache claim as "reduces
   small-botnet cold-path cost", not "95% SYN-flood hit rate".
4. Resolve F6: pick option (b) — ship 4b.0 + 4b.3 first,
   re-plan. Defer 4b.1, 4b.2, 4b.4, 4b.5, 4b.6, 4c.x to
   post-measurement.
5. Resolve F9: add the "ArcSwap keeps old PolicyState live
   during DAG rebuild" sentence to the config-apply latency
   section.
6. Question 5: walk pkg/cluster/config_sync* to confirm DAG
   ships over the wire, OR add this verification as a 4b.0
   deliverable.

## Bottom line

PLAN-NEEDS-MAJOR. The architecture direction is right; the
numerical claims and sequencing are not yet defensible. v4
addresses F3/F4/F5/F6/F9 + Question 5 verification and is then
PLAN-READY for the trimmed scope (4b.0 + 4b.3 + 4a-kill +
doc-coherency updates).

The trimmed scope is a viable first cut. Full 10-PR program
re-planned after 4b.0/4b.3 land.
