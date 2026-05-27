# #1608 — Phase 4c cold-path hardening — plan v1

Per-source-IP ingress rate-limit (4c.1) plus per-(src, dst, dport)
verdict micro-cache (4c.2). Both are defensive depth in front of the
existing linear-scan policy backend; the goal is "small-botnet floods
do not saturate one worker."

This plan was drafted with `userspace-dp/src/afxdp/poll_stages.rs` and
`flow_cache.rs` in front of me; symbol references are exact at HEAD
b1d738d20.

## 0 Goal and honest framing

The cold path runs the full policy eval pipeline on every flow-cache
miss. Workloads that miss every packet (SYN-flood with random 5-tuples,
port scans, source-spoofed DNS amplification) exercise the policy linear
scan at line rate. The current code path passes a 1 Mpps cold-path
flood through `resolve_flow_session_decision` → policy `indices` linear
scan → NAT → FIB lookup, every packet.

The two mechanisms below are NOT a replacement for screen profiles or
for the underlying policy backend — they are a 5-cycle drop-and-stop
filter (4c.1) and a 30–50 cycle skip-the-scan filter (4c.2) layered
before the existing pipeline. Both are opt-in; default-off; sized to
fit in L2 cache; configured per-zone (4c.1) or globally (4c.2).

**What this issue does NOT deliver:** a measured CPU% number against
a real 1 Mpps cold-path flood, because the synthetic flood harness
(`test/incus/synthetic-policy-gen.sh` / `cold-path-microbench.sh`)
belongs to issue #1607 and is explicitly out of scope here. This plan
proposes a substitute: an in-tree cargo benchmark (`benches/cold_path_4c.rs`)
that drives the rate-limit + verdict cache directly from a synthetic
descriptor stream. The bench produces the ≥50% / ≥30% acceptance
numbers; the full 1 Mpps wire-line measurement waits on #1607 and is
documented as a follow-up.

If the reviewers reject the cargo-bench substitute, the right pivot is
to gate this PR's merge on #1607 landing first, NOT to ship #1608
without an acceptance-grade measurement.

## 1 What changes

### 1.1 New module `userspace-dp/src/afxdp/cold_path_gate/`

- `mod.rs` — `ColdPathGate` struct (owns rate-limit + verdict cache)
- `source_bucket.rs` — fixed-size source-IP token-bucket table
- `verdict_cache.rs` — 4K-entry 4-way set-associative verdict cache
- `tests.rs` — unit tests for bucket refill, cache hit/miss/eviction,
  generation invalidation

Per-worker (one `ColdPathGate` per binding). Lives on
`BindingScratch` (already per-worker, allocation-free).

### 1.2 Wire-protocol

`ScreenProfileSnapshot` gains a single optional field. The plan keeps
the field on the existing per-zone struct (which is the canonical
per-zone container) rather than introducing a new top-level snapshot,
to minimise wire churn and avoid file-zone overlap with #1606 (which
is touching `protocol/security.rs` for the address-book rewrite —
adding a single Option field at the end is mechanical and won't merge
conflict).

```rust
// userspace-dp/src/protocol/security.rs
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ScreenProfileSnapshot {
    // ... existing fields
    /// #1608 4c.1: per-source-IP cold-path rate-limit, packets/sec.
    /// `None` disables; `Some(0)` is treated as `None` (defensive).
    #[serde(rename = "cold_path_rate_limit_per_source_pps", default)]
    pub cold_path_rate_limit_per_source_pps: Option<u32>,
}
```

### 1.3 Junos CLI binding (Go side)

- `pkg/config/typed.go` — new field on the per-zone screen struct:
  `ColdPathRateLimitPerSourcePPS *uint32`
- `pkg/cmdtree/tree.go` — entry under
  `security screen ids-option <profile> cold-path-rate-limit per-source <pps>`
- `pkg/config/compiler.go` — emit the field when present

### 1.4 Insertion point in the dataplane

In `userspace-dp/src/afxdp/poll_descriptor/mod.rs` after the screen
check at line 521 and BEFORE the flow-cache fast path at line 571.
This ordering is deliberate:

- Screen runs FIRST because it owns syn-flood / icmp-flood / land /
  source-spoof / IDS — the rate-limit gate is a backstop, not a
  replacement.
- The flow-cache check stays AFTER because legitimate cached flows
  must NOT pay the gate cost. The gate only fires on cache misses,
  which is exactly the cold path.

Actually — re-reading: the flow-cache hit logic is at line 571, AFTER
screen. So the correct placement is:

```
stage_screen_check        (line 521) — existing, untouched
stage_ipsec_passthrough   (line 553) — existing, untouched
stage_flow_cache_hit      (line 574) — existing fast path; cache HITS exit early
  → if FlowCacheOutcome::FallThrough, we are on the cold path
stage_cold_path_gate      (NEW) — 4c.1 rate-limit + 4c.2 verdict cache
resolve_flow_session_decision  (line 613) — existing policy eval
```

This is the cheapest correct insertion: the rate-limit only fires on
true cold-path packets, and the verdict cache only persists outputs
of the actual policy eval below it.

### 1.5 Verdict cache: what we cache and what we don't

The 4c.2 micro-cache stores ONLY the policy permit/deny verdict (plus
optional NAT rewrite tuple). It does NOT cache:

- Frame-rewrite descriptors (those belong on the per-flow cache)
- NAT pool slot allocations (must run real session install)
- FIB-resolved next-hop + neighbor MAC

The verdict cache is consulted on cache miss; a hit lets the cold
path SHORTCUT the policy linear scan but still runs the rest of the
pipeline (NAT pool, FIB, neighbor learn, session install). The win is
in cycles, not full-pipeline elimination. This is structurally
narrower than the issue body implies; that narrowing is intentional
and matches what cache-correctness allows.

## 2 Per-source token-bucket design (4c.1)

### 2.1 Bounded storage

A `HashMap<IpAddr, TokenBucket>` is itself a DDoS vector — SYN-flood
with random source IPs grows the map without bound. Use a FIXED-SIZE
open-addressed table:

```rust
const SOURCE_TABLE_WAYS: usize = 4;
const SOURCE_TABLE_SETS: usize = 1024;  // 4K entries, ~96 KB
                                        // (24 B/entry: IpAddr=17 + bucket=8)
                                        // padded to 32 → 128 KB worst case
const SOURCE_TABLE_SIZE: usize = SOURCE_TABLE_WAYS * SOURCE_TABLE_SETS;

struct TokenBucket {
    tokens: u32,           // current bucket level, in PPS units
    last_refill_ns: u64,   // timestamp of last refill computation
}

struct SourceBucketEntry {
    src_ip: Option<IpAddr>,  // None = empty slot
    bucket: TokenBucket,
}
```

Same 4-way set-associative layout as `flow_cache.rs`. On collision,
LRU eviction within the set. Aging is implicit: an inactive entry
gets evicted when a new source maps to its set.

Memory: 4 K × 32 B = 128 KB per worker (within the 256 KB combined
acceptance budget; 4c.2 gets the other 128 KB).

### 2.2 Refill math

No per-packet wall-clock read. Refill happens lazily on every lookup
using the cached `now_ns` already computed once per `poll_descriptor`
batch:

```
elapsed_ns = now_ns - bucket.last_refill_ns
refill_tokens = elapsed_ns * rate_pps / 1_000_000_000
bucket.tokens = min(burst, bucket.tokens + refill_tokens)
bucket.last_refill_ns = now_ns
```

`burst = rate_pps` (1-second burst window). On overflow / wraparound,
saturate at `u32::MAX`.

Edge case (raised as Q1 in section 7): if a source is hit by a single
packet, parked, and re-hit 10 minutes later, `elapsed_ns` is large but
the refill arithmetic must NOT panic on integer overflow. Use
`u128::from(elapsed_ns).saturating_mul(rate_pps as u128) / 1e9` to
absorb the overflow.

### 2.3 Hash + cache aliasing

`set_index = FxHasher(src_ip) & (SOURCE_TABLE_SETS - 1)`. FxHasher
on IpAddr produces good distribution; 12-bit index ensures legitimate
sources will not all collapse onto one set absent specific adversarial
choice of source IPs.

**Adversarial input warning:** An attacker who knows the FxHasher seed
and the SETS constant CAN choose source IPs to all collide on one set,
defeating the per-source isolation. Mitigation is to use a per-process
random seed (FxHasher already uses one if seeded — confirm at impl
time) and to fall back to per-set LRU eviction so a colliding-source
attack degrades to "newest source dropped" not "all sources of one
victim get parked."

### 2.4 IPv6 handling

Each `/128` host is a distinct key. The issue body's reference to
"/64 prefixes vs /128 hosts" raises whether to collapse v6 sources by
/64. This plan does NOT collapse — collapsing a /64 means a single
malicious /128 inside a legitimate /64 can starve all legitimate /128
hosts in that prefix. The /128 keying matches how screen profiles
already do source tracking (`session_limit_src`). If operators want
/64 aggregation, that's a follow-up issue (separate semantic decision).

## 3 Verdict micro-cache design (4c.2)

### 3.1 Key

`(src_ip, dst_ip, dst_port)`. 3-tuple is the issue body's spec; this
narrows over the flow-cache 5-tuple by collapsing src_port + protocol
into the cache value side. The narrowing is correct for the workload:
port scans hold src_ip fixed and sweep dst_port; the verdict is the
same for src_port=49152 and src_port=49153 against the same dst_port,
because the policy rules in zone-pair → indices scan don't typically
match on src_port. (When they do, this cache will produce wrong
verdicts. See Q4 in section 7.)

Wait — that's a real problem. Policies CAN match on src_port. The
verdict cache key must include src_port, OR the cache must be gated
off when any active policy rule references src_port. The issue body's
3-tuple spec is wrong on this point.

**Plan resolution:** key is 4-tuple `(src_ip, dst_ip, src_port, dst_port)`,
and the cache stores protocol in the value side (verdict varies by
protocol; cache must verify the protocol matches before returning a
hit). Memory budget unchanged: 4 K × 28 B = 112 KB per worker.

### 3.2 Storage

```rust
struct VerdictCacheKey {
    src_ip: IpAddr,        // 17 B (1 tag + 16 max)
    dst_ip: IpAddr,        // 17 B
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    ingress_zone_id: u16,  // zones change verdict; key MUST include
}
// Cache stores tuple → CachedVerdict + stamp
struct CachedVerdict {
    verdict: Verdict,           // permit / deny + optional NAT rewrite ID
    config_generation: u64,
}
enum Verdict {
    Permit { policy_id: u32 },
    Deny,
}
```

Same 4-way 1024-set layout as `source_bucket.rs`. Generation
invalidation is LAZY (on lookup): if `entry.config_generation !=
current_config_generation`, treat as miss and evict. Active clear is
NOT used because config bumps must NOT stop the world.

### 3.3 What hits the cache

Cache insertion happens AFTER `resolve_flow_session_decision` returns
a policy verdict, BEFORE flow-cache insertion of the rewrite
descriptor. The cache stores the policy decision only; the rest of
the slow path (NAT pool, FIB, session install) still runs. On the
SECOND port scan probe, the verdict cache hit lets us skip the
linear scan over `indices` in `policy.rs:430-442` — the ≥30%
policy-eval cycle drop target.

### 3.4 Why this isn't just the flow-cache

The flow-cache already gates the fast path on a 5-tuple (`SessionKey`)
match. The verdict cache is a SUPERSET-COVERAGE cache: it matches
flows that have NO session entry (SYN with no prior handshake, scan
probes that get dropped before session install). The flow-cache misses
these because there's no session to cache against; the verdict cache
catches them because it's a pure-policy cache below the session layer.

If reviewers ask "isn't this just a duplicate of the flow-cache" — no,
the flow-cache caches session-install OUTPUT (rewrite descriptor for
an installed session); the verdict cache caches policy-eval OUTPUT
(rule selection) before the session decision is made.

## 4 Generation invalidation interaction with HA

The flow-cache already handles config_generation + fib_generation +
owner_rg_epoch + lease invalidation (see `FlowCacheStamp::capture`).
The verdict cache only stamps `config_generation` because:

- A verdict-cache hit does NOT skip FIB lookup (FIB still runs after
  the verdict gate)
- The verdict cache returns a policy decision, not a rewrite descriptor;
  RG ownership doesn't affect the decision (the decision is "permit
  with these NAT rewrites" — the RG-dependent question is "do I install
  the session", which the verdict cache doesn't answer)
- Owner_rg_lease_until is similarly irrelevant — the verdict cache
  doesn't gate the session install

The rate-limit bucket has NO stamp because rate limits are per-source
counters, not policy-dependent. A config update that changes the
per-source PPS rate updates the rate live (the rate is read from
`screen_profiles` on every cold-path lookup); existing bucket levels
are NOT reset (in the same way RateCounter in screen/rate.rs doesn't
reset on threshold change).

**HA failover edge case:** during failover, the new master starts
with cold cold-path-gate state. An attacker mid-flood will get a fresh
empty bucket on the new master and one burst-window's worth of
unfiltered cold-path traffic. This is the same property the rest of
the dataplane has on failover (flow cache cold-starts too); not a
regression.

The verdict cache is similarly cold on failover. Acceptable.

## 5 Counters and observability

New `BatchCounters` fields:

- `cold_path_rate_limit_drops: u64` — packets dropped by 4c.1
- `cold_path_verdict_cache_hits: u64` — 4c.2 cache hits
- `cold_path_verdict_cache_misses: u64` — 4c.2 cache misses

Surfaced via Prometheus + `show security flow` (alongside existing
screen_drops). No new CLI commands required for v1; status output is
sufficient.

## 6 Files touched (exact list)

Rust dataplane:
- NEW `userspace-dp/src/afxdp/cold_path_gate/mod.rs`
- NEW `userspace-dp/src/afxdp/cold_path_gate/source_bucket.rs`
- NEW `userspace-dp/src/afxdp/cold_path_gate/verdict_cache.rs`
- NEW `userspace-dp/src/afxdp/cold_path_gate/tests.rs`
- EDIT `userspace-dp/src/afxdp/mod.rs` — `pub(super) mod cold_path_gate;`
- EDIT `userspace-dp/src/afxdp/worker/` — add `cold_path_gate: ColdPathGate`
  to per-binding state
- EDIT `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — insertion at
  line ~605 (after flow-cache miss, before resolve_flow_session_decision)
- EDIT `userspace-dp/src/afxdp/disposition.rs` — counters
- EDIT `userspace-dp/src/protocol/security.rs` — `Option<u32>` field on
  `ScreenProfileSnapshot`

Go control plane:
- EDIT `pkg/config/typed.go` — `ColdPathRateLimitPerSourcePPS *uint32`
  on per-zone screen struct
- EDIT `pkg/cmdtree/tree.go` — CLI tree entry
- EDIT `pkg/config/compiler.go` — emit field on ScreenProfileSnapshot

Tests:
- NEW `userspace-dp/src/afxdp/cold_path_gate/tests.rs` (unit)
- NEW `userspace-dp/benches/cold_path_4c.rs` (synthetic flood + scan)
- EDIT existing flow_cache tests (verify no interaction)

Docs:
- EDIT `docs/userspace-jit-design.md` — Phase 4c row
- NEW `docs/cold-path-gate.md` — operator-facing brief

## 7 Open questions for reviewers (must answer before PLAN-READY)

**Q1 — Token-bucket refill cadence and false-drop risk.**
Plan §2.2 says refill uses the cached `now_ns` from the poll batch.
That cadence is the worker tick — typically <1 ms under load, longer
when idle. A source that sends 1 packet, parks, returns 10 s later
sees `elapsed_ns = 10e9`, refill of `10e9 * rate_pps / 1e9 = 10 *
rate_pps` tokens (clamped to `burst`). This is correct, not a false
drop. The only false-drop risk would be in the OPPOSITE direction:
if `now_ns` lagged behind real time, we'd undercount refill. Since
`now_ns` is monotonic and only stale by one poll tick (sub-ms), the
undercount is bounded to one poll tick's worth of tokens, which at
1 Kpps is sub-token. **OK by analysis** — call out and confirm.

**Q2 — Cache aliasing on FxHasher.**
For both source-bucket and verdict-cache, set_index is the low 10
bits of FxHasher. If FxHasher is seeded per-process, an adversary can
not pre-compute collisions. If it's unseeded (deterministic), an
adversary can. Confirm FxHasher use here is seeded; if not, switch
to SipHash with a per-binding random key (small one-time cost).

**Q3 — HA peer rate-limit synchronization.**
Plan §4 explicitly says cold-path-gate state is NOT synced across
HA peers. An attacker that can force failover gets a fresh bucket on
the new master. Is this acceptable, or do reviewers want a sync
shim? My read: not acceptable to add HA sync for this (flow-cache
already cold-starts on failover; this is consistent), but flag it
as a design choice rather than an oversight.

**Q4 — Verdict cache key includes src_port.**
The issue body specifies 3-tuple `(src_ip, dst_ip, dst_port)`. Plan
§3.1 widens this to 4-tuple to handle policies that match on
src_port. Is this widening correct, or should the cache instead be
GATED OFF whenever any active policy rule references src_port? The
gate-off approach is more conservative but pushes detection to
config-compile time. Recommend: 4-tuple key (gives the verdict
cache wider coverage), gate-off as a fallback if the 4-tuple proves
not to cover other per-packet match dimensions.

**Q5 — Where does this interact with NAT pool exhaustion?**
A verdict cache hit returns a policy verdict including "permit with
NAT rewrite X". On the cold path, the NAT pool allocation still runs
after the cache hit. If the pool is exhausted, the NAT decision will
differ from the cached verdict (the cached verdict said "permit"; the
actual pool says "no slots"). What does the dataplane do? Today
without the cache: NAT pool exhaustion drops the packet at the NAT
allocation step. With the cache: same behavior, because we still run
the NAT allocation. **No regression** — confirm with reviewers.

## 8 Acceptance criteria (concrete)

- [ ] `cargo build --release -p userspace-dp` clean
- [ ] `cargo test --release -p userspace-dp` clean, 5/5 flake check
  on new tests
- [ ] `go test ./...` clean
- [ ] Cargo bench `cold_path_4c` shows ≥50% CPU% drop under 1 Mpps
  10-source flood (in-process synthetic)
- [ ] Cargo bench shows ≥30% policy-eval cycles drop on second-pass
  port scan (in-process synthetic)
- [ ] Cargo bench memory footprint ≤256 KB per worker for 4c.1 + 4c.2
  combined
- [ ] `make cluster-deploy` + Pass A (v4/v6 push/-R) full smoke,
  CoS-off and CoS-on, no regression
- [ ] `make test-failover` ≤ 60 ms (cold-path-gate state is per-worker,
  failover unaffected)
- [ ] `docs/userspace-jit-design.md` Phase 4c row added with measured
  numbers
- [ ] `docs/cold-path-gate.md` operator-facing brief
- [ ] No file-zone overlap with #1606 or #1607 (verified)

## 9 Risks and PLAN-KILL exposure

- **R1: cargo-bench substitute for 1 Mpps wire-line measurement.**
  Plan §0 calls this out. Reviewers may reject the substitute and
  demand we gate on #1607. If so: this plan converts to "land code +
  unit tests; defer acceptance smoke to #1607-follow-up issue."
- **R2: per-worker rate-limit is per-AF_XDP-queue, not per-flow-source.**
  RSS hashing on 5-tuple sprays a single source IP's SYN-flood
  (random src_port) across all N workers. The per-worker bucket is
  effectively N× the configured rate. This is structural physics
  documented in `feedback_per5tuple_fairness_killed`. Operators
  configuring `cold-path-rate-limit per-source 1000` are getting
  ~1000 × N pps total for an attacker spraying 5-tuples; ~1000 pps
  total for an attacker holding 5-tuple constant. The CLI knob's
  semantic is "per-source per-worker", which is what AF_XDP physics
  allows. Must be documented in operator brief.
- **R3: verdict cache correctness when policy includes per-packet match.**
  Q4 above. If policy matches on a field not in the 4-tuple key
  (e.g. DSCP — currently flow-cache-DSCP-gated, would need same
  treatment here), cache returns wrong verdict. Plan: reuse the
  `has_dscp_match` gate that flow-cache uses (in
  `userspace-dp/src/filter/mod.rs`); skip cache insertion when any
  per-packet match is active. Same gate, same code path.
- **R4: cache pollution under burst.**
  4 K entries × 4 ways = 16 K distinct verdicts before set-LRU
  eviction. A scan over 65 K ports holds 16 K verdicts and evicts
  the previous 16 K — on the second pass, set-LRU has already
  rotated. Real port scans (1024 ports, common) fit comfortably.
  Scan over 65 K ports gets ~25% hit rate on second pass instead of
  ~95%. Bench must measure this; if acceptance is missed, increase
  ways or size (within 256 KB budget).
- **R5: file-zone overlap with #1606.**
  Plan §1.2 adds a single Option<u32> field at the END of
  `ScreenProfileSnapshot`. #1606 is rewriting `protocol/security.rs`
  for AddressBookSnapshot. The Option-at-end pattern minimises
  merge-conflict risk. If #1606 lands first, the conflict is
  mechanical. If #1608 lands first, #1606's struct rewrite has to
  preserve the new field. Coordinate via comment on #1606's PR.

## 10 Out of scope (filed as follow-up issues if reviewers want)

- Per-/64 IPv6 source aggregation
- HA peer rate-limit synchronization
- 1 Mpps wire-line measurement (waits on #1607)
- Verdict cache learning across HA peers (similar story to flow cache)
- Per-source-IP allowlist / never-drop list
- Adaptive PPS based on observed legitimate-cold-path rate
- Operator-facing `clear security cold-path-gate` command
- Per-zone (not per-profile) configuration shape

## 11 Plan version

v1 — initial draft. Will iterate on reviewer feedback before any
code lands.
