# #1608 PLAN-KILL — Phase 4c cold-path hardening plan v1

**Reviewers:** Claude SMR + Codex + AGY (3/3 converge on PLAN-KILL).

Date: 2026-05-27.

## Convergent fatal findings

Three independent reviewers converged on the following structural
fatals — none of which are recoverable by editing plan v1 in place;
all require redesign of either the rate-limit mechanism, the verdict
cache, or both.

### Fatal axis 1 — RSS spray defeats per-source semantics (all three reviewers)

Per-source-IP token-bucket runs PER-WORKER. RSS hashing on the full
5-tuple sprays a single source's random-src_port flood across every
AF_XDP worker. The CLI knob's stated semantic "per-source IP" is
unimplementable on AF_XDP zero-copy without cross-worker shared
atomic state.

- The issue's acceptance criterion "≥50% CPU% drop under 1 Mpps cold-path
  flood from 10 source IPs against a 100-rule firewall" fails by
  construction with N-worker × per-worker buckets.
- Same physics class as the per-5-tuple-fairness PLAN-KILLs
  (`feedback_per5tuple_fairness_killed`): AF_XDP ZC queue-binding is
  permanent physics; no per-flow / per-source enforcement is
  achievable in userspace from a single worker.
- Recovery requires either (a) cross-worker shared atomic per-source
  state (paying MESI ping-pong on every cold-path miss, ~50-100
  cycles), (b) renaming the CLI knob to honest per-worker semantics
  with a documented N multiplier (and accepting that acceptance fails
  as written), or (c) pre-RSS aggregation at the userspace-xdp shim
  (eBPF map writes per packet — perf regression for the legitimate
  case).

### Fatal axis 2 — verdict cache returns wrong verdicts (Claude SMR + Codex + AGY)

Plan §3.1 widens the issue's 3-tuple key to a 4-tuple `(src_ip, dst_ip,
src_port, dst_port)`. This still misses:

- `from_zone_id` + `to_zone_id` — policy evaluation is per zone-pair;
  two flows with identical 4-tuples but different egress resolutions
  get different policies. Codex caught this; it would return wrong
  verdicts on any topology with cross-zone egress ambiguity.
- DSCP, forwarding-class, frag-flags, TCP-flag bits, routing-instance,
  time-of-day matches — all are per-packet policy match dimensions
  outside the proposed 4-tuple key.
- The existing #1431 cache-key-invariant infrastructure at
  `userspace-dp/src/protocol/security.rs:62-90` explicitly warns:
  "Skipping this classification SILENTLY breaks flow-cache: a
  first-packet decision gets reused for later packets that can
  differ on the new field." Plan hand-waves "reuse the
  has_dscp_match gate" without citing it.

### Fatal axis 3 — wrong insertion point (Codex)

Plan §1.4 places the gate at ~line 605 in `poll_descriptor/mod.rs`,
between flow-cache miss and `resolve_flow_session_decision`. But that
resolver is the SESSION-table lookup, not the policy linear scan the
cache is trying to skip. The real policy scan is much later in the
slow path (~line 1375 per Codex). The verdict cache must live next to
the actual policy scan, not at the session-lookup hand-off. This
re-frames the design: it has to skip the policy scan, not skip the
session lookup.

### Fatal axis 4 — token-bucket refill truncation (AGY)

Naive integer arithmetic `refill_tokens = elapsed_ns * rate_pps / 1e9`
with `elapsed_ns = 50,000` (AF_XDP fast-poll cadence) and
`rate_pps = 1000` evaluates to 0 tokens, and the plan unconditionally
writes `bucket.last_refill_ns = now_ns` afterwards. The bucket NEVER
refills under fast polling — permanent DoS for legitimate traffic
once the initial burst is consumed. Recovery requires fixed-point
representation OR tracking the consumed nanoseconds remainder
(`last_refill_ns += tokens_to_add * 1e9 / rate_pps`).

### Fatal axis 5 — storage exceeds 256 KB budget (Claude SMR + Codex + AGY)

Plan §2.1 / §3.2 storage math is wrong on `Option<IpAddr>` and struct
alignment padding. Accurate Rust layout:

- `SourceBucketEntry` = 40 B (Option<IpAddr>=17, padding=7, TokenBucket=16) × 4096 = **160 KB**
- `VerdictCacheEntry` = 64 B (key=42 + 6 pad + value=16) × 4096 = **256 KB**
- Combined = **416 KB**, exceeds the 256 KB acceptance budget by 62.5%.

Adding `from_zone_id` + `to_zone_id` per axis 2 pushes the verdict
entry to 48-byte key, worsens this.

### Major axis 6 — cargo-bench substitute is dishonest (all three reviewers)

In-process cargo bench can NOT measure:
- AF_XDP RX driver cost (the part that drives "CPU% per worker")
- RSS distribution pattern
- L1/L2 cache pollution from the existing flow-cache scan + policy scan
- NIC ring pressure / interrupt cost

A single-threaded cargo bench tells you whether the rate-limit + cache
cells are fast in isolation. It does NOT validate the issue's stated
acceptance criterion. The honest recovery is to gate this PR on
#1607's microbench harness landing, OR downgrade the acceptance
criterion to "unit-level: gate is O(1) hash + branch."

## What this means for the issue

Issue #1608 is NOT "close issue, no recovery." The defensive-depth
goal — "small-botnet floods don't take out the cold path" — is
legitimate. The acceptance criterion AS WRITTEN is structurally
unmet by the proposed design.

A round-2 plan would need to:

1. Pick an honest semantic for 4c.1 (cross-worker shared bucket OR
   per-worker bucket with a renamed CLI knob).
2. Move the verdict cache to the real policy-scan site
   (`poll_descriptor/mod.rs:~1375`, not the session-lookup hand-off).
3. Key the verdict cache on the full policy tuple including BOTH
   zone IDs and gate-off cache when any out-of-key match field is
   present (DSCP, TCP flags, frag, etc.) — riding the existing #1431
   infrastructure.
4. Fix the token-bucket refill with fixed-point or consumed-ns-only.
5. Compact the cache (2K entries × 4 ways; OR split v4/v6 tables;
   OR truncated-hash key) with `size_of` proofs.
6. Either gate merge on #1607's wire-line harness OR rewrite the
   acceptance criteria.

That's a substantial redesign, not an edit. Per the protocol contract,
PLAN-KILL is the right outcome for plan v1.

## Provenance

- Plan: `docs/pr/1608-cold-path-hardening/plan.md` (v1, 2026-05-27)
- Claude SMR: `docs/pr/1608-cold-path-hardening/claude-smr-plan-r1.md`
- Codex (task-mpoiqsu3-3pmepo): `docs/pr/1608-cold-path-hardening/codex-plan-r1.md`
- AGY (adversarial-review-mpoipbsv-u6epb6): `docs/pr/1608-cold-path-hardening/agy-plan-r1.md`
- Reviewer IDs: `docs/pr/1608-cold-path-hardening/reviewer-ids.md`

Branch `refactor/1608-cold-path-hardening` preserved for the eventual
round-2 author to pull the plan + reviewer artifacts. No PR opened.
