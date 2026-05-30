# #1608 — Phase 4c cold-path hardening — research plan **v3 (research-only) — CONVERGED PLAN-KILL**

> **Convergence (2026-05-29):** Codex r4 + AGY r1 + Claude SMR r1 all
> **PLAN-KILL-CONFIRMED (Path A)**. Reopen only via Path D
> (run the now-uncapped #1615 flooder to a per-worker saturating
> cold-flood, populate the Scale Target table, demonstrate the policy
> scan + session install is the dominant per-worker cost).

> **History:** v1 PLAN-KILLED 2026-05-27 (6 fatal axes), v2 PLAN-KILLED
> 2026-05-27 (10 new fatals), then PARKED pending #1606 + #1607 v2 + #1609.
> This is the `/research` re-evaluation now that all three gating issues
> are CLOSED. The deliverable is a converged 3-way plan (Codex + AGY +
> Claude SMR) ending at PLAN-READY **or** PLAN-KILL. No PR, no production
> code. See the v1/v2 kill comments on #1608 for the prior fatal lists;
> they are not re-litigated here except where the landscape changed.

## Section 1 — Problem statement & scope

#1608 proposes two independent defensive mechanisms in front of the
cold path (flow-cache miss → policy linear scan → session install):

- **4c.1** per-source ingress rate-limit (token bucket before policy
  eval) to bound cold-path work under a cold-flow flood.
- **4c.2** verdict micro-cache keyed on the policy-match tuple to skip
  re-running the full scan for repeated cold verdicts.

This research asks the prior-to-design question the two PLAN-KILLs and
the parking decision deferred: **is the cold path a measured bottleneck
on the supported hardware, and do these two mechanisms add value that
the merged #1606 (address-book dedup) + #1660 (dead-host negative
cache) + #1620/#1635 (cold-path latency instrumentation) do not already
provide?**

## Section 2 — Current cold-path topology (verified against origin/master @ 6bdf9d73e)

The cold path for a forwarded transit packet that misses the flow cache:

1. `poll_descriptor/mod.rs:2392` `ForwardingDisposition::MissingNeighbor`
   arm — **#1660 dead-host negative-cache gate fires FIRST**
   (`neg_neigh_gate`, `:2418`). A negatively-cached, unresolved,
   un-expired dst is recycled immediately: no probe, no `pending_neigh`
   slot, no `MissingNeighborSeed` session, **no policy eval**.
2. `poll_descriptor/mod.rs:1393` `evaluate_policy_result_with_len`
   (ForwardCandidate slow path) — the canonical "policy decision on a
   new flow". **Wrapped by the #1620/#1635 cold-path latency histogram**
   (`cp_sample_tag`/`sample_tsc_start`/`record_sample`, `:1380-1445`).
3. `poll_descriptor/mod.rs:2522` `evaluate_policy_with_len`
   (session-install slow path; sessionless / NAT-driven forwarding).
4. `policy.rs:873` `evaluate_policy_result_with_len`:
   - `zone_pair_index.get(key)` — O(1) hash on `(from_zone, to_zone)`.
   - `for &idx in indices` — **linear scan over that zone-pair's rule
     indices** (`policy.rs:886`), then global indices (`:901`).
   - `try_match_rule` (`policy.rs:926`): inactive gate → `compiled_apps`
     O(1) protocol/port match → **`source_v4_match_any ||
     source_literal_v4.contains() || source_book_idxs.iter().any(|i|
     state.books[i].v4.contains())`** (`:944-949`).

**Landscape change since v2 was planned (#1606 landed):** the per-rule
address match is no longer "each rule independently builds its own
PrefixSet of literal CIDRs." It is now: match-any short-circuit flag →
per-rule literal `PrefixSetV4` (trie) → shared `state.books[idx]` dense
address-book entries via `source_book_idxs`. Address-book bodies are
deduplicated across rules (the #1605 1.6 TB memory blocker is gone). The
remaining rule-count-linear cost is the **outer `for &idx in indices`
zone-pair scan**, not the per-rule address set.

**#1623 scaffolding landed but the DAG did NOT.** `PolicyRule` now
carries `source_prefixes_v{4,6}: Option<Arc<[Prefix]>>` parallel arrays
(`policy.rs:182-185`) for a *future* Multi-Book LPM builder, but the
multi-stage DAG (#1609 → #1623) was PLAN-KILLED after 6 rounds. The
production cold path is **still the linear zone-pair scan**.

## Section 3 — The measurement gap (load-bearing for the whole issue)

#1608's own acceptance criteria are CPU-percentage and cycle-count
deltas under synthetic floods. The prerequisite that was supposed to
supply the baseline — #1607/#1611/#1612 hardware-ceiling measurement —
**did not produce a populated Scale Target table.** Verified:
`docs/userspace-jit-design.md` has a "Measurement plan" section
(`:637-644`) but **zero populated A1/A2/B1/B2 rows** (no
`p50`/`p99`/`ns/packet` table).

**Correction (Codex r1 finding #1) — #1615 is RESOLVED, so the
measurement is now ACHIEVABLE but was never run.** The single-thread
flooder ceiling (~870 K pps, #1611) that #1612 cited as the blocker no
longer holds: the #1615 multi-thread flooder (CLOSED) reaches
**~2.94 M pps aggregate at 4 threads (BLOCKING GATE PASS ≥2.5 M) and
~4.4 M pps at 8 threads** (`docs/pr/1615-flooder-multithread-virtio/
measurements.md:23,55`). At ~2.94 M pps across 6 workers ≈ 490 K
pps/worker — still below the ~5 Mpps/worker cold-path saturation point,
but with 8 threads (~4.4 M / ~733 K pps/worker) and a focused single-
zone-pair flood (all packets to one worker's queue share) per-worker
cold-path saturation is now within reach of the harness. **Nobody has
run that measurement and populated the Scale Target table.** So the
cold path's per-packet cost and its position on the bottleneck frontier
remain unmeasured — not because the tooling can't, but because the
measurement step was never executed. This makes the measurement-first
precondition (Path D) *available today*, which strengthens rather than
weakens the case against shipping a mechanism blind.

The #1605 kill verdict already quantified the established-flow side:
JIT-the-rewrite saves 0.4-0.6% of one core because the dominant costs
are memcpy (8%), NAPI (12%), syscalls (3%), poll_binding (22%). No
equivalent flamegraph exists for the *cold* path under flood. The only
in-tree cold-path instrument is the #1620/#1635 latency histogram, which
measures *latency per cold eval*, not *fraction of a core under flood*.

**Hostile framing:** absent a measured cold-path saturation profile,
both mechanisms are defending a threat model that has not been
demonstrated on the supported dataplane. The burden of this plan is to
either (a) cite a real measurement, or (b) justify the mechanisms as
pure availability defense-in-depth with a bounded, near-zero steady-state
cost — and show they are not already covered by #1660.

## Section 4 — Overlap analysis vs #1660 (dead-host negative cache)

#1660 (merged, `neg_neigh.rs`) already fast-fails one of the three
attack classes #1608 names:

| #1608 attack class | Reaches policy eval today? | Covered by #1660? |
|---|---|---|
| SYN flood, random src IP, **dead/unresolved dst** | NO — `neg_neigh_gate` recycles before policy eval after the first per-dst probe times out | **YES** (per-dst, per-binding, 3 s TTL) |
| SYN flood, random src IP, **live/on-link dst** (the firewall's own subnets) | YES — resolves, hits policy eval every packet | NO |
| Port scan, single src, sweeping dport, **live dst** | YES — policy eval per packet | NO |
| DNS amplification inbound, source-spoofed, **live dst** | YES — policy eval per packet | NO |

The mechanism: an **unresolved** dst is dispatched as
`ForwardingDisposition::MissingNeighbor`, where the neg-cache gate at
`:2418` fires and `continue`s (`:2442`) before the session-install
policy eval at `:2522`. A **resolved** dst is dispatched as
`ForwardCandidate` and reaches the canonical policy eval at `:1393`,
which never consults `neg_neigh`. So the dead-host class is covered by
the disposition split, and the live-dst class is not.

So #1608 is NOT a duplicate of #1660, but its *most-cited* example
(SYN flood to random/dead hosts) is already handled. The residual
threat #1608 uniquely addresses is **flood to a LIVE, resolvable dst**
(the victim service or the firewall's own interface) where every packet
legitimately reaches policy eval. This narrows the real scope
considerably and must be stated honestly.

## Section 5 — Why v1 and v2 died (carried forward, must not regress)

Convergent fatals the v3 design space inherits as hard constraints:

- **4c.1 keying physics.** AF_XDP RSS sprays the 5-tuple across N
  workers; a per-worker per-source-IP bucket sees ~1/N of an attacker.
  v2's per-DESTINATION key is the only worker-local key that sees the
  full share of a flood (the victim dst is RSS-invariant within a
  worker's queue share). Any v3 MUST use a per-worker honest semantic
  with documented N multiplier OR pay cross-worker MESI (killed).
- **4c.1 must drop SILENTLY** outside the policy engine: counter +
  `scratch_recycle` + `continue`, NO `emit_policy_deny_event` (v2 fatal
  #1 — per-packet event stream is itself a DoS), and the drop must
  actually `continue` (v2 fatal #2 — a non-Permit return at `:2522`
  fell through to session install).
- **4c.1 bucket init must be zero/single-packet credit, not full
  burst** (v2 fatal #3 — eviction storm grants a fresh burst per miss).
- **4c.1 bucket key must include zone/profile** (v2 fatal #4 — Junos
  screen profiles are per-zone).
- **4c.1 refill must be fixed-point or consumed-ns** (v1 fatal #4 —
  `elapsed_ns × pps / 1e9` truncates to 0 under fast polling, permanent
  DoS).
- **4c.2 cache MUST cache `policy_id == 0` (default-deny)** (v2 fatal #5
  — the typical flood is no-match → default-deny; skipping it = 0% hit
  under the exact attack). Rely on `config_generation` for safety.
- **4c.2 key MUST cover every `try_match_rule` input** (from/to zone
  IDs, src/dst IP, protocol, src/dst port) AND carry a #1431-style
  CACHE-KEY INVARIANT comment block on `PolicyRule` — NOT a
  `mem::size_of` proxy (v2 fatal #9 — `Vec`/`Arc`/`String` fields make
  size invariant to semantic additions; the #1623 `Option<Arc<[T]>>`
  fields prove the struct grows without `size_of` catching match-dim
  changes).
- **Storage: per-worker (not per-binding) ownership; `size_of` proofs**
  (v2 fatals #6, #7 — const_assert sizes were wrong, ownership boundary
  blew the L2 budget).
- **Acceptance can't be a single-thread cargo bench** (v1 fatal #6 /
  v2 fatal — must gate on a wire-line harness or downgrade to cycle
  counts. The #1607 harness is no longer TX-capped (#1615 lifted it to
  ~2.94-4.4 M pps), so a wire-line acceptance gate is now feasible —
  it has simply never been run for the cold path).

## Section 6 — Multiple Path Options

### Path A — PLAN-KILL (recommended default unless measurement appears)

Close-with-rationale. Rationale:
1. The cold-path bottleneck is **unmeasured** on supported hardware
   (Section 3); #1607/#1612 never populated the Scale Target table, and
   although #1615 has since lifted the flooder ceiling to ~2.94-4.4 M
   pps, the saturating cold-path measurement was never run.
2. The most-cited attack (flood to dead/random dst) is **already
   handled by #1660** (Section 4).
3. The residual threat (flood to a *live* dst reaching policy eval) is a
   genuine availability concern but is **not demonstrated** to saturate
   a worker at realistic rule counts: post-#1606 the per-rule cost is a
   match-any flag + a trie `contains` + a shared-book `contains`, and
   the rule-count-linear part is the zone-pair index scan — which #1609's
   DAG was the chartered fix for (killed, but the cost was never shown to
   bite in production).
4. Both v1 and v2 died on structural fatals; the design surface is
   demonstrably deep, and there is no measured win to justify the risk.

PLAN-KILL leaves the issue OPEN with `plan-kill`, preserving the v3
research so a future author with a real measurement can resurrect it.

### Path B — 4c.2 verdict micro-cache ONLY, gated on a measured win

Ship the verdict cache against the existing linear scan, deferring 4c.1
entirely. Justified ONLY if a measurement (Path D first) shows the
zone-pair linear scan is a real cold-path cost at the operator's rule
count. Design constraints (all from Section 5): full policy-tuple key
incl. both zone IDs; cache default-deny; `config_generation` stamp for
invalidation; #1431-style CACHE-KEY INVARIANT comment on `PolicyRule`;
per-worker set-associative table (e.g. 2-way × 2 K = 4 K entries) with
real `size_of` proof ≤ budget; insertion at the `policy.rs:873` site or
immediately wrapping the two call sites (`:1393`, `:2522`). Correctness
hazard: staleness across config reload — must invalidate on
`config_generation` bump, which is already the flow-cache invalidation
primitive.

**Structural hazard (AGY r1) — the verdict cache is worse than useless
under the exact attack it targets.** Under a random-source SYN flood
(the issue's headline), the 5-tuple varies every packet → the cache hit
rate is **~0%** (every cold packet is a unique key). The cache then adds
a hash lookup + a set-eviction + a heavy write-cycle *insertion* on
every packet, and those writes pollute the worker's L1/L2 data cache —
degrading the established-flow hot path that shares the core. So under
the attack the verdict cache *increases* cold-path cost and *decreases*
hot-path throughput. It only helps the narrow repeated-tuple case (a
slow port scan that revisits the same (src,dst,dport) within the cache
lifetime), which is not the saturation threat. This is a fundamental
reason Path B is the weaker of the two.

### Path C — 4c.1 silent per-destination rate-limit ONLY

Ship the rate-limit against live-dst floods only, deferring 4c.2. All
Section-5 4c.1 constraints apply. This is the only mechanism that adds
something #1660 does not (live-dst floods). Default-off, per-zone knob,
per-worker bucket with documented N multiplier, zero-credit init,
fixed-point refill, silent drop. Hostile concern: interaction with the
**legitimate-burst** case (a real client opening many short-lived
connections, e.g. a web crawler or a CDN origin pull) — a per-dst bucket
on the firewall's own service IP would throttle legitimate cold connects;
must be default-off and documented as an attack-mitigation knob, not a
general policy.

**Structural hazard (AGY r1) — bottleneck-shifting.** Even if 4c.1
drops post-policy, for a flood to a *live* dst the saturation cost is
not only the policy scan; the next pipeline stage is session install
(`MissingNeighborSeed` seed at `poll_descriptor/mod.rs:2652-2657`,
conntrack-table allocation). A rate-limit that drops *before* policy
eval does avoid the scan + the install, so 4c.1 is structurally the
*right* place to cut — but the win is only real if the policy scan +
install is actually the per-worker saturation cost, which is exactly
what Path D would measure. Without that measurement, 4c.1's benefit is
unquantified; with it, 4c.1 is the higher-value mechanism (it cuts the
whole tail, not just the scan, and has no L1/L2-pollution downside that
Path B carries).

### Path D — Measurement-first (precondition for B or C)

Do NOT ship either mechanism until a cold-path saturation profile exists
on real hardware. **This is now ACHIEVABLE: #1615 is CLOSED and the
multi-thread flooder reaches ~2.94-4.4 M pps** (Section 3), enough to
drive a single-zone-pair cold flood toward per-worker saturation. The
remaining work is purely to *run* it: focus the flooder on one zone-pair
(steer to one worker's queue share), capture a flamegraph under the
flood, populate the Scale Target table, and confirm the policy scan +
session install is the dominant per-worker cost. Only then is the
bottleneck claim falsifiable and the acceptance criteria meetable. This
is the honest precondition the v2 kill and the parking decision both
gestured at; **it has not been satisfied, even though the tooling now
exists to satisfy it.**

### Recommendation

**Path A (PLAN-KILL) as the default**, with Path D as the documented
reopen criterion. The two gating issues that were supposed to make a v3
"narrow" (#1607 measurement, #1609 DAG) both failed to deliver their
*deliverable*: the DAG never shipped (only #1623 scaffolding), and the
Scale Target measurement was never run — even though #1615 has since
made the harness capable of >2.5 M pps. The mechanisms therefore still
sit in front of an unmeasured cold path, and the strongest attack
example is already covered by #1660. If a
future measurement shows the live-dst flood saturates a worker, Path C
(rate-limit only) is the higher-value reopen; Path B (verdict cache) is
second and depends on rule-count-linear scan cost being demonstrated.

## Section 7 — Hot-path cost (steady state) for B and C

Both mechanisms claim near-zero steady-state cost. Verified concerns:
- 4c.1: one hash lookup + token check per **cold** packet only (the hot
  flow-cache-hit path is untouched). But a per-dst hash on every cold
  packet competes for the same L1/L2 lines as the policy scan it
  precedes; under benign cold traffic (legit new connects) it is pure
  overhead. Must be default-off.
- 4c.2: one hash lookup per cold packet; on a hit it skips the scan. Net
  win only if (scan cost − cache lookup cost) × hit rate > miss-path
  insert cost. Unquantified without Path D.

## Section 8 — Memory bounds

Per-worker, not per-binding (v2 fatal #7). The v2 convergent layout
numbers this plan inherits verbatim (do not re-derive): `TokenBucket`
= 32 B (3×u64 + u32, aligns to 32), `DestBucketEntry` = 56 B,
`VerdictCacheEntry` = 96 B (two `IpAddr` at 17 B each + both zone IDs
+ src/dst ports + protocol + verdict + generation stamp, with
alignment padding). With that layout: a 4 K-entry verdict cache alone is ~384 KB,
already over the 256 KB issue budget. Path B must either halve entries
(2 K × 96 B = 192 KB) or split v4/v6 tables. Path C's per-dst bucket
table at 56 B × 2 K = 112 KB. Combined exceeds 256 KB → the issue's own
memory acceptance criterion is unmeetable at 4 K entries; must be
re-derived if B or C proceeds.

## Section 9 — Correctness hazards (B and C)

- **Verdict-cache staleness across config reload (B):** a cached permit
  for a rule that a commit just deleted must not be honored. Mitigation:
  `config_generation` stamp in the key or a generation field compared on
  hit, evicting on mismatch. This is the same primitive the flow cache
  uses; the hazard is real but solved if the stamp is mandatory.
- **Verdict-cache match-dimension drift (B):** any future `PolicyRule`
  match dimension (time-of-day via `scheduler_name`, already a field at
  `policy.rs:128`; or a new DSCP/flag match) silently corrupts cached
  verdicts. The `mem::size_of` proxy does NOT catch this. A #1431-style
  comment-block invariant + a test that fails when a new match call is
  added to `try_match_rule` is mandatory.
- **Rate-limit false-positive on legitimate burst (C):** per-dst bucket
  on a busy service IP throttles legitimate cold connects. Default-off +
  per-zone sizing + operator documentation required.
- **No HA-sync needed (both):** like #1660's neg-cache, these are
  per-worker best-effort caches; a failover peer rebuilds them. No
  session-sync interaction. (This is a point in favor of B/C if they
  ship.)

## Section 10 — Acceptance criteria (only if B or C proceeds)

The issue's CPU-% and cycle-count criteria are unmeetable until Path D
is actually run (the saturating-flood flamegraph + Scale Target table
that #1615's now-uncapped harness can produce but nobody has produced).
Until that measurement exists, acceptance MUST be downgraded to: (a)
unit-level cycle counts via `core::arch` rdtsc microbench on the gate
primitive in isolation, AND (b) a smoke proof that the established-flow
hot path (v4+v6, push+reverse, all CoS classes) and `make test-failover`
≤60 ms are unchanged. The flood-mitigation acceptance criteria stay TBD
until the Path D measurement is run on the #1615 multi-thread harness.

## Section 11 — Reviewer questions (must be answered at convergence)

1. Is "the cold path is a bottleneck" measured anywhere, or is it
   purely a threat model? (Section 3 says: not measured.)
2. Does #1660 already cover the genuine hazard, leaving only live-dst
   floods? (Section 4 says: mostly, residual is live-dst.)
3. Given #1606's address-book dedup, is the rule-count-linear cost (the
   zone-pair index scan) actually large enough to need 4c.2 at realistic
   rule counts, or was that #1609's chartered (killed) problem?
4. Do the v1/v2 fatal axes (Section 5) close, or do they resurface in B
   and C?
5. Is the right outcome PLAN-KILL with a Path-D reopen criterion, or is
   there a measured win that makes B or C ship now?
