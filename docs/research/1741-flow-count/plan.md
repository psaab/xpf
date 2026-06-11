# #1741 — CoS active-flow over-count: u16 epoch-wrap ghost resurrection

Revision: v2 (2026-06-10) — round-1 findings folded in (Codex
PLAN-NEEDS-MAJOR HIGH-1/HIGH-2: close-path taxonomy corrected, clean-close
choreography repro added; Codex+AGY MEDIUM: Path-A borrow shape spelled out)
Branch: `research/1741-flow-count`
Status: round 2 review pending

## 1. Problem

`xpf_userspace_cos_active_flow_count{ifindex,queue_id,worker_id}` (and the
derived `xpf_fairness_cstruct` / `xpf_fairness_active_flows` /
`xpf_fairness_max_worker_flow_share` gauges, plus the #1830
`xpf_userspace_cos_flow_fair_flows_active` overlay and the per-binding
`xpf_userspace_binding_active_flow_count`) intermittently report MORE
active flows than exist. Issue #1741 captured 3-of-6 scrapes over-counting
(62, 49, 75 for exactly 48 pinned iperf3 streams), with
`xpf_fairness_cos_active_flow_counts_truncated` = 0 throughout.

A prior research round (2026-06-01, `docs/pr/1741-cos-active-flow-overcount/
plan.md` @ `194bc6d81`) killed two fix designs (forward-only filter;
per-FlowCache canonical-pair dedup) and could not reproduce the symptom —
the issue carries a `plan-kill` label but stayed OPEN with a
"re-open with a captured runnable repro" disposition.

**This round found the mechanism, with a deterministic runnable repro.**

## 2. Root cause (found, code-first + deterministic repro)

The metric is NOT an incremented/decremented gauge. It is a periodic
owner-only scan of each binding's 4096-entry `FlowCache`
(`active_flow_debug_entries`, `userspace-dp/src/afxdp/flow_cache.rs:465`),
counting entries whose `last_used_epoch` is within
`ACTIVE_WINDOW_EPOCHS = 10` ticks of `current_epoch` (~650 ms hot), keyed
per `(descriptor.egress_ifindex, tx_selection.queue_id)`, published per
binding (`umem/debug_state.rs:231-275`), summed at the coordinator per
`(ifindex, queue_id, worker_id)` (`coordinator/status.rs:359-384`).

The activity stamp is a **u16** (`FlowCacheEntry::last_used_epoch`,
`flow_cache.rs:158`), aged with `current_epoch.wrapping_sub(last_used_epoch)
< 10` (`active_entry_age`, `flow_cache.rs:453-460`). `current_epoch` is a
u16 advanced once per debug-publish tick (`tick_advance_epoch`, skipping
the 0 sentinel — cycle length 65535).

Dead flows are NOT removed from the cache. Production eviction paths are
only: stale-stamp on lookup (`flow_cache.rs:614-653`), HA-invalid
(`poll_descriptor/flow_cache_hit.rs:113`), and 4-way set-collision LRU.
The RST-teardown eviction (`worker/lifecycle.rs:235`) is currently DEAD
in production: `should_teardown_tcp_rst` unconditionally returns `false`
(`session_glue/mod.rs:621-634`, the #stray-RST mitigation), so
`rst_teardowns` is always empty. [v2: corrected per Codex r1 HIGH-2.]

**Which dead flows bank a nonzero (ghost-able) stamp** [v2: narrowed per
Codex r1 HIGH-1]. A FIN/RST packet is NOT `packet_eligible`
(`flow_cache.rs:216` requires TCP flags & 0x17 == 0x10), so it takes the
slow path, whose cache population is gated only by `should_cache`
(`flow_cache.rs:221`: protocol + disposition, flags not consulted) —
the FIN therefore RE-INSERTS the entry, and dedup-on-insert REPLACES it
with `last_used_epoch: 0` (`flow_cache.rs:373`, `:689-690`;
`poll_descriptor/mod.rs:1992-2016`). The FIN itself sentinel-clears.
BUT the close choreography continues: in a client-initiated close
(iperf3's shape — the client closes data streams at `-t` expiry), the
LAST forward-direction packet is the client's final pure ACK (ACKing
the server's FIN-ACK), which IS `packet_eligible` → fast-path lookup
HIT → re-stamps `last_used_epoch = current_epoch` nonzero
(`flow_cache.rs:665-668`). Proven by the v2 choreography repro (below):
insert → data-ACK hit → FIN re-insert (assert: count drops to 0,
Codex's step confirmed) → final-ACK hit (assert: count back to 1) →
idle → wrap → **10 resurrections**. Additionally frozen-nonzero with no
choreography needed: UDP flows (no close packets), TCP flows that die
abruptly (peer vanish, timeout, mid-transfer reset of the *other*
direction), and any flow whose last same-direction packet was data/ACK.
NOT ghost-able: a flow whose last forward-direction packet was the
FIN/RST itself (e.g., server-initiated close where the client never
sends a final same-direction ACK) — those end sentinel-cleared.

**Therefore: every dead entry left with a nonzero stamp resurrects into
the active window for exactly 10 epochs, once per 65535-tick cycle**,
when `current_epoch`
sweeps back past its frozen stamp. A run of K flows that ended together
freezes K entries into a ~10-epoch-wide cohort; one wrap-cycle later the
whole cohort re-enters the window for ~10 ticks and any scrape landing in
that window over-counts by up to +K. Cohorts from different historical
moments resurrect at different phases; each binding's epoch counter has
its own phase, so per-worker rows spike independently — exactly the
observed shape (`{22,4,8,19,4,5}=62`, `{16,26,9,24}=75`: a subset of
workers carrying ghost cohorts on top of the live 48).

### Deterministic repros (both FAIL on master; patches in this directory)

1. `repro-test.patch` — minimal: insert one entry, hit it once (stamping
   epoch 1), age it out, keep ticking untouched:

   ```
   assertion failed: dead entry resurrected into the active window 10
   times (first at tick Some(65519)) — #1741 ghost over-count
   ```

   Run 3×, identical output (deterministic — no timing dependence).

2. `repro-test-v2-clean-close.patch` [v2, answers Codex r1 HIGH-1] —
   models the production clean client-initiated close choreography:
   data-ACK hits, FIN slow-path re-insert (asserts the sentinel-clear
   Codex identified), final pure-ACK fast-path hit (asserts the
   re-stamp), then idle across the wrap → 10 resurrections. Run 2×,
   identical.

The dead entry counts as active for exactly `ACTIVE_WINDOW_EPOCHS` ticks
per wrap cycle, forever.

### Why it was intermittent / unreproducible before

- The wall-clock wrap period is load-dependent: the tick advances per
  `update_binding_debug_state` CALL (mask 0xFFFF), so it is ~65 ms only
  at calibrated hot rates and exactly 65 ms idle (`debug_state.rs:27`,
  #1294) — wrap ≈ 24-71 min. The ghost window is ~0.65-1.3 s per cohort
  per cycle. Catching it needs a long-lived daemon (hours of prior runs
  accumulating cohorts) and 1 Hz scrape luck — the 2026-06-01 dig-in had
  both; the kill-round repro (fresh deploy, scrape minutes later) had
  neither.
- [v2 honesty hedge, per Codex r1 MEDIUM] The mechanism + the observed
  SHAPE (per-worker spikes, intermittency, truncated=0, sums exceeding N
  by cohort-sized amounts) are proven; per-scrape ATTRIBUTION of the
  specific 3-of-6 dig-in rows is plausible but NOT demonstrated — it
  requires multiple phased cohorts across 6 bindings and/or faster
  effective tick cadence under load. The plan does not rest on it: the
  bug exists and is fixed regardless of whether some of those scrapes
  had an additional cause; no other over-count mechanism was found by
  three reviewers (see §5 and round-1 docs).
- The symmetric-key correlation in the issue is coincidental sequencing
  (those runs came later in the session, more dead cohorts banked), not
  mechanism: the wrap ghost is direction- and RSS-key-agnostic.

### Live validation of the steady-state metric (2026-06-10, loss cluster)

With CoS applied on `loss:xpf-userspace-fw0` (ifindex 14 = reth0.80,
queues 0-11), 24 pinned iperf3 streams to port 5211 (queue 11, uncapped,
22.2 Gb/s): mid-run sums `{5,4,3,5,1,7}` = **25 = 24 data + 1 control**
across 3 consecutive scrapes; all queue-11 rows vanish ≤1 s post-stop.
The metric is exact when no cohort is resonating — consistent with the
wrap ghost being the (only found) over-count mechanism.

A 95-min opportunistic live resonance watch (1 Hz scrape of queue-11 rows
on the otherwise-idle cluster after the 25-flow cohort died) was launched;
its outcome is supplementary — the unit test is the canonical repro. The
watch result will be recorded in this doc / the issue thread either way.
(Caveat: the watch is invalidated by any intervening deploy or smoke run
on the shared cluster; the harness script is preserved in §11.)

## 3. Blast radius

All consumers of the same scan inherit the ghost:

- `xpf_userspace_cos_active_flow_count` (#1248) — the issue's metric.
- `xpf_userspace_binding_active_flow_count` (#1219) — same scan, first
  return value.
- `xpf_fairness_cstruct`, `xpf_fairness_active_flows`,
  `xpf_fairness_active_workers`, `xpf_fairness_max_worker_flow_share`
  (#1247) — derived in Go from the cos rows.
- `xpf_userspace_cos_flow_fair_flows_active` (#1830 g) — coordinator
  overlay summing the same per-binding rows.
- `show class-of-service`-adjacent status surfaces and the flow worker
  debug map rows (`flow_worker_map`, #1249) — ghost entries also reappear
  there for the same 10-tick windows.
- #1850's cookbook fixture assertion (`active_flow_count > 1` after a
  2-flow run) could in principle false-pass off ghosts; after the fix it
  can only pass off genuinely-recent flows.

NOT implicated: queue scheduling/fairness behavior itself (the scan is
telemetry-only; no packet-path state reads it), the #1846 sojourn gauges,
and the (separate, second-order) UNDER-count of heavily-throttled flows
documented in the 2026-06-01 kill round (window semantics: a flow whose
packets arrive slower than the elastic ~650 ms window drops out — that is
the documented meaning of "active", not a bug fixed here; see §9).

## 4. Paths

### Path A (recommended): sentinel-clear on scan ("clamp-on-scan")

`active_flow_debug_entries` takes `&mut self`; while scanning, any entry
whose age is `>= ACTIVE_WINDOW_EPOCHS` (and `last_used_epoch != 0`) gets
`last_used_epoch = 0` (the existing "never touched" sentinel). The scan
runs immediately after every `tick_advance_epoch` call — both in the hot
publish path and the #1294 idle path (`debug_state.rs:231`) — so an entry
is sentinel-cleared on the first scan after leaving the window and can
never be re-matched by a wrapped `current_epoch`.

- Hot-path cost: zero. The scan is the existing ~65 ms debug-cadence
  O(4096) owner-only walk; the fix adds one conditional store per
  newly-expired entry, off the packet path.
- Invariant restored: "counted active ⇔ hit within the last 10 real
  ticks", with no wrap exception. Live flows are unaffected (their
  stamps are refreshed every hit, ages 0-9 never clamp).
- The repro test flips to assert 0 resurrections over 70,000 ticks
  (passes only with the clamp).
- Risk: requires `&mut` borrow at the single call site, which already
  holds `&mut BindingWorker`. No API fan-out (single caller).
- Implementation shape [v2, per Codex r1 MEDIUM + AGY r1 HIGH-resolved]:
  the `&self` helper `active_entry_age` cannot be called while
  `self.entries.iter_mut()` is alive — copy `current_epoch` into a
  local before the loop and inline the age computation
  (`current.wrapping_sub(entry.last_used_epoch)`) inside the `iter_mut`
  body; clamp with a direct field store. AGY round-1 compiled and
  green-suite-validated exactly this shape (its reverted diff is kept
  as `agy-impl-reference.patch` — reference only; Phase 2 authors
  fresh).
- Subtlety to encode in the test: `count_active_flows` (#[cfg(test)])
  and `active_flow_debug_entries` must agree post-clamp; and the clamp
  must NOT fire for age exactly 9 (boundary test).

### Path B: widen `last_used_epoch`/`current_epoch` to u32

Wrap period becomes 2^32 ticks (~8.8 years at 65 ms). Simple, but grows
the hot `FlowCacheEntry` (+2 bytes each field, possible padding growth in
a struct sized for cache lines) and `lookup()` writes a u32 instead of a
u16 per hit. Does not establish the clean invariant (a 2^32 ghost is
still a ghost); strictly worse than A unless A's `&mut` is contested.
NOT recommended; listed for completeness.

### Path C: close-unreproducible with harness

Obsolete — the mechanism is found and deterministically reproducible.
Kept only as the kill-disposition fallback if reviewers refute the
mechanism's reachability in production (they would need to refute the
persistence of dead entries or the wrap arithmetic; both are quoted
above).

### Path D: instrument-then-watch

Strictly dominated by A: the fix is smaller than any instrument and the
repro test pins it. Not proposed.

## 5. Why the two killed designs stay dead

The v1 (`!is_reverse` filter) and v2 (canonical-pair dedup) designs
targeted cross-direction/cross-binding DUPLICATION, which the kill round
proved is not the mechanism (cells are per-egress-ifindex; NAT breaks
pair identity; coordinator aggregation discards canonical ids). The wrap
ghost requires no duplication: a single cache entry over-counts by
re-entering the window. Nothing in Path A resurrects the killed designs.

## 6. Gates (Phase 2 — /engineer)

- `cargo build --release` clean (warning count == base).
- FULL `cargo test --release` awk-aggregated 0-failed; ledger flakes
  standalone-proven.
- `go test ./...` green (Go side unchanged; emission tests still pass).
- New tests: (1) the flipped repro — 0 resurrections across ≥70,000
  ticks; (2) window boundary — age 9 counted, age 10 cleared, cleared
  entry stays uncounted after wrap; (3) a live flow re-hit after a clamp
  is counted again (sentinel is recoverable by a real hit).
- No `cargo fmt` of the focused files.
- Hot-path rule: no per-packet cost added (clamp lives in the debug-
  cadence scan only).
- Live (parent smoke): standard smoke A+B; plus optional post-fix
  resonance watch (§11 harness) showing no queue-row resurrection.

## 7. Risks

- **Borrow change**: `active_flow_debug_entries(&self → &mut self)` —
  single caller, no contention; compile-time verified.
- **Semantics**: clamping resets `observed_bytes` visibility? No —
  clamp touches only `last_used_epoch`; `observed_bytes` and the entry
  itself stay (cache hit behavior unchanged; a returning flow re-stamps
  and is counted again).
- **Idle bindings**: the #1294 idle path publishes (and thus clamps) at
  65 ms wall-clock; a binding that stops being polled entirely (removed)
  drops out of `workers.live` and its rows vanish — unchanged.
- **Elastic window**: the hot-tick cadence remains call-count-based, so
  the "~650 ms" window stays elastic under load. Out of scope (#9) —
  the fix removes the wrap exception, not the elasticity.

## 8. Docs

- `docs/fairness-regimes.md`: note the gauge's restored invariant
  (active ⇔ hit within the last 10 ticks, no wrap ghosts) and the
  elastic-window caveat.
- Module comment on `last_used_epoch` / `active_entry_age` updated to
  document the sentinel-clear contract.
- Issue #1741: drop the `plan-kill` label on PLAN-READY; PR closes it.

## 9. Out of scope

- The window-semantics UNDER-count of heavily-throttled flows (kill-round
  observation: 2 counted for 48 slow `-R` streams) — that is the
  documented meaning of the 650 ms window; #1746's policy evaluation must
  use the gauge with that caveat, not this fix.
- Making the hot tick wall-clock-true (elastic window) — separate issue
  if #1746 needs it.
- Dead-entry garbage collection of the flow cache (capacity reuse is
  handled by LRU; ghosts are fixed by the clamp without removal).

## 10. Deliverable

One small PR (Phase 2): the Path-A clamp + tests + doc notes,
`Closes #1741`. Telemetry-only; no wire/protocol change; no Go change.

## 11. Repro/validation harness (preserved)

- **Deterministic unit repros**: `repro-test.patch` (minimal) and
  `repro-test-v2-clean-close.patch` (production close choreography) in
  this directory; apply to `flow_cache_tests.rs`, run
  `cargo test --release issue_1741`; both FAIL on master with
  "resurrected ... 10 times"; both must PASS post-fix when flipped into
  the suite (plus the boundary/sentinel-recovery tests of §6).
- **Live steady-state validation** (run 2026-06-10, passed): apply CoS
  (`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` if absent),
  `iperf3 -c 172.16.80.200 -p 5211 -P 24 -t 22` from
  `loss:cluster-userspace-host`, mid-run scrape
  `xpf_userspace_cos_active_flow_count{queue_id="11"}` ×3 → sum must be
  25 (24 + control); post-stop rows must vanish ≤1 s. All cluster
  commands wrapped in `flock /tmp/xpf-cluster.lock sg incus-admin -c ...`.
- **Live resonance watch** (optional, long): after a K-flow run dies on
  an otherwise-idle queue, scrape its rows at 1 Hz for ≥95 min; any
  nonzero row with no traffic = wrap ghost (master) / must never fire
  (post-fix). Script preserved at `/tmp/xpf-1741-ghost-watch.sh`
  (copied into this directory as `ghost-watch.sh`).

## Decision asked of reviewers

PLAN-READY on Path A (clamp-on-scan), or PLAN-KILL with a concrete
refutation of either (a) dead-entry persistence, (b) the wrap
arithmetic, or (c) the claim that Path A restores the invariant without
hot-path cost. The deterministic repro is runnable from the patch in
this directory — refutations should engage it.
