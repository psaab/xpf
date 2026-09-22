# Plan: dedicated telemetry for named pre-L3 drops (#10498)

Status: DRAFT v1 — for parent-lane plan review. No production code in this round.

## 1. Issue framing

Three named pre-L3 drop sites in
userspace-dp/src/afxdp/poll_descriptor/mod.rs are silent — no dedicated
counter, event, or log distinguishes "no traffic" from "traffic dropped":

1. UMEM-slice failure (~L248-253): pushes the descriptor to scratch_recycle
   and continues with NO counter and not even a touched flag at the site.
2. Unknown-VLAN drop (~L265-275, causal owner #10313): sets only
   telemetry.counters.touched = true before recycling.
3. Destination-MAC drop (~L281-290, causal owner #10314): same touched-only
   treatment.

touched is a boolean flush/liveness flag set idempotently at 40+ unrelated
sites (disposition.rs, icmp.rs, poll_stages.rs, tx/dispatch, cookie_reply,
reject_reply, nat_exception, flowless_verdict, rx_telemetry); it gates
BatchCounters::flush and carries no tally. This contradicts the
docs/engineering-style.md overflow/failure policy row: invariant violation
at runtime requires bumping a dedicated counter and continuing.

Acceptance (from the issue): one dedicated counter per named drop, surfaced
in show/telemetry; touched remains liveness-only; drop accounting never
relies on it.

## 2. Honest scope and value

Value: LOW but real. Silent pre-L3 drops complicate outage triage today —
an operator cannot tell an idle link from a link whose traffic dies on
unknown-VLAN or dst-MAC admission. Three attributed counters close exactly
that triage gap. Nothing more is claimed: this changes no verdict, no
forwarding behavior, no performance characteristic.

Cost: the telemetry pipeline has ~9 touch points per counter (batch slot,
bump site, flush arm, live atomic, snapshot load, copy/zero/reset parity,
Go wire field, status render + golden, Prometheus series + docs). Times
three counters plus unit/visibility tests, this is a medium-sized,
mechanical, review-heavy change — roughly 27 small edits, each trivial,
whose risk lives entirely in forgetting one half of a parity pair.

Honest caveat on the UMEM site: record_rx_descriptor_telemetry runs for
every descriptor BEFORE the UMEM-slice arm and already sets touched plus
rx_packets, so the batch still flushes — the loss is attribution, not the
flush. The issue's "not even a touched flag" is literally true AT THE SITE
and the fix should still set touched there (every bump site sets it; the
site must stay correct if rx accounting ever moves), but no flush bug is
being fixed here.

## 3. Shipped context (precedent, not invention)

The design below copies the #4743/#4768 per-drop-counter chain
(martian_dropped, ipv6_ext_header_dropped), the closest shipped sibling:
fail-closed pre-policy drops with per-binding counters, status rows, and
unconditional Prometheus series. Adjacent precedent:

- #1187 double-buffer: BatchCounters batch on plain u64, flush deltas to
  BindingLiveState atomics under Relaxed ordering; nonzero-gated arms avoid
  MESI ping-pong with coordinator status reads under flood.
- #3326 host_inbound_denied + #4477 nat_alloc_fail: the GlobalCtr-bridged
  family — Rust per-binding counts summed in Go (manager_counters.go
  sumBindingCounters), delta-pushed into GlobalCtr indexes by
  syncBPFCountersLocked, folded into the aggregate Packets dropped total
  (totalDrops = policyDenied + screenDrops + hostInboundDenied +
  natAllocFail), rendered in show security flow statistics, exported as
  xpf_host_inbound_denies_total-class series.
- #3343 per-reason screen drops: aggregate + indexed breakout array flushed
  element-wise; reasons without a published ordinal bump only the aggregate.
- #2515 / #5190 / #5190-cohort: copy_live_snapshot vs zero_unbound_slot vs
  reconcile/reset.rs MUST stay field-for-field in step; drift happened
  twice (stale drop totals on unbound slots), now guarded by poison-harness
  parity tests.
- #10313 (unknown-VLAN guard) and #10314 (dst-MAC guard) are CLOSED causal
  owners; this plan touches their verdicts in NO way and keeps both linked.
- #4768: martian/ipv6 series are emitted unconditionally (0 is a real "no
  such drops" signal) so operators can alert without polling status text.

## 4. Concrete design

### 4.1 Counter names, types, placement

Three new u64 slots on BatchCounters
(userspace-dp/src/afxdp/mod.rs, beside martian_dropped /
ipv6_ext_header_dropped), each with a doc comment naming the issue,
the guard owner, and the flush target:

- pre_l3_umem_slice_dropped — UMEM-slice None arm (~L248-253).
- pre_l3_unknown_vlan_dropped — unknown_ingress_vlan arm (~L265-275).
- pre_l3_dst_mac_dropped — !ingress_destination_mac_accepted arm (~L281-290).

Rationale for the pre_l3_ family prefix: 56 scratch_recycle.push sites
exist in poll_descriptor/mod.rs; bare names (vlan_dropped, mac_dropped)
will collide with future per-feature counters, while the prefix groups the
family in status output and series names. Bare-name alternative is open
question Q4.

Type: plain u64 on BatchCounters (batch-local, cache-hot, zeroed on
flush); AtomicU64 on BindingLiveState (binding_state/mod.rs + ctor init);
u64 on BindingLiveSnapshot (binding_state/snapshot.rs load Relaxed).

### 4.2 Bump sites (the only hot-path diff)

At each of the three arms, before scratch_recycle.push(desc.addr):

  telemetry.counters.touched = true;
  telemetry.counters.pre_l3_X_dropped += 1;

No helper, no record_* method indirection: the two-line shape is what
flowless_verdict.rs:63-64 (ipv6_ext_header_dropped) and every disposition
arm already do. The UMEM arm additionally GAINS touched = true (see the
section-2 caveat for why this is convention, not a flush fix). Guard order
(VLAN before MAC before L3) and verdicts are untouched — counters are pure
observers.

### 4.3 Emission path (per counter, in order)

1. flush() arm in userspace-dp/src/afxdp/mod.rs: nonzero-gated
   live.X.fetch_add(delta, Relaxed) + reset to 0 (#1187 shape).
2. BindingLiveState AtomicU64 + constructor init (binding_state/mod.rs).
3. BindingLiveSnapshot load (binding_state/snapshot.rs).
4. copy_live_snapshot + zero_unbound_slot
   (coordinator/refresh_bindings.rs) + reconcile/reset.rs clearing —
   all three, same PR (#2515/#5190 discipline).
5. Go wire: protocol_binding.go X uint64 with json omitempty; Rust serde
   default for cross-version safety (older helper omits -> 0).
6. Status render: format/status_sections.go sum-across-bindings +
   "Pre-L3 UMEM-slice drops:" / "Pre-L3 unknown-VLAN drops:" /
   "Pre-L3 dst-MAC drops:" rows + status_summary.golden update.
7. Prometheus: xpf_userspace_pre_l3_umem_slice_dropped_total and siblings,
   summed across bindings, emitted unconditionally (#4768 shape).
8. Docs: docs/junos-cli-reference.md rows beside the Martian / IPv6
   ext-header drop documentation.
9. NOT folded into GlobalCtrDrops/totalDrops: martian/ipv6 precedent keeps
   non-enforcement drops out of Packets dropped (see Q3 for the dissent).

Scope/cardinality convention preserved: per-binding counters summed to
operator totals; NO per-VLAN / per-MAC / per-interface labels. Process-wide
global atomics (status.rs NDP_NA_*/FABRIC_LINK_* pattern) are for rare
control-plane events, not per-packet drops — explicitly not used here.

## 5. API preservation

- Rust: BatchCounters and BindingLiveState gain fields; all producers are
  in-crate (pub(in crate::afxdp)); no public API changes. Flush stays
  private; no signature changes at bump sites (TelemetryContext already
  threaded).
- Wire: additive omitempty JSON fields with serde defaults — old helper vs
  new manager (and reverse) degrade to 0, no break (protocol_binding.go
  documents this pattern per field).
- CLI/REST/Prometheus: additive rows/series only; existing series values
  unchanged (no refolding of Packets dropped). Golden file update is
  additive lines.
- Layout: new BindingLiveState atomics are appended; implementation MUST
  re-run the layout-guard tests and report any offset/size assert needing
  re-measurement rather than assuming none exists (see risk C2).

## 6. Hidden invariants (the plan-review checklist)

- H1 Hot-path cost: each bump is ONE branch-predictable u64 increment on
  the already-borrowed &mut BatchCounters. NO per-packet allocation, NO
  lock, NO atomic on the packet path (atomics only at flush under
  Relaxed). The increment sits on the drop arm (cold by definition — drops
  are the exception), so steady-state forwarding pays nothing.
- H2 touched stays boolean liveness: no reader may treat it as a tally;
  no drop accounting may branch on it. Flush's early return on !touched is
  a MESI optimization, not semantics.
- H3 Guard order is load-bearing: unknown-VLAN before dst-MAC before ARP/
  NDP, decap, flow/session, screen, policy. Counter edits must not move,
  merge, or early-exit any guard.
- H4 UMEM arm purity: the None arm must not touch area/frame (the slice
  does not exist); bump-then-recycle only.
- H5 Flush discipline: nonzero gate, fetch_add, reset to 0 — in that
  order, per field. A missed reset double-counts; a missing gate adds MESI
  traffic under flood.
- H6 Triple parity: copy_live_snapshot, zero_unbound_slot, reconcile/
  reset.rs clear the same field set; the poison-harness parity test must
  cover the three new fields or the PR is incomplete.
- H7 No label cardinality: values aggregated per binding, summed globally.
  Any per-VLAN/per-MAC breakout proposal fails this invariant and needs a
  new plan round.

## 7. Risk table (4 classes)

| # | Class | Risk | Likelihood / effect | Mitigation | Residual |
|---|-------|------|---------------------|------------|----------|
| P1 | Packet-path correctness | Counter edit disturbs a guard (reorder, swallowed recycle, verdict change) | Low / HIGH — silent forward/drop flip | Two-line observer-only diff per site; no guard motion; unit tests assert recycle + verdict unchanged; fail-on-revert bump tests | Near zero; review diff is 6 lines of hot path |
| P2 | Performance | Extra work on the hot path (branch mispredict, cache pressure) | Very low / low — drops arms are cold; increment on hot struct | H1 shape (single u64 += 1, no atomic/alloc/lock); no new branches (bump inside existing arm) | Nil; no perf gate required beyond existing suite |
| C1 | Compat (wire/layout) | New fields break old-helper/new-manager interop or layout asserts | Low / medium — status skew or test red | omitempty + serde default both directions; run layout-guard + golden tests; report re-measurements explicitly | Near zero; additive-only change |
| C2 | Compat (reset parity) | New field copied but not cleared (unbound slot shows stale drops) — the exact #2515/#5190 recurrence | Medium (it happened twice) / low — cosmetic stale total | H6 triple-parity + extend poison-harness parity test to the 3 fields; test RED without the reset half | Near zero if the test lands in the same PR |
| O1 | Operability | Counters land but operators cannot find them (no status row / series / docs) | Low / medium — the issue's triage gap persists | Section 4.3 steps 6-8 mandatory, not follow-up; counter-visibility proof in test plan | Near zero |
| O2 | Operability | Packets-dropped total confusion: are pre-L3 drops in GlobalCtrDrops or not? | Certain confusion if undocumented / low — triage arithmetic | Explicit NOT-folded decision (Q3 records dissent); docs row states the exclusion like the martian/ipv6 rows do | Documented; revisitable |
| T1 | Test | Unit tests pin the bump but not the visibility (dead-counter recurrence à la pre-#3326 GlobalCtrHostInboundDeny stuck at 0) | Medium / medium — green suite, blind operator | Counter-visibility proof required: status text + Prometheus series asserted end-to-end, not just the Rust field | Low; mirrors the #3326/#4477 bridge tests |

(4 classes: Packet-path, Compat, Operability, Test. Highest real risk is
C2 by history and T1 by precedent — both handled by named tests, not care.)

## 8. Test plan

Unit (Rust, fail-on-revert style per site, mirroring
flowless_verdict_tests.rs):

- Unknown-VLAN crafted frame (tagged VID with no configured unit on a
  trunk whose units agree on one zone) through the poll_descriptor head:
  pre_l3_unknown_vlan_dropped == 1, touched set, descriptor recycled,
  downstream stages unreached.
- Dst-MAC reject frame (unicast to foreign MAC): pre_l3_dst_mac_dropped
  == 1, touched set, recycled. Plus positive controls: broadcast/
  multicast and expected-MAC frames do NOT bump.
- UMEM OOB slice (desc.addr/len past area end): pre_l3_umem_slice_dropped
  == 1, touched set, recycled, no panic.
- Flush: batch with (1,2,3) across the three slots flushes exactly (1,2,3)
  into BindingLiveState and resets batch slots to 0; untouched batch
  flushes nothing.
- Triple parity: extend the #2515/#5190 poison harness with the three
  fields — RED if any of copy/zero/reset omits one.
- Golden: status_summary.golden gains the three rows; Go aggregation test
  sums them across bindings.

Counter-visibility proof (the T1 killer, mandatory):

- End-to-end: drive one drop of each kind through a status poll; assert
  the three status-text rows move 0 -> 1 AND the three Prometheus series
  exist with value 1. Follows the engineering-style.md witness rule: pair
  each crafted drop frame with a witness frame proving the harness would
  have observed a pass, and sample the AGGREGATE-capable surface (status
  text) rather than inferring from absence.
- Negative: idle poll shows 0s (series present, not absent) — "no traffic"
  vs "dropped" now distinguishable, which is the issue's entire point.

No cluster/incus lanes required: all proof runs in userspace unit + Go
status-render tests. If a lane cannot run in the test env, the PR body
says so with reason (never a claimed green).

## 9. Out of scope (explicit)

- The other ~53 scratch_recycle.push sites: the issue files three NAMED
  drops and disclaims "exactly three" (Limits section). No enumeration,
  no aggregate pre-L3 catch-all in this change.
- Per-VLAN / per-MAC / per-interface label breakouts (H7 cardinality
  invariant).
- Per-drop events or logs (the #3610 tuple-rich event pattern): the issue
  asks for counters; hot-path logging of drops is a flood-DoS on the log
  pipeline.
- XDP-side (kernel/AF_XDP shim) drops before userspace ever sees the
  descriptor — different layer, different telemetry.
- Folding into GlobalCtrDrops / Packets dropped (decided NO in 4.3.9;
  Q3 keeps the appeal window open).
- Any verdict change to #10313/#10314 guards (causal owners stay linked,
  untouched).

## 10. Open questions (PLAN-KILL invitations)

- Q1 Aggregate vs per-drop: is three counters worth ~27 touch points, or
  should this collapse to ONE pre_l3_dropped aggregate (possibly with
  debug-only per-site breakout)? If reviewers judge the surface cost too
  high for a LOW-impact triage gap, KILL the per-drop design toward the
  aggregate — the plan survives in reduced form.
- Q2 UMEM-slice placement: a UMEM-slice failure is a driver/memory
  invariant violation, not an enforcement/admission drop. Does it belong
  on the operator surface at all, or in DebugPollCounters only (with just
  the two admission drops operator-visible)? The engineering-style.md
  runtime row supports a dedicated counter either way; actionability
  decides. KILL the third operator counter if unactionable.
- Q3 GlobalCtrDrops folding: martian/ipv6 precedent says non-enforcement
  drops stay OUT of Packets dropped; host-inbound/nat-alloc precedent
  folds enforcement drops IN. Are unknown-VLAN/dst-MAC drops
  "enforcement" (operator-configured admission) or "hygiene" (martian
  class)? A wrong call here corrupts Packets-dropped triage arithmetic —
  argue it now, not in review round 3.
- Q4 Naming: pre_l3_ family prefix vs bare vlan/mac/umem names? Prefix
  groups but is longer and without in-tree precedent (existing names are
  bare: martian_dropped, ipv6_ext_header_dropped). If consistency beats
  grouping, KILL the prefix.
- Q5 UMEM-site touched: rx_telemetry already touched the batch before the
  UMEM arm, so touched = true at the UMEM site is belt-and-braces
  convention, not behavior. Minimal-diff reviewers may prefer the bare
  increment. Worth one line of debate; either answer is fine if recorded.
- Q6 Layout asserts: does BindingLiveState (or its consumers) carry
  offset/size const asserts that three new AtomicU64s break? The plan
  assumes append-and-re-measure; if measurement shows a fixed-layout
  consumer (shared memory, ABI), the placement design needs rework — a
  legitimate PLAN-KILL of section 4 as written.
- Q7 Event parity: should unknown-VLAN drops ALSO emit a tuple-rich event
  like #3610 host-inbound denies (which zone/MAC/VID is dropping)? The
  issue asks for counters only, and per-packet events on an attacker-
  triggerable drop are a pipeline-flood risk. Default NO; a YES needs its
  own rate-limit design and is a scope appeal, not a tweak.

## 11. Blast-radius summary (measured)

- Drop sites: 56 scratch_recycle.push sites in poll_descriptor/mod.rs; 3
  in scope, ~53 explicitly out (section 9).
- touched setters: 40+ sites across the afxdp tree — flag, not tally;
  untouched by this plan except the 3 (2 modified + 1 gained) bump lines.
- BatchCounters: 63 u64 fields + touched + screen_reason_drops array; +3
  fields, +3 flush arms (64 gated arms today).
- BindingLiveState: per-binding atomic block; +3 atomics + ctor + snapshot
  load.
- Parity surface: 166 copy lines in refresh_bindings.rs across the
  copy/zero/reset triple — +3 each, test-guarded.
- Consumers per counter: flush -> live -> snapshot -> BindingStatus ->
  Go wire -> status render + golden -> Prometheus -> docs (9 touch
  points x3, plus unit/visibility/golden tests).
- No verdict, forwarding, config-schema, or public-API consumer is
  affected; dashboards/docs referencing the NEW names do not exist yet
  (greenfield surface), while the OLD family rows (Martian, IPv6
  ext-header, host-inbound, NAT-alloc) document the pattern to copy.
