# Plan: dedicated telemetry for named pre-L3 drops (#10498)

Status: IMPLEMENTED/READY — implementation landed; parent delta review is
next. This document records the shipped counter plumbing and its verification.

## 1. Issue framing

Three named pre-L3 drop sites in
userspace-dp/src/afxdp/poll_descriptor/mod.rs are silent — no dedicated
counter, event, or log distinguishes the three named reasons from ordinary
idle traffic:

1. UMEM-slice failure (~L248-253): pushes the descriptor to
   scratch_recycle and continues with no local drop counter and no touched
   assignment at that site.
2. Unknown-VLAN drop (~L265-275, causal owner #10313): sets only
   telemetry.counters.touched = true before recycling.
3. Destination-MAC drop (~L281-290, causal owner #10314): same touched-only
   treatment.

touched is a boolean flush/liveness flag, not a tally. The current tree has
57 touched=true setters in the afxdp scope (including tests); they are
idempotent stores at unrelated RX, disposition, screen, NAT, reject, and TX
sites. BatchCounters::flush uses the flag only as its early-return gate.

The engineering-style.md runtime-failure row at line 639 is narrower than
the issue wording: it requires a dedicated counter for a rare runtime
invariant violation/driver bug, which squarely covers the UMEM-slice failure.
It does not by itself require counters for expected configured admission
outcomes such as unknown VLAN or destination-MAC rejection. Those two are
still worth dedicated telemetry by the shipped martian/IPv6 fail-closed
precedent and because operators need to distinguish those three named
reasons; this plan does not misstate the style row as a blanket mandate.
The fail-closed show-surface guidance at lines 642-662 separately supports
surfacing an actionable reason when a path is deliberately excluded.

Acceptance remains one dedicated counter per named drop, visible in
show/telemetry, with touched retaining liveness-only semantics. No verdict
or forwarding behavior changes.

## 2. Honest scope and value

Value: LOW but real. The three named pre-L3 reasons are currently absent
from the operator's reason breakdown, so an outage investigator cannot tell
an idle link from traffic rejected by an unknown VLAN, a destination-MAC
anti-loop guard, or a UMEM slice failure. This closes the attribution gap
for these three named reasons only; it does not claim to instrument every
packet discarded before or after L3. Other silent or debug-only drops remain
explicitly out of scope below.

Cost: the pipeline has 16 named checkpoints per counter when structural
fields and read surfaces are counted: bump site; BatchCounters slot; flush;
BindingLiveState field and constructor; BindingLiveSnapshot field and load;
copy_live_snapshot; zero_unbound_slot; reconcile/reset.rs; Rust wire field;
Go wire field; Go sum/bridge; status aggregation/render and golden; global
counter bridge where applicable; Prometheus descriptor/collector; and docs.
Three counters therefore touch roughly 48 checklist locations plus tests.
The work is mechanical but review-heavy: a missed copy/reset/wire seam can
produce a clean zero instead of a visible count.

The UMEM caveat is important: record_rx_descriptor_telemetry runs for every
descriptor before the UMEM-slice arm and already sets touched plus RX
counters, so the current batch still flushes. The requested UMEM counter is
an attribution fix, not a claim that this particular path currently strands
a batch. The new bump still sets touched by convention and future-proofing.

## 3. Shipped context and live search

The closest shipped chain is #4743/#4768:

BatchCounters.martian_dropped / ipv6_ext_header_dropped → nonzero-gated
flush with Relaxed fetch_add and reset → BindingLiveState AtomicU64 + ctor
→ BindingLiveSnapshot struct/load → coordinator copy_live_snapshot and
zero_unbound_slot → reconcile/reset.rs → Rust BindingStatus wire fields
with serde rename/default → Go BindingStatus json tags → sumBindingCounters
and the 1/s global-counter bridge → status summary aggregation/render and
golden → Prometheus descriptor/collector → CLI/API and docs. This is two
composed precedents: the martian/IPv6 path is the direct Rust→wire→status/
userspace-Prom chain; #3326 host-inbound adds the GlobalCtr bridge. The full
source path is enumerated in §4.3 and the blast-radius census in §11.

Other relevant precedent:

- #1187 batches plain u64 fields in the owner worker and flushes only
  nonzero fields into per-binding Relaxed atomics, avoiding per-packet
  cross-core MESI traffic.
- #3326 host_inbound_denied and #4477 nat_alloc_fail are configured
  enforcement drops bridged through Go into GlobalCtr indexes and the
  aggregate Packets dropped total.
- #3343 carries an aggregate plus indexed screen-reason array and tests the
  fixed-length wire array element-wise.
- #2515/#5190 establish that copy_live_snapshot and zero_unbound_slot must
  stay in parity. The #5190 census is automatic over serialized fields; it
  does not need a hand-edited field list for these additions.
- #10313 and #10314 are CLOSED causal owners. This plan changes neither
  guard predicate nor verdict.

### Live merged-PR search (required STEP-0 evidence)

The direct GitHub repository query
`is:pr is:merged #10498` at
https://github.com/psaab/xpf/pulls?q=is%3Apr+is%3Amerged+%2310498 returned
0 total. The repository pull-request search
`repo:psaab/xpf 10498` at
https://github.com/search?q=repo%3Apsaab%2Fxpf+10498&type=pullrequests
returned 0 results. A broader merged title query
`is:pr is:merged "pre-L3"` at
https://github.com/psaab/xpf/pulls?q=is%3Apr+is%3Amerged+%22pre-L3%22
returned four unrelated PRs (#6882, #3907, #2424, #1283), none a fix for
#10498. Local history also shows the #10313/#10314 causal commits but no
named pre-L3 telemetry plumbing.

## 4. Concrete design

### 4.1 Counter names, types, and placement

Use the existing bare-name style (`martian_dropped`,
`ipv6_ext_header_dropped`) rather than inventing a `pre_l3_` prefix:

- `umem_slice_dropped` — the UMEM `slice(...) == None` arm.
- `unknown_vlan_dropped` — the `unknown_ingress_vlan(...)` arm.
- `dst_mac_dropped` — the `!ingress_destination_mac_accepted(...)` arm.

The stage and status labels carry the pre-L3 context; bare names match the
counter vocabulary already used in this crate and avoid a speculative
collision rationale. The corresponding Rust/Go wire keys are exactly
`umem_slice_dropped`, `unknown_vlan_dropped`, and `dst_mac_dropped`.

Each is a plain u64 on BatchCounters (single-owner batch-local state), an
AtomicU64 on BindingLiveState (Relaxed fetch_add at flush), a u64 field on
BindingLiveSnapshot, and a u64 field on the Rust and Go BindingStatus wire
structures. Add the fields beside the existing martian/IPv6 family in each
like-for-like structure; append the live atomics according to the existing
layout discipline, then re-measure the layout assertions.

### 4.2 Bump sites

At each of the three existing recycle arms, immediately before
scratch_recycle.push(desc.addr), add the observer-only shape:

  telemetry.counters.touched = true;
  telemetry.counters.<reason> += 1;

The UMEM arm gains touched by convention even though RX telemetry has already
set it earlier in the same descriptor path. No helper or record_* method is
needed: the two-line shape matches flowless_verdict.rs and disposition.rs.
Guard order remains VLAN → destination MAC → ARP/NDP → tunnel decapsulation
→ flow/session → L3 policy; each branch still recycles and continues exactly
as before.

### 4.3 Emission and consumer path

For each counter, implement and test every checkpoint below:

1. BatchCounters field and the one existing drop-arm increment.
2. `flush`: nonzero gate, `live.field.fetch_add(delta, Relaxed)`, then
   batch reset to zero.
3. BindingLiveState AtomicU64 field plus constructor initialization.
4. BindingLiveSnapshot field plus its Relaxed load.
5. `copy_live_snapshot` assignment into the bound BindingStatus.
6. `zero_unbound_slot` clear of an unbound status slot.
7. `reconcile/reset.rs::reset_binding_counters` clear during reconcile.
8. Rust BindingStatus serde field with exact rename and default.
9. Go BindingStatus field with the matching exact json tag and omitempty.
10. `sumBindingCounters` aggregation across bindings.
11. The existing status summary one-pass aggregation and status rows, with
    golden fixture values distinct per row.
12. Prometheus descriptor registration plus collector emission: all three
    counters are summed across bindings into three aggregate process-level
    unlabeled series and emitted unconditionally (zero is a real signal).
    Only the VLAN/MAC admission reasons enter the GlobalCtr bridge; UMEM
    remains userspace status/Prometheus-only.
13. CLI/REST/gRPC show surfaces for the named rows and, for the two folded
    admission reasons, their global counter breakdowns.
14. Documentation of status labels, metric names, and Packets dropped scope.

Global-counter ruling (resolved Q3): unknown VLAN and destination-MAC are
configuration-driven admission rejects, the same operator-enforcement class
as folded host-inbound deny. Add two dedicated global indices named
`GlobalCtrUnknownVLANDrops` and `GlobalCtrDstMACDrops` at the next currently
free slots (41 and 42 on this baseline, verified during implementation),
raise `GlobalCtrMax` accordingly and update the shared C/Go map-size
constants. `userspaceCounterSnapshot` sums both fields; `totalDrops()` adds
both; `syncBPFCountersLocked` pushes both reason deltas and the aggregate.
Add the corresponding CLI/API/Prometheus breakdown rows and distinct global
series (for example `xpf_unknown_vlan_drops_total` and
`xpf_dst_mac_drops_total`) so GlobalCtrDrops remains a total-with-breakdown.
Concrete current owners for those checkpoints are `userspace-dp/src/afxdp/mod.rs` (batch/flush), `userspace-dp/src/afxdp/binding_state/mod.rs` and `binding_state/snapshot.rs` (live/snapshot), `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs` plus `coordinator/reconcile/reset.rs` (copy/zero/reset), `userspace-dp/src/protocol/binding.rs` (Rust serde wire), `pkg/dataplane/userspace/protocol_binding.go` and `manager_counters.go` (Go wire/sum/bridge), `pkg/dataplane/userspace/format/status_sections.go` and its golden test (show summary), `pkg/api/metrics_descriptors_userspace_drops.go`, `metrics_userspace.go`, `metrics.go`, `metrics_descriptors_global.go`, and `metrics_counters.go` (Prometheus descriptors/collector/registration), REST `pkg/api/types.go` (`GlobalStats`) plus `stats.go` (`globalStatsHandler`), gRPC `proto/xpf/v1/xpf.proto` plus generated `pkg/grpcapi/xpfv1/xpf.pb.go` and `pkg/grpcapi/server_show_status.go`, CLI `pkg/grpcapi/server_show_flow.go` plus `pkg/cli/cli_show_flow.go`, and `docs/junos-cli-reference.md`.

### Pinned global_counters ABI and upgrade path

The two new global indices are not mixed-version-safe merely because the
BindingStatus wire fields use serde defaults and Go `omitempty`. The pinned
`global_counters` map is a separate ABI: `bpf/headers/xpf_common.h:307`
currently defines `GLOBAL_CTR_MAX` as 43, `bpf/headers/xpf_maps.h:324` uses that C
value for `max_entries`, `pkg/dataplane/types.go:984` defines the Go
`GlobalCtrMax` as 43, and `pkg/dataplane/loader_userspace_shim.go:728`
creates the Go shared map with that value. Adding indices 41 and 42 required
all of these max-entry values to become 43. There is no Rust `GlobalCtrMax`
constant or Rust declaration to update; the C header and Go loader are the
map-size authorities.

The live upgrade path is already explicit and must remain the compatibility
contract: `LoadUserspaceShim` → `shimPrePublishLoad` →
`loadUserspaceShimObjectsOnce` → `validateUserspaceShimSpec` →
`validateUserspaceShimLivePins`, with `xpfd verify-dataplane` (including the
`xpfd upgrade --rolling` deploy/reload path) running the
same pre-stop gate during deploy. A running old daemon's pinned
`global_counters` shape (max_entries 41) therefore intentionally fails the
new shape (max_entries 43) before the old daemon is stopped; the plan must
not promise a hitless rolling upgrade across this map-ABI change. The error
uses `userspaceShimStalePinRemediation`, whose existing recovery path is
`docs/operations/userspace-shim-pin-recovery.md`: drain the node or move
traffic to its peer, stop xpfd, unlink only the named incompatible pin, and
start xpfd so the new map is recreated. Hitless shutdown preserves pins, so a
plain restart is not a migration. No targeted automatic migration tool
exists; `xpfd cleanup` is the broader last resort and must not be proposed as
the default.

Add a fail-on-revert compatibility cell in
`pkg/dataplane/livepin_global_counters_10498_test.go`: with a new expected
shape at max_entries 43, a fabricated old live pin at 41 must be rejected by
`validateUserspaceShimSpecWith` with `global_counters`, `MaxEntries`,
`ABI-incompatible`, and the targeted-pin remediation; a matching 43 pin must
pass. The cell is RED if `global_counters` is removed from the ABI inventory
or if the max-entry comparison is bypassed. Also pin C/Go parity by checking
`GLOBAL_CTR_MAX` in `bpf/headers/xpf_common.h`, Go `GlobalCtrMax`, and the
Go `global_counters` MapSpec all equal 43.

The UMEM-slice failure is a driver/memory hygiene failure, analogous to
metadata_errors and the martian/IPv6 non-enforcement family. It receives the
same status and userspace Prometheus visibility but is deliberately excluded
from GlobalCtrDrops and gets no GlobalCtr index. Update the Packets dropped
scope documentation to say explicitly that VLAN/MAC admission drops are
included while UMEM-slice hygiene is not. This split is intentional and
per-reason; the rejected uniform NOT-folded default would undercount the two
configured admission controls.

Cardinality stays per-binding and process-global: no VLAN ID, MAC, ifindex,
or interface labels. The userspace series sum BindingStatus across bindings;
the two folded global series read their dedicated GlobalCtr offsets.

## 5. API and compatibility preservation

- Rust internals remain `pub(in crate::afxdp)` with no signature changes;
  only additive fields and observer increments are required.
- Rust and Go wire fields are additive, use exact matching names,
  `serde(default)` on Rust and `omitempty` on Go, and decode absent fields
  as zero for mixed-version helper/manager rollout. This additive-wire
  compatibility does not make the separately pinned `global_counters` map
  shape mixed-version-safe; its 41→43 crossing is guarded by the live-pin
  preflight and targeted migration path in §4.3.
- Additive CLI/status/REST/gRPC rows do not remove existing fields. The one
  intentional semantic change is documented: GlobalCtrDrops gains the two
  configured admission reasons, while the UMEM hygiene counter remains
  outside it.
- BindingLiveState is in-process Arc-shared Rust layout, not a shared-memory
  or C ABI object. Existing size/offset tests must be run and measured
  literals updated only if the append changes them; this is not a reason to
  redesign the pipeline.
- The Rust JSON-key and Go JSON-decode pins in §8 are mandatory because a
  serde rename/json tag mismatch otherwise degrades silently to zero.

## 6. Hidden invariants

- H1 Hot-path cost: a drop arm performs one branch-predictable u64
  increment on the already-borrowed BatchCounters. No allocation, lock, or
  packet-path atomic is introduced; only the existing per-poll Relaxed flush
  touches live atomics.
- H2 touched is liveness only. No reader treats it as a count, and no drop
  accounting depends on its numeric history. Its early-return role is a
  flush optimization.
- H3 Guard order and verdicts are load-bearing and unchanged.
- H4 The UMEM None arm never dereferences or slices a missing frame; it only
  bumps the counter and recycles.
- H5 Flush order is nonzero gate → fetch_add → reset. Missing reset would
  double-count; missing gate would add cross-core traffic under flood.
- H6 Copy/reset parity has two distinct guards: the existing #5190 census
  automatically checks every serialized copy_live_snapshot field against
  zero_unbound_slot and needs no extension; a new targeted 9956-style
  round-trip cell checks batch → flush → live → snapshot → copy → status →
  zero for these three fields; a separate reconcile/reset.rs companion cell
  checks reset_binding_counters. The latter is required because reset.rs is
  not covered by the #5190 census and an omission is green today.
- H7 No labels are added for VLAN, MAC, or interface identity.
- H8 Owner-worker lifecycle is single-writer: BatchCounters is stack-local
  to the owner poll loop, bounded by the existing RX batch limits; the live
  field is read Relaxed by the periodic snapshot. These descriptor drops do
  not need a Cold-path writer.
- H9 u64 overflow is not a practical per-poll concern (at most the existing
  bounded descriptor batch); process-wide wrap is handled by the existing
  safeDelta/reset convention.
- H10 Global bridge deltas are disjoint: VLAN and MAC each bump once on the
  first matching pre-L3 guard; UMEM never enters totalDrops, so no double
  count or orphaned global term is possible.
- H11 `global_counters` is a pinned map ABI, not an additive wire field:
  C/Go `max_entries` must be exactly 43 after adding indices 41 and 42. An
  old 41-entry live pin is refused before stop and requires the targeted
  migration; no hitless mixed-version crossing is claimed.

## 7. Risk table (exactly four classes)

| # | Class | Risk | Likelihood / effect | Mitigation | Residual |
|---|---|---|---|---|---|
| P1 | Packet-path | An observer edit reorders a guard, swallows recycle, or changes a verdict. | Low / HIGH — forward/drop behavior could flip. | Keep the two-line bump inside each existing arm; head tests assert recycle and downstream non-reachability. | Near zero. |
| C1 | Compat | Additive Rust/Go fields, the pinned global_counters max_entries 41→43, or two new global indices mismatch mixed versions or layout/map sizes. | Low / medium — silent zero, status skew, map refusal, or blocked upgrade. | Exact wire-name pins, serde default/json omitempty, C/Go max-entry parity at 43, live-pin preflight, targeted recovery documentation, and the explicit old-pin fail-on-revert cell. | Low with planned migration; no hitless crossing claim. |
| C2 | Compat | A new field is copied but not cleared, or reconcile reset omits it. | Medium / medium — stale unbound totals or reset survivors; this recurrence happened before. | #5190 auto census for copy/zero; targeted 9956 round-trip plus reset.rs companion cell for the three fields. | Low if both cells land. |
| O1 | Operability | A counter exists but its status/Prometheus/global scope is misleading or undiscoverable. | Medium / medium — triage remains ambiguous or Packets dropped arithmetic lies. | 16-checkpoint checklist; distinct rows/series; explicit VLAN/MAC-included vs UMEM-excluded docs and global breakdowns. | Low. |
| T1 | Test | All-ones fixtures or fabricated-only tests let wiring mistakes pass, especially at the Rust/Go JSON seam. | Medium / high — green suite with permanent zero telemetry. | Distinct 1/2/3 fixtures, split Rust/Go harnesses, both wire-name pins, and enumerated red-on-revert tripwires in §8. | Low. |

The four classes are Packet-path, Compat, Operability, and Test. Performance
is intentionally a Packet-path risk, not a fifth class.

## 8. Test plan and red-on-revert map

No cross-language Rust-drop-to-Go-text test exists in the current tree. Keep
the proof honest by splitting the harnesses while pinning their seam.

### Rust packet and lifecycle cells

- Three head cells drive `txn_run_descriptor` / the existing poll-head
  harness, one for each named arm. Each asserts its target BatchCounters
  slot is 1, the other two are 0, the descriptor is recycled, and the
  downstream stage is unreached (no session, forward request, local delivery,
  or route-miss accounting). Reverting any one bump makes its named head
  cell RED.
- The UMEM cell uses a custom XdpDesc variant: metadata remains valid, but
  the descriptor's frame range is outside the UMEM slice. This proves
  `umem_slice_dropped` rather than the unrelated `metadata_errors` counter;
  a naive out-of-bounds fixture that fails metadata parsing is rejected as a
  vacuous test.
- Unknown-VLAN uses the existing tagged unknown-VID recycle fixture. Dst-MAC
  uses the existing wrong-unicast destination fixture plus positive
  broadcast/multicast and expected-MAC controls.
- A flush/round-trip cell seeds distinct BatchCounters values (7, 11, 13),
  flushes into BindingLiveState, asserts the batch resets to zero, repeats the
  flush to prove idempotence, then snapshots, copies into BindingStatus, and
  checks each distinct value survives before zero_unbound_slot clears all
  three. Reverting any flush arm or copy/zero assignment makes the distinct
  assertion RED.
- A separate `reconcile/reset.rs` companion cell seeds BindingStatus with
  (1, 2, 3), calls reset_binding_counters, and asserts all three become 0.
  Reverting any reset line is RED. The #5190 automatic serialization census
  remains unchanged; it already covers copy_live_snapshot vs
  zero_unbound_slot without hand-maintained field additions.
- Rust wire-name pin serializes a BindingStatus payload with values 1, 2, 3
  and asserts the exact JSON keys `umem_slice_dropped`,
  `unknown_vlan_dropped`, and `dst_mac_dropped`. Reverting any serde rename
  is RED even though a defaulted receiver would otherwise read zero.

### Go fabricated-status and surface cells

- The Go status aggregation fixture fabricates three BindingStatus values
  1, 2, and 3 across different bindings and asserts each named status row
  renders its own aggregate, never an all-ones or copied field. Removing
  any sum or render term is RED.
- The Go Prometheus fixture uses distinct binding values and asserts three
  aggregate process-level unlabeled series are emitted unconditionally with
  their distinct totals. Removing a descriptor, collector emit, aggregation,
  or zero-preserving path is RED.
- A Go JSON-decode pin feeds the three exact Rust keys with values 1, 2, 3
  and asserts the Go fields. Reverting any json tag is RED.
- Global-counter bridge tests use distinct unknown-VLAN and dst-MAC values,
  assert each new reason index, and assert GlobalCtrDrops includes those two
  plus the existing enforcement terms but not UMEM. Removing either
  sum/total/delta term or either new index is RED; repeated polls assert
  safeDelta idempotence.
- The global ABI cell fabricates an old pinned `global_counters` shape at
  max_entries 41 against the new 43-entry expected shape and asserts the
  pre-stop refusal plus targeted migration remediation. Reverting the
  `global_counters` inventory entry, the C/Go max-entry parity, or the
  `MaxEntries` comparison makes this cell RED; a matching 43-entry pin is a
  positive control.
- Status golden data uses distinct values (for example 1, 2, 3), not three
  ones, so a copy-paste row wiring error cannot pass.

### Named tripwires

| Counter | Rust head | Flush/reset | Wire seam | Go status/metrics |
|---|---|---|---|---|
| umem_slice_dropped | UMEM custom-desc head cell | round-trip + reset companion | Rust key + Go decode pin | status row + userspace series; absent from GlobalCtrDrops |
| unknown_vlan_dropped | tagged unknown-VID head cell | round-trip + reset companion | Rust key + Go decode pin | status/series + GlobalCtrUnknownVLANDrops + folded total |
| dst_mac_dropped | wrong-unicast head cell | round-trip + reset companion | Rust key + Go decode pin | status/series + GlobalCtrDstMACDrops + folded total |

The existing layout-guard suite is the compatibility proof for appended
AtomicU64s. The existing canonical throughput smoke is the performance
regression check; no new microbenchmark is proposed.

## 9. Out of scope

- The 57-site census is a boundary, not a promise to instrument all sites:
  54 executable `scratch_recycle.push` sites occur in mod.rs and 3 in
  flow_cache_hit.rs; only 3 named pre-L3 heads are in scope. The other
  mod.rs sites are post-head disposition/flow/session/NAT/screen/TX paths;
  flow_cache_hit.rs sites are post-L3 fast-path behavior.
- Known adjacent debug-only or opt-in paths remain out: the junos-host
  drop arm with touched/debug accounting, and filter terms without an
  operator count. This plan closes attribution for the three named reasons,
  not every silent drop in the dataplane.
- No per-VLAN, per-MAC, per-ifindex, or per-interface labels.
- No per-packet events or logs. A hostile input can trigger these guards at
  line rate; event emission would require a separate rate-limit design.
- No XDP/kernel drops before userspace receives a descriptor.
- No verdict, forwarding, VLAN classification, destination acceptance, or
  causal-owner changes for #10313/#10314.
- No folding of the UMEM hygiene counter into GlobalCtrDrops. VLAN/MAC
  folding is in scope because Q3 is now resolved and priced.

## 10. Resolved decisions and remaining open questions

Resolved for v2:

- Q1 aggregate vs per-drop: reject one aggregate. The issue acceptance
  explicitly requires a dedicated counter per named drop; an aggregate would
  recreate the attribution ambiguity.
- Q2 UMEM placement: keep UMEM operator-visible in the same batched path.
  DebugPollCounters is debug-only and cannot satisfy show/telemetry
  acceptance. The metadata_errors-shaped direct-live path was considered
  but rejected because it would split the three-counter lifecycle and omit
  the uniform BindingStatus/Prometheus proof.
- Q3 GlobalCtrDrops: fold unknown-VLAN and dst-MAC as configured admission
  rejects with two dedicated GlobalCtr indices and breakdown rows; exclude
  UMEM as driver/memory hygiene. The documentation must state this split.
- Q4 naming: use bare `umem_slice_dropped`, `unknown_vlan_dropped`, and
  `dst_mac_dropped` to match existing counter names; status labels provide
  the pre-L3 context.
- Q5 UMEM touched assignment: keep the redundant store at the UMEM arm.
  `rx_telemetry` currently sets touched earlier, but the one cold-path store
  preserves the invariant that every counter bump also arms the flush and
  remains correct if RX accounting is moved. Kill the extra store only if a
  measured hot-path review shows a real cost; no allocation, lock, or atomic
  is introduced by this line.
- Q6 layout/perf: BindingLiveState has no C/shared-memory ABI consumer;
  append and re-measure existing layout assertions. The existing canonical
  cluster-smoke throughput lane is the performance check; no new benchmark.
- Q7 events: default NO. Counters meet the issue, while attacker-triggered
  per-packet events would churn the bounded forensic event path.

Remaining non-blocking questions (each may still invite PLAN-KILL if its
answer invalidates the stated value/cost balance):

- Q8 Should the three status labels say “UMEM slice”, “unknown VLAN”, and
  “destination MAC” without hyphens for CLI parity, or retain the exact
  guard vocabulary used in this plan? Kill only if the label cannot be made
  unambiguous without adding labels.
- Q9 Should the global VLAN/MAC metric help text repeat the userspace
  per-binding series names, or link them as aggregate/per-binding siblings?
  Kill the duplicate global series only if an existing global surface can
  expose the distinct breakdown without a new metric.
- Q10 Should the Rust wire-name pin be a focused JSON unit test or join an
  existing protocol compatibility table? Either is acceptable; kill only
  if the chosen location cannot fail on a serde rename regression.
- Q11 Should the reset companion cell share one tuple assertion or use three
  individually named assertions? Keep whichever yields the clearer
  fail-on-revert message; kill the compact form if it hides the omitted
  field.
- Q12 Should the implementation add a one-line comment at each status row
  linking the GlobalCtrDrops scope decision, or is the central docs row
  sufficient? Kill the duplicate comments if they drift from the docs.

## 11. Blast-radius summary (re-measured)

The census query was stated and rerun at the v1 tip:

- `grep -n 'scratch_recycle\.push' userspace-dp/src/afxdp/poll_descriptor/mod.rs`
  returned 55 matching lines; one is a comment, leaving 54 executable code
  pushes in mod.rs.
- The same query against
  `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` returned 7
  matching lines; four are comments, leaving 3 executable pushes. Tree-wide
  total: 57 executable pushes; 3 are the named pre-L3 heads in scope, about
  51 other executable mod.rs pushes plus the 3 post-L3 flow-cache pushes are
  out of scope.
- The census confirms no fourth named pre-L3 drop among the adjacent ARP,
  IPv6, screen, IPsec, fragment, host-inbound, or metadata-failure paths;
  those paths have their own counters/events or are explicitly different
  scope.
- `touched = true` appears at 57 afxdp setters (including test fixtures);
  it remains a flag, not a tally.
- BatchCounters has 63 scalar u64 fields plus touched and the screen-reason
  array; its flush has 64 nonzero-gated scalar/array arms. The design adds
  three fields and three arms.
- Each counter crosses 16 named checkpoints (§2), including both
  BindingLiveSnapshot and BindingStatus structures, the Rust↔Go wire-name
  seam, status aggregation, global bridge where applicable, and Prometheus
  emission. The #5190 census is automatic for copy/zero; reset.rs needs the
  explicit companion cell.
- Implementation files are bounded to the existing Rust telemetry structs,
  three poll-head arms, coordinator snapshot/reset bridge, Rust/Go protocol
  binding structs, userspace manager/status/metrics/CLI/API surfaces, tests,
  and docs. No forwarding/config-schema or unrelated packet behavior is
  changed.
