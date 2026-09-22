# DRAFT v2 — Issue #10507: standby FabricRedirect revalidation stamps recorded-egress Permit surviving promotion (fail-open)

Status: DRAFT v2 after plan-review round 1. PlanA and PlanB both returned
PLAN-NEEDS-MAJOR; this revision is a redesign fold, not a wording-only update.
No production code is changed on this path.

Worktree: `.claude/worktrees/10507-fabricredirect`
Branch: `fix/10507-fabricredirect`
STEP-0 source base: `5049e78c9`
Issue: https://github.com/psaab/xpf/issues/10507 (OPEN, zero comments)

## 1. Problem and security invariant

On a standby node, a peer-owned session hit is judged by M2 zone-policy
revalidation against the PEER-RECORDED egress zone instead of the live to-zone.
A Permit stamps `policy_revalidated_gen` at the LIVE config generation.
Promotion rewrites decision/metadata/liveness but no revalidation field, so the
stamp survives and a promoted node can forward a flow the live policy denies
until the next generation-bumping publish or session end. This is a High,
fail-open defect.

The required invariant is stronger than "clear a stamp when a command arrives":

> A Permit derived from a recorded egress may never authorize local forwarding.
> Packet-time forwarding authority, not worker-command completion, decides
> whether a recorded stamp may short-circuit M2.

The invariant must hold for every session origin, forward and reverse hits,
known and unknown owner RG, command-applied and command-backlogged states,
lease expiry/renewal, and shared-map materialization. A FabricPuntSeed's
separate purpose (preserving a peer return while the flow remains a fabric
redirect) must survive, but seed survival is not authorization for a changed
local egress.

## 2. STEP-0 evidence and source chain

The issue is live at `5049e78c9`. Pin `b71c52d6` is an ancestor. No merged PR
references #10507 (`git log --all --grep=10507` was empty; the merged-PR search
for FabricRedirect, recorded-egress, and revalidation returned only unrelated
work). The GitHub issue is OPEN and has zero comments.

The complete chain was re-read from SOURCE:

1. `userspace-dp/src/afxdp/session_glue/mod.rs:2403-2431` re-resolves a
   session hit using local FIB information, including the #326 synced-session
   path. `:2442-2449` applies HA ownership. On standby, a peer-owned live
   candidate becomes `HAInactive`; `:2450-2455` calls
   `redirect_session_via_fabric_if_needed`, returning `FabricRedirect`.
2. `userspace-dp/src/afxdp/forwarding/fabric.rs:500-525` constructs a fresh
   redirect resolution whose egress is the fabric parent. This intentionally
   replaces the useful pre-redirect local egress in the decision presented to
   M2.
3. `userspace-dp/src/afxdp/poll_descriptor/policy_revalidation.rs:738-740`
   keys `to_zone_override` on `disposition == FabricRedirect` alone; `:754`
   lets recorded `metadata.egress_zone` override the live to-zone.
4. The forward and reverse Permit exits at `:432-433` and `:662-663` call
   `SessionTable::mark_policy_revalidated`, which writes the live generation
   at `session/mod.rs:1838-1846`.
5. `session/mod.rs:2936-3006` (`refresh_for_ha_transition`) rewrites
   decision, metadata, liveness, and hold fields but no policy revalidation
   provenance. `update_session` (`:2622-2873`) likewise does not change the
   policy stamp. The current production reach of `update_session` is the
   peer-to-local promote funnel; refresh-local and refresh-for-activation
   wrappers are test-only callers. Ordinary hit liveness uses `lookup.rs`.
6. `poll_descriptor/mod.rs:1246` invokes M2 with the resolved post-redirect
   decision, so the packet path currently has no recorded-vs-live fence before
   the `Fresh` early return.
7. A second hole is reverse-first: `policy_revalidation.rs:547-674` loads the
   stored forward companion, but the existing Permit stamps only the reverse
   target (`:663`). Clearing or promoting that reverse row does not make the
   stored forward companion's recorded egress current.
8. `SessionOrigin` has ten variants in `session/entry.rs:402-440`:
   `ForwardFlow`, `ReverseFlow`, `LocalMiss`, `MissingNeighborSeed`,
   `FabricPuntSeed`, `SyncImport`, `SharedMaterialize`, `SharedPromote`,
   `WorkerLocalImport`, and `TunOrigin`. `is_peer_synced` includes
   `SyncImport`, `SharedMaterialize`, and `WorkerLocalImport` (`:466-474`),
   while only the first two are promotable (`:484-486`). Any fix that relies
   only on promotion misses WorkerLocalImport.
9. HA publication stores new runtime state before worker commands in
   `afxdp/ha/state.rs:80-150,200-249`. Workers load runtime before applying a
   bounded command batch (`worker/loop_body/mod.rs:1031-1072,1382-1415`). The
   command queue is capped at 4096 and drains at most 256 per pass
   (`worker_queue.rs:80,528-580,593-623`), so packets can arrive between
   state publication and Demote/Refresh completion.
10. Packet-time HA authority includes leases: `types/runtime.rs:469-503`
    defines `active && lease.active(now_secs)`. `forwarding/ha.rs:263-291`
    detects transitions using the boolean `active` edge, not a lease expiry
    followed by active-to-active renewal. Thus lease-only changes cannot rely
    on an activation command.
11. Flow-cache RG epoch validation evicts cached descriptors at
    `afxdp/flow_cache.rs:997-1027`, but it does not invalidate
    `SessionEntry.policy_revalidated_gen`. The next slow-path packet therefore
    reaches the insufficient generation-only M2 check, which is exactly where
    the packet-time provenance fence belongs.
12. Accepted synced upserts already fail closed: `session/install.rs:424-445`
    rejects an unauthorized local overwrite, otherwise removes the old entry
    and constructs a fresh one; `:537-551` sets both filter and policy
    revalidation to unvalidated, with `policy_revalidated_gen: 0`. Shared
    materialization calls this reset path at `session_glue/mod.rs:2184-2233`.
    It does not preserve a receiver stamp. A rejected overwrite preserves the
    local entry, which is a local-verdict case and is safe.

## 3. Corrected blast radius and census

Scope is Rust only: `userspace-dp/src/**/*.rs` contains 45 files and 158
`FabricRedirect` matches. This is not a count of every file type under `src`.

The M2 production surface is:

- `afxdp/poll_descriptor/policy_revalidation.rs`: cold judgment and the two
  Permit stamp exits;
- `afxdp/poll_descriptor/mod.rs`: the one production M2 call site;
- `session/mod.rs`: stamp storage/read/write helpers and transition mutators;
- `session/policy_revalidation_8356_tests.rs`;
- `afxdp/tests_policy_revocation_8356.rs`.

The four external files referencing the revalidation functions are therefore
`session/mod.rs`, `session/policy_revalidation_8356_tests.rs`,
`afxdp/tests_policy_revocation_8356.rs`, and `afxdp/poll_descriptor/mod.rs`.
`SyncedSessionEntry` has no policy stamp (`afxdp/worker/synced_entry.rs:13-47`),
so a receiver-local provenance field does not require a wire format or
ProtocolVersion change.

Transition census:

- One production promote funnel: `maybe_promote_synced_session_with_conntrack`
  (`session_glue/promote.rs:71-162`) calls `promote_synced_with_origin` at
  `:101`, which calls `update_session`.
- The resolver invokes that helper for forward hits and for reverse-session
  installation (`session_glue/mod.rs:2463` and `:2602`); the reverse-install
  call passes `ReverseFlow` and is a promotion no-op, which is relevant to the
  reverse-first design.
- Two production `refresh_for_ha_transition` callers exist:
  `refresh_owner_rgs.rs:67` and `demote_owner_rgs.rs:111`.
- `refresh_local` and `refresh_for_ha_activation` are test-only external
  wrappers; they must remain in differential coverage but are not claimed as
  packet-path reach.

## 4. Recommended redesign: packet-time provenance fence

### 4.1 Receiver-local stamp provenance

Extend the receiver-local policy stamp with a small provenance value, for
example `PolicyRevalidationKind`:

- `Unvalidated`: constructor/upsert default; generation 0 remains stale;
- `LiveEgress`: Permit was derived using a current local forwarding egress;
- `RecordedEgress`: Permit was derived while the current decision was a
  non-local `FabricRedirect` and therefore used recorded egress by design.

Keep this field local to `SessionEntry`; do not add it to `SyncedSessionEntry`
or the HA wire. Every constructor and remove-plus-fresh upsert initializes it
as `Unvalidated`. Change the two Permit exits to pass the kind explicitly.
`mark_policy_revalidated` must not continue to erase the distinction behind a
single no-argument API.

### 4.2 The M2 packet-time gate

Before the existing `Fresh` fast return, evaluate the current packet-time
resolution and the stamp kind:

1. `LiveEgress + current locally-forwarding resolution` keeps the existing
   once-per-generation fast path. This does not claim to close the separate
   same-generation FIB-flap residual.
2. `RecordedEgress` may short-circuit only while the current resolution is
   still a non-local fabric redirect. The packet must remain on the fabric
   redirect path; the recorded Permit never authorizes a local TX.
3. Any non-`LiveEgress` provenance (`Unvalidated` or `RecordedEgress`) plus a
   current `ForwardCandidate` or other locally forwarding candidate is always
   stale, even when its numeric generation equals the live generation (for
   example after A1 resets provenance without an eager command). Run the cold
   policy walk against the current local egress. A Permit changes the stamp to
   `LiveEgress`; Deny/Reject revokes the pair before forwarding.
4. If the current result cannot provide a valid local egress while the caller
   would otherwise locally forward, fail closed: revoke/drop rather than
   returning `Decline` and allowing a stale recorded Permit to stand. A
   current `HAInactive`, `FabricRedirect`, or other non-local result does not
   authorize local forwarding and keeps the existing standby/seed retention
   behavior. The existing `egress_ifindex == 0` standby lookup-failure guard
   remains for the non-local branch; it must not become a local-forward bypass.
5. `LocalDelivery` remains governed by the existing host-inbound/junos-host
   path and is not silently converted into a transit zone-pair judgment. The
   fence must assert that a recorded transit Permit cannot reach local transit
   forwarding through this arm.

The implementation should expose one helper that answers the combined
freshness/authority question, rather than sprinkling origin tests beside the
old generation compare. The helper must receive the packet-time decision (and,
where needed, current HA resolution) so command completion is not an input.
The existing M2 call in `poll_descriptor/mod.rs` is the required production
wiring point.

### 4.3 Reverse-first and reverse-only handling

A reverse hit is authoritative only through its forward companion. Whenever
the packet-time result would locally forward and the stored forward companion
is `FabricRedirect` or otherwise lacks `LiveEgress` provenance, the reverse
path must obtain the current forward resolution before it can promote or reuse
a Permit. This requirement applies even when A1 has reset the reverse row to
`Unvalidated`; it is not conditional on seeing `RecordedEgress` on the reverse
row:

- Resolve the stored forward companion with the same local FIB plus HA/lease
  authority used by the session-hit resolver, not the reverse packet's cached
  or fabric transport resolution.
- If the current forward resolution is a valid local forwarding candidate, use
  that live forward egress for this one cold reverse judgment. On Permit, stamp
  only the reverse hit's row; do not mark or update the forward companion from
  reverse-packet evidence, because its live-arrival FROM identity is not proven
  equivalent to the reverse stored-provenance FROM identity. On Deny/Reject,
  revoke both sides using the existing pair-aware teardown.
- If the forward companion is absent, inconsistent, or cannot produce a valid
  current egress while the packet would be locally forwarded, fail closed; do
  not return `Decline` and do not promote the reverse row. This is the explicit
  answer for reverse-only promotion.
- If the current forward result remains `FabricRedirect`, retain only the
  non-local seed/redirect behavior. Do not treat that outcome as a local
  Permit. Fabric return traffic must continue to use the recorded FROM-zone
  semantics where #7770 requires it.

This ensures the reverse cold judgment cannot consume the stored
`FabricRedirect` decision: it uses the same-packet live forward resolution but
stamps only the reverse row. The forward companion remains non-live/recorded,
so its next forward hit re-enters the cold path under §4.2; no paired stamp
synchronization is required or treated as the security proof. The production
regression must exercise the actual reverse-hit poll path before any eager
Refresh command is applied.

### 4.4 Gate ordering and ICMP early exits
The provenance/authority fence MUST run immediately after the `flow?` guard
and before the existing `LocalDelivery` shortcut, reverse dispatch, and
type-sensitive ICMP exits. The host-inbound/junos-host path remains the
authority for a genuine `LocalDelivery` result; the transit fence must prove
that a recorded transit stamp is not being used to authorize that result.

The forward ICMP guard at `policy_revalidation.rs:351-355` returns before
`policy_revalidation_target`. The reverse companion first probes its reverse
stamp at `:552-557`, then its forward-companion ICMP guard at `:596-600` can
return before the cold forward policy walk. The security-relevant distinction
is that the reverse guard follows the reverse stamp probe but still precedes
the forward cold judgment. Both placement points must be fenced. That is safe
for a `LiveEgress` stamp (the existing type-sensitive policy cannot be
re-derived without the packet type), but it is not safe for `RecordedEgress`
after the resolution becomes local.
The new order is:

1. Inspect stamp provenance and the current packet-time resolution.
2. If the stamp is `RecordedEgress` and the current result remains
   `FabricRedirect`/non-local, preserve the existing no-local-authorization
   behavior; ICMP `Decline` cannot forward locally in this state.
3. If the current result is locally forwarding, force the live-egress path
   before the ICMP early exits. When the ICMP verdict may depend on type and
   this cold helper does not have the type, return `Revoke`/fail closed for a
   recorded stamp rather than returning `None`. Do not stamp the recorded
   Permit. For a reverse hit, revoke the pair after the forward-companion
   check; an absent or unresolvable companion is also fail closed.
4. A `LiveEgress` stamp keeps the established type-sensitive `Decline`
   behavior, because that is not a recorded-egress authorization. A
   `FabricPuntSeed` remains eligible for the explicit non-local seed branch.

Add explicit ICMP cells to the coverage matrix: a recorded forward hit that
is now locally forwarding must be `Revoke`/drop (or remain non-local), and a
recorded reverse hit must be pair-fail-closed (or remain non-local). Neither
may reach the old early `None` path and locally forward.

### 4.5 Defense-in-depth transition resets

Retain the original A1/A2 resets only as defense in depth:

- A1 clears policy provenance on a peer-to-local transition in the production
  `update_session` promotion funnel. Current production reach is promote-only;
  this is not a steady-state per-packet branch.
- A2 clears policy provenance in `refresh_for_ha_transition` for activation and
  demotion refreshes. The demote `HAInactive`/`TableUnavailable` skip remains
  a non-forwarding/liveness rule, not the security proof.
- A1 and A2 must land atomically with the packet-time fence. Either reset alone
  is insufficient under queue backlog, lease-only transitions, or reverse-first
  input. The packet-time fence remains correct if commands are delayed, dropped,
  or never emitted.
- Harden `collect_refresh_owner_rgs_items` to include every
  `origin.is_peer_synced()` entry even when `owner_rg_id <= 0` and
  `fabric_ingress == false`. This closes the known collector omission as
  defense in depth; it is not a substitute for the packet-time invariant.
**Recorded deviation from unconditional A1/A2 (Main-approved Option A).**
The lane implements Fresh-only transition resets, not the unconditional
clear stated above: `update_session` (A1) and `refresh_for_ha_transition`
(A2) reset `policy_revalidation_kind` to `Unvalidated` only when
`policy_revalidated_gen` equals the live generation (Fresh); a Stale row
retains its kind through the transition. Main (invariant authority)
approved this tightening over (B) a distinct Reset provenance (same Stale
fencing outcome, bigger blast radius — newly fences Fresh resets beyond
the RED) and (C) accepting Decline for Stale-reset (violates §7.1
explicitly); the approval satisfies the 6th advisory's AGENTS escalation.
Precedented as a recorded deviation (cf. #10567's accepted deviations).

Rationale: an unconditional reset launders Stale Recorded — a fenced
recorded authorization that must fail closed on Decline and type-armed
ICMP even when stale (gate: `Recorded + intent` fences regardless of
freshness) — into Stale Unvalidated, the never-validated carve-out that
Declines per #8618/#9513 to avoid manufacturing a verdict it could not
derive. The laundering trades a fail-closed fence for an unfenced
carve-out precisely when a prior recorded authorization exists but the
generation moved (Cell 1c RED: gen-7 Recorded → gen-8 armed + A1 reset →
Stale Unvalidated + type-armed → Decline/survive instead of revoke). A
Stale row already re-judges via the Stale arm; its kind decides
fail-closed vs carve-out, so preserving Stale Recorded keeps the fence
through the transition. Fresh behavior is bit-identical to unconditional
(Fresh → Unvalidated, forcing cold); the packet-time fence — the
security proof — is unaffected and remains correct if commands are
delayed, dropped, or never emitted.

Fencing table for A1/A2 (post-deviation):
- Fresh (any kind) + peer→local / Refresh → Unvalidated (force cold;
  fail closed on Decline/ICMP when locally forwarding).
- Stale Recorded + transition → Recorded preserved (cold via Stale arm;
  fail closed on Decline/ICMP when locally forwarding, incl. no-egress).
- Stale Unvalidated/Live + transition → preserved (Stale Unvalidated
  keeps the #8618 with-egress Decline carve-out; Stale Live keeps the
  ordinary stale Decline; both still fail closed on no-egress per the
  unconditional rule 4).
- Boundary pins (Fresh behavior unchanged) live with the stamp-lifecycle
  tests; Cell 1c pins the Stale-Recorded fence through A1.


## 5. Ten-origin coverage table

Legend:

- `LF`: current packet-time resolution is locally forwarding; require a live
  egress policy walk, then stamp `LiveEgress` on Permit or revoke on Deny.
- `NR`: current result is non-local redirect/non-forwarding; no recorded Permit
  is allowed to authorize local forwarding. Preserve redirect only where the
  origin/path explicitly permits it.
- `RF`: reverse-first forward-companion fence; resolve and judge the stored
  forward companion, or fail closed.
- `SD`: FabricPuntSeed-specific redirect survival; it preserves the peer return
  only while the flow remains non-local and never authorizes a changed local
  egress.
- `TD`: existing TunOrigin/self-origin decline/host semantics; no transit
  recorded-egress authority.
- `FC`: fail closed (revoke/drop) when an otherwise-local packet has no valid
  current forward egress or companion.
- `IMP`: impossible for a well-formed entry/direction; keep an invariant guard
  and fail closed if observed.

Columns encode owner-known/unknown (K/U), direction (F/R), and command state
(A/N = applied/not applied). The fence in each cell is packet-time; A2 command
completion is never assumed.

| Origin (all ten) | K/F/A | K/F/N | K/R/A | K/R/N | U/F/A | U/F/N | U/R/A | U/R/N |
|---|---|---|---|---|---|---|---|---|
| ForwardFlow | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| ReverseFlow | IMP/FC | IMP/FC | RF/FC | RF/FC | IMP/FC | IMP/FC | RF/FC | RF/FC |
| LocalMiss | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| MissingNeighborSeed | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| FabricPuntSeed | SD or LF | SD or LF | SD/RF | SD/RF | SD or FC | SD or FC | SD/RF or FC | SD/RF or FC |
| SyncImport | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| SharedMaterialize | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| SharedPromote | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| WorkerLocalImport | LF | LF | RF | RF | LF or FC | LF or FC | RF or FC | RF or FC |
| TunOrigin | TD | TD | TD | TD | TD | TD | TD | TD |

ICMP overlay for `RecordedEgress` plus a type-dependent policy:

| Hit family | K/F/A | K/F/N | K/R/A | K/R/N | U/F/A | U/F/N | U/R/A | U/R/N |
|---|---|---|---|---|---|---|---|---|
| Forward hit | ICMP-FC/NR | ICMP-FC/NR | ICMP-FC/NR | ICMP-FC/NR | ICMP-FC/NR | ICMP-FC/NR | ICMP-FC/NR | ICMP-FC/NR |
| Reverse hit | ICMP-RF/FC/NR | ICMP-RF/FC/NR | ICMP-RF/FC/NR | ICMP-RF/FC/NR | ICMP-RF/FC/NR | ICMP-RF/FC/NR | ICMP-RF/FC/NR | ICMP-RF/FC/NR |

`ICMP-FC/NR` means a now-local forward hit revokes/drops, while a still
non-local redirect remains non-authorizing. `ICMP-RF/FC/NR` means a valid
forward companion is pair-fail-closed when local, an absent/unresolvable
companion is fail-closed, and a still-non-local redirect remains non-authorizing.

## 6. Corrected review questions and premises

### Q1 — Does activation collection cover every session?

No. `collect_refresh_owner_rgs_items` currently skips
`owner_rg_id <= 0 && !fabric_ingress` before origin inspection
(`refresh_owner_rgs.rs:137-140`). Harden it to include all peer-synced rows;
the packet-time fence still closes the window before a command is applied.

### Q2 — Are cross-worker materialization and fanout sufficient?

Materialization is receiver-local and resets policy validation to generation
zero through `upsert_synced_with_origin`; `SyncedSessionEntry` carries no policy
stamp. Refresh fanout reaches live worker queues and records transition debt.
This proves eventual reset/materialization behavior only, not safety before a
queued command drains. The packet-time fence closes that stronger requirement.

### Q3 — Does accepted upsert preserve a stamp?

No. That premise was false. Accepted upsert removes and reconstructs the entry,
initializing `policy_revalidated_gen` to zero. Only a rejected local overwrite
leaves an existing local entry unchanged, which is a local-verdict case.

### Q4 — Is the skipped demote refresh safe?

Only as a non-forwarding/liveness behavior. A skipped row must not be described
as carrying a necessarily genuine live verdict. A1/A2 and the packet-time fence
must land atomically; after a later local candidate appears, LF/RF forces live
judgment regardless of whether demote/refresh completed.

### Q5 — Is the origin taxonomy airtight?

No, and the fix must not require it to be. The ten variants include three
peer-synced origins, but only SyncImport and SharedMaterialize are promotable;
WorkerLocalImport is peer-synced but non-promotable. SharedPromote is local
post-promotion. TunOrigin is explicitly self-originated and excluded from
ordinary transit policy. The packet-time provenance fence covers all variants.

### Q6 — Is the hot-path A1 cost claim accurate?

No. Current production `update_session` reach is promotion-only; ordinary
per-packet liveness uses `session/lookup.rs`. Remove the claim that A1 adds a
steady-state per-packet branch. A2 may cause bounded cold revalidation after a
transition. Keep smoke/failover validation as behavioral/performance evidence,
not as proof of a nonexistent steady-state branch.

### Q7 — Is same-generation FIB flap in scope?

No. A generic stale LIVE-verdict/FIB-change residual remains a separate #8356
question. The #10507 counterexamples require no FIB change, so this exclusion
cannot be used to dismiss them.

## 7. Full nine-cell regression matrix

Every security cell must establish a real M2 Permit first, using the actual
poll path, and assert the observable forwarding or revocation outcome. A test
that only inspects a cleared field is insufficient. Each security cell gets a
RED-on-revert run with the packet-time fence reverted. The implementing lane
must run the full affected test files, not only the expected-to-flip test.

1. **Existing command-driven forward path, hardened.** Standby SyncImport with
   diverged recorded/live egress: real M2 recorded Permit, then activation
   Refresh and a next packet without a generation publish. Assert live Deny
   revokes and no packet forwards. Also run the unchanged-generation hit-driven
   promotion case and assert the same outcome on the promoting packet. Repeat
   the forward case with a type-dependent ICMP policy: recorded plus now-local
   must revoke/drop rather than take the old ICMP `None`/Decline exit.
2. **Collector skip and inclusion control.** Use owner RG zero with
   fabric-ingress false and a peer-synced row; prove packet-time LF/FC protects
   it before Refresh. Pair it with owner RG zero plus fabric-ingress true to pin
   inclusion in the hardened collector and retain non-local redirect behavior.
3. **WorkerLocalImport bounded-queue flap.** Keep config generation and FIB
   fixed. Put transition commands behind at least two 256-command slices; send
   packets between slices while runtime has changed. A non-promotable
   WorkerLocalImport must never forward on its recorded Permit. RED on revert.
4. **Lease expiry and active-to-active renewal.** Let the forwarding lease
   expire without an active-boolean edge, exercise the recorded standby path,
   renew active state, and send the first packet after renewal. No activation
   command may be required for LF/RF to force current policy. RED on revert.
5. **Applied demote, standby restamp, re-promote, and skipped refresh.** Cover
   applied demotion followed by a standby recorded Permit and re-promotion;
   verify A1/A2 clear only as defense while PF supplies authority. Separately
   cover HAInactive and TableUnavailable refresh skips and assert no local
   forwarding from their stale recorded stamps. RED on revert.
**TableUnavailable waiver (Main-granted, redundancy-by-construction).**
No independent TableUnavailable M2 cell is added: `PolicyGateCurrent::NonLocal`
is a SINGLE variant fed by a wildcard (`policy_gate_current_for_resolution`
`_ => NonLocal`, covering HAInactive, TableUnavailable, NoRoute,
FabricRedirect, LocalDelivery, PolicyDenied, DiscardRoute,
NextTableUnsupported with no per-disposition branches), so HAInactive and
TableUnavailable produce BIT-IDENTICAL gate answers for equal (gen,kind)
(force/fail false → Fresh coasts, Stale cold Declines stand). The skip guard
is likewise ONE shared `!matches!(HAInactive|TableUnavailable)` condition
around a SINGLE skipped `refresh_for_ha_transition` call
(`refresh_owner_rgs.rs`, `demote_owner_rgs.rs`); kind preservation holds by
construction (skipped call touches nothing) with no per-arm kind path to
diverge. Coverage rides on HAInactive skip+retention (Cell 5b, GREEN),
NoRoute retention (Cell 7b poll + #9513, GREEN), gate NonLocal units
(Fresh-Live/Recorded + NonLocal coast, GREEN), and existing #9752 terminal
re-resolution pins (stamped+empty → TableUnavailable, GREEN).
SELF-INVALIDATING: if you add a TableUnavailable-specific arm anywhere in
gate/skip/retention, you MUST add Cell 5c proving it — this waiver dies the
moment the unity breaks.
6. **Reverse-first/reverse-only promotion.** Store a FabricRedirect forward
   companion with recorded Permit, switch HA state, and deliver a production
   reverse hit before Refresh is applied. Resolve the current forward egress;
   assert live Deny revokes both entries and the reverse packet is not forwarded.
   If the companion cannot resolve, assert fail-closed rather than Decline.
   Repeat with a type-dependent ICMP policy: recorded plus now-local must
   pair-fail-closed before the reverse ICMP `None`/Decline exit. RED on revert.
7. **FabricPuntSeed and standby lookup-failure guards.** A permitted
   FabricPuntSeed must continue to admit the peer return while it remains a
   fabric redirect, across activation/flap transitions, with asserts that no
   recorded transport Permit authorizes local forwarding. Preserve the
   `egress_ifindex == 0` standby retention/no-revoke behavior. RED on revert for
   any accidental local-forward path.
8. **Shared materialization/re-import.** After a recorded Permit, materialize
   and accepted-reimport the shared row on another worker. Assert its policy
   stamp/provenance starts unvalidated and the first packet gets a live policy
   result. Include a rejected local overwrite control showing local state is not
   clobbered. RED on revert if a remote stamp is trusted.
9. **Already-owned unrelated activation.** A locally-owned live Permit survives
   an unrelated RG activation with stable forwarding/revocation behavior. A2
   may cause one cold re-judge, but the test asserts the observable verdict,
   not an implementation field. RED is not expected for this guard-only cell.

Lock-step test doubles:

- `reference_refresh_for_ha_transition` must mirror any A2 stamp/provenance
  semantics.
- `reference_update_session` must mirror A1 promotion semantics.
- Extend `entries_equiv` to compare policy generation and provenance; current
  equality checks omit `policy_revalidated_gen`, so differential parity alone
  cannot establish this security property.

## 8. Verification and implementation contract

Production implementation must remain Rust-only and issue-scoped. Use the
actual package name and manifest:

`cargo test --manifest-path userspace-dp/Cargo.toml -p xpf-userspace-dp`

Run the complete affected test files/modules, including session policy stamp
lifecycle, real poll-descriptor revocation, HA queue/transition tests, and
FabricPuntSeed tests. Do not run only the expected-to-flip cell. Demonstrate
RED-on-revert for the security cells using the same real-M2 tests. Run the
behavioral HA smoke/failover validation required by the parent lane; the lane
must not claim it proves a steady-state A1 branch.

No Go code, wire-format field, ProtocolVersion bump, cluster/incus command, or
external provider API is required by this design. No PR is opened on the
DESIGN path. Parent/next lane performs delta review before any production edit.

## 9. STEP-0 and review close-out

- Issue #10507 is OPEN with zero comments.
- The source chain and all matching stamp/transition sites were searched at
  `5049e78c9`; the rs-only blast count is 45 files / 158 matches.
- PlanA and PlanB both found v1 PLAN-NEEDS-MAJOR; their blocking counterexamples
  are now addressed by the packet-time provenance fence, reverse-companion
  live-resolution requirement, exhaustive origin/owner/direction/command table,
  corrected upsert/reachability/package premises, and nine-cell matrix.
- No production code is changed. This DRAFT v2 is ready for delta re-review,
  not for mechanical implementation without approval.
