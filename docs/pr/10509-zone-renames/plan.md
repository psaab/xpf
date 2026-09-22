# DRAFT v2 cluster plan: zone-rename trio (#10509, #10510, #10511)

Status: DRAFT v2 after hostile round-1 review and parent adjudication.
Base: `2781465ee` (docs: correct session-sync contract documentation, #10508).
Worktree: `.claude/worktrees/10509-zonerenames`, branch `fix/10509-zone-renames`.
Lane: Wave-4 cluster lane, SERIAL route; one plan lane avoids shared transport
and invalidation conflicts. No production code is included in this plan.

## 0. Round-1 verdicts and gate

- **#10509: PLAN-NEEDS-MINOR.** The measurement-first path is retained, but
  the verdict statement and harness are corrected: Foreign is deterministic;
  Drop is conditional. Stage A is measurement/pinning only. Stage B remains
  deferred until the measured shape matrix is reviewed.
- **#10510: PLAN-NEEDS-MAJOR.** Option A (bare positional-index binding) is
  rejected as skew-unsafe. Option B is selected with the complete
  sync-derived-origin discriminator, an explicit old/new zone-diff descriptor,
  purge-wins ordering, and split owner-absent/failover tests.
- **#10511: CONDITIONAL-KILL CLEARED BY SOURCE PROOF; PLAN-NEEDS-MAJOR.** The
  three kill-class questions are answered below: a viable Go evaluator already
  exists, false rename classification is prevented by explicit Rename ancestry
  plus resolved-fingerprint validation, and capture/id-0/bulk cost are scoped.
  If Rename ancestry cannot be threaded through the existing commit/snapshot
  boundary, this leg becomes PLAN-KILL rather than falling back to a
  content-only classifier.

STEP-0 source evidence is complete. The merged-PR cache query
`pr://psaab/xpf?state=merged&limit=100` returned recent merged work (#10558
through #10377) and no merged #10509, #10510, or #10511 fix; the three issue
pages remain OPEN. The local base search was also scoped to the pre-plan base
`2781465ee`, not the plan commit itself.

## 1. Per-issue problem and STEP-0 evidence

All three issue pages are OPEN and carry validated-by-research (3/3 MATERIAL,
Low), pinned `b71c52d6`. The evidence below was read from source at the base.

### 1.1 #10509 — commit-window transient foreign classification

**Corrected problem statement.** A zone rename changes the live arrival
`StableZoneID` (pure name hash), while an existing session still records the
old `metadata.ingress_zone`. Therefore `session_hit_authority` deterministically
returns `Foreign` during the transition. **Drop is conditional, not
unavoidable:** `foreign_hit_verdict` re-evaluates the live pair
`(arrival_zone, recorded egress_zone)`. A single-zone rename with an unchanged
egress zone and an equivalent permit commonly returns `Forward`; a dead pair,
default-deny, or another verdict-changing shape returns `Drop`. The stale row
is not repaired by this Foreign path. The issue is the bounded, deterministic
commit-window Foreign classification and its conditional packet impact; the
retracted claim was a life-of-session outage.

Evidence:

| Claim | Source |
|---|---|
| Stable id is a pure FNV-1a name hash | `pkg/config/zoneid.go:38-44` |
| live arrival id is compared with recorded ingress id | `userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:139-167` |
| Foreign verdict evaluates arrival zone against recorded egress zone | same file `:259-298` |
| only the non-permit result reaches Drop; Revoke is later and gated | same file `:299-325` |
| drop is counted in the packet dispatch | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1278-1284` |
| counter storage | `userspace-dp/src/afxdp/types/runtime.rs:691` |
| every hit refreshes `last_seen_ns` | `userspace-dp/src/session/lookup.rs:263-268` |

**Blast radius.** Rust per-packet hit classification, cluster-wide, during
the interval before the commit invalidation sweep or session end. Depending on
shape, packets either forward under the Foreign verdict or drop; the stale row
can remain live because hit refresh updates `last_seen`. This is Low severity
and is not evidence that every rename drops traffic.

### 1.2 #10510 — first-policy id-0 synced rows survive in bounded HA subsets

Synced sessions admitted by literal first policy id 0 can survive with stale
recorded zones when the owner cannot purge them. M1 deliberately skips id 0
because wire zero is overloaded; #9526's Rust purge matches only a bound
`policy_counter`, but SyncImport sets that handle to `None` and
`reresolve_session_policy_id` retains the frozen stamped id for an unbound row.
Promotion retags the row to `SharedPromote` while preserving the unbound
metadata, so a SyncImport-only purge would miss the target. Foreign handling
then silently drops or forwards per the live pair while `last_seen` keeps the
row alive. The affected cases are owner-down/partition/crash and
failover-before-rename where the ex-owner's close is correctly filtered. A
normal two-node owner rename is already covered by bound purge plus close
sync.

Evidence:

| Claim | Source |
|---|---|
| M1 skips overloaded id 0 | `pkg/daemon/daemon_policy_invalidate.go:37-66,93-117` |
| #9526 recognizes delete/rename by stable rule disappearance | `userspace-dp/src/afxdp/session_glue/mod.rs:655-678` |
| #9526 purge requires a bound counter handle and skips reverse rows | same file `:680-718` |
| SyncImport carries the index but installs no counter handle | `userspace-dp/src/server/helpers/session_sync.rs:477-485` |
| unbound reresolve keeps the frozen id | `userspace-dp/src/policy.rs:1801-1818` |
| promotion retags to SharedPromote and republishes | `userspace-dp/src/afxdp/session_glue/promote.rs:94-151` |
| peer-synced and promotable-origin predicates | `userspace-dp/src/session/entry.rs:466-486` |
| sync-derived family includes peer-synced or SharedPromote | `userspace-dp/src/afxdp/shared_ops.rs:225-243` |
| per-hit idle refresh | `userspace-dp/src/session/lookup.rs:263-268` |
| demoted-owner eligibility and close walk | `pkg/daemon/daemon_ha_userspace_stream.go:133-141,914-985` |

**Corrected blast radius.** HA sync plus Rust rotation purge, limited to
owner-absent and failover-before-rename subsets. Packets can be Foreign and
silently Drop (or Forward when the live pair permits); the stale row itself
persists under refreshed `last_seen` until idle/GC. This is not a claim that
all id-0 rows are policy rows or that every row is swept.

### 1.3 #10511 — extensive rematch tears down renamed policies

`StablePolicyRuleID` embeds policy name, so a policy or zone rename removes the
old stable key and appears as delete plus add. `deletedPolicyRuntimeIDs` adds
old nonzero ids without a rematch gate; `changedPolicyRuntimeIDs` intentionally
skips absent keys; `clearSessionsForDeletedPolicies` then tears down
unconditionally. Under `policy-rematch extensive`, Junos retains a session
when the post-rename policy set still permits it through another rule. xpf's
default and plain-rematch teardown behavior is correct and must remain
unchanged; only the extensive retain arm is in scope.

Evidence:

| Claim | Source |
|---|---|
| stable key contains from-zone, to-zone, and name | `pkg/dataplane/userspace/policies_ids.go:107-110` |
| deleted set has no rematch gate and excludes id 0 | `pkg/daemon/daemon_policy_invalidate.go:93-117` |
| deleted sessions are cleared unconditionally | same file `:154-167` |
| changed set skips absent/deleted keys | same file `:631-666` |
| extensive fingerprints are built for common stable keys only | same file `:643-655,720-746` |
| Foreign dispatch precedes Owner revalidation | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:794-806,1249-1284` |

**Blast radius.** Go commit invalidation for extensive-mode deployments on
rename, plus the Rust first-policy rotation leg when id 0 is involved. Without
the new explicit ancestry contract, non-rename delete/add changes remain on
the current teardown path. Severity is Low availability/parity, not a global
teardown correctness defect.

## 2. Coupling, separation, and shippability

### 2.1 Shared root and actual shared boundaries

Both zone ids and policy rule ids are name-derived. There is currently no
per-object old-to-new rename-continuity link, although a coarse commit epoch
already exists (`ConfigSnapshot.generation`, session/flow generation stamps).
The missing link manifests in three different consumers:

1. Rust hit authority compares a live zone id with a recorded zone id (#10509).
2. Go commit invalidation and Rust first-policy rotation handle delete-plus-add
   rows differently (#10510).
3. Go extensive rematch has no way to distinguish an explicit rename from a
   delete plus add (#10511).

The shared **transport boundary** is real, not an assertion that Go and Rust
can call one function: the existing commit-to-snapshot path must carry a
validated rename descriptor and the extensive gate. The shared **behavioral
classifier** is a cross-language semantic contract, not one source-level
function.

### 2.2 Independent slices

| Leg | Can ship alone? | Shared prerequisite | Safe fallback |
|---|---|---|---|
| #10509 Stage A measurement/pin | Yes; no production behavior change | none | no dataplane change |
| #10509 Stage B shrink | Yes after Stage A, but deferred | optional rename-map/epoch transport | accept bounded Foreign window |
| #10510 Option B | Yes after additive rename descriptor reaches Rust snapshot | descriptor + sync-derived origin gate | old helper behavior for snapshots without descriptor |
| #10511 Go extensive retain | Yes after explicit ancestry/capture transport | descriptor, capture rework, Go evaluator | delete teardown for unproven changes |
| #10511 Rust id-0 arm | Yes with #10510 descriptor and extensive bit | same additive snapshot fields | current bound-only first-policy purge |

The lane remains serial because #10510 and #10511 touch the same descriptor,
capture, and first-policy rotation boundaries. They are still per-leg
shippable: Stage A first; then the additive descriptor transport; then #10510
purge; then #10511 retain/evaluator; finally joint tests. #10511 is not allowed
to weaken #10510's unbound id-0 safety.

### 2.3 Revised cross-language contract

**C1 — single provenance source, dual consumers.** Do not require one function
across Go and Rust. The configstore `RenameAsPlantClass` operation has an
unambiguous mutation boundary (`pkg/configstore/store_command.go:292-324`),
so it can record source/destination ancestry in the candidate commit. Go validates
that ancestry against old/new policy objects and emits an additive
`RenameDescriptor` in the config snapshot/apply event. Go invalidation and Rust
rotation both consume that descriptor. If an input was produced by generic
set/delete or ancestry is missing, it is not a rename for retention purposes.
The descriptor's normalized schema and an equivalence corpus are the semantic
contract; no second content-only detector is permitted.

**C2 — post-fix eligibility partition, purge-wins for unsafe rows.** The
partition is evaluated in this order:

1. An unbound, sync-derived, forward id-0 row whose old zones are covered by a
   validated descriptor is purged by #10510. It is never retained merely
   because a broad extensive evaluator would find a permit.
2. A bound row carrying a validated renamed policy id is re-evaluated only
   when both `PolicyRematch` and `PolicyRematchExtensive` are enabled. A permit
   retains it; a non-permit uses the existing companion-aware teardown.
3. Default mode, plain rematch, ambiguous ancestry, and non-renames use the
   existing deletion path.

This is a **post-fix** invariant. It intentionally excludes unbound overloaded
zero rows from extensive retention because they lack an admitting-rule
identity; this is what prevents a later delete from missing stale state and
prevents a false purge of unrelated zero populations.

## 3. Design per issue

### 3.1 #10509 — Stage A measurement first

No mechanism change is selected before measurement. The harness must emulate
the existing commit-window boundary: publish the new forwarding snapshot,
record the rename timestamp, then invoke the same invalidation/sweep boundary
used by M1 after a controlled, measured delay. The window ends at that sweep
or at session termination, **not** when `reresolve_session_policy_id` runs;
that function changes policy id only, and Foreign rows do not enter the
Owner-only next-packet revalidation path.

The Stage-A shape matrix is mandatory:

| Shape | Expected authority/verdict before sweep | Expected drop oracle |
|---|---|---|
| single-zone rename, egress unchanged, equivalent permit | Foreign, then Forward | zero drops; proves Foreign is not synonymous with Drop |
| single-zone rename, egress unchanged, default deny or no permit | Foreign, then Drop | positive conditional-drop cell |
| multi-zone rename, recorded egress id dead, default deny | Foreign, then Drop | positive dead-pair control |
| multi-zone rename, recorded egress id dead, default permit | Foreign, then Forward | zero-drop default-policy variant |

For every row, count packets, distinct affected sessions, and
`foreign_authority_drops` until the sweep-emulated boundary. Report the
observed max and distribution per shape, then decide shrink-vs-accept with
reviewers. The positive dead-pair cell must observe at least one drop before
any upper-bound assertion; it prevents a measured maximum of zero from making
the RED cell vacuous.

Stage B remains deferred:

- **Option 1, restamp:** use the validated descriptor to rewrite old zone ids
  at rotation. Risk: accidentally converts a genuine re-zone into Owner and
  bypasses #9384 revocation.
- **Option 2, epoch-aware authority:** use the existing coarse generation plus
  a per-object descriptor; HA wire coherence and old-helper defaults are
  required. This is larger than Stage A.
- **Option 3, accept + pin:** keep the bounded Foreign window and publish the
  measured shape-specific bound. This is the default recommendation unless
  Stage A shows operationally material drops.

### 3.2 #10510 — Option B selected; Option A killed

**Option A is rejected for this plan.** `policy_counter_idx` is positional in
the sender's rule table. The policy source warning at
`userspace-dp/src/policy.rs:1738-1762` states that resolving it against the
current table after insertion/reorder can misattribute the session. The sync
wire carries install generation, policy id, and counter index
(`userspace-dp/src/protocol/control.rs:976-1004`), but not a sender config
generation or stable rule id. A bare receiver-side bind is therefore
skew-unsafe. A future Option A would require an additive stable rule id or
sender config generation plus an explicit None fallback; that is not this
cluster's implementation.

**Option B discriminator.** Extend the #9526 rotation purge to accept the
validated old/new zone descriptor and match only all of:

- `metadata.policy_counter.is_none()`;
- forward half (`!metadata.is_reverse`);
- stamped policy id is the overloaded first-policy value 0;
- `origin.is_peer_synced() || origin == SessionOrigin::SharedPromote` (the
  existing `sync_derived` family);
- recorded ingress/egress zones are the old ids in the descriptor's zone map.

The descriptor is produced from explicit Rename ancestry and validated against
the old/new policy snapshots. If the zone mapping is absent or ambiguous, no
new overloaded-zero sweep is attempted. The purge runs before any extensive
retention decision, enforcing C2.

Producer enumeration and negative controls are explicit. The sync-derived
family includes `SyncImport`, `SharedMaterialize`, `WorkerLocalImport`, and
`SharedPromote`; promotion specifically retags `SyncImport` to
`SharedPromote`. Other origins are `ForwardFlow`, `ReverseFlow`, `LocalMiss`,
`MissingNeighborSeed`, `FabricPuntSeed`, and `TunOrigin`
(`userspace-dp/src/session/entry.rs:402-440`). The unbound gate excludes
locally bound demote-flipped replicas; origin- and zone-negative tests cover
all of these variants, plus legacy/old-peer rows. The demoted-owner close
filter remains unchanged; receiver/rotation ownership is the fix.

Additive snapshot/apply fields carry the descriptor and
`policy_rematch_extensive` to Rust. Old helpers decode empty/false and retain
today's behavior, while new peers receive the validated map. No cluster
command or external API is required.

### 3.3 #10511 — explicit ancestry, evaluator, capture, and id-0 scope

#### Rename classification is provenance-first and false-rename safe

A content-only deleted-key/added-key matcher is not sound: a delete plus add
of one of two identical policies is indistinguishable from a name rename when
only snapshots are compared. Therefore the detector does **not** infer intent
from a single equal fingerprint. `Store.RenameAsPlantClass` already receives
source and destination paths while holding the candidate lock
(`pkg/configstore/store_command.go:292-324`); add a candidate ancestry record
there and carry it through commit to the daemon/snapshot descriptor.

Validation rules:

1. Expand each explicit source/destination ancestry record to the affected
   stable policy keys in old/new configs.
2. Require a one-to-one ancestry mapping. Overlapping moves, A→B→A chains
   that do not normalize to one final mapping, and duplicate destinations are
   ambiguous and fall back to deletion.
3. Compute a verdict-only **resolved fingerprint** for each mapped old/new
   policy: resolved source/destination address prefixes, application terms,
   action, scheduler binding/effective state, protocol/port terms, and all
   other runtime verdict fields; strip identity-only from-zone, to-zone, name,
   and runtime id fields before hashing. The existing
   `PolicyResolvedFingerprints` implementation proves that resolved addresses
   and application expansions are available (`pkg/dataplane/userspace/policies_resolved_fingerprint.go:13-75`),
   but its identity-bearing whole snapshot hash is not used directly.
4. A fingerprint mismatch, a missing old/new rule, or a one-to-many/many-to-one
   expansion is not a rename and uses existing teardown. Generic
   set/delete/add commits carry no ancestry and always use this safe fallback.

This makes the single-duplicate false-rename case fail closed: only an
explicit Rename operation can nominate it, and the resolved-fingerprint and
one-to-one checks can still reject it. A true explicit zone/policy rename is
not lost to duplicate content. Bulk zone rename cost is one ancestry expansion
plus one old/new policy pass and hash-index lookup: O(P + R + S) time and
O(P + R) temporary memory for P policy slots, R rename records, and S captured
sessions; no deleted-by-added quadratic scan.

#### Go evaluator is the selected implementation

`pkg/policymatch.Match` is already the Go simulator with the runtime's exact
precedence: exact pair, merged single wildcard, both-any, global scope, and
default (`pkg/policymatch/policymatch.go:1059-1075,1243-1344`). It already
threads scheduler fail-closed state with `PolicyInactiveFn`
(`:330-351`) and ICMP type/code semantics (`:266-279`). A new helper uses the
same commit-time scheduler maps already computed in
`daemon_policy_invalidate.go:209-214`.

The captured query contract is explicit:

- forward rows are evaluated once; reverse rows use their canonical forward
  companion;
- source remains the original session source, while destination and port use
  the captured DNAT rewrite when present, matching the Rust Foreign evaluator
  (`session_hit_authority.rs:274-295`);
- `SessionValue` carries NAT source/destination addresses and ports
  (`pkg/dataplane/bpf_session_value.go:99-103,170-173`); NPTv6 has no per-row
  rewrite field, so the original tuple is used and pinned in parity tests;
- session-sync rows carry no ICMP type/code, so Query leaves these nil. The
  existing Go evaluator fails closed for type-constrained terms when nil,
  matching runtime `packet_icmp = None`;
- established-session rows are queried as L4-present/non-first-fragment;
  global/wildcard/default and scheduler gates remain in the existing evaluator.

The parity corpus extends `testdata/policy_verdict_corpus.txt` and the existing
`pkg/policymatch/policy_verdict_corpus_9167_test.go` with NAT, NPTv6,
ICMP-unknown, scheduler, global, wildcard, duplicate, and default cases. Go
asserts the retained/deleted decision; Rust or a joint harness asserts that a
retained session still forwards. A new Rust RPC is not required.

#### Capture and id-0 extensive rework

`policyInvalidationCapture` gains a pre-publication `renamed` descriptor map
alongside deleted/modified sets. The capture remains old-numbering based
(#6948), enumerates each affected forward row once, and sends only the rows
that fail the extensive re-evaluation to the existing companion-aware delete
and HA delete-sync path. This avoids post-publication id contamination.

The Go deleted-id set continues to exclude id 0. The additive snapshot fields
carry `policy_rematch_extensive` and the first-policy rename descriptor to the
Rust worker. On rotation:

1. Option B purges unbound sync-derived id-0 rows first.
2. For a bound first-policy row and an explicit rename under extensive mode,
   Rust re-evaluates the row against the new forwarding policy using its
   existing policy evaluator; permit retains, non-permit invokes the existing
   full-pair purge. With extensive off, the current unconditional #9526 purge
   remains unchanged.
3. Thus the #10511 extensive-retain oracle covers id 0 without asking Go to
   infer a bound handle from an overloaded wire scalar.

The Rust rotation walk is one session-table pass. The Go capture is one
session-table pass plus the O(P+R) descriptor index. This is the specified
bulk cost for a zone rename affecting many policy keys.

## 4. Contracts and invariants

### Cross-language contracts

- **C1 provenance transport:** configstore Rename ancestry is the only source
  of rename intent; Go validates and serializes a descriptor; Go and Rust
  consume that descriptor. No content-only detector and no impossible
  cross-language shared function.
- **C2 post-fix partition:** purge unsafe unbound id-0 sync-derived rows first;
  retain only bound rows re-permitted by extensive evaluation; otherwise use
  existing teardown. Ambiguous/no-ancestry changes are deletes.
- **C3 teardown reuse:** every purge/deletion arm uses the existing
  companion-aware delete and HA delete-sync (#2468), including Rust id-0.
- **C4 capture coherence:** descriptor and old ids are captured before
  publication, alongside deleted/modified capture, so old numbering cannot be
  contaminated by live-row refresh.
- **C5 compatibility:** additive descriptor/extensive fields default empty/false
  for old peers/helpers; no old wire row is rebound from a positional index.

### Invariants

- I1 default and plain-rematch rename teardown is unchanged.
- I2 overloaded wire-zero host-local, neighbor-seed, fabric, tunnel, legacy,
  and non-sync local rows are never swept by the first-policy purge.
- I3 a genuine interface re-zone still reaches Foreign and #9384 revoke; no
  #10509 Stage-B option may convert genuine Foreign to Owner.
- I4 demoted-owner close emission remains filtered by owner RG; receiver-side
  purge/rebind owns #10510.
- I5 old-peer rows lacking descriptor, sender config epoch, stable rule id, or
  ICMP type retain today's safe behavior.
- I6 extensive retention never leaves an unbound stale id-0 row or stale zone
  stamp that a later deletion cannot target.
- I7 explicit Rename ancestry with changed verdict content, duplicate/ambiguous
  expansion, or missing capture falls back to teardown (fail closed).

## 5. Risks and mitigations

- **R1 wrong authority shrink (#10509):** restamp/epoch could mask a genuine
  re-zone. Stage B is deferred; any candidate must keep #9519/#9384 controls.
- **R2 vacuous measurement:** a single-zone permit has zero drops. The dead-pair
  positive control and shape matrix require a reachable positive cell first.
- **R3 id-0 overreach (#10510):** origin + unbound + zero + old-zone descriptor
  gates and exhaustive negative origins prevent sweeping overloaded zero rows.
- **R4 positional misbind (#10510-A):** killed in this plan; no bare
  `policy_counter_idx` resolution is permitted.
- **R5 ancestry transport loss (#10511):** missing/ambiguous provenance falls
  back to delete; if the descriptor cannot cross the commit/snapshot boundary,
  #10511 is PLAN-KILL rather than content inference.
- **R6 evaluator parity (#10511):** Go evaluator is already the maintained
  parity simulator; corpus adds NAT, NPTv6, scheduler, ICMP-unknown, and tier
  cases, and Rust forwarding is asserted separately.
- **R7 stale retain:** purge-wins unbound ordering plus bound-id re-resolution
  prevents a later delete from missing retained state.
- **R8 bulk commit cost:** O(P+R+S), one indexed pass per side; no pairwise
  deleted×added comparison and no second full sweep.

## 6. Test plan and RED cells

No tests are run on the design path. Implementers must run the full affected
file/module, not only the expected-to-flip cell, and record RED-on-revert
firsthand for each issue.

### #10509

- Full authority module: `userspace-dp/src/afxdp/poll_descriptor/session_hit_authority_tests.rs`
  plus affected packet-dispatch tests.
- Stage-A harness matrix above; assert the dead-pair control observes
  `foreign_authority_drops > 0` before sweep emulation, then assert the
  measured upper bound. The single-zone permit control asserts Foreign with
  Forward and zero drops. RED-on-revert: removing the drop accounting or
  changing the conditional verdict fails the positive cell; setting the bound
  to observed-max minus one is valid only after the positive cell proves
  observed-max > 0.
- Sweep emulation asserts packets after the boundary no longer count against
  the rename window, while the stale-row/last-seen control proves the window
  is not falsely ended by policy-id refresh.

### #10510

- Full Rust first-policy files: `deleted_first_policy_purge_9526_tests.rs`
  and `worker/loop_body/first_policy_purge_rotation_9526_tests.rs`; full Go
  `userspace_sync_test.go` for the owner-RG close controls.
- Owner-absent rename: promoted `SharedPromote`, unbound, stamped id-0 row
  with old zones is purged; RED-on-revert leaves it alive. Failover-before-
  rename: demoted ex-owner close remains n=0 while receiver rotation purges or
  repairs the row; RED-on-revert leaves the survivor.
- Negative controls enumerate all origins in `SessionOrigin`, old/legacy peer
  rows, nonzero policy ids, reverse halves, bound rows, and zone pairs outside
  the descriptor. None may be removed by Option B. A separate test pins that
  Option A's bare positional index is rejected/does not bind under skew.

### #10511

- Full Go invalidation/rematch files: `daemon_policy_invalidate_test.go`,
  `daemon_policy_rematch_extensive_8993_test.go`, and
  `policy_reused_id_overclear_6948_test.go`.
- Explicit ancestry + extensive + alternate permit: capture re-evaluates and
  retains the bound renamed session. RED-on-revert tears it down. Go asserts
  the retain/delete decision; the Rust/joint forwarding cell asserts the
  retained packet forwards.
- Full negative matrix: default mode teardown, plain-rematch teardown,
  extensive with no alternate permit, generic delete+add with no ancestry,
  two identical policies with ambiguous ancestry, resolved-fingerprint change,
  scheduler active-to-inactive in the same commit, NAT destination rewrite,
  NPTv6, unknown ICMP type, and global/wildcard tiers.
- First-policy id-0 extensive: bound row is re-evaluated in Rust and retained
  only on permit; unbound sync-derived row is purged first. RED-on-revert
  covers both the Rust gate and Go capture partition.
- Full Rust worker rotation module is required after the id-0 arm changes; no
  single-test-only acceptance.

### Joint regression

One HA fixture covers explicit zone/policy ancestry, snapshot descriptor,
owner-absent promoted id-0, bound alternate permit, and default/plain controls;
it asserts C2's post-fix partition exactly. The fixture also measures the
shape-specific #10509 window without claiming that every Foreign packet drops.

## 7. Open questions, resolved questions, and PLAN-KILL conditions

### Resolved by source for v2

- **10509 measurement:** unresolved by design and intentionally first. The
  matrix makes a zero single-zone result meaningful rather than vacuous.
- **10510 Option A safety:** bare binding is unsafe by the documented
  positional-index warning and is removed from this plan; a future stable-id
  or sender-epoch wire addition is separate work.
- **10510 promotion marker:** no new marker is needed; promotion's
  `SharedPromote` is covered by the existing sync-derived predicate.
- **10511 evaluator:** Go `policymatch.Match` is viable and already implements
  the runtime tier/scheduler/ICMP behavior. Session rows supply NAT fields but
  not ICMP type, so nil is the explicit fail-closed fallback; Rust forwarding
  is a separate oracle.
- **10511 false rename:** snapshot content alone is insufficient. Explicit
  Rename ancestry from `Store.RenameAsPlantClass` is the required provenance;
  resolved identity-stripped fingerprints validate, rather than invent,
  intent. Generic delete+add falls back to teardown.
- **10511 capture/id-0/bulk:** pre-publication `renamed` capture, additive
  extensive/descriptor snapshot fields, Rust bound-id-0 re-evaluation, and
  O(P+R+S) passes are the specified scope.

### Remaining open questions

- **O-10509-1 (PLAN-KILL for Stage B only):** what is the measured packet/session
  bound for each matrix shape? If no shape has a material positive window,
  Stage B is killed and Option 3 accept+pin closes the issue.
- **O-10509-2:** if Stage B is selected, can the descriptor be reused for a
  rotation-local restamp without weakening genuine Foreign/revoke semantics?
- **O-10510-1:** can all supported snapshot producers emit the descriptor with
  old-helper empty defaults? If not, the unsupported producer cohort stays on
  current behavior and is explicitly excluded from acceptance.
- **O-10510-2:** can the full origin/zone negative enumeration be run without
  cluster commands? Existing unit harnesses and `walkUserspaceSessionDeltas`
  probes indicate yes; if not, the owner-absent acceptance leg is PLAN-KILL.
- **O-10511-1 (conditional-KILL):** can Rename ancestry travel from the
  configstore candidate commit through daemon capture and the Rust snapshot
  with bounded additive fields? Source proves the mutation API and existing
  additive serde snapshot pattern. If implementation discovery disproves that
  boundary, concede PLAN-KILL for #10511; do not substitute a content-only
  classifier.
- **O-10511-2:** exact NAT/NPTv6 and ICMP-unknown parity cases must be added to
  the existing corpus before implementation is accepted.
- **O-JOINT-1:** lock the descriptor schema and C2 ordering before either
  #10510 or #10511 production leg lands.

## 8. STEP-0 and review verification record

- First action reported `pwd`, branch `fix/10509-zone-renames`, HEAD
  `2781465ee`, and assigned scope.
- Read all three issue pages and source sections listed in §1.
- Local merged-fix search was scoped to base `2781465ee`; the actual merged-PR
  cache query was `pr://psaab/xpf?state=merged&limit=100`, with no #10509,
  #10510, or #10511 fix present.
- Consistency checks covered every authority callsite, daemon invalidation and
  capture callsite, SyncImport/promotion origin predicate, and first-policy
  purge caller. No production file was edited.
- Round-1 findings folded: corrected Foreign/Drop statement and blast radius;
  shape matrix and sweep-emulated window; SharedPromote discriminator and
  complete origin enumeration; Option A kill; provenance transport replacing
  impossible C1; purge-wins replacing stale retain order; Go evaluator,
  capture/id-0/bulk scope, and split Go/Rust tests for #10511.
