# Cluster plan: zone-rename trio (#10509, #10510, #10511)

Status: IMPLEMENTED in the cluster lane; retain the design gates below as
verification scope for #10509, #10510, and #10511.
Base: `9927bbfa` (current origin/master at implementation start).
Worktree: `.claude/worktrees/10509-zonerenames`, branch `fix/10509-zone-renames`.
Lane: Wave-4 cluster lane, SERIAL route. Production and test changes are included.

## 0. Verdicts and gate

- **#10509: PLAN-NEEDS-MINOR.** Foreign is deterministic but Drop is
  conditional. Stage A remains measurement/pinning only, with the required
  shape matrix, observation window, and non-vacuous positive control.
- **#10510: PLAN-NEEDS-MAJOR.** Bare positional-index binding is killed as
  skew-unsafe. Option B now derives removed zone ids from old/new snapshot
  disappearance, independent of the CLI mutation or HA ancestry.
- **#10511: CONDITIONAL-KILL CLEARED; PLAN-NEEDS-MAJOR before implementation.**
  The evaluator, provenance-first predicate, resolved-fingerprint validation,
  capture/id-0/bulk scope, and the HA ancestry transport are all specified.
  The transport is an additive internal sidecar; if implementation proves the
  sidecar cannot follow the existing ordered config-apply lifecycle, #10511
  becomes PLAN-KILL rather than falling back to content-only inference.

All three issue pages remain the source requirements for this implementation.
The lane was rebased for implementation against `9927bbfa`; the additive
sidecar now follows local and HA config-apply paths, with legacy fallback
gates retained for unknown or incapable peers. This plan records the design
evidence; implementation and scoped proof live in the source and tests.

## 1. Per-issue problem and STEP-0 evidence

All three issues are validated-by-research (3/3 MATERIAL, Low), pinned
`b71c52d6`. Every source location below was read from the base.

### 1.1 #10509 — commit-window Foreign classification, conditional drops

A zone rename changes the live arrival `StableZoneID` (pure name hash), while
an existing session still records the old `metadata.ingress_zone`.
`session_hit_authority` therefore deterministically returns `Foreign` during
the transition. **Drop is conditional, not unavoidable:**
`foreign_hit_verdict` re-evaluates the live pair `(arrival_zone, recorded
egress_zone)`. A single-zone rename with an unchanged egress and equivalent
permit commonly returns `Forward`; a dead pair, default-deny, or other verdict
change returns `Drop`. The stale row is not repaired by this Foreign path. The
retracted claim was a life-of-session outage.

Evidence:

| Claim | Source |
|---|---|
| Stable id is a pure FNV-1a name hash | `pkg/config/zoneid.go:38-44` |
| live arrival id is compared with recorded ingress id | `userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:139-167` |
| Foreign verdict evaluates arrival zone against recorded egress | same file `:259-298` |
| only the non-permit result reaches Drop; Revoke is later and gated | same file `:299-325` |
| drop is counted in packet dispatch | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1278-1284` |
| `may_revoke` is true only for local admitting-interface forward hits | `userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:169-180`; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:794-806` |
| Foreign Drop increments its counter; Revoke tears down and increments policy revocation telemetry | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1277-1284,1312-1342` |
| counter storage | `userspace-dp/src/afxdp/types/runtime.rs:691` |
| every hit refreshes `last_seen_ns` | `userspace-dp/src/session/lookup.rs:263-268` |

**Blast radius:** Rust per-packet hit classification, cluster-wide, from new
snapshot publication until the invalidation sweep or session end. Depending on
shape, packets forward or drop; the stale row can remain live because hit
refresh updates `last_seen`. Low severity; not every rename drops traffic.

### 1.2 #10510 — first-policy id-0 synced rows in bounded HA subsets

Synced sessions admitted by literal first policy id 0 can survive with stale
recorded zones when the owner cannot purge them. M1 deliberately skips id 0
because wire zero is overloaded; #9526's Rust purge matches only a bound
`policy_counter`, but SyncImport sets that handle to `None` and
`reresolve_session_policy_id` retains the frozen stamped id for an unbound row.
Promotion retags the row to `SharedPromote` while preserving unbound metadata,
so a SyncImport-only purge misses the target. Foreign handling then silently
drops or forwards per the live pair while `last_seen` keeps the row alive. The
owner-down/partition/crash and failover-before-rename subsets are affected; a
normal two-node owner rename is already covered by bound purge plus close sync.

Evidence:

| Claim | Source |
|---|---|
| M1 skips overloaded id 0 | `pkg/daemon/daemon_policy_invalidate.go:37-66,93-117` |
| #9526 recognizes delete/rename by stable rule disappearance | `userspace-dp/src/afxdp/session_glue/mod.rs:655-678` |
| #9526 purge requires a bound counter and skips reverse rows | same file `:680-718` |
| SyncImport carries the index but installs no counter handle | `userspace-dp/src/server/helpers/session_sync.rs:477-485` |
| unbound reresolve keeps frozen id | `userspace-dp/src/policy.rs:1801-1818` |
| promotion retags to SharedPromote | `userspace-dp/src/afxdp/session_glue/promote.rs:94-151` |
| peer-synced/promotable-origin predicates | `userspace-dp/src/session/entry.rs:466-486` |
| sync-derived family includes SharedPromote | `userspace-dp/src/afxdp/shared_ops.rs:225-243` |
| per-hit idle refresh | `userspace-dp/src/session/lookup.rs:263-268` |
| demoted-owner eligibility and close walk | `pkg/daemon/daemon_ha_userspace_stream.go:133-141,914-985` |

**Blast radius:** HA sync plus Rust rotation purge, only owner-absent and
failover-before-rename subsets. Packets may be Foreign and silently Drop (or
Forward when the live pair permits); the stale row itself persists under
refreshed `last_seen` until idle/GC. This is not a claim that every id-0 row is
a policy row or that every row is swept.

### 1.3 #10511 — extensive rematch tears down renamed policies

`StablePolicyRuleID` embeds policy name, so a policy or zone rename removes the
old stable key and appears as delete plus add. `deletedPolicyRuntimeIDs` adds
old nonzero ids without a rematch gate; `changedPolicyRuntimeIDs` skips absent
keys; `clearSessionsForDeletedPolicies` tears down unconditionally. Under
`policy-rematch extensive`, Junos retains a session when the post-rename set
still permits through another rule. xpf's default and plain-rematch teardown
behavior is correct and must remain unchanged; only extensive retain is in
scope.

Evidence:

| Claim | Source |
|---|---|
| stable key contains from-zone, to-zone, and name | `pkg/dataplane/userspace/policies_ids.go:107-110` |
| deleted set has no rematch gate and excludes id 0 | `pkg/daemon/daemon_policy_invalidate.go:93-117` |
| deleted sessions clear unconditionally | same file `:154-167` |
| changed set skips absent/deleted keys | same file `:631-666` |
| extensive fingerprints common stable keys only | same file `:643-655,720-746` |
| Foreign dispatch precedes Owner revalidation | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:794-806,1249-1284` |

**Blast radius:** Go commit invalidation for extensive deployments on rename,
plus Rust first-policy rotation when id 0 is involved. Unproven delete/add
changes retain current teardown. Low availability/parity severity.

## 2. Coupling, separation, and shippability

### 2.1 Shared root and boundaries

Zone ids and policy rule ids are name-derived. A coarse commit epoch already
exists (`ConfigSnapshot.generation`, session/flow generation stamps), but no
per-object old-to-new continuity link exists. The missing link reaches three
different consumers:

1. Rust hit authority compares live and recorded zone ids (#10509).
2. Go commit invalidation and Rust first-policy rotation handle delete-plus-add
   rows differently (#10510).
3. Go extensive rematch lacks explicit rename intent (#10511).

The shared boundary is the ordered config/snapshot apply lifecycle, not one
cross-language function. #10510 uses old/new zone state directly. #10511 uses
an ancestry sidecar only where extensive retention needs intent.

### 2.2 Independent slices

| Leg | Can ship alone? | Prerequisite | Safe fallback |
|---|---|---|---|
| #10509 Stage A | Yes; no behavior change | none | no dataplane change |
| #10509 Stage B | Yes after Stage A, deferred | optional map/epoch transport | accept bounded Foreign window |
| #10510 Option B | Yes | sync-derived gate + snapshot zone validation | no purge on invalid/rejected snapshot |
| #10511 Go retain | Yes after sidecar/capture | ancestry sidecar + Go evaluator | delete teardown without ancestry |
| #10511 Rust id-0 arm | Yes with #10510 rotation | extensive bit + ancestry descriptor | current bound-only first-policy purge |

Serial order: Stage A; #10510 old-minus-new zone-set purge; #10511 ancestry
sidecar/capture/evaluator; then joint HA regression. The legs are separately
shippable, but one lane avoids conflicts in rotation/capture boundaries.

### 2.3 Feasible contracts

**C1 — separate state predicates.** #10510 computes
`removed_zone_ids = unique(old_snapshot.zone_ids) - unique(new_snapshot.zone_ids)`
from the actual old/new states immediately before rotation. It never gates
safety on the CLI mutation or HA ancestry. #10511 alone uses explicit
configstore Rename ancestry for extensive retention, carried on local and HA
config-apply paths. Neither requires a cross-language shared function.

**C2 — post-fix partition, purge wins for unsafe rows.**

1. An unbound, sync-derived, forward id-0 row whose recorded ingress OR egress
   zone id is in `removed_zone_ids` is purged by #10510. It is not retained by
   an extensive permit.
2. A bound row carrying a validated #10511 renamed policy id is re-evaluated
   only when both rematch knobs are enabled. Permit retains only after an
   atomic pair rebind/restamp. Go's nonzero capture produces a new numeric
   policy id, stable RuleID, and renamed-zone ids as a rebind record; it never
   transports or stores a Rust Arc. Rust consumes that record and owns the
   matched new rule-counter Arc, updating both Rust `SessionEntry.metadata`
   halves, their conntrack/BPF map values, policy id, counter handle, and
   recorded ingress/egress zones atomically. Rust's id-0 arm resolves the same
   numeric id and Arc in its rotation walk. Non-permit uses existing
   companion-aware teardown.
3. Default, plain rematch, ambiguous ancestry, generic delete/add, and invalid
   or collision-quarantined snapshots use existing teardown or retain the
   previous-good snapshot as appropriate.

This is a post-fix property. Unbound overloaded-zero rows are excluded from
extensive retention because they lack an admitting-rule identity.

## 3. Design per issue

### 3.1 #10509 — Stage A measurement first

No mechanism change is selected before measurement. The harness publishes the
new forwarding snapshot, records the rename timestamp, and invokes the same
invalidation/sweep boundary used by M1 after a controlled measured delay. The
window ends at that sweep or session termination, **not** at
`reresolve_session_policy_id`: that function changes policy id only, and
Foreign rows do not enter the Owner-only next-packet revalidation path.

Required matrix:

| Shape | Origin/half lanes | Verdict before sweep | Accounting oracle |
|---|---|---|---|
| single-zone rename, egress unchanged, equivalent permit | peer-synced forward, reverse companion, local admitting-interface forward | Foreign then Forward | zero Drop and zero Revoke; Foreign is not Drop |
| single-zone rename, egress unchanged, default deny/no permit | peer-synced forward and reverse (Drop lane); local admitting-interface forward (Revoke lane) | Foreign then Drop/Revoke | observe each lane's matching counter before upper bounds |
| multi-zone rename, recorded egress id dead, default deny | peer-synced forward and reverse (Drop lane); local admitting-interface forward (Revoke lane) | Foreign then Drop/Revoke | dead-pair positive in both accounting lanes |
| multi-zone rename, recorded egress id dead, default permit | peer-synced forward, reverse companion, local admitting-interface forward | Foreign then Forward | default-policy zero control for both Drop and Revoke |

Count packets, distinct affected sessions, `foreign_authority_drops`, and
`policy_revoked_sessions` through the observation window. The Drop lane
must use a peer-synced/reverse or non-admitting-interface row, because a local
forward hit on its admitting interface is allowed to Revoke and does not
increment the Drop counter. The dead-pair cell must observe at least one Drop
and at least one Revoke in their respective lanes before upper-bound
assertions, so a single-zone max of zero cannot make the RED cells vacuous.
Stage B options (restamp, per-object epoch, accept+pin) remain deferred;
accept+pin is the default unless measurement is material.

### 3.2 #10510 — Option B from snapshot disappearance; Option A killed

**Option A is rejected.** `policy_counter_idx` is positional and the source
warning says current-table resolution after insertion/reorder can misattribute
sessions (`userspace-dp/src/policy.rs:1738-1762`). The sync wire has install
generation, policy id, and counter index but no sender config generation or
stable rule id (`userspace-dp/src/protocol/control.rs:976-1004`). Bare
receiver binding is skew-unsafe. A future stable-id or sender-epoch wire
addition with None fallback is separate work.

**Option B does not use Rename ancestry.** Immediately before forwarding-state
assignment, derive `removed_zone_ids` from the actual old and new snapshots:

`removed_zone_ids = unique(old_snapshot.zones.ids) - unique(new_snapshot.zones.ids)`

The set is valid only when every old id used in it is unique in the old
snapshot and both snapshots pass duplicate-zone/collision-quarantine
validation. If validation fails, snapshot integrity rejects or retains the
previous-good forwarding state before packet processing; no ambiguous id is
matched. This is the fail-closed control for collisions and works equally for
CLI Rename, generic set/delete/add, config load, or a fixture. It also covers
pure zone deletion, which provenance-only logic would miss.

Extend the #9526 rotation purge and match all of:

- `metadata.policy_counter.is_none()`;
- forward half (`!metadata.is_reverse`);
- stamped policy id is overloaded first-policy value 0;
- `origin.is_peer_synced() || origin == SessionOrigin::SharedPromote` (the
  existing sync-derived family);
- recorded ingress **or** egress zone id is in `removed_zone_ids` and was
  unique in the old snapshot.

The producer set is the complete `SessionOrigin` enumeration: sync-derived
includes `SyncImport`, `SharedMaterialize`, `WorkerLocalImport`, and
`SharedPromote`; other origins are `ForwardFlow`, `ReverseFlow`, `LocalMiss`,
`MissingNeighborSeed`, `FabricPuntSeed`, and `TunOrigin`
(`userspace-dp/src/session/entry.rs:402-440`). The unbound gate excludes
locally bound demote-flipped replicas. No configstore ancestry or positional
bind is added for #10510. The worker may carry `removed_zone_ids` as a
rotation-local value if it receives only precomputed ForwardingState; it is
not operator mutation metadata. Purge runs before #10511 retention.

### 3.3 #10511 — provenance, evaluator, capture, id-0, and HA transport

#### Local rename classification is provenance-first

Snapshot content alone cannot distinguish a delete plus add of one of two
identical policies from a name rename. `Store.RenameAsPlantClass` receives
source/destination paths under the candidate lock
(`pkg/configstore/store_command.go:292-324`), with CLI and gRPC callers
(`pkg/cli/cli_config.go:91-94`, `pkg/grpcapi/server_config.go:181-185` cited by
source review). Add a candidate ancestry record and carry it into commit.

Validation: expand source/destination to stable policy keys; require one-to-one
mapping; reject overlapping moves, unresolved chains, duplicate destinations,
missing rules, or one-to-many/many-to-one expansions. Compute a verdict-only
resolved fingerprint with identity-only from-zone, to-zone, name, and runtime-id
fields stripped. Resolved address prefixes and application terms are already
available (`pkg/dataplane/userspace/policies_resolved_fingerprint.go:13-75`).
A mismatch falls back to teardown. Generic set/delete/add has no ancestry and
falls back to teardown rather than false-retaining a duplicate. Cost is one
ancestry expansion plus one old/new policy pass and hash index: O(P+R+S), no
deleted-by-added quadratic scan.

#### Go evaluator

`pkg/policymatch.Match` already mirrors exact, merged single-wildcard,
both-any, global, and default precedence
(`pkg/policymatch/policymatch.go:1059-1075,1243-1344`), scheduler fail-closed
`PolicyInactiveFn` (`:330-351`), and ICMP fields (`:266-279`). Commit-time
scheduler maps already exist (`pkg/daemon/daemon_policy_invalidate.go:209-214`).

Query contract: evaluate the forward row once and use its canonical companion
for reverse rows; source remains original; captured DNAT destination and port
are used as Rust does (`session_hit_authority.rs:274-295`); SessionValue carries
NAT fields (`pkg/dataplane/bpf_session_value.go:99-103,170-173`); inbound NPTv6
arrives DNAT-shaped (its `rewrite_dst` sets the generic DNAT bit with the
translated dst and no port rewrite), so it rematches through the same
translated-dst path while outbound source translation keeps the original
policy tuple; sync rows lack ICMP type/code, so nil is an explicit fail-closed
query matching runtime `packet_icmp=None`; established rows are
L4-present/non-first-fragment. No new Rust RPC is needed. The shared corpus
covers ICMP-unknown, scheduler-shape-agnostic, global, wildcard, duplicate,
default, and fragment cases in `testdata/policy_verdict_corpus.txt`; NAT and
scheduler TIME shapes are inexpressible in the `q` row grammar (no NAT or time
fields) and are pinned instead by the Go evaluator unit cells, a documented
decision rather than a corpus gap. Go decides retain/delete; Rust/joint tests
forwarding separately.

#### Capture, id-0, retain-rebind, and cost

`policyInvalidationCapture` gains a pre-publication `renamed` descriptor map
alongside deleted/modified sets. It enumerates each affected forward row once
under old numbering and sends failed re-evaluations through existing
companion-aware delete + HA delete-sync. A permitting Go result supplies the
new `PolicyID` and stable `RuleID` (`pkg/policymatch/policymatch.go:746-785`);
the retained pair is re-bound before it can be counted as retained.

For the Go nonzero arm, capture serializes canonical-key plus matched new
numeric policy id, stable RuleID, and remapped-zone rebind records into the
additive snapshot. Rust rotation consumes those records and atomically updates
both Rust `SessionEntry.metadata` halves and their conntrack/BPF map values:
stored `policy_id` becomes the new numeric id, `policy_counter` becomes the
Arc for the permitting new rule, and recorded ingress/egress zones are
changed through the validated rename map. Go never writes a Rust Arc, and this
uses the existing snapshot transport rather than a new RPC. Updating the map
values in the same rotation makes the next Go invalidation match the new id
immediately rather than waiting for periodic refresh.

The Go deleted-id set continues to exclude id 0. Additive snapshot fields carry
`policy_rematch_extensive` and the #10511 first-policy ancestry descriptor to
Rust. On rotation, #10510 first purges unbound sync-derived id-0 rows from the
old-minus-new zone set. For a bound first-policy row and explicit #10511 rename
under extensive, the Rust query runs before assigning the new forwarding state:
it evaluates the forward row's tuple using the new forwarding policy, resolves
arrival ingress from the row's admitting interface and current zone map, and
remaps the recorded egress zone through the validated ancestry map before
evaluation. It uses the row's NAT rewrite and original source/ports, and
passes ICMP type/code as unknown (nil), fail-closed for type-constrained terms.
It evaluates once and uses the canonical reverse companion. A Permit returns
the matched new numeric policy id and counter handle, then atomically
rebinds/restamps both `SessionEntry.metadata` halves, their conntrack/BPF map
values, and renamed zone ids; a non-permit or unresolvable admitting
interface invokes existing full-pair purge. The
evaluator seam is `evaluate_policy_result_without_counting`
(`userspace-dp/src/policy.rs:225-255,2987-3014`). Extensive off preserves
current unconditional #9526 purge. Rust scans sessions once; Go captures once
plus the O(P+R) ancestry index; #10510's zone-set difference is O(Z).

#### HA config-sync ancestry sidecar (required residual closure)

The current HA leg is text-only and must be extended; local ancestry alone is
not enough. Current source chain is:

1. Sender `QueueConfig(configText)` draws a generation and calls
   `encodeConfigPayload(configText, gen)` (`pkg/cluster/sync_conn_config.go:259-275`,
   `pkg/cluster/sync_protocol.go:1070-1088`). Production callers pass text
   only from `pkg/daemon/daemon_ha_sync.go:443-468,554-614`.
2. Receiver decodes `(text, gen)` and creates
   `configApplyItem{gen,text,incarnation}` (`pkg/cluster/sync_conn_read.go:1144-1179`;
   item type `pkg/cluster/sync.go:1716-1730`).
3. The ordered `configApplyLoop` invokes `OnConfigReceived(item.text)` only
   after stale-generation/incarnation gates (`pkg/cluster/sync_conn_config.go:482-546`).
4. Wiring installs a text-only callback to `handleConfigSync` (`pkg/daemon/daemon_ha_comms_wiring.go:188-198`),
   which calls `syncAndApply`; `reportSessionAuthorizationChanges` then invokes
   the three invalidators and consumes/clears the pre-publication capture
   (`pkg/daemon/daemon_ha_sync.go:660-717`,
   `pkg/daemon/daemon_policy_invalidate.go:345-379`).

Design the bounded additive sidecar as follows:

- Commit ancestry is recorded at `RenameAsPlantClass` and stored in the
  daemon's pending map keyed by active-config hash/commit identity, not by
  the wire generation (the existing sender retry marker is connection-epoch
  times config-text hash). At each fresh `QueueConfigWithAncestry` call, take
  the config text and matching ancestry atomically; `QueueConfig` allocates
  the wire generation internally and encodes the pair. Both existing sender
  callsites (`pushConfigToPeer` and `reconcileConfigSyncToPeer`) use that
  lookup. A reconnect/reconcile retry gets a fresh wire generation but
  reattaches ancestry from the same active-config identity.
- Add an ancestry trailer to the config payload after the existing generation
  trailer: magic, length, and bounded serialized RenameDescriptor. Decode the
  ancestry trailer first, then the existing config-generation trailer. A
  legacy raw payload or old generation-only payload returns nil ancestry; the
  existing config text and generation behavior remains unchanged. Advertise
  support as `capFlagConfigAncestry` in the existing length-gated
  `syncMsgPeerCapabilities`/`localCapabilityFlags`, scoped and reset with the
  peer incarnation. Only a capable peer receives the sidecar; unknown and
  incapable peers receive text/generation and extensive rename retention safely
  falls back to teardown. Test unknown, incapable, capable, and reconnect
  reset states. A new sender reaching an old parser retains the fail-safe
  apply rejection behavior rather than applying text with unknown metadata.
- Extend `configApplyItem` with ancestry and carry text plus ancestry together
  through stale-generation and peer-incarnation checks. A queue-full receive
  drops the whole item and sends the existing config-apply nack; the receiver
  never retains an orphaned descriptor. Add an additive callback
  `OnConfigReceivedWithAncestry(text, ancestry)` while retaining the old
  `OnConfigReceived(text)` fallback for legacy tests/peers. `configApplyLoop`
  calls the new callback when present and the old callback otherwise.
- Wire the new callback to `handleConfigSyncWithAncestry`; the old
  `handleConfigSync(text)` remains a wrapper passing nil. The apply path passes
  ancestry into capture construction before snapshot publication, then
  `reportSessionAuthorizationChanges` consumes it exactly once. On successful
  apply, clear the daemon's pending ancestry by active-config hash/commit
  identity after the active/applied digest converges. On compile/promote
  failure, RG0-primary rejection, queue-full drop, or nack, leave that sender
  entry pending; the next reconcile creates a fresh wire generation and
  reattaches the sidecar from sender state. Reordered generations and replaced
  peer incarnations discard text plus ancestry together. Duplicate already-
  applied pushes may clear sender state only after active/applied digest
  convergence.
- This is an internal transport addition. No external cluster command or
  provider API is added, but the HA leg does require this codec/callback/
  capture change. The existing config-sync codec, callers, callback, ordered
  queue, capture, and lifecycle are the complete scope. If this sidecar cannot
  be threaded through that chain, #10511 is PLAN-KILL; no text-diff inference
  is allowed.

## 4. Contracts and invariants

- **C1 state predicates:** #10510 uses old-minus-new zone IDs; #10511 uses
  explicit ancestry on local and HA config apply. No cross-language function.
- **C2 partition:** purge unsafe unbound id-0 first; retain only bound
  extensive rows whose Go/Rust re-evaluation permits; otherwise existing
  teardown. Ambiguous ancestry or missing sidecar means delete behavior.
- **C3 teardown reuse:** every purge/deletion uses existing companion-aware
  delete and HA delete-sync (#2468).
- **C4 capture coherence:** old ids and #10511 ancestry are captured before
  publication and consumed once; #10510 derives zone disappearance from the
  old/new snapshots at rotation.
- **C5 compatibility:** absent sidecar/old callback/old payload defaults to nil
  ancestry and current safe teardown; no positional-index rebind.

- **C6 GRE0 tunnel-variant purge (sanctioned):** a BPF-mirror GRE row with
  discriminator zero cannot be re-identified, so the Go capture routes it to
  the delete bucket with `PurgeTunnelVariants` and the helper deletes every
  discriminator variant of the tuple (`delete_synced_tunnel_variants`). The
  wildcard fires ONLY for GRE + discriminator zero on both sides; all other
  shapes take exact-match delete. Same-tuple sibling GRE sessions are deleted
  with the target — intentional fail-closed teardown (the alternative is a
  leaked row or a cross-session alias), documented and pinned, not incidental.
- **C7 rotation order (intentional):** the worker rotation runs the Go-arm
  rebind BEFORE the #10510 removed-zone purge. The predicates are disjoint —
  rebind touches bound sessions, purge touches unbound id-0 sync-derived rows
  — so rebound rows (now bound under new zones) cannot match the purge, and
  the order is benign rather than load-bearing. Earlier plan text describing
  purge-before-retain as order-sensitive is superseded by this contract.

Invariants: default/plain rename teardown unchanged; overloaded-zero local,
legacy, and non-sync rows never swept; genuine Foreign/#9384 re-zone behavior
unchanged; demoted-owner close filtering unchanged; old peers preserve current
behavior; any row retained by #10511 extensive rematch is rebind/restamped on
both halves with the new policy identity and renamed zone ids, so it has no
stale bound counter or stale zone stamp. Rows outside that retain path may
carry old zone stamps during the measured #10509 Foreign window and remain
subject to the live-pair verdict; invalid/collision-quarantined snapshots
retain previous-good state; ancestry mismatch/ambiguity fails closed.

## 5. Risks and shippability

- #10509 Stage B may mask genuine Foreign; deferred until matrix measurement.
- #10510 overpurge is prevented by sync-derived + unbound + zero + removed-id
  gates and unique/collision validation.
- Positional binding is explicitly killed.
- HA sidecar loss safely falls back to teardown but leaves the extensive retain
  cohort uncovered; this is the #10511 conditional-KILL tripwire.
- Blind-rebind race (residual, bounded stale-authorization risk): a rebind
  record names the tuple, not the old policy id, so a session that closes and
  reopens on the same tuple between the pre-publication capture and the
  rotation rebind (~ms window, shrunk from unbounded by single-use metadata)
  is rebound without a fresh verdict. The renamed rule's identical fingerprint
  bounds the exposure, but concurrent policy reordering or other commit
  changes in the window could expand authorization; only an old policy/session
  identity guard on the record would close it fully.
- Multi-hop HA ancestry loss (residual): a standby that applies a peer-synced
  config records no daemon-side pending ancestry for it, so a second hop
  forwards text-only and the extensive retain is lost (safe teardown) beyond
  one hop. Documented, not fixed: provenance survives exactly one HA hop.

Shippability order: Stage A; #10510 snapshot-zone purge plus full Rust/Go
controls; #10511 local ancestry and evaluator; HA sidecar and sync-path test;
then joint fixture. Each earlier leg remains useful if a later leg is deferred.

## 6. Test plan and RED cells

The design-path cells below are IMPLEMENTED in the lane; the PR body Validation
section records the firsthand module runs and RED-on-revert proofs. Reviewers
must still run full affected files/modules, not only the expected-to-flip
test, and record RED-on-revert firsthand.

### #10509

Run full `userspace-dp/src/afxdp/poll_descriptor/session_hit_authority_tests.rs`
and affected packet-dispatch tests. The matrix must drive both a Drop lane
(peer-synced/reverse or non-admitting-interface) and a Revoke lane (local
forward on its admitting interface), and account separately for
`foreign_authority_drops` and `policy_revoked_sessions`. The dead-pair Drop
cell and Revoke cell must each observe a positive event before upper-bound
assertions; single-zone permit must assert Foreign+Forward with zero of both.
Sweep emulation must end the count while last-seen control proves policy-id
refresh did not end it. Reverting either accounting/verdict path reds its
positive cell; max-minus-one is used only after observed max > 0.

### #10510

Run full `deleted_first_policy_purge_9526_tests.rs`,
`worker/loop_body/first_policy_purge_rotation_9526_tests.rs`, and Go
`userspace_sync_test.go`. Owner-absent fixture installs promoted SharedPromote,
unbound, stamped-zero row, applies an old/new snapshot whose old zone id
vanishes from the new zone set, and asserts purge; revert leaves survivor.
Empty or absent zone-set producer controls assert no-op rather than treating
an empty new set as disappearance of every old id.
Failover-before-rename keeps demoted ex-owner close n=0 while receiver rotation
purges. Negative matrix covers all SessionOrigin variants, legacy/old-peer,
nonzero id, reverse half, bound row, zone id outside removed set, duplicate old
id, and collision-quarantined snapshot. Positional Option A remains rejected.

### #10511

Run full `daemon_policy_invalidate_test.go`,
`daemon_policy_rematch_extensive_8993_test.go`,
`policy_reused_id_overclear_6948_test.go`, and the full Rust rotation module.
Explicit ancestry + extensive + alternate permit retains a bound renamed row;
revert tears it down. Negatives cover default/plain, no alternate permit,
generic no-ancestry delete/add, duplicate ambiguity, resolved-fingerprint
change, scheduler flip, NAT/NPTv6, ICMP-unknown, global/wildcard, and fragment
cases. Go asserts retain/delete; Rust/joint asserts forwarding.
Retain-then-delete RED cell: T1 explicit rename + extensive alternate permit
must retain and restamp/rebind both halves, their conntrack/BPF map values, to
the matched new policy id/counter and remapped zones; T2 deletes the renamed
new rule, and the next invalidation must find that new identity and remove both
halves. Reverting either Go rebind-record serialization or Rust
counter/metadata/map restamp must leave the row visible at T2 and RED.
The Rust id-0 cell separately proves the same retain/rebind result during
rotation, including new numeric id, new counter Arc, both halves, their map
values, and remapped zones; the #10510 unbound purge runs first and cannot be
retained by this arm.

### HA sync and joint fixture (required)

Drive the in-process HA path, not just direct helpers: sender
`QueueConfigWithAncestry` -> new codec trailer -> decode -> `configApplyItem` ->
ordered `configApplyLoop` -> `OnConfigReceivedWithAncestry` ->
`handleConfigSyncWithAncestry` -> `syncAndApply` -> pre-publication capture ->
`clearSessionsForPolicyChanges`. Seed the receiver with SyncImport and
SharedPromote id-0 rows, use the demoted-owner close filter (n=0) before apply,
and assert the sidecar reaches capture. Include legacy/no-sidecar fallback
(assert teardown/current behavior), queue-full/re-push, reordered generation,
and replaced-incarnation pair-drop controls. This fixture asserts C2 across
#10510 owner-absent purge, #10511 bound alternate retention, default/plain
teardown, and the #10509 shape-specific window.

## 7. Open questions and PLAN-KILL conditions

Stage-B items stay open; every implementation prerequisite below is RESOLVED
with its outcome recorded, since the lane implemented rather than killed.
- **O-10509-1 (Stage-B PLAN-KILL only):** measured bound per shape; if no
  material positive window, kill Stage B and accept+pin. OPEN (Stage B deferred).
- **O-10509-2:** if Stage B is selected, can its measured per-object
  zone-transition map preserve genuine Foreign/#9384 semantics? OPEN (Stage B
  deferred).
- **O-10510-1: RESOLVED.** Producers expose the `zone_set_validated` marker;
  either side unvalidated/empty forces an empty removal set and a safe no-op,
  never inferring disappearance from an empty new set or from CLI ancestry.
- **O-10510-2: RESOLVED.** Origin/zone/collision negatives run in unit
  harnesses without cluster commands (derivation cells, rotation purge and
  selectivity, marker validation); no PLAN-KILL triggered.
- **O-10511-1 (conditional-KILL, local + HA): RESOLVED — kill cleared.**
  Rename ancestry travels `RenameAsPlantClass` through local commit and the
  complete QueueConfig/encode/decode/configApplyItem/OnConfigReceived/
  handleConfigSync/capture lifecycle with bounded additive fields and legacy
  fallback on both legs; content-only inference was never used.
- **O-10511-2: RESOLVED.** ICMP-unknown, tier, and fragment parity cases went
  into the shared corpus; NAT/NPTv6/scheduler-time shapes are pinned by Go
  evaluator unit cells because the `q` grammar cannot encode session NAT
  metadata or time (documented in the corpus header).
- **O-JOINT-1: RESOLVED.** Predicates and sidecar schema locked before
  production work; #10510 stays independent of sidecar availability.

## 8. Verification record

- Implementation started from origin/master `9927bbfa` in branch
  `fix/10509-zone-renames`, with this worktree and assigned scope recorded.
- All three issue pages were read; merged-PR cache search was run in addition
  to base-scoped local history and found no merged fix.
- Source callsites checked: authority/dispatch; daemon invalidation/capture;
  SyncImport/promotion/origin predicates; first-policy rotation; configstore
  Rename callers; QueueConfig sender/codec; decode/configApplyItem;
  configApplyLoop callback; HA wiring/handleConfigSync; and invalidation capture.
- This v4 folds D1-R4 retain/rebind/restamp for both Go and Rust arms, D2-R1
  Drop/Revoke accounting, D2-R2 rotation-query detail, D2-R3 invariant
  correction, D2-R4 populated-zone producer guard, and D2-R5 wording cleanup.
- The implementation added the evaluator, capture, sidecar, capability-gate,
  and userspace restamp proofs listed above; the parent validation pass must
  still run the complete repository matrix after the lane rebase.
