# DRAFT v1 — Fix plan for #10512: commit invalidation misses deleted tenant on bare 5-tuple mirror collision

Status: DRAFT v1 (STEP-0 output, design path — no production code in this commit).
Issue: #10512 (OPEN, bug + audit + validated-by:research + source:deep-review).
Base: `2781465ee3afe52a780d94d2245cb565a1e80548` on `fix/10512-commit-invalidation` (clean vs `origin/master`).
Lane: Eng10512. Date: 2026-09-22.

## 1. STEP-0 verification (what was confirmed, not assumed)

- `gh issue view 10512` → OPEN. Body pins the mechanism precisely; comment cross-links the same #5578 partial-clear family: #10513 (candidate-present helper-error discard) and #10528 (NotFound-recovery per-key swallow). Those are distinct roots/fixes and explicitly out of scope here.
- Not already fixed:
  - `git log --all --oneline --grep='10512' -i` → 0 hits.
  - `gh pr list --state merged --search "10512"` → empty; `--search "invalidation"` shows only older work (#7822 for #6948, #5588 for #5578, #4350, #4252, etc.), none closing #10512.
  - `gh pr list --state open --search "10512"` → empty.
  - `git diff origin/master...HEAD --stat` → empty (lane starts at base).
- Live on HEAD by source (all paths below read at base, not inferred):
  - The Go sweep matches ONLY `val.PolicyID` in BOTH producers:
    - Legacy post-apply: `pkg/daemon/daemon_policy_invalidate.go:449-461` (v4) and `:463-477` (v6), inside `clearSessionsForPolicyIDs`.
    - Pre-publication capture: `pkg/daemon/daemon_policy_invalidate_capture.go:210-223` (v4) and `:224-237` (v6), inside `capturePolicyInvalidationLocked`.
  - The enumeration source is the bare-keyed BPF mirror: `pkg/dataplane/session_store.go:221-233` (`ForEachV4/V6` → `dp.BatchIterateSessions{,V6}`) → `pkg/dataplane/maps_session.go:252-284` (batch lookup over `sessions`/`sessions_v6` maps).
  - The BPF key is the bare 5-tuple with no domain axis: `userspace-dp/src/afxdp/bpf_map/mod.rs:547-563` (`bpf_session_key_v4`: src_ip/dst_ip/src_port/dst_port/protocol) and `:568-583` (v6). `SessionKey` in Go is the same bare shape: `pkg/dataplane/types.go:12-20` (v4), `:432-436` (v6).
  - Both publishers overwrite with `BPF_ANY`: `userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:138-145` (v4) and `:390-397` (v6). Two tenants sharing a tuple therefore occupy ONE row carrying the last publisher's value.
  - The mirror's `RoutingDomain` VALUE cannot de-alias a KEY collision. This is stated in-tree, not a new claim: `docs/log/9546.md:28-30` ("the BPF key has no domain axis ... so two tenants sharing a 5-tuple share one mirror row. This turns 'both refused as ambiguous' into 'the surviving row deletes exactly'; it does not de-alias."). The forward/reverse value contract is `publish_conntrack.rs:154-176` (`conntrack_row_routing_domain`).
  - The empty-candidate path returns success: `daemon_policy_invalidate.go:529-532` (`deleteInvalidatedSessions`: `if c.empty() { return nil }`). When the surviving row carries tenant B's `PolicyID` while tenant A's policy was deleted, the A-targeted candidate set is empty, the delete is a nil no-op, and the commit reports success although A's domain-scoped helper session remains.
  - The authoritative helper table IS per-domain: `userspace-dp/src/session/key.rs:66-157` (`SessionKey.routing_domain: u32`, with reverse-match keys deliberately zeroed at `:293-300`). The standby keys synced sessions BY domain (`docs/log/9146.md:36-40`, proven by the #8636 fixture `state_holding_the_same_tuple_in(&[100_007, 100_008])` → 4 rows). The loss is purely in the Go-visible mirror enumeration.
  - No helper verb enumerates sessions by policy per domain today. The control dispatch (`userspace-dp/src/server/handlers/mod.rs:262-472`) offers `sync_session` (upsert/delete one 5-tuple), `drain_session_deltas`, `export_owner_rg_sessions`, `export_all_sessions`, `session_counters` (per-tuple diagnostic, #7919), plus counters/snapshot/binding verbs. None answers "which (domain, 5-tuple) rows were admitted by policy id N".

GATE: DESIGN needed. The miss is structural (lossy discovery index), not a one-line predicate fix. Any repair that stays on the mirror cannot see the shadowed tenant; any repair that leaves the mirror needs a new cross-language contract or a new Go-side index, both with HA/protocol/ABI consequences. No production code is changed on this path.

## 2. Source map (exact files/symbols the implement lane will touch or read)

### 2.1 Invalidation producers (both must be fixed together)
- `pkg/daemon/daemon_policy_invalidate.go`
  - `clearSessionsForDeletedPolicies` (:154-167) — consumes `policyInvalidationCapture.deleted` or falls back to `clearSessionsForPolicyIDs(deletedPolicyRuntimeIDs(...))`.
  - `clearSessionsForModifiedPolicies` (:201-215) — same for `modified` / `changedPolicyRuntimeIDs`.
  - `clearSessionsForDefaultPolicyChange` (:272-284) — same for `deflt` / `defaultPolicyChangeRuntimeIDs`.
  - `clearSessionsForPolicyIDs` (:406-507) — legacy post-apply enumeration; predicate at :450-461 / :464-477.
  - `deleteInvalidatedSessions` (:529-595) — single delete site; empty→nil at :530-532; HA delete-sync at :545-579.
  - `deletedPolicyRuntimeIDs` (:93-118) — old-numbering id set; id-0 excluded (:104-108); first-policy purge delegated to helper (:58-66, `purge_sessions_bound_to_deleted_first_policy`).
  - `changedPolicyRuntimeIDs` (:631-683) — policy-rematch-gated modified set.
- `pkg/daemon/daemon_policy_invalidate_capture.go`
  - `armPolicyInvalidationPlan` (:124-126), `capturePolicyInvalidationLocked` (:149-246) — one pass per family at :210-237, same PolicyID-only predicate, called at the last statement before `rt.ApplyConfig` from `pkg/daemon/daemon_apply_dataplane.go:171`.
  - Arm sites: `pkg/daemon/daemon_apply_commit.go:284,663,949` (three commit-class paths).
- `pkg/daemon/daemon_policy_invalidate_test.go`, `policy_reused_id_capture_6948_test.go`, `policy_reused_id_overclear_6948_test.go`, `daemon_policy_modified_4234_test.go`, `daemon_policy_default_4342_test.go`, `policy_rematch_shipped_6723_test.go` — existing contract cells; the #6723 wiring test pins `clearSessionsForPolicyChanges → clearSessionsForModifiedPolicies → changedPolicyRuntimeIDs`.

### 2.2 Mirror (lossy discovery index)
- `pkg/dataplane/session_store.go:221-233` (`ForEachV4/V6`), `:529-627` (`DeleteBatchKnownV4/V6` — scoped deletes via `ScopedSessionKey{Key, RoutingDomain}` at `:113-122`), `:746-824` (peer-marked #9714 path).
- `pkg/dataplane/maps_session.go:46-284` (`IterateSessions{,V6,From,V6From}`, `BatchIterateSessions{,V6}` over `sessions`/`sessions_v6`).
- `pkg/dataplane/types.go:12-20` + `:432-436` (bare keys), `:23-...` + `:443-...` (`SessionValue{,V6}` with `PolicyID`, `RoutingDomain`, `ReverseKey`, `Created`, `IsReverse`).
- `pkg/dataplane/bpf_session_value.go:135-139,205-209` (on-map `routing_domain` slot, #9546), `routing_domain_mirror_9546_test.go`, `bpf_session_value_test.go:361-362` (offsets 144/192).
- `userspace-dp/src/afxdp/bpf_map/mod.rs:547-583` (bare key constructors), `publish_conntrack.rs:96-152` (v4 publish), `:311-404` (v6 publish), `:170-176` (row domain stamp), `:183-290` + `:410-497` (value builders).
- `userspace-dp/src/session/key.rs:66-157` (authoritative per-domain key), `userspace-dp/src/session/mod.rs:1039+` (`SessionTable`), `userspace-dp/src/afxdp/bpf_map_tests.rs` (mirror tests).

### 2.3 Helper delete path (works once discovery names the row — #9146/#9364/#9546)
- `pkg/dataplane/userspace/manager_sessions.go:771-810` (`deleteHelperSessionsScopedV4{,Marked}`, `...V6...`), `manager_sessionsync_request.go:16,140` (`buildSessionSyncRequestV4/V6`), `protocol_ha.go:41+` (`SessionSyncRequest` with `routing_domain`, `peer_delete`, `forward_only`).
- `userspace-dp/src/server/handlers/mod.rs:262-472` (verb dispatch; `sync_session` served off-lock at :207-210), `userspace-dp/src/protocol/control.rs:314+` (`ControlRequest`), `pkg/dataplane/userspace/protocol.go` (Go side; current version v16+ per #9714/#9752 comments).

### 2.4 Prior art that bounds this fix (read before designing)
- `docs/log/9146.md:16-54` (bare-mirror swap emits zero retractions; standby accumulates both rows; bare delete refused as ambiguous #8636).
- `docs/log/9546.md:20-30` (value carries domain; key still bare; explicitly does not de-alias).
- `pkg/dataplane/userspace/batch_delete_domain_9364_test.go`, `batch_delete_mirror_domain_9546_test.go`, `sync_delete_domain_9146_test.go` (delete-scoping cells; the #9546 cell follows the GC path exactly: seed → `ForEachV4` → `DeleteBatchKnownV4` → wire).
- Sibling filings in the same #5578 family (do NOT fix here): #10513 (helper-error discard), #10528 (NotFound per-key swallow), #9364 (once-selected scope the delete — fixed), #9526 (id-0 first-policy purge — fixed, helper-side), #6948 (pre-publication capture — fixed, same predicate), #8636 (bare-delete refusal — fixed, orthogonal).

## 3. Blast radius (measured at base)

- Invalidation entry/wiring: 3 arm sites (`daemon_apply_commit.go`), 1 capture site (`daemon_apply_dataplane.go:171`), 3 clear consumers + 1 shared core + 1 shared delete site (`daemon_policy_invalidate.go`), 2 producers (capture + legacy) each scanning 2 families with the same predicate. Any discovery change must land in BOTH producers or the defect moves to the fallback path (boot/non-commit applies use legacy; commit-class uses capture).
- Enumeration consumers sharing the mirror: conntrack GC (`pkg/conntrack/gc.go:313,390` + deletes at :362,447), cluster bulk sync (`pkg/cluster/sync_bulk.go:235,247`), conn sweep (`pkg/cluster/sync_conn_sweep.go:255,303`), HA reconcile (`pkg/daemon/daemon_ha.go:2304,2318`), stale reconcile (`pkg/dataplane/session_store.go:1023,1047`), plus `show`/`clear` surfaces. A mirror-key change touches ALL of them; a helper-verb addition touches only the invalidation producers (plus the new verb's own tests).
- Delete-path callers of `DeleteBatchKnownV4/V6`: GC, cluster-stale reconcile, commit invalidation (this issue), plus ~15 test fakes pinning scoped/peer/forward-only behavior (#9364/#9714/#9752 cells). Discovery changes must keep producing `SessionEntry{Key, Value}` with a trustworthy `Value.RoutingDomain` or every scoped-delete cell regresses.
- Cross-language surface: BPF C header (`bpf/headers/xpf_conntrack.h`), Rust mirror (`BpfSessionKey*`/`BpfSessionValue*`), Go mirror (`SessionKey{,V6}`/`SessionValue{,V6}` + `bpfSessionValue{,V6}`), control protocol (`ControlRequest`/`SessionSyncRequest` both sides, `ProtocolVersion`/`CONFIG_SNAPSHOT_PROTOCOL_VERSION`). A BPF-key change is a 3-language ABI break with pinned-map migration (cf. #5460/#4983/#9546 crossings); a new control verb is a 2-language protocol addition with version bump (cf. #7919/#8121/#9412/#9714/#9752).
- Test suites that must stay green: `pkg/daemon` (invalidation + #6948/#4234/#4342/#4343/#6723 cells), `pkg/dataplane` + `pkg/dataplane/userspace` (mirror, scoped delete, sync wire), `pkg/conntrack`, `pkg/cluster`, `userspace-dp` session/bpf_map/server suites. Privileged cells (real BPF maps, CAP_BPF) skip on unprivileged CI (#9337) — the acceptance fixture below needs the privileged cluster.

## 4. Root cause (one paragraph)

Discovery and authority disagree by construction. Authority (helper `SessionTable`, HA-synced store) is keyed per routing domain; discovery (Go `ForEachV4/V6` over the BPF conntrack mirror) is keyed on the bare 5-tuple and keeps one row per tuple under `BPF_ANY` last-writer-wins. The invalidation predicate (`val.PolicyID in deletedIds`) is evaluated against the surviving row only, so when the survivor belongs to the non-deleted tenant the deleted tenant's sessions are never named, the candidate set is empty, `deleteInvalidatedSessions` returns nil, and the commit reports success with stale helper sessions still installed. #9546's value-carried domain fixes WHICH domain a selected row deletes in; it cannot surface a row the key collision already discarded.

## 5. Fix options (implement lane picks one; reviewer confirms)

### Option A — Helper-side policy-scoped delete verb (recommended for design review)
- Shape: new control verb, e.g. `delete_sessions_by_policy { policy_ids[], reason }` (both families in one call or per-family verbs), executed helper-side against the authoritative per-domain `SessionTable` (and the synced-session table on standby). Go producers stop enumerating the mirror for discovery and instead (a) compute the same three id sets, (b) call the verb at the same two boundaries (pre-publication capture point for the candidate decision, post-apply for the delete — or capture-then-delete with the verb doing both phases), (c) mirror-gc the bare rows for the deleted tuples as today via the existing scoped path, (d) HA-sync the deletes as today (#2468).
- Why it fits: the helper already owns the per-domain index, the rule-handle binding (`purge_sessions_bound_to_deleted_first_policy` precedent for id-0), the #3395 re-resolution that moves `policy_id` under Go, and the ambiguous-delete refusal (#8636) that proves it can see both tenants. Discovery moves to where the data is instead of reconstructing it from a lossy projection.
- Costs: new 2-language control verb + protocol bump + version-skew behavior (old helper must fail closed or Go must fall back to mirror scan with a loud partial-clear error, never silent success); per-worker fan-out design (session tables are per-worker — cf. `session_counters` kick/collect at `handlers/mod.rs:452-460` and `export_all_sessions` push); lock discipline (off-lock like `sync_session` vs locked phase); HA standby semantics (verb must run on both nodes or ride the existing delete-sync channel); `policy_id` staleness window (verb must evaluate against the OLD numbering — same #6948 placement constraint, now helper-side).
- Touches: `userspace-dp/src/server/handlers/*` (new verb + per-worker session-table scan by `policy_id`), `userspace-dp/src/protocol/control.rs` + `pkg/dataplane/userspace/protocol*.go` (request/response, version bump), `pkg/daemon/daemon_policy_invalidate*.go` (replace mirror enumeration with verb call in both producers; keep `deleteInvalidatedSessions` for mirror/HA fan-out), tests both sides + privileged two-domain fixture.

### Option B — Per-domain mirror enumeration (de-alias at the mirror)
- Shape: give the mirror a domain axis so Go can enumerate per domain: either (B1) widen the BPF map KEY with `routing_domain` (new map, new ABI, migration), or (B2) keep the key bare and add a per-domain secondary index (second map keyed `(domain, 5-tuple)` → presence/policy, maintained by all four publish sites + refresh + delete + GC), or (B3) stop sharing one row by salting collisions (rejected — changes forwarding lookup identity).
- Why it fits: keeps discovery in Go, keeps the existing predicate shape (`PolicyID` + domain loop), no new helper RPC on the commit path.
- Costs: (B1) is the largest ABI break in the repo's history for this map — 3-language struct change, pinned-map migration with live-pin preflight refusal, size asserts in C/Rust/Go, every `ForEach`/`Get`/`Delete`/`show`/`clear`/GC/sync caller re-examined, rolling-upgrade mixed-version behavior. (B2) doubles the write fan-out on the hottest path (publish/refresh/delete/GC must keep two maps consistent under `BPF_ANY` races and partial failures) and still needs a disciplined reader (stale index entries → over-clear of valid commits). Both keep the #6948 re-stamp race (the index must be captured pre-publication too).
- Touches (B1): `bpf/headers/xpf_conntrack.h`, `pkg/dataplane/{types,bpf_session_value,maps_session,session_store}.go`, `userspace-dp/src/afxdp/bpf_map/*`, every test pinning offsets/sizes/wire. (B2): same writers plus a new map definition, lifecycle, and consistency tests. Either is a multi-PR crossing, not a single commit.

### Option C — Go-side policy→sessions index (de-alias without touching the dataplane)
- Shape: maintain in Go (daemon or userspace Manager) a `(policy_id, domain) → set of 5-tuples` index fed by install/delete/refresh/sync events; the invalidation producers consult the index for the deleted ids instead of scanning the mirror, then delete the named `(domain, tuple)` rows through the existing scoped path.
- Why it fits: no ABI break, no new helper verb, no commit-path RPC; purely control-plane state.
- Costs: the index must observe EVERY mutation that moves `policy_id` or domain — frame-driven installs (3 sites), HA peer import, #3395 re-resolution re-stamps (helper-internal, 100ms slices), GC expiry, operator clears, cluster-stale reconciles, standby promotion — or it drifts and either misses (this bug again, silently) or over-clears (drops valid commits' sessions, the #6948 inverse). The re-stamp feed alone likely needs a new helper→Go event stream (back to a protocol change, but continuous instead of on-demand). HA/failover and daemon-restart reconstruction are unsolved in this sketch. Highest silent-drift risk of the three options.
- Touches: `pkg/daemon/*` (index lifecycle tied to apply/commit), `pkg/dataplane/userspace/*` (install/delete hooks), possibly a new event-stream leg, plus drift-detection/reconciliation tests. Recommend rejecting unless A and B both fail review.

Recommendation: take Option A into plan review. It puts the predicate where the index already exists, bounds the change to the invalidation producers + one new verb, and reuses the proven scoped-delete + HA-sync machinery for the actual removals. Option B is the principled long-term repair but is a multi-PR ABI crossing disproportionate to a commit-success lie with a narrower available fix; Option C trades a visible miss for invisible index drift.

## 6. Acceptance test plan (must all land with the fix)

1. Privileged two-domain same-tuple fixture (the issue's acceptance, runs on the privileged cluster): install helper sessions for tenants A (domain 100007) and B (domain 100008) on the identical 5-tuple; delete ONLY A's policy; assert A's helper rows are gone (or the commit fails loudly) while B's rows remain; repeat across standby/failover (synced-session promotion must not resurrect A). Both families (v4 + v6). This is the RED cell: it fails on base (A survives, commit nil) and passes with the fix.
2. Unprivileged regression at the producer level (runs on ordinary CI): fake store/helper pair modeling the collision (mirror row carries B's `PolicyID`, helper holds A+B per-domain rows); drive `armPolicyInvalidationPlan → capturePolicyInvalidationLocked → clearSessionsForPolicyChanges` and the legacy `clearSessionsForPolicyIDs` fallback; assert A named + B untouched. Mirror the existing #6948/#9364/#9546 cell style (fake socket + recording manager, e.g. `newSyncOnlyManager9146`).
3. RED-on-revert firsthand: revert the fix (keep the tests), show the new cells FAIL; re-apply, show PASS. Record the exact commands and outputs in the implement PR.
4. No-over-clear guards: single-tenant delete still deletes exactly; mirror-occupant-tenant delete still works; valid commit with no deletions scans nothing and reports success; modified-policy path (`policy-rematch`) and default-policy path (#4342) unchanged; id-0 first-policy behavior unchanged (#9526 helper purge still owns it).
5. Affected suites green: `pkg/daemon`, `pkg/dataplane/...`, `pkg/conntrack`, `pkg/cluster`, `userspace-dp` session/bpf_map/server tests. No project-wide `go test ./...` mid-flight (parent runs it once after all lanes land); scoped `go test` with lane-isolated `GOCACHE`/`GOTMPDIR` under `/dev/shm`.
6. HA/failover leg: the privileged fixture's standby/failover repetition, plus delete-sync propagation assertions (#2468 channel) so a cleared session cannot resurrect on promotion.

## 7. Risks and edge cases (each must be closed by the implement lane)

- Silent-skew sensitivity (the core hazard): any fallback (old helper, verb error, partial enumeration) must surface a #5578 error and suppress the success line — never return nil with candidates unvisited. The `c.empty() → nil` early return must become "empty AND positively known empty", not "empty because discovery failed".
- Valid-commit breakage: the new discovery must not widen the candidate set beyond the deleted/modified/default id sets under OLD numbering (#6948 placement). Over-clear drops live permitted sessions — the inverse defect. The admitted-after-activation guard (legacy path) and pre-publication capture (commit path) semantics must be preserved or re-expressed helper-side.
- Old-numbering window: runtime policy ids are positional; delete renumbers survivors. Whatever evaluates the predicate (helper verb or Go index) must evaluate it against the pre-publish numbering. For Option A this means the verb needs the OLD id set + a capture-before-publish call, or the helper must resolve ids from a pinned pre-publish rule table.
- Reverse/DNAT companions: discovery names FORWARD rows only; `DeleteBatchKnownV4/V6` expands to reverse + DNAT/NAT64 companions. A helper-side verb must preserve companion expansion (or return forward rows for Go to expand as today). Reverse rows carry the same `policy_id` — including them double-deletes and, for NAT, targets the translated tuple.
- id-0 exclusion: `policy_id 0` stays excluded from the Go id sets (overloaded: first policy + host-inbound/fabric/tunnel/synced/legacy zeros). The helper-side verb must either also exclude 0 or take over the #9526 first-policy purge deliberately with its discriminator (rule counter-handle binding) — not by sweeping `policy_id == 0`.
- Standby/no-packet population: M2 next-packet re-derivation does NOT repair this class (no packet on standby; explicitly M2-declined populations). The fix must work with zero traffic on the standby and survive failover promotion.
- Version skew: new verb + old helper (rolling upgrade) must fail closed with a loud commit error or a well-defined fallback — never silent success. Protocol bump per repo precedent (bump on the merits, pin the digest cell).
- Two producers, two families: capture + legacy, v4 + v6. Fixing one producer or one family moves the defect, it does not close it. The #6948 capture's "non-nil empty capture is authoritative" invariant must survive.
- Sibling scope discipline: #10513 and #10528 are separate roots in the same family. The implement lane must not absorb them; cross-link and stop at the discovery boundary.

## 8. Open questions for plan review (parent lanes)

1. Option A verb shape: one `delete_sessions_by_policy` verb that both discovers and deletes helper-side, or a read verb (`list_sessions_by_policy` → Go decides → existing scoped deletes)? The former is fewer round trips; the latter keeps Go as the delete orchestrator (HA-sync, mirror cleanup, logging) and is easier to make RED-testable at the producer level.
2. Where does the OLD-numbering capture live under Option A — Go passes the OLD id set computed at arm time (current `deleted`/`modified`/`deflt` sets), or the helper pins the pre-publish rule table? Who owns the #6948 placement invariant?
3. Per-worker fan-out: session tables are per-worker. Is the verb a broadcast + collect (cf. `session_counters`, `export_all_sessions`), or does it run against a coordinator-visible aggregate? What are the bounds (worst-case session count × workers) on the commit path?
4. Failure semantics: verb timeout/partial-worker-failure → commit error (fail closed) with what operator guidance? Is there any safe fallback to the mirror scan, or does fallback reintroduce the silent miss?
5. Does the verb need to cover the synced-session table on the standby explicitly, or does the existing #2468 delete-sync propagation suffice? The acceptance fixture's failover leg decides this empirically.
6. Long-term: is Option B1 (domain-axis BPF key) the intended end state, with Option A as the bounded repair? If so, should this plan file the B1 crossing as a follow-up issue now so the mirror's lossiness is tracked as tech debt rather than rediscovered?

## 9. Implement-lane execution sketch (after plan approval)

1. Work in the implement worktree/branch only; lane-isolated `GOCACHE`/`GOTMPDIR` under `/dev/shm`; no cluster/incus commands except the privileged fixture runs the harness provides; no merges; no reviewer dispatch (parent owns it).
2. Write the failing tests first (§6.1–6.2), prove RED on base, then implement the chosen option.
3. Keep the change minimal: both producers, both families, same three id sets, same delete/HA-sync machinery; no refactors, no adjacent cleanups.
4. Prove RED-on-revert firsthand (§6.3), run the affected suites (§6.5), rebase on `origin/master`, open the PR with `Closes #10512` and a Why/What/Validation body, report + STOP.

## 10. STEP-0 deliverable checklist

- [x] Issue read (`gh issue view 10512 --comments` + JSON); OPEN; mechanism + acceptance + siblings recorded.
- [x] Live on base confirmed: 0 merged/open PRs for #10512; `git log --grep` clean; source predicates read at HEAD (PolicyID-only in both producers; bare BPF key; `BPF_ANY` overwrite both families; empty→nil success).
- [x] Source map from SOURCE (§2) with file:line + symbols; no inferred paths.
- [x] Blast radius quantified (§3); prior art distinguished (§2.4).
- [x] GATE recorded: DESIGN needed; no production code touched in this commit.
- [x] DRAFT v1 plan staged, committed via `git add -f docs/pr/10512-commit-invalidation/plan.md`, and pushed; report + STOP.
