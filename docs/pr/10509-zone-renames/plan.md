# DRAFT v1 cluster plan: zone-rename trio (#10509, #10510, #10511)

Status: DRAFT v1 (STEP-0 complete; plan review comes from parent lanes next).
Base: `2781465ee` (docs: correct session-sync contract documentation, #10508).
Worktree: `.claude/worktrees/10509-zonerenames`, branch `fix/10509-zone-renames`.
Lane: Wave-4 cluster lane, SERIAL route (single lane for all three to avoid merge conflicts).
Gate result: ALL THREE need design. No production code on this path.

## 1. Per-issue problem + STEP-0 evidence

All three are OPEN, all validated-by:research (3/3 MATERIAL Low), pinned `b71c52d6`.
Base-liveness check at `2781465ee`: `git log --all --grep 10509/10510/10511` empty
(no merged fix); every symbol below read live from source at HEAD.

### 1.1 #10509 — commit-window transient foreign drops on every rename

Problem: after a zone rename, the live arrival id (new `StableZoneID` hash, a
pure function of the zone name) can never equal the recorded
`metadata.ingress_zone` (old hash), so `session_hit_authority` returns Foreign
unavoidably; `foreign_hit_verdict` judges the (new arrival id, old recorded
egress id) pair, matches no rule, and falls to default deny. Bounded
commit-window transient: deterministic trigger (every rename, cluster-wide,
silent but for `foreign_authority_drops`). The persistent-outage form was
RETRACTED; R2/R3/R4 split into separate filings.

STEP-0 evidence (all verified live):

| Claim | Location |
|---|---|
| `StableZoneID` pure name hash (FNV-1a) | `pkg/config/zoneid.go:38` |
| arrival-vs-recorded compare, Foreign on mismatch | `userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:139-167` |
| foreign verdict judges (arrival_zone, recorded egress), Drop falls through | same file `:259-305` |
| silent drop counter | `poll_descriptor/mod.rs:1278-1279`, declared `types/runtime.rs:691` |
| per-hit idle refresh sustains rows | `userspace-dp/src/session/lookup.rs:267` |

Blast radius: Rust dataplane per-packet hit path, cluster-wide, on every zone
rename, for the duration of the commit window (until the session restamps,
re-resolves, or ends). Sessions survive; packets drop. Severity Low.

### 1.2 #10510 — first-policy (id 0) synced rows survive rename (owner-absent + failover-before-rename)

Problem: synced sessions admitted by the FIRST policy (`policy_id` 0) in a
renamed pair persist with stale recorded zones when the owner cannot purge
them. Three compounding skips: (a) the Go commit sweep (M1) skips id 0;
(b) the #9526 helper purge matches only bound `metadata.policy_counter`
handles, while SyncImport installs `policy_counter: None` and `reresolve`
keeps `None => stamped`, so promoted first-policy rows stay unbound;
(c) the authority compare is generation-independent and Foreign/Drop is
silent, while per-hit `last_seen` refresh sustains the row under traffic.
Cases: owner-down/partition/crash, and failover-before-rename with both nodes
up (ex-owner close filtered after demotion). Normal two-node rename is COVERED
(owner bound purge + close delta).

STEP-0 evidence (all verified live):

| Claim | Location |
|---|---|
| M1 skips id 0 (overloaded wire value) | `pkg/daemon/daemon_policy_invalidate.go:104-108` (+ doc `:37-66`) |
| #9526 purge matches bound handles only | `userspace-dp/src/afxdp/session_glue/mod.rs:711-714` |
| #9526 fires on delete AND rename (stable-id disappearance) | same file `:655-678` |
| SyncImport installs `policy_counter: None` | `userspace-dp/src/server/helpers/session_sync.rs:485` |
| wire carries `policy_counter_idx` but handle stays None | same file `:477-485` |
| reresolve `None => stamped` (frozen id kept) | `userspace-dp/src/policy.rs:1817` (fn `:1801-1818`) |
| per-hit `last_seen` refresh | `userspace-dp/src/session/lookup.rs:267` |
| demoted-owner close filter (non-fabric OwnerRGID path) | `pkg/daemon/daemon_ha_userspace_stream.go:67` (`shouldSyncUserspaceDelta`) |
| close deltas gated by same predicate | same file `:970-985`; walk at `:914` |

Blast radius: HA sync + Rust rotation purge, owner-absent and
failover-before-rename subsets only. Survivors forward under stale recorded
zones until idle/GC (sustained by traffic). Severity Low.

### 1.3 #10511 — policy-rematch extensive tears down renamed policies (Junos parity gap)

Problem: `StablePolicyRuleID` embeds the policy name (`<from>-><to>/<name>`),
so a rename makes the old key disappear; `deletedPolicyRuntimeIDs` inserts the
old nonzero id with no rematch gate, `changedPolicyRuntimeIDs` skips
absent/deleted keys, and `clearSessionsForDeletedPolicies` tears down
unconditionally. Under `policy-rematch extensive` a renamed policy's sessions
die even when another policy still permits the flow. Junos parity: DEFAULT
closes on rename (xpf correct), PLAIN covers changed policies only (xpf
correct), EXTENSIVE keeps the session when another allowing policy matches
(xpf gaps). Fix MUST be extensive-only; a global rename exemption would break
default/plain parity.

STEP-0 evidence (all verified live):

| Claim | Location |
|---|---|
| stable key embeds zones + name | `pkg/dataplane/userspace/policies_ids.go:108` |
| deleted set: no rematch gate, id-0 excluded | `pkg/daemon/daemon_policy_invalidate.go:93-117` |
| unconditional teardown of deleted set | same file `:154-167` |
| changed set skips absent keys (deletion-clear owns them) | same file `:663-666` |
| extensive fingerprints common keys only | same file `:652-655`, `:733-746` |
| M3 precedence: arrival-zone mismatch sets Foreign before M2 | `session_hit_authority.rs` + dispatch (issue cites `mod.rs` arms) |

Blast radius: Go daemon commit path, extensive-mode deployments only, on
policy rename (and zone rename via the same key-disappearance mechanism).
Availability/parity: sessions torn down that Junos extensive would keep.
Severity Low.

## 2. Coupling map

### 2.1 Shared root cause

Stable identity is name-derived in both planes: `StableZoneID` (zone-name
hash) and `StablePolicyRuleID` (`<from>-><to>/<name>`). There is no rename
event or identity epoch anywhere in the pipeline: every rename lands as
delete + add with no continuity link. All three issues are facets of that one
missing concept:

- #10509: the dataplane hit authority compares a live name-derived id
  against a recorded name-derived id with no rename continuity.
- #10510: the rename-as-delete teardown path orphans rows it cannot see
  (unbound id-0 synced rows) in exactly the cases the owner cannot help.
- #10511: the commit-time deleted-set teardown cannot tell rename from
  delete, so extensive mode cannot apply its keep-if-permitted rule.

### 2.2 Shared code paths

1. Rename commit path (Go): daemon apply -> `deletedPolicyRuntimeIDs` /
   `changedPolicyRuntimeIDs` -> `clearSessionsForDeletedPolicies` /
   `clearSessionsForModifiedPolicies` -> HA delete-sync (#2468). Touched by
   any #10510 (M1 side) or #10511 fix.
2. Rotation teardown path (Rust): forwarding-snapshot rotation ->
   `deleted_first_policy_rule_id` -> `purge_sessions_bound_to_deleted_first_policy`
   (#9526). Touched by any #10510 (helper side) fix; must agree with (1) on
   what "renamed policy's session" means.
3. Authority verdict plane (Rust): `session_hit_authority` /
   `foreign_hit_verdict` (#10509's drop site). This is also what makes
   #10510's survivors SILENT (generation-independent Foreign/Drop) and what
   #10511's M3 precedence notes (Foreign set before M2 revalidation, so
   session-hit revalidation never sees the renamed flow). Any #10509 change
   to the compare moves the floor under #10510 and #10511.
4. Sync/promotion plane (Go + Rust): SyncImport (`policy_counter: None`) ->
   promotion -> `reresolve None => stamped`; delta eligibility
   (`shouldSyncUserspaceDelta`) shared by incremental and bulk paths.
   #10510's home ground; #10511's retained sessions must also sync
   coherently after a rename.

### 2.3 Fix-order dependencies

1. #10509 measurement FIRST. Its acceptance is measure-then-decide
   (shrink-vs-accept). If the window is shrunk (restamp/versioning), both
   #10510's authority-repair option and #10511's re-evaluation timing change.
   If accepted-with-pin, the other two design against a fixed floor.
2. #10510 and #10511 MUST be designed jointly: they push the rename
   teardown path in opposite directions (purge survivors vs retain
   re-permitted sessions). The joint contract (section 4) must define the
   partition so neither fix undoes the other: extensive-retain must not
   retain rows #10510 purges, and the #10510 purge must not kill rows #10511
   retains.
3. Rust rotation purge vs Go commit sweep ordering must be settled once for
   both #10510 and #10511 (rotation-time vs commit-time teardown agree on
   rename semantics; no double-teardown races, no gaps).

Recommended implementation order (after plan approval): #10509 measure+pin ->
joint #10510+#10511 design lock -> #10510 -> #10511 -> joint regression.

## 3. Design per issue

### 3.1 #10509 design

Acceptance mandates measurement before mechanism. Two stages:

Stage A — quantify + pin (no behavior change):
- Harness: drive a zone rename against a live session table in the
  userspace-dp test rig (Rust-side rotation + synthetic arrival packets with
  old recorded zones), counting `foreign_authority_drops` and affected
  sessions per rename until the row restamps/ends. Pin the observed bound as
  a regression (upper-bound assertion: drops-per-rename <= measured max, so
  future growth reds).
- Decide shrink-vs-accept on the measured data with reviewers.

Stage B — shrink options (only if data justifies; each needs review sign-off):
- Option 1 (restamp on rotation): at forwarding-snapshot rotation, rewrite
  recorded `ingress_zone`/`egress_zone` for rows whose zones were renamed.
  Needs a rename map (old id -> new id) plumbed from the Go commit into the
  snapshot; risk is restamping rows the Foreign protection must still judge
  (interaction with #9519/#9384 re-zone revocation).
- Option 2 (generation/epoch-aware compare): stamp rows and snapshots with a
  config generation; `session_hit_authority` treats a same-generation rename
  pair as continuous. Needs the epoch on the wire for HA coherence; larger
  blast radius.
- Option 3 (accept + pin): keep the transient, keep the pinned bound, close
  the issue as accepted-risk. Legitimate terminal state per the issue text.

Recommendation: Stage A now; Stage B option chosen on data. Default to
Option 3 unless the window is operationally visible.

### 3.2 #10510 design

Acceptance: bind or purge id-0 synced rows on promotion/rename (or repair
authority generation-independently). Options:

- Option A (bind at promotion): resolve the wire `policy_counter_idx`
  (already carried, `session_sync.rs:477-484`) against the local
  `PolicyCounterStore` at SyncImport/promotion time, so promoted rows arrive
  bound and the #9526 purge sees them. Design questions: idx validity during
  config skew (rename commit windows where the two nodes hold different
  snapshots — idx may name the wrong rule on the peer); old-peer idx 0
  ("no counter") must stay unbound; what binds when the rule is absent
  locally (keep None = today's behavior).
- Option B (purge unbound id-0 on rename rotation): extend the #9526 purge
  to unbound rows carrying the renamed first policy's stamped id. Needs a
  NEW discriminator: unbound + stamped-0 is also the shape of host-local,
  neighbor-seed, fabric, tunnel, and legacy rows. Candidate discriminators:
  `SessionOrigin::SyncImport` (or promoted-from-sync bit if promotion
  preserves it) + stamped policy_id 0 + recorded zones in the renamed pair.
  Must prove the discriminator cannot match the overloaded-zero populations
  the Go sweep deliberately spares.
- Option C (authority repair): make the Foreign compare generation-aware so
  stale-zone survivors re-resolve instead of silently dropping (shared with
  #10509 Option 2). Widest blast radius; only if #10509 Stage B goes there.

Recommendation: Option A if the skew analysis holds (idx resolution keyed to
a generation check, fall back to None on mismatch); else Option B with a
proven discriminator. Option C only as a #10509 Stage B cohort.

Failover-before-rename half: the ex-owner close filter
(`shouldSyncUserspaceDelta` demotion path) is CORRECT behavior for live
ownership (a demoted node must not emit); the fix is on the receiver/rotation
side (bind or purge), not by re-opening the demoted-owner emit gate. Do not
"fix" the filter.

### 3.3 #10511 design

Acceptance: under `PolicyRematchExtensive` with an alternate allowing policy,
a rename re-evaluates and retains the session. Extensive-only. Components:

1. Rename-vs-delete detection (Go, commit time): a deleted stable key K_old
   with id N is a RENAME (not a delete) iff exactly one added stable key
   K_new in the same commit carries a policy whose verdict-relevant content
   equals K_old's (match sets + action, same comparators as
   `policyMatchOrActionChanged`, plus scheduler effective state). Zone
   rename is the bulk form: every key in the renamed pair remaps; detection
   must run in near-linear time (index added keys by content fingerprint,
   not O(deleted x added)). Ambiguity rule: zero or >1 content-equal
   candidates => NOT a rename (fall back to delete teardown). This keeps
   default/plain behavior byte-identical (detection result consumed only on
   the extensive path).
2. Re-evaluation of the renamed policy's sessions: for each session carrying
   a renamed id, re-judge the flow against the NEW policy set; retain iff
   another (or the renamed) policy permits. Open design point: where the
   evaluator lives. Candidates: (i) Go-side match via `pkg/policymatch`
   (needs verdict-parity proof vs the Rust evaluator, incl. NAT-rewrite
   tuples, ICMP-type gates, scheduler fail-closed, global/wildcard tiers);
   (ii) Rust-helper query at commit (round-trip that does not exist today).
   The retained session keeps forwarding and its next-packet path re-derives
   normally; teardown (when no policy permits) reuses the existing
   companion-aware delete + HA delete-sync.
3. Gating: the retain path executes iff `newCfg.Security.PolicyRematch`
   AND `newCfg.Security.PolicyRematchExtensive`; all other modes keep the
   exact current teardown. The capture path (#6948,
   `daemon_policy_invalidate_capture.go`) must carry the renamed-id set
   alongside deleted/modified.

Recommendation: component 1 as specified; component 2 needs the evaluator
decision (open question O-10511-1, PLAN-KILL class) before implementation.

## 4. Contracts + invariants

Joint contract (all three fixes must hold these):

- C1 (rename detection single source): exactly one function decides
  rename-vs-delete at commit; the #10510 purge side and #10511 retain side
  consume its result, never re-derive it.
- C2 (partition): a renamed policy's session is retained (extensive +
  re-permitted) XOR purged (covered by #10510 bind/purge) XOR torn down
  (default/plain, or extensive with no permitting policy). No session may
  satisfy two arms; the arms are evaluated in that order.
- C3 (teardown reuse): every teardown arm uses the companion-aware delete +
  HA delete-sync (#2468); no new delete path.
- C4 (capture coherence, #6948): any new id set (renamed ids) is captured
  pre-publication alongside deleted/modified, against old numbering.

Invariants (must not regress):

- I1: default/plain rename teardown unchanged (Junos parity) — byte-identical
  behavior when extensive is off.
- I2: wire-0 populations (host-local, neighbor-seed, fabric, tunnel,
  legacy/old-peer) are never swept by a first-policy operation.
- I3: Foreign protection (#9519/#9384/#9604) unchanged: no #10509 shrink may
  convert a genuinely-foreign arrival into Owner, and the #9384 admitting-
  interface revoke still fires.
- I4: demoted-owner emit gate stays closed (`shouldSyncUserspaceDelta`
  demotion path); receiver/rotation side owns the #10510 fix.
- I5: rolling upgrade safe: old-peer (idx 0 / policy_id 0 / no epoch) rows
  behave as today under every new path.

## 5. Risks

- R1 (evaluator parity, #10511): a Go-side re-judge that disagrees with the
  Rust evaluator retains sessions Junos would drop (stale permit) or drops
  sessions Junos would keep (the bug persists). Mitigation: parity corpus
  between the two evaluators before relying on it; else helper query.
- R2 (wrong-rule binding, #10510-A): idx resolution under config skew binds
  a synced row to the wrong rule's counter (misattribution + wrong purge
  fate). Mitigation: generation check on resolve, None on mismatch.
- R3 (discriminator overreach, #10510-B): an unbound-row purge that matches
  overloaded-zero populations causes a forwarding blip on rename (the exact
  harm the id-0 exclusion exists to prevent). Mitigation: origin-gated
  discriminator + negative tests over every zero population.
- R4 (Foreign weakening, #10509-B): restamp/epoch compare that erases a real
  zone-mismatch signal. Mitigation: existing #9519/#9384/#9604 suites must
  stay green unchanged; new tests assert Foreign still fires post-rename for
  genuinely moved interfaces.
- R5 (rename-detection ambiguity, #10511): duplicate-content policies or
  simultaneous delete+add with equal content misclassified. Mitigation: the
  exactly-one-candidate rule (ambiguity => delete teardown, today's
  behavior).
- R6 (zone-rename scale): zone rename remaps every key in the pair; naive
  pairwise detection is quadratic per commit. Mitigation: content-indexed
  detection, near-linear.
- R7 (serial-lane conflicts): all three fixes share the commit/rotation
  paths by construction; implement in the section 2.3 order on this branch.

## 6. Test plan (incl. RED cells)

Conventions: each fix ships a regression that FAILS on the pre-fix code
(RED-on-revert firsthand) and PASSES post-fix; each new behavior also ships
the negative control proving the populations it must not touch.

- T-10509-A (measure + pin): Rust rig test — live table + zone rename
  rotation + arrival packets; assert `foreign_authority_drops`-per-rename <=
  pinned bound and affected-sessions counted. RED cell: bound set to
  measured-max - 1 must FAIL (proves the pin measures the real window, not
  zero). Negative: genuinely-moved-interface arrivals still Foreign + Drop
  (#9519 controls green unchanged).
- T-10509-B (shrink, if taken): same rig; assert post-shrink drops == 0 (or
  the new bound) for rename continuity AND Foreign still fires for true
  re-zone. RED cell: revert shrink, keep test => FAIL.
- T-10510-A (bind) or T-10510-B (purge): owner-absent rename rig — synced
  id-0 row (SyncImport `policy_counter: None`, first-policy stamped id, old
  zones) + rename rotation/commit; assert no stale survivor past idle/GC
  (bound-and-purged or rebound with new zones). Failover-before-rename rig:
  demoted ex-owner close filtered (existing probe shape:
  `walkUserspaceSessionDeltas` primary CLOSE n=1, demoted n=0) + receiver
  rotation; assert ex-owner rows cleared or rebound. RED cells: revert fix =>
  survivor present => FAIL. Negatives: every overloaded-zero population
  (host-local, neighbor-seed, fabric, tunnel, legacy) survives the new purge
  untouched; normal two-node rename still covered by existing paths.
- T-10511 (extensive retain): Go daemon test — two policies, rename one
  under `PolicyRematch + Extensive` with the other permitting the flow;
  assert the renamed policy's session is re-evaluated and RETAINED (and a
  sendable packet still forwards). RED cell: revert fix => session torn down
  => FAIL. Negatives: default mode teardown unchanged; plain-rematch
  teardown unchanged (existing #8993/#9387 suites green); extensive with NO
  alternate permit still tears down; ambiguous rename (duplicate content)
  falls back to delete teardown; zone-rename bulk form retains across the
  pair.
- Joint regression: one test exercising rename under extensive + HA sync +
  first-policy involvement, asserting the C2 partition (each fixture session
  lands in exactly its arm).

## 7. Open questions (incl. PLAN-KILL)

- O-10509-1: What is the measured window (packets/sessions per rename)?
  PLAN-KILL class for Stage B: if ~0 in practice, Stage B is accept+pin
  (Option 3) and no shrink is designed.
- O-10509-2: Can a restamp map (old zone id -> new zone id) be plumbed from
  the Go commit into the Rust snapshot rotation without a wire-format break?
- O-10510-1: Is `policy_counter_idx` resolution against the local store safe
  during rename commit skew (nodes on different snapshots)? What generation
  check gates it, and what is the None-fallback behavior?
- O-10510-2 (Option B): does promotion preserve a from-sync marker usable as
  the purge discriminator, or must one be added? Enumerate every producer of
  unbound stamped-0 rows to prove the discriminator.
- O-10510-3: Are the owner-absent + failover-before-rename subsets reachable
  in a rig without cluster commands (unit/harness only)? PLAN-KILL class: if
  untestable, the fix cannot carry its RED cell and the design must change.
- O-10511-1: Where does commit-time re-evaluation live — Go `pkg/policymatch`
  (needs verdict-parity proof vs the Rust evaluator) or a new Rust-helper
  query (round-trip that does not exist)? PLAN-KILL class: if neither is
  viable without scope explosion, extensive rename-retain needs rescoping.
- O-10511-2: Which tuple fields re-enter evaluation for NAT'd sessions
  (pre/post-rewrite), and how do ICMP-type gates, scheduler fail-closed, and
  global/wildcard tiers participate?
- O-10511-3: Exact rename-identity predicate — content equality over match
  sets + action + scheduler state, or narrower? Zone-rename bulk remap vs
  pairwise detection performance budget per commit.
- O-JOINT-1: Do #10510 and #10511 agree on one rename-detection source (C1)?
  Lock the shared helper signature before either implements.

## Appendix: STEP-0 verification commands (all run at HEAD in this worktree)

- `git log --all --oneline --grep='10509\|10510\|10511'` => empty (no merged fix).
- `git log --all --oneline --grep='zone rename\|rematch\|StableZoneID\|foreign.*drop' -i`
  => related history only (#9526, #9098/#9387/#9649 rematch, #9949, #9604).
- Symbol greps + file reads listed in the section 1 tables (Rust
  `userspace-dp/src/...`, Go `pkg/daemon/...`, `pkg/config/zoneid.go:38`,
  `pkg/dataplane/userspace/policies_ids.go:108`).
- Working tree clean before/after (`git status --short` empty except this plan).
