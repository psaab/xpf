# Plan of action — #5488: scoped-global multi-zone deny narrows on a same-version old helper (fail-open under version skew)

- **Revision:** r3 (r1→r2: folded Claude SMR F1 three-generation v3 collision +
  F2 symmetric skew direction. r2→r3: folded Codex nit #5 effective-coverage
  test design + nit #6 plural-as-authoritative wording. Converged: Claude SMR +
  Codex both PLAN-READY on Path C; AGY off-task/blocked, documented.)
- **Research branch:** `research/5488-scoped-global-proto-skew`
- **Base:** `origin/master` @ `4e0c7f74cf0d`
- **Mode:** `/research` — plan only, no production code, STOP at PLAN-READY / PLAN-KILL.
- **Reviewers (research quad, 3-way):** Claude SMR + Codex + AGY. Copilot joins at `/engineer` on the code PR.

---

## 1. Status

PLAN DRAFT — awaiting reviewer convergence. This document evaluates three
mutually exclusive fix paths (A: version bump, B: capability negotiation, C:
version-free safe lowering) and makes a recommendation weighing the #5364
deploy-crossing cost of a version bump against the version-free safety of
per-verdict singular lowering.

---

## 2. Issue framing (the defect)

`buildOneRuleSnapshot` (`pkg/dataplane/userspace/policies_lower.go:209-247`)
lowers a global policy's optional zone scope into FOUR wire fields:

```go
MatchFromZone:  config.ScopeSingular(pol.Match.FromZones), // FIRST zone only
MatchToZone:    config.ScopeSingular(pol.Match.ToZones),   // FIRST zone only
MatchFromZones: pol.Match.FromZones,                        // FULL set (additive)
MatchToZones:   pol.Match.ToZones,                          // FULL set (additive)
```

`config.ScopeSingular` (`pkg/config/types_security.go:539-544`) returns
`zs[0]` — the FIRST zone of the scope list. The plural `MatchFromZones/
MatchToZones` were added by #4626 (M03) as ADDITIVE JSON fields carrying the
complete zone set.

The snapshot protocol version was **not bumped** when #4626 added the plural
fields. Both sides are still at **3**:

- Go: `ProtocolVersion = 3` (`pkg/dataplane/userspace/protocol.go:11`)
- Rust: `CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 3`
  (`userspace-dp/src/protocol/control.rs:22`)

A pre-#4626 helper ALSO advertises version 3 and parses only the singular
`match_from_zone/match_to_zone` (it has no `match_from_zones/match_to_zones`
serde fields). The apply gate is a strict equality check:

```rust
// userspace-dp/src/server/handlers/snapshot.rs:25
if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION { /* reject */ }
```

`3 == 3` → the old helper ACCEPTS the snapshot and silently ignores the plural
fields. A global **deny** scoped `match from-zone [ dmz trust ] to-zone
untrust` lowers to singular `match_from_zone = "dmz"`; the old helper resolves
the scope to `{dmz}` only and the `trust → untrust` deny **silently vanishes**
→ that traffic falls through to a later permit / default → **fail-open policy
bypass** during the version-skew window.

A CURRENT (post-#4626) helper is correct: `parse_policy_state` prefers the
plural via `effective_match_zones(&snap.match_from_zones, &snap.match_from_zone)`
(`userspace-dp/src/policy.rs:331-339`, consumed at `policy.rs:2084-2093`). The
bug is exclusively an OLD-helper decode under version skew.

**Invariant violated:** a compatibility extension that changes deny/reject
COVERAGE must never be silently ignorable under an unchanged protocol version.

---

## 3. Honest scope + value framing

**What this is:** an upgrade-safety / defense-in-depth hardening in the same
family as two gates that already exist in this exact file:

- `ensurePolicySchedulerProtocolLocked` (`manager_compile.go:551-571`) —
  refuses to publish a scheduled-policy config to a helper whose
  `ConfigSnapshotProtocolVersion < ProtocolVersion`.
- `ensurePersistentSourceNATProtocolLocked` (`manager_compile.go:573-593`) —
  same for persistent source NAT.

Both features got a version bump (to 3) when they landed, so their `>=
ProtocolVersion` gate can actually distinguish an old helper. #4626's
multi-zone scope did NOT bump, so **no gate in the family can see it** — the
version-3 collision is the root cause.

**Reachability (bounded):** on a clean deploy the daemon and helper ship and
restart together (`make cluster-deploy` sha256-verifies both; a fresh xpfd
spawns a fresh helper — `ensureProcessLocked`, `process.go:17-...`), so
same-node versions match and the bug does NOT fire. The skew window is a
**mixed-version install**: a new xpfd running against an older `userspace-dp`
binary/process — a partial/botched deploy, a manual/rescue swap, or a staged
upgrade that advances the daemon before the helper. This is precisely the
window the scheduler/NAT gates already defend; #5488 is the *security* (fail-
open) hole in that defense.

**"Version 3" is a THREE-generation collision, not two (SMR F1).** `git log`
shows `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3` has been fixed since `8477cf1a6`
(#1567, protocol-module split), and BOTH scoped-global commits landed on it
WITHOUT a bump: `eb42f8404` (#3148, singular `match_from_zone/to_zone`) and
`572952745` (#4626 M03, plural `match_from_zones/to_zones`). So version 3 spans:
- **gen1** (pre-#3148): no scoped-global support — ignores BOTH singular and
  plural → every global is any-zone on both sides.
- **gen2** (#3148 … #4626): honors the SINGULAR field only (the exact helper
  #5488 names).
- **gen3** (#4626+): honors the PLURAL, prefers it (correct).

This is why the version-3 collision — not #4626 specifically — is the root
cause, and it shapes the per-generation safety analysis in §5.

**PLAN-KILL-acceptable line:** it is legitimate to PLAN-KILL if reviewers judge
that (a) the mixed-version window is not a supported state (deploys are always
lockstep and sha-verified, so a version-3 old helper "cannot happen"), AND (b)
the residual risk does not justify any of the three fixes' costs. HOWEVER,
PLAN-KILL would be *inconsistent with the project's own posture*: the
scheduler/NAT gates prove the project treats the helper-older-than-Go window as
real and worth fail-closing, and this is the one member of that family that
fails OPEN on a security control. The bar for KILL is therefore "the window is
truly unreachable," not "it's rare."

---

## 4. What's already shipped (do not re-litigate)

- **#3148 / #3287 scoped-global lowering.** A global policy keeps its
  structural `from_zone/to_zone == "junos-global"` (preserving global-tier
  classification + config order) and carries its optional zone scope
  out-of-band in `match_from_zone/match_to_zone`. Empty scope = all zones
  (`security.rs:446-456`; `build_global_zone_scope` maps empty/`any` →
  `GlobalZoneScope::Any`, `policy.rs:307-309`).
- **#4626 (M03) multi-zone plural fields.** Junos scope is a zone LIST
  (`match from-zone [ trust dmz ]`); the additive `match_from_zones/
  match_to_zones` carry every zone. Helper PREFERS plural, falls back to
  singular (`effective_match_zones`). Host-inbound scope (`to-zone
  junos-host`) is armed from the RESOLVED plural scope
  (`global_to_zone.is_host_scope()`, `policy.rs:2148-2153`), NOT the raw
  singular — so a plural-only snapshot already works on a current helper.
- **Go read-back parity.** `effectiveMatchFromZones()/effectiveMatchToZones()`
  (`policies_lower.go:254-273`) also prefer plural, falling back to singular.
- **Existing fail-closed publish gates** (the pattern this fix should join):
  `ensurePolicySchedulerProtocolLocked`, `ensurePersistentSourceNATProtocol
  Locked`, and `disarmBeforeUnsupportedPublishLocked` (`manager_ha.go:434-450`,
  which disarms forwarding when `ConfigSnapshotProtocolVersion < ProtocolVersion`
  for unrepresentable content).

The singular field's ONLY consumer, when the plural is present, is an OLD
helper. Every current reader (new helper `effective_match_zones`; Go
`effectiveMatchFromZones`) prefers plural. The display/read sites
(`server_show_zones.go:277`, `api/security.go:311`) use `ScopeSingular` for
operator-facing rendering only. This is what makes Path C's per-verdict rewrite
of the singular VALUE safe on the current path.

---

## 5. Concrete design — three path options

### Path A — bump `CONFIG_SNAPSHOT_PROTOCOL_VERSION` 3→4 (both sides) + feature-gated refusal

- Bump `ProtocolVersion` (Go) and `CONFIG_SNAPSHOT_PROTOCOL_VERSION` (Rust) to 4.
- Go stamps `Version: ProtocolVersion` on every snapshot
  (`builder.go:32/79`, `manager_generation.go:112`) — UNCONDITIONAL.
- The Rust equality gate (`snapshot.version != 4` → reject) then makes an old
  v3 helper fail-closed on the snapshot. Add
  `ensureScopedGlobalMultiZoneProtocolLocked` (mirroring the scheduler gate)
  for a *clear operator diagnostic* when a multi-zone config meets an old
  helper, though the equality gate already fail-closes.

**Cost — the load-bearing point (relate to #5364):** because the version field
is stamped unconditionally and the Rust gate is strict `!=`, a v4 Go daemon
**cannot publish ANY config to a v3 helper** — not just multi-zone ones. The
bump is a **hard flag-day**: helper and daemon must cross 3→4 together. This is
exactly the #5364 class of event — *"rolling deploy cannot cross a shim-map ABI
change on a stale cluster."* A rolling cluster-deploy that lands the new xpfd
before the new helper (or vice-versa) fail-closes the dataplane until both
cross the boundary. Operationally: **bumping forces a coordinated (non-rolling)
helper+daemon reload**, and inherits whatever #5364 lands as the "coordinated
pin-clear refresh mode." It also silently RE-TARGETS the pre-existing
`>= ProtocolVersion` scheduler/NAT gates to require 4, tightening them in the
same fail-closed direction (acceptable, but a blast-radius fact to note).

**Verdict:** protocol-hygiene-correct (a wire semantic changed → the version
SHOULD bump), maximally visible (nothing silent), but the deploy-crossing cost
is the heaviest of the three and hits EVERY config, not just the unsafe one.

### Path B — helper capability advertisement (keep version 3)

- Helper advertises a new bit in its status (`ProcessStatus` /
  `UserspaceCapabilities` — today only `forwarding_supported: bool` +
  `unsupported_reasons: Vec<String>`, `snapshot.rs:656-661`), e.g.
  `multi_zone_scoped_global_supported: bool` (or a monotonic
  `config_snapshot_min_feature_version`).
- Go publishes plural to capable helpers; for an INCAPABLE (old) helper with a
  multi-zone scoped global, Go REFUSES to publish (fail-closed) — or falls back
  to Path C's safe-singular for that helper.
- Version stays 3, so the Rust equality gate keeps passing and **rolling deploy
  still works for every non-multi-zone config**. Only the exact unsafe case
  (multi-zone scoped global × old helper) fail-closes.

**Cost:** adds a NEW helper→Go capability channel that does not exist today
(the only helper→Go feature signal is the single int
`ConfigSnapshotProtocolVersion`). More wire surface + negotiation logic than A,
for a benefit (per-feature granularity) that C achieves with zero wire change.
An old helper still doesn't advertise the bit, so the fail-closed path is a Go
refusal — the same operator-visible "cannot publish" outcome as A, but scoped
to multi-zone configs only.

**Verdict:** the surgical middle ground — preserves rolling deploy for ~all
configs, fail-closes only the unsafe one — but it introduces the most new
machinery of the three.

### Path C — version-free safe lowering (per-verdict singular) — RECOMMENDED

Choose the singular field's VALUE per verdict so an OLD helper reading only the
singular is ALWAYS at least as strict as configured. The plural fields remain
the AUTHORITATIVE full-fidelity representation for current (gen3) readers; the
singular fields become a deliberate *conservative compatibility projection* of
the scope (widest for deny/reject, narrowest for permit) — NOT a lossy
optimization but a fidelity-preserving-for-new / safe-for-old dual encoding. No
version bump, no capability, no deploy wall (Codex nit #6).

- **deny / reject** → singular = `""` (empty). An old helper maps empty →
  `GlobalZoneScope::Any` (`policy.rs:307-309`) → the deny/reject applies to ALL
  from-zones → **over-denies** the other configured zones. Fail-CLOSED
  (security-preserving): the `trust → untrust` deny no longer vanishes; it is
  *widened*, never *narrowed*.
- **permit** → singular = first zone (narrowest single-zone representation). An
  old helper permits only that one zone-pair; the other scoped zones fall
  through to later policies / default-deny → **under-permits**. Fail-CLOSED
  (never grants a zone-pair the operator did not configure).

Uniform-monotonicity argument (all verdict types):

| Verdict | Old-helper singular | Direction | Safety |
|---|---|---|---|
| deny | `""` = any-zone | widen (over-deny) | fail-closed |
| reject | `""` = any-zone | widen (over-reject) | fail-closed |
| permit | first zone | narrow (under-permit) | fail-closed |
| `then count`/`then log` (modifiers on any verdict) | inherits verdict | telemetry only | no security effect |

There is no fourth terminal action: `PolicyAction ∈ {permit, deny, reject}`
(`types_security.go:582-584`; Rust `parse_action`, `policy.rs:3413-3420`).
`count`/`log` are modifiers (`LogSessionInit/Close`), not actions, so they ride
their verdict.

**Per-generation robustness (SMR F1) — the sharp qualification.** Because
version 3 spans three helper generations (§3), Path C's safety is not uniform
across ALL old helpers — but it IS uniform for the deny/reject direction the
invariant names:

| Verdict → singular | gen1 (ignores scope) | gen2 (singular only) | gen3 (plural) |
|---|---|---|---|
| deny/reject → `""` | any-zone deny = **over-deny (fail-closed)** | empty→any-zone = **over-deny (fail-closed)** | correct |
| permit → first-zone | any-zone permit = **OVER-PERMIT (fail-OPEN)** | first-zone = under-permit (fail-closed) | correct |

**The deny/reject widening is fail-closed across ALL three v3 generations**
(gen1 ignores the field → any-zone; gen2 reads empty → any-zone; both over-deny).
This fully discharges the #5488 invariant, which is explicitly about DENY
coverage. **Path C's permit-narrow is fail-closed only against singular-honoring
(gen2+) helpers**; a gen1 helper ignores the singular field and over-permits a
scoped permit — a fail-OPEN. That gen1 permit hole is PRE-EXISTING (gen1
predates #3148/#4626; never covered) and is OUTSIDE #5488's deny-coverage scope;
Path C does not regress it, but it does NOT close it either. Only Path A's
version bump fail-closes gen1.

**Symmetric skew direction (SMR F2).** #5488 names the new-Go/old-helper
direction (Go emits plural + singular-first; old helper ignores plural). The
REVERSE — an OLD Go (pre-#4626, emits singular-first, NO plural) driving a NEW
gen3 helper (helper binary upgraded before xpfd on a node) — ALSO narrows the
deny: gen3's `effective_match_zones` sees an empty plural, falls back to the
singular first-zone, and the `trust→untrust` deny vanishes = fail-open. Path C
CANNOT fix this (it changes only what NEW Go emits; it cannot rewrite
already-shipped old Go). Path A closes it (v4 gen3 helper rejects the old Go's v3
snapshot via the strict `!=` gate). Path B does not (old Go has no
capability-check code). This too is pre-existing (old Go always emitted
singular-first) — Path C is a non-regression, not a fix, for this direction.

**Cost / footguns (must be handled in `/engineer`):**
1. **Per-verdict logic belongs ONLY at wire-lowering sites**, not display
   sites. The value-rewrite must apply at `policies_lower.go:239-240` AND
   `zones_quarantine.go:161,171` (the #4626 quarantine path also derives the
   singular). It must NOT touch the operator-facing renderers
   (`server_show_zones.go:277`, `api/security.go:311`) — those should keep
   showing the configured first zone. Centralize in one helper, e.g.
   `config.ScopeSingularForVerdict(zones, action)`, used only on the wire path.
2. **Availability regression during the skew window** (bounded to multi-zone
   scoped globals): over-denial of other zones, under-permit of scoped permit
   zones. Security is preserved; connectivity for *other* zones may drop until
   the helper is upgraded.
3. **Host-inbound sharp edge:** a scoped host-inbound DENY (`match to-zone
   junos-host` from `[dmz trust]`) widened to `from = any` becomes a
   host-inbound deny from ALL zones on the old helper. If ordered before a
   host-inbound *permit* for management, it could shadow it and risk mgmt
   lockout during skew. The to-side is always the single token `junos-host`
   (`IsHostToZoneScope`, `types_security.go:552-554`), so only the FROM-side
   widens — but the risk is real and must be called out (mitigation options in
   §11 Q3).

**Verdict:** matches the issue author's own stated fix direction ("lower
deny/reject scopes safely (expand) and permit scopes narrowly"), converts the
deny/reject fail-open → fail-closed with ZERO wire/version/deploy cost, and
keeps the plural fields authoritative for current readers. The price is a
bounded *availability* regression on an already-degraded (mixed-version)
install, never a security regression.

### Recommendation

**Path C**, primarily because its deny/reject widening discharges the #5488
invariant (deny coverage is never silently narrowed) — and does so **robustly
across ALL three version-3 helper generations** (§5 table) — WITHOUT paying the
#5364 deploy-crossing cost that Path A imposes on *every* config, and without
inventing the new capability channel Path B needs. Path C's residual — an
availability dip for *other* zones on a mixed-version box — is fail-closed and
bounded to a rare config on an already-abnormal install.

**Scope of the Path C recommendation, stated honestly (SMR F1/F2).** Path C is a
COMPLETE fix for the defect #5488 names (deny coverage under the new-Go/old-
helper skew) and a NON-REGRESSION for the two adjacent cases it cannot reach: the
symmetric helper-first direction (old Go → gen3 helper still narrows the deny)
and gen1's pre-existing scoped-*permit* over-permit. **Only Path A closes the
entire multi-generation version-3 collision** (both skew directions + gen1's
permit hole), because a bumped, strict-`!=`, unconditionally-stamped version is
the only construct that makes an old helper of ANY generation fail-closed. If
reviewers/operators require closing the full collision — not just the named deny-
narrowing — Path A becomes mandatory and its all-configs flag-day is the price.

**Pick Path A instead if** reviewers/operators decide a *silent* availability
change during upgrade is itself unacceptable and prefer a hard, visible flag-day
(nothing changes behavior silently; the deploy just refuses until both sides
cross 4). Path A is the "protocol purist" answer and is the right call if the
project wants the version number to remain a truthful statement of wire
semantics. **Path B** is the fallback if the team wants A's explicitness but
cannot accept A's all-configs flag-day — at the cost of new negotiation
machinery.

A defensible HYBRID (note, not primary): ship Path C now (immediate, cheap,
fail-closed), and bump the version at the NEXT unavoidable ABI break (Path A
folded into a future flag-day) so the version eventually re-aligns with wire
semantics without paying a dedicated deploy wall for #5488 alone.

---

## 6. API + wire preservation

- **Path C:** ZERO wire change. `MatchFromZone/MatchToZone` JSON tags,
  `match_from_zones/match_to_zones`, and the `version` field are byte-identical.
  Only the VALUE placed in the singular field changes, and only for scoped
  globals. Current helper and Go read-back are unaffected (both prefer plural).
- **Path A:** `version` field value changes 3→4 (both structs). No field
  added/removed. Old×new both fail-closed by the existing equality gate.
- **Path B:** additive helper→Go status field only; snapshot wire unchanged;
  serde `default` keeps old helpers decoding.

No gRPC/proto change in any path (scope fields are internal snapshot JSON, not
protobuf). No CLI grammar change.

---

## 7. Hidden invariants

1. **Both-sides version parity** — Go `ProtocolVersion` and Rust
   `CONFIG_SNAPSHOT_PROTOCOL_VERSION` must stay equal (Path A must bump BOTH; a
   one-sided bump self-fail-closes every deploy via the equality gate).
2. **Deny/reject coverage monotonicity** — the wire lowering must never let an
   old decoder resolve a *smaller* deny/reject scope than configured. Path C
   enforces this by construction; A/B enforce it by refusing the publish.
3. **No fail-open in the skew window** — the whole point; any residual must be
   fail-CLOSED (over-deny / under-permit), never fail-open.
4. **Plural stays authoritative on the current path** — current helper +
   Go read-back MUST keep preferring plural; Path C must not perturb
   `effective_match_zones`/`effectiveMatchFromZones`.
5. **Host-scope arming reads the resolved plural, not the singular** — already
   true (`policy.rs:2148-2153`); Path C must not regress it (the singular
   rewrite for a host-inbound deny widens the FROM side only).
6. **Singular rewrite is wire-only** — display/API renderers keep showing the
   configured first zone (operator sees the config, not the wire-safety form).

---

## 8. Risk table

| Risk | Path | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Version bump breaks ALL rolling deploys crossing 3→4 | A | High (by design) | Dataplane blip / refused publish until lockstep | Coordinated reload; inherit #5364 refresh mode |
| Silent availability dip (over-deny other zones) on mixed-version box | C | Low (rare config × mixed install) | Connectivity loss for non-scoped zones during skew | Fail-closed; bounded to skew; document |
| Host-inbound deny widen → mgmt lockout | C | Low | SSH/mgmt loss during skew | §11 Q3: treat host-inbound scope conservatively / don't widen to-host denies |
| Per-verdict logic leaks into display renderers | C | Med (footgun) | Operator sees wrong scope | Centralize wire-only helper; unit-test display parity |
| New capability channel bugs / negotiation races | B | Med | Publish refused when it should proceed, or vice-versa | Additive serde default; explicit tests |
| Reviewers judge window unreachable | all | — | PLAN-KILL | §3 KILL bar: prove lockstep-only |

---

## 9. Test plan

**Fail-on-revert unit test (the load-bearing gate) — must FAIL on current
master, PASS after the chosen fix.** Model on
`protocol_failopen_2124_test.go` (constructs a config, lowers it, asserts the
snapshot behavior a specific helper generation would see).

- **Path C test (Go) — assert EFFECTIVE coverage, not `singular == ""` (Codex
  nit #5):** build configs with a global **deny** AND a global **reject** scoped
  `match from-zone [ dmz trust ] to-zone [ untrust dmz2 ]` (multi-zone on BOTH
  the source AND destination dimensions); run the real lowering
  (`buildOneRuleSnapshot`); simulate an OLD (gen2) helper by resolving the scope
  from ONLY the singular `MatchFromZone/MatchToZone`; assert the *effective*
  resolved scope COVERS every configured zone-pair on both sides (the widened
  any-zone superset), i.e. the deny/reject still applies to `trust → untrust`.
  On current master the singular = first-zone (`"dmz" / "untrust"`) → old-decode
  covers only `dmz → untrust` and DROPS `trust → …` and `… → dmz2` → **test
  FAILS** (fail-on-revert). The assertion must be on resolved coverage, not the
  raw string value. Add the permit mirror: a scoped permit's gen2 old-decode
  must NOT cover a zone-pair OUTSIDE the configured set (under-permit, never
  over-permit) — and explicitly note that gen1 (singular-ignoring) is NOT
  covered by this test because Path C cannot close the gen1 scoped-permit hole
  (§5 F1). A `parse_action`-parity assertion that `reject` and `deny` share the
  widening path guards against a future divergence.
- **Path A test (Go):** assert `ensureScopedGlobalMultiZoneProtocolLocked`
  REFUSES to publish a multi-zone scoped-global config when
  `lastStatus.ConfigSnapshotProtocolVersion < ProtocolVersion`, and the
  version constants are equal Go↔Rust. On current master there is no such gate
  → **test would need the new gate to pass** (fail-on-revert on the gate).
- **Rust decode test:** mirror the Go assertion in `policy_tests.rs` (there is
  already a plural-only decode test at `policy_tests.rs:5524-5540`) — assert a
  Path-C singular-only decode (deny → empty → `GlobalZoneScope::Any`) is
  strictly ⊇ the configured set.

**Build/CI:** `make test` (Go + Rust cargo legs, #4006). Rust leg must pass
(`build_global_zone_scope`/`effective_match_zones` untouched by C).

**Smoke:** a cluster/rolling-upgrade smoke that actually exercises a
mixed-version helper is **shim-walled** (#5364 / the loss-cluster shim-ABI wall
in project memory) — DEFER the live rolling-upgrade verify to `/engineer` lab
time and note it as lab-bound (the issue already says "final verify
lab-bound"). The unit tests above are the mergeable proof; the live skew test
is deferred, not skipped silently.

---

## 10. Out of scope

- Redesigning the snapshot protocol / capability framework wholesale.
- #4626's zone-set implementation for *current* helpers (already shipped and
  correct).
- #5364's coordinated rolling-deploy refresh mode itself (Path A would *depend*
  on it, but building it is separate).
- Any change to global-policy evaluation ORDER or the `junos-global` tier
  classification.
- HA session-sync / cross-node snapshot transport (each node lowers to its own
  local helper; there is no cross-fabric snapshot skew).

---

## 11. Open questions (each invitable to PLAN-KILL)

1. **Is the mixed-version window a supported state at all?** If deploys are
   *always* lockstep + sha-verified and a rescue/partial-deploy old helper is
   explicitly out-of-support, the bug is unreachable and PLAN-KILL is
   defensible (§3). Counter: the scheduler/NAT gates say the project supports
   it. **Reviewers must rule on reachability.**
2. **Does the project prefer a silent-but-fail-closed availability regression
   (C) or a loud hard flag-day (A)?** This is a values call, not a technical
   one — it decides A vs C. If "no silent behavior change during upgrade, ever"
   is a hard rule, C is out and A wins.
3. **Host-inbound deny widening (C):** is widening a `to-zone junos-host` deny's
   FROM side to `any` acceptable, or must host-inbound denies be special-cased
   (e.g. keep first-zone / refuse to widen) to avoid mgmt-lockout risk? Could
   PLAN-KILL Path C if reviewers find no safe host-inbound lowering.
4. **Path A blast radius:** is it acceptable that a 3→4 bump fail-closes EVERY
   config (not just multi-zone) against an old helper? If the ISSU/in-place
   flow keeps the helper alive across a daemon-only upgrade for zero-downtime,
   Path A forces a dataplane blip on the bump — is that tolerable, or does it
   argue decisively for C/B?
5. **Path B capability shape:** if B is chosen, is a boolean
   `multi_zone_scoped_global_supported` sufficient, or should it be a monotonic
   `config_snapshot_min_feature_version` so future additive features reuse the
   channel? A one-off bool risks a proliferation of feature bits.
6. **Does any current or planned reader depend on the singular field carrying
   the FIRST zone specifically** (not empty)? Verified none on the wire path
   today (all prefer plural), but a future consumer that reads singular
   directly would break under C. Should we add a compile-time/comment contract
   forbidding singular-only reads on the wire path?
7. **Hybrid acceptance:** is "ship C now, fold the version bump into the next
   unavoidable ABI break" acceptable, or does leaving `version` at 3 while wire
   semantics changed violate a protocol-truthfulness principle the team holds?
8. **Symmetric direction (SMR F2):** does the team require closing the
   helper-first skew (old Go → new gen3 helper still narrows the deny)? If yes,
   Path C is insufficient and Path A is mandatory. If the deploy model
   guarantees Go-upgrades-before-helper (never helper-first), Path C suffices.
9. **gen1 permit hole (SMR F1):** is the pre-existing scoped-*permit* over-permit
   on a gen1 (pre-#3148) helper in scope? It is outside #5488's deny-coverage
   invariant and only Path A closes it. Are gen1 helpers still a supported
   in-field state, or EoL such that only gen2 matters?

---

## Appendix — verified ground-truth references (origin/master @ 4e0c7f74cf0d)

- `pkg/dataplane/userspace/policies_lower.go:209-247` — four-field lowering.
- `pkg/config/types_security.go:539-544` — `ScopeSingular` returns `zs[0]`.
- `pkg/dataplane/userspace/protocol.go:11` — `ProtocolVersion = 3`.
- `userspace-dp/src/protocol/control.rs:22` — `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3`.
- `userspace-dp/src/server/handlers/snapshot.rs:25,376` — strict `!=` apply gate.
- `pkg/dataplane/userspace/builder.go:32,79`, `manager_generation.go:112` —
  `Version: ProtocolVersion` stamped unconditionally.
- `userspace-dp/src/policy.rs:331-339` — `effective_match_zones` (prefers plural).
- `userspace-dp/src/policy.rs:302-325` — `build_global_zone_scope` (empty/`any` → `Any`).
- `userspace-dp/src/policy.rs:2084-2093,2148-2153` — plural-preferring decode + host-scope arming.
- `userspace-dp/src/protocol/security.rs:453-469` — singular + plural serde fields (`default`).
- `pkg/dataplane/userspace/manager_compile.go:551-593` — scheduler/NAT version gates (the pattern).
- `pkg/dataplane/userspace/manager_ha.go:434-450` — `disarmBeforeUnsupportedPublishLocked`.
- `pkg/dataplane/userspace/zones_quarantine.go:161,171` — second singular-derive site.
- `pkg/config/types_security.go:582-584` — `PolicyAction ∈ {permit, deny, reject}`.
- `userspace-dp/src/policy.rs:3413-3420` — `parse_action`.
