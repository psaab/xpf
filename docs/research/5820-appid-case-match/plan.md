# #5820 — AppID case-insensitive session matching collapses valid application names

Research-only design plan. No production code is changed by this document.

- Issue: #5820 (labels: bug, audit, security) — "AppID: case-insensitive
  session matching collapses valid application names and broadens destructive
  clears".
- Coupled MERGED work: #5821 (PR #5956) — reserved the `UNKNOWN` sentinel out
  of the application namespace **case-insensitively**, *because*
  `SessionMatches` folds case. This plan must resolve the interaction.
- Base: branch `research/5820-appid-case-match` off `origin/master`
  (`13fad1d31` at time of writing).

---

## 1. Defect restated

`pkg/appid/runtime.go:210-214`:

```go
func SessionMatches(filter string, appNames map[uint16]string, cfg *config.Config,
    proto uint8, srcPort, dstPort uint16, appID uint16) bool {
    if filter == "" {
        return true
    }
    return strings.EqualFold(ResolveSessionName(appNames, cfg, proto, srcPort, dstPort, appID), filter)
}
```

The operator's `show`/`clear ... application <name>` filter is compared to the
session's resolved application name with Unicode case-folded equality
(`strings.EqualFold`). Application names are **case-sensitive identifiers**
everywhere else in the stack (parse, store, catalog, AppID assignment), so two
distinct configured applications differing only in case (`Payroll` vs
`payroll`, or a user `JUNOS-HTTP` vs the predefined `junos-http`) both match a
single-case filter. On the destructive `clear` path this deletes a broader set
of sessions than requested; on the display path it collapses two distinct
applications into one filter result.

The required invariant (from the issue): an operational application selector
must identify exactly one configured/catalog application, and a destructive
filter must never broaden silently through case folding.

---

## 2. Blast radius

### 2.1 The single folding site that causes the bug

Only one comparison folds an application name against operator input:

- `pkg/appid/runtime.go:214` — `SessionMatches` (`strings.EqualFold`).

Every other `strings.EqualFold` in `pkg/config` / `pkg/api` / `pkg/appid` is
unrelated to application-name identity (DDNS URL scheme `http`/`https`; IPsec
`ah` protocol token; `protoName` filter; CORS `Origin`/`Host`; SSE
`permit`). The one exception that *is* application-name-related is the #5821
reservation gate (§2.4).

### 2.2 Callers of `SessionMatches` — the affected surface

Six call sites across three packages, all consuming the same folded predicate:

| File | Lines | Surface | Destructive? |
|------|-------|---------|--------------|
| `pkg/grpcapi/server_sessions.go` | 548 (`matchV4`), 593 (`matchV6`) | gRPC `GetSessions` **and** `ClearSessions` (shared `sessionFilter`) | **Yes** — `ClearSessions` deletes every matched session |
| `pkg/api/sessions.go` | 1275, 1319 | REST session list/query | No (read) |
| `pkg/cli/session_filter.go` | 296, 341 | CLI `show`/`clear` session filter | **Yes** on the clear path |

The gRPC `sessionFilter.matchV4/matchV6` predicate is shared by the read
(`GetSessions`) and the destructive (`ClearSessions`) walks, so the same
over-match feeds both display collapse and over-delete. This is the security
core of the issue: a filtered clear can delete sessions the operator did not
name.

### 2.3 How application names are parsed / stored / keyed — can `Foo` and `foo` coexist?

**Yes, they coexist as distinct applications today. There is no
case-uniqueness or case-normalization gate anywhere in the config layer.**

- Storage type (`pkg/config/types_security.go:1092-1094`):
  ```go
  type ApplicationsConfig struct {
      Applications    map[string]*Application
      ApplicationSets map[string]*ApplicationSet
      ...
  }
  ```
  Plain Go maps keyed by the **exact** name string.
- `namedInstances` (`pkg/config/compiler_protocols.go:983`) returns the name
  verbatim (`child.Keys[1]` in the flat-set shape, `sub.Name()` in the
  hierarchical shape). No folding, no canonicalization.
- `compileApplications` (`pkg/config/compiler_applications.go`) writes
  `apps.Applications[appName] = app` with that exact key. `strings.ToLower` in
  this file is applied only to **protocol tokens, service-port names, and ALG
  names** (`:505`, `:534`, `:597`, `:710`, `:772`, `:782`) — never to the
  application *name*.
- `config.ResolveApplication` (`pkg/config/predefined.go:206-217`) does exact
  map lookups (user map first, then the predefined `junos-*` table). No fold.
- `appid.CatalogNames` (`pkg/appid/runtime.go:39`) collects names into a
  `map[string]struct{}` keyed exactly, then `BuildCatalog`
  (`pkg/appid/catalog.go`) assigns a distinct `app_id` (1..65535) to each
  distinct-case name in sorted order, and `AppNames[appID] = name` records the
  exact name. `ResolveSessionName` maps a stamped `app_id` back to that exact
  name.

Net: `set applications application Payroll ...` and `set applications
application payroll ...` compile to two distinct `Application` entries, receive
two distinct AppIDs, and stamp two distinct session labels. Only the operator
*filter* comparison folds them together. The bug is isolated to the match
predicate — the rest of the stack is already case-exact.

This is the decisive fact for the design: **case-sensitivity is already the de
facto namespace contract of the store; `SessionMatches` is the sole
inconsistency.**

### 2.4 The #5821 reservation's dependence on case-folding

`pkg/config/compiler_validate_strict_application.go:778-803`,
`validateReservedApplicationNamesStrict`, rejects a user
`application`/`application-set` named `UNKNOWN` **case-insensitively**:

```go
for _, name := range appNames {
    if strings.EqualFold(name, ReservedApplicationName) {   // ReservedApplicationName == "UNKNOWN"
        return reservedApplicationNameError("application", name)
    }
}
// ... same EqualFold for application-sets
```

The doc comment states the reason explicitly (`:753-756`): *"SessionMatches
already folds case (strings.EqualFold), so 'unknown' and 'Unknown' collide with
the sentinel too; the reservation is therefore case-insensitive to keep the
whole case-folded name-slot owned by the sentinel."*

So #5821 reserved the entire fold-class of `UNKNOWN` **only because**
`SessionMatches` folds. The two are directly coupled: the reservation's
case-insensitivity is a downstream consequence of the folding bug this issue
targets. Call site: `pkg/config/compiler_uniformgates.go:820-840` (strict on
commit, lenient-downgrade to warning on tolerant-load / peer-sync via
`opts.lenientReservedApplicationNames`).

Coupled tests:
- `pkg/config/compiler_reserved_appname_5821_test.go:47`
  `TestReservedApplicationNameCaseVariantsRejected` — asserts `unknown`,
  `Unknown`, `uNkNoWn` are all **rejected**. This test encodes the
  case-insensitive contract and would flip if the reservation relaxes.
- `pkg/appid/reserved_name_5821_test.go`
  `TestReservedApplicationNameMatchesUnknownSentinel` — asserts
  `config.ReservedApplicationName == appid.Unknown` (`"UNKNOWN"`). This canary
  is orthogonal to case and **stays** regardless of the chosen option.

---

## 3. The semantic question: are Junos application names case-sensitive?

**Yes.** Junos configuration identifiers — including `applications application
<name>` and `applications application-set <name>` — are case-sensitive. Junos
treats `Payroll` and `payroll` as two distinct application objects, references
them case-exactly from `security policies ... match application`, and its
operational `show security flow session application <name>` filter matches the
configured name case-exactly. Junos does not fold operator application filters,
and it does not reject a config for defining two applications that differ only
in case.

Corroborating evidence *inside xpf* (independent of external Junos docs):

- The store already behaves case-sensitively end to end (§2.3) — the parser,
  typed store, resolver, catalog, and AppID stamping all preserve and key on
  exact case. The **only** case-folding component is the operator match
  predicate, i.e. the reported bug. That asymmetry is itself the strongest
  signal that exact-case is the intended contract and the fold is the defect.
- The predefined table is uniformly lowercase `junos-*`
  (`pkg/config/predefined.go`), and `ResolveApplication` does exact lookups —
  the codebase never relies on folding to resolve a name.

Conclusion: the Junos-parity contract is **case-sensitive application names
with case-exact operator matching**. This directly favors the issue's
"preferred" fix direction and rules out any design that would *forbid* a
config Junos accepts (i.e. rules out forced case-folding of the namespace as
the primary fix — see Option B).

---

## 4. Design options

### Option A — Case-sensitive exact matching (+ relax #5821 to exact-case). RECOMMENDED.

Make `SessionMatches` compare exactly, and — because the reservation's
case-insensitivity existed *only* to compensate for folding — relax #5821 to
reserve only the exact `UNKNOWN` spelling.

- `pkg/appid/runtime.go:214`:
  ```go
  return ResolveSessionName(appNames, cfg, proto, srcPort, dstPort, appID) == filter
  ```
  (`strings` stays imported — still used at `:333-334` in `resolveTupleFallback`
  helpers, so no import churn.)
- `pkg/config/compiler_validate_strict_application.go`: change both
  `strings.EqualFold(name, ReservedApplicationName)` (`:788`, `:798`) to
  `name == ReservedApplicationName`; update the doc comment (`:743-777`) and
  `reservedApplicationNameError` (`:808-817`) to drop "case-insensitively"; the
  sentinel `UNKNOWN` is only ever rendered upper-case by `ResolveSessionName`,
  so only an application literally named `UNKNOWN` can now alias it.

**Interaction with #5821:** the reservation *relaxes* — `unknown` / `Unknown`
become valid user application names again (they can no longer collide with the
upper-case-only sentinel under exact matching). `TestReservedApplicationName-
CaseVariantsRejected` must flip from "rejected" to "accepted". The canary
`TestReservedApplicationNameMatchesUnknownSentinel` is unchanged.

**Blast radius:** two one-line production changes (the match predicate + the
reservation predicate) plus comment/test/doc updates. No new gate, no new
namespace contract, no config rejected that was previously accepted; one config
class (`application unknown`/`Unknown`) that #5821 *newly* rejected becomes
accepted again.

**Migration:** an existing config with distinct-case apps immediately gets
correct (non-broadening) filter behavior. An operator who relied on the fold
(`clear ... application payroll` matching `Payroll`) now matches only the exact
name — but that reliance *was* the security bug and does not match Junos, so the
change is the intended correction. No config bricks; no dataplane/catalog
change.

**Junos parity:** exact. Matches Junos case-sensitive identifiers and case-exact
operator filters.

**Residual (documented, not a regression):** the sentinel is upper-case
`UNKNOWN`; a filter must be typed `UNKNOWN` to select unclassified sessions.
Non-ASCII fold classes (the issue's Unicode note) become a non-issue because
nothing folds anymore.

### Option B — Case-normalize the application namespace at commit (canonical fold)

Add a commit-time gate rejecting any two applications/application-sets whose
names fold to the same canonical (ASCII-lower) form, so at most one application
exists per fold-class; folding in `SessionMatches` is then safe.

- New strict gate mirroring the sibling `validate*Strict` family: reject
  `Foo`+`foo`, and (per the issue's acceptance list) a user `JUNOS-HTTP` that
  folds onto predefined `junos-http`. Must run at strict commit, catalog build,
  tolerant load, and peer sync, and must **fail closed** for destructive
  operations on a tolerant/legacy config that already carries a collision.
- `SessionMatches` may keep `EqualFold`; the #5821 reservation stays
  case-insensitive (consistent with a folded namespace).

**Interaction with #5821:** none required — the reservation stays as-is.

**Blast radius:** large. A brand-new commit gate touching four load paths, plus
a tolerant-path fail-closed policy for pre-existing collisions, plus the
predefined-vs-user collision axis (every user name must be checked against the
whole `junos-*` fold-space).

**Migration:** hostile. Any existing config that legitimately defined
distinct-case apps (valid in Junos) now **fails commit** and must be renamed. A
peer running an older binary could hold a collision that the new binary must
refuse to act on destructively.

**Junos parity:** **broken.** Junos accepts distinct-case applications; Option B
forbids a config Junos permits. Rejected as the primary fix for that reason.

### Option C — Hybrid: exact matching + catalog-resolved tolerant operator input

Adopt Option A's exact-match core, but let the operator *filter* be
case-insensitive **only when unambiguous**, resolved against the live catalog
before any table walk (the issue's "resolve against the current catalog first…
proceed only when exactly one exact name belongs to that fold; return an
explicit ambiguity error otherwise").

- Add a pre-admission resolver in each caller (`grpcapi`, `api`, `cli`) that
  maps `filter` → the set of catalog names (`view.appNames` values ∪ the
  `UNKNOWN` sentinel) whose fold equals `filter`. Exactly one → substitute that
  exact name and proceed with exact matching. Zero → no match (empty result / no
  delete). More than one → **ambiguity error before any read or delete**.
- `SessionMatches` itself becomes exact (Option A); the tolerance lives in the
  one-time filter-resolution step, not per-session.

**Interaction with #5821:** same as Option A — the reservation can relax to
exact-case, since the fold now happens against the concrete catalog with an
ambiguity guard rather than blindly per session.

**Blast radius:** medium-plus. Three caller-side resolvers, a new ambiguity
error surfaced over gRPC/REST/CLI, and careful ordering so the ambiguity check
runs *before* the destructive walk begins (the issue's acceptance test
"ambiguous case-insensitive input fails before the table walk/deletion
begins").

**Migration:** preserves operator convenience (any case works when
unambiguous) while satisfying the never-over-delete invariant. But it adds a new
error class and three code paths for a convenience the primary bug does not
require.

**Junos parity:** Junos does not offer case-insensitive filter convenience, so
Option C is a *superset* of Junos behavior — safe, but beyond parity.

---

## 5. Recommendation

**Adopt Option A** — make `SessionMatches` case-sensitive (exact `==`) and relax
the #5821 reservation to exact-case. It is the issue's stated "preferred"
direction, it is the Junos-parity contract (§3), it aligns the one inconsistent
component with the already-case-exact store/catalog (§2.3), it carries the
smallest blast radius (two one-line predicate changes), and it rejects no config
that was previously accepted (it *relaxes* one #5821 restriction).

Option C's ambiguity-resolved tolerant input is a reasonable **follow-on
enhancement** if operators later want case-insensitive filter convenience; it is
not required for correctness and is explicitly out of scope for the first
increment. Option B is rejected: it breaks Junos parity and has the largest
migration cost.

### 5.1 Minimal first increment (single coherent change)

1. **`pkg/appid/runtime.go`** — `SessionMatches`: replace `strings.EqualFold(
   ResolveSessionName(...), filter)` with `ResolveSessionName(...) == filter`.
   `strings` remains used elsewhere in the file (`:333-334`), so no import
   change.
2. **`pkg/config/compiler_validate_strict_application.go`** —
   `validateReservedApplicationNamesStrict`: change both `strings.EqualFold(
   name, ReservedApplicationName)` (`:788`, `:798`) to `name ==
   ReservedApplicationName`; update the doc comment (`:743-777`, remove the
   "case-insensitively" rationale and the "SessionMatches folds case" clause)
   and the `reservedApplicationNameError` message (`:808-817`, remove "reserved
   case-insensitively"). Verify `strings` is still needed in that file (it is —
   used by other validators, e.g. `:66`); no import change.
3. **Tests (coupled edit):**
   - Flip `pkg/config/compiler_reserved_appname_5821_test.go`
     `TestReservedApplicationNameCaseVariantsRejected` (`:47`) — `unknown` /
     `Unknown` / `uNkNoWn` now **accepted**; keep exact `UNKNOWN` (and the
     application-set + multi-term variants) **rejected**.
   - Keep `TestReservedApplicationNameMatchesUnknownSentinel` unchanged.
   - Add a `pkg/appid` `SessionMatches` regression: two case-distinct apps
     (`Payroll`/`payroll`) resolve to distinct names; filter `payroll` matches
     only the `payroll` session, not `Payroll`; **fail-on-revert** — restoring
     `EqualFold` must make the regression over-match/over-delete (the issue's
     required fail-on-revert acceptance test).
   - Add a user-vs-predefined case-collision case (`JUNOS-HTTP` user vs
     `junos-http` predefined) proving the filter no longer collapses them.
4. **Docs:** update the filter-contract description in
   `docs/services-application-identification.md` (the AppID show/filter
   contract) to state application filters are case-sensitive; add a release
   note that the #5821 reservation relaxes from case-insensitive to exact-case
   (mirroring how #5821 itself was called out as a behavior change).

### 5.2 How it composes with #5821 (explicit)

- **The #5821 validator changes.** `validateReservedApplicationNamesStrict`
  flips from `strings.EqualFold` to exact `==` on both the application and
  application-set walks. This is a **coupled edit**, not an independent one: the
  reservation was made case-insensitive *only because* `SessionMatches` folded,
  and this increment removes that fold. Leaving the reservation
  case-insensitive after making matching exact would be a harmless-but-
  inconsistent superset restriction (it would keep rejecting a valid
  Junos-parity name like `Unknown`); relaxing it keeps the namespace contract
  uniformly case-sensitive.
- **The #5821 test flips** (`TestReservedApplicationNameCaseVariantsRejected`),
  and its comment (`:45-46`) must be rewritten — the "SessionMatches folds case"
  justification is no longer true.
- **The #5821 canary stays** (`TestReservedApplicationNameMatchesUnknown-
  Sentinel`) — the sentinel literal and its equality with `appid.Unknown` are
  unaffected by the case-sensitivity change.
- **Tolerant-load / peer-sync posture is unchanged** — the reservation gate
  keeps its `lenientReservedApplicationNames` downgrade
  (`compiler_uniformgates.go`); only the comparison operator narrows.

---

## 6. Acceptance-test mapping (from the issue)

| Issue acceptance criterion | Covered by Option A |
|----------------------------|---------------------|
| case-distinct custom applications and application-sets | `Payroll`/`payroll` regression (§5.1.3) — distinct AppIDs, exact filter |
| custom vs predefined name collisions | `JUNOS-HTTP` user vs `junos-http` predefined case (§5.1.3) |
| exact show and filtered clear delete only the requested AppID | `SessionMatches` exact `==` drives both `GetSessions` and `ClearSessions` via the shared `sessionFilter` |
| ambiguous case-insensitive input fails before the table walk | N/A for Option A (no case-insensitive input is accepted; there is no fold to be ambiguous). Would be the deliverable of the deferred Option C follow-on |
| IPv4/IPv6, REST/gRPC/CLI, local/peer clear parity | one predicate, all six call sites (§2.2); `matchV4`+`matchV6` both change |
| tolerant legacy config/catalog ambiguity fails closed for destructive ops | Option A removes the fold entirely, so no case-ambiguity can arise at runtime; the legacy-collision fail-closed concern is specific to Options B/C |
| fail-on-revert: per-session `EqualFold` must over-delete in the regression | explicit fail-on-revert test (§5.1.3) |

Note: two acceptance items ("ambiguous input fails before the walk",
"tolerant legacy ambiguity fails closed") are written against a design that
*keeps* case-insensitive operator input (Option C). Under Option A they are
**vacuously satisfied** — with no fold there is no ambiguity to resolve. If the
reviewer insists operators retain case-insensitive filter convenience, that is
precisely Option C and should be scoped as the follow-on.

---

## 7. Non-goals / deferred

- **Option C ambiguity-resolved tolerant filters** — deferred enhancement; not
  required for the security fix. File as a follow-on if operator convenience is
  desired.
- **Forced case-folding of the namespace (Option B)** — rejected (breaks Junos
  parity, largest migration cost).
- **No dataplane / catalog / wire changes** — AppID assignment and the
  `app_id`↔name maps already key on exact case; this fix touches only the
  operator match predicate and the coupled #5821 commit gate.

---

## 8. Files read (evidence, all at `origin/master` 13fad1d31)

- `pkg/appid/runtime.go` — `SessionMatches` (:210), `ResolveSessionName` (:189),
  `CatalogNames` (:39), `resolveTupleFallback`.
- `pkg/appid/catalog.go` — `BuildCatalog`, case-exact `AppNames` assignment.
- `pkg/config/types_security.go:1092` — `ApplicationsConfig` map types.
- `pkg/config/compiler_applications.go` — `compileApplications`, exact-key
  store; `strings.ToLower` only on proto/service/ALG tokens.
- `pkg/config/compiler_protocols.go:983` — `namedInstances` (exact-name).
- `pkg/config/predefined.go:206` — `ResolveApplication` (exact lookup).
- `pkg/config/compiler_validate_strict_application.go:778` —
  `validateReservedApplicationNamesStrict` (#5821, case-insensitive).
- `pkg/config/compiler_uniformgates.go:820` — reservation call site.
- `pkg/grpcapi/server_sessions.go:548,593` — `matchV4`/`matchV6` (clear+show).
- `pkg/api/sessions.go:1275,1319` — REST filter.
- `pkg/cli/session_filter.go:296,341` — CLI filter.
- `pkg/config/compiler_reserved_appname_5821_test.go`,
  `pkg/appid/reserved_name_5821_test.go` — coupled #5821 tests.
