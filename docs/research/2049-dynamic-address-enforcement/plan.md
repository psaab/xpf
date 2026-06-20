# Plan: Dynamic-address feed enforcement + refresh correctness (Batch A: #2049 + #2050)

Revision: r2 (2026-06-19) — #2049 enforcement-join RE-TARGETED from the
retired eBPF compiler (`pkg/dataplane/compiler.go`) to the runtime userspace
snapshot path (`pkg/dataplane/userspace/policies.go` +
`buildSnapshotWithSchedulerState`). A hostile re-review found the r1 join
point (`compileAddressBook` / `resolveAddrList` / `CompileResult.AddrIDs`)
is dead for forwarding: that compiler is the eBPF path retired in
#1373/#1476 and its `AddrIDs` never reach the AF_XDP helper. The #2050
refresh-correctness + fail-safe sections are unchanged (reviewed PLAN-READY
in r1).

Research branch: `research/review-015-triage`
Base: origin/master `ff38a92e1`
Source: `/tmp/codex-review-015.md` findings #1 (HIGH) and #2 (HIGH)
Companion-free research. Stops at PLAN-READY. NO production code changes here.

These two issues are batched because feed enforcement (#2049) is unsafe to
ship until the refresh path (#2050) can prove semantic-change detection and
last-good-snapshot behavior. A stale-but-enforced denylist/allowlist is worse
than an unenforced one.

---

## 1. Issue framing

### #2049 — feeds are status-only, never enforced (HIGH, security-real)

`security dynamic-address feed-server` + `address-name ... profile feed-name`
are parsed into `cfg.Security.DynamicAddress.{FeedServers,AddressBindings}`
(`pkg/config/compiler_services.go:176-239`). The daemon starts a feed manager
that fetches prefixes and registers an `onUpdate` callback
(`pkg/daemon/daemon_run.go:884-893`). The callback recompiles the **same
static active config** via `d.applyConfig(activeCfg)`. The fetched prefixes
live only in `feedState.prefixes` and are exposed by `Manager.GetPrefixes` —
which has **no production caller** in the forwarding path.

The runtime forwarding path is the AF_XDP userspace helper. The Go control
plane resolves address-books into a wire `ConfigSnapshot` that is published
to the helper via `apply_snapshot`. Address resolution for the helper happens
entirely in `pkg/dataplane/userspace/`:
- `buildSnapshotWithSchedulerState` (`builder.go:17`) assembles the snapshot
  and fills `AddressBooks` from `buildAddressBookTable(cfg)` (`builder.go:61-64`)
  and `Policies` from `buildPolicySnapshotsWithSchedulerState`.
- `buildAddressBookTable` (`policies.go:155`) builds the deduped
  `[]AddressBookSnapshot` rows + a `nameToID map[string]uint32`, reading
  **only `cfg.Security.AddressBook`** (it returns `nil, nil` when
  `AddressBook == nil`).
- `expandBookNameToCIDRs` (`policies.go:282`) resolves one name (recursively)
  to v4/v6 CIDRs, again reading **only `cfg.Security.AddressBook`**.
- `classifyPolicyAddresses` (`policies.go:110`) splits a policy's address
  tokens into `SourceBookIDs`/`DestinationBookIDs` (via `nameToID`) vs
  free-form `*Literals`; a token that is not in `nameToID` falls through to a
  CIDR/`any` literal. A feed-backed `address-name` is in neither the book nor
  a parseable CIDR, so it is silently emitted as a literal that matches
  nothing.
- `expandUserspacePolicyAddresses` (legacy back-compat field) likewise only
  expands AddressBook names.

The **retired** eBPF compiler `pkg/dataplane/compiler.go`
(`compileAddressBook` 431-521 / `resolveAddrList` 641-692 / `CompileResult.AddrIDs`)
is reached only via `CompileUserspaceShim`→`CompileConfig` (`loader.go:161`)
and its result is consumed solely for XDP attach / interface bookkeeping
(`attachUserspaceShimXDP`, `syncInterfaceAttachments`, `recordApplyResult`).
`AddrIDs` is **never** serialized into the snapshot and never reaches the
helper. The eBPF dataplane is retired (#1373/#1476). Joining feed prefixes
into `compileAddressBook`/`CompileResult.AddrIDs` (the r1 plan) would compile
cleanly and change **nothing** in the runtime forwarding path — a no-op fix.

Net effect today: a policy/NAT rule that references a feed-backed
`address-name` is emitted to the helper as a literal that matches nothing
(or, if a static address of the same name shadows it, silently uses the
static value). Refreshing the feed changes **nothing** in the dataplane.
This is a stored, periodically-refreshed **security** surface that does not
enforce.

This is NOT an explicitly-deferred feature: `docs/feature-gaps.md:134-138`
markets it ("xpf has dynamic address feeds"); the original feature
(`d89ad98c0`, #143) added parse + status + show but never the enforcement
join. There is no "not implemented" disclaimer in operator docs.

### #2050 — refresh compares count, ignores scanner errors (HIGH)

`pkg/feeds/feeds.go:205-235`:
- The scan loop (`bufio.Scanner`, default 64 KB token cap) has **no
  `scanner.Err()` check**. An overlong line (`bufio.ErrTooLong`) or a transport
  read error silently truncates the set.
- The new snapshot replaces `fs.prefixes` **unconditionally** and stamps
  `fs.lastFetch = now()` (marks "successful") even on a truncated/partial read.
- The callback fires only when `len(prefixes) != oldCount` — **count, not
  content**. A same-size content swap (`192.0.2.0/24` -> `198.51.100.0/24`) is
  silently dropped.
- `HoldInterval` (Junos "retain last-good for N seconds on failure") is parsed
  and displayed but never consumed.
- `pkg/feeds/` has **no test file**.

---

## 2. Blast radius

- `pkg/feeds/feeds.go` — refresh loop, snapshot type, status fields. New
  package split optional (see Path options).
- `pkg/dataplane/userspace/policies.go` — **PRIMARY join site.**
  `buildAddressBookTable` gains a feed-prefix overlay: for each
  `AddressBinding{Name, FeedNames}`, union the live feed snapshots into the
  bucket for that name (creating a bucket if the name is not also a static
  book entry) BEFORE ID assignment. The existing canonicalize/dedup/sort/hash
  path then assigns it an ID and emits an `AddressBookSnapshot` row, and
  `nameToID[name]` is populated so `classifyPolicyAddresses` routes the
  policy token into `SourceBookIDs`/`DestinationBookIDs` instead of a
  no-match literal. `expandBookNameToCIDRs` may also need to consult the
  overlay if a feed-backed name is referenced from inside an AddressSet
  (recursive membership). No new resolver package required — the overlay is a
  `map[string]feedPrefixes` argument threaded into `buildAddressBookTable`.
- `pkg/dataplane/userspace/builder.go` /
  `pkg/dataplane/userspace/manager.go` — thread the feed-prefix overlay
  through `buildSnapshotWithSchedulerState` (`builder.go:17`), which is called
  from `Manager.Apply`-side compile at `manager.go:571`. The overlay is read
  from a manager-held snapshot accessor (populated by the daemon from the feed
  manager) under `m.mu`, mirroring how `routeOverlay`/`activeState` are
  already threaded.
- `pkg/daemon/daemon_run.go` — the `onUpdate` callback already calls
  `d.applyConfig(activeCfg)`. The daemon must push the latest feed snapshots
  into the dataplane manager (via a `SetFeedSnapshots`-style setter, mirroring
  `SetRouteOverlay`) BEFORE/within `applyConfig`, so the overlay the compile
  reads is the just-refreshed content. `applyConfig` is hash-gated, but the
  snapshot content hash includes `AddressBooks` (see §2a), so a content change
  republishes.
- `pkg/config/types_security.go` — no struct change required for the join
  (the overlay is a runtime value, not config). Only touched if the
  OPTIONAL commit-check (P-A3) is included.
- `pkg/config` commit-check — OPTIONAL: validate that an `address-name`
  referenced by a policy is either in the AddressBook or bound to a feed (so a
  typo still fails commit; today a feed-backed name is legal config).
- Show surfaces (`server_show_security_text.go`, `api/show_text.go`) — add
  hash/last-error/stale fields (cosmetic, follows the new status type).

NOT touched: `pkg/dataplane/compiler.go` (retired eBPF compiler;
`compileAddressBook`/`resolveAddrList`/`CompileResult.AddrIDs` are dead for
forwarding — see §1). The r1 plan's compiler overlay is dropped entirely.

The snapshot build is on the commit + feed-refresh path, NOT the per-packet
path. `AddressBooks` is rebuilt from scratch on every snapshot
(`buildAddressBookTable` allocates fresh tables each call), so an overlay is a
natural extension — a stale feed set is never left behind.

### 2a. The duplicate-publish content-hash gate (WHY the join must be here)

`Manager.Apply` skips a redundant `apply_snapshot` when the new snapshot's
content hash equals `m.lastSnapshotHash`
(`snapshotContentHash`, `builder.go:82`; gate + setters at
`manager.go:126`, `:691-692`, `:887-890`, `process.go:336`/`:365`). The hash
is taken over a shallow copy with `Generation`, `FIBGeneration`,
`GeneratedAt`, `Config` (nil'd), and `Neighbors` (filtered) excluded — but it
**INCLUDES `AddressBooks`** (the `[]AddressBookSnapshot` rows are not zeroed).

This is the load-bearing reason the join MUST land inside
`buildAddressBookTable` / the snapshot build, NOT in `compiler.go`:

- A feed `onUpdate` re-runs `applyConfig` against the **same `*config.Config`**
  (the feed prefixes are NOT in the typed config). Everything else in the
  snapshot is byte-identical to the previous publish.
- If the feed overlay lands in `AddressBooks`, a content change (new/removed
  prefix) shifts the `AddressBookSnapshot` rows → the content hash changes →
  the gate lets the publish through → the helper enforces the new set.
- If the feed overlay landed anywhere that does NOT feed the snapshot (e.g.
  the retired `compiler.go`), the snapshot would be byte-identical, the hash
  would match `lastSnapshotHash`, and the duplicate-publish gate would
  **silently drop the refresh** — the worst case: it looks wired but every
  refresh after the first is suppressed.

A same-content refresh (identical prefixes) correctly produces an identical
hash and is correctly skipped (no wasted round-trip). This is the desired
behavior and aligns with #2050's hash-based change detection.

---

## 3. Concrete design

### #2050 first (refresh correctness — the safety gate)

Immutable snapshot + status split inside the feed manager:

```go
type Snapshot struct {
    Prefixes []string // canonicalized, deduped, sorted
    Hash     [32]byte // sha256 over the canonical join
    Count    int
}
type feedStatus struct {
    LastSuccess time.Time
    LastError   string
    StaleSince  time.Time // set when a fetch fails and we keep last-good
}
```

`fetchFeed` becomes:
1. HTTP GET (unchanged guards).
2. Scan with an explicit `scanner.Buffer(...)` raised cap + a max-prefix cap;
   **after the loop check `scanner.Err()`**. On error: record `LastError`,
   set `StaleSince` if not already, RETAIN the existing snapshot, do NOT
   replace, do NOT stamp success, return.
3. Canonicalize (parse to `net.IPNet`, normalize to masked form), dedup, sort,
   hash.
4. Compare new hash to current snapshot hash. Replace snapshot + stamp
   `LastSuccess` regardless (it IS a fresh good fetch); fire `onUpdate` **only
   if hash changed**.
5. Wire `HoldInterval`: if a feed has been failing longer than `HoldInterval`,
   optionally drop to empty (fail-closed) — see open question Q3.

### #2049 (enforcement — the join, RUNTIME userspace path)

A daemon-owned snapshot accessor joins `AddressBindings` to live feed
snapshots and threads a **feed-prefix overlay** into the userspace snapshot
build — NOT the retired eBPF compiler.

```go
// pkg/dataplane/userspace/policies.go
// buildAddressBookTable(cfg, feedOverlay) — feedOverlay is
// map[address-name] -> {v4, v6 CIDRs} resolved from the live feed snapshots
// of the AddressBinding's FeedNames.
//
// For each AddressBinding{Name, FeedNames} that has a live snapshot:
//   - resolve FeedNames -> union of canonical CIDRs (the overlay value)
//   - merge those CIDRs into the bucket for `Name` (create a bucket if the
//     name is not also a static book entry)
//   - the existing sort/dedup/canonicalize/hash/ID-assign path then emits an
//     AddressBookSnapshot row and sets nameToID[Name] = id
//
// classifyPolicyAddresses(cfg, nameToID, tokens) then routes the policy's
// feed-backed token into SourceBookIDs/DestinationBookIDs (it was previously
// dropped to a no-match literal because nameToID had no entry).
```

Threading: the overlay is read from a manager-held value (set by the daemon
from the feed manager, analogous to `routeOverlay`) and passed through
`buildSnapshotWithSchedulerState` (`builder.go:17`) →
`buildAddressBookTable` and `buildPolicySnapshotsWithSchedulerState`. Both
already receive `cfg`; add the overlay as one more argument.

`buildAddressBookTable` allocates fresh tables on every call, so the overlay
is recomputed on every commit AND every feed `onUpdate` → `applyConfig`.
Determinism (sorted names, content-hash bucketing, deterministic ID probe —
unchanged) keeps IDs stable across restarts for a given feed content; IDs may
shift when feed content changes, which is fine because the whole snapshot is
published atomically (`apply_snapshot`) and the content-hash gate (§2a)
forces the republish.

### Multiple Path Options

**P-A1 (snapshot location): in-place vs package split.**
Codex recommends splitting into `pkg/feeds/{fetch,parse,state}`. RECOMMENDATION:
do the snapshot/status/canonicalize refactor **in-place** in `pkg/feeds`
first (the package is ~240 LOC, one file, zero tests). A three-package split
is gold-plating for this size and adds merge surface; defer it unless the file
grows. Add the `Snapshot` type + a `snapshotForFeed(name) Snapshot` accessor;
that is the contract callers consume.

**P-A2 (no-snapshot-yet behavior): fail-closed vs retain-last-good.**
At daemon start, before the first successful fetch, a policy referencing a
feed-backed address resolves to an **empty set** (fail-closed):
- If the address is on the *source/match* side of an ALLOW policy -> matches
  nothing -> traffic falls through to the next policy / default-deny. Safe.
- If the address is referenced by a DENY/block policy -> empty set blocks
  nothing until the feed loads. This is the only "fail-open" window, and it is
  the *correct* Junos-equivalent behavior (the feed simply isn't loaded yet),
  and it is bounded by the first fetch (seconds). RECOMMENDATION: **empty-set
  fail-closed at startup, retain-last-good on later refresh failure** (#2050
  guarantees last-good is never replaced by a partial read). Document the
  startup window explicitly. A configurable `default-policy`-style override is
  out of scope.

**P-A3 (commit-time reference validation).** OPTIONAL: extend commit-check so a
policy referencing an `address-name` that is neither an AddressBook entry nor a
feed binding fails commit (today such a name passes commit and is silently
emitted to the helper as a no-match literal — it never matches and never
errors). RECOMMENDATION: include it — it converts a silent no-match into a
commit-time error, matching Junos.

---

## 4. Hidden invariants

- Address IDs in the userspace snapshot are content-derived, not sequential:
  `buildAddressBookTable` (`policies.go:223-252`) buckets names by canonical
  CIDR bytes, assigns `id = hash64 & 0xFFFFFFFF` (0 reserved → 1) with a
  deterministic linear probe on collision. The overlay must merge feed CIDRs
  into a name's bucket BEFORE bucketing/hash, so a feed-backed name shares an
  ID with a static book of identical content (the existing content-equality
  invariant) and the ID is stable for a given content. Do NOT invent a
  separate ID space — reuse the bucket pipeline.
- `buildAddressBookTable` rebuilds the whole table from scratch each call (no
  persistent map mutation), so the overlay runs within the same snapshot build
  — a stale feed set is never left behind. The published snapshot fully
  replaces the helper's address-book state (`apply_snapshot`).
- The content-hash dedup gate (§2a) includes `AddressBooks`. The overlay MUST
  land in those rows or the refresh is silently suppressed. This is the
  invariant that the r1 (compiler.go) join violated.
- The `onUpdate` callback runs on a feed-manager goroutine and calls
  `d.applyConfig` — that path must already be concurrency-safe with commit
  (it is; commit serializes via applySem). The manager-held feed-overlay
  accessor read MUST be under `Manager.mu` (mirror `routeOverlaySnapshot()`),
  and the daemon must set the overlay before/within the same `applyConfig`.
- Canonicalization must not reorder semantics: a `/32` host and a `/24` that
  contains it are distinct prefixes; dedup is exact-CIDR only. Feed prefixes
  pass through the same `sortV4/V6CIDRs` + `dedupSortedStrings` +
  `canonicalizeAddressBookContent` path as static book entries.
- HoldInterval default is 7200s (`types_security.go:29`); 0 means default, not
  "never retain". Wiring it must respect that.

## 5. Risk table

| Risk | Severity | Mitigation |
|------|----------|------------|
| Feed content change shifts book IDs mid-traffic | Med | Whole snapshot publishes atomically via apply_snapshot; helper swaps address-book state in one shot |
| Refresh silently suppressed by the content-hash dedup gate | High | Join lands in `AddressBooks` (in-hash); test asserts the published snapshot row changes on a same-config feed update (§2a, §6) |
| Startup fail-closed blocks legit traffic referenced by feed before first fetch | Low | Bounded to first-fetch window (seconds); ALLOW side is safe; document |
| Empty feed (HTTP 200, no lines) replaces good set with empty | Med | Treat zero-prefix successful fetch as suspicious -> Q3 (retain-last-good vs accept-empty config knob) |
| Canonicalization bug drops/mangles a prefix | Med | Round-trip parse + table tests; compare against raw lines in test |
| New status fields break existing show/JSON consumers | Low | Additive fields only |
| Overlay ID collision with static sets | Low | Content-hash bucket pipeline already de-collides via deterministic probe; identical-content feed+static share an ID by design |
| Per-refresh full snapshot rebuild cost on large feeds | Low | Refresh interval is >= seconds; snapshot build is not per-packet |

## 6. Test plan

#2050 (pkg/feeds, net-new test file):
- same-count content swap fires callback (hash differs)
- identical content does NOT fire callback
- overlong line -> scanner.Err -> last-good retained, no replace, no success stamp
- transport error mid-stream -> last-good retained
- duplicate lines canonicalize to one prefix
- invalid lines skipped, valid ones kept
- bare IP -> /32 and /128 normalization

#2049 (pkg/dataplane/userspace — assert against the published snapshot, NOT
legacy `result.AddrIDs`):
- `buildAddressBookTable(cfg, overlay{P1})` for a feed-backed `address-name`
  emits an `AddressBookSnapshot` row whose `PrefixesV4/V6` contain P1's CIDR,
  and `nameToID[name]` is set (non-zero).
- `buildPolicySnapshotsWithSchedulerState` for a policy referencing that
  feed-backed name yields a `PolicyRuleSnapshot` with the name's ID in
  `SourceBookIDs` (or `DestinationBookIDs`), NOT in `SourceLiterals` — proving
  `classifyPolicyAddresses` now routes it as a book reference.
- feed overlay P1 -> P2: the rebuilt snapshot's `AddressBookSnapshot` for that
  name contains P2 and not P1, and the `SourceBookIDs` entry follows the new
  content's ID.
- duplicate-publish gate (§2a): build snapshot S1 with overlay{P1}, then S2
  from the **same `*config.Config`** with overlay{P2}; assert
  `snapshotContentHash(S1) != snapshotContentHash(S2)` (so `Manager.Apply`
  republishes). Conversely, same-content overlay yields an equal hash (skip is
  correct).
- startup before first fetch -> overlay is empty for the name -> book row is
  empty (or absent) -> `classifyPolicyAddresses` still routes via a present
  (empty) book ID, policy present, no panic, no compile error (fail-closed:
  matches nothing).
- NAT path: a source-/destination-address-name backed by a feed resolves the
  same way (the NAT snapshot builders consume the same address resolution —
  verify the relevant `build*NATSnapshots` path or document if NAT uses a
  separate resolver that also needs the overlay).
- (P-A3) commit referencing an unknown address-name (neither book nor feed)
  fails commit-check.

## 7. Out of scope

- `pkg/feeds/{fetch,parse,state}` three-package split (P-A1 declined for now).
- SecIntel-format integration (`docs/feature-gaps.md:138`).
- A configurable "fail-open until first fetch" policy knob.
- Per-feed TLS pinning / auth headers (separate hardening).

## 8. Open questions

- **Q1**: Should a feed-backed `address-name` be allowed to ALSO appear in the
  static AddressBook (shadowing)? Recommend: reject at commit (ambiguous).
- **Q2**: ID stability across feed content change — acceptable to shift IDs, or
  must feed sets get a reserved high ID band? Recommend: shift is fine (the
  whole snapshot publishes atomically; IDs are content-derived, not a reserved
  band), simpler.
- **Q3**: Zero-prefix successful HTTP 200 — accept (empty enforced set) or treat
  as failure and retain last-good? Recommend: retain last-good + log warning;
  an explicit empty feed is rare and dangerous. Possibly a config knob later.
- **Q4**: HoldInterval semantics on permanent failure — after HoldInterval
  elapses with no good fetch, drop to empty (fail-closed) or keep last-good
  forever? Junos drops. Recommend match Junos (drop to empty after hold).

---

## 9. Hostile Claude-SMR self-review

**Is #2049 real and security-relevant? YES — and it is the highest-priority of
the four.** Verified end to end: the binding is stored, the prefixes are
fetched, and the **runtime userspace snapshot** genuinely cannot see them
(`GetPrefixes` has no forwarding caller; the snapshot's address resolution —
`buildAddressBookTable`/`expandBookNameToCIDRs`/`classifyPolicyAddresses` in
`policies.go` — reads only `cfg.Security.AddressBook`, so a feed-backed name is
emitted as a no-match literal). An operator who builds a threat-feed denylist
policy gets a config that commits and never enforces. That is a silent security
control failure on a marketed feature — worse than a missing feature, because
the operator believes it works. Not a candidate for KILL or DEFER.

**r1→r2 RE-TARGET (the hostile re-review catch):** the r1 plan put the join in
`pkg/dataplane/compiler.go` (`compileAddressBook` / `resolveAddrList` /
`CompileResult.AddrIDs`). I verified in this worktree that this is the RETIRED
eBPF compiler (#1373/#1476): it is reached only via
`CompileUserspaceShim`→`CompileConfig` (`loader.go:161`), and its `result` is
consumed solely for XDP attach + interface bookkeeping
(`attachUserspaceShimXDP`, `syncInterfaceAttachments`, `recordApplyResult`).
`AddrIDs` is never serialized into the `ConfigSnapshot` and never reaches the
AF_XDP helper. The r1 join would compile cleanly and forward nothing — a no-op
"fix." Worse, because the snapshot would be byte-identical, the
content-hash duplicate-publish gate (`snapshotContentHash`, `builder.go:82`,
which INCLUDES `AddressBooks`) would have suppressed every refresh anyway. The
join is re-targeted to `buildAddressBookTable` (`policies.go:155`) threaded via
`buildSnapshotWithSchedulerState` (`builder.go:17`, called at
`manager.go:571`). Confirmed by reading the three functions: all read only
`cfg.Security.AddressBook` today.

**Adversarial counter-argument I considered and rejected:** "Maybe this is
intentionally deferred and low-traffic." Rejected — `feature-gaps.md` markets
it as present, there is no deferral disclaimer, and the show output actively
reports prefix counts, which signals "this is live." That makes silent
non-enforcement a trust/security defect, not a known gap.

**Is the batch coupling correct? YES.** Shipping #2049 alone would enforce a
denylist that silently goes stale on same-size feed rotations (#2050) — a
classic "looks fixed, quietly broken" outcome. #2050 must land first or
together. Strong agree with Codex's Batch A.

**Where I push back on Codex's recommended fix:** the proposed
`pkg/feeds/{fetch,parse,state}` three-package split + a separate
`DynamicAddressResolver` package is over-engineered for a 240-LOC, zero-test
package. The *contract* that matters is the immutable feed snapshot + the
snapshot-build overlay in `buildAddressBookTable`, not the package count. I
down-scope to in-place refactor + one accessor + a snapshot-build overlay
threaded through `buildSnapshotWithSchedulerState`. This is a HOW
simplification, not a WHAT change.

**Sharpest risk:** the startup fail-closed window (P-A2) and the empty-feed
case (Q3). A naive implementation that accepts an HTTP-200-empty body as a
valid snapshot would let a misconfigured/hijacked feed endpoint **silently
disable** an enforced denylist by serving an empty file. The plan must treat
zero-prefix-after-success as retain-last-good (Q3), or this fix introduces a
new fail-open vector. Flagging this as a MUST-resolve before implementation,
not an open nicety.

**Verdict basis:** real, security-relevant, well-scoped once down-sized, with
one must-resolve safety question (Q3) that is answerable in design.

### Recommendation

- **#2050: PLAN-READY** — ship first (or together with #2049). Refresh
  correctness is small, self-contained, testable, and is the safety
  precondition for enforcement.
- **#2049: PLAN-READY (pending re-review)** — r2 re-targets the enforcement
  join to the RUNTIME userspace snapshot path
  (`pkg/dataplane/userspace/policies.go` `buildAddressBookTable` +
  `buildSnapshotWithSchedulerState`), NOT the retired eBPF compiler. Ship
  immediately after / with #2050, using P-A1 in-place + P-A2
  startup-fail-closed/retain-last-good + P-A3 commit validation. This is the
  highest-priority finding in review-015 and is a genuine
  security-enforcement gap on a marketed feature. Resolve Q3 (empty-feed =
  retain-last-good) in the design before coding. The re-targeted join needs a
  fresh hostile pass before implementation.
