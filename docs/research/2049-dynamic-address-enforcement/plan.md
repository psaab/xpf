# Plan: Dynamic-address feed enforcement + refresh correctness (Batch A: #2049 + #2050)

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
static active config**. The fetched prefixes live only in `feedState.prefixes`
and are exposed by `Manager.GetPrefixes` — which has **no production caller**.

The dataplane compiler (`pkg/dataplane/compiler.go`):
- `compileAddressBook` (431-521) only reads `cfg.Security.AddressBook`.
- `resolveAddrList` (641-692) resolves names only via `result.AddrIDs` and
  returns `fmt.Errorf("address %q not found")` (lines 661, 682) for any name
  that is not in the AddressBook.

Net effect: a policy/NAT rule that references a feed-backed `address-name`
either fails compile ("address not found") or, if a static address of the same
name shadows it, silently uses the static value. Refreshing the feed changes
**nothing** in the dataplane. This is a stored, periodically-refreshed
**security** surface that does not enforce.

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
- `pkg/daemon/daemon_run.go` — wire a resolver between feed snapshots and the
  dataplane apply path. The `onUpdate` callback already calls `applyConfig`;
  the resolver must be consulted inside the compile so a refresh actually
  changes the compiled output.
- `pkg/dataplane/compiler.go` — `compileAddressBook` gains a dynamic-address
  overlay; `CompileResult.AddrIDs` gains feed-backed names. `resolveAddrList`
  unchanged if dynamic names land in `AddrIDs` with real IDs.
- `pkg/config/types_security.go` — possibly a snapshot-passing contract.
- `pkg/config` commit-check — OPTIONAL: validate that an `address-name`
  referenced by a policy is either in the AddressBook or bound to a feed (so a
  typo still fails commit; today a feed-backed name is legal config).
- Show surfaces (`server_show_security_text.go`, `api/show_text.go`) — add
  hash/last-error/stale fields (cosmetic, follows the new status type).

The dataplane compile is on the commit + feed-refresh path, NOT the per-packet
path. Address-book maps are already cleared+repopulated each compile
(`ClearAddressBookV4/V6/Membership`), so an overlay is a natural extension.

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

### #2049 (enforcement — the join)

A daemon-owned resolver joins `AddressBindings` to live snapshots and feeds an
**overlay** into the dataplane compile:

```go
// pkg/dataplane/compiler.go (or a new dynaddr overlay)
// For each AddressBinding{Name, FeedNames}, union the snapshots of FeedNames
// into a deterministic implicit address-set, assign it an AddrID, and write
// membership for each CIDR. The address-name then resolves like any AddressBook
// set in resolveAddrList.
```

The compile already clears+rebuilds address maps each pass, so the overlay is
recomputed every commit AND every feed `onUpdate` -> `applyConfig`. Determinism
(sorted names, sorted prefixes) keeps IDs stable across restarts within a given
feed content; IDs may shift when feed content changes, which is fine because
the whole policy set recompiles atomically.

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
feed binding fails commit (today a feed-backed name passes commit and only
fails at dataplane compile). RECOMMENDATION: include it — it converts a runtime
"address not found" compile error into a commit-time error, matching Junos.

---

## 4. Hidden invariants

- Address IDs are assigned 1-based, deterministic by sorted name
  (`compiler.go:450-519`). The dynamic overlay MUST assign IDs from the same
  `result.nextAddrID` counter AFTER static addresses/sets to avoid collisions.
- `compileAddressBook` clears `address_book_v4/v6` + membership at the top of
  every compile. The overlay must run within the same compile pass (so a stale
  feed set is never left behind).
- The `onUpdate` callback runs on a feed-manager goroutine and calls
  `d.applyConfig` — that path must already be concurrency-safe with commit
  (it is; commit serializes via applySem). Verify the resolver read of the
  snapshot is under `Manager.mu` (it is via the accessor).
- Canonicalization must not reorder semantics: a `/32` host and a `/24` that
  contains it are distinct prefixes; dedup is exact-CIDR only.
- HoldInterval default is 7200s (`types_security.go:29`); 0 means default, not
  "never retain". Wiring it must respect that.

## 5. Risk table

| Risk | Severity | Mitigation |
|------|----------|------------|
| Feed content change shifts AddrIDs mid-traffic | Med | Whole policy set recompiles atomically; dataplane swap is already atomic per compile |
| Startup fail-closed blocks legit traffic referenced by feed before first fetch | Low | Bounded to first-fetch window (seconds); ALLOW side is safe; document |
| Empty feed (HTTP 200, no lines) replaces good set with empty | Med | Treat zero-prefix successful fetch as suspicious -> Q3 (retain-last-good vs accept-empty config knob) |
| Canonicalization bug drops/mangles a prefix | Med | Round-trip parse + table tests; compare against raw lines in test |
| New status fields break existing show/JSON consumers | Low | Additive fields only |
| Overlay ID collision with static sets | Med | Single shared nextAddrID counter; test asserts disjoint IDs |
| Per-refresh full recompile cost on large feeds | Low | Refresh interval is >= seconds; compile is not per-packet |

## 6. Test plan

#2050 (pkg/feeds, net-new test file):
- same-count content swap fires callback (hash differs)
- identical content does NOT fire callback
- overlong line -> scanner.Err -> last-good retained, no replace, no success stamp
- transport error mid-stream -> last-good retained
- duplicate lines canonicalize to one prefix
- invalid lines skipped, valid ones kept
- bare IP -> /32 and /128 normalization

#2049 (pkg/dataplane + integration):
- feed snapshot with prefixes P1 -> policy referencing the address-name
  compiles to a set containing P1's CIDR
- feed update P1 -> P2 -> recompile -> compiled set contains P2, not P1
- NAT rule referencing a feed-backed source-address-name resolves
- startup before first fetch -> empty set, no compile error, policy present
- (P-A3) commit referencing an unknown address-name (neither book nor feed)
  fails commit-check

## 7. Out of scope

- `pkg/feeds/{fetch,parse,state}` three-package split (P-A1 declined for now).
- SecIntel-format integration (`docs/feature-gaps.md:138`).
- A configurable "fail-open until first fetch" policy knob.
- Per-feed TLS pinning / auth headers (separate hardening).

## 8. Open questions

- **Q1**: Should a feed-backed `address-name` be allowed to ALSO appear in the
  static AddressBook (shadowing)? Recommend: reject at commit (ambiguous).
- **Q2**: ID stability across feed content change — acceptable to shift IDs, or
  must feed sets get a reserved high ID band? Recommend: shift is fine (atomic
  recompile), simpler.
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
fetched, and the dataplane compile genuinely cannot see them (`GetPrefixes` has
zero callers; `resolveAddrList` errors on the name). An operator who builds a
threat-feed denylist policy gets a config that commits (or fails confusingly)
and never enforces. That is a silent security control failure on a marketed
feature — worse than a missing feature, because the operator believes it works.
Not a candidate for KILL or DEFER.

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
package. The *contract* that matters is the immutable snapshot + the
compile-time overlay, not the package count. I down-scope to in-place refactor
+ one accessor + a compiler overlay. This is a HOW simplification, not a
WHAT change.

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
- **#2049: PLAN-READY** — ship immediately after / with #2050, using P-A1
  in-place + P-A2 startup-fail-closed/retain-last-good + P-A3 commit
  validation. This is the highest-priority finding in review-015 and is a
  genuine security-enforcement gap on a marketed feature. Resolve Q3
  (empty-feed = retain-last-good) in the design before coding.
