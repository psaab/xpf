# pkg/feeds

Dynamic-address feed fetcher. Periodically pulls CIDR prefixes from HTTP
feed servers and triggers config recompile when the resolved set changes
**by content** (not merely by count).

## Entry points

- `Manager` — `feeds.go`.
- `New(updateFn)` — `feeds.go`. `updateFn` is `func() error`: it applies the
  fetched content to the dataplane and RETURNS the apply result. A rejected
  apply (non-nil error) is retried on the next identical refetch (#5646, below).
- `Apply(ctx context.Context, daCfg *config.DynamicAddressConfig)` — `feeds.go`. Reconciles the per-feed refresh goroutines; carries a persisted feed's last-good snapshot forward across the reconfigure (#5282, see below).
- `GetPrefixes(name)` — `feeds.go`. Returns the current enforced (last-good) snapshot.
- `StopAll()`, `FeedInfo`, `AllFeeds()` — surfaced to `show security dynamic-address`. `StopAll` is the shutdown path (cancels every producer, empties the map); `Apply` no longer routes through it (#5282).

## Day-2 reconcile (#5036)

`Manager.Apply` is driven by the daemon, not called once at boot. The daemon
constructs the manager **unconditionally** at startup (`ensureFeedManager`, even
with no feed servers) and calls `reconcileFeeds` on every applied config
generation (wired into `applyConfigLocked`, before the feed-overlay push).
`reconcileFeeds` is gated on a hash of the feed-**server** configuration
(`feedsConfigHash`, which excludes address bindings), so `Apply` re-runs only
when the server set actually changes — a feed **content** refresh (which
re-enters `applyConfig` via the `onUpdate` callback) leaves the hash unchanged
and does not restart the fetchers. Before #5036 the manager was built only if
boot-time feed servers existed and `Apply` was never re-invoked, so a feed
server added/removed/edited after boot was silently ignored until restart (a
deny policy bound to a day-2-added feed armed with zero prefixes — fail-open).

## Apply-time snapshot handoff — no fail-open window on reconfigure (#5282)

`Apply` reconciles the running producer set **without** dropping a persisted
feed's enforced prefixes. Before #5282 it called `StopAll` as its FIRST step,
which cancelled every producer and replaced `m.feeds` with an **empty** map;
the replacement `feedState`s started empty and fetched **asynchronously**. So
editing a deny feed's URL/interval instantly dropped its installed snapshot —
the overlay (`SnapshotForBindings`, joined into the dataplane address book)
compiled **match-none** from that instant until the new fetch landed. Worse, if
the new endpoint was down, `retainForever` (the #2050 default) pinned the
**empty** set indefinitely: a **fail-open denylist window** where traffic that
should be DENIED was ALLOWED — directly contradicting #2050's "never fail-open a
stale denylist" promise.

`Apply` now builds the desired plan first, then swaps the producer set under one
lock: it cancels every old producer (each captured its old URL/interval, so even
a persisted feed with an edited URL/interval needs a fresh refresh loop) but, for
each feed that **persists** (same name), carries its last-good enforced snapshot
forward into the replacement `feedState` (`carryForwardSnapshot`). The persisted
feed keeps enforcing its last-good prefixes until its NEW fetch **atomically**
replaces them (`installSnapshot`). Distinctions:

- **persisted feed** (same name, possibly new URL/interval) → last-good retained
  until the new fetch lands; if the new fetch FAILS, `retainForever` keeps the
  carried set installed indefinitely (never reverts to empty — #2050 preserved),
- **removed feed** (deleted from config) → no plan entry, no replacement, its
  snapshot is dropped (correct — the operator removed it),
- **brand-new feed** → no prior snapshot to carry; until its first successful
  fetch its binding is **omitted** from the enforcement overlay (#5645, below),
  so a referencing policy fails **closed**, not a match-none fail-open.

The atomic swap on a successful new fetch is unchanged, so the overlay compiler
never sees a torn prefix set. Retained FAILURE markers (`LastError`/`StaleSince`)
are intentionally NOT carried: the new endpoint gets a clean slate and the first
post-Apply fetch re-derives stale state, which also gives an opt-in
`hold-interval` a fresh window on the new endpoint rather than a partially-elapsed
one (strictly more conservative for the fail-open guard).

## First-fetch fail-closed — no match-none deny window (#5645)

`#5282` closes the fail-open window on a **reconfigure** (a persisted feed keeps
its last-good prefixes). `#5645` closes the sibling window on **first fetch**,
where there is no prior snapshot to keep. Before the fix, `SnapshotForBindings`
published a binding whose feeds had no installed snapshot as a **present-but-empty**
slice. The daemon compiled that direct feed-bound name into a **match-none**
address-book row — correct for a `permit` (permit-none), but a `deny` policy
referencing the name then **never fired**, so traffic it must block was PERMITTED
for the whole window until the first fetch succeeded (a firewall **fail-open**).
A blocked/failed first fetch (`retainForever` has nothing to retain) held that
window open indefinitely.

`SnapshotForBindings` now **omits** a binding unless **every** one of its feeds
has an installed snapshot. If **any** constituent is unready — before its first
successful fetch, an unknown/typo'd feed name, or after a hold-interval drop —
the whole binding is omitted rather than published with the ready subset or an
empty slice. A ready feed always installs ≥ 1 prefix (a zero-prefix fetch is
rejected — see below), so "no installed snapshot" is exactly `len(prefixes)==0`.
Leaving the name **unresolved** makes the policy lowering treat it as
unrepresentable (`addrRepresentable` → `__unsupported_address__` → whole-snapshot
preflight reject), so the referencing policy fails **closed** (previous-good
retained / fresh-boot default-deny) — the same action-agnostic contract `#3261`
gives an empty static book. A **persisted** feed carries its last-good snapshot
forward (`#5282`), so it still resolves to prefixes here and is still published;
the omission fires only for a binding with an unready feed.

**All-constituent readiness + static-alias taint (codex-182 residual).** The
first cut omitted a binding only when **all** its feeds were unready. Two residual
partial-deny fail-opens remained: (1) a **composite** binding unioning a ready
and an unready feed published only the ready subset — the unready feed's prefixes
were silently unmatched; and (2) when the binding name **also** exists as a
**static** address-book entry, omitting it from the overlay was not enough —
`buildAddressBookTableWithFeeds` still built the static name/ID, so a `deny`
enforced only the static subset. The fix now requires **all** constituents ready
(case 1), and the userspace `addrRepresentable` treats a **declared**
dynamic-address binding that is **absent** from the overlay as unresolved →
unrepresentable → fail-closed **even when a static alias of the same name
exists** (case 2). A third residual arm of the same class was closed in **#5753**:
a declared binding nested **inside an address-set** that also carries a static
alias of that name stayed fail-open because the recursive representability walk
(`nameRepresentability`) did not receive the binding set and resolved the static
alias instead. That walk is now threaded `cfg.Security.DynamicAddress.AddressBindings`
so the **nested** member gets the SAME declared-but-unresolved guard the top level
has — an unready binding taints the enclosing set → the `deny` fails closed
instead of narrowing to the partial static subset. A **ready** feed (present in
the overlay) and a static member with **no** declared binding of that name are
unaffected. Only the referencing security **policy** path is gated this way; NAT
rules that reference an unready feed still fall back to the static subset (out of
scope for the deny fail-open this issue names).

## Hold-interval fail mode per binding (#9689)

An explicit `hold-interval` drops a failing feed's last-good snapshot to empty,
and under #5645 the binding built on it is then **omitted**. Every policy that
references it becomes unrepresentable, and the whole snapshot is rejected, so
the previous-good snapshot stays enforced. That is the right fail direction for
a denylist, and it has three costs:

- an **allowlist** keeps permitting the addresses the feed stopped publishing;
- **later commits** are not enforced either, because every snapshot carries
  the same unrepresentable rule;
- `show security dynamic-address` reported the cleared live set while the
  last-good one was enforced.

`set security dynamic-address address-name <n> profile fail-mode drop` lets the
operator choose the other direction for a binding:

- `retain` (the default, and what an omitted leaf means) keeps the behaviour
  above;
- `drop`: once **every** unready constituent was dropped by its hold-interval,
  `SnapshotForBindings` publishes the binding with the remaining feeds'
  prefixes, possibly none. Policy lowering already treats a present empty row as
  match-none (#2049), so an allowlist becomes permit-none and a denylist
  deny-none, and the rest of the snapshot is enforced.

`drop` never covers a feed with **no first snapshot**, or an unknown feed name.
Those keep #5645's fail-closed omission, because nothing was ever enforced for
them to drop. `feedState.holdDropped` is what tells a hold drop from a
never-fetched feed; it is set in `recordFailure`'s drop branch and cleared by
the next successful install.

The show surface now prints the hold interval as it is applied (an omitted
`hold-interval` retains indefinitely; the 7200s default it used to print was
never enforced). It also prints `HOLD-DROPPED` or `STALE` per feed, and each
binding's fail mode and enforced state.

## Publication-debt retry — a rejected apply is retried, not swallowed (#5646)

The `onUpdate` callback drives the daemon to APPLY the fetched feed content to
the dataplane, and that apply can be **rejected** — a whole-snapshot preflight
reject (`#3261`/`#5645`), a compile failure, or a transient control-socket
error. Before `#5646` `installSnapshot` committed the fetched content hash and
then fired a **void** `onUpdate`, so a rejected apply left the hash committed:
every later refetch of the (still-good, still-unapplied) **identical** content
saw "unchanged hash" and **skipped** `onUpdate`. The good content then sat
un-enforced indefinitely — **publication debt** — because the provider keeps
serving the same body (hash never changes again) and the default refresh is
hourly. The intended feed/policy silently failed open until an unrelated commit
or a genuine content change happened to re-drive the apply.

The fix decouples the **installed-content** hash from the **published** hash:

- `onUpdate` now returns `error` (`func() error`). A nil return means the apply
  was **accepted**; a non-nil return means it was **rejected**. The production
  callback (`ensureFeedManager`, `daemon_feeds.go`) returns the result of
  `applyConfigResult` (an error-returning sibling of `applyConfig`).
- `feedState.publishedHash` / `hasPublished` track the hash last **confirmed
  applied**. `installSnapshot` always commits `fs.hash` to the freshly-fetched
  content (so the display/`#5282`-carry hash stays truthful), but fires
  `onUpdate` whenever the fetched content differs from `publishedHash` — **not**
  from `fs.hash`. `publishedHash` advances **only** on a nil (accepted) return.
- A **rejected** apply therefore leaves `publishedHash` stale, so the next
  identical refetch re-evaluates `needsPublish == true` and **retries** the
  apply. The retry fires on the normal refresh cadence — one publish attempt per
  fetch, never a tight loop.
- A **successfully-applied** feed has `publishedHash == fs.hash`, so an
  identical refetch is suppressed (`needsPublish == false`) — **no thrash** and
  no busy-loop, preserving the `#5282` no-re-fire-on-carry-forward contract
  (`carryForwardSnapshot` inherits `publishedHash`/`hasPublished`).
- The **hold-interval drop-to-empty** (`recordFailure`) resets
  `publishedHash`/`hasPublished`, so a later recovery (refetch of the prior
  content) re-fires `onUpdate` and re-enforces the recovered set rather than
  seeing a stale published hash and suppressing the re-apply.

## Refresh correctness & fail-safe behavior (#2050)

A fetch is treated as **successful** only when the transport read completes
without error **and** the parsed set is non-empty. On any failure the manager
applies a *retain-last-good* policy rather than installing a partial/empty set:

- **scanner errors fail the fetch.** The body is scanned with a raised
  per-line cap (`maxLineBytes`, 1 MiB); an overlong line (`bufio.ErrTooLong`)
  or a mid-stream read error returns an error. The whole read fails — a
  truncated set is never installed. `scanner.Err()` is checked after the loop.
- **body-size + entry caps bound the fetch (#3934).** The response body is
  read through an `io.LimitReader` capped at `maxFeedBodyBytes` (32 MiB) and the
  parsed set is capped at `maxFeedPrefixes` (1,048,576 entries). A body larger
  than the size cap, or one producing more than the entry cap, fails the whole
  fetch (retain last-good) rather than buffering an arbitrarily large body into
  memory or installing a partial-but-huge set. This closes a remote OOM DoS: a
  feed server (or a MITM on a plaintext-http feed) returning a huge/infinite
  body cannot exhaust daemon memory. The size cap sits well under the 64 MiB
  userspace-dp control-request cap (`MaxControlRequestBytes`, #2744) so a single
  feed cannot dominate the apply snapshot. The 30 s client timeout
  (`httpClientTimeout`) bounds a slow-loris server that dribbles bytes.
- **plaintext-http feeds are warned (#3934).** A feed URL using `http://`
  (no transport integrity — a MITM can substitute the body) logs a one-time
  `slog.Warn` at `Apply`. `https` is strongly preferred for any feed source.
- **content-based change detection, keyed off the last *published* set (#5646).**
  Prefixes are canonicalized (parsed to masked CIDR / `/32` / `/128`), deduped,
  sorted, and SHA-256 hashed. The `onUpdate` recompile callback fires whenever
  the fetched content differs from what was last **successfully applied** — a
  same-count content swap (`192.0.2.0/24` -> `198.51.100.0/24`) fires; a
  reordered but identical set does not. See "Publication-debt retry" below for
  why the trigger keys off the *published* hash, not merely the last-fetched
  hash.
- **no success stamp on a partial/errored read.** `LastFetch`/`LastSuccess`
  are stamped, and the active snapshot replaced, only on a complete successful
  fetch. A failed fetch records `LastError` and leaves the snapshot untouched.
- **zero-prefix HTTP 200 is suspect.** An HTTP-200 body that parses to zero
  usable prefixes is treated as a failure (retain last-good), so a hijacked or
  misconfigured endpoint serving an empty file cannot silently fail-open an
  enforced denylist.
- **`hold-interval` is the opt-in timed drop (default: retain forever).**
  On a fetch failure the last-good snapshot is retained from `StaleSince`.
  By default (`hold-interval` unset) it is retained **indefinitely** — it is
  never auto-dropped to empty — so a stale denylist cannot silently
  fail-open. This is the operator-chosen posture and deliberately diverges
  from Junos hold-interval-then-drop. Only when `hold-interval` is explicitly
  configured > 0 does the snapshot drop to empty after that interval elapses
  (clearing `StaleSince`/`Hash`) and fire an `onUpdate`.

  **The drop does NOT make enforcement see an empty set (#9527).** The
  dropped feed has no installed snapshot, so `SnapshotForBindings` omits every
  binding built on it. Here is what follows for an enforced policy that
  references such a binding:
  - The policy lowers to `__unsupported_address__`.
  - The helper's integrity preflight rejects the WHOLE snapshot.
  - The dataplane keeps the previous-good state (fresh boot: default-deny).
  - The same holds for later commits, until the feed recovers or the reference
    is edited out.

  So the last-good prefixes stay enforced, whichever way the feed is used: a
  denylist keeps DENYING them, and an allowlist keeps PERMITTING them. Only
  `show security dynamic-address`, which reads the live set, goes empty. A
  binding that no enforced policy references carries no enforcement either way.
  Retaining previous-good is #5645's decision. A per-binding fail mode
  (retain, versus drop to an enforced empty set) is not implemented.
- **an out-of-range interval falls back; it never wraps (#8597).**
  `update-interval` and `hold-interval` are bounded to
  `[1, config.MaxDurationSeconds]` by the strict schema, but the compiler
  stores them as a raw `strconv.Atoi` int and the tolerant Load /
  HA-sync ingress downgrades an out-of-range value to a warning (#1960),
  so the runtime cannot assume the bound. `time.Duration(n) *
  time.Second` overflows int64 nanoseconds past `MaxDurationSeconds` and
  the residue can be small and POSITIVE — the half a `<= 0` check cannot
  see. `feedIntervalSeconds` / `resolveHoldInterval` therefore range-check
  before the multiply and fall back (never clamp to the maximum, per the
  #6769 reasoning: a value this far out is a typo or a hostile config,
  not a request for the largest window allowed).
  The direction matters most for `hold-interval`: falling back to
  `retainForever` KEEPS a stale denylist enforced, where the wrap turned
  "retain forever" into "drop to empty after 512 nanoseconds of failure"
  — an inversion of the #2050 posture above.
- **startup is fail-closed.** Before the first successful fetch there is no
  snapshot; `GetPrefixes` returns empty. A policy referencing a feed-backed
  address resolves to nothing until the first good fetch (bounded to seconds).
- **mixed valid/invalid bodies are observably degraded (#2993).** A body that
  mixes valid prefixes with malformed lines still installs the valid prefixes
  (a clean body is bit-identical to before), but the skipped invalid lines are
  no longer *silent*: `parseFeed` counts every malformed (non-comment, non-CIDR,
  non-IP) line and keeps a bounded sample (`maxInvalidSample`, 5).
  `FeedInfo` surfaces `InvalidLines`, `InvalidSample`, and `Degraded`
  (`InvalidLines > 0`); `show security dynamic-address` prints a `DEGRADED`
  line. A degraded install logs one `slog.Warn` on the content change (not every
  tick). This is **skip-with-count + degraded status**, not all-or-nothing: a
  provider bug that mangles one line of a denylist still enforces the rest, but
  the operator can see (and alarm on) that the installed set differs from the
  published feed instead of it reporting a clean success. The markers are
  cleared when a later clean body installs, and on a `hold-interval`
  drop-to-empty.
- **the invalid-line sample is byte-bounded, not just count-bounded (#4922).**
  The scanner admits a malformed line up to `maxLineBytes` (1 MiB), so the
  pre-#4922 code — which retained the first 5 offenders *verbatim* — let one
  feed pin ~5 MiB of garbage in memory (kept in `feedState`, deep-copied by
  `AllFeeds`) and emit multi-MB `slog.Warn` records on the degraded warning, all
  within the advertised feed limits. Each retained sample entry is now bounded
  at the retention point (in `parseFeed`, so `installSnapshot`/`AllFeeds`/the
  `slog.Warn` all inherit the bounded form): the offending line is truncated to
  its first `maxInvalidSampleBytes` (256) raw bytes, `strconv.Quote`-escaped so
  NULs / control bytes / newlines / invalid UTF-8 render as printable `\x..`
  escapes (never raw control bytes into a log or CLI show), and a truncated line
  is annotated with its **original byte length** (`… (<n> bytes total)`) so an
  operator can still triage "line was 1 MiB, starts with `<prefix>`" without
  retaining the whole thing. A short line (< the cap) is retained
  quoted-but-otherwise-intact. A per-entry ceiling (`maxInvalidSampleEntryBytes`)
  and an aggregate budget (`maxInvalidSampleTotalBytes`, the count cap × the
  per-entry cap) are the hard ceilings; the existing count bound (5) and
  changed-degraded-only logging are unchanged.

`FeedInfo` carries additive status fields (`LastSuccess`, `LastError`,
`StaleSince`, `Hash`) alongside the legacy `URL`/`Prefixes`/`LastFetch`.

## Where a credential may be placed in a feed URL (#7406)

A `feed-server` has **no credential leaf**. The entire leaf set is `url`,
`hostname`, `update-interval`, `hold-interval` and `feed-name <name> path`
(`pkg/config/schema_security.go`), so a provider's subscription key has nowhere
to go but the URL itself. This is what makes a feed different from a DDNS
provider, which always has a dedicated `config.Secret` leaf (`password`,
`api-token`, `aws-secret-key`) to hold the credential — `pkg/ddns/README.md`
tells operators to put it there, and **that advice does not transfer here**.

`FeedServer.MarshalJSON` and `FeedEntry.MarshalJSON` (#6703) run `url` and each
`path` through `config.RedactURL` on the JSON route, and `urlLeafIndices`
(#7406) does the same on the AST route behind `show configuration`, the gRPC
config RPCs and the REST config reads. Between them, every placement
`RedactURL` understands is covered on every config-read surface:

    https://feeds.example.com/list.txt?token=SECRET  ->  ...?<redacted>
    https://user:SECRET@feeds.example.com/list.txt   ->  https://<redacted>@...
    https://feeds.example.com/list.txt#SECRET        ->  ...#<redacted>

A key that **is** a host label or a path segment is rendered **verbatim**:

    https://SECRET.feeds.example.com/list.txt        <-- rendered verbatim
    https://feeds.example.com/SECRET/list.txt        <-- rendered verbatim

(the `hostname` leaf is the first case). This is not a redactor bug.
`https://SECRET.feeds.example/l.txt` and `https://cdn.feeds.example/l.txt` are
indistinguishable strings, so any rule that hides the first hides the host and
path of every feed — the diagnostic payload that makes a redacted URL worth
printing at all.

**Operator consequence:** if a feed provider keys on a hostname label or a path
segment, that key is visible to anyone who can read the configuration (`show
configuration`, `GET /api/v1/config`, `show security dynamic-address`) and no
placement avoids it. Treat such a configuration as sensitive. Where the
provider offers a query-string or userinfo form, prefer it — those are redacted.

## Callers

`pkg/daemon` (compile-cycle integration), `pkg/grpcapi` (status queries).

## Dependencies

`pkg/config` only.

## Gotchas

- HTTP client timeout is 30 s (`httpClientTimeout`, slow-loris protection).
  Timeouts log a warning but do not stop the manager — the next refresh tick
  retries.
- Multiple feeds can share a server; each feed's path is appended to the
  base URL.
- Default refresh interval is 1 hour; the Junos config can override via
  `update-interval`.
- Feed bodies are parsed line-by-line, one CIDR per line. Comment lines
  (`#`, `//`) and blanks are skipped silently. A malformed non-comment line
  is skipped but **counted** (`InvalidLines`/`InvalidSample`, marks the feed
  `Degraded`, #2993) — it is no longer a silent drop. Each `InvalidSample`
  entry is a byte-bounded, `strconv.Quote`-escaped prefix (≤
  `maxInvalidSampleBytes` raw bytes) plus the original byte length, NOT the
  verbatim line (#4922) — so a hostile provider serving near-1-MiB malformed
  lines cannot pin megabytes in memory or emit multi-MB log records. A
  *scanner-level* error (overlong line / read error) is NOT skipped: it fails
  the whole fetch (retain last-good).
- A successful fetch always replaces the snapshot and stamps success, but
  the `onUpdate` recompile fires only when the canonical content hash differs
  from the last **successfully-applied** set — not on every fetch, not merely on
  a count change, and (per #5646) not suppressed by a prior **rejected** apply of
  the same content (which is retried on the next refetch). See "Publication-debt
  retry" above.
- **Feed size vs. the dataplane control-socket cap (#2744 / #3934):** feed
  prefixes are carried inline as CIDR text in the userspace-dp `apply_snapshot`
  (`buildAddressBookTableWithFeeds`, `pkg/dataplane/userspace/policies.go`).
  Each feed is now bounded at fetch time by BOTH a total body-size cap
  (`maxFeedBodyBytes`, 32 MiB) and a total-entry cap (`maxFeedPrefixes`,
  1,048,576) (#3934), so a single feed can no longer buffer an unbounded body
  or dominate the serialized snapshot. The control socket separately caps a
  single request at `MaxControlRequestBytes` (64 MiB, in lockstep with the Rust
  `MAX_CONTROL_REQUEST_BYTES`); at ~45 B per IPv6 CIDR that covers ~1.4M
  prefixes. The per-feed 32 MiB body cap keeps a single feed's serialized
  contribution comfortably under that ceiling. A snapshot past the control cap
  is still surfaced as a config error at apply time (Go pre-flight in
  `pkg/dataplane/userspace/process.go`) rather than silently rejected by the
  helper after commit.

## A default-route entry is refused (#9248)

`parseFeed` refuses a line whose CANONICAL prefix -- the string that would be
installed -- is the whole IPv4 or IPv6 address space: `0.0.0.0/0`, `::/0`, and
mapped forms such as `::ffff:0:0/96`, which renders as `0.0.0.0/0`. Feed prefixes become the address set a policy MATCHES
(`pkg/dataplane/userspace` `policies_lower.go` / `policies_addrbook.go`), so a
single default-route line in content this box does not author would turn every
policy on that dynamic address into "match anything": a permit fails open and a
deny drops everything.

- When the response ALSO carries usable prefixes, the refused line is counted
  and sampled exactly like a malformed line (`InvalidLines`, `InvalidSample`
  with a `default route refused:` prefix), so the installed feed reports
  `Degraded` instead of a clean success.
- A feed whose ONLY entries were refused default routes fails its fetch with a
  reason that names them ("whole-address-space entries are refused"). That is
  a fetch FAILURE, not a degraded install: it shows in `LastError`, while
  `Degraded`, `InvalidLines` and `InvalidSample` keep describing the last-good
  snapshot still enforced -- a clean last-good feed keeps reading
  `Degraded=false`. The feed's existing failure handling applies: the last-good set stays enforced
  until that handling's own hold-interval expiry drops it, as for any failing
  feed.
- The boundary is an accidental whole-space line, not a hostile provider: a
  feed listing `0.0.0.0/1` and `128.0.0.0/1` covers the same space and is
  installed.
- Only `/0` is refused. Short but real prefixes still install -- bogon lists
  carry `224.0.0.0/3`-shaped entries, and a higher floor would silently empty
  them.
