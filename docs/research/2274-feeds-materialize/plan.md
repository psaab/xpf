# #2274 — dynamic-address feed materialization: plan-of-action

## 1. Status

**PLAN-KILL (duplicate of #2049 — already shipped).**

The feature #2274 asks for — materialize fetched dynamic-address feed
prefixes into the address/policy compilation path so a security policy
`match source-address <feed-name>` enforces the feed CIDRs — is **already
implemented, wired end-to-end, and covered by non-tautological tests** on
`origin/master`. It landed via **PR #2058 (issue #2049)**, merged
**2026-06-20 14:42 UTC**, the day BEFORE #2274 was filed
(**2026-06-21 22:57 UTC**).

#2274 is a re-discovery of the *symptoms* #2049 documented, produced by
grepping the same two stale/wrong code paths the original #2049 evidence
cited (`feeds.GetPrefixes` — never the enforcement accessor — and the
**retired eBPF** `pkg/dataplane/compiler.go::compileAddressBook`), while
the live enforcement path (`SnapshotForBindings` →
`buildAddressBookTableWithFeeds`) had been wired in #2058 ~32 hours
earlier and was not inspected.

Recommended action: **close #2274 as a duplicate of #2049**, with a
pointer to the merge commit `d6aa5f792` (PR #2058) and the live call
chain below. No code change. (If anything, a one-line clarifying comment
in `pkg/dataplane/compiler.go::compileAddressBook` noting the userspace
overlay lives in `policies.go` could prevent the next audit from
re-filing — captured as an optional doc-only follow-up in §10, NOT part
of this kill.)

## 2. Issue framing

#2274 (MEDIUM, bug) claims:

1. `feeds.Manager.GetPrefixes` (feeds.go:204) has zero production callers.
2. `pkg/dataplane/compiler.go::compileAddressBook` has no dynamic-address
   / feed / GetPrefixes reference.
3. `compiler_policy*.go` has no dynamic-address reference, so a policy
   cannot resolve a `dynamic-address-name` to feed prefixes.
4. Therefore the feed refresh recompile re-runs a normal compile that
   ignores feeds; fetched prefixes never reach the dataplane; the feature
   is fetch-only; #143's promised materialization is absent.

Claims (1) and (2) are **literally true but irrelevant**. Claim (3) and
the conclusion (4) are **false** on the current tree:

- `GetPrefixes` is genuinely caller-less in production — but it is NOT the
  enforcement accessor. The enforcement accessor is
  `feeds.Manager.SnapshotForBindings` (feeds.go:241), added by #2049
  commit `edf03ed42`, explicitly documented as "the first production
  caller of the per-feed prefix snapshot — before #2049 the fetched
  prefixes were status-only and never reached the forwarding path."
  `GetPrefixes` survives only for the status/show path semantics and
  tests; its zero-caller status is a (correct) observation about a
  different function than the one that does the work.

- `pkg/dataplane/compiler.go::compileAddressBook` builds the **legacy
  eBPF `CompileResult`** address-ID/membership maps. Post-#1373/#1476 the
  eBPF dataplane is retired; that `CompileResult` is still produced (it
  is used for commit-time validation and book-keeping — `loader.go:169`,
  `userspace/legacy_dataplane.go:183` call `Compile`), but it is **NOT**
  the address book the AF_XDP helper enforces. The enforced address book
  is the wire `ConfigSnapshot.AddressBooks`, built by
  `pkg/dataplane/userspace/policies.go::buildAddressBookTableWithFeeds`,
  which DOES consume the feed overlay. The audit inspected the wrong
  builder.

The proof is the issue timeline plus the merge: **#2049's own "Evidence"
section uses the identical three grep findings as #2274** (GetPrefixes
no-caller; daemon onUpdate recompile; compileAddressBook no
DynamicAddress awareness). #2049 was then FIXED by #2058 and CLOSED.
#2274 re-states #2049's pre-fix evidence as if it were current.

## 3. Scope / value

If the feature were genuinely missing, the value would be HIGH (an
advertised security control — threat-feed denylists / allowlists — would
be inert). But it is present and enforced. The residual *value of any
#2274 work* is therefore approximately zero on the production path:

- No new enforcement is needed.
- No new policy-reference grammar is needed (it already resolves).
- No new wire field is needed.

The only non-zero-value artifact this research can produce is the audit
trail proving the feature is shipped, plus an optional doc breadcrumb so
the same false positive is not re-filed a third time. That is doc-only
and out of scope for a MEDIUM bug fix; it does not justify a code PR.

**Two narrower, UNVERIFIED concerns surfaced during the hostile review
(neither rescues #2274 as filed; file separately if wanted):**

- **NAT-rule dynamic-address reference (UNVERIFIED).** #2274's
  fix-direction mentions "policy/NAT dataplane address sets." The shipped
  #2049 overlay backs the POLICY `nameToID` path. Whether a NAT rule can
  reference a `dynamic-address-name` in this codebase, and whether such a
  reference would resolve the feed via the userspace overlay (vs the
  retired-eBPF `CompileResult`), was NOT exhaustively proven in this
  research. It is a DISTINCT, unproven concern — and real-world usage
  (vsrx.conf) references the dynamic-address names only as policy
  `source-address`, never in NAT pools. It does not make #2274's stated
  bug ("a security policy cannot resolve a dynamic-address-name") true.
  If desired, file as its own feature/verification issue, not as #2274.
- **Feed-refresh apply cost (perf, out of scope).** The feed `onUpdate`
  callback re-enters the FULL `applyConfig`, not the surgical in-place
  republish. The duplicate-publish content-hash gate skips no-op
  refreshes, so the common case is cheap; a content-changing refresh
  reshapes the books/policy sections via a full apply. Whether that is
  too disruptive for high-churn feeds is a perf property of #2049's
  mechanism, not a materialization gap — a possible follow-up, out of
  #2274's scope.

## 4. What's shipped (the live, end-to-end materialization path)

Verified on worktree base `c677175021f0` (origin/master). Full chain,
config → fetch → overlay → wire snapshot → enforcement:

**Config model + parse (#143 + #2049):**
- `pkg/config/types_security.go:18-44` — `DynamicAddressConfig{FeedServers,
  AddressBindings}`, `FeedServer{...,FeedEntries}`, `FeedEntry{Name,Path}`,
  `AddressBinding{Name, FeedNames}`.
- `pkg/config/compiler_services.go:348-411` (`compileDynamicAddress`) —
  parses `feed-server <name> { url|hostname|update-interval|hold-interval;
  feed-name <fn> { path ...; } }` AND
  `address-name <an> { profile { feed-name <fn>; } }` into the typed
  config. Matches the real `vsrx.conf:1686-1708` block exactly
  (Cloudflare ipv4/ipv6 feeds + `cloudflare-ipv4`/`cloudflare-ipv6`
  address-name bindings, referenced by policies at vsrx.conf:162, 400,
  etc.).
- `pkg/config/schema_security.go:434-449` — config-mode `set`/`?`/commit
  schema for the full grammar (feed-server, feed-name+path, address-name,
  profile, feed-name), so the binding is authorable and tab-completable.

**Fetch + retain (#2050):**
- `pkg/feeds/feeds.go` — `Manager.Apply` starts per-feed refresh loops;
  `fetchFeed`/`installSnapshot` canonicalize + retain last-good
  (retain-forever default; opt-in hold-interval drop).

**Materialization accessor (#2049 `edf03ed42`):**
- `pkg/feeds/feeds.go:241` `SnapshotForBindings(daCfg)` — resolves each
  `AddressBinding` to the deduped/sorted union of its feeds' live
  prefixes, keyed by address-name. Deep-copied, fail-closed on empty.

**Daemon hand-off (#2049 `2d52d216b`):**
- `pkg/daemon/daemon_feeds.go:22` `feedSnapshotsForConfig(cfg)` — joins
  the INCOMING config's bindings to live feed snapshots (so a commit that
  removes a binding stops enforcing it).
- `pkg/daemon/daemon_apply.go:684-685` — at the top of the apply path
  (under `applySem`, mirroring `SetRouteOverlay`):
  `setter.SetFeedSnapshots(d.feedSnapshotsForConfig(cfg))`. The inline
  comment states the gap this closes verbatim.

**Refresh re-entry (pre-existing + #2049):**
- `pkg/daemon/daemon_run.go:912-918` — feed `onUpdate` callback fires
  `d.applyConfig(activeCfg)` on a content change; applyConfig re-runs the
  hand-off above with the new overlay → re-materializes.

**Overlay storage + snapshot build (#2049 `2d52d216b` + `cdf52c837`):**
- `pkg/dataplane/userspace/manager.go:174,810` — `m.feedOverlay` cached by
  `SetFeedSnapshots` (deep-copied) WITHOUT publishing.
- `pkg/dataplane/userspace/legacy_dataplane.go:219` —
  `LegacyDataPlaneAdapter.SetFeedSnapshots` forwards to the Manager (the
  default runtime dataplane is the adapter; #2049 `cdf52c837` added this
  after the first cut's type-assertion silently missed it — caught and
  pinned by `TestLegacyAdapterForwardsFeedSnapshots`).
- `pkg/dataplane/userspace/builder.go:59,74` and
  `manager.go:715,719` — both the full-build and the in-place republish
  pass `feedOverlay` into
  `buildPolicySnapshotsWithSchedulerStateAndFeeds` and
  `buildAddressBookTableWithFeeds`.
- `pkg/dataplane/userspace/policies.go:220-355`
  (`buildAddressBookTableWithFeeds`) — merges feed CIDRs into each bound
  name's content bucket BEFORE canonicalize/dedup/sort/hash/ID-assign;
  emits an `AddressBookSnapshot` row carrying the feed prefixes AND
  populates `nameToID[name]`.
- `pkg/dataplane/userspace/policies.go:113,142-174`
  (`classifyPolicyAddresses`) — a policy `match source/dest-address`
  token that names a feed-backed name now resolves through `nameToID` to
  `SourceBookIDs`/`DestinationBookIDs` (was a no-match literal pre-#2049).

**Scheduler-republish retention (#2049 `ef39cf3ce`):**
- `manager.go:711-719` — even a CoS scheduler-only republish rebuilds
  policies/books under the cached overlay, so feed enforcement is not
  dropped between full applies.

**Rust-side enforcement (INFERRED, not directly read):** the feed prefixes
ride EXISTING wire structures — `AddressBookSnapshot` rows + policy
`SourceBookIDs`/`DestinationBookIDs` (the #1606 address-book mechanism).
No feed-specific wire field is added, so a feed-backed row is
byte-indistinguishable from a static one. If the Rust matcher honors
#1606 book references for static named address books (a baseline the whole
product depends on), it honors feed-backed ones identically. This was
inferred from wire-shape identity + the static-book baseline, NOT from a
direct read of the Rust matcher; a live-feed lab test (§10 out-of-scope)
would close it. It does not change the verdict: the materialization #2274
asks about is the Go-side join, which is present and tested.

**Tests (#2049 `654c9ac8f`, `2e20a02a1`):**
- `pkg/feeds/feeds_bindings_test.go` — `SnapshotForBindings` union/dedup/
  deep-copy/empty.
- `pkg/dataplane/userspace/feed_enforcement_test.go` — book-row +
  nameToID population (with NON-TAUTOLOGICAL no-overlay guards), policy
  source/dest routed as book reference not literal, empty-feed
  fail-closed, content-change reshapes the published snapshot + shifts
  the content hash (so the refresh is not duplicate-dropped), overlay
  merges with a static book, adapter hand-off reaches the Manager,
  scheduler-republish retains enforcement.
- Confirmed green this session:
  `go test ./pkg/feeds/... ./pkg/dataplane/userspace/ -run
  'Feed|Snapshot|Bindings|Overlay'` → `ok` both packages.

## 5. Concrete design with code sketches

N/A — PLAN-KILL. No code change proposed. The "design" already exists on
master and is reproduced in §4 as the as-built reference.

For completeness, had the feature been absent, the correct design would
have been exactly what #2049 shipped (overlay join in the userspace
snapshot builder, NOT in the retired eBPF `compileAddressBook`, NOT a new
resolution pass) — see §6 of this doc's companion review for why the
alternatives the #2274 fix-direction implies (materialize into
`compileAddressBook`; add a separate resolution pass) would have been
wrong. The chosen mechanism is the right one and is in place.

## 6. Public API preservation

No API change. For the record, #2049 preserved all public shapes:
`feeds.Manager.GetPrefixes` and `AllFeeds` are untouched (status path);
`SnapshotForBindings` is additive; `SetFeedSnapshots` is additive on the
manager + adapter; the wire `ConfigSnapshot` schema gained no new field
(feed prefixes ride existing `AddressBookSnapshot` rows + policy
`SourceBookIDs`/`DestinationBookIDs`). HA wire compatibility was preserved
precisely because the overlay reuses the existing #1606 address-book wire
shape rather than introducing a feed-specific message.

## 7. Hidden invariants (already honored by the shipped code)

These are the invariants any feed-materialization change MUST honor; all
are satisfied today, which is part of why re-implementing would be pure
risk:

- **HA determinism:** feed overlay is NOT cluster-synced; each node runs
  its own fetcher and recomputes the overlay locally (confirmed: no
  `feed`/`SnapshotForBindings`/`DynamicAddress` reference in
  `pkg/cluster/`). The address-book ID assignment is deterministic across
  peers because `buildAddressBookTableWithFeeds` iterates names in sorted
  order, buckets by canonical content bytes, and sorts buckets by
  `(hash64, canonical_bytes)`. Two peers with the same feed content
  derive the same IDs; transient cross-peer staleness (one node fetched a
  newer snapshot) is bounded by the refresh interval and self-heals on
  the next fetch — the same staleness window any per-node feed design has.
- **Fail-closed on empty:** a bound-but-empty feed (pre-first-fetch, or
  hold-interval drop) still produces a `nameToID` entry + an empty book
  row, so the policy token routes as a book reference matching nothing —
  NOT as a no-match literal and NOT as match-any. (Allowlist → matches
  nothing = closed; denylist → matches nothing = operator-opted open per
  #2050, documented.)
- **Duplicate-publish gate:** a feed content change must shift the
  snapshot content hash or the refresh is silently dropped. Honored —
  feed CIDRs flow into the hashed `AddressBookSnapshot` content
  (`TestFeedContentChangeReshapesPublishedSnapshot` pins this).
- **Content-equality ID sharing:** a feed-backed name whose content
  equals a static book shares its ID (feed CIDRs join the same
  expand/normalize/dedup path).
- **Scheduler-republish must not drop feeds:** in-place republishes read
  the cached `m.feedOverlay`, not nil.

## 8. Risk table

| Risk | Likelihood | Impact | Note |
|---|---|---|---|
| Re-implementing an already-shipped feature regresses #2049 | High (if #2274 is "fixed" naively) | High | Any second materialization path (e.g. into `compileAddressBook`) would double-enforce or diverge from the userspace overlay; the #2049 tests would still pass while a NEW broken path shipped. This is the central reason to KILL. |
| Audit re-files the same false positive (#2049 → #2274 → ...) | Medium | Low | Mitigation = the doc breadcrumb in §10 (optional, doc-only). |
| `GetPrefixes`'s zero-caller status is mistaken for dead code and deleted | Low | Low | It backs status-path semantics + tests; leave it. Out of scope. |

## 9. Test plan

No code change → no new tests. The verification performed for this kill:

- [x] Static call-graph trace of the full chain (§4), every hop on
  origin/master `c677175021f0`.
- [x] Confirmed `SnapshotForBindings` HAS a production caller
  (`daemon_feeds.go:29`) and is reached from `daemon_apply.go:684`.
- [x] Confirmed the enforced address book is the userspace
  `buildAddressBookTableWithFeeds`, not the retired eBPF
  `compileAddressBook`.
- [x] Ran the materialization suite green:
  `go test ./pkg/feeds/... ./pkg/dataplane/userspace/ -run
  'Feed|Snapshot|Bindings|Overlay'` → ok / ok.
- [x] Confirmed PR #2058 (issue #2049) merge `d6aa5f792` is on
  origin/master and predates #2274's filing by ~32h.
- [x] Confirmed config grammar parity vs real `vsrx.conf:1686-1708`
  (Cloudflare feeds + address-name bindings + policy source-address refs).

## 10. Out of scope

- Live feed-fetch lab verification (an external HTTP fetch). Not needed to
  prove the materialization wiring; #2049 deferred it too.
- Deleting/relocating `feeds.GetPrefixes`. It is a status-path accessor;
  removing it is a separate cleanup decision, not a #2274 concern.
- **Optional doc-only follow-up (NOT part of this kill, file separately if
  desired):** a one-line breadcrumb in
  `pkg/dataplane/compiler.go::compileAddressBook` and/or
  `pkg/feeds/feeds.go::GetPrefixes` pointing at the live userspace overlay
  (`policies.go::buildAddressBookTableWithFeeds` / `SnapshotForBindings`),
  so the next adversarial grep does not re-file. This is the only
  actionable residue and it is doc-only; it does not justify reopening
  #2274 as a bug.

## 11. Open questions

1. Should #2274 be **closed as duplicate of #2049** (recommended) or kept
   open solely to track the optional doc breadcrumb in §10? Recommendation:
   close as duplicate; if the breadcrumb is wanted, file a fresh
   doc-only/chore issue so the bug label does not imply a live
   non-functional security control.
2. Is there any deployment on a tree OLDER than `d6aa5f792` (pre-#2058)
   where the gap is genuinely live? If so the fix is "upgrade past
   #2058," not new code — #2049 is the fix of record.

---

### Appendix A — Multiple Path Options (for the record; all moot under KILL)

The #2274 fix-direction text implies up to four design axes. The shipped
#2049 design already picked the correct point on each; re-deciding them is
the work this KILL avoids:

- **Where to materialize:** (a) into the retired eBPF
  `compileAddressBook` `CompileResult` [WRONG — not the enforced book]; (b)
  a new standalone dynamic-address resolution pass [unnecessary
  indirection]; (c) **overlay-join inside the userspace snapshot builder**
  [SHIPPED — `buildAddressBookTableWithFeeds`]. (c) is correct because the
  enforced artifact is the wire `ConfigSnapshot`, and joining there keeps
  the content hash / duplicate-publish gate honest.
- **Refresh cost:** (a) full dataplane recompile per refresh [the daemon
  `onUpdate` does re-enter `applyConfig`, but…]; (b) **incremental
  in-place republish** [SHIPPED via the cached `m.feedOverlay` + republish
  paths that rebuild only policies/books, and the content-hash
  duplicate-publish gate skips no-op refreshes]. The combination means an
  unchanged feed costs a hash compare, and a changed feed reshapes only
  the address-book/policy sections — not a link-detach/helper-restart.
- **Policy reference grammar:** reuse the existing address-token resolver
  (`classifyPolicyAddresses` + `nameToID`) [SHIPPED] vs a new
  feed-specific match keyword [unnecessary; breaks Junos parity]. Junos
  references a dynamic-address by its `address-name` in the SAME
  `source-address`/`destination-address` slot as a static book — the
  shipped path matches that exactly.
- **HA:** sync the materialized set [WRONG — fetched data, not config] vs
  **per-node recompute** [SHIPPED — config syncs, each node fetches +
  materializes locally; deterministic ID assignment keeps wire IDs
  identical for identical content].
