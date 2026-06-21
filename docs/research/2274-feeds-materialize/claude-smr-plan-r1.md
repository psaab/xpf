# Claude SMR — hostile plan review r1 (#2274 feed materialization)

Reviewer stance: adversarial. The plan concludes **PLAN-KILL (duplicate of
#2049, already shipped)**. My job is to break that conclusion. A KILL that
is wrong is worse than a kill-less plan: it leaves a real,
advertised-but-inert security control (threat-feed denylists) shipping
without enforcement. So I attack the "already shipped + actually enforced"
claim from every angle. If ANY link in the materialization chain is
broken at runtime, the KILL is wrong and this must flip to PLAN-READY.

## Attack 1 — "SnapshotForBindings has a caller, but is that caller on the live runtime path, or dead test scaffolding?"

The plan rests on a single hand-off:
`daemon_apply.go:684 setter.SetFeedSnapshots(d.feedSnapshotsForConfig(cfg))`,
guarded by `if setter, ok := d.dp.(feedSnapshotSetter); ok`. A type
assertion that silently fails is EXACTLY the class of bug that ships an
"implemented" feature that never runs (the #2049 history even records the
first cut missed the adapter forwarding method, so the assertion held but
the call dead-ended at a no-op).

Verification I demanded and got:
- `daemon_run.go:77` constructs the runtime dp via `dpuserspace.Boot()`.
- `manager.go:141 Boot()` returns `NewLegacyDataPlaneAdapter(New())` →
  `*LegacyDataPlaneAdapter`.
- `legacy_dataplane.go:219` defines
  `(a *LegacyDataPlaneAdapter) SetFeedSnapshots(...)` which forwards to
  `m.SetFeedSnapshots`.

So at runtime `d.dp` IS a `*LegacyDataPlaneAdapter`, the type assertion
`d.dp.(feedSnapshotSetter)` SUCCEEDS, and the forwarded call reaches the
Manager's `feedOverlay`. This is not test scaffolding — it is the default
boot path. `TestLegacyAdapterForwardsFeedSnapshots` exists precisely
because the earlier silent-miss happened and was fixed in `cdf52c837`.
**Attack fails. The hand-off is live.**

## Attack 2 — "The overlay is stored, but is it actually CONSUMED by the build that gets published?"

Storing `m.feedOverlay` and never reading it would be a classic unwired
field. I traced every consumer:
- `builder.go:59` `buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg,
  activeState, feedOverlay)` and `:74`
  `buildAddressBookTableWithFeeds(cfg, feedOverlay)` — the FULL build.
- `manager.go:714-719` — the in-place republish reads
  `cloneFeedOverlay(m.feedOverlay)` and passes it into the SAME two
  builders.
- `policies.go:43` — the policy builder calls
  `buildAddressBookTableWithFeeds(cfg, feedOverlay)` for its `nameToID`,
  so a feed-backed token classifies as a book reference.

The non-tautological tests (`feed_enforcement_test.go`) assert the
no-overlay build does NOT emit the row / does NOT set nameToID, and the
with-overlay build does — so the consumption is real, not a constant.
**Attack fails. The field is wired and the tests would catch its removal.**

## Attack 3 — "Maybe enforcement reaches the Go wire snapshot but the Rust helper ignores it."

The feed prefixes ride EXISTING wire structures: `AddressBookSnapshot`
rows + policy `SourceBookIDs`/`DestinationBookIDs` (the #1606 address-book
mechanism). There is no feed-specific wire field that the Rust side could
be missing. If the Rust matcher honors #1606 book references for a STATIC
address book (which it must, or every named address policy is broken — a
far louder bug than #2274), it honors a feed-backed one identically,
because the wire shape is byte-identical: a row with prefixes + a policy
book-ID reference. The plan's claim that no wire field was added is the
key: there is no separate Rust decode path to be unimplemented.

Caveat I must record honestly: I did NOT read the Rust matcher to confirm
#1606 book references are enforced — I am inferring from "static named
address-book policies work" (a baseline the whole product depends on) and
from the fact that feed rows are indistinguishable from static rows on the
wire. This is a strong inference, not a direct Rust read. It does NOT
change the verdict (the materialization #2274 asks about is the
Go-side join, which is present), but a future live-feed lab test would
close it. The plan already lists live verification as out-of-scope/§10,
consistent with #2049's own deferral. **Attack does not land, with a noted
inference.**

## Attack 4 — "The issue says GetPrefixes has zero callers. Is the plan hand-waving that away?"

No. The plan AGREES `GetPrefixes` has zero production callers — and shows
that is irrelevant because it is the status-path accessor, not the
enforcement accessor. The enforcement accessor `SnapshotForBindings` is a
DIFFERENT function added by #2049. The audit conflated "the function I
grepped has no callers" with "the feature has no enforcement." The plan
correctly separates the two. **Attack fails — the plan does not dodge,
it disambiguates.**

## Attack 5 — "compileAddressBook genuinely has no feed reference. Is that a real second gap?"

`compileAddressBook` (pkg/dataplane/compiler.go) builds the legacy eBPF
`CompileResult`. The eBPF dataplane is retired (#1373/#1476); that result
is used for commit-time validation/book-keeping, not for the enforced
address book. The enforced book is the userspace wire snapshot. So the
issue's observation is true of a path that does not enforce anything. The
plan is right to call it "literally true but irrelevant."

BUT — hostile sub-point: is there ANY path where the legacy
`CompileResult` address IDs DO drive enforcement (e.g. a NAT address-set
that still reads `result.AddrIDs`)? The issue's fix-direction mentions NAT
("populate the policy/NAT dataplane address sets"). If a NAT rule can
reference a dynamic-address-name and that path reads the legacy
CompileResult rather than the userspace overlay, there could be a residual
NAT-only gap even though POLICY is fixed.

This is the one attack that could carve out a narrower-but-real issue. I
checked the surface: the materialization overlay flows into
`buildAddressBookTableWithFeeds`, which backs the policy `nameToID`. NAT
address-set resolution in the userspace path would need its OWN overlay
join to enforce a feed in a NAT rule. I did NOT exhaustively prove NAT
rules can/can't reference a dynamic-address-name in this codebase, nor
that they'd resolve the feed. HOWEVER:
- The issue #2274's PRIMARY, explicit, repeated claim is the POLICY
  match-address path ("a security policy cannot resolve a
  dynamic-address-name"). That is squarely fixed.
- #2049 (the canonical fix) framed and closed the POLICY enforcement gap;
  its title is "feed prefixes ... never populate policy/dataplane address
  sets" and its tests cover policy source/dest.
- vsrx.conf references the cloudflare dynamic-address names ONLY as policy
  `source-address`, not in NAT pools (the real-world usage #143 cited).

Disposition: a NAT-rule-references-a-dynamic-address-name path, IF it
exists and IF it doesn't resolve the feed, is a DIFFERENT, narrower,
unproven concern than what #2274 asserts — and would be its own issue
under the project's scope-discipline rule ("bug fix and behaviour choice
do not ride in the same PR"). It does NOT rescue #2274 as filed, because
#2274's stated bug (policy cannot reference a dynamic-address) is false.
**Recommendation:** the issue-closure comment should explicitly note "the
policy-match-address materialization #2274 describes is shipped (#2049);
if a NAT-rule dynamic-address reference is desired and unenforced, that is
a separate, unverified feature request — file it distinctly." I have added
this nuance to the verdict so the KILL is not over-broad. The plan §3/§10
should carry it; flagged below.

## Attack 6 — "Is the plan a duplicate-close that loses information #143 wanted?"

#143 wanted: per-feed `path`, `address-name → profile → feed-name`
bindings, AND materialization into policy resolution. All three are
present: `FeedEntry.Path` (parsed at compiler_services.go:382), the
binding (compiler_services.go:396-407), the materialization (#2049). #143's
own multi-feed-path-collapse symptom (only the last feed-name survived) is
fixed by `FeedEntries []FeedEntry`. The schema authoring grammar
(schema_security.go:434) is present. Nothing #143 promised is missing.
**Attack fails.**

## Attack 7 — "Refresh disruption: does each feed refresh trigger an expensive full recompile, making the shipped design a perf landmine the plan glosses over?"

The plan claims incremental. Hostile read: the feed `onUpdate`
(daemon_run.go:912) DOES call `d.applyConfig(activeCfg)` — a full apply,
not a surgical address-set push. So on EVERY content-changing refresh the
whole config re-applies. Is that a disruption?
- The duplicate-publish content-hash gate (`snapshotContentHash`,
  pinned by `TestFeedContentChangeReshapesPublishedSnapshot`) means an
  UNCHANGED feed produces an identical snapshot and is skipped — no churn
  on the common case.
- A CHANGED feed reshapes the address-book/policy sections; whether
  `applyConfig` detaches links / restarts the helper on a books-only delta
  is a real question. But this is a PROPERTY OF THE SHIPPED CODE, and if
  it is too disruptive it is a PERF FOLLOW-UP on #2049's mechanism, not
  evidence that #2274's "fetch-only, never materialized" claim is true.
  The prefixes DO reach the dataplane; that is the #2274 question.

So Attack 7 cannot revive #2274 either. It could justify a SEPARATE perf
issue ("feed refresh should use the in-place republish path, not full
applyConfig") — noted as a possible follow-up, out of #2274's scope.
**Attack does not land on the verdict; spawns an optional perf follow-up.**

## Attack 8 — "Could the plan be wrong about the timeline — is #2058 actually NOT in the tree #2274 was filed against?"

`git branch -r --contains d6aa5f792` shows `origin/master`. #2058 merged
2026-06-20 14:42 UTC; #2274 filed 2026-06-21 22:57 UTC. The fix was in
master >32h before the issue. The audit ran against a tree that contained
the fix and still re-derived the pre-fix evidence — confirming it inspected
the wrong functions, not a stale checkout. **Attack fails.**

## Convergence

Seven of eight attacks fail outright. Attack 5 (NAT-rule dynamic-address)
and Attack 7 (refresh-cost) each spawn a DISTINCT, narrower, unproven
follow-up but neither rescues #2274 AS FILED — #2274's concrete claim
("a security policy cannot resolve a dynamic-address-name; fetched
prefixes never reach the dataplane") is demonstrably false on master.

Required plan edits before I sign off (all minor, all to keep the KILL
honest, not to change the verdict):
1. §3/§10: record the NAT-rule dynamic-address reference as an explicitly
   UNVERIFIED, SEPARATE potential feature — do not let the duplicate-close
   silently assert NAT is covered.
2. §10: note the optional perf follow-up (feed refresh full-applyConfig vs
   in-place republish) as out-of-scope-of-#2274.
3. §4: keep the honest caveat that the Rust-side #1606 enforcement was
   inferred (from wire-shape identity + static-book baseline), not read.

With those three honesty edits applied, the verdict stands.

## Verdict: PLAN-KILL (converged)

#2274 is a duplicate of the already-merged #2049 (PR #2058,
`d6aa5f792`, on origin/master). The dynamic-address feed materialization
into policy/address compilation that #2274 says is absent is present,
wired end-to-end on the default runtime path, and covered by
non-tautological tests (green this session). Close #2274 as a duplicate of
#2049; no production code change. Two narrower, unproven, out-of-scope
follow-ups (NAT-rule dynamic-address reference; feed-refresh apply cost)
may be filed separately if desired.
