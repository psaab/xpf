# B3-A adopt audit (`fix/11005-addrhot`, base `5d4230f9d`)

Recorded by EngB3A2 on adopt. Worktree `/var/tmp/worktrees/11005-addrhot` only;
`/home/ps/git/pi-xpf` inspected read-only (no Rust diff remains there — the
prior lane's mis-landed Rust edits are gone; intent recovered from
`history://EngB3A` transcript + issue bodies).

## 1. Change-set inventory (59 dirty files, zero commits)

### Go impl (7 files) — COMPLETE, coherent
| File | Hunks | Classification |
|---|---|---|
| `pkg/dataplane/userspace/policies_addrbook.go` | resolver+parse-once rewrite (~L211-230 table loop; new `addressBookExpansionResolver` w/ per-name + per-value memo; `parsedAddressBookCIDR`, `sortParsedAddressBookCIDRs`, `canonicalizeParsedAddressBookContent`; `parseAddressBookCIDR` hook var; slim `expandBookNameRecursive` kept for NAT lowering) | #11006 impl (+ #11005 table-shape) |
| `pkg/dataplane/userspace/policies_lower.go` | new `buildPolicySnapshotsWithAddressBook(cfg,…,nameToID)` entry (old entry kept as thin wrapper); per-build `representabilityCache`; `buildOneRuleSnapshot` classifies v3 FIRST, emits legacy `source/destinationAddresses` ONLY for non-v3-shaped sides (sentinel still forced on both shapes for unrepresentable) | #11005 thread-through + #11007 memo/omit |
| `pkg/dataplane/userspace/builder.go` | `buildSnapshotWith…` builds table once, shares `nameToID` with lowering (was: lowering built+discarded, then table rebuilt); + gofmt realignment of `snap` literal (canonical, keep) | #11005 |
| `pkg/dataplane/userspace/manager_compile.go` | scheduler republish builds table once, shares IDs (was: pair rebuilt) | #11005 |
| `pkg/dataplane/userspace/policies_reject.go` | rejection reasons build table once, share IDs (was: pair rebuilt) | #11005 |
| `pkg/dataplane/userspace/policies_resolved_fingerprint.go` | both fingerprint fns build table once, share IDs; comment fix (book-table contribution wording) | #11005 |
| `pkg/dataplane/userspace/protocol_policies.go` | comment-only: legacy fields documented as non-v3-only + exact-equality gate note | #11007 doc |

Semantics spot-checks (audit, not re-verified by test yet):
- `isV4CIDR`/`isV6CIDR` (`policies.go:148-161`) are pure `net.ParseCIDR`
  predicates; bare IPs never matched them (no `/`), so old code normalized
  bare IPs via the later `net.ParseIP` branch — the resolver's
  ParseIP-first order is equivalent (ParseCIDR/ParseIP inputs are disjoint).
- Old `normalizeAnyInCIDRs` was a no-op (flags computed, discarded); removal
  is behavior-null. `addressBookContentHash64` was already a `var` hook at
  base — no conversion needed.
- Resolver caches only acyclic expansions (`if !cycle`), sorts+dedups per
  name; table output is the same flat sort+dedup+canonical bytes as before.
- Unparseable values dropped in both old and new paths.
- `daemon_policy_invalidate.go` / `daemon_policy_rename.go` untouched: they
  call the (now cheaper) fingerprint fns; per-old/new-cfg recomputation is
  inherent, not redundant. "Share where safe" satisfied at builder level.

### Go tests (5 files) — 4 authorized migrations + new cells
| File | Verdict |
|---|---|
| `addressbook_slash_name_4340_test.go` | AUTHORIZED migration: `buildPolicySnapshots` → `buildSnapshot`, asserts via v3 IDs + `policySnapshotAddrs` resolving through `AddressBooks` rows. Same property (slash names resolve to prefixes). OK |
| `any_ipv4_keyword_literal_9574_test.go` | AUTHORIZED migration: legacy assertion flipped to assert ABSENCE (`len==0`) while v3 literals still asserted present. Same property (keyword reaches wire as CIDR) + new omit-shape. OK |
| `manager_policy_test.go` | AUTHORIZED migration: legacy expansion asserts → `policySnapshotAddrs` v3 resolution. Same prefixes. OK |
| `zone_local_addressbook_3061_test.go` | AUTHORIZED migration: helper generalized to resolve v3 (literals + book-row join, `t.Fatalf` on missing book ID); source/dest wrappers preserved. Same property. OK |
| `address_book_test.go` | NEW cells (no weakening): `…HashesEachAddressBookBucketOnce11005` (static + feed-backed), `…ParsesEachRawPrefixOnce11006` (nested-set + determinism), `…StoresPrefixesOnce11007` (24 rules × 512 prefixes, wire-once + alloc-flat), `…FingerprintTracksAddressBookDefinition11007`; plus `TestPolicyBuildEmitsBookIDsAndLiterals` updated to v3-ownership asserts. OK |

No other `*_test.go` touched. `git diff --name-only -- '*_test.go'` ⊆ authorized set. ✓

### Fixture regen (47 files) — canonical writer output, keep
- `testdata/policy_duplicate_rule_id_9584.json`,
  `testdata/policy_generated_corpus/rows/*.json` (45),
  `testdata/policy_verdict_corpus_snapshots.json`.
- Content change is exactly the omit-shape (`source/destination_addresses`
  removed where v3-shaped; book rows carry payload).
- Incidental churn: key order (alphabetical → Go struct order) + `->` →
  `\u003e` escaping. This IS the repo writer's canonical format
  (`policy_generated_corpus_gen_10587_test.go:158` `json.MarshalIndent`);
  the test compares canonical re-marshals (L146-150), so the churn is
  semantically null and future regens are stable. Keep; do not hand-minimize.

### Rust impl — MISSING (entire #11005-Rust half)
- `git diff --stat -- userspace-dp/` in worktree: EMPTY. Zero Rust spillover,
  zero Rust impl. Prior lane's Rust work (policy.rs rebind helper,
  forwarding_build preparsed entry, reconcile/snapshot_refresh threading,
  status.rs bindings) landed in the wrong tree and was reverted/lost.
- To (re-)implement on the NEW base (see §3): single-parse threading on the
  apply path + parse-count regression test. Design: parse once against the
  LIVE counter store as the preflight (preserves accumulated hit-count Arcs
  by construction), roll back `tracked_rule_ids` on preflight failure
  (#6995 precedent), hand the `PolicyState` into the forwarding build.
  (Prior lane's scratch-then-rebind would reset hit counts without a perfect
  rebind walk; live-parse avoids the walk entirely.)

## 2. Missing vs the three acceptances
- #11005 Go: DONE (one table build; hash-count cell proves it).
- #11005 Rust: MISSING — preflight parse (`snapshot_refresh.rs:233`) +
  final-build parse (`forwarding_build/mod.rs` `state.policy = …`) still both
  present; handler/reconcile paths still to map. Must thread preparsed state
  through every apply path (refresh + reconcile + handler) with
  failure-atomicity + previous-good preserved.
- #11006: DONE (parse-once cell + determinism cell).
- #11007: DONE Go-side (memo + omit + wire-once + alloc-flat cells).
  Compat proof (omit-gate): Rust ignores legacy fields when v3-shaped
  (`userspace-dp/src/policy.rs:2212-2220`: v3-shaped sides use ONLY
  `*_literals` + book IDs; `parse_legacy_address_set` runs only for
  non-v3-shaped sides); cross-version helpers are refused outright by exact
  equality (`userspace-dp/src/server/handlers/snapshot.rs:28,539`
  `snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION`, plus Go-side
  `ensureRequiredSnapshotProtocolLocked` disarm gates in
  `manager_compile.go`). v3-shape predates this batch on both sides and no
  version bump is needed: every same-version reader already v3-ignores.
  (ProtocolVersion 33→34 in rebase range is #10703's fence, unrelated.)

## 3. Rebase preview (base `5d4230f9d` → `origin/master`, 30 commits)
- Touched-path churn that OVERLAPS our hunks: ONLY
  `pkg/dataplane/userspace/policies_lower.go` (comment-only #5575→#11013/#11014
  reword at L182, between our L121-154 and L191 hunks — adjacent, expect clean
  auto-merge; watch closely).
- Non-overlapping churn on our files' neighbors:
  - `userspace-dp/src/policy.rs` (319 lines, #11009/#11010 `try_match_rule`→
    `RuleMatchOutcome` + frag-deny): all hunks at L1164+ (rule-eval/match
    paths), NONE in the parse-state region (~L1650 struct, ~L2006-2045
    parsers, ~L2190 v3 build). Clean re-apply expected; DO NOT revert #11019-shape.
  - `snapshot_refresh.rs` (+14-11, #11033 directed-broadcast at L313): far
    from preflight region (L218-290). Clean.
  - `forwarding_build/mod.rs` (+5, #10703 SYN flags at L667): adjacent to the
    `state.policy = …` site (~L620-640) but distinct lines. Manageable.
  - `policies.go` (token rename), `protocol.go` (v34 bump), `flow.go`,
    `neighbors.go`, `zones_*`: no overlap with our hunks.
- Post-rebase re-verification required: `snapshot_shape_version_8892_test.go`
  golden moved to the #10703 digest at v34 — our change adds no wire fields,
  so the digest must still match; the test itself is the check.

## 4. RED / verification results (post-implementation)
- #11005 Go: `TestSnapshotBuildHashesEachAddressBookBucketOnce11005` went
  RED after an extra hash invocation (4 calls for 2 rows in both static and
  feed-backed cases). Restored implementation passes in the affected suite.
- #11006: `TestAddressBookTableParsesEachRawPrefixOnce11006` went RED with
  the parsed-prefix cache bypassed (the duplicate feed CIDR parsed twice).
  Restored implementation passes in the affected suite.
- #11007: `TestSharedFeedBookSnapshotStoresPrefixesOnce11007` went RED after
  a v3 book-reference side emitted legacy source fields (all 24 rules failed
  the omission assertion). Restored implementation passes in the suite.
- #11005 Rust: `apply_snapshot_reuses_policy_preflight_on_same_plan_refresh_11005`
  went RED when the handler bypassed the prepared-policy handoff (parse count
  2, expected 1). Restored handoff passes the targeted test.
- Go: `TMPDIR=/var/tmp GOTMPDIR=/var/tmp go test ./pkg/dataplane/userspace ./pkg/daemon -count=1`
  passed both packages.
- Rust: `cargo test --bins`: `fairness-eval` passed 63 tests; userspace binary had 7,083 passed,
  one failure (#9894), and 6 ignored. The same full suite from clean
  `origin/master` `5af40e250` passed 63 `fairness-eval` tests and reproduced
  the #9894 failure in the userspace binary (7,082 passed, 6 ignored). It is
  a base failure, not attributable to this batch.
- Focused Rust apply regression passed after restoring the prepared handoff.
