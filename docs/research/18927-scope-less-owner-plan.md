# #18927 child 2 — scope-less session imports and owner judgment

**Status:** DRAFT v3 — narrow fold of the two convergent plan-review blockers; no production change in this commit.
**Base:** `origin/master` / assigned branch base `6c27f54cf24107758d522e4b2d7203bea9f32f92` (2026-11-05).
**Self-assessment:** **PLAN-READY** for delta confirmation on the reverse-guard narrowing and named controls. This is not implementation approval.

## Decision

Recommend a bounded fix, not PLAN-KILL. Preserve #15176 for ambiguous rows, but do not preserve a dynamic source-NAT translation when an owner-side validator proves that the live dynamic source-NAT rule list is empty. Zero live dynamic rules cannot authorize the stored translation under any ingress interface, routing instance, or historical logical unit. This is the only candidate-invariant proof in child 2; do not infer withdrawal from evaluating an identity-less row against a fabricated empty scope.

The deliberate #15176 decline is in `userspace-dp/src/afxdp/poll_descriptor/policy_revalidation.rs:1523-1549`: `scope_dependent && identity_absent && nat_scope_ifindex.is_none()` returns `None` before source-NAT rule inspection. It is pinned by `imported_scopeless_snat_kept_without_recorded_scope_15176` (`policy_revalidation_tests.rs:5757-5765`) and `imported_reth_vlan_scopeless_kept_16826` (`:8404-8466`). The dynamic matcher scans live rules in order and returns false when none match (`userspace-dp/src/nat/source/mod.rs:1727-1831`, terminal `false` at `:1831`); the current policy hit still declines before that proof.

## Exact proposed rule and placement

Production policy changes are confined to `userspace-dp/src/afxdp/poll_descriptor/policy_revalidation.rs`; policy tests are in `userspace-dp/src/afxdp/poll_descriptor/policy_revalidation_tests.rs`. The source-NAT matcher and wire format need no change.

1. Replace the unconditional scope-less early return with a “scope unavailable” marker and retain the early keep for ambiguous cases. This includes fabric/zero ingress and a positive tagged `(ifindex,VLAN)` that has no current Rust logical-unit mapping; the latter must not be judged against the raw-parent fallback of `resolve_ingress_logical_ifindex(...).unwrap_or(raw_ifindex)` (`afxdp/forwarding/nat.rs:24-61`). Treating an unresolved tagged mapping as ambiguous is a second behavior change: it replaces the current potentially-wrong parent-scope judgment with a conservative keep when live rules remain.
2. The only exception to that early keep is a possible **empty-dynamic-rule invariant** candidate: `source_nat_static == Some(false)`, a source rewrite, neither NAT64 nor NPTv6, and `forwarding.source_nat_rules.is_empty()`. Unknown provenance (`None`) is not proof of dynamic SNAT (`policy_revalidation.rs:858-903`). Do not directly revoke at this predicate.
3. Continue the candidate through the existing owner/FIB/zone/static/destination checks and one `source_nat_translation_still_valid` walk. Extend its result so it distinguishes `InvalidNoLiveDynamicRules` from ordinary invalidity. Emit `InvalidNoLiveDynamicRules` **only** after the dynamic provenance is explicit, destination validation passes (including composed DNAT+SNAT), the stored egress and required zones resolve, no matching static-SNAT branch supersedes the dynamic case, and the dynamic source-NAT list is empty. Egress miss (`:822-824`), missing zones, absent provenance, static-provenance conflict, invalid destination, and non-empty rule mismatch all return ordinary invalidity, never this invariant reason.
4. The reverse-hit unjudged-epoch keep at `:1773-1792` is bypassed **iff** the validator returned `InvalidNoLiveDynamicRules`. Scope evidence alone—a recorded `nat_scope_ifindex` or a derivable logical ingress mapping—MUST NOT bypass it. All other invalidity reasons retain the existing `:1773-1792` behavior, including `companion_present_reverse_hit_declines_when_invalid_current_epoch_16217`, which remains unchanged and GREEN. This makes the empty-list proof, not “the row had a scope,” the sole reason a reverse imported row can bypass the epoch keep.
5. Keep the earlier owner/terminal declines ahead of any final revoke. In particular, do not directly revoke at the scope marker: stored terminal rows at `:1550-1579`, FabricRedirect/HAInactive at `:1711-1715`, and non-owner gateway-fallback rows at `:1717-1720` must still decline. The companion-less reverse `NoLocalEntry` arm at `:1371-1397` also remains unchanged; its same-row divergence from companion-present reverse hits is a follow-up child candidate, not this fix.

For a non-empty source-NAT list there is no sound finite historical candidate inventory in an identity-less row; current configured logical units alone are not a complete set. Therefore child 2 does not enumerate candidates or generalize beyond the empty-list classifier. A non-empty scoped successor remains ambiguous under #15176.

### Cost bound

The added scope-unavailable/empty-list predicate is O(1) (plus the existing logical-map lookup for the unresolved-tagged-mapping guard). The eligible stale hit inherits the existing validation work once: egress/zone/static/destination checks and the current rule walk. This plan makes **no CPU, latency, or throughput claim**. There is no candidate sweep or new allocation. Non-empty ambiguous rows retain the current early keep and do not gain a per-packet rule scan.

## Import-path census

The repository has no captured live session table from which to estimate deployment prevalence. The counts below come from a bounded nine-row cohort run through the actual Go sender/wire/receiver and Rust import-constructor paths; they establish reachable classes, not production frequency.

The measured cohort exercised Go `stampInstallGenV4`, the production session frame codec and `handleMessage`, Go `buildSessionSyncRequestV4` plus JSON serialization, and Rust `build_synced_session_entry`. Sender folds, receiver folds, and receiver logical mapping were controlled in-memory fixtures (`reth0.80` resolved to `(20,80)` and logical ifindex 22). The legacy-tail row omitted only `NatScopeFold`, retaining the five-byte handshake/egress suffix. The prior temporary cohort harness passed under the isolated test runner; its rows and expected classes must now be retained with the Go output tied to the exact Rust inputs (test plan below). This is not a live prevalence measurement.

| Rust-imported class | Scope absent | Scope present | Total | Evidence / interpretation |
|---|---:|---:|---:|---|
| Ingress fold resolves to a current `(ifindex,VLAN)` and logical unit | 3 | 1 | **4** | Scope-less cases are zero scope fold, unknown peer-side scope fold, and legacy tail without `NatScopeFold`; scope is independently derivable from ingress identity. |
| No original ingress identity (unresolved/absent fold or fabric ingress) | 3 | 2 | **5** | Three scope-less identity-less rows are unresolved ingress fold, no ingress fold, and fabric ingress. Two scope-present controls show the folds are independent. |
| **Total** | **6** | **3** | **9** | **Scope-less = 3 identity-bearing + 3 identity-less. Scope-present = 1 identity-bearing + 2 identity-less.** |

Go resolves ingress at `pkg/dataplane/userspace/manager_sessionsync_request.go:308-317` and resolves the NAT-scope fold independently at `:318-327`; a missing/unknown NAT-scope fold does not erase a resolved ingress fold. `pkg/cluster/sync_conn_gen.go:821,835` stamps `NatScopeFold` for current V4/V6 peers. Rust construction is through `userspace-dp/src/server/handlers/sync_session.rs:165-225` and `server/helpers/session_sync.rs:332-336,480-610`.

**Class definitions.** “Identity-bearing on import” means the receiver resolved a non-zero local `(ifindex,VLAN)` from the cluster fold; it does **not** prove the original install-time interface. Owner judgment additionally requires a current Rust logical-unit mapping usable by the NAT scope matcher (`forwarding/mod.rs:374-383`, `forwarding/nat.rs:24-61`). A positive raw ifindex with a missing tagged-unit mapping is unresolved, not permission to judge the physical parent as the original VLAN unit. Fabric/zero/unresolved ingress carries no original interface identity; a zone and flow routing-domain do not recover the missing ingress ifname/RI.

The Go and Rust sides must share inputs, not independently restate them: retain a checked-in `pkg/dataplane/userspace/testdata/session_sync_scope_cohort_18927.jsonl` containing the nine JSON `SessionSyncRequest` records emitted by the real Go cohort path. `session_ingress_fold_import_7095_test.go` must build each row through the sender fold, frame codec/receive, and request builder, then compare its JSON output byte-for-byte with this fixture. The Rust policy test must parse those same JSONL lines as `SessionSyncRequest` and call `build_synced_session_entry` before owner-hit testing; it must not recreate the nine rows as separate Rust literals. This makes the Go fold/wire results the actual Rust importer inputs. The controlled cohort does not contain the missing-local-logical-VLAN-map case; add that as a separate synthetic policy-row cell. Supplementary hand-built Rust import specimens at `userspace-dp/src/server/tests.rs:9290-9351` are not included in the nine-row totals.

## Owner-hit verdict matrix

“Judged” is not synonymous with a bare `None`: a valid judgment stamps the current source-NAT revalidation epoch; an invalid judgment returns `StaleSourceNat`; an epoch-exempt keep has neither revocation nor a new stamp. The tests must assert these distinctions.

| Imported row / first hit | Matching live rule | Non-empty mismatching rule set | Empty dynamic source-NAT list with `InvalidNoLiveDynamicRules` |
|---|---|---|---|
| Scope-less identity-less, forward owner hit | Keep under #15176; no stamp | Keep under #15176; no stamp | Revoke `StaleSourceNat` after owner/FIB/zone checks |
| Scope-less identity-less, reverse hit with forward companion and unjudged epoch | Keep under #15176; no stamp | Keep under #15176; no stamp | Revoke `StaleSourceNat`; the exact invariant result bypasses the epoch keep |
| Scope-less identity-bearing, local logical mapping present, forward owner hit | Judge and survive; stamp | Judge and revoke `StaleSourceNat` | Revoke `StaleSourceNat` by the universal proof |
| Same identity-bearing row, reverse hit with companion, no forward VLAN and unjudged epoch | Judge and survive; stamp | Keep under unchanged `:1773-1792` epoch rule; no stamp | Revoke `StaleSourceNat` only for the exact invariant result |
| Positive tagged ingress but local logical mapping missing, forward or reverse | Keep as unresolved; no guessed parent-scope verdict | Keep as unresolved; no guessed parent-scope verdict | Revoke only if validator reaches `InvalidNoLiveDynamicRules`; otherwise ordinary invalidity follows existing direction/epoch behavior |
| Scope-present row, forward owner hit | Judge and survive; stamp | Judge and revoke `StaleSourceNat` | Revoke `StaleSourceNat` by the universal proof |
| Scope-present row, reverse hit with companion, no forward VLAN and unjudged epoch | Judge and survive; stamp | Keep under unchanged `:1773-1792` epoch rule; no stamp | Revoke `StaleSourceNat` only for the exact invariant result |
| Any row that hits stored terminal, FabricRedirect/HAInactive, or non-owner fallback before source-NAT judgment | Existing decline | Existing decline | Existing decline; never direct-revoke at the early marker |
| Companion-less reverse row taking `NoLocalEntry` at `:1371-1397` | Existing branch | Existing branch | Existing branch in this fix; same-row divergence is a follow-up child candidate |

The #16217 control `companion_present_reverse_hit_declines_when_invalid_current_epoch_16217` remains unchanged and GREEN: a scope-present or identity-bearing reverse row with ordinary non-empty-rule invalidity and an unjudged/current epoch is still kept by `:1773-1792`. **Scope evidence alone is not a bypass.** Only `InvalidNoLiveDynamicRules` can bypass that keep.

## Required retained test cells

No production code is included in this plan commit. The implementation lane’s first act is to add/run `identityless_scopeless_snat_empty_live_rules_revokes_18927` **RED on master**. The earlier no-scope runtime probe was **not executed**: the runner path was proven with an existing cell, but the temporary source edit did not reach the Cargo worktree. Source-deterministic evidence is only that the current `return None` at `policy_revalidation.rs:1547-1549` precedes rule validation and the empty-list matcher ends false at `nat/source/mod.rs:1831`; do not report this as a runtime result.

Required new cells:

- `identityless_scopeless_snat_empty_live_rules_revokes_18927`: start from `scoped_snat_case_15176(false, None)` (`policy_revalidation_tests.rs:5695-5703`), set `source_nat_static = Some(false)`, replace rules with `[]`, use a nonterminal owner resolution, and assert `StaleSourceNat`, not `None`.
- Reverse twin with forward companion, established traffic, no `forward_ingress_vlan_id`, and unjudged epoch: assert revoke only when the validator returns `InvalidNoLiveDynamicRules`.
- `positive_tagged_ingress_missing_logical_map_empty_rules_revokes_18927`: positive `(ifindex,VLAN)` but remove the Rust local logical mapping; provide a current raw-parent zone mapping, real egress, explicit dynamic provenance, and empty rules so the validator reaches the invariant result. Assert forward and reverse revocation. Its non-empty-rule controls must keep; this is the second behavior change and is not implied by the nine measured rows.
- Composed DNAT+dynamic-SNAT empty-list cell: keep destination NAT valid, make only dynamic source-NAT rules empty, and assert the exact invariant result/revocation. An invalid destination must remain ordinary invalidity and must not qualify for the epoch bypass.
- Empty-list controls for stored terminal resolution, FabricRedirect, HAInactive, and non-owner gateway fallback: assert existing keep/decline. These prove the implementation cannot direct-revoke from the early marker and bypass the owner/terminal declines at `:1550-1579,1671-1720`.
- Ordinary invalidity controls: FIB egress miss, missing zones, absent dynamic provenance, static-provenance conflict, and a non-empty rule mismatch must not return `InvalidNoLiveDynamicRules`; reverse imported hits still take the existing `:1773-1792` keep when its epoch predicate says keep.
- Keep `imported_scopeless_snat_kept_without_recorded_scope_15176`, `imported_reth_vlan_scopeless_kept_16826`, recorded-scope valid/withdrawn controls, and `companion_present_reverse_hit_declines_when_invalid_current_epoch_16217` unchanged.

Retain the nine-row Go output fixture and two consumers described above. For each imported row, exercise forward/reverse first hits under matching non-empty rules and an empty list: **36** isolated stale-hit cases. Expected counts: 12 scope-less identity-bearing cases (all judged: six matching-rule stamps, six empty-list revokes); six identity-less ambiguous matching-rule keeps (no stamp); six identity-less empty-list revokes; 12 scope-present cases (all judged: six matching-rule stamps, six empty-list revokes). Add the missing-local-logical-map synthetic pair outside this 36-case count. The count is test-corpus reachability, never a live prevalence estimate.

The new unresolved-tagged-mapping early keep is an independent behavior change from the empty-list invariant; implementation acceptance requires the **full existing `policy_revalidation_tests.rs` module** under the isolated/CI environment, not just the newly added cells.

## Rejected alternative: PLAN-KILL / blanket #15176 reaffirmation

Reaffirming the early decline for every scope-less row preserves a dynamic translation even when the live dynamic source-NAT list is empty. Conversely, blanket judgment against egress, zone, routing-domain, or only current configured interfaces is unsound: the rule matcher uses ingress interface/RI selectors and first-match order (`nat/source/mod.rs:1247-1264,1711-1831`), while egress describes the other side. The selected fix handles only a validator-proven universal absence and keeps every ordinary ambiguous mismatch on #15176.

## Wire and legacy-peer compatibility

`NatScopeFold` is already additive for current peers: V4/V6 senders stamp it at `pkg/cluster/sync_conn_gen.go:821,835`; `sync_protocol.go:631` appends it to the metadata tail and the decoder reads the full extension at `:729-739`. A legacy five-byte handshake/egress tail has no `NatScopeFold`, so the new decoder receives zero; an old decoder ignores the added tail. The Go request builder resolves scope independently from ingress (`manager_sessionsync_request.go:314-327`). No new wire field or compatibility shim is proposed.

A legacy peer without `NatScopeFold` but with a resolved ingress fold enters the identity-bearing, scope-less path and is judged only when the local logical mapping exists. A peer with absent/unresolved ingress identity remains ambiguous except for the validator-proven empty dynamic rule result. Identity is a currently resolved receiver-local ifindex/VLAN, **not proof of the original device**: sender folding occurs against current config, and `manager_sessionsync_request.go:331-335` documents that an ifindex recycled onto a sibling between install and sync may resolve to that sibling. The snapshot-presence fence (`:780-795`) and Rust logical-map requirement bound the new behavior to a currently named mapping; the recycle-before-sync false-judgment risk remains and needs install-time identity/generation as a separate follow-up if stronger proof is required.

## Retention risk and operational bound

Junos `inactivity-timeout never` is supported: wire seconds `86401` maps to `u64::MAX` (`userspace-dp/src/session/mod.rs:525-551`; session timeout selection `:8115-8160`). Established active flows refresh the idle deadline on traffic (`session/lookup.rs:1192-1204`). Thus a genuinely ambiguous identity-less row with a non-empty live ruleset can survive indefinitely when configured `never`; this is accepted to avoid revocation against invented ingress data. The empty-list invariant removes only the provably unauthorized dynamic source translation on the first eligible owner stale hit. Finite global timeout inputs saturate at `MAX_SESSION_TIMEOUT_NS` (`session/mod.rs:501-522`), and ordinary application overrides are separately capped.

Other risks: sender-side ifindex recycling remains a residual; reverse ordinary-invalid rows retain the unjudged-epoch rule; non-empty unrelated successor rules remain ambiguous; and companion-less reverse rows can diverge from companion-present rows until a separate child addresses `NoLocalEntry`. No broader candidate enumeration or new wire-compatibility risk is introduced.

## Open questions for the three plan seats

1. Is the proposed `InvalidNoLiveDynamicRules` classification sufficiently narrow to exclude egress miss, missing zones, destination invalidity, absent provenance, static conflict, and every non-empty mismatch, while covering composed DNAT+dynamic-SNAT when the destination remains valid?
2. Are the named terminal/non-owner controls, positive-ifindex unmapped-VLAN twins, and unchanged #16217 cell sufficient to protect the reverse-guard narrowing and the second behavior change?
3. Does the checked-in Go JSONL output fixture plus byte-for-byte Go assertion and Rust import of those exact records make the nine-row owner census reproducible without independently rebuilding Rust metadata?

## Scope-size estimate and landing hygiene

Small bounded change: one Rust production module (`policy_revalidation.rs`), one Rust policy test module, one existing Go import test extension, and one shared JSONL test fixture, plus this plan doc. No production Go, codec, Rust import-constructor, or wire-format changes. The two earlier branch commits need their subjects and bodies reworded to include `(#18927)` at landing prep. This revision commit must have the subject `docs: narrow scope-less owner revalidation plan (#18927)` and a full Why/What/Validation/Risk body.
