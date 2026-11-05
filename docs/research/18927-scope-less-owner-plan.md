# #18927 child 2 — scope-less session imports and owner judgment

**Status:** DRAFT v1 — design recommendation; no production change proposed.
**Base:** `origin/master` / assigned branch base `6c27f54cf24107758d522e4b2d7203bea9f32f92` (2026-11-05).
**Self-assessment:** Recommend **PLAN-KILL** for the proposed “judge scope-less imports at the owner” behavior. This is one seat's recommendation, not three-seat convergence and not an issue disposition. The source proves identity-bearing rows already enter the judged path; rows with neither a recorded scope nor original ingress identity cannot be judged truthfully from owner/egress information alone.

## Decision

Reaffirm #15176 for structurally identity-less imports: when a scope-dependent NAT rewrite has no recorded `nat_scope_ifindex` and either `fabric_ingress` is true or `ingress_ifindex` is zero, keep the session instead of manufacturing an empty ingress scope. Do not add an owner/egress-based bypass around that decline.

The predicate is exact in `userspace-dp/src/afxdp/poll_descriptor/policy_revalidation.rs:1523-1549`: `scope_dependent` is limited to rewrites requiring the relevant checks; `identity_absent` is `fabric_ingress || ingress_ifindex == 0`; only `scope_dependent && identity_absent && nat_scope_ifindex.is_none()` returns `None`. This return precedes the owner-line, stored-terminal, live-resolution, and NAT-validity decisions (`:1550-1754`). Consequently the documented issue label “scope-less imports not judged by the owner” (`docs/ha-failover-status.md:647-654`) overstates the affected population: the guard does **not** exempt a non-fabric row with a positive ingress ifindex.

For a non-fabric row with real ingress identity but no NAT-scope stamp, the revalidator derives the logical ingress from the stored `(ingress_ifindex, ingress_vlan_id)` and uses its local interface/RI maps (`policy_revalidation.rs:820-854`; `afxdp/forwarding/nat.rs:24-61`). A scope-less imported `(20,80)` fixture maps to logical ifindex 22 in the #16826 test setup (`policy_revalidation_tests.rs:8404-8432`) and is not covered by the identity-absent decline. This is already the bounded rule the proposed fix would seek for identity-bearing rows.

For the remaining class—fabric ingress or zero ingress ifindex—the owner has no truthful original logical ingress unit. `source_nat_translation_matches` selects the first live rule using ingress interface/RI scope and zone, then checks the stored translation (`nat/source/mod.rs:1247-1264,1711-1831`). Egress identifies egress-side zone/interface/RI and interface-mode SNAT address, not the original ingress unit. `routing_domain` is a flow/table identity; it is not a substitute for an ingress ifname or the rule's ingress routing-instance string (`afxdp/forwarding/nat.rs:24-61`). Zone and routing-domain alone cannot prove an interface-scoped rule match. Judging the row with an empty or guessed ingress scope can false-revoke a valid session or select a different first-match rule.

## Import-path census

The repository contains no captured live session table from which to count deployment rows. The counts below are therefore explicitly **measured source-path/test-specimen counts**, not claims about live prevalence. I traced the production producer → wire → Go request builder → Rust import constructor and counted available full-constructor specimens; no active cluster/session dump was read.

| Census unit | Identity-bearing, derivable | Structurally identity-less / exempt | Count and evidence |
|---|---|---|---|
| Full Rust import specimens through `build_synced_session_entry` | **1**: request has local ingress `(42,50)`, non-fabric by default, zone IDs 2/3, no NAT-scope field (zero default); helper preserves `(42,50)` | **1**: request has zone IDs 2/3 but omits ingress ifindex/VLAN and NAT scope; helper preserves `(0,0)` | **2 specimens total, 1 per class**, `userspace-dp/src/server/tests.rs:9290-9351`. Both use the production import constructor at `server/helpers/session_sync.rs:332-336,480-610`; they are tests, not runtime-row counts. |
| Production import constructor | One shared constructor for V4/V6 and the `upsert`, `mirror_upsert`, and `mirror_publish_only` request operations | Same constructor; it copies `fabric_ingress` and maps `req.ingress_ifindex <= 0` to zero | **1 constructor**, `server/handlers/sync_session.rs:165-225`; shared field construction at `server/helpers/session_sync.rs:480-610`. |
| Scope-less revalidation specimens | **1** policy fixture with identity `(20,80)` and no NAT-scope stamp | **1** policy fixture with `(0,0)` and no NAT-scope stamp | **2 policy specimens**, `policy_revalidation_tests.rs:5695-5703,5757-5765,8427-8466`. These directly exercise the revalidation function but construct metadata in test code rather than traverse the Go wire. |

The scope and ingress folds are independent in the real path. The Go sender stamps `NatScopeFold` separately for V4/V6 (`pkg/cluster/sync_conn_gen.go:821,835`); `stampNatScopeFold` returns zero for nonpositive scope and otherwise folds the logical scope (`pkg/cluster/sync.go:2528-2553`). The sync tail decodes both folds only when the full 9-byte `{handshake, egress fold, NAT-scope fold}` suffix exists; the 5-byte legacy suffix supplies only the egress fold (`pkg/cluster/sync_protocol.go:729-739`). The Go receiver resolves ingress and NAT scope independently; an unresolved NAT-scope fold or missing local logical row leaves scope unset (`pkg/dataplane/userspace/manager_sessionsync_request.go:314-328,717-748`).

That yields two meaningful scope-less output classes at the Rust trust boundary:

1. **Derivable ingress:** `!fabric_ingress && ingress_ifindex > 0`, with a known `(ifindex,VLAN)` logical mapping or a genuinely untagged physical identity. A missing NAT-scope fold does not erase ingress identity; the policy path derives it and judges.
2. **No original ingress identity:** `fabric_ingress || ingress_ifindex == 0`. The actual fabric stamp deliberately records `(0,0)` because the local fabric NIC is not the peer's original ingress (`userspace-dp/src/session/entry.rs:37-57,71-79`; `session_glue/forward_commit.rs:55-67`). A zone ID may remain, but the interface/VLAN is not present. This is the #15176 keep class.

The import builder's comment identifies the structural causes of zero ingress as legacy sender/no wire field, no cluster-stable interface name, and fabric redirection (`userspace-dp/src/server/tests.rs:9322-9350`). Scope can independently be absent because the sender did not record it, the sender's NAT-scope fold is zero, an old tail lacks `NatScopeFold`, or receiver resolution cannot name the local logical row. A scope-failure cause alone does **not** mean ingress identity is absent: the separately resolved ingress fold can still make a non-fabric row derivable and judged.

## Existing behavior / decision matrix

| Imported forward row | Existing path | Expected action on stale-generation hit when rule is withdrawn / valid | Evidence |
|---|---|---|---|
| Identity-less (`fabric_ingress` or ingress ifindex 0), no scope | #15176 scope decline | **Withdrawn → keep**; do not invent an empty scope | `policy_revalidation.rs:1543-1549`; `imported_scopeless_snat_kept_without_recorded_scope_15176` at `policy_revalidation_tests.rs:5757-5765`; `docs/log/15176.md:26-39,68-75` |
| Identity-bearing, no NAT-scope stamp | Derive logical ingress from `(ifindex,VLAN)` and judge the current rule set | **Withdrawn → judged; invalid translation revokes.** The #16826 cell only proves the live-rule control survives; a dedicated withdrawn-rule identity-bearing cell is a useful review question, not an unrun result claimed here. | `policy_revalidation.rs:820-854`; `policy_revalidation_tests.rs:8404-8466` |
| Any ingress shape, recorded NAT scope; scoped rule withdrawn/rescoped | Judge under recorded scope | **Withdrawn/rescoped → revoke** as `StaleSourceNat` | `recorded_scope_snat_revoked_when_rule_withdrawn_15176` and `...rescoped_15176`, `policy_revalidation_tests.rs:5768-5795` |
| Any ingress shape, recorded NAT scope; live rule remains valid | Judge under recorded scope | **Valid → survive** | `fabric_scoped_snat_survives_with_recorded_scope_15176`, `policy_revalidation_tests.rs:5745-5755`; logical VLAN proof in #16826 log |

This is not a proposed code change or a request to add the missing test under this plan-kill recommendation. It records the distinctions needed to avoid treating an identity-bearing no-scope row as the identity-less #15176 case.

## Rejected alternative: judge by egress owner

Rejected: bypass the keep whenever the local node currently forwards the egress RG, then validate against egress, zone, or routing-domain information alone. `source_nat_translation_still_valid` uses the forward egress to select the egress row and zone pair, but it still needs ingress scope for `from_interface` and `from_routing_instance` matching (`policy_revalidation.rs:820-854`; `nat/source/mod.rs:1247-1264`). Multiple ingress logical units can share an egress and routing domain; no reverse map from egress to the session's original ingress exists (`afxdp/forwarding/mod.rs:374-383`). The owner can know which egress it now forwards, not which of several ingress interfaces admitted this session.

A zone-only fallback is not equivalent: source-NAT rules may conjunctively constrain interface and routing instance, and first-match ordering means dropping one unknown axis can change which rule is selected. A proof that every possible ingress candidate yields the same verdict could be safe in principle, but no such candidate-invariance proof exists in the current validator; implementing it would be a new algorithm, not a bounded owner check.

## Wire and legacy-peer compatibility

`NatScopeFold` is already additive and length-gated. New Go senders append it after the egress fold (`sync_protocol.go:631`; decode `:729-739`). A new decoder sees a legacy tail without that final four-byte field as `NatScopeFold == 0`; an old decoder ignores the newer tail. The Rust request field is serde-defaulted to zero (`userspace-dp/src/protocol/control.rs:1334-1340`), then becomes `None` (`server/helpers/session_sync.rs:609`). No raw peer-local ifindex crosses this wire: the sender transmits a stable fold and the receiver resolves to its own logical ifindex.

Compatibility consequence: an old sender may omit NAT-scope fold while still carrying the earlier ingress fold; if that ingress fold resolves to a non-fabric local identity, current Rust revalidation derives scope from it. A peer predating ingress-fold support, a failed/ambiguous ingress resolution, or a fabric-origin row can still import with no original ingress identity and stays on the #15176 keep. This preserves rolling-upgrade parsing and does not create a new guessed scope.

## Risks and costs

- **Accepted behavior cost:** an identity-less imported scoped translation can survive a rule withdrawal because it has no truthful matching scope; the documented #15176 trade is survival until idle expiry or another independent session-lifetime/revocation mechanism (`docs/log/15176.md:68-75`).
- **Rejected-fix risk:** an owner-only override could revoke valid flows under an empty/wrong interface scope or retain a withdrawn flow by selecting an unscoped successor. The rule selector's scope/first-match semantics make either direction possible.
- **Compatibility risk:** none introduced by this recommendation; no wire or runtime behavior changes.
- **Performance:** no runtime hot-path work is added. A future candidate-scope proof would add work proportional to candidate interfaces/rules on the stale-hit path; this is an architectural risk, not a measured cost.
- **Census limit:** source and fixtures establish reachable shapes, not their live frequency. A representative session-table capture or instrumentation-backed count would be needed before making deployment prevalence claims.

## Validation plan if a seat overturns PLAN-KILL

No code or tests are proposed on this branch. If seats find a truthful identity-bearing class not already judged, restrict any fix to `userspace-dp/src/afxdp/poll_descriptor/policy_revalidation.rs` and `policy_revalidation_tests.rs`, with a predicate that proves which identity fields are authoritative; do not use a nonzero egress/owner RG as ingress proof. Tests must run the full `policy_revalidation_tests.rs` module under the applicable isolated/CI environment, not only the new cell.

Required matrix if a rule change is later authorized:

| Identity | Scope present | Withdrawn rule | Valid rule |
|---|---|---|---|
| Identity-less | No | Keep | Keep / no invented-scope verdict |
| Identity-bearing | No | Judge (revoke only if the real derived scope no longer matches) | Judge and survive |
| Either | Yes | Revoke | Survive |

A finding that identity-bearing scope-less rows are currently skipped must first falsify the actual predicate at `policy_revalidation.rs:1543-1549` and the ingress derivation at `:820-854`; otherwise this proposed fix duplicates existing behavior.

## Open questions for the three plan seats

1. Can any production import produce `fabric_ingress == false`, positive `ingress_ifindex`, and a scope-less row for which the stored ingress `(ifindex,VLAN)` is not the original logical ingress identity? If yes, identify the exact producer/import transition and demonstrate it against the current path.
2. Is there a concrete owner-side proof (not a zone/egress guess) that recovers or uniquely constrains the ingress interface/RI for identity-less rows, including first-match rule ordering? What state and all competing ingress candidates must the proof cover?
3. Does the documented keep-until-expiry cost for truly identity-less rows justify a separate, backward-compatible provenance addition, or is reaffirming #15176 the correct bounded disposition until a source identity can be carried? What actual evidence would change that choice?

## Scope-size estimate

This recommendation is **one documentation file, zero production files, zero runtime behavior changes**. That is the bounded child-2 deliverable. If the seats overturn it in favor of new identity transport rather than the already-working derivation path, the change is not the two-file policy-only fix sketched above: it must preserve stable identity through Go cluster encoding/decoding, Go request resolution, Rust binding/import, and both language test suites. **Estimate: roughly 6–8 source/test files** for that alternative; estimate only, not a measured diff.
