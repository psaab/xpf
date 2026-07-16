PLAN-KILL (Option C) — reject Option A and re-plan around C: the global ordinal has no rule-set identity, so it can fall through past the one Junos-selected rule set.

# 1. Junos semantics

## Answer

The plan has the two documented precedence stages right, but Option A does not implement them.

Juniper's current **NAT Overview** says that when a packet matches multiple rule sets, Junos chooses the rule set with the more-specific context, ordered interface > zone > routing instance. It then says that the rules **in that selected rule set** are evaluated in order and the first matching rule is used. The older Juniper NAT application note depicts the same pipeline as rule-set lookup by precedence, one matching rule set, and then ordered rule lookup. These are external sources, not in-repo evidence:

- [Juniper NAT Overview — “Understanding NAT Rule Sets and Rules”](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html)
- [Juniper SRX/J Series NAT application note, pp. 5–7](https://supportportal.juniper.net/sfc/servlet.shepherd/document/download/0693c00000LXgIuAAL?operationContext=S1)

The destination-specific page is consistent at the context layer: it describes two match layers and uses interface-versus-zone as its example of the “most specific” destination-NAT rule. Its wording calls these overlapping “rules,” but the distinguishing conditions are rule-set `from` contexts, not packet-match prefix lengths. It also lists `off` as a destination-NAT action. External source: [Juniper Destination NAT — “Understanding Destination NAT Rules”](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-destination.html).

I did **not** find an official sentence that literally says, “do not try a less-specific rule set if the selected rule set has no matching rule.” No-fall-through is nevertheless the direct reading of all three official descriptions: select one most-specific rule set, then perform ordered lookup inside that set. The application-note diagram is singular (“Matching Rule Set N”), and neither source describes returning to rule-set selection. This is an external-document inference, not a fact verified in this repository. If absolute certainty is required, a vSRX packet trace is a prerequisite; uncertainty is not permission to ship the opposite behavior.

Option A performs global rule-candidate selection. Consider:

1. `rs-if`, scoped to ingress interface `ge-0/0/0.0`, whose only rule matches destination A.
2. `rs-zone`, scoped to that interface's ingress zone, with a rule matching destination B.
3. A packet enters `ge-0/0/0.0` for B.

Both rule-set contexts match. Under the documented select-one pipeline, `rs-if` wins by context; no rule in it matches B, so the inferred Junos result is no DNAT. Option A filters out the nonmatching interface row and globally selects the matching, higher-ordinal zone row. It therefore translates B: it has silently implemented rule-level fall-through.

This is not an “exotic refinement” that can safely be deferred, contrary to `docs/research/5145-dnat-first-match/plan.md:324-327`. The current snapshot is flat: the Go builder walks rule sets and rules and appends expanded rows at `pkg/dataplane/userspace/nat_destination.go:92-103,516-550`; the Go wire struct carries a rule name and three context fields but no rule-set identity at `pkg/dataplane/userspace/protocol.go:677-812`; the Rust snapshot likewise has no rule-set identity at `userspace-dp/src/protocol/nat.rs:205-309`; and `DnatEntry` has no such field at `userspace-dp/src/nat/destination.rs:64-126`. Once flattened, Rust cannot first select a rule set and then search only its rules.

The compiler and builder do preserve useful ordering material: the compiler appends parsed rules in its walk and then appends each scope-expanded rule set at `pkg/config/compiler_nat_destination.go:89-103,232-243`; the builder walks those slices in order at `pkg/dataplane/userspace/nat_destination.go:97-103`. That supports a within-rule-set sequence, but it does not substitute for a rule-set identifier.

## Evidence verdict

The plan's two-level prose model is supported; its global implementation is not. A parity implementation needs at least `(effective_rule_set_id, context_rank, rule_index)` and two-stage lookup, with the no-rule-match behavior pinned by a primary document or vSRX test.

## Question-alone PLAN-KILL?

**Yes.** Option A cannot express the documented selection boundary, and the plan explicitly tries to defer the missing architecture.

# 2. The ordinal design

## Answer

A scalar is mathematically equivalent to lexicographic `(context_rank, config_index)` **if** it is assigned by a stable rank-first walk, is unique per rule, does not overflow, and all expansions of one rule share it. The plan's proposed assignment does exactly that in its abstract ordering at `docs/research/5145-dnat-first-match/plan.md:139-151,186-195`. There is no counterexample caused merely by replacing that tuple with a dense integer.

The fatal loss occurs one level higher: the proposed key orders **rules**, whereas Junos first selects a **rule set**. Keeping `context_rank` and `config_index` as two fields would still choose the zone rule in the counterexample above, because the interface rule is not a matching candidate. Tuple-versus-scalar is a distraction; global-candidate argmin is the wrong abstraction.

Two same-type rule sets do not rescue the design:

- If their effective context values differ—two different interfaces or two different zones—one packet normally does not match both values.
- If they have the same effective context, the official Juniper material cited above specifies specificity but no declaration-order tie-break. I could not verify a primary Juniper rule for this duplicate-context case. Juniper-hosted community examples report commit rejection for destination-NAT rule sets with the same context, but that is non-primary evidence: [Juniper Community example](https://community.juniper.net/discussion/destination-nat-jsrx210-rule-set-rs1-and-rule-set-rs2-have-same-context-error-configuration-check-out-failed). Option A's stable declaration order would invent semantics unless xpf first rejects duplicate effective contexts or a vSRX test establishes a tie-break.

There is also a flattening hazard before Rust sees the data. Some configured rules emit no row—non-DNAT/no-pool rules and unresolved pools are skipped at `pkg/dataplane/userspace/nat_destination.go:105-147`, and malformed destinations are skipped at `pkg/dataplane/userspace/nat_destination.go:504-520`. Gaps in an ordinal are harmless, but loss of an entire selected rule set is not: two-stage Junos selection still needs to know that the more-specific rule set exists even when it has zero emitted candidates for a packet or, under lenient input, zero emitted rows at all.

## Evidence verdict

The fused integer itself is sound as an encoding of a lexicographic **rule order**. It is not an encoding of Junos rule-set selection. The proposed wire and Rust structures cannot represent the missing boundary.

## Question-alone PLAN-KILL?

**Yes.** The failure is architectural, not a tie-breaking nit. Option A needs a different data model, not separate integer fields.

# 3. Cost

## Answer

The plan is correct that production DNAT rule-table lookup occurs on the session-miss branch, not on every established-session packet. Session resolution starts at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:967-988`; on a hit, the poll loop returns the stored `resolved.decision` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1368-1388`. The `else` branch increments `session_misses` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1388-1390`, and the DNAT lookup occurs later inside that branch at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1558-1573`. The plan's cited counter line has drifted from 1387 to 1389; that does not change the conclusion.

That validates “per session miss.” It does **not** validate the plan's stronger “once per new session” or “negligible” conclusions:

- A session miss is not synonymous with a successfully installed new session. DNAT lookup occurs at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1558-1573`, before the routing override can drop and continue at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1815-1831`; such traffic does not create a reusable session and can pay again.
- Today an exact match short-circuits before every broader tier at `userspace-dp/src/nat/destination.rs:615-687`. The proposed global minimum must inspect lower tiers even for a common exact hit, because an earlier prefix/wildcard rule may have the lower ordinal. “Same asymptotic cost” does not mean same session-establishment cost.
- The plan calls prefix lookup one of four tiers, but it is itself a three-bucket short-circuit: exact protocol+port, wildcard port, and `PROTO_ANY` at `userspace-dp/src/nat/destination.rs:777-840`. A faithful global argmin must inspect all three relevant prefix vectors as well as all three exact-host vectors. If it leaves `match_prefix_lpm` short-circuiting, a later prefix sub-tier with a lower ordinal is missed. The four-tier pseudocode at `docs/research/5145-dnat-first-match/plan.md:203-214` is therefore under-specified.
- Prefix selection linearly scans every slot in a selected bucket at `userspace-dp/src/nat/destination.rs:862-884`; source and extra-L4 predicates are evaluated per candidate at `userspace-dp/src/nat/destination.rs:128-197`. The builder may emit many rows per configured rule through its nested expansion and append loop at `pkg/dataplane/userspace/nat_destination.go:148-155,516-550`.

The plan supplies no table-size measurement, session-creation-rate measurement, or benchmark for exact-hit traffic with a large prefix bucket. Its “handful to dozens” assertion at `docs/research/5145-dnat-first-match/plan.md:229-237` is unsupported in-repo. As an external upper-bound warning, Juniper's current capacity table lists destination-NAT capacities up to 51,200 rules on some platforms; that does not prove xpf deployments are that large, but it disproves treating large tables as architecturally irrelevant. External source: [Juniper NAT Overview — NAT Rule Capacity](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html).

A viable Option A plan would have to specify all six bucket scans (or a different index), cap/measure candidate populations, and benchmark at least exact-hit and denied-miss workloads with large same-bucket prefix tables.

## Evidence verdict

**Per-session-miss is true; negligible cost is unproven.** The current `LOW` performance rating at `docs/research/5145-dnat-first-match/plan.md:278-285` is not evidence-based.

## Question-alone PLAN-KILL?

**Yes for the plan as written.** This may be repairable with an indexed design and benchmarks, but the proposed algorithm is both incomplete and defended by an unsupported risk claim.

# 4. HA mixed-version behavior

## Answer

Synced sessions replay a resolved NAT decision; they do not re-run destination rule lookup. The plan's conclusion is partly right, but its stated `dnat_table` mechanism is wrong.

Resolved-decision trace:

1. A pure DNAT match creates a `NatDecision` with `rewrite_dst` populated and `rewrite_src: None` at `userspace-dp/src/nat/destination.rs:695-720`. `NatDecision` is explicitly documented as HA-serialized through the session decision/delta at `userspace-dp/src/nat/mod.rs:84-103`.
2. The Rust session-event codec writes the resolved NAT ports and addresses, including `rewrite_dst`, at `userspace-dp/src/event_stream/codec/session_sync.rs:45-52,127-131`. Go decodes those into `NATDstPort`/`NATDstIP` at `pkg/dataplane/userspace/eventstream.go:1087-1093,1121-1130`.
3. The daemon converts the delta into a session value and sets the DNAT flag plus resolved destination at `pkg/daemon/daemon_ha_userspace_convert.go:184-214`, then queues that value for HA at `pkg/daemon/daemon_ha_userspace_stream.go:342-370`. The cluster wire encodes and decodes the v4 NAT destination at `pkg/cluster/sync_protocol.go:95-141,375-388` (v6 encode/decode: `pkg/cluster/sync_protocol.go:195-236,490-505`).
4. The cluster receiver installs through the userspace-specific session installer at `pkg/dataplane/session_store.go:300-303,355-358`. The receiving userspace manager copies the stored NAT destination into `SessionSyncRequest` and clears it only when the DNAT flag is absent at `pkg/dataplane/userspace/manager_ha.go:1283-1312` (v6: `pkg/dataplane/userspace/manager_ha.go:1364-1395`). The request's destination fields are defined at `pkg/dataplane/userspace/protocol.go:2866-2893`.
5. Rust parses those fields and reconstructs `NatDecision.rewrite_dst` at `userspace-dp/src/server/helpers.rs:447-474,497-539`. The sync handler immediately calls `upsert_synced_session`; there is no DNAT rule-table call at `userspace-dp/src/server/handlers/sync_session.rs:19-23`. HA publishes the imported `entry.decision.nat` into session state at `userspace-dp/src/afxdp/ha.rs:310-316,355-369` and sends the same entry to workers at `userspace-dp/src/afxdp/ha.rs:410-417`. The worker command re-resolves only local forwarding from the already resolved decision, then installs that unchanged NAT decision at `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:33-75`; subsequent session lookup reads the stored decision at `userspace-dp/src/afxdp/session_glue/mod.rs:1053-1155`.

The plan specifically attributes this safety to a `dnat_table` BPF-map publish at `docs/research/5145-dnat-first-match/plan.md:257-270`. That is false for pure DNAT. `publish_dnat_table_entry` immediately returns unless `nat.rewrite_src` exists at `userspace-dp/src/afxdp/checksum.rs:303-311`; HA's comments describe the publish as reverse-SNAT steering at `userspace-dp/src/afxdp/ha.rs:317-350`. The Go session store has the same condition: it calls `SetDNATEntry` only for a forward SNAT session at `pkg/dataplane/session_store.go:289-296,344-350`. Pure DNAT survives HA because the resolved decision is installed in the synchronized session, not because this reverse-SNAT map is populated.

That protects a successfully synchronized live session. It does not make rolling mixed-version semantics safe for fresh, expired, missed, or independently created sessions. An old helper resolves those with current specificity precedence while a new helper resolves them with Option A order; the plan itself acknowledges this divergence at `docs/research/5145-dnat-first-match/plan.md:257-270`. After a role transition, otherwise identical new flows can change translation or exemption behavior based only on which version is active.

The all-zero fallback is also underspecified. “Deterministic” is insufficient: a new helper receiving snapshots from an old control plane must execute the **exact current algorithm**—the exact/wildcard/proto-any/prefix short-circuit plus zone-first and LPM—not merely break equal ordinals by insertion order. Current precedence is explicit at `userspace-dp/src/nat/destination.rs:615-687,745-756,843-889`; the plan asks only for a deterministic fallback at `docs/research/5145-dnat-first-match/plan.md:257-274,303-305`.

Option A therefore needs either a negotiated semantic capability/config-generation gate that retains old precedence until both peers support the new mode, or an explicit operational prohibition on mixed-version activation. An additive JSON field is decoding-compatible; it is not a semantic gate.

## Evidence verdict

Session sync replays the resolved decision, but through session state, not the `dnat_table` map. Synced sessions narrow the skew window; they do not remove the need to gate a security-relevant match-semantics change.

## Question-alone PLAN-KILL?

**Yes.** The mitigation names the wrong mechanism, the legacy fallback does not promise legacy semantics, and no activation gate exists in the plan.

# 5. Regression surface

## Answer

Option A does not preserve all of the claimed invariants. One missed interaction makes the motivating `off` example fail end to end even if the ordinal lookup itself returns the intended winner.

### Zone-specific versus wildcard

Current exact lookup explicitly searches a matching nonempty `from_zone` before empty-zone entries at `userspace-dp/src/nat/destination.rs:725-775`; prefix lookup repeats that priority before LPM at `userspace-dp/src/nat/destination.rs:843-889`. The exact behavior has an adversarial regression test where an earlier wildcard row must lose to a later zone-specific row at `userspace-dp/src/nat/tests_destination.rs:1450-1491`.

Valid new ordinals could preserve zone-scoped over truly global entries because the plan ranks zone above global. But the current “zone-wildcard” arm also contains interface- and RI-scoped entries: those scopes live in separate fields, `from_zone` is empty, and `scope_ok` merely AND-gates them at `userspace-dp/src/nat/destination.rs:65-72,128-136,757-773`. Option A intentionally changes those relationships to interface > zone > RI. That may be a parity correction, but it is a new behavior, not simple subsumption. In all-zero legacy mode, removing the explicit two-pass selector breaks even zone-over-global unless the complete old algorithm remains as a separate mode.

### #3844 off-versus-translate and the missed LocalDelivery failure

The narrow identity invariant can survive. `off` becomes `DnatOutcome::Exempt` at `userspace-dp/src/nat/destination.rs:200-207`, and the `off` bit is part of both prefix and exact dedup identities at `userspace-dp/src/nat/destination.rs:892-933,935-975`, so otherwise-identical off and translate rows remain distinct.

The end-to-end semantics do **not** survive the plan's unchanged local-address registration:

1. `destination_ips_scoped` skips each off row but still exports every non-off translate destination, without considering which row can win by ordinal, at `userspace-dp/src/nat/destination.rs:1028-1083`.
2. The forwarding builder installs all those translate destinations into firewall-local sets at `userspace-dp/src/afxdp/forwarding_build/mod.rs:441-492`.
3. A winning exemption is collapsed to the same `None` as “no rule” at `userspace-dp/src/nat/destination.rs:688-698`. The poll path therefore retains the original destination as the effective routing target at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1596-1602,1673-1683`.
4. That original destination is passed to forwarding resolution at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1836-1868`. If it was registered by the later translate, forwarding returns `LocalDelivery` before ordinary FIB lookup at `userspace-dp/src/afxdp/forwarding/mod.rs:1468-1543`.

Therefore, in the plan's `/24 off` followed by `/32 translate` example, making the `/24` row win does not necessarily route the real host without NAT. The later `/32` translate still marks that address as a VIP; the exempt packet can be consumed as firewall-local. This directly contradicts the reason the code gives for excluding off destinations—avoiding proxy-ARP/ND hijack of a real routed host—at `userspace-dp/src/nat/destination.rs:1032-1039`, and refutes “local-address registration unaffected” at `docs/research/5145-dnat-first-match/plan.md:275-276`.

The same trace means the plan's claim that the common more-specific `/32 off` idiom “already works” at `docs/research/5145-dnat-first-match/plan.md:59-66` is established only at matcher level. A covering translate prefix may still add the off host to the local set through bounded prefix expansion at `userspace-dp/src/nat/destination.rs:1043-1077`. That needs an end-to-end test before it can be used to justify scope or risk.

Fixing this is not a small ordinal tweak. The dataplane must preserve an explicit Exempt outcome into forwarding so that DNAT-derived local ownership can be bypassed for that flow, or compute precedence-aware local ownership. Static global local-IP sets cannot by themselves encode source-, port-, protocol-, interface-, or zone-dependent exemptions. Both options violate the plan's “lookup API unchanged/local registration unaffected” premise at `docs/research/5145-dnat-first-match/plan.md:239-248,275-276`.

### #3164 LPM and other existing contracts

Option A deliberately retires #3164 rather than preserving it. Exact hosts currently beat prefixes at `userspace-dp/src/nat/destination.rs:615-687`, and prefix buckets use proto/port specificity plus longest prefix at `userspace-dp/src/nat/destination.rs:777-889`. The regression test expressly requires a later `/28` to beat an earlier `/24` and an exact host to beat both at `userspace-dp/src/nat/tests_destination.rs:1084-1123`. The same LPM/exact-host contract is public documentation at `docs/userspace-dnat-plan.md:572-579`, `docs/feature-gaps.md:189-196`, and `docs/feature-coverage.md:351-352`. The plan mentions reversing one LPM test at `docs/research/5145-dnat-first-match/plan.md:294-305`, but it does not list those required documentation migrations.

Additional established contracts include:

- A later exact-port translate beats an earlier wildcard-port translate at `userspace-dp/src/nat/tests_destination.rs:1397-1447`.
- A later concrete protocol/port translate beats an earlier IP-only rule at `userspace-dp/src/nat/tests_dnat_proto.rs:151-199`.
- Exact and prefix insertion replace an identical earlier same-action entry with the later entry at `userspace-dp/src/nat/destination.rs:896-933,935-975`; explicit tests require last-wins for same-zone and unscoped duplicates at `userspace-dp/src/nat/tests_destination.rs:1567-1610,1613-1635`. “Keep lowest ordinal” flips these to first-wins.
- The deliberate current cross-tier contract is documented in code at `userspace-dp/src/nat/destination.rs:745-756`; this is the surviving intent from #3852, not an accidental implementation detail.

There is a test-masking trap: Rust's snapshot derives `Default` at `userspace-dp/src/protocol/nat.rs:205-206`, and the cited direct Rust fixtures use `..DestinationNATRuleSnapshot::default()`, for example `userspace-dp/src/nat/tests_destination.rs:1401-1420,1453-1476`. After an ordinal is added, those fixtures become all-zero legacy inputs. If all-zero correctly preserves old semantics, the old tests remain green while production Go emits nonzero order and behaves differently. Production-semantics tests must stamp ordinals explicitly or build snapshots through the Go path; legacy all-zero tests must be separate.

## Evidence verdict

Zone/global ordering can be preserved only with a true legacy mode; #3844 row distinctness can be preserved; #3164 and several specificity/duplicate contracts are intentionally reversed. More importantly, the unmodeled local-delivery path invalidates the motivating success case.

## Question-alone PLAN-KILL?

**Yes.** The LocalDelivery interaction is an architectural blocker, and the migration/test analysis is incomplete even apart from it.

# 6. Is PLAN-KILL the right call? Option C versus Option A

## Answer

Yes: kill Option A. Option C is the proportionate direction, but the current three-line Option C is not itself implementation-ready and needs a new plan.

The risk/reward balance favors C:

- Current most-specific precedence was deliberately documented and remains explicit at `userspace-dp/src/nat/destination.rs:745-756`.
- The plan itself says the reported inversion requires the unusual broad-earlier rule to cross representation tiers, while a more-specific off already wins at matcher level at `docs/research/5145-dnat-first-match/plan.md:54-72`; that matcher behavior is covered for exact-port off over wildcard translate at `userspace-dp/src/nat/tests_destination.rs:268-324`.
- Option A changes translate/translate, prefix, port, protocol, duplicate, cross-context, fresh-session HA, and local-delivery behavior—not just the security-labeled off case. The concrete surfaces are cited in sections 3–5 above.
- Option C can make the silent precedence inversion operator-visible without changing Rust lookup, snapshot wire semantics, or HA session decisions. The plan itself recognizes that trade at `docs/research/5145-dnat-first-match/plan.md:74-77,349-378`.
- Option A defers functional smoke and rests on design plus unit tests at `docs/research/5145-dnat-first-match/plan.md:310-318`, which is especially weak when its motivating success case needs full forwarding-path coverage.

A viable Option C plan must still specify:

1. **Disposition and compatibility.** For an off exemption that current tier precedence will bypass, a strict commit error is more defensible than an ignorable warning; tolerant load/peer-sync should warn rather than brick. The repository already documents the strict-error/tolerant-warning pattern for DNAT validation at `pkg/config/compiler_validate_strict_nat.go:159-174,289-303`.
2. **The exact overlap model.** A naive “longer prefix later” check is insufficient. The builder expands address lists, applications, protocols, ports, source constraints, and destination ranges before emitting rows at `pkg/dataplane/userspace/nat_destination.go:148-155,270-315,380-420,516-550`. The lint must reason over the same canonical match space and current exact/wildcard/proto-any/prefix precedence, while retaining source rule names for diagnostics.
3. **Scope.** Start with inversions inside one effective rule set; explicitly define whether broad translate/translate is an error, warning, or merely informational. Diagnose both rule names, the overlapping traffic, and the tier that will win.
4. **Dynamic address names.** NAT address-name resolution unions static prefixes with live feed content at `pkg/dataplane/userspace/nat.go:26-47`, and feed updates rebuild snapshots independently of a new operator edit at `pkg/dataplane/userspace/manager_overlay.go:63-73`. A commit-only literal-prefix lint can miss an inversion introduced by later feed content; the plan needs conservative validation or a feed-update diagnostic.
5. **Tests.** Cover broad-off/later-specific translate, broad-translate/later-specific translate, disjoint source/port/protocol/scope cases, application and feed expansion, strict-versus-tolerant handling, and full forwarding/local-target behavior. The last item is mandatory because `Exempt` currently loses its identity before routing, as shown in section 5.

Option C does not close the Junos parity gap; it makes the narrow dangerous inversion explicit while avoiding a knowingly wrong parity rewrite. The local-delivery finding should be fixed or separately tracked regardless, because it may affect the current “common” more-specific-off pattern too.

## Evidence verdict

The current Option A is not salvageable by nits. Option C offers the better risk decision, but it needs a concrete lint semantics/expansion/compatibility/test plan before implementation.

## Question-alone PLAN-KILL?

**Yes for Option A.** The correct next artifact is a revised Option C plan, not implementation of this plan.

# Final summary

**Verdict: PLAN-KILL (Option C).** Reject Option A and re-plan the operator-visible lint path.

Top risks if Option A proceeds as written:

1. **Wrong Junos architecture:** the flat global ordinal cannot honor a selected rule-set boundary and implements undocumented fall-through.
2. **Motivating case fails end to end:** a losing translate still registers the destination as firewall-local, while a winning `off` collapses to `None`, so exempt traffic can take `LocalDelivery` instead of ordinary routing.
3. **Under-gated broad behavior change:** legacy all-zero semantics, mixed-version fresh sessions, six-bucket scan cost, and multiple deliberate specificity/duplicate contracts are not adequately modeled or validated.

If Option A is ever reconsidered, the minimum bar is a primary/vSRX no-fall-through result, explicit rule-set identity and two-stage selection, an Exempt-aware forwarding/local-ownership design, exact legacy-mode semantics plus HA activation gating, and large-table session-miss benchmarks. Given the narrow reported trigger and the deliberate current contract, that is disproportionate to a precisely designed Option C lint.
