# Hostile plan reviewer B (independent Claude general-purpose) — r1 — #2078

VERDICT: PLAN-KILL (favor Path C2 — warn-and-document). As written the plan
is NOT ready to ship Path B: one of its three knobs is not implementable as
described and the plan omits a decisive prior project decision.

1. [BLOCKER] `no-syn-check-in-tunnel` is NOT implementable as described —
   "in tunnel" has no dataplane signal and `fabric_ingress` is a semantic
   misidentification. `ingress_is_fabric`
   (`userspace-dp/src/afxdp/forwarding/mod.rs:293-297`) tests the HA cluster
   fabric link (inter-chassis session-sync), not a Junos IPsec/GRE tunnel.
   `SessionMetadata` (`session/entry.rs:24-29`) has only `fabric_ingress` /
   `is_reverse` — no tunnel marker. A grep for ipsec/gre/decap ingress markers
   finds only WireGuard + the HA fabric. Gating on `fabric_ingress` would
   silently relax syn-check for cross-chassis HA traffic. This sinks Path B as
   scoped.

2. [BLOCKER] The plan omits a 4th sibling knob with identical status AND an
   explicit reviewed decision to keep this family config-only.
   `TCPSessionConfig` (`pkg/config/types_security.go:110-128`) carries
   `NoSequenceCheck` (#2008 M9); its in-source comment is a deliberate
   posture: "typed-config only today, exactly like NoSynCheck /
   RstInvalidateSession ... the single seam a future sequence-checking
   dataplane would read." The plan treats #2078 as fresh when the project
   already, knowingly, chose the config-only-seam answer for the whole family.
   A plan must (a) acknowledge that decision, (b) justify reversing it for two
   of four, (c) say what happens to `no-sequence-check`. The plan does none.

3. [MAJOR] Ignores prior-art RST design rationale.
   `docs/active-active-new-connections.md:840-890` already reasoned RST:
   suppress RST→CLOSED for ESTABLISHED, forward RST to endpoints, keep
   `rst-invalidate-session` as opt-in "accepting the stream-death risk,"
   because "BPF conntrack doesn't track TCP sequence numbers." This is exactly
   RISK-2, already decided. The plan re-litigates from scratch.

4. [MAJOR] RISK-1's mitigation is incoherent. "No-op unless tcp-session
   stanza configured" is non-Junos (SRX syn-check is on by default regardless
   of stanza) and surprising (setting an unrelated established-timeout would
   silently flip syn-check on). The only honest choices are default-on (breaks
   every deployment accepting mid-stream TCP incl. asymmetric/ECMP/post-
   failover synced flows) or never-enforce. Open question #2 has no clean
   answer — an argument for C2.

5. [MAJOR] HA/failover under-analyzed; test plan doesn't exercise the new
   path. Synced-session import uses `SyncImport`/`SharedMaterialize` origins;
   a careless gate keyed on "non-SYN at install" rather than strictly
   `ForwardFlow` would drop bulk-sync import. rst-invalidate on a synced
   session: a blind RST tears down a session the peer believes live, then the
   delete must propagate over session-sync — unanalyzed. §7's
   `make test-failover` is a no-regression gate, not a new-path test (project
   memory: "test-failover proves no-regression NOT the new feature").

6. [MAJOR] Proportionality strongly favors PLAN-KILL (C2). Two (of four) LOW,
   rarely-used knobs; audit rated #2078 LOW. Real harm is silent misleading,
   removed by C2 at near-zero risk, consistent with the existing config-only
   posture. Path B touches the install + lookup hot paths, has no clean
   rollout, adds a spoofable-teardown vector, and can't deliver one of three
   knobs. Benefit does not beat risk.

7. [MINOR] Completeness: config-mode schema completion is ALREADY done
   (`pkg/config/schema_security.go:243-246` — all four knobs), contradicting
   §E's open item. No counters / `show` surface specified for the silent
   syn-check drops (mandatory per account-don't-unwind,
   `engineering-style.md:188-190`). Screen / SYN-cookie-flood ordering vs a
   default-on syn-check unanalyzed.

8. [MINOR] Every source line reference is stale (~40-55 lines);
   `session/mod.rs` split into install/lookup/expire (#2005). Real call-site
   origins: `poll_descriptor/mod.rs:534`=ReverseFlow, 1373=ForwardFlow,
   1575=ReverseFlow, 2777=MissingNeighborSeed — the gate attaches to ONE site
   (ForwardFlow), not "the forward-create install call" generically.

9. [MINOR] "rst-invalidate = one extra branch" understates the eager-cleanup
   removal path (`remove_entry`, `session/mod.rs:645`, #964 invariant) plus
   skipping the wheel push after a scoped `&mut` borrow ends.

VERIFIED RIGHT: flow.go/protocol.go field absence; no SYN gate at install
(tcp_flags used only for timeout/closing); RST arm sets closing+30s only;
tcp_flags free on fast path; `state.x=snapshot.flow.x` threading
(`forwarding_build/mod.rs:173-181`, `PowerModeDisable` as a parity-only-flag
precedent); bool↔bool wire safety vs the #1961/#1977 numeric class;
engineering-style branch discipline; dead `flow_config_map`/TCPFlags removal
is legit cleanup.

Bottom line: PLAN-KILL with a Path-C2 follow-up. If a maintainer overrides to
ship, the plan must first: drop/re-scope `no-syn-check-in-tunnel`; reconcile
against the config-only-seam decision + `no-sequence-check` + the active-
active RST rationale; replace the incoherent RISK-1 gate; specify SyncImport-
safe origin gating + cross-chassis RST-teardown sync + a new-path failover
test; add drop/teardown counters + a `show` surface + screen/SYN-cookie
ordering analysis. Even fully revised, proportionality (#6) stands and I still
favor C2.
