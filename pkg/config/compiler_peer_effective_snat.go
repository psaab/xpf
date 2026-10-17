package config

// The SOURCE-NAT subject of the peer-effective strict gate (#5876). The
// mechanism that compiles the peer view and dispatches every registered subject
// lives in compiler_peer_effective.go; this file owns only which validators the
// source-NAT subject runs.
//
// The strict SNAT gates (validateSourceNATPoolStrict,
// validateSourceNATPoolAddressGrammarStrict, validateSourceNATPoolAddressScopeStrict,
// validateSourceNATPersistentNoTranslationStrict, validateSourceNATAggregateCardinalityStrict,
// validateNATPoolReferencesStrict, validateNATSourceAddressNameReferencesStrict)
// already run inside
// compileExpanded — but ONLY against the single node the commit compiles for.
// The strict commit gate (configstore.compileTreeStrict) compiles
// CompileConfigForNode(localNodeID) alone, so a source-NAT pool / reference error
// that is valid on the ORIGIN's effective view but invalid on the PEER's — a
// per-node pool address, a divergent `port range`, a top-level rule referencing a
// pool that only a peer `groups nodeN` block defines — is chassis-aware compiled
// only for the local node and never strict-validated. The originating commit
// passes green; the standby then ingests the synced snapshot via the TOLERANT
// path (Store.SyncApply -> CompileConfigForNodeLenient), which downgrades the
// strict SNAT gate to a warning and installs nothing (fail-closed) — SNAT
// silently degrades on the node that just took over. This gate pulls the peer's
// strict SNAT check forward to the origin's commit.
//
// The peer-effective view the subject runs against is produced with
// CompileConfigForNodeLenient(peerID) by the shared mechanism — the EXACT
// transform the standby applies on Store.SyncApply — so the pools and rules
// validated here are precisely what the peer will instantiate (same ${node}
// apply-group substitution and per-node rewrites).
//
// validateSourceNATStrictView runs the strict NAT representability validators
// that touch source-NAT rules (the source-NAT-relevant validators the NAT gates
// in runUniformGates dispatch on the local compiled view) against an
// ALREADY-COMPILED *Config. It REUSES the existing validators verbatim — no new
// SNAT rules — so the peer-effective gate (#5876) and the local commit path
// cannot drift on what a representable source pool / rule is.
//
// The peer view is validated by exactly the strict validators that iterate the
// source-NAT config, because the standby's own SyncApply is LENIENT — the origin's
// peer gate is the SOLE strict check the peer view ever gets, so any strict
// validator that could catch a peer-only ${node}/groups divergence in a source
// rule must run here (else that divergence strands the standby, the #5876 shape).
// This includes the pool/reference/grammar/persistent validators AND the
// rule-match/action validators (match-destination-port, terminal-action
// cardinality, and match-applications — the last fails OPEN to a wildcard
// translation, so omitting it would leave a peer-only fail-open, #6048 review).
// validateNATPoolReferencesStrict / validateNATSourceAddressNameReferencesStrict /
// the three match-action validators also cover destination NAT; they are included
// whole (splitting them would duplicate logic) so the peer gate is a beneficial
// superset that matches their local-view behavior exactly — a peer-only DNAT
// pool / address-name / match error is caught too, never a false-reject.
//
// The set also includes validateNATPoolExternalTupleOverlapStrict (#5144, run
// strict), because a peer-only overlapping pool set — differently-named
// overlapping source pools, a source pool that also backs a NAT64 rule-set, or
// duplicate members produced only under the peer's `${node}`/groups resolution —
// is precisely the divergent-commit fail-open this gate exists to close: the
// origin commits green and the standby lenient-loads the vulnerable independent
// allocators. It is the last strict source-NAT gate wired in runTailGates rather
// than runUniformGates, so it is carried here explicitly.
func validateSourceNATStrictView(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if err := validateSourceNATPoolStrict(cfg); err != nil {
		return err
	}
	if err := validateNATPoolReferencesStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATPoolAddressScopeStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATPoolAddressGrammarStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATAggregateCardinalityStrict(cfg); err != nil {
		return err
	}
	if err := validateNATSourceAddressNameReferencesStrict(cfg); err != nil {
		return err
	}
	if err := validateNATMatchDestinationPortStrict(cfg); err != nil {
		return err
	}
	if err := validateNATTerminalActionCardinalityStrict(cfg); err != nil {
		return err
	}
	if err := validateNATMatchApplicationsStrict(cfg); err != nil {
		return err
	}
	// #5144: source-NAT / NAT64 external-tuple overlap. A `${node}`/groups
	// rewrite that makes the peer's resolved pool set overlap (differently-named
	// overlapping source pools, a source pool that also backs a NAT64 rule-set,
	// or duplicate members) while the origin's is disjoint would COMMIT green on
	// the origin, and the standby's lenient SyncApply only WARNS + installs the
	// vulnerable independent allocators — a peer-only false-ACCEPT of the exact
	// #5144 collision. Run the strict overlap gate against the peer-effective view
	// too (lenient=false → error, no warnings). The local commit already runs it
	// in runTailGates; this is its #5876 peer-effective mirror.
	if _, err := validateNATPoolExternalTupleOverlapStrict(cfg, false); err != nil {
		return err
	}
	// #14368: a peer-only divergence can likewise place a static external
	// inside the peer's referenced pool set while the origin's is disjoint.
	if _, err := validateStaticNATPoolOverlapStrict(cfg, false); err != nil {
		return err
	}
	return nil
}
