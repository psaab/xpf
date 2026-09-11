package config

import (
	"errors"
	"fmt"
	"strings"
)

// ErrDPDKDataplaneRetired is the sentinel error returned at commit
// time when a configuration sets `system dataplane-type dpdk`. External
// API consumers (gRPC orchestration, REST wrappers, CLI tooling) can
// match this with errors.Is rather than substring-searching the wrapped
// error text. The wrapped form is preserved verbatim so the operator-
// facing migration message remains stable; see #1525.
//
// Mirrors the runtime-side dataplane.ErrDPDKBackendRetired sentinel
// introduced by #1527 so the config-time and runtime layers both expose
// structured rejections.
var ErrDPDKDataplaneRetired = errors.New(
	"the DPDK dataplane backend has been retired; " +
		"use 'set system dataplane-type userspace' " +
		"(see #1525)")

// ErrEBPFDataplaneRetired is the sentinel error returned at commit
// time when a configuration sets `system dataplane-type ebpf`. The
// parse path still accepts the token as a legal value so that
// `load merge` / `load override` of a pre-retirement configuration
// does not syntax-error; this strict validator is what tells the
// operator to migrate.
//
// Mirrors the runtime-side dataplane.ErrEBPFBackendRetired sentinel
// introduced by #1476 so the config-time and runtime layers both
// expose structured rejections. The verbatim message must remain
// stable for downstream tooling that matches by text.
var ErrEBPFDataplaneRetired = errors.New(
	"the legacy eBPF dataplane backend has been retired; " +
		"use 'set system dataplane-type userspace' " +
		"(see #1373)")

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
// It clones the tree before expansion so the original tree is not mutated.
func CompileConfig(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{})
}

// CompileConfigLenient is CompileConfig with the tolerant-path
// downgrades enabled (#1798 control-char sanitize-in-place, lenient
// VRRP track duplicates). Use on TOLERANT paths that compile an
// already-active / already-persisted config the operator did not just
// author — e.g. Store.Load of a persisted config — so an upgraded node
// boots through. MUST NOT be used on the candidate-commit path:
// commit / commit-check use the strict CompileConfig so new operator
// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
// covers the cluster paths (Store.SyncApply, peer-interface display).
// (The former #1733 equal-flow worker-cap downgrade was retired in
// #1830 (e) — the dataplane no longer caps equal-flow at 32 workers.)
func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, lenientCompileOpts())
}

// validateWebManagementAuthStrict hard-rejects a `system services
// web-management` config that binds the REST / config API to a NON-LOOPBACK
// address without any REST authentication configured (#4047, fable-161 F-155).
//
// The REST server (pkg/api) serves the mutating config endpoints — POST
// /api/v1/config/{set,delete,commit,commit-confirmed,rollback,load,activate}
// and /api/v1/system/action — with NO auth middleware unless api-auth is set:
// pkg/api/server.go wires the auth middleware only when cfg.Auth != nil, and
// the daemon (daemon_run.go) sets apiCfg.Auth only when web-management api-auth
// carries at least one user or api-key. The default bind is loopback
// 127.0.0.1:8080 (safe); a `web-management http|https interface <mgmt-if>`
// stanza resolves to the interface's routable address (daemon_run.go ->
// resolveInterfaceAddr), so binding off-loopback WITHOUT api-auth exposes every
// mutating config RPC to any host that can reach the management address — a
// network attacker can reconfigure the firewall unauthenticated.
//
// A non-loopback bind is signalled by a non-empty HTTPInterface or
// HTTPSInterface (the only way web-management moves the REST server off
// loopback). "Authenticated" means APIAuth carries at least one user OR
// api-key — the same predicate daemon_run.go uses to actually wire the auth
// middleware, so this gate rejects exactly the configs that would bind
// unauthenticated. HTTPS is covered too: transport encryption without
// authentication still lets any reachable client mutate config.
//
// Strict on the commit / commit-check path (hard-reject). Downgraded to a
// cfg.Warnings entry on the tolerant load / peer-sync paths
// (lenientWebManagementAuth) so an already-persisted or peer-synced config that
// an older binary accepted still BOOTS (#1960 fail-closed-on-load). The daemon's
// runtime bind path independently CLAMPS a non-loopback + no-auth bind back to
// loopback (part B, daemon_run.go), so the leniently-loaded config is preserved
// but not left exposed — the operator adds api-auth and recommits to restore the
// non-loopback bind.
func validateWebManagementAuthStrict(cfg *Config) error {
	if cfg == nil || cfg.System.Services == nil || cfg.System.Services.WebManagement == nil {
		return nil
	}
	wm := cfg.System.Services.WebManagement
	var binds []string
	if wm.HTTPInterface != "" {
		binds = append(binds, fmt.Sprintf("http interface %q", wm.HTTPInterface))
	}
	if wm.HTTPSInterface != "" {
		binds = append(binds, fmt.Sprintf("https interface %q", wm.HTTPSInterface))
	}
	if len(binds) == 0 {
		return nil // loopback bind (default) — safe without auth
	}
	// #5636: an EMPTY Basic password or empty api-key is NOT a valid
	// credential — a quoted-empty secret (`password ""` / `api-key ""`) parses
	// as a credential row but authenticates any request that presents the empty
	// value, so it must not satisfy the off-loopback auth gate. Count only
	// USABLE (non-empty) credentials here; the daemon runtime wiring
	// (daemon_run.go) and the API middleware (pkg/api/auth.go) independently
	// drop/reject empty secrets, and validateAPIAuthNoEmptySecretsStrict rejects
	// the empty secret outright at strict commit.
	authed := apiAuthHasUsableCredential(wm.APIAuth)
	if authed {
		return nil
	}
	return fmt.Errorf(
		"system services web-management binds the REST/config API off-loopback (%s) without api-auth — the REST API is UNAUTHENTICATED, so an off-loopback bind exposes the mutating config endpoints (set / commit / rollback / system action) to the network; configure `set system services web-management api-auth {user <name> password <pw> | api-key <key>}` or remove the interface binding to keep the API on loopback (#4047)",
		strings.Join(binds, ", "))
}

// apiAuthHasUsableCredential reports whether an api-auth stanza carries at
// least one NON-EMPTY credential: a user with a non-empty password, or a
// non-empty api-key. An empty Basic password or empty api-key is never a valid
// credential — wiring it would let a request presenting `username:` (no
// password) or an empty Bearer/X-API-Key token authenticate — so it must not
// count as "authenticated" for the off-loopback bind gate (#5636). Mirrors the
// runtime credential wiring in daemon_run.go and the empty-secret rejection in
// pkg/api/auth.go.
func apiAuthHasUsableCredential(a *APIAuthConfig) bool {
	if a == nil {
		return false
	}
	for _, u := range a.Users {
		if u != nil && u.Password != "" {
			return true
		}
	}
	for _, k := range a.APIKeys {
		if k != "" {
			return true
		}
	}
	return false
}

// validateAPIAuthNoEmptySecretsStrict rejects a `system services web-management
// api-auth` stanza that carries an EMPTY Basic password or an EMPTY api-key. A
// quoted-empty secret (`password ""` / `api-key ""`) parses as a real
// credential row: without this gate the compiler stores it, daemon_run.go wires
// it into the runtime AuthConfig, and the middleware's constant-time compare
// matches a request that presents the empty value (`username:` with no
// password, or a `Bearer `/empty X-API-Key token). On an OFF-loopback bind that
// is an authentication bypass — any reachable client authenticates with an
// empty secret (#5636, codex-review-181 M28). An empty secret is never a valid
// credential regardless of bind, so reject it at strict commit / commit-check.
// Downgraded to a warning on the tolerant load / peer-sync path
// (lenientWebManagementAuth) so an already-persisted config still BOOTS (#1960);
// the empty credential is independently dropped at runtime wiring
// (daemon_run.go) and rejected by the middleware (pkg/api/auth.go), so it never
// becomes an active credential.
func validateAPIAuthNoEmptySecretsStrict(cfg *Config) error {
	if cfg == nil || cfg.System.Services == nil || cfg.System.Services.WebManagement == nil {
		return nil
	}
	wm := cfg.System.Services.WebManagement
	if wm.APIAuth == nil {
		return nil
	}
	for _, u := range wm.APIAuth.Users {
		if u != nil && u.Password == "" {
			return fmt.Errorf(
				"system services web-management api-auth user %q has an empty password — an empty Basic secret is not a valid credential and would authenticate any request presenting `%s:` with no password (an auth bypass on an off-loopback bind); set a non-empty password or remove the user (#5636)",
				u.Username, u.Username)
		}
	}
	for _, k := range wm.APIAuth.APIKeys {
		if k == "" {
			return fmt.Errorf(
				"system services web-management api-auth has an empty api-key — an empty api-key is not a valid credential and would authenticate any request presenting an empty Bearer / X-API-Key token (an auth bypass on an off-loopback bind); set a non-empty api-key or remove it (#5636)")
		}
	}
	return nil
}

func compileConfigWithOpts(tree *ConfigTree, opts compileOpts) (*Config, error) {
	// #2008 H1: prune `inactive:`-marked subtrees BEFORE every other
	// pre-expansion gate, group expansion, and compilation. Doing it first
	// means the tunnel-id collision gate ignores inactive tunnel
	// definitions, an `inactive: apply-groups foo` suppresses the inherited
	// config, and inactive nodes inside a `groups {}` body are pruned —
	// none of the ~15 compiler files or validators ever observe an inactive
	// node. cloneForExpansion returns a fresh, freely-mutable pruned tree in a
	// single deep copy (no double-clone on the has-inactive path); the result
	// never aliases the caller's tree, so the caller retains groups/apply-groups
	// nodes for `show configuration` and ExpandGroups below mutates only our copy.
	tree = tree.cloneForExpansion()

	// #8662: normalize brace-elided ("compact") statements into their braced
	// shape BEFORE group expansion and every validator, so nothing downstream
	// has to know the two spellings exist. Applied at BOTH compile entry
	// points — this one and the node-aware sibling — because a normalization
	// present on only one of them would make a cluster peer compile the same
	// config differently from the node that authored it, which is the class of
	// asymmetry #8597 K51 was. Scoped to the security-relevant subset for now;
	// see compact_normalize_8662.go.
	if !opts.skipCompactNormalize {
		normalizeCompactStanzas(tree)
	}
	// #8752: fold a repeated named-instance statement into the first
	// occurrence, on the TOLERANT path only. The strict path keeps rejecting
	// (#3473) so the operator is still told to rename; the tolerant path cannot
	// reject — it exists to boot a config already on disk — and its only other
	// option is to split the statements into two policies, which is what it does
	// today and which loses the second statement's content. Runs at BOTH compile
	// entry points for the reason the comment above gives: a transform present on
	// only one makes a peer compile the same config differently from the node
	// that authored it.
	//
	// It also WARNS rather than merging silently. The #3473 gate's lenient arm
	// exists to tell the operator their on-disk config has a duplicate; merging
	// removes the duplicate and would therefore remove the diagnostic with it,
	// swallowing exactly the information the gate was added to surface.
	var dupMergeWarnings []string
	// Issue 9023: repeated named BLOCKS, merged on BOTH paths. Unlike the
	// policy fold below there is no duplicate-name gate here to preserve, so
	// tolerant-only scoping would leave the operator-typed case losing data.
	for _, what := range mergeDuplicateBlocks9023(tree) {
		dupMergeWarnings = append(dupMergeWarnings,
			"duplicate block `"+what+"` — the repeated statements were merged into the "+
				"first occurrence (#9023); previously the later block replaced the earlier "+
				"one and its configuration was discarded")
	}
	// #9571: the fold also reports every policy it merged into a PERMIT although
	// one of the statements said deny or reject. Those are poisoned right after
	// the compile below (markFoldWidenedPolicies9571), so the load is refused
	// rather than admitting traffic a statement denied.
	var foldWidened []foldWidenedPolicy9571
	if opts.lenientDuplicatePolicyNames {
		var merged []string
		merged, foldWidened = mergeDuplicateNamedInstances(tree)
		for _, what := range merged {
			// The wording deliberately carries "duplicate policy name" and
			// "#3473": that is the existing contract for this diagnostic, and
			// the #3473 cell matches on it. Merging must not silently retire a
			// warning by rephrasing it.
			dupMergeWarnings = append(dupMergeWarnings,
				"duplicate policy name in `"+what+"` — the repeated statements were merged "+
					"into the first occurrence on the tolerant path so the configuration "+
					"loads as authored; a strict commit rejects the duplicate instead "+
					"(#3473/#8752)")
		}
		for _, w := range foldWidened {
			dupMergeWarnings = append(dupMergeWarnings, foldWidenedWarning9571(w))
		}
	}

	// #1873 R-B: tunnel-endpoint id collision gate. Runs on the
	// PRE-expansion tree (ExpandGroups removes the groups stanza) so
	// the check covers the UNION of tunnel names across all groups —
	// both cluster nodes accept/reject identically. Strict paths
	// hard-reject; lenient paths warn (see tunnelid.go). Read-only, so it is
	// safe to run on the soon-to-be-expanded copy.
	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
		tree, opts.sanitizeFreeTextControlChars)
	if tunnelIDErr != nil {
		return nil, tunnelIDErr
	}

	// #3075: stable-zone-id collision gate. Like the tunnel gate above it runs
	// on the PRE-expansion tree and unions zone names across all groups (Views
	// 1/2/3, see zoneid.go) so both cluster nodes accept/reject identically.
	// Strict hard-rejects a colliding pair; lenient warns.
	zoneIDWarnings, zoneIDErr := validateZoneIDCollisionAST(
		tree, opts.lenientZoneIDCollision)
	if zoneIDErr != nil {
		return nil, zoneIDErr
	}

	// #3855: stable routing-instance table-id collision gate. Like the zone gate
	// above it runs on the PRE-expansion tree and unions the instance names each
	// compile path's own group expansion lands (#9657), so both cluster nodes
	// accept/reject identically. Strict
	// hard-rejects a colliding pair (two VRFs must never share a kernel table);
	// lenient warns and compileRoutingInstances quarantines the later instance.
	riTableIDWarnings, riTableIDErr := validateRoutingInstanceTableIDCollisionAST(
		tree, nil, opts.lenientRoutingInstanceTableIDCollision)
	if riTableIDErr != nil {
		return nil, riTableIDErr
	}
	// #9622: reserved routing-instance name gate — same three-view name union
	// as the table-id gate above. Strict only: the lenient paths skip it and
	// compileRoutingInstances quarantines the instance with one warning.
	if !opts.lenientReservedRoutingInstanceName {
		if err := validateReservedRoutingInstanceNamesAST(tree, nil); err != nil {
			return nil, err
		}
	}

	// #5180: duplicate hierarchical named-block gate. Runs PRE-expansion on the
	// top-level stanzas (never a group body — apply-groups deep-merges rather
	// than duplicating) so an authored `groups`/`interfaces`/`screen ids-option`
	// block written twice is rejected (strict) instead of silently reduced to
	// last-writer-wins; lenient warns and keeps the historical result. It also
	// rejects a quoted-empty group/interface/screen-ids-option name (#6455). A
	// duplicate authored entirely inside an applied group body is deferred (#6455
	// Finding 1) — see dup_names_6455.go.
	dupBlockWarnings, dupBlockErr := validateDuplicateNamedBlockAST(
		tree, opts.lenientDuplicateNamedBlock)
	if dupBlockErr != nil {
		return nil, dupBlockErr
	}

	// #5649 (C181-M18): duplicate NAT rule-name gate — see
	// validateDuplicateNATRuleNamesAST. Pre-expansion, top-level `security`
	// stanzas only, beside the #5180 gate. Two same-named rules in one NAT
	// rule-set BOTH survive as first-match entries sharing one config identity
	// (the rule name; counter-less for NPTv6 static); strict rejects,
	// lenient warns. Also rejects a quoted-empty rule name (#6455).
	dupNATRuleWarnings, dupNATRuleErr := validateDuplicateNATRuleNamesAST(
		tree, opts.lenientDuplicateNATRuleName)
	if dupNATRuleErr != nil {
		return nil, dupNATRuleErr
	}

	// #6454 (C181-M18 sibling): duplicate NAT rule-SET-name gate — see
	// validateDuplicateNATRuleSetNamesAST. The rule-SET axis one level above the
	// #5649 rule-name gate: two same-named rule-sets within one nat type
	// (source/destination/static/nat64) BOTH survive as separate first-match
	// tables sharing one name, and the CLI named-rule-set show lookup returns on
	// the first match, so the operator cannot disambiguate the two (not a
	// per-rule counter merge — NATCounterKey includes the rule name). Pre-
	// expansion, top-level `security` stanzas only, keyed by (natType, rule-set)
	// so a same-named rule-set across DIFFERENT nat types stays legitimate; strict
	// rejects, lenient warns. Also rejects a quoted-empty rule-set name (#6455).
	dupNATRuleSetWarnings, dupNATRuleSetErr := validateDuplicateNATRuleSetNamesAST(
		tree, opts.lenientDuplicateNATRuleSetName)
	if dupNATRuleSetErr != nil {
		return nil, dupNATRuleSetErr
	}

	// #6455 Finding 1: the POST-expansion half of the duplicate-name gate
	// family. The three gates above scan only top-level stanzas, so a duplicate
	// authored ENTIRELY inside an applied group body — appended wholesale by
	// apply-groups, never coalesced — reaches the compiled config with both
	// instances alive while the byte-identical inline duplicate is rejected.
	// This re-runs the SAME three scanners on a group-EXPANDED clone, once per
	// cluster node (node0 AND node1) like the #5878/#5879/#6178 union gates, so
	// the fragment-coalescing false-reject that killed a per-group-body scan
	// cannot occur (the fragments are one node by then) and a peer-only `groups
	// node1` duplicate is caught. Findings the pre-expansion gates already
	// warned about are dropped so an inline duplicate reports once. See
	// dup_names_expanded_6455.go.
	dupExpandedWarnings, dupExpandedErr := validateDuplicateNamesExpandedAST(
		tree, opts.lenientDuplicateNamesExpanded,
		concatWarnings(dupBlockWarnings, dupNATRuleWarnings, dupNATRuleSetWarnings))
	if dupExpandedErr != nil {
		return nil, dupExpandedErr
	}

	// #5878: numeric interface-unit alias gate (#5631) as a BOTH-NODE-effective
	// union. Runs PRE-expansion, beside the tunnel/zone/table-id gates, so a
	// peer-only `groups node1`/`${node}` alias that collides only in the
	// STANDBY node's effective view is rejected at commit even on a generic
	// (non-node) compile — the union is a pure function of the candidate and
	// verdict-identical across both nodes. Strict rejects; lenient warns
	// (#1960). See validateInterfaceUnitAliasCollisionsAST.
	unitAliasWarnings, unitAliasErr := validateInterfaceUnitAliasCollisionsAST(
		tree, opts.lenientInterfaceUnitAliasCollisions)
	if unitAliasErr != nil {
		return nil, unitAliasErr
	}

	// #5879: canonical per-physical-interface QinQ / stacked-VLAN honesty
	// gate — see compiler_interfaces_qinq.go. Runs PRE-expansion beside the
	// tunnel/zone/table-id/unit-alias union gates: it expands the candidate
	// once per cluster node itself (node0 AND node1) so the accept/reject
	// verdict is identical on both nodes and a peer-only-group or
	// `vlan-tags`-spelled inner tag is caught. Strict hard-rejects an
	// unsupported inner tag; lenient warns (#1960).
	qinqWarnings, qinqErr := validateQinQVLANStackAST(tree, opts.lenientQinQVLANStack)
	if qinqErr != nil {
		return nil, qinqErr
	}

	// #6178: input-vlan-map / output-vlan-map (per-unit VLAN rewrite) honesty
	// gate — see compiler_interfaces_vlanmap.go. Runs PRE-expansion beside
	// the QinQ gate, expanding the candidate once per cluster node (node0 AND
	// node1) so a peer-only-group vlan-map is caught and the verdict is
	// HA-symmetric. Strict hard-rejects an unsupported push/pop/swap; lenient
	// warns (#1960).
	vlanMapWarnings, vlanMapErr := validateVLANMapAST(tree, opts.lenientVLANMap)
	if vlanMapErr != nil {
		return nil, vlanMapErr
	}

	// #6662 / #6701 (#6706 review blocker): the `system login` packed-body and
	// built-in-class-shadow gates, as BOTH-NODE-effective unions. Pre-expansion
	// for the same reason as the #5878/#5879/#6178 gates above — a `groups
	// node1` login body that only the PEER's `${node}` expansion selects is
	// stripped before an expanded-view gate could see it, commits green on the
	// origin, and reaches the standby through the tolerant sync path where it
	// only warns. See compiler_system_login_gates.go.
	loginPackedWarnings, loginPackedErr := validateLoginPackedStatementsAST(
		tree, opts.lenientLoginPackedStatements)
	if loginPackedErr != nil {
		return nil, loginPackedErr
	}
	loginShadowWarnings, loginShadowErr := validateLoginClassShadowsBuiltinAST(
		tree, opts.lenientLoginClassShadowsBuiltin)
	if loginShadowErr != nil {
		return nil, loginShadowErr
	}

	usedNodeFallback := false

	// Expand groups before compilation — resolve all apply-groups references.
	if err := tree.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := tree.ExpandGroupsWithVars(vars); err2 != nil {
				return nil, fmt.Errorf("apply-groups: %w", err2)
			}
			usedNodeFallback = true
		} else {
			return nil, fmt.Errorf("apply-groups: %w", err)
		}
	}

	cfg, err := compileExpanded(tree, opts)
	if err != nil {
		return nil, err
	}
	if usedNodeFallback {
		cfg.Warnings = append(cfg.Warnings, `apply-groups "${node}" resolved using default node0 context during generic compile`)
	}
	// #9571: poison what the fold widened. After the compile, because the flag
	// lives on the compiled policy; before return, because the snapshot builder
	// and the #6707 rollback preflight both read it from the returned cfg.
	markFoldWidenedPolicies9571(cfg, foldWidened)
	cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupMergeWarnings...)
	cfg.Warnings = append(cfg.Warnings, zoneIDWarnings...)
	cfg.Warnings = append(cfg.Warnings, riTableIDWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupBlockWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupNATRuleWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupNATRuleSetWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupExpandedWarnings...)
	cfg.Warnings = append(cfg.Warnings, unitAliasWarnings...)
	cfg.Warnings = append(cfg.Warnings, qinqWarnings...)
	cfg.Warnings = append(cfg.Warnings, vlanMapWarnings...)
	cfg.Warnings = append(cfg.Warnings, loginPackedWarnings...)
	appendClusterNTPAdvisoryLocked(cfg, opts)
	appendContestedTrunkZoneAdvisoryLocked(cfg, opts)
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, opts)
	appendUserspaceRxMTUAdvisoryLocked(cfg, opts)
	cfg.Warnings = append(cfg.Warnings, loginShadowWarnings...)
	// #6706: record that a `system login` path was authored packed, so the
	// daemon can tell "RBAC never configured" from "RBAC configured and dropped"
	// — both of which arrive here as System.Login == nil. Set from the BROADER
	// detector, not from len(loginPackedWarnings): the reporting gate is silent
	// for the short prefixes, and those are precisely the ones whose packed and
	// nested spellings disagree about whether the CLI denies or permits.
	cfg.System.LoginDroppedByPacking = loginPathPackedAnywhere(tree)
	return cfg, nil
}

// CompileConfigForNode is like CompileConfig but resolves ${node} variables
// in apply-groups names before lookup. nodeID selects which per-node group
// to apply (e.g. nodeID=0 maps "node" -> "node0", so apply-groups "${node}"
// resolves to group "node0"). This supports a single shared config for both
// nodes in a chassis cluster.
func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{})
}

// CompileConfigForNodeLenient is CompileConfigForNode with the
// tolerant-path downgrades enabled (see CompileConfigLenient). Use on
// node-aware TOLERANT paths that compile an already-active / peer-synced
// config the local operator did not just author: Store.SyncApply (HA
// peer-sync ingress) and the read-only peer-interface display re-compiles
// (cli_show_interfaces.go, server_show_interfaces.go). MUST NOT be used to
// decide whether a CANDIDATE commit is accepted — see CompileConfigLenient.
//
// ONE deliberate exception, and it does not weaken that rule (#6861 F3):
// ValidatePeerEffectiveStrict (compiler_peer_effective.go) calls this from a
// strict commit helper. It is not using the lenient compile as the acceptance
// decision — it is using it to MODEL what the standby's tolerant SyncApply will
// instantiate, and then re-imposes strictness by running
// peerEffectiveStrictSubjects over the result. The candidate's own acceptance
// still comes from the strict CompileConfig on the local view. Reading that
// call as a violation and "fixing" it to the strict compiler would break the
// peer gate: a peer view that will not strict-compile is exactly the case it
// must inspect, and a compile error there is swallowed by its
// `err != nil -> return nil` arm.
func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
	return compileConfigForNodeWithOpts(tree, nodeID, lenientCompileOpts())
}

func compileConfigForNodeWithOpts(tree *ConfigTree, nodeID int, opts compileOpts) (*Config, error) {
	// #2008 H1: prune `inactive:` subtrees first — see compileConfigWithOpts.
	// Centralizing the strip in this shared node-aware entry guarantees BOTH
	// cluster nodes compile the identical active set from the same persisted
	// (Inactive-flag-carrying, JSON-synced) tree, so a deactivated stanza is
	// dead on both nodes — no split-brain firewall posture. cloneForExpansion
	// returns a fresh, freely-mutable pruned tree in a single deep copy (never
	// aliases the caller's tree) so ExpandGroupsWithVars below mutates only our copy.
	tree = tree.cloneForExpansion()

	// #8662: normalize brace-elided ("compact") statements into their braced
	// shape BEFORE group expansion and every validator, so nothing downstream
	// has to know the two spellings exist. Applied at BOTH compile entry
	// points — this one and the node-aware sibling — because a normalization
	// present on only one of them would make a cluster peer compile the same
	// config differently from the node that authored it, which is the class of
	// asymmetry #8597 K51 was. Scoped to the security-relevant subset for now;
	// see compact_normalize_8662.go.
	if !opts.skipCompactNormalize {
		normalizeCompactStanzas(tree)
	}
	// #8752: fold a repeated named-instance statement into the first
	// occurrence, on the TOLERANT path only. The strict path keeps rejecting
	// (#3473) so the operator is still told to rename; the tolerant path cannot
	// reject — it exists to boot a config already on disk — and its only other
	// option is to split the statements into two policies, which is what it does
	// today and which loses the second statement's content. Runs at BOTH compile
	// entry points for the reason the comment above gives: a transform present on
	// only one makes a peer compile the same config differently from the node
	// that authored it.
	//
	// It also WARNS rather than merging silently. The #3473 gate's lenient arm
	// exists to tell the operator their on-disk config has a duplicate; merging
	// removes the duplicate and would therefore remove the diagnostic with it,
	// swallowing exactly the information the gate was added to surface.
	var dupMergeWarnings []string
	// Issue 9023: repeated named BLOCKS, merged on BOTH paths. Unlike the
	// policy fold below there is no duplicate-name gate here to preserve, so
	// tolerant-only scoping would leave the operator-typed case losing data.
	for _, what := range mergeDuplicateBlocks9023(tree) {
		dupMergeWarnings = append(dupMergeWarnings,
			"duplicate block `"+what+"` — the repeated statements were merged into the "+
				"first occurrence (#9023); previously the later block replaced the earlier "+
				"one and its configuration was discarded")
	}
	// #9571: the fold also reports every policy it merged into a PERMIT although
	// one of the statements said deny or reject. Those are poisoned right after
	// the compile below (markFoldWidenedPolicies9571), so the load is refused
	// rather than admitting traffic a statement denied.
	var foldWidened []foldWidenedPolicy9571
	if opts.lenientDuplicatePolicyNames {
		var merged []string
		merged, foldWidened = mergeDuplicateNamedInstances(tree)
		for _, what := range merged {
			// The wording deliberately carries "duplicate policy name" and
			// "#3473": that is the existing contract for this diagnostic, and
			// the #3473 cell matches on it. Merging must not silently retire a
			// warning by rephrasing it.
			dupMergeWarnings = append(dupMergeWarnings,
				"duplicate policy name in `"+what+"` — the repeated statements were merged "+
					"into the first occurrence on the tolerant path so the configuration "+
					"loads as authored; a strict commit rejects the duplicate instead "+
					"(#3473/#8752)")
		}
		for _, w := range foldWidened {
			dupMergeWarnings = append(dupMergeWarnings, foldWidenedWarning9571(w))
		}
	}

	// #1873 R-B: union-of-groups tunnel id collision gate — see
	// compileConfigWithOpts. Pre-expansion on purpose; read-only, safe on the copy.
	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
		tree, opts.sanitizeFreeTextControlChars)
	if tunnelIDErr != nil {
		return nil, tunnelIDErr
	}

	// #3075: stable-zone-id collision gate — see compileConfigWithOpts.
	// Pre-expansion union across all groups so the verdict is identical on both
	// cluster nodes; read-only, safe on the soon-to-be-expanded copy.
	zoneIDWarnings, zoneIDErr := validateZoneIDCollisionAST(
		tree, opts.lenientZoneIDCollision)
	if zoneIDErr != nil {
		return nil, zoneIDErr
	}

	// #3855: stable routing-instance table-id collision gate — see
	// compileConfigWithOpts. Union of the names each compile path's group
	// expansion lands (#9657), so the verdict is identical on both cluster nodes;
	// read-only, safe on the copy.
	riTableIDWarnings, riTableIDErr := validateRoutingInstanceTableIDCollisionAST(
		tree, &nodeID, opts.lenientRoutingInstanceTableIDCollision)
	if riTableIDErr != nil {
		return nil, riTableIDErr
	}
	// #9622: reserved routing-instance name gate — same three-view name union
	// as the table-id gate above. Strict only: the lenient paths skip it and
	// compileRoutingInstances quarantines the instance with one warning.
	if !opts.lenientReservedRoutingInstanceName {
		if err := validateReservedRoutingInstanceNamesAST(tree, &nodeID); err != nil {
			return nil, err
		}
	}

	// #5180: duplicate hierarchical named-block gate — see compileConfigWithOpts.
	// Pre-expansion, top-level stanzas only; strict rejects, lenient warns. Also
	// rejects a quoted-empty group/interface/screen-ids-option name (#6455).
	dupBlockWarnings, dupBlockErr := validateDuplicateNamedBlockAST(
		tree, opts.lenientDuplicateNamedBlock)
	if dupBlockErr != nil {
		return nil, dupBlockErr
	}

	// #5649 (C181-M18): duplicate NAT rule-name gate — see compileConfigWithOpts
	// / validateDuplicateNATRuleNamesAST. Pre-expansion, top-level `security`
	// stanzas only; strict rejects, lenient warns. Also rejects a quoted-empty
	// rule name (#6455).
	dupNATRuleWarnings, dupNATRuleErr := validateDuplicateNATRuleNamesAST(
		tree, opts.lenientDuplicateNATRuleName)
	if dupNATRuleErr != nil {
		return nil, dupNATRuleErr
	}

	// #6454 (C181-M18 sibling): duplicate NAT rule-SET-name gate — see
	// compileConfigWithOpts / validateDuplicateNATRuleSetNamesAST. Pre-expansion,
	// top-level `security` stanzas only, keyed by (natType, rule-set); strict
	// rejects, lenient warns. Also rejects a quoted-empty rule-set name (#6455).
	dupNATRuleSetWarnings, dupNATRuleSetErr := validateDuplicateNATRuleSetNamesAST(
		tree, opts.lenientDuplicateNATRuleSetName)
	if dupNATRuleSetErr != nil {
		return nil, dupNATRuleSetErr
	}

	// #6455 Finding 1: the POST-expansion half of the duplicate-name gate
	// family. The three gates above scan only top-level stanzas, so a duplicate
	// authored ENTIRELY inside an applied group body — appended wholesale by
	// apply-groups, never coalesced — reaches the compiled config with both
	// instances alive while the byte-identical inline duplicate is rejected.
	// This re-runs the SAME three scanners on a group-EXPANDED clone, once per
	// cluster node (node0 AND node1) like the #5878/#5879/#6178 union gates, so
	// the fragment-coalescing false-reject that killed a per-group-body scan
	// cannot occur (the fragments are one node by then) and a peer-only `groups
	// node1` duplicate is caught. Findings the pre-expansion gates already
	// warned about are dropped so an inline duplicate reports once. See
	// dup_names_expanded_6455.go.
	dupExpandedWarnings, dupExpandedErr := validateDuplicateNamesExpandedAST(
		tree, opts.lenientDuplicateNamesExpanded,
		concatWarnings(dupBlockWarnings, dupNATRuleWarnings, dupNATRuleSetWarnings))
	if dupExpandedErr != nil {
		return nil, dupExpandedErr
	}

	// #5878: numeric interface-unit alias gate (#5631) as a BOTH-NODE-effective
	// union — see compileConfigWithOpts. Pre-expansion on purpose: the union
	// across View 1 (groups) + Views 2/3 (node0/node1 expansions) is identical
	// on both nodes, so a `groups node1`/`${node}` alias that collides only in
	// the peer's effective view is rejected here even when THIS commit compiles
	// s.nodeID alone (the #5878 divergent-commit defect). Strict rejects on the
	// operator commit / commit-check path; lenient warns on load / peer-sync.
	unitAliasWarnings, unitAliasErr := validateInterfaceUnitAliasCollisionsAST(
		tree, opts.lenientInterfaceUnitAliasCollisions)
	if unitAliasErr != nil {
		return nil, unitAliasErr
	}

	// #5879: canonical per-physical-interface QinQ / stacked-VLAN honesty
	// gate — see compileConfigWithOpts / compiler_interfaces_qinq.go. Runs
	// PRE-expansion: it expands the candidate once per cluster node itself
	// (node0 AND node1) so a peer-only-group or `vlan-tags`-spelled inner tag
	// is rejected here even when THIS commit compiles nodeID alone. Strict
	// rejects; lenient warns (#1960).
	qinqWarnings, qinqErr := validateQinQVLANStackAST(tree, opts.lenientQinQVLANStack)
	if qinqErr != nil {
		return nil, qinqErr
	}

	// #6178: input-vlan-map / output-vlan-map (per-unit VLAN rewrite) honesty
	// gate — see compileConfigWithOpts / compiler_interfaces_vlanmap.go. Runs
	// PRE-expansion per cluster node (node0 AND node1) so a peer-only-group
	// vlan-map is rejected here even when THIS commit compiles nodeID alone.
	// Strict rejects; lenient warns (#1960).
	vlanMapWarnings, vlanMapErr := validateVLANMapAST(tree, opts.lenientVLANMap)
	if vlanMapErr != nil {
		return nil, vlanMapErr
	}

	// #6662 / #6701 (#6706 review blocker): the `system login` packed-body and
	// built-in-class-shadow gates, as BOTH-NODE-effective unions. This is the
	// site the blocker turned on: with the gates running post-expansion on the
	// single local view, `groups node1 { system login ... }` + `apply-groups
	// "${node}"` committed green on node 0 (the body was already stripped) and
	// arrived at node 1 through Store.SyncApply, which is lenient and only
	// warns — so the shadowing/packed body was live on the peer with no strict
	// check anywhere. Evaluating BOTH node views here makes the verdict
	// HA-symmetric: whichever node commits rejects it. Same doctrine as
	// #5878/#5879/#6178 above, and the same argument
	// compiler_peer_effective_snat.go (#5876) makes for source NAT.
	loginPackedWarnings, loginPackedErr := validateLoginPackedStatementsAST(
		tree, opts.lenientLoginPackedStatements)
	if loginPackedErr != nil {
		return nil, loginPackedErr
	}
	loginShadowWarnings, loginShadowErr := validateLoginClassShadowsBuiltinAST(
		tree, opts.lenientLoginClassShadowsBuiltin)
	if loginShadowErr != nil {
		return nil, loginShadowErr
	}

	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := tree.ExpandGroupsWithVars(vars); err != nil {
		return nil, fmt.Errorf("apply-groups: %w", err)
	}

	// #4329: thread the runtime cluster node identity into compileExpanded so
	// it can stamp ClusterConfig.NodeID for a leaf-less flat vSRX config
	// BEFORE any NodeID-dependent derivation runs (reth member resolution AND
	// the compile-time fabric-member / FabricInterface auto-detect). See the
	// stamp block in compileExpanded for the full rationale and guards.
	opts.nodeAware = true
	opts.stampNodeID = nodeID

	cfg, err := compileExpanded(tree, opts)
	if err != nil {
		return nil, err
	}

	// #9571: poison what the fold widened. After the compile, because the flag
	// lives on the compiled policy; before return, because the snapshot builder
	// and the #6707 rollback preflight both read it from the returned cfg.
	markFoldWidenedPolicies9571(cfg, foldWidened)
	cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupMergeWarnings...)
	cfg.Warnings = append(cfg.Warnings, zoneIDWarnings...)
	cfg.Warnings = append(cfg.Warnings, riTableIDWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupBlockWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupNATRuleWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupNATRuleSetWarnings...)
	cfg.Warnings = append(cfg.Warnings, dupExpandedWarnings...)
	cfg.Warnings = append(cfg.Warnings, unitAliasWarnings...)
	cfg.Warnings = append(cfg.Warnings, qinqWarnings...)
	cfg.Warnings = append(cfg.Warnings, vlanMapWarnings...)
	cfg.Warnings = append(cfg.Warnings, loginPackedWarnings...)
	appendClusterNTPAdvisoryLocked(cfg, opts)
	appendContestedTrunkZoneAdvisoryLocked(cfg, opts)
	appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg, opts)
	appendUserspaceRxMTUAdvisoryLocked(cfg, opts)
	cfg.Warnings = append(cfg.Warnings, loginShadowWarnings...)
	// #6706: record that a `system login` path was authored packed, so the
	// daemon can tell "RBAC never configured" from "RBAC configured and dropped"
	// — both of which arrive here as System.Login == nil. Set from the BROADER
	// detector, not from len(loginPackedWarnings): the reporting gate is silent
	// for the short prefixes, and those are precisely the ones whose packed and
	// nested spellings disagree about whether the CLI denies or permits.
	cfg.System.LoginDroppedByPacking = loginPathPackedAnywhere(tree)
	return cfg, nil
}

// compileExpanded compiles an already-expanded (groups resolved) ConfigTree
// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
	// P1 (#4406 step 1): AST pre-walk gates. Extracted into runPreWalkGates
	// (compiler_prewalk.go) — the contiguous SAFE phase that MUTATES `tree`
	// via expandInterfaceRanges (#4027) BEFORE the base skeleton (P2) and the
	// section dispatch (P4), returning its warnings in source order for the P3
	// append below and the FIRST gate error. Behavior-preserving lift; do NOT
	// reorder P1 relative to P2+.
	preWalkWarnings, err := runPreWalkGates(tree, opts)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Security: SecurityConfig{
			Zones:  make(map[string]*ZoneConfig),
			Screen: make(map[string]*ScreenProfile),
			// #3065: fail-CLOSED no-match default. The PolicyAction zero
			// value is PolicyPermit (iota==0), so an unset default-policy
			// would otherwise ship as permit-all — the opposite of the
			// Junos SRX default-security-policy (deny-all). Initialize the
			// fallback to PolicyDeny here so an absent
			// `security policies default-policy` stanza denies unmatched
			// zone-pair traffic. An operator opts back into permit-all
			// explicitly via `set security policies default-policy
			// permit-all` (handled in compilePolicies).
			DefaultPolicy: PolicyDeny,
		},
		Interfaces: InterfacesConfig{
			Interfaces: make(map[string]*InterfaceConfig),
		},
		Applications: ApplicationsConfig{
			Applications:    make(map[string]*Application),
			ApplicationSets: make(map[string]*ApplicationSet),
		},
		ClassOfService: &ClassOfServiceConfig{
			ForwardingClasses: make(map[string]*CoSForwardingClass),
			DSCPClassifiers:   make(map[string]*CoSDSCPClassifier),
			DSCPRewriteRules:  make(map[string]*CoSDSCPRewriteRule),
			Schedulers:        make(map[string]*CoSScheduler),
			SchedulerMaps:     make(map[string]*CoSSchedulerMap),
			Interfaces:        make(map[string]*CoSInterface),
		},
	}
	cfg.Warnings = append(cfg.Warnings, preWalkWarnings...)

	// P4 (#4406 step 2): section-compile dispatch. Extracted into
	// compileSections (compiler_dispatch.go) — the ordered per-section
	// dispatch that routes each root child (in author order) to its
	// already-extracted section compiler and returns the FIRST section error.
	// Behavior-preserving lift; do NOT reorder P4 relative to P3 above or the
	// P5 cross-section derivations below.
	if err := compileSections(tree, cfg, opts); err != nil {
		return nil, err
	}

	// P5 (#4406 step 5): cross-section derivations. Extracted into
	// resolveDerivedConfig (compiler_derivations.go) — the contiguous,
	// NON-reorderable block of post-dispatch mutations that fold cross-section
	// state into the compiled *Config now that every section compiler (P4) has
	// populated its own sub-struct. In internal order: the #4329 NodeID stamp
	// (MUST precede the fabric fixup AND validateDeviceMapStrict, which both
	// read cc.NodeID) → resolveBGPAutonomousSystem → lo0-filter extract →
	// applyCoSInterfaceLevelBindings → resolveCoSTrafficControlProfiles (MUST
	// follow the interface-level fold) → fabric member/interface fixup. It runs
	// NO validation and returns NO error — a pure mutation phase. Behavior-
	// preserving lift; runs AFTER the P4 section dispatch above and BEFORE the
	// P6a early-strict folds below, so every derived field the later validators
	// read is populated in the same order. Do NOT reorder or split the
	// sub-steps.
	resolveDerivedConfig(cfg, opts)

	// P6a (#4406 step 6, FINAL): early-strict validation + the two folds.
	// Extracted into runEarlyStrictAndFolds (compiler_earlystrict.go) — the
	// RISKY entangled phase that interleaves validation with two cfg-mutations
	// whose output is consumed non-locally in P6b: the fail-fast
	// validateDataplaneTypeStrict (#1526, wins the first-error slot), the
	// pristine-book address-book/zone name gate (#3061/#4340, before the fold
	// injects `/`-bearing synthetic names), the resolveZoneLocalAddressBooks and
	// resolveStaticNATThenPrefixNames folds (MUT cfg.Security, read by the P6b
	// policy match-address + validateStaticNATThenTargetStrict gates — invariant
	// #5), and the #1538 errors.Join independent-strict-family accumulator (fully
	// CONTAINED here — NOT threaded into P6b). Behavior-preserving lift; runs
	// AFTER the P5 derivations above and BEFORE the P6b uniform gates below, so
	// the strict first-error slot (invariant #6) and the tolerant-path warning
	// order (invariant #7) are unchanged. Do NOT reorder the interleave.
	if err := runEarlyStrictAndFolds(cfg, opts); err != nil {
		return nil, err
	}

	// P6b (#4406 step 4): uniform fail-open validation gates. Extracted into
	// runUniformGates (compiler_uniformgates.go) — the long contiguous run of
	// ~75 independent validators, each of which returns the FIRST strict error
	// or downgrades to a warning on its tolerant flag. Reads the compiled
	// *Config, the group-expanded *ConfigTree (validateEventOptionsWithinAST is
	// an AST pre-walk), and opts; performs NO cfg mutation. Behavior-preserving
	// lift; runs AFTER the P6a early-strict + folds accumulator above and BEFORE
	// the P7 tail gates below, so the strict first-error slot (invariant #6) and
	// the tolerant-path warning order (invariant #7) are unchanged. Do NOT
	// reorder any gate.
	if err := runUniformGates(tree, cfg, opts); err != nil {
		return nil, err
	}

	// P7 (#4406 step 3): tail validation / finalization gates. Extracted into
	// runTailGates (compiler_tailgates.go) — the contiguous trailing gate
	// sequence (ValidateConfig structural warnings through the SSH-hardening
	// advisory) that threads warnings and dispatches the FIRST strict error.
	// Behavior-preserving lift; runs LAST, AFTER the P6b uniform gates and
	// BEFORE the final return, so the strict first-error slot and the
	// tolerant-path warning order are unchanged.
	if err := runTailGates(cfg, opts); err != nil {
		return nil, err
	}

	// #1539: the structural invariant `cfg.System.DPDKDataplane = nil`
	// was added on master (PR #1553) as a runtime safeguard against
	// AST leakage of retired DPDK sub-tree fields. After this PR
	// deletes the DPDKDataplane field entirely (per #1539 author's
	// explicit note: "This is dead code after #1528 (Phase 3) deletes
	// the field entirely; remove this line in #1528"), the field no
	// longer exists, so the Go compiler enforces the invariant at
	// compile time — there is no value to nil out.

	return cfg, nil
}
