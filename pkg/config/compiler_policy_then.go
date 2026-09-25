package config

import "fmt"

// compiler_policy_then.go carries the #3114 reject-at-commit gate for a
// security-policy `then permit` action arm that carries an UNSUPPORTED
// child (e.g. `application-services`, firewall-authentication, tunnel
// ipsec-vpn).
//
// The defect: Junos SRX `then permit` accepts a rich set of action
// modifiers that turn a bare permit into a permit-with-inspection or a
// permit-into-tunnel — `application-services { utm-policy X; idp; }`,
// `firewall-authentication`, `tunnel ipsec-vpn`, `destination-address`,
// SSL-proxy / AppFW / SecIntel attachments, etc. xpf's policy compiler
// (compilePolicy in compiler_security.go) handles the `then` arm by
// switching only on the terminal/modifier tokens it implements —
// `permit`, `deny`, `reject`, `log`, `count`. The `permit` arm sets
// `pol.Action = PolicyPermit` and NEVER inspects `t.Children`. Any child
// under `then permit` falls out with NO error and is SILENTLY DROPPED. The
// set-schema (schema_security.go) does not list those children and
// schema_walk.go returns nil for unknown keywords by design, so nothing
// rejects them either.
//
// Why that is dangerous: dropping a `then permit application-services`
// (or any inspection/authentication modifier) turns a permit-only-with-
// inspection rule into an UNCONDITIONAL permit. An operator who writes
// `then permit application-services utm-policy strict-web` believes the
// traffic is UTM/IDP/SSL-proxy inspected; xpf forwards it without the
// service chain. Enforcement is weaker than the committed config — a
// direct security fail-OPEN. Surfacing it (reject at commit) is the safe
// choice.
//
// Full support for the `then permit` service chain (typed service-chain
// model + userspace capability gate + Rust enforcement) is a substantial,
// separate feature. Until it lands the SAFE behaviour is to REJECT an
// unsupported `then permit` child at commit rather than silently strip it
// — mirroring the campaign's reject-at-commit pattern for unsupported-but-
// parsed stanzas (#3113 unsupported policy `match` leaf, #3079 NAT
// rule-set scope, #3055 reserved zone names, #3060 bare `then log`). Same
// #1960 strict-with-lenient doctrine.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf, and not a
// typed-Config validator) for the same two reasons validatePolicyMatch-
// LeavesStrict (#3113) is — the dropped child is gone from the typed
// *Config by compile time (only the raw AST still carries it), and
// SchemaValidate returns nil for unknown keywords so it cannot REJECT.
// The walk runs on the group-expanded, inactive-pruned tree, so an
// apply-groups-inherited `then permit` child is caught and an `inactive:`
// policy is ignored for free.
//
// Both zone-pair (`from-zone`/`to-zone`) and `global` policies are
// covered.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// child is a hard compile error naming the policy scope, the policy, and
// the unsupported child, and directing the operator to remove it.
//
// Lenient path (load / peer-sync, lenient=true): every offending child is
// returned as a warning and compilation continues — an already-persisted
// or peer-synced config that an older binary silently accepted still
// BOOTS (#1960 fail-closed-on-load class). The child is NOT removed from
// the tree; it stays dropped by the compiler exactly as before this gate.

// supportedPolicyThenPermitChildren is the EXACT set of `then permit`
// children the policy compiler (compilePolicy in compiler_security.go)
// enforces. The `permit` arm sets pol.Action = PolicyPermit and reads NO
// children, so today the supported set is EMPTY — any child under
// `then permit` is silently dropped and is rejected by
// validatePolicyThenPermitStrict. Keep this in lockstep with compilePolicy's
// `then` switch: if the compiler ever learns to enforce a `then permit`
// modifier (e.g. a typed service chain), add it here so it is no longer
// rejected.
var supportedPolicyThenPermitChildren = map[string]bool{}

// policyUnsupportedThenPermitModifiers returns the unsupported `then permit`
// modifier tokens a policy carries — at most one per `then permit` action node
// (matching the strict gate's report-first-per-node behavior). It is the single
// source of truth shared by the #3114 strict gate (validatePolicyThenPermitStrict)
// and compilePolicy's #5575 fail-closed LenientContentDropped flag, so the
// reject gate and the runtime poison decision never diverge on which permits
// carry a silently-dropped inspection/service-chain modifier.
//
// A bare `then permit` (a `permit` node with no modifier tokens) is fully
// supported and contributes nothing. ALL `then permit` nodes across ALL
// `then {}` blocks are inspected (policyThenActionNodes): a flat-set
// `set ... then permit` followed by `set ... then permit application-services X`
// produces TWO separate `permit` nodes (the #3377 two-node split), and #3842
// adds the DUPLICATE inner `then {}` block case. collapsedThenActionTokens
// flattens each node's modifier tokens across all three parser groupings
// (flat-onto-permit, collapsed-child, nested). The supported permit-modifier set
// is empty (supportedPolicyThenPermitChildren), so any token is unsupported.
func policyUnsupportedThenPermitModifiers(polNode *Node) []string {
	var out []string
	for _, permitNode := range policyThenActionNodes(polNode, "permit") {
		for _, tok := range collapsedThenActionTokens(permitNode) {
			if supportedPolicyThenPermitChildren[tok] {
				continue
			}
			out = append(out, tok)
			break
		}
	}
	return out
}

// validatePolicyThenPermitStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `then permit` action
// arm carries a child the compiler does not enforce (see file header).
// Covers both zone-pair and global policies.
func validatePolicyThenPermitStrict(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(scope, policyName, child string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then permit %q is not supported "+
				"(xpf permits or denies on L3/L4 only; it does not implement "+
				"the permit service chain — application-services (UTM/IDP/"+
				"AppFW/SSL-proxy), firewall-authentication, or tunnel — and an "+
				"unsupported then-permit child is silently dropped, turning a "+
				"permit-with-inspection rule into an UNCONDITIONAL permit the "+
				"operator did not intend — a fail-open) — remove the %q "+
				"modifier under then permit (#3114)",
			scope, policyName, child, child,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		for _, tok := range policyUnsupportedThenPermitModifiers(polNode) {
			if err := emit(scope, policyName, tok); err != nil {
				return err
			}
		}
		return nil
	}

	// #3562: iterate EVERY top-level `security` node and EVERY `policies`
	// sibling, not the first match at any level. parseStatements APPENDS a
	// repeated top-level block instead of merging it (parser.go) and
	// compileExpanded compiles every `security` root, so a `then permit`
	// modifier in a SECOND duplicate `security {}` (or duplicate `policies {}`)
	// block would bypass a first-`security`/first-`policies` walk while the
	// compiler still compiled the policy and silently dropped the modifier
	// (turning a permit-with-inspection into an unconditional permit — a
	// fail-open). Descending with forEachChild at security/policies closes that
	// multi-level duplicate-block bypass. The inner per-policy then-permit check
	// (checkPolicy) is unchanged.
	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
							return err
						}
					}
				case "from-zone":
					// Mirror compilePolicies' two AST shapes.
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						// Hierarchical: Keys=["from-zone","trust","to-zone","untrust"]
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						// Flat set: from-zone → <name> → to-zone → <name> → policy ...
						for _, fzSub := range child.Children {
							tzNode := fzSub.FindChild("to-zone")
							if tzNode == nil {
								continue
							}
							for _, tzSub := range tzNode.Children {
								pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// supportedPolicyThenRejectChildren is the EXACT set of `then reject`
// children the policy compiler (compilePolicy in compiler_security.go)
// enforces. The `reject` arm sets pol.Action = PolicyReject and reads NO
// children, so today the supported set is EMPTY — any child under
// `then reject` (a Junos reject-profile `profile <name>`, a packet-type
// reject like `tcp-reset`, or any other modifier) is silently dropped and
// is rejected by validatePolicyThenRejectStrict. Keep this in lockstep
// with compilePolicy's `then` switch `reject` arm: if the compiler ever
// learns to enforce a `then reject` modifier (a synthesized reject
// response or a per-packet-type reset), add it here so it is no longer
// rejected.
var supportedPolicyThenRejectChildren = map[string]bool{}

// validatePolicyThenRejectStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `then reject` action
// arm carries a child the compiler does not enforce — the #3115 sibling of
// validatePolicyThenPermitStrict (#3114).
//
// The defect: compilePolicy's `then` switch `reject` arm sets
// `pol.Action = PolicyReject` and NEVER inspects `t.Children`. A
// `then reject profile <name>` (a custom reject-response profile) or a
// `then reject tcp-reset` (a packet-type reject) therefore commits cleanly
// but has its profile / packet-type SILENTLY DROPPED — the dataplane emits
// generic reject behaviour regardless of what the operator configured. The
// set-schema (schema_security.go) does not list `reject` children and
// schema_walk.go returns nil for unknown keywords, so nothing rejects them
// either. The configured wire-contract / blocked-content semantics are
// lost without any commit-time signal: the operator cannot tell the
// profile is inert.
//
// Unlike #3114 (a dropped `then permit application-services` turns a
// permit-with-inspection rule into an UNCONDITIONAL permit — a fail-open)
// this is not a fail-open: reject still rejects. But it is a wire-contract
// and operator-observability divergence — until reject profiles / packet-
// type rejects are implemented the SAFE behaviour is to REJECT an
// unsupported `then reject` child at commit rather than silently strip it.
// A bare `then reject` (no child) is fully supported and commits.
//
// Same AST-pre-walk rationale, dual-shape (flat-set Keys[1] + hierarchical
// Children) handling, both-scope (zone-pair + global) coverage, and
// #1960 strict-with-lenient doctrine as validatePolicyThenPermitStrict.
func validatePolicyThenRejectStrict(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(scope, policyName, child string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then reject %q is not supported "+
				"(xpf emits a generic reject only; it does not implement "+
				"reject profiles or per-packet-type reject responses such as "+
				"tcp-reset — an unsupported then-reject child is silently "+
				"dropped, so the configured custom reject response is inert and "+
				"the operator cannot tell from commit that it has no effect) — "+
				"remove the %q modifier under then reject (a bare then reject "+
				"still works) (#3115)",
			scope, policyName, child, child,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		// A bare `then reject` (a `reject` node with no modifier tokens) is
		// fully supported. Only `then reject <modifier>` (a reject profile or
		// a packet-type reject like tcp-reset) carries an unsupported
		// modifier. ALL `then reject` nodes across ALL `then {}` blocks are
		// inspected (policyThenActionNodes) for the same two-node split reason
		// as the permit gate — `set ... then reject` then `set ... then reject
		// profile X` produces TWO separate `reject` nodes — plus the #3842
		// duplicate inner `then {}` block case. collapsedThenActionTokens
		// flattens each node's modifier tokens across all three parser
		// groupings. The supported reject-modifier set is empty
		// (supportedPolicyThenRejectChildren), so any token is unsupported;
		// report the first per offending node.
		for _, rejectNode := range policyThenActionNodes(polNode, "reject") {
			for _, tok := range collapsedThenActionTokens(rejectNode) {
				if supportedPolicyThenRejectChildren[tok] {
					continue
				}
				if err := emit(scope, policyName, tok); err != nil {
					return err
				}
				break
			}
		}
		return nil
	}

	// #3562: iterate EVERY top-level `security` node and EVERY `policies`
	// sibling, not the first match at any level. parseStatements APPENDS a
	// repeated top-level block instead of merging it (parser.go) and
	// compileExpanded compiles every `security` root, so a then-action modifier
	// in a SECOND duplicate `security {}` (or duplicate `policies {}`) block
	// would bypass a first-`security`/first-`policies` walk while the compiler
	// still compiled the policy and silently dropped the modifier. Descending
	// with forEachChild at security/policies closes that multi-level
	// duplicate-block bypass. The inner per-policy then-action check
	// (checkPolicy) is unchanged.
	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
							return err
						}
					}
				case "from-zone":
					// Mirror compilePolicies' two AST shapes.
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						for _, fzSub := range child.Children {
							tzNode := fzSub.FindChild("to-zone")
							if tzNode == nil {
								continue
							}
							for _, tzSub := range tzNode.Children {
								pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// collapsedThenActionTokens flattens every modifier token under a single
// `then <action>` node (permit / deny / reject) into one token sequence —
// the action node's own Keys[1:] plus the keys of every descendant node —
// regardless of how the flat-set parser grouped them. The parser can
// produce three shapes: flat-onto-action (action.Keys[1:]), collapsed-child
// (one child node carrying all tokens on its Keys), and nested (each
// modifier its own node). Flattening makes the reject gates shape-agnostic.
//
// For the deny gate this mirrors the compiler's applyCollapsedDenyModifiers
// (compiler_security.go) exactly — action.Keys[1:] plus every descendant
// key — so the gate and the wiring can never disagree on the modifier set.
// For the permit/reject gates the supported modifier set is empty, so any
// token returned here is an unsupported modifier the compiler silently
// drops and the gate rejects at commit.
//
// Each gate must additionally iterate ALL same-named action nodes under
// `then` (FindChildren, not FindChild) before calling this: a flat-set
// `set ... then permit` followed by `set ... then permit application-
// services X` produces TWO separate `permit` nodes, and a FindChild-first
// gate would inspect only the (valid) bare node and miss the unsupported
// modifier on the second. The strict commit path still rejects such a
// config via the #3043 conflicting-terminal-action gate, but only this
// all-nodes walk surfaces the specific #3114/#3115 unsupported-modifier
// diagnostic (and the matching lenient-path warning).
func collapsedThenActionTokens(actionNode *Node) []string {
	var toks []string
	if len(actionNode.Keys) >= 2 {
		toks = append(toks, actionNode.Keys[1:]...)
	}
	var walk func(n *Node)
	walk = func(n *Node) {
		toks = append(toks, n.Keys...)
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range actionNode.Children {
		walk(c)
	}
	return toks
}

// validatePolicyThenDenyStrict walks the `security policies` subtree of the
// group-expanded AST and rejects any policy whose `then deny` action arm
// carries a collapsed modifier the compiler does not enforce — the #3141
// sibling of validatePolicyThenPermitStrict (#3114) and
// validatePolicyThenRejectStrict (#3115). Covers both zone-pair and global
// policies.
//
// The defect (codex-review-068 finding 068-01): compilePolicy's `then`
// switch `deny` arm set `pol.Action = PolicyDeny` and NEVER inspected the
// collapsed tail. A flat-set `then deny log session-init` collapses
// `log session-init` onto the deny node (Keys=["deny","log","session-init"])
// rather than nesting it as a sibling `then log` node, so the deny arm
// dropped it — the policy denied traffic but `pol.Log` was never set and the
// configured audit logging was silently inert (a deny-rule observability /
// compliance failure, not a packet fail-open). #3141 fixes the LEGITIMATE
// deny+log/deny+count case by wiring those collapsed modifiers in the
// compiler (applyCollapsedDenyModifiers). This validator is the safety net
// for the REMAINING collapsed modifiers the compiler still cannot enforce:
// they are rejected at commit rather than silently stripped.
//
// Same AST-pre-walk rationale, dual-shape (flat-set Keys[1] + hierarchical
// Children) handling, both-scope (zone-pair + global) coverage, and #1960
// strict-with-lenient doctrine as validatePolicyThenPermitStrict. A bare
// `then deny`, and a `then deny log`/`then deny count` (now wired), commit.
func validatePolicyThenDenyStrict(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(scope, policyName, child string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then deny %q is not supported "+
				"(xpf denies on L3/L4 and supports only the log "+
				"(session-init/session-close) and count modifiers under "+
				"then deny — an unsupported then-deny modifier is silently "+
				"dropped, so the configured behavior is inert and the operator "+
				"cannot tell from commit that it has no effect) — remove the "+
				"%q modifier under then deny (a bare then deny, then deny log, "+
				"or then deny count still works) (#3141)",
			scope, policyName, child, child,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// #3374: session-init/session-close are LOG sub-options, valid ONLY when
	// a `log` token accompanies them in the same collapsed action. A flat-set
	// `then deny session-init` (no `log`) collapses to
	// Keys=["deny","session-init"]; recognizedCollapsedDenyToken accepts the
	// bare sub-token (it cannot tell a sub-token from a top-level modifier
	// positionally), so the gate above let it through and
	// applyCollapsedDenyModifiers silently wired session-init logging for a
	// form Junos rejects. emitOrphanLogSub flags a session-init/session-close
	// sub-token that has no `log` parent in the collapsed tail.
	emitOrphanLogSub := func(scope, policyName, tok string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then deny %q is not valid without "+
				"a log token — session-init/session-close are sub-options of "+
				"then deny log (or the standalone then log), not bare deny "+
				"modifiers, so a collapsed then deny %s silently wires logging "+
				"for syntax Junos rejects — use then deny log %s (or then log "+
				"%s) instead (#3374)",
			scope, policyName, tok, tok, tok, tok,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		// #3842: union `then deny` nodes across ALL `then {}` blocks
		// (policyThenActionNodes), not just the first via FindChild — a
		// duplicate inner then block (load merge/override) carries deny
		// modifiers the compiler applies but a FindChild-first gate never
		// validated.
		denyNodes := policyThenActionNodes(polNode, "deny")
		if len(denyNodes) == 0 {
			return nil
		}
		// A bare `then deny` (a `deny` node with no modifier tokens) is fully
		// supported. Only `then deny <modifier>` carries a collapsed modifier,
		// which the parser groups into one of THREE AST shapes depending on
		// whether deny / its modifiers are declared schema leaves:
		//   - Flat-onto-deny (deny NOT a schema leaf — historical):
		//     `then deny log session-init count` collapses the whole tail onto
		//     the deny node, Keys=["deny","log","session-init","count"]; the
		//     modifier tokens are Keys[1:].
		//   - Collapsed-child (deny IS a schema leaf, #3377): the trailing
		//     tokens form a single child node with all tokens on its Keys,
		//     e.g. deny → child Keys=["log","session-init","count"], or
		//     deny → child Keys=["count","session-init"].
		//   - Nested (deny + modifiers ARE schema leaves, #3377): each modifier
		//     is consumed as its own structural node, e.g.
		//     deny → log → session-init → count.
		// collapsedThenActionTokens flattens all three into the SAME token
		// sequence the compiler's applyCollapsedDenyModifiers acts on
		// (compiler_security.go: deny.Keys[1:] plus every key of every
		// descendant node), so the validator and the wiring agree exactly on
		// the modifier set regardless of how the parser grouped it. EVERY token
		// must be recognized: checking only the first child key missed a
		// supported-leads / unsupported-trails sequence like
		// `then deny count evilmod` (the #3141 review-fold failure mode), which
		// would otherwise be silently dropped. recognizedCollapsedDenyToken is
		// the EXACT set applyCollapsedDenyModifiers acts on — the log/count
		// modifiers plus log's session-init/session-close sub-tokens.
		//
		// ALL `then deny` nodes are unioned (FindChildren, not FindChild): a
		// split `set ... then deny log` + `set ... then deny session-init`
		// produces two deny nodes, and the compiler's per-node
		// applyCollapsedDenyModifiers accumulates BOTH onto the same pol.Log,
		// so the validator must compute `hasLog` over the union to agree with
		// the wiring (a per-node check would wrongly flag the session-init
		// node as an orphan #3374 reject for a config the compiler logs
		// correctly).
		var toks []string
		for _, dn := range denyNodes {
			toks = append(toks, collapsedThenActionTokens(dn)...)
		}
		hasLog := false
		for _, tok := range toks {
			if tok == "log" {
				hasLog = true
				break
			}
		}
		for _, tok := range toks {
			if !recognizedCollapsedDenyToken(tok) {
				if err := emit(scope, policyName, tok); err != nil {
					return err
				}
				continue
			}
			// #3374: a recognized session-init/session-close sub-token is
			// valid only with a `log` token in the same collapsed action.
			if (tok == "session-init" || tok == "session-close") && !hasLog {
				if err := emitOrphanLogSub(scope, policyName, tok); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// #3562: iterate EVERY top-level `security` node and EVERY `policies`
	// sibling, not the first match at any level. parseStatements APPENDS a
	// repeated top-level block instead of merging it (parser.go) and
	// compileExpanded compiles every `security` root, so a then-action modifier
	// in a SECOND duplicate `security {}` (or duplicate `policies {}`) block
	// would bypass a first-`security`/first-`policies` walk while the compiler
	// still compiled the policy and silently dropped the modifier. Descending
	// with forEachChild at security/policies closes that multi-level
	// duplicate-block bypass. The inner per-policy then-action check
	// (checkPolicy) is unchanged.
	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
							return err
						}
					}
				case "from-zone":
					// Mirror compilePolicies' two AST shapes.
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						for _, fzSub := range child.Children {
							tzNode := fzSub.FindChild("to-zone")
							if tzNode == nil {
								continue
							}
							for _, tzSub := range tzNode.Children {
								pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// validatePolicyUnsupportedThenSiblings rejects a `then` child the policy
// compiler does not implement, including explicit `then next term`. It also
// diagnoses unknown `then log` modes that tolerant schema validation warns
// about but lets ingress continue with. The firewall-filter compiler has
// separate, supported next-term semantics; this gate is scoped to security
// policies.
func validatePolicyUnsupportedThenSiblings(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	checkPolicy := func(scope, policyName string, polNode *Node) error {
		for _, sibling := range policyUnsupportedThenSiblings(polNode) {
			msg := fmt.Sprintf(
				"security policies %s policy %q has unsupported then sibling %q "+
					"(the compiler drops it, which can leave an earlier permit active); "+
					"remove it (#11013)",
				scope, policyName, sibling,
			)
			if !lenient {
				return fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg)
		}
		for _, mode := range policyUnsupportedThenLogTokens(polNode) {
			msg := fmt.Sprintf(
				"security policies %s policy %q has unsupported then log mode %q "+
					"(the compiler drops it, so configured session logging is incomplete; "+
					"remove it or use session-init/session-close (#11023))",
				scope, policyName, mode,
			)
			if !lenient {
				return fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg)
		}
		return nil
	}

	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
							return err
						}
					}
				case "from-zone":
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						for _, fzSub := range child.Children {
							tzNode := fzSub.FindChild("to-zone")
							if tzNode == nil {
								continue
							}
							for _, tzSub := range tzNode.Children {
								pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// validatePolicyEnforcementSubtrees rejects direct policy `term` and
// `session-options` children that compilePolicy drops, while allowing harmless
// unknown policy metadata to remain advisory-only.
func validatePolicyEnforcementSubtrees(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	checkPolicy := func(scope, policyName string, polNode *Node) error {
		for _, subtree := range policyDroppedEnforcementSubtrees(polNode) {
			msg := fmt.Sprintf(
				"security policies %s policy %q contains dropped enforcement subtree %q "+
					"(nested enforcement is not compiled and could weaken the direct policy action) (#11014)",
				scope, policyName, subtree,
			)
			if !lenient {
				return fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg)
		}
		return nil
	}

	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
							return err
						}
					}
				case "from-zone":
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						for _, fzSub := range child.Children {
							tzNode := fzSub.FindChild("to-zone")
							if tzNode == nil {
								continue
							}
							for _, tzSub := range tzNode.Children {
								pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}
