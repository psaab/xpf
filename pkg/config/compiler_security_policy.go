package config

import "fmt"

func compilePolicies(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		if child.Name() == "default-policy" {
			var policyStr string
			if len(child.Keys) >= 2 {
				// Flat form: default-policy deny-all;
				policyStr = child.Keys[1]
			} else if len(child.Children) > 0 {
				// Hierarchical form: default-policy { deny-all; }
				policyStr = child.Children[0].Name()
			}
			switch policyStr {
			case "permit-all":
				sec.DefaultPolicy = PolicyPermit
			case "deny-all":
				sec.DefaultPolicy = PolicyDeny
			case "reject-all":
				// #3065: reject-all is valid Junos; previously it fell
				// through this switch and left the (now deny) default
				// untouched. Map it to PolicyReject so the dataplane
				// no-match verdict sends an ICMP/RST reject instead of a
				// silent drop.
				sec.DefaultPolicy = PolicyReject
			}
			continue
		}
		// #3534 (split from #3363 Part 2): `default-policy-log
		// session-init|session-close` requests RT_FLOW session logging for the
		// implicit default-policy verdict. Mirrors the per-policy `then log`
		// selection (#2508) — the flags are stamped onto the Rust default-verdict
		// result and, for a default-PERMIT verdict, onto the installed session so
		// it emits RT_FLOW_SESSION_CREATE/CLOSE like a named policy. The flag
		// lives in a sibling container because the `default-policy` enum leaf
		// cannot carry `then` children (schema.go typed-leaf invariant).
		if child.Name() == "default-policy-log" {
			// #3703: multi-value session-log list leaf. Read every mode via the
			// firewallMatchValues SSOT (Keys[1:] AND/OR one-per-child) so a
			// bracket / single-line `default-policy-log [ session-init
			// session-close ]` keeps BOTH flags; the prior FindChild lookups
			// missed session-close when the bracket tail mis-nested it under
			// session-init (the #2419 collapse bug). Unknown tokens are rejected
			// at commit by SchemaValidate (the enum leaf validator).
			for _, mode := range firewallMatchValues(child) {
				switch mode {
				case "session-init":
					sec.DefaultPolicyLogSessionInit = true
				case "session-close":
					sec.DefaultPolicyLogSessionClose = true
				}
			}
			continue
		}
		// #4233: `security policies policy-rematch [extensive]`. In Junos this
		// re-evaluates in-progress sessions against the changed policy set on
		// commit (and, WITHOUT the knob, Junos still drops the sessions of a
		// DELETED policy). xpf performs no session invalidation on commit yet
		// (enforcement tracked as #4234), so the knob is recorded here only so
		// it is no longer silently dropped, and ValidateConfig emits an
		// accepted-only advisory. `extensive` may arrive as a flat trailing
		// key (Keys=["policy-rematch","extensive"]) or a hierarchical child.
		if child.Name() == "policy-rematch" {
			sec.PolicyRematch = true
			if len(child.Keys) >= 2 && child.Keys[1] == "extensive" {
				sec.PolicyRematchExtensive = true
			}
			for _, sub := range child.Children {
				if sub.Name() == "extensive" {
					sec.PolicyRematchExtensive = true
				}
			}
			continue
		}
		// "global { policy ... }" - global policies applied to all zone pairs
		if child.Name() == "global" {
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				pol := compilePolicy(polInst, true)
				sec.GlobalPolicies = append(sec.GlobalPolicies, pol)
			}
			continue
		}
		// "from-zone trust to-zone untrust { ... }"
		if child.Name() == "from-zone" {
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair

			if len(child.Keys) >= 4 {
				// Hierarchical: Keys=["from-zone", "trust", "to-zone", "untrust"]
				//
				// #9246: a BRACKETED zone list lands here too, and silently.
				// `to-zone [ untrust dmz ]` lexes to exactly this 4-key shape
				// with the residue swallowing the whole rule onto one leaf:
				//
				//	[from-zone trust to-zone untrust]
				//	  [dmz policy p1 then permit]
				//
				// so FindChildren("policy") below matches nothing and the pair
				// compiles with ZERO policies -- the authored rule exists
				// nowhere. `from-zone [ trust dmz ]` shifts the keys instead:
				//
				//	[from-zone trust dmz to-zone]
				//	  [untrust policy p1 then permit]
				//
				// making Keys[3] the literal string "to-zone", which today is
				// caught only by accident, as an undefined zone named
				// "to-zone".
				//
				// Junos accepts no bracketed list on from-zone/to-zone -- a
				// policy context is ONE zone pair -- so this is refused rather
				// than expanded. Expanding would invent a semantics the
				// platform does not have and would owe an answer about what a
				// single policy NAME means once it exists in several contexts.
				if bad := malformedZonePairShape9246(child); bad != "" {
					sec.MalformedZonePairs = append(sec.MalformedZonePairs, bad)
					continue
				}
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
				zpp := &ZonePairPolicies{
					FromZone: zp.from,
					ToZone:   zp.to,
				}

				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					zpp.Policies = append(zpp.Policies, compilePolicy(polInst, false))
				}

				sec.Policies = append(sec.Policies, zpp)
			}
		}
	}
	return nil
}

// #9574: the `any-ipv4` / `any-ipv6` -> `0.0.0.0/0` / `::/0` rewrite
// (normalizePolicyAddrToken, #2008 H11) used to run here, while the policy was
// compiled and BEFORE any address-book resolution, so an address-book object
// named `0.0.0.0/0` captured the keyword. The compiled config now keeps the
// keyword, and the userspace snapshot builder writes the CIDR the dataplane
// parses (config.PolicyAddressKeywordLiteral) after it has classified the token
// as a keyword.

// policyMatchChildren returns the children of EVERY `match {}` block under a
// security-policy term, flattened in declaration order. #3842: a policy
// loaded via `load merge` / `load override` (or a hierarchical config that
// authors two blocks) carries DUPLICATE inner `match {}` blocks as SEPARATE
// children — parseStatements APPENDS a repeated block, it does not merge it
// (parser.go) — and Junos merges duplicate match blocks. Reading only the
// first via FindChild("match") silently DROPS the second block's constraints,
// WIDENING the policy with a clean commit (a security fail-open) AND hiding
// the second block from the strict match gates. The compiler (compilePolicy)
// and the strict match gates (validatePolicyMatchLeavesStrict #3113/#3142/
// #3673, validatePolicyRequiredMatchStrict #3044) all accumulate over this
// helper so every match block is both enforced and validated. #3562/#3377
// closed the top-level duplicate-`security`/`policies` and duplicate-action-
// node cases; this closes the duplicate inner match/then blocks under one
// term.
func policyMatchChildren(polNode *Node) []*Node {
	var out []*Node
	for _, mn := range polNode.FindChildren("match") {
		out = append(out, mn.Children...)
	}
	return out
}

// policyThenChildren is the `then {}` sibling of policyMatchChildren (#3842):
// the children of EVERY `then {}` block under a policy term, flattened in
// order. compilePolicy accumulates the terminal action / log / count over all
// then blocks, so a second `then { reject; }` after a first `then { permit; }`
// contributes a SECOND terminal action that the #3043 conflicting-terminal-
// action gate rejects at commit (the fail-closed floor) instead of being
// silently dropped into a fail-open permit.
func policyThenChildren(polNode *Node) []*Node {
	var out []*Node
	for _, tn := range polNode.FindChildren("then") {
		out = append(out, tn.Children...)
	}
	return out
}

// policyThenActionNodes returns every `then` action node named `action`
// (permit / deny / reject) across ALL `then {}` blocks under a policy term.
// The then-action reject gates (validatePolicyThenPermitStrict #3114,
// validatePolicyThenRejectStrict #3115, validatePolicyThenDenyStrict #3141)
// use it so a modifier carried by a DUPLICATE `then {}` block is inspected,
// not only the first block's action nodes (#3842). It composes with the
// existing per-then-block FindChildren(action) two-node handling (#3377).
func policyThenActionNodes(polNode *Node, action string) []*Node {
	var out []*Node
	for _, tn := range polNode.FindChildren("then") {
		out = append(out, tn.FindChildren(action)...)
	}
	return out
}

// compilePolicy extracts a Policy from a named policy instance. isGlobal marks
// a `security policies global` policy (vs a zone-pair policy) so the #5575
// unsupported-match-leaf detection honors the global-only from-zone/to-zone
// match context (#3148) exactly as validatePolicyMatchLeavesStrict does.
func compilePolicy(polInst struct {
	name string
	node *Node
}, isGlobal bool) *Policy {
	pol := &Policy{Name: polInst.name}

	// #3842: accumulate across ALL `match {}` blocks (policyMatchChildren) —
	// a duplicate inner match block must contribute its constraints, never be
	// silently dropped by a FindChild-first read (a fail-open widening).
	matchChildren := policyMatchChildren(polInst.node)
	if len(matchChildren) > 0 {
		for _, m := range matchChildren {
			switch m.Name() {
			case "source-address":
				// #4121: read BOTH Keys[1:] AND Children via the
				// firewallMatchValues SSOT — the SAME reader the strict match
				// gates (validatePolicyMatchLeavesStrict) use — so the compiler
				// and gates can never diverge on a dual-AST shape (the #2419
				// bracketed-list class). The prior either/or read
				// (`if len(Keys)>=2 { Keys[1:] } else { Children }`) was correct
				// for every shape the parser actually produces (bracket/inline →
				// Keys, block → Children, repeated → sibling nodes, all mutually
				// exclusive), but a `source-address a1 { a2; }` node carrying
				// members in BOTH slots dropped the child members. Reading both
				// removes that divergence and shares one reader with the gates.
				pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, firewallMatchValues(m)...)
			case "destination-address":
				// #4121: read BOTH slots via the firewallMatchValues SSOT (see
				// the source-address arm).
				pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, firewallMatchValues(m)...)
			case "source-address-excluded":
				pol.Match.SourceAddressExcluded = true
			case "destination-address-excluded":
				pol.Match.DestinationAddressExcluded = true
			case "from-zone":
				// #3148/#4626 M03: global-policy from-zone match SCOPE. The
				// schema exposes this leaf only under `security policies
				// global policy <p> match`; for zone-pair policies the zones
				// come from the surrounding from-zone/to-zone stanza so this
				// case is never reached. Junos accepts a zone LIST here, so
				// read BOTH Keys[1:] AND Children via the firewallMatchValues
				// SSOT — the #2419 lexer collapses `[ trust dmz ]` onto one
				// leaf's Keys (["from-zone","trust","dmz"]) and repeated `set`
				// lines land as sibling children. Accumulate every value;
				// reading only Keys[1] was the #4626 miscompile that dropped
				// all zones past the first. Empty stays "all zones".
				pol.Match.FromZones = append(pol.Match.FromZones, firewallMatchValues(m)...)
			case "to-zone":
				// #3148/#4626 M03: global-policy to-zone match SCOPE — accumulate
				// every value via firewallMatchValues (see from-zone).
				pol.Match.ToZones = append(pol.Match.ToZones, firewallMatchValues(m)...)
			case "application":
				// #4121: read BOTH slots via the firewallMatchValues SSOT (see
				// the source-address arm).
				pol.Match.Applications = append(pol.Match.Applications, firewallMatchValues(m)...)
			}
		}
	}

	// #3842: accumulate across ALL `then {}` blocks (policyThenChildren) so a
	// duplicate inner then block's terminal action / log / count is enforced.
	// Two terminal actions from two then blocks feed pol.terminalActions and
	// are rejected by the #3043 conflicting-terminal-action gate at commit
	// (fail-closed) rather than the second being silently dropped (fail-open).
	thenChildren := policyThenChildren(polInst.node)
	if len(thenChildren) > 0 {
		for _, t := range thenChildren {
			switch t.Name() {
			case "permit":
				pol.Action = PolicyPermit
				pol.terminalActions = append(pol.terminalActions, PolicyPermit)
			case "deny":
				pol.Action = PolicyDeny
				pol.terminalActions = append(pol.terminalActions, PolicyDeny)
				// #3141: a flat-set `then deny log session-init` collapses the
				// log/count modifier onto the deny node
				// (Keys=["deny","log","session-init",...], no children) instead
				// of nesting it as a sibling `then log` node. The deny arm used
				// to read only t.Name() and silently dropped the collapsed
				// modifier, so deny-with-logging committed but never logged.
				// Wire the collapsed log/count modifier here so deny+log works
				// in BOTH the flat-collapsed and the separate-node
				// (`then { deny; log session-init; }`, handled by the `log` arm)
				// forms — matching the standalone `then log`/`then count` arms.
				// validatePolicyThenDenyStrict rejects any OTHER (non-log,
				// non-count) collapsed deny modifier at commit (#3141).
				applyCollapsedDenyModifiers(pol, t)
			case "reject":
				pol.Action = PolicyReject
				pol.terminalActions = append(pol.terminalActions, PolicyReject)
			case "log":
				// #3703: `then log` is a multi-value session-log list leaf. A
				// bracket / single-line list (`then log [ session-init
				// session-close ]`) carries the modes as Keys[1:] AND/OR
				// one-per-child; read BOTH via the firewallMatchValues SSOT so
				// session-close is not dropped when it trails session-init in a
				// bracket list (the #2419 collapse bug). Unknown tokens are
				// rejected at commit by SchemaValidate (the enum leaf validator);
				// a bare `then log` (no mode) is rejected by
				// validatePolicyLogActionStrict (#3060). ACCUMULATE (create once,
				// never reset): a multi-value leaf whose values arrive on SEPARATE
				// flat-set lines (`then log session-init` + `then log
				// session-close`) produces TWO sibling `log` leaves, so resetting
				// pol.Log per node would drop the earlier flag.
				if pol.Log == nil {
					pol.Log = &PolicyLog{}
				}
				for _, mode := range firewallMatchValues(t) {
					switch mode {
					case "session-init":
						pol.Log.SessionInit = true
					case "session-close":
						pol.Log.SessionClose = true
					}
				}
			case "count":
				pol.Count = true
			}
		}
	}

	// #3043 fail-closed default: a policy with NO explicit terminal action
	// (a log-only / count-only stanza, or a typo'd `then`) must NOT inherit
	// PolicyPermit (the PolicyAction zero value) — that was a silent
	// fail-OPEN. Default the runtime action to DENY so the tolerant
	// load / HA-sync path (which only WARNS, see
	// validatePolicyTerminalActionStrict + lenientPolicyTerminalAction)
	// fails closed; the strict commit path rejects the actionless policy
	// outright (terminalActions is empty). Conflicting actions keep the
	// pre-existing last-wins runtime value so a leniently-loaded config
	// still boots; the strict gate rejects the conflict at commit. That
	// last-wins was decided for ONE policy with conflicting `then` blocks. When
	// the #8752 duplicate-name fold would use it to turn an earlier statement's
	// deny into a permit, the merged policy is poisoned instead (#9571,
	// markFoldWidenedPolicies9571).
	if len(pol.terminalActions) == 0 {
		pol.Action = PolicyDeny
	}

	if descNode := polInst.node.FindChild("description"); descNode != nil {
		pol.Description = nodeVal(descNode)
	}
	if snNode := polInst.node.FindChild("scheduler-name"); snNode != nil {
		pol.SchedulerName = nodeVal(snNode)
	}

	// #4232 (fable-167 P-4b): record any DIRECT child of `policy <name>` whose
	// keyword the compiler does not read. match/then/description/scheduler-name
	// are the recognized leaves; anything else (a typo like `descripton`, or an
	// unimplemented policy option) was silently dropped. Recording it lets the
	// compiler emit an accepted-but-inert / probable-typo advisory. Iterate in
	// config order for a deterministic warning.
	for _, child := range polInst.node.Children {
		switch child.Name() {
		case "match", "then", "description", "scheduler-name":
			// recognized above
		default:
			pol.UnknownChildren = append(pol.UnknownChildren, child.Name())
		}
	}

	// #4626 M03: canonicalize the accumulated scoped-global zone sets to a
	// sorted, de-duplicated form so display is stable, HA expansion is
	// order-symmetric, and `[ dmz trust ]` == `[ trust dmz ]`. A single-zone
	// scope is a no-op (a 1-element sorted slice), keeping the pre-#4626
	// single-string behaviour bit-identical; a zone-pair policy leaves both
	// nil (never populated).
	pol.Match.FromZones = sortDedupZones(pol.Match.FromZones)
	pol.Match.ToZones = sortDedupZones(pol.Match.ToZones)

	// #5575: fail-CLOSED on the tolerant load / peer-sync path. A policy the
	// #3044 / #3113 / #3114 strict gates would REJECT (a missing required match
	// dimension, an unsupported `match` leaf, or an unsupported `then permit`
	// modifier) is downgraded to a WARNING by CompileConfigLenient — but the
	// compiler then SILENTLY DROPS the offending constraint: a missing dimension
	// leaves the corresponding match slice empty, an unsupported match leaf /
	// then-permit modifier is never read. The userspace matcher reads an empty
	// dimension as match-ANY, so the leniently-loaded policy silently widens to
	// a permit BROADER than configured (a fail-open on the persisted-load /
	// HA-sync path). Record the invalidation on the typed Policy so the
	// userspace snapshot builder can poison the rule with the __unsupported__
	// sentinel (never-match) instead of publishing the widened permit.
	//
	// This uses the SAME per-policy predicates the three strict gates use
	// (single source of truth), so the flag is set for EXACTLY the policies a
	// strict commit would reject. On the strict path those policies never reach
	// compilePolicy — runPreWalkGates hard-rejects them first — so a clean
	// strict-committed policy always leaves the flag false and its snapshot is
	// byte-identical to before. The distinction between an INTENTIONAL wildcard
	// (`match application any` → a non-empty ["any"] slice → match-any, flag
	// false) and a DROPPED / MISSING constraint (empty slice, flag true) is made
	// here on the AST: policyMissingRequiredMatchDimensions treats an omitted
	// leaf differently from an explicit `any`.
	//
	// #6526: policyValuelessMatchDimensions is the third predicate because a
	// dimension written with NO OPERAND (`source-address;`) compiles to the
	// BYTE-IDENTICAL empty slice the omitted form produces — it read as
	// "present" to the name-based predicate above and therefore slipped past
	// this poison as well as past the strict gate, so a leniently-loaded
	// valueless permit was published to the dataplane fully widened. It
	// covers all five value-bearing dimensions, including the scoped-global
	// from-zone/to-zone whose empty set means "all zones".
	if len(policyMissingRequiredMatchDimensions(polInst.node)) > 0 ||
		len(policyValuelessMatchDimensions(polInst.node, isGlobal)) > 0 ||
		len(policyUnsupportedMatchLeafFindings(polInst.node, isGlobal)) > 0 ||
		len(policyUnsupportedThenPermitModifiers(polInst.node)) > 0 {
		pol.LenientContentDropped = true
	}

	return pol
}

// recognizedCollapsedDenyToken reports whether tok is a token that
// applyCollapsedDenyModifiers acts on inside a FLAT-collapsed `then deny`
// sequence — the `log`/`count` modifiers plus log's session-init/
// session-close sub-tokens. On the flat path the lexer flattens a modifier
// and its sub-tokens into a single Keys slice (e.g.
// Keys=["deny","log","session-init","count"]), so the validator cannot tell
// a modifier from a sub-token positionally; it accepts exactly the tokens
// the wiring consumes and rejects anything else. This is the single source
// of truth shared by applyCollapsedDenyModifiers (the wiring) and
// validatePolicyThenDenyStrict (the reject gate) so they never disagree on
// what is a supported token vs an unsupported modifier that would be
// silently dropped (#3141).
func recognizedCollapsedDenyToken(tok string) bool {
	switch tok {
	case "log", "session-init", "session-close", "count":
		return true
	default:
		return false
	}
}

// applyCollapsedDenyModifiers wires a `log`/`count` action modifier that a
// flat-set `then deny <modifier>` collapsed onto the deny node, so deny+log
// (and deny+count) work in the flat form exactly as they do as separate
// `then` siblings (#3141). The modifier appears in TWO AST shapes:
//   - Flat set `then deny log session-init` collapses the whole tail onto
//     the deny node: Keys=["deny","log","session-init"] (no children).
//     Keys[0] is "deny"; Keys[1:] carry the modifier and its sub-tokens.
//   - A hierarchical `then { deny { log { session-init; } } }` (non-canonical
//     but parseable) nests the modifier as a child node of deny.
//
// Only `log` (with session-init/session-close sub-tokens) and `count` are
// recognized — the exact set the standalone `then log`/`then count` arms
// support. Any OTHER collapsed deny modifier is left untouched here and
// rejected at commit by validatePolicyThenDenyStrict, mirroring the #3114/
// #3115 then-permit/then-reject reject-at-commit gates.
func applyCollapsedDenyModifiers(pol *Policy, denyNode *Node) {
	apply := func(tok string) {
		switch tok {
		case "log":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
		case "session-init":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
			pol.Log.SessionInit = true
		case "session-close":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
			pol.Log.SessionClose = true
		case "count":
			pol.Count = true
		}
	}
	// Flat-collapsed tail: Keys[1:] (Keys[0] == "deny").
	if len(denyNode.Keys) >= 2 {
		for _, k := range denyNode.Keys[1:] {
			apply(k)
		}
	}
	// Hierarchical children (non-canonical shape).
	var walk func(n *Node)
	walk = func(n *Node) {
		for _, k := range n.Keys {
			apply(k)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range denyNode.Children {
		walk(c)
	}
}

// LenientDroppedPolicyLocator names the first policy in cfg whose compile
// SILENTLY DROPPED a match / then-permit constraint on the tolerant path
// (#5575 LenientContentDropped), or "" when none did.
//
// The flag is the compiler's fail-closed poison: policies_lower.go stamps such
// a rule with the __unsupported__ application sentinel so the Rust integrity
// preflight REJECTS THE WHOLE SNAPSHOT rather than arming a permit broader than
// the operator configured. So a config carrying this flag is one the dataplane
// is GUARANTEED to refuse — which makes it a usable local predicate for "this
// config cannot become the running snapshot" without a round trip to the
// helper.
//
// It walks BOTH policy shapes. A zone-pair rule and a global rule reach the
// poison through the same compilePolicy path, so a walker that checked only
// `Security.Policies` would report a clean config for a poisoned global policy
// — the exact miss that would let an unappliable rollback target through the
// #6707 gate. Returning the locator rather than a bare bool lets the caller
// name the offending rule to the operator; a rule with no zone context is a
// global policy and is labelled as such.
func LenientDroppedPolicyLocator(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && pol.LenientContentDropped {
				return fmt.Sprintf("from-zone %s to-zone %s policy %q",
					zpp.FromZone, zpp.ToZone, pol.Name)
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol != nil && pol.LenientContentDropped {
			return fmt.Sprintf("global policy %q", pol.Name)
		}
	}
	return ""
}
