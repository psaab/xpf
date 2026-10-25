package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_ipmon_then_16712.go carries the #16712 gate for
// `services ip-monitoring policy <p> then` children.
//
// compileIPMonitoring reads only `preferred-route` under `then`
// (compiler_services.go); IPMonitoringPolicy has no interface action
// and the runtime (pkg/ipmon) never touches an interface. The `then`
// container was open-world in setSchema, so the Junos interface
// action
//
//	set services ip-monitoring policy p then interface ge-0/0/1 enable
//	set services ip-monitoring policy p then interface ge-0/0/1 disable
//
// (and any other undeclared child such as `preffered-route`) passed
// Set and Commit with no error and no warning, while the
// preferred-route half of the same policy still worked. The backup
// interface the operator expected to come up (or the primary to go
// down) on probe failure was never touched.
//
// WHY NOT closedWorld ON `then`: that flag INHERITS (see #9017), so
// arming it on `then` would close every level below it —
// `preferred-route`, `route`, and the `routing-instance` subtree —
// on the SchemaValidate path only. CompileConfig (strict compile
// without SchemaValidate) would still accept silently, and the
// tolerant load / peer-sync paths need a warning, not the schema
// walk's hard reject. This gate is scoped to exactly the `then`
// level, runs on the group-expanded AST in runPreWalkGates (both
// strict and lenient compile paths), and inherits nothing. The
// permitted set is read from the schema (#9017's rule), so a child
// declared under `then` later is permitted automatically.
//
// Strict (commit / commit-check): hard-reject naming the policy and
// the unsupported action, with a specific message for the Junos
// `interface <if> enable|disable` action. Lenient (load /
// peer-sync): warn so an already-persisted or peer-synced config
// still BOOTS (#1960); the interface action stays inert there,
// which is the pre-existing runtime behaviour, now surfaced.

// ipMonThenChildTokens16712 returns the statement keywords declared
// directly under `services ip-monitoring policy <p> then`, sorted,
// or nil if the schema node is missing.
func ipMonThenChildTokens16712() []string {
	svc := setSchema.children["services"]
	if svc == nil {
		return nil
	}
	ipm := svc.children["ip-monitoring"]
	if ipm == nil {
		return nil
	}
	pol := ipm.children["policy"]
	if pol == nil {
		return nil
	}
	thenNode := pol.children["then"]
	if thenNode == nil || len(thenNode.children) == 0 {
		return nil
	}
	out := make([]string, 0, len(thenNode.children))
	for k := range thenNode.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ipMonThenChildTokensOf16712 returns the statement keywords one
// `then` node carries, across both AST shapes. Mirrors
// thenChildTokens14660 / dhcpRelayChildTokensOf9552: a packed
// `then interface ge-0/0/1 enable;` packs the child keyword on
// Keys[1] and its Children (if any) are that child's body; only a
// bare `then` node has Children that are `then` statements.
func ipMonThenChildTokensOf16712(thenNode *Node) []string {
	if len(thenNode.Keys) >= 2 {
		return []string{thenNode.Keys[1]}
	}
	var out []string
	for _, ch := range thenNode.Children {
		if ch != nil && ch.Name() != "" {
			out = append(out, ch.Name())
		}
	}
	return out
}

// validateIPMonThenChildrenAST16712 walks every
// `services ip-monitoring policy <p> then` block on the
// group-expanded, inactive-pruned tree and rejects (strict) or
// warns (lenient) about any child the schema does not declare
// under `then` — today anything other than `preferred-route`.
// It is an AST pre-walk because unknown children are gone by the
// time compileIPMonitoring has run: PreferredRoutes carries no
// trace of the dropped token.
func validateIPMonThenChildrenAST16712(nodes []*Node, lenient bool) ([]string, error) {
	declared := ipMonThenChildTokens16712()
	if len(declared) == 0 {
		// Schema unreadable: decline to judge rather than refuse
		// every ip-monitoring policy (mirrors #9323/#9552/#16459).
		return nil, nil
	}
	permitted := make(map[string]bool, len(declared))
	for _, tok := range declared {
		permitted[tok] = true
	}
	var warnings []string
	seen := map[string]bool{}
	emit := func(policy, tok string) error {
		var msg string
		if tok == "interface" {
			// The Junos interface action: name it specifically so
			// the operator learns the exact unsupported action,
			// not just that some token is unknown.
			msg = fmt.Sprintf("services ip-monitoring policy %q then: interface action is not supported by xpf (#16712) — "+
				"`then interface <if> enable|disable` compiles to NOTHING: the interface is never enabled or disabled on probe failure; "+
				"remove it or keep only `then preferred-route`", policy)
		} else {
			msg = fmt.Sprintf("services ip-monitoring policy %q then: %q is not a `then` statement "+
				"xpf implements (known: %s) — it compiles to NOTHING: it renders in `show configuration` and no action is taken on probe failure (#16712)",
				policy, tok, strings.Join(declared, ", "))
		}
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
		return nil
	}
	checkThen := func(policy string, thenNode *Node) error {
		if thenNode == nil {
			return nil
		}
		// Packed head on the then node itself (`then interface ...`
		// with no children): Keys[1] is the child keyword. When
		// Keys[1] is present the Children, if any, are that child's
		// body, not siblings — judge only Keys[1].
		if len(thenNode.Keys) >= 2 {
			tok := thenNode.Keys[1]
			if tok == "" || permitted[tok] || routingInstanceApplyMetaKeyword9323(tok) {
				return nil
			}
			return emit(policy, tok)
		}
		for _, tok := range ipMonThenChildTokensOf16712(thenNode) {
			if tok == "" || permitted[tok] || routingInstanceApplyMetaKeyword9323(tok) {
				continue
			}
			if err := emit(policy, tok); err != nil {
				return err
			}
		}
		return nil
	}

	for _, svc := range nodes {
		if svc == nil || svc.Name() != "services" {
			continue
		}
		// Fully packed flat-set / elided spelling:
		// `services ip-monitoring policy p then interface ...` may
		// pack the whole tail onto the services node's Keys.
		if len(svc.Keys) >= 6 && svc.Keys[1] == "ip-monitoring" && svc.Keys[2] == "policy" && svc.Keys[4] == "then" {
			tok := svc.Keys[5]
			if tok != "" && !permitted[tok] && !routingInstanceApplyMetaKeyword9323(tok) {
				if err := emit(svc.Keys[3], tok); err != nil {
					return warnings, err
				}
			}
			continue
		}
		for _, ipm := range svc.FindChildren("ip-monitoring") {
			if ipm == nil {
				continue
			}
			// `ip-monitoring policy p then interface ...` packed
			// onto the ip-monitoring node.
			if len(ipm.Keys) >= 5 && ipm.Keys[1] == "policy" && ipm.Keys[3] == "then" {
				tok := ipm.Keys[4]
				if tok != "" && !permitted[tok] && !routingInstanceApplyMetaKeyword9323(tok) {
					if err := emit(ipm.Keys[2], tok); err != nil {
						return warnings, err
					}
				}
				continue
			}
			for _, polInst := range namedInstances(ipm.FindChildren("policy")) {
				polNode := polInst.node
				if polNode == nil {
					continue
				}
				// Packed policy tail: `policy p then interface ...`
				// packs `then` and its child onto the policy node's
				// Keys (namedInstances keeps the full Keys run).
				if len(polNode.Keys) >= 4 && polNode.Keys[2] == "then" {
					tok := polNode.Keys[3]
					if tok != "" && !permitted[tok] && !routingInstanceApplyMetaKeyword9323(tok) {
						if err := emit(polInst.name, tok); err != nil {
							return warnings, err
						}
					}
					continue
				}
				for _, thenNode := range polNode.FindChildren("then") {
					if err := checkThen(polInst.name, thenNode); err != nil {
						return warnings, err
					}
				}
			}
		}
	}
	return warnings, nil
}
