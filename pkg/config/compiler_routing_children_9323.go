package config

import (
	"fmt"
	"sort"
	"strings"
)

// #9323: `routing-instances <name>` was an OPEN-WORLD container at every config
// channel, so a `security`, `firewall` or entirely bogus subtree nested under a
// routing instance committed clean, rendered back in `show configuration`, and
// compiled to NOTHING.
//
// Measured before this gate, through `configstore.CheckText` (the operator
// commit gate) and `compileTreeStrict`, flat-set and braced alike:
//
//	set routing-instances VRF-A security nat nat64 rule-set rs1 prefix 64:ff9b::/96
//	set routing-instances VRF-A totally-bogus-keyword foo bar
//	set routing-instances VRF-A firewall filter f1 term t1 then discard
//
// all three: CompileConfig = nil, SchemaValidate = nil, zero objects compiled.
// For the first, CheckText reported `nat64 rule-sets compiled=0` with no error
// and no warning.
//
// Why an operator reaches for it: Junos-style per-instance scoping is the
// natural way to make NAT64 or a filter apply only inside a VRF, and there is
// no supported way to do it — `routing_domain` is stamped from the INGRESS
// INTERFACE, never from the NAT rule-set, and `NAT64RuleSnapshot` carries no
// routing scope field at all. So the spelling an operator would try is exactly
// the one that silently does nothing. The sibling it would most be confused
// with, `security nat nat64`, is `closedWorld: true` precisely because "a
// silent drop there is a real footgun".
//
// WHY NOT `closedWorld: true` ON THE WILDCARD. That was the first attempt. The
// flag INHERITS down every level, which is what made the same flip wrong at the
// config root (it rejects 9 of the 10 shipped and example configs — see
// schema_walk.go) and at `firewall family` (#9017, where it began rejecting
// `from source-prefix-list trusted`).
//
// Here the whole-suite measurement said it was SAFE — `go test ./...` with it
// armed rejected zero configs — and that reading was WRONG, which is worth
// recording because it is the trap: a targeted over-reach probe then found
//
//	routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001
//
// REJECTED, because the per-instance `protocols bgp group` subtree does not
// declare `neighbor` while the shared compiler (compileProtocols, whose result
// is copied into ri.BGP) handles it fully. BGP neighbours inside a VRF are
// ordinary configuration and NO FIXTURE IN THE TREE WRITES ONE, so a green
// suite was evidence about the corpus rather than about the change. Arming the
// wildcard exposes every incompleteness in the per-instance protocol grammar;
// this gate is scoped to the instance level and inherits nothing.
//
// THE PERMITTED SET IS READ FROM THE SCHEMA, not hardcoded (#9017's rule): a
// keyword declared under the routing-instance wildcard is permitted here
// automatically, so there is no second place to remember. The schema and the
// compiler's own `isRoutingInstanceKeyword8787` are held to the SAME SET by
// TestRoutingInstanceSchemaAndCompilerAgree9323 — before #9323 they had
// already drifted, the schema declaring 4 of the compiler's 8.

// routingInstanceChildTokens9323 returns the keywords the
// `routing-instances <name>` wildcard declares, sorted, for use in the gate and
// in its message.
func routingInstanceChildTokens9323() []string {
	ri := setSchema.children["routing-instances"]
	if ri == nil || ri.wildcard == nil {
		return nil
	}
	out := make([]string, 0, len(ri.wildcard.children))
	for k := range ri.wildcard.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateRoutingInstanceChildTokensAST rejects a keyword directly under
// `routing-instances <name>` that the schema does not declare.
//
// Strict (commit / commit-check) hard-rejects. Lenient (Store.Load /
// Store.SyncApply) warns, so a config an older binary persisted, or a peer
// sends, still BOOTS (#1960 no-brick doctrine) — the same split #9017 uses.
//
// It runs on the AST rather than on the typed config for the reason the defect
// exists at all: an unknown subtree compiles to NOTHING, so by the time
// cfg.RoutingInstances exists there is no trace of it left to validate.
func validateRoutingInstanceChildTokensAST(nodes []*Node, lenient bool) ([]string, error) {
	declared := routingInstanceChildTokens9323()
	if len(declared) == 0 {
		// The schema could not be read. Refusing every routing instance here
		// would turn a lookup failure into a total outage, so decline to judge.
		return nil, nil
	}
	permitted := make(map[string]bool, len(declared))
	for _, tok := range declared {
		permitted[tok] = true
	}

	var warnings []string
	for _, riNode := range nodes {
		if riNode == nil || riNode.Name() != "routing-instances" {
			continue
		}
		for _, inst := range riNode.Children {
			if inst == nil || inst.Name() == "" {
				continue
			}
			instName := inst.Name()
			// A meta statement at the `routing-instances` level is a SIBLING of
			// the instance names, not an instance. Measured: #7029's
			// `routing-instances { apply-macro M { k v; } RI { … } }` reached
			// this loop as an "instance" called apply-macro whose child `M` was
			// then judged an unknown keyword — a hard reject of a config Junos
			// permits at any hierarchy point.
			if isApplyStatementNode(inst) {
				// #9657: the node is read as the statement, never as an instance,
				// quoted or not, which is what the compiler and the collision scan
				// do too. A one-key stanza under the keyword's name may be an
				// instance the operator wrote there, and a routing-instance keyword
				// among its children suggests it. It is WARNED, not refused: the shape
				// cannot prove that an instance was meant. The two-key form
				// (`apply-macro M { ... }`) is always the statement and is not warned.
				// Since #9685 a flat `set routing-instances apply-macro interface k v`
				// builds that two-key form too (the name stays on the statement's
				// keys), so only a braced one-key stanza reaches this warning.
				if len(inst.Keys) == 1 {
					for _, ch := range inst.Children {
						if ch == nil || !permitted[ch.Name()] {
							continue
						}
						warnings = append(warnings, fmt.Sprintf("routing-instances: %q is a statement keyword and "+
							"cannot name a routing instance; the stanza is read as that statement, so if %q under it "+
							"was meant as a routing-instance setting, no instance is created — rename the instance (#9657)",
							instName, ch.Name()))
						break
					}
				}
				continue
			}
			for _, tok := range routingInstanceChildTokensOf9323(inst) {
				// …and the same three inside an instance body, for the same
				// reason: `apply-groups-except` and `apply-macro` SURVIVE group
				// expansion as live nodes (ExpandGroups removes only
				// `apply-groups`), so they reach this gate verbatim.
				if routingInstanceApplyMetaKeyword9323(tok) {
					continue
				}
				if permitted[tok] {
					continue
				}
				msg := fmt.Sprintf("routing-instances %s: %q is not a routing-instance "+
					"keyword (known: %s) — the subtree under it compiles to NOTHING: it "+
					"commits clean, renders in `show configuration`, and takes effect "+
					"nowhere. There is no supported way to scope NAT or a firewall "+
					"filter to a routing instance; configure it globally instead (#9323)",
					instName, tok, strings.Join(declared, ", "))
				if lenient {
					warnings = append(warnings, msg)
					continue
				}
				return warnings, fmt.Errorf("%s", msg)
			}
		}
	}
	return warnings, nil
}

// routingInstanceChildTokensOf9323 returns the property keywords one instance
// node carries, across ALL THREE spellings that reach this gate.
//
// MEASURED, because the first version of this function was WRONG in the
// false-reject direction — it rejected two entirely valid configs, which is a
// worse defect than the one #9323 fixes:
//
//	flat set   `set routing-instances VRF-A security nat …`
//	           [VRF-A] > [security nat nat64 rule-set rs1 prefix …]
//	           Keys = [VRF-A]; the keyword is the CHILD's name.
//
//	braced     `VRF-A { security { … } }`
//	           [VRF-A] > [security] > [nat] > …
//	           Keys = [VRF-A]; the keyword is the CHILD's name.
//
//	brace-      `VRF-A security { … }`
//	elided     [VRF-A security] > [nat] > …
//	           Keys = [VRF-A, security]; the keyword is on the KEYS TAIL and the
//	           CHILDREN ARE THAT KEYWORD'S BODY.
//
// Reading Children in the third shape judges the BODY of a legitimate keyword
// as if it were an instance property. Measured before the fix:
//
//	VRF-A routing-options { static { route 0.0.0.0/0 next-hop 10.0.0.1; } }
//	  -> REJECTED: "static" is not a routing-instance keyword
//	VRF-A protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0; } } }
//	  -> REJECTED: "ospf" is not a routing-instance keyword
//
// Both are valid configuration. This is #9055's lesson, which the COMPILER
// already learned at the sibling site ("an elided BODY-BEARING keyword puts its
// NAME on the Keys tail and its BODY in Children, so the property loop sees the
// body's contents instead of the keyword") — and which this gate had to learn
// separately because it splits the node itself.
//
// So the two sources are EXCLUSIVE, not additive: a node whose Keys carry a
// tail is a packed/elided instance keyword and its Children belong to that
// keyword; only a bare `[<name>]` node has Children that are the instance's own
// properties.
func routingInstanceChildTokensOf9323(inst *Node) []string {
	// Packed or brace-elided: `[VRF-A security]`, `[VRF-A instance-type vrf]`.
	// The instance keyword is the first tail token. Children, if any, are that
	// keyword's BODY and are NOT instance properties.
	if len(inst.Keys) >= 2 {
		return []string{inst.Keys[1]}
	}
	// Bare `[VRF-A]`: every child's own name is an instance property keyword.
	// Covers both the flat-set chain and the ordinary braced block.
	var out []string
	for _, ch := range inst.Children {
		if ch != nil && ch.Name() != "" {
			out = append(out, ch.Name())
		}
	}
	return out
}

// routingInstanceApplyMetaKeyword9323 reports whether tok is one of the three
// Junos meta statements that may appear at ANY hierarchy point and never denote
// content (#7029).
//
// Same three keywords, and the same reason, as zoneInterfaceApplyMetaKeyword in
// compiler_security_zones.go: `apply-groups-except` and `apply-macro` survive
// group expansion as live nodes, so they reach a gate verbatim, and
// `apply-groups` is listed too so the set does not depend on expansion having
// run — which the tolerant display paths do not guarantee.
func routingInstanceApplyMetaKeyword9323(tok string) bool {
	switch tok {
	case "apply-groups", "apply-groups-except", "apply-macro":
		return true
	}
	return false
}
