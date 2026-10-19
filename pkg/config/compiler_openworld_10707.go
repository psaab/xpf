package config

import (
	"fmt"
	"strings"
)

// routingKnobWarning11314 replaces generic open-world advisories with specific
// diagnostics for Junos routing knobs that the compiler accepts but does not
// apply.
func routingKnobWarning11314(path []string, keyword string) string {
	if keyword == "rib-group" && len(path) >= 3 &&
		path[len(path)-3] == "static" && path[len(path)-2] == "route" {
		hasRoutingOptions := false
		for _, part := range path {
			if part == "routing-options" {
				hasRoutingOptions = true
				break
			}
		}
		if hasRoutingOptions {
			return fmt.Sprintf(
				"%s rib-group is ACCEPTED but NOT APPLIED: xpf only installs this static "+
					"route in its enclosing routing table; static-route rib-group route "+
					"sharing is not implemented (#11314)",
				strings.Join(path, " "))
		}
	}
	if len(path) == 3 && path[0] == "routing-instances" && path[2] == "routing-options" {
		switch keyword {
		case "rib-groups":
			return fmt.Sprintf(
				"routing-instance %q routing-options rib-groups is ACCEPTED but NOT APPLIED: "+
					"per-instance RIB-group definitions are retained in the compiled instance "+
					"but are not consumed by the route-sharing runtime; define route-sharing "+
					"groups globally under routing-options (#11314)",
				path[1])
		case "generate":
			return fmt.Sprintf(
				"routing-instance %q routing-options generate is ACCEPTED but NOT APPLIED: "+
					"per-instance generated routes are retained in the compiled instance but are "+
					"not applied to its forwarding configuration; configure generated routes "+
					"globally under routing-options (#11314)",
				path[1])
		case "forwarding-table":
			return fmt.Sprintf(
				"routing-instance %q routing-options forwarding-table is ACCEPTED but NOT APPLIED: "+
					"the export policy is retained in compiled instance state, but ECMP policy "+
					"selection reads only global routing-options forwarding-table export (#11782)",
				path[1])
		}
	}
	return ""
}

// warnUnknownRoutingLeaves10707 reports unmodeled child keywords in the
// protocols, policy-options, and routing-options grammars. Those schemas stay
// open-world because several have valid but not-yet-modeled Junos children;
// warning preserves those configurations while making possible silent drops
// visible on both strict commit and tolerant load/sync paths.
func warnUnknownRoutingLeaves10707(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var warnings []string
	var seen map[string]struct{}
	appendWarning := func(message string) {
		if seen != nil {
			if _, ok := seen[message]; ok {
				return
			}
		} else {
			seen = make(map[string]struct{})
		}
		seen[message] = struct{}{}
		warnings = append(warnings, message)
	}
	warn := func(path []string, keyword string) {
		if message := routingKnobWarning11314(path, keyword); message != "" {
			appendWarning(message)
			return
		}
		appendWarning(fmt.Sprintf("%s: unmodeled configuration keyword %q is accepted by the open-world schema and may be silently ignored (#10707)",
			strings.Join(path, " "), keyword))
	}
	var walkChildren func(nodes []*Node, parent *schemaNode, path []string)
	var walkInstances func(nodes []*Node, container *schemaNode, remaining int, path []string)
	walkChildren = func(nodes []*Node, parent *schemaNode, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			keyword := node.Keys[0]
			// Apply statements are permitted at any hierarchy level
			// (#7029/#9685) and are not config keywords to warn on.
			if isApplyStatementKeyword(keyword) {
				continue
			}
			// #15199 interfaces walk: vrrp-group children are owned by
			// the #15046 closed gate (strict reject / lenient warn);
			// descending here would double-report unknown children.
			if len(path) > 0 && path[0] == "interfaces" &&
				(keyword == "vrrp-group" || keyword == "vrrp-inet6-group") {
				continue
			}
			// #15199: filter/simple-filter under interfaces are owned by
			// the #12090/#10293 strict gates (single diagnostic contract,
			// #12656); the generic advisory must not double-report them.
			if len(path) > 0 && path[0] == "interfaces" &&
				(keyword == "filter" || keyword == "simple-filter") {
				continue
			}
			// BGP SAFI diagnostics belong to the compiler gate, not this
			// child walker: a hierarchical one-liner can carry the SAFI in
			// node.Keys without a child keyword to visit.
			if isBGPSAFIWarningOwned11815(path, keyword) {
				continue
			}
			if message := routingKnobWarning11314(path, keyword); message != "" {
				appendWarning(message)
				continue
			}
			childSchema := resolveSchemaChild(parent, keyword)
			if childSchema == nil {
				warn(path, keyword)
				continue
			}
			// A leaf with no declared children or wildcard may carry a value
			// list or an opaque compiler-owned body. Its children are not
			// schema keywords.
			if (childSchema.children == nil && childSchema.wildcard == nil) || childSchema.closedWorldOpaque {
				continue
			}
			consumed, descend := consumeNodeKeys(node.Keys, childSchema)
			pathLen := len(path)
			path = append(path, node.Keys[:consumed]...)
			// #14412: a packed node has no Children for this walk to visit,
			// so a credential token packed past the identity (misplaced or
			// case-variant) was invisible here exactly as it was to the
			// schema walker. Warn on it by the same predicate the strict
			// gate uses; validly placed packed credentials resolve as
			// children of descend and stay silent.
			if !childSchema.packedTail {
				if tok, _ := packedTailCredential14412(node, descend, consumed); tok != "" {
					warn(path, tok)
				}
			}
			// #15778: a packed node (compact/elided one-liner) carries
			// further statements on its Keys tail with no Children for
			// the walk above to visit, so an unknown tail keyword
			// (metric, resolve, bfd-liveness-detection on a static
			// route, or any bogus token) escaped the #10707 warning
			// its braced twin draws. Walk the tail through the same
			// schema resolution, warning only on the first token that
			// leaves the modelled grammar; tokens before it that
			// resolve (with their declared values) are consumed, and
			// quoted/bracketed tokens are authored values (#9635).
			if !childSchema.packedTail {
				if childSchema.multi || childSchema.valueList {
					// A multi/valueList leaf (static next-hop) packs
					// further PARENT statements past its values
					// (next-hop 10.0.0.1 no-install); judge from
					// its head under the parent grammar so the
					// helper's multi absorption can tell values
					// from sibling heads.
					warnPackedTail15778(node, parent, 0, path, warn)
				} else {
					warnPackedTail15778(node, descend, consumed, path, warn)
				}
			}
			remaining := 1 + childSchema.args - consumed
			if remaining > 0 {
				walkInstances(node.Children, childSchema, remaining, path)
				path = path[:pathLen]
				continue
			}
			walkChildren(node.Children, descend, path)
			path = path[:pathLen]
		}
	}
	walkInstances = func(nodes []*Node, container *schemaNode, remaining int, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			consumed := remaining
			if consumed > len(node.Keys) {
				consumed = len(node.Keys)
			}
			pathLen := len(path)
			path = append(path, node.Keys[:consumed]...)
			if stillMissing := remaining - consumed; stillMissing > 0 {
				walkInstances(node.Children, container, stillMissing, path)
				path = path[:pathLen]
				continue
			}
			walkChildren(node.Children, container, path)
			path = path[:pathLen]
		}
	}

	for _, node := range tree.Children {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		switch node.Keys[0] {
		case "protocols":
			walkChildren(node.Children, schemaProtocols, []string{"protocols"})
			// #15778: a fully packed root (protocols ospf …) carries
			// its statements on the root Keys tail.
			if len(node.Keys) > 1 {
				if tok := firstUnknownPackedKeyword15778(node, schemaProtocols, 1); tok != "" {
					warn([]string{"protocols"}, tok)
				}
			}
		case "policy-options":
			walkChildren(node.Children, schemaPolicyOptions, []string{"policy-options"})
			if len(node.Keys) > 1 {
				if tok := firstUnknownPackedKeyword15778(node, schemaPolicyOptions, 1); tok != "" {
					warn([]string{"policy-options"}, tok)
				}
			}
		case "routing-options":
			walkChildren(node.Children, schemaRoutingOptions, []string{"routing-options"})
			if len(node.Keys) > 1 {
				if tok := firstUnknownPackedKeyword15778(node, schemaRoutingOptions, 1); tok != "" {
					warn([]string{"routing-options"}, tok)
				}
			}
		case "routing-instances":
			for _, instance := range namedInstances([]*Node{node}) {
				instancePath := []string{"routing-instances", instance.name}
				for _, property := range routingInstancePropertyNodes9323(instance.node) {
					if property == nil {
						continue
					}
					pathLen := len(instancePath)
					instancePath = append(instancePath, property.Name())
					switch property.Name() {
					case "protocols":
						walkChildren(property.Children, schemaRoutingInstanceProtocols, instancePath)
					case "routing-options":
						instanceRO := schemaRoutingInstances.wildcard.children["routing-options"]
						walkChildren(property.Children, instanceRO, instancePath)
						// #15778: elided routing-options carries its
						// statements on the property Keys tail, not in
						// Children. instance-import/export there is
						// owned by the #11314 RI gate (strict reject),
						// so skip those; warn on the first other
						// unmodelled tail keyword as #10707.
						if len(property.Keys) > 1 {
							if tok := firstUnknownPackedKeyword15778(property, instanceRO, 1); tok != "" &&
								tok != "instance-import" && tok != "instance-export" {
								warn(instancePath, tok)
							}
						}
					}
					instancePath = instancePath[:pathLen]
				}
			}
		case "interfaces":
			// #15199 (A05-06): extend the #10707 open-world advisory to
			// the interfaces subtree. Unknown interface/unit/family
			// keywords (ether-options, family bridge, filtr, arbitrary
			// tokens) previously committed with zero warnings and
			// compiled to nothing — including the fail-open
			// `family inet filtr input f1` shape, which left the unit
			// unfiltered. Warn-only on both paths, like the routing
			// grammars above: the schema stays open-world, but the
			// silent drop becomes visible.
			walkChildren(node.Children, schemaInterfaces, []string{"interfaces"})
		}
	}
	return warnings
}

// firstUnknownPackedKeyword15778 walks the packed tail of node starting
// at Keys[from] through descend's grammar and returns the first token
// that does not resolve as a child keyword there, or "" if the whole
// tail resolves (or is authored values). Resolution mirrors the braced
// walk: a resolving child consumes 1+args keys (plus a compoundKey
// sub-token); a leaf with no children/wildcard owns the rest of the
// tail as values/body and ends the scan silently; a wildcard child
// consumes its name slot plus args without judging the name. Quoted
// or bracketed tokens are authored values (#9635), never heads. Only
// the first unknown token is reported: everything after it is that
// unknown statement's own tail, exactly as the braced walk reports a
// child once and does not descend into it.
// firstUnknownPackedKeyword15778 returns the first packed-tail token at
// or after Keys[from] that does not resolve as a statement head under
// descend, or "" if the tail resolves or cannot be judged safely.
// Keys[from] MUST be a statement head under descend (callers arrange
// this: walkChildren passes the first token past the node's own
// 1+args identity together with the node's parent grammar — see
// warnPackedTail15778 — and the root/RI callers pass Keys[1] with the
// root grammar). A resolving child consumes its 1+args span; a leaf
// with no children/wildcard owns the rest as values; a multi/valueList
// leaf absorbs values until a sibling head or its own modifier child
// appears. Quoted/bracketed tokens are authored values (#9635).
func firstUnknownPackedKeyword15778(node *Node, descend *schemaNode, from int) string {
	if node == nil || descend == nil || from >= len(node.Keys) {
		return ""
	}
	mask := authoredValueMask9635(node.KeysQuoted, node.KeysBracketed, len(node.Keys))
	cur := descend
	i := from
	for i < len(node.Keys) {
		if cur == nil || (cur.children == nil && cur.wildcard == nil) || cur.packedTail || cur.closedWorldOpaque {
			return ""
		}
		tok := node.Keys[i]
		if mask != nil && mask[i] {
			i++
			continue
		}
		if isApplyStatementKeyword(tok) {
			return ""
		}
		child := resolveSchemaChild(cur, tok)
		if child == nil {
			return tok
		}
		if child.multi || child.valueList {
			consumed, _ := consumeNodeKeys(node.Keys[i:], child)
			j := i + consumed
			// A bracketed value run ([ 10.0.0.1 10.0.0.2 ]) is
			// marked by BracketedClosed on the node; its values
			// are absorbed wholesale. Otherwise the first token
			// after the declared value that names a sibling head
			// (next-hop 10.0.0.1 no-install) resumes statement
			// walking there instead of being absorbed as a value.
			if node.BracketedClosed {
				return ""
			}
			resumed := false
			for j < len(node.Keys) {
				if mask != nil && mask[j] {
					j++
					continue
				}
				t := node.Keys[j]
				if mod, isMod := child.children[t]; isMod {
					j += 1 + mod.args
					continue
				}
				if sib := resolveSchemaChild(cur, t); sib != nil {
					i = j
					resumed = true
					break
				}
				// First non-sibling, non-modifier token after the
				// declared span is another absorbed value only
				// when a later sibling exists; handled by the loop.
				j++
			}
			if !resumed {
				return ""
			}
			continue
		}
		consumed, next := consumeNodeKeys(node.Keys[i:], child)
		i += consumed
		cur = next
	}
	return ""
}

// warnPackedTail15778 warns (#10707 via warn) on the first unmodelled
// keyword in node's packed tail. descend is the PARENT grammar the
// node's head was resolved under, and consumed is the node's own
// 1+args span, so Keys[consumed] is the first tail statement head.
// Nested instance-import/export under a routing-instance
// routing-options is owned by the #11314 strict RI gate, so it is not
// double-reported here.
func warnPackedTail15778(node *Node, descend *schemaNode, consumed int, path []string, warn func([]string, string)) {
	tok := firstUnknownPackedKeyword15778(node, descend, consumed)
	if tok == "" {
		return
	}
	// Credential tokens are owned by the #14412 packed-tail check,
	// which runs alongside this one in walkChildren.
	if isPackedTailCredentialToken14412(tok) {
		return
	}
	if (tok == "instance-import" || tok == "instance-export") &&
		len(path) == 3 && path[0] == "routing-instances" && path[2] == "routing-options" {
		return
	}
	if len(path) > 0 && path[0] == "interfaces" &&
		(tok == "filter" || tok == "simple-filter" || tok == "vrrp-group" || tok == "vrrp-inet6-group") {
		return
	}
	// An unknown family value under interfaces (family foo …) is
	// owned by the #12090/#12656 family gates, not this advisory.
	if len(path) >= 2 && path[0] == "interfaces" && path[len(path)-1] == "family" {
		return
	}
	warn(path, tok)
}
