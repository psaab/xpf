package config

// #9792 PART 2: the leaf-run gate's lenient-only register.
//
// #9156's gate lists containers whose one-line run compiles differently from
// the separate-lines oracle on the LENIENT path. Every row is lenient-only: the
// schema gate refuses the packed spelling at commit, and Store.Load (boot from
// the persisted DB) and Store.SyncApply (HA sync from the peer) still reach it.
// #9235 established that the reach is real (a tree written before a leaf was
// declared carries the packed spelling) and that the remedy is
// hoistAndSplitRun8939 at the container's compile-time reader, through
// expandRun9235 / expandRunChildren9235. This file resolves the containers for
// the rows #9792 fixes. Each fixed row leaves leafRunKnownDiffer9156 in the same
// change, because the gate's ratchet fails on a listed row that agrees.
//
// A nil resolver disables the expansion at its site without any behavioural
// cell necessarily noticing, so TestFlatRunResidueSchemasResolve9792 pins each
// one non-nil with the leaves its row names.
//
// A container whose instances are NAMED (`interfaces <if>`, `routing-instances
// <ri>`, `bridge-domains <bd>`) declares its body as a WILDCARD, so the walk
// passes a placeholder name ("xpfname") to step into that body. Without it the
// next keyword is consumed as the instance name: `("interfaces", "tunnel")`
// resolves the interface body and `wireguard` then resolves to nil.

func synFloodSchema9792() *schemaNode {
	return resolveSchemaPath9235("security", "screen", "ids-option", "tcp", "syn-flood")
}

func limitSessionSchema9792() *schemaNode {
	return resolveSchemaPath9235("security", "screen", "ids-option", "limit-session")
}

func securityZoneSchema9792() *schemaNode {
	return resolveSchemaPath9235("security", "zones", "security-zone")
}

// policySchema9792 resolves the policy body at either position compilePolicy
// serves.
func policySchema9792(global bool) *schemaNode {
	if global {
		return resolveSchemaPath9235("security", "policies", "global", "policy")
	}
	return resolveSchemaPath9235("security", "policies", "from-zone", "policy")
}

func nat64RuleSetSchema9792() *schemaNode {
	return resolveSchemaPath9235("security", "nat", "nat64", "rule-set")
}

func feedServerSchema9792() *schemaNode {
	return resolveSchemaPath9235("security", "dynamic-address", "feed-server")
}

func packetFilterSchema9792() *schemaNode {
	return resolveSchemaPath9235("security", "flow", "traceoptions", "packet-filter")
}

func bridgeDomainSchema9792() *schemaNode {
	return resolveSchemaPath9235("bridge-domains", "xpfname")
}

func cosInterfaceSchema9792() *schemaNode {
	return resolveSchemaPath9235("class-of-service", "interfaces")
}

// samplingFlowServerSchema9792 resolves the collector body. compileSamplingFamily
// serves both families, and the inet and inet6 bodies declare the same leaves
// (TestFlatRunResidueSchemasResolve9792 checks both), so one resolver drives the
// expansion for either.
func samplingFlowServerSchema9792() *schemaNode {
	return resolveSchemaPath9235("forwarding-options", "sampling", "instance", "family", "inet", "output", "flow-server")
}

func interfaceSchema9792() *schemaNode {
	return resolveSchemaPath9235("interfaces", "xpfname")
}

func gigetherOptionsSchema9792() *schemaNode {
	return resolveSchemaPath9235("interfaces", "xpfname", "gigether-options")
}

func aggregatedEtherOptionsSchema9792() *schemaNode {
	return resolveSchemaPath9235("interfaces", "xpfname", "aggregated-ether-options")
}

func tunnelWireguardSchema9792() *schemaNode {
	return resolveSchemaPath9235("interfaces", "xpfname", "tunnel", "wireguard")
}

func tunnelWireguardPeerSchema9792() *schemaNode {
	return resolveSchemaPath9235("interfaces", "xpfname", "tunnel", "wireguard", "peer")
}

// bgpNeighborSchema9792 resolves the neighbor body the #9192 merge reads for
// both the default instance and a routing instance (same declaration).
func bgpNeighborSchema9792() *schemaNode {
	return resolveSchemaPath9235("protocols", "bgp", "group", "neighbor")
}

func routingInstanceSchema9792() *schemaNode {
	return resolveSchemaPath9235("routing-instances", "xpfname")
}

// preferredRouteSchema9792 resolves the `route <cidr>` body of an ip-monitoring
// preferred-route, directly or under its routing-instance sub-block.
func preferredRouteSchema9792(inInstance bool) *schemaNode {
	if inInstance {
		return resolveSchemaPath9235("services", "ip-monitoring", "policy", "then", "preferred-route", "routing-instance", "route")
	}
	return resolveSchemaPath9235("services", "ip-monitoring", "policy", "then", "preferred-route", "route")
}

func systemSchema9792() *schemaNode {
	return resolveSchemaPath9235("system")
}

func ntpServerSchema9792() *schemaNode {
	return resolveSchemaPath9235("system", "ntp", "server")
}

// expandResolvingRuns9792 expands a child only when it is unambiguously a
// packed leaf run of `container`, and passes every other child through
// untouched. It is used at every #9792 site.
//
// hoistAndSplitRun8939 alone is too eager for these readers, and three
// failures measured that:
//   - A leaf whose schema declares no children, but which carries an AST body,
//     is taken for a nested run. Its body is then hoisted to the container,
//     including children that do not resolve there. `system processes { utmd
//     disable; }` lost its disabled process that way (TestSystemConfigSetSyntax).
//   - An unknown trailing token under a known leaf was hoisted beside it. That
//     changed #3332's "not a supported screen option" diagnostic and #8321's
//     single unknown-leaf record (`limit-session source-ip-based 100 extra`).
//   - A whole-body expansion reached into a deep subtree. The `description` at
//     the end of `protocols > bgp > group g > authentication-key k >
//     description d` was hoisted to the routing instance, adding two #9156 rows.
//     The #9234 bound missed it, because `authentication-key` does not declare
//     `description`.
//
// So a child expands only when both of these hold:
//   - its head is a DECLARED, value-bearing, single-valued leaf of the container;
//   - EVERY statement in its run is a declared leaf of the container: each
//     descendant's head in the nested (flat-set) shape, or the token at Keys[2]
//     in the packed (braced) shape.
//
// Anything else stays exactly as authored, for the reader's own diagnostics.
func expandResolvingRuns9792(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	out := make([]*Node, 0, len(children))
	for _, c := range children {
		if packedOrNestedLeafRun9792(c, container) {
			out = append(out, hoistAndSplitRun8939([]*Node{c}, container)...)
			continue
		}
		out = append(out, c)
	}
	return out
}

// expandResolvingRun9792 is expandResolvingRuns9792 for a caller that reads the
// node with FindChild: a shallow clone with the expanded children.
func expandResolvingRun9792(n *Node, container *schemaNode) *Node {
	if n == nil || container == nil || len(n.Children) == 0 {
		return n
	}
	clone := *n
	clone.Children = expandResolvingRuns9792(n.Children, container)
	return &clone
}

// packedOrNestedLeafRun9792 reports whether c is a leaf run of container that
// hoistAndSplitRun8939 may flatten without moving anything the container does
// not declare.
func packedOrNestedLeafRun9792(c *Node, container *schemaNode) bool {
	if c == nil || len(c.Keys) < 2 {
		return false // a run's head carries its value; `processes { ... }` does not
	}
	head := container.children[c.Keys[0]]
	if head == nil || len(head.children) > 0 || head.wildcard != nil || head.multi {
		return false
	}
	if len(c.Children) == 0 {
		// Packed on one node's Keys: the token after the head's value must
		// itself be a declared leaf, or these are values, not statements.
		return len(c.Keys) > 2 && container.children[c.Keys[2]] != nil
	}
	return allDescendantsDeclared9792(c, container)
}

func allDescendantsDeclared9792(n *Node, container *schemaNode) bool {
	for _, ch := range n.Children {
		if ch == nil || len(ch.Keys) == 0 || container.children[ch.Keys[0]] == nil {
			return false
		}
		if !allDescendantsDeclared9792(ch, container) {
			return false
		}
	}
	return true
}
