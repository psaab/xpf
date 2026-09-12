package config

import "testing"

// TestFlatRunResidueSchemasResolve9792 pins every #9792 resolver non-nil and
// carrying the leaves its register row names. A resolver that returned nil
// would make expandRun9235 a no-op and silently turn the fix off at that site.
func TestFlatRunResidueSchemasResolve9792(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  *schemaNode
		want []string
	}{
		{"screen tcp syn-flood", synFloodSchema9792(), []string{"alarm-threshold", "attack-threshold"}},
		{"screen limit-session", limitSessionSchema9792(), []string{"destination-ip-based", "source-ip-based"}},
		{"security-zone", securityZoneSchema9792(), []string{"description", "screen"}},
		{"global policy", policySchema9792(true), []string{"description", "scheduler-name"}},
		{"from-zone policy", policySchema9792(false), []string{"description", "scheduler-name"}},
		{"nat64 rule-set", nat64RuleSetSchema9792(), []string{"prefix", "source-pool"}},
		{"dynamic-address feed-server", feedServerSchema9792(), []string{"hostname", "hold-interval"}},
		{"flow traceoptions packet-filter", packetFilterSchema9792(), []string{"destination-prefix", "protocol"}},
		{"bridge-domain", bridgeDomainSchema9792(), []string{"domain-type", "routing-interface"}},
		{"class-of-service interface", cosInterfaceSchema9792(), []string{"output-traffic-control-profile", "priority-low-min-share"}},
		{"sampling inet flow-server", samplingFlowServerSchema9792(), []string{"port", "source-address"}},
		{"sampling inet6 flow-server", resolveSchemaPath9235("forwarding-options", "sampling", "instance", "family", "inet6", "output", "flow-server"), []string{"port", "source-address"}},
		{"interface", interfaceSchema9792(), []string{"bandwidth", "description"}},
		{"gigether-options", gigetherOptionsSchema9792(), []string{"802.3ad", "redundant-parent"}},
		{"aggregated-ether-options", aggregatedEtherOptionsSchema9792(), []string{"link-speed", "minimum-links"}},
		{"tunnel wireguard", tunnelWireguardSchema9792(), []string{"listen-port", "private-key"}},
		{"tunnel wireguard peer", tunnelWireguardPeerSchema9792(), []string{"endpoint", "persistent-keepalive"}},
		{"bgp neighbor", bgpNeighborSchema9792(), []string{"authentication-key", "description"}},
		{"routing-instances bgp neighbor", resolveSchemaPath9235("routing-instances", "xpfname", "protocols", "bgp", "group", "neighbor"), []string{"authentication-key", "description"}},
		{"routing-instance", routingInstanceSchema9792(), []string{"description", "instance-type"}},
		{"preferred-route route", preferredRouteSchema9792(false), []string{"next-hop", "preferred-metric"}},
		{"preferred-route routing-instance route", preferredRouteSchema9792(true), []string{"next-hop", "preferred-metric"}},
		{"system", systemSchema9792(), []string{"dataplane-type", "domain-name"}},
		{"ntp server", ntpServerSchema9792(), []string{"key", "routing-instance"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got == nil {
				t.Fatalf("#9792: the resolver returned nil, which makes expandRun9235 a no-op and turns the %s fix off silently", tc.name)
			}
			// A DECLARED child, not resolveSchemaChild: a wildcard container
			// answers every keyword with its instance body, so the lookup would
			// pass for a resolver that stopped one level too high.
			for _, w := range tc.want {
				if tc.got.children[w] == nil {
					t.Errorf("#9792: %s schema does not declare %q", tc.name, w)
				}
			}
		})
	}
}

// TestPackedOrNestedLeafRunGuard9792 drives the guard every #9792 site expands
// through. Each row is a shape that must stay exactly as authored. Each was a
// measured regression of an unguarded expansion, or is its counterpart that
// must still expand.
func TestPackedOrNestedLeafRunGuard9792(t *testing.T) {
	leaf := func(keys ...string) *Node { return &Node{Keys: keys} }
	with := func(n *Node, kids ...*Node) *Node { n.Children = kids; return n }
	for _, tc := range []struct {
		name      string
		node      *Node
		container *schemaNode
		want      bool
	}{
		{"opaque block with no value (system processes { utmd disable; })",
			with(leaf("processes"), leaf("utmd", "disable")), systemSchema9792(), false},
		{"value-bearing leaf with a declared nested tail",
			with(leaf("source-ip-based", "100"), leaf("destination-ip-based", "200")), limitSessionSchema9792(), true},
		{"value-bearing leaf with an UNKNOWN nested tail (#3332 / #8321 diagnostics)",
			with(leaf("source-ip-based", "100"), leaf("extra")), limitSessionSchema9792(), false},
		{"packed statements on one node's Keys",
			leaf("source-ip-based", "100", "destination-ip-based", "200"), limitSessionSchema9792(), true},
		{"packed tail that is not a declared leaf (values, not statements)",
			leaf("source-ip-based", "100", "extra"), limitSessionSchema9792(), false},
		{"a container head (routing-instance protocols subtree)",
			with(leaf("protocols"), with(leaf("bgp"), leaf("description", "d"))), routingInstanceSchema9792(), false},
		{"a declared tail whose own descendant is undeclared",
			with(leaf("description", "d"), with(leaf("instance-type", "virtual-router"), leaf("bogus", "x"))), routingInstanceSchema9792(), false},
		{"a declared tail chain two statements deep",
			with(leaf("description", "d"), with(leaf("instance-type", "virtual-router"), leaf("route-distinguisher", "65000:1"))), routingInstanceSchema9792(), true},
		// Each real-schema row above that rejects a head shape is ALSO rejected by
		// a later check (a valueless real head is a container too; a real
		// container head has an undeclared tail), so deleting either shape arm
		// changed no verdict and both mutations survived. guardSchema9792 gives
		// each shape a DECLARED tail, so only the shape arm can reject it.
		{"a valueless FLAG head with a declared nested tail",
			with(leaf("flag"), leaf("leaf", "v")), guardSchema9792(), false},
		{"a value-bearing CONTAINER head with a declared nested tail",
			with(leaf("box", "name"), leaf("leaf", "v")), guardSchema9792(), false},
		{"a value-bearing WILDCARD head with a declared nested tail",
			with(leaf("named", "n1"), leaf("leaf", "v")), guardSchema9792(), false},
		{"a MULTI head packed with a declared leaf token",
			leaf("list", "a", "leaf", "v"), guardSchema9792(), false},
		{"POSITIVE CONTROL: a plain value leaf head with the same declared tail",
			with(leaf("leaf", "v"), leaf("flag")), guardSchema9792(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.container == nil {
				t.Fatal("PREMISE: the container resolved to nil")
			}
			if got := packedOrNestedLeafRun9792(tc.node, tc.container); got != tc.want {
				t.Errorf("packedOrNestedLeafRun9792 = %v, want %v", got, tc.want)
			}
		})
	}
}

// guardSchema9792 is a synthetic container with one head of each shape
// packedOrNestedLeafRun9792 distinguishes, plus a value leaf and a flag that
// any tail can name as a declared statement.
func guardSchema9792() *schemaNode {
	return &schemaNode{children: map[string]*schemaNode{
		"leaf":  {args: 1},
		"flag":  {},
		"box":   {args: 1, children: map[string]*schemaNode{"x": {}}},
		"named": {wildcard: &schemaNode{}},
		"list":  {multi: true},
	}}
}
