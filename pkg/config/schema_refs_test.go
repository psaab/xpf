package config

import (
	"sort"
	"strings"
	"testing"
)

// TestSchemaRefsResolve is deliverable #1 of #16147 (R3): the
// non-panicking audit, landed FIRST in sequence. It enumerates every
// registered static SchemaRef plus every literal path prefix walked by
// an arg-taking resolver, and lists EVERY dead outcome in one run —
// the property an init panic alone cannot give (a panic aborts ~45
// importing packages and surfaces one bad ref per run).
//
// A failure here names a dead schema path. Per the validated narrowed
// form, a dead path surfaced by this audit is a silent-drop BUG to
// file separately (the resolver returning nil silently disables the
// packed-body expansion at its site), not refactor fallout to fix
// inside the SchemaRef conversion.
//
// The want table pins, for representative refs, a child the resolved
// node must declare directly — distinguishing "resolved" from
// "resolved to the WRONG node", which a non-nil check alone misses
// (the #9235/#9792 instrument-control pattern). A seeded bad ref turns
// this test red: TestSchemaRefsAuditDetectsSeededBadRef16147 proves
// the audit is not vacuous, and the same seeded registry turns the
// init validation red via validateSchemaRefs.
func TestSchemaRefsResolve(t *testing.T) {
	if problems := auditSchemaRefs(); len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("#16147: %d unresolved SchemaRef(s) — each is a site where a packed body would be silently dropped:\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	if len(staticSchemaRefs) < 80 {
		t.Fatalf("#16147: only %d SchemaRefs registered; the registry must cover the converted resolver population", len(staticSchemaRefs))
	}

	// Representative wrong-node pins: direct declared child, not
	// resolveSchemaChild (a wildcard container answers every keyword).
	for _, tc := range []struct {
		name string
		r    schemaRef
		want string
	}{
		{"bgp", refBGP, "group"},
		{"bgp group instance", refBGPGroup, "neighbor"},
		{"bgp multipath", refBGPMultipath, "multiple-as"},
		{"isis interface instance", refISISInterface, "metric"},
		{"ospf", refOSPF, "area"},
		{"ra interface instance", refRAInterface, "prefix"},
		{"policy term then", refPolicyTermThen, "accept"},
		{"policy statement instance then", refPolicyStatementInstanceThen, "accept"},
		{"filter then (inet)", refFilterThen, "discard"},
		{"security flow", refSecurityFlow, "tcp-session"},
		{"flow tcp-session", refFlowTCPSession, "closing-timeout"},
		{"security log profile", refSecurityLogProfile, "stream-name"},
		{"screen ids-option", refScreenIdsOption, "icmp"},
		{"nat destination rule", refNATDestRule, "match"},
		{"nat source pool instance", refNATSourcePoolInstance, "address"},
		{"ipsec vpn instance", refIPsecVPNInstance, "gateway"},
		{"ipsec traffic-selector instance", refIPsecTrafficSelector, "local-ip"},
		{"syslog host", refSyslogHost, "facility-override"},
		{"system services ssh", refSystemServicesSSH, "root-login"},
		{"login user instance", refLoginUserInstance, "class"},
		{"login class instance", refLoginClassInstance, "permissions"},
		{"scheduler daily", refSchedulerDaily, "start-time"},
		{"snmp v3 usm user", refSNMPv3USMUser, "authentication-md5"},
		{"rpm probe test instance", refRPMProbeTest, "target"},
		{"rpm thresholds", refRPMThresholds, "successive-loss"},
		{"tunnel", refTunnel, "source"},
		{"interface unit", refInterfaceUnit, "family"},
		{"cos scheduler-maps forwarding-class", refCoSSchedulerMapsFC, "scheduler"},
		{"dhcp-relay overrides", refDHCPrelayOverrides, "forward-only"},
		{"sampling output", refSamplingOutput, "flow-server"},
		{"chassis cluster", refChassisCluster, "reth-count"},
		{"generate route instance", refGenerateRoute, "policy"},
		{"rib-groups instance", refRibGroupsInstance, "import-rib"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.r.resolve()
			if got == nil {
				t.Fatalf("#16147: SchemaRef %s (%s) resolved to nil", tc.name, tc.r.String())
			}
			if got.children[tc.want] == nil {
				var have []string
				for k := range got.children {
					have = append(have, k)
				}
				sort.Strings(have)
				t.Errorf("#16147: SchemaRef %s resolved to a node that does not declare %q (declares %v) — wrong node, not no node",
					tc.name, tc.want, have)
			}
		})
	}

	// Pointer-identity pins: refs that must land on the SAME node as
	// the walk they replaced (equality is load-bearing at e.g.
	// policy_term_packed_12537.go, which compares a leaf schema against
	// the term schema by pointer).
	if refPolicyTerm.resolve() != schemaForPath("policy-options", "policy-statement", "term") {
		t.Errorf("#16147: refPolicyTerm is not pointer-identical to the schemaForPath walk it replaces")
	}
	if refInterfaceUnit.resolve() == nil || refInterfaceUnit.resolve() != schemaForPath("interfaces", "xpfname", "unit") {
		t.Errorf("#16147: refInterfaceUnit (interfaces x unit) must resolve to the same node as the xpfname spelling via the wildcard")
	}
	if got := refSystem.resolve(); got == nil || got != setSchema.children["system"] {
		t.Errorf("#16147: refSystem must be the top-level system node")
	}
	// Groups-wildcard ordering: the groups wildcard mirrors the
	// top-level children after init; a ref resolved post-init through
	// the top level must be the same node the groups subtree sees.
	groups := setSchema.children["groups"]
	if groups == nil || groups.wildcard == nil {
		t.Fatalf("#16147: groups wildcard not wired at test time (init ordering broken)")
	}
	if groups.wildcard.children["security"] == nil || refSecurityFlow.resolve() == nil {
		t.Errorf("#16147: groups wildcard does not mirror security after init")
	}
	if groups.wildcard.children["system"] != refSystem.resolve() {
		t.Errorf("#16147: groups-wildcard system node differs from refSystem — ref captured a pre-init tree")
	}
}

// TestSchemaRefsAuditDetectsSeededBadRef16147 is the seeded-bad-ref
// control: it registers a deliberately dead ref (and a deliberately
// dead arg-resolver prefix is already covered by the same audit loop),
// proves auditSchemaRefs names it, and proves validateSchemaRefs —
// the init-panic body — panics naming it. Without this control the
// audit above could pass vacuously (e.g. resolve() returning a
// non-nil wrong node, or the registry silently emptying).
func TestSchemaRefsAuditDetectsSeededBadRef16147(t *testing.T) {
	const seeded = "refSeededBad16147"
	staticSchemaRefs[seeded] = ref("security", "no-such-container-16147")
	defer delete(staticSchemaRefs, seeded)

	problems := auditSchemaRefs()
	found := false
	for _, p := range problems {
		if strings.Contains(p, seeded) {
			found = true
		}
	}
	if !found {
		t.Fatalf("#16147: audit did not name the seeded bad ref; got %v", problems)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("#16147: validateSchemaRefs did not panic on the seeded bad ref")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, seeded) {
			t.Fatalf("#16147: validateSchemaRefs panic did not name the seeded ref: %v", r)
		}
	}()
	validateSchemaRefs()
}

// TestSchemaRefsArgResolversStayFunctions16147 pins the narrowed
// form's carve-out: arg-taking resolvers stay functions, and every
// value from their closed argument sets resolves non-nil through
// them. Converting any of these to a static var would be the
// unsound half of the original proposal.
func TestSchemaRefsArgResolversStayFunctions16147(t *testing.T) {
	for _, kind := range []string{"dscp", "ieee-802.1", "inet-precedence"} {
		if cosClassifiersSchema15064(kind) == nil {
			t.Errorf("#16147: cosClassifiersSchema15064(%q) resolved to nil", kind)
		}
	}
	for _, kind := range []string{"inet-precedence", "exp", "dscp", "ieee-802.1"} {
		if cosRewriteRulesSchema15064(kind) == nil {
			t.Errorf("#16147: cosRewriteRulesSchema15064(%q) resolved to nil", kind)
		}
	}
	for _, which := range []string{"classifiers", "rewrite-rules"} {
		if cosBindingSchema8939(which) == nil {
			t.Errorf("#16147: cosBindingSchema8939(%q) resolved to nil", which)
		}
	}
	for _, isV6 := range []bool{false, true} {
		if dhcpPoolSchema15691(isV6) == nil {
			t.Errorf("#16147: dhcpPoolSchema15691(%v) resolved to nil", isV6)
		}
	}
	for _, kind := range []string{"host", "file", "user"} {
		if syslogDestinationHoistSchema9414(kind) == nil {
			t.Errorf("#16147: syslogDestinationHoistSchema9414(%q) resolved to nil", kind)
		}
	}
	// syslogDestinationHoistSchema9414 copies the node and strips the
	// wildcard; the copy must not alias-mutate the shared schema.
	if h := syslogDestinationHoistSchema9414("host"); h != nil && h.wildcard != nil {
		t.Errorf("#16147: syslog hoist schema must carry no wildcard (copy semantics changed)")
	}
	for _, global := range []bool{true, false} {
		if policySchema9792(global) == nil {
			t.Errorf("#16147: policySchema9792(%v) resolved to nil", global)
		}
		if preferredRouteSchema9792(global) == nil {
			t.Errorf("#16147: preferredRouteSchema9792(%v) resolved to nil", global)
		}
	}
	// Node-dependent resolvers: branch is read off the parent node.
	ike := &Node{Keys: []string{"ike"}}
	ipsec := &Node{Keys: []string{"ipsec"}}
	for _, parent := range []*Node{ike, ipsec} {
		if gatewayLeafSchema8939(parent) == nil {
			t.Errorf("#16147: gatewayLeafSchema8939(%v) resolved to nil", parent.Keys)
		}
		for _, kind := range []string{"proposal", "policy"} {
			if securityNamedLeafSchema8939(parent, kind) == nil {
				t.Errorf("#16147: securityNamedLeafSchema8939(%v, %q) resolved to nil", parent.Keys, kind)
			}
		}
	}
	if gatewayLeafSchema8939(nil) != nil || gatewayLeafSchema8939(&Node{}) != nil {
		t.Errorf("#16147: gatewayLeafSchema8939 must stay nil for a parentless node (tolerant contract)")
	}
}
