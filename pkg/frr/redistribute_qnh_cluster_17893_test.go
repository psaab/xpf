package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17893: QNH override maps attached an unfiltered daemon-agnostic
// policy tail, cluster IS-IS discarded its AF variant suffix, and a
// known-impossible family conjunction degraded to a bare deny.

func TestQNHMetricPolicyTailFilteredPerDaemon17893(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 192.168.50.0/24 qualified-next-hop 192.0.2.1 metric 42",
		"set policy-options prefix-list V4NETS 192.168.50.0/24",
		"set policy-options prefix-list V6NETS 2001:db8:50::/48",
		"set policy-options policy-statement V4-ONLY term v4 from protocol static",
		"set policy-options policy-statement V4-ONLY term v4 from prefix-list V4NETS",
		"set policy-options policy-statement V4-ONLY term v4 then accept",
		"set policy-options policy-statement V4-ONLY term v6 from protocol static",
		"set policy-options policy-statement V4-ONLY term v6 from prefix-list V6NETS",
		"set policy-options policy-statement V4-ONLY term v6 then accept",
		"set protocols ospf export V4-ONLY",
	)
	fc := &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
	got, _ := New().buildManagedSectionWithQNH11447(fc)
	set := buildQNHMetricSet11447(fc, fc.PolicyOptions)
	if set == nil || set.global == nil {
		t.Fatalf("no QNH scope:\n%s", got)
	}
	qnhBase := set.global.policyMaps["V4-ONLY"]
	ospfMap := qnhBase + "-ospf"
	if !strings.Contains(got, "redistribute static route-map "+ospfMap+"\n") {
		t.Errorf("OSPF must attach the daemon-filtered QNH map %q:\n%s", ospfMap, got)
	}
	ospf := strings.Join(redistSeqs16864(t, got, ospfMap), "\n")
	if !strings.Contains(ospf, "match ip address prefix-list V4NETS") || strings.Contains(ospf, "V6NETS") || strings.Contains(ospf, "match ipv6") {
		t.Errorf("QNH ospf tail must keep only v4 terms:\n%s", ospf)
	}
	mustNoEmptyPermit16864(t, got, ospfMap)

	// Positive control: BGP evaluates the full daemon-agnostic policy.
	bgp := renderRedistributeVariantMapCluster16864(New(), fc.PolicyOptions, "V4-ONLY", fc.PolicyOptions.PolicyStatements["V4-ONLY"], "static", redistVariantBGP16864, false)
	bgpSeqs := strings.Join(redistSeqs16864(t, bgp, "V4-ONLY-static-xpf-redist"), "\n")
	if !strings.Contains(bgpSeqs, "V4NETS") || !strings.Contains(bgpSeqs, "V6NETS") {
		t.Errorf("BGP control map must keep both families:\n%s", bgpSeqs)
	}
}

func TestISISClusterStaticPreservesAFVariant17893(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V4NETS": {Name: "V4NETS", Prefixes: []string{"192.168.50.0/24"}},
			"V6NETS": {Name: "V6NETS", Prefixes: []string{"2001:db8:50::/48"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"DUAL": {Name: "DUAL", Terms: []*config.PolicyTerm{
				{Name: "v4", FromProtocols: []string{"static"}, PrefixList: []string{"V4NETS"}, Action: "accept"},
				{Name: "v6", FromProtocols: []string{"static"}, PrefixList: []string{"V6NETS"}, Action: "accept"},
			}},
		},
	}
	m := New()
	entries := m.redistributeEntries("DUAL", po, "isis")
	for i := range entries {
		entries[i].clusterMode = true
	}
	got := isisRedistributeLines(entries, "level-2")
	if !strings.Contains(got, "redistribute ipv4 static level-2 route-map DUAL-static-xpf-redist-isis-v4\n") {
		t.Errorf("cluster IS-IS ipv4 line must name -isis-v4 variant:\n%s", got)
	}
	if strings.Contains(got, "redistribute ipv4 static level-2 route-map DUAL-static-xpf-redist\n") {
		t.Errorf("cluster IS-IS must not attach the unsuffixed map:\n%s", got)
	}

	// Non-cluster control keeps the same AF-specific attachment name.
	for i := range entries {
		entries[i].clusterMode = false
	}
	nonCluster := isisRedistributeLines(entries, "level-2")
	if !strings.Contains(nonCluster, "redistribute ipv4 static level-2 route-map DUAL-static-xpf-redist-isis-v4\n") {
		t.Errorf("non-cluster IS-IS AF control changed:\n%s", nonCluster)
	}
}

func TestOffFamilyCommunityRejectOmitted17893(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V6NETS": {Name: "V6NETS", Prefixes: []string{"2001:db8::/32"}},
		},
		Communities: map[string]*config.CommunityDef{"CUST": {Name: "CUST", Members: []string{"65000:100"}}},
	}
	ps := &config.PolicyStatement{Name: "MIX", Terms: []*config.PolicyTerm{
		{Name: "bad-route-filter", FromProtocols: []string{"bgp"}, RouteFilters: []*config.RouteFilter{{Prefix: "2001:db8::/32", MatchType: "exact"}}, FromCommunity: []string{"CUST"}, Action: "reject"},
		{Name: "bad-prefix-list", FromProtocols: []string{"bgp"}, PrefixList: []string{"V6NETS"}, FromCommunity: []string{"CUST"}, Action: "reject"},
		{Name: "good", FromProtocols: []string{"bgp"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.0.2.0/24", MatchType: "exact"}}, Action: "accept"},
	}}
	got := renderRedistributeVariantMapCluster16864(New(), po, "MIX", ps, "bgp", redistVariantOSPF16864, false)
	ospf := strings.Join(redistSeqs16864(t, got, "MIX-bgp-xpf-redist-ospf"), "\n")
	if strings.Contains(ospf, "deny 10\n") || strings.Contains(ospf, "deny 20\n") {
		t.Errorf("known off-family rejects must be omitted before community fallback, not become deny-all:\n%s", ospf)
	}
	if !strings.Contains(ospf, "permit") || !strings.Contains(ospf, "match ip address") {
		t.Errorf("same-family accept control must remain in ospf variant:\n%s", ospf)
	}

	// Positive control: BGP evaluates the community and keeps each
	// family-specific predicate in its original term.
	bgp := renderRedistributeVariantMapCluster16864(New(), po, "MIX", ps, "bgp", redistVariantBGP16864, false)
	bgpSeqs := strings.Join(redistSeqs16864(t, bgp, "MIX-bgp-xpf-redist"), "\n")
	if !strings.Contains(bgpSeqs, "match community CUST") || !strings.Contains(bgpSeqs, "match ipv6") || !strings.Contains(bgpSeqs, "V6NETS") {
		t.Errorf("BGP control must retain the full reject predicates:\n%s", bgpSeqs)
	}

	// Same-family unsupported reject remains a fail-closed bare deny.
	sameFamily := &config.PolicyStatement{Name: "MIX-SAME", Terms: []*config.PolicyTerm{{
		Name: "bad4", FromProtocols: []string{"bgp"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.0.2.0/24", MatchType: "exact"}}, FromCommunity: []string{"CUST"}, Action: "reject",
	}}}
	sameFamilyRender := renderRedistributeVariantMapCluster16864(New(), po, "MIX-SAME", sameFamily, "bgp", redistVariantOSPF16864, false)
	sameFamilySeqs := strings.Join(redistSeqs16864(t, sameFamilyRender, "MIX-SAME-bgp-xpf-redist-ospf"), "\n")
	if !strings.Contains(sameFamilySeqs, "deny 10") || strings.Contains(sameFamilySeqs, "match community") {
		t.Errorf("same-family BGP-only reject control must retain its bare deny:\n%s", sameFamilySeqs)
	}
}
func TestISISClusterComposedStaticPreservesAFVariant17893(t *testing.T) {
	fc := &FullConfig{
		ClusterMode:   true,
		PolicyOptions: chainPO15156(),
		ISIS: &config.ISISConfig{
			NET:    "49.0001.0100.0100.1001.00",
			Level:  "level-2",
			Export: []string{"NO-RFC1918", "STATICS"},
		},
	}
	got := New().buildManagedSection(fc)
	base := composedISIS15156()
	for _, family := range []struct {
		name   string
		suffix string
	}{
		{name: "ipv4", suffix: "-isis-v4"},
		{name: "ipv6", suffix: "-isis-v6"},
	} {
		attached := base + family.suffix
		if !strings.Contains(got, "redistribute "+family.name+" static level-2 route-map "+attached+"\n") {
			t.Errorf("cluster IS-IS composed %s static line must attach %q:\n%s", family.name, attached, got)
		}
		redistSeqs16864(t, got, attached)
	}
	if strings.Contains(got, "route-map "+base+"\n") {
		t.Errorf("cluster IS-IS must not attach the unsuffixed composed map %q:\n%s", base, got)
	}
}
