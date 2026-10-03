package config

import (
	"strings"
	"testing"
)

// #9820/#11421: a static route whose IP next-hop has a different address
// family from its destination must be refused at strict commit and downgraded
// to a warning on the tolerant path. IPv4-via-IPv6 is valid FRR/RFC5549 syntax,
// but the userspace FIB cannot represent it.
//
// FAIL-ON-REVERT: neutralize validateStaticNextHopFamilyStrict (or drop
// its call in runUniformGatesRoutingRibRPM) and every REFUSE cell below
// compiles clean — each assertCommitRejects fires RED.

func TestStaticNextHopFamilyRefused_9820(t *testing.T) {
	cases := []struct {
		name string
		sets []string
	}{
		{"global-static", []string{
			"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		}},
		{"rib-inet6", []string{
			"set routing-options rib inet6.0 static route 2001:db8::/32 next-hop 192.0.2.1",
		}},
		{"inline-interface-flat", []string{
			"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1 interface ge-0/0/1.0",
		}},
		{"qualified-nexthop", []string{
			"set routing-options static route 2001:db8::/32 qualified-next-hop 192.0.2.1 preference 7",
			"set routing-options static route 2001:db8::/32 qualified-next-hop 192.0.2.1 interface ge-0/0/1.0",
		}},
		{"routing-instance", []string{
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances blue routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		}},
		{"forwarding-instance", []string{
			"set routing-instances fwd instance-type forwarding",
			"set routing-instances fwd routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		}},
		{"mixed-ecmp", []string{
			"set routing-options static route 2001:db8::/32 next-hop 2001:db8::1",
			"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.sets...)
			assertCommitRejects(t, tree, "IPv6 destination with IPv4 next-hop")
		})
	}
}

// The instance scope label must name the routing-instance so the operator
// finds the offending stanza.
func TestStaticNextHopFamilyNamesInstance_9820(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("instance v6-static/v4-NH compiled without error")
	}
	if !strings.Contains(err.Error(), "routing-instances blue") {
		t.Errorf("error should name the instance scope, got: %v", err)
	}
}

// Same REFUSE fixtures must warn (not reject) on the tolerant path.
func TestStaticNextHopFamilyLenientWarns_9820(t *testing.T) {
	sets := [][]string{
		{"set routing-options static route 2001:db8::/32 next-hop 192.0.2.1"},
		{"set routing-options rib inet6.0 static route 2001:db8::/32 next-hop 192.0.2.1"},
		{"set routing-options static route 2001:db8::/32 qualified-next-hop 192.0.2.1 preference 7"},
		{
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances blue routing-options static route 2001:db8::/32 next-hop 192.0.2.1",
		},
		{"set routing-options static route 10.0.0.0/8 next-hop 2001:db8::1"},
	}
	for i, s := range sets {
		tree := flatTreeFromSets(t, s...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("fixture %d: lenient load must NOT fail, got: %v", i, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "static route next-hop family") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fixture %d: lenient load must warn next-hop family, warnings=%v", i, cfg.Warnings)
		}
	}
}

func TestStaticNextHopFamilyAccepted_9820(t *testing.T) {
	cases := []struct {
		name string
		sets []string
	}{
		{"v4-via-v4", []string{
			"set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1",
		}},
		{"v6-via-v6", []string{
			"set routing-options static route 2001:db8::/32 next-hop 2001:db8::1",
		}},
		{"v6-via-mapped", []string{
			"set routing-options static route 2001:db8::/32 next-hop ::ffff:192.0.2.1",
		}},
		{"rib-inet-v4-named", []string{
			"set routing-options rib inet.0 static route 10.0.0.0/8 next-hop 192.0.2.1",
		}},
		{"v6-discard", []string{
			"set routing-options static route 2001:db8::/32 discard",
		}},
		{"v6-reject", []string{
			"set routing-options static route 2001:db8::/32 reject",
		}},
		{"forwarding-instance-v6-via-v6", []string{
			"set routing-instances fwd instance-type forwarding",
			"set routing-instances fwd routing-options static route 2001:db8::/32 next-hop 2001:db8::1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.sets...)
			cfg := assertCommitAccepts(t, tree)
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "static route next-hop family") {
					t.Fatalf("kept form must not warn next-hop family, warnings=%v", cfg.Warnings)
				}
			}
		})
	}
}

// A v6 next-table route carries no FRR next-hop and passes the family gate
// (the target instance exists so the #5693 gate passes too).
func TestStaticNextHopFamilyNextTablePasses_9820(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-instances target instance-type virtual-router",
		// #9810: one unclaimed unit (N=1) so the per-ingress window gate admits the leak.
		"set interfaces ge-0/0/0 unit 0",
		"set routing-options static route 2001:db8::/32 next-table target.inet6.0",
	)
	assertCommitAccepts(t, tree)
}

// Direct gate cells for next-hop shapes the flat-set syntax cannot author:
// structured interface-only, raw @iface, and bare interface names carry
// no IP part and pass; an empty tree passes.
func TestStaticNextHopFamilyGateDirect_9820(t *testing.T) {
	if err := validateStaticNextHopFamilyStrict(nil); err != nil {
		t.Fatalf("nil config must pass, got: %v", err)
	}
	mkRoute := func(nh NextHopEntry) *Config {
		return &Config{RoutingOptions: RoutingOptionsConfig{
			StaticRoutes: []*StaticRoute{{
				Destination: "2001:db8::/32",
				NextHops:    []NextHopEntry{nh},
			}},
		}}
	}
	for _, tc := range []struct {
		name string
		nh   NextHopEntry
		pass bool
	}{
		{"structured-interface-only", NextHopEntry{Interface: "ge-0/0/1.0"}, true},
		{"raw-at-iface", NextHopEntry{Address: "@eth0"}, true},
		{"bare-interface-name", NextHopEntry{Address: "tunnel0"}, true},
		{"v6-gateway", NextHopEntry{Address: "2001:db8::1"}, true},
		{"mapped-gateway", NextHopEntry{Address: "::ffff:192.0.2.1"}, true},
		{"v4-gateway", NextHopEntry{Address: "192.0.2.1"}, false},
		{"v4-at-iface", NextHopEntry{Address: "192.0.2.1@eth0"}, false},
		{"v4-with-interface", NextHopEntry{Address: "192.0.2.1", Interface: "ge-0/0/1.0"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStaticNextHopFamilyStrict(mkRoute(tc.nh))
			if tc.pass && err != nil {
				t.Fatalf("must pass, got: %v", err)
			}
			if !tc.pass && err == nil {
				t.Fatal("must be refused")
			}
		})
	}
	// The interface qualifier is named in the refusal.
	err := validateStaticNextHopFamilyStrict(mkRoute(NextHopEntry{Address: "192.0.2.1", Interface: "ge-0/0/1.0"}))
	if err == nil || !strings.Contains(err.Error(), "ge-0/0/1.0") {
		t.Fatalf("refusal should name the interface qualifier, got: %v", err)
	}
}

// Path E precedence: the new gate runs after #5633 and before #5701, so a
// dual violation reports the earlier gate's error. Exercised through the
// real segment with strict opts on hand-built configs.
func TestStaticNextHopFamilyPrecedence_9820(t *testing.T) {
	// #5633 (disposition conflict) precedes the family gate.
	cfg5633 := &Config{RoutingOptions: RoutingOptionsConfig{
		StaticRoutes: []*StaticRoute{
			{Destination: "10.9.0.0/16", Discard: true, NextHops: []NextHopEntry{{Address: "10.9.0.1"}}},
			{Destination: "2001:db8::/32", NextHops: []NextHopEntry{{Address: "192.0.2.1"}}},
		},
	}}
	err := runUniformGatesRoutingRibRPM(&ConfigTree{}, cfg5633, compileOpts{})
	if err == nil || !strings.Contains(err.Error(), "contradictory dispositions") {
		t.Fatalf("#5633 must win over the family gate, got: %v", err)
	}
	// The family gate precedes #5701 (route-map sequence bound).
	cfg5701 := &Config{RoutingOptions: RoutingOptionsConfig{
		StaticRoutes: []*StaticRoute{{
			Destination: "2001:db8::/32",
			NextHops:    []NextHopEntry{{Address: "192.0.2.1"}},
		}},
	}}
	cfg5701.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{
		"BIG": {Name: "BIG", Terms: []*PolicyTerm{{
			Name:          "t",
			PrefixList:    makeNames("pl", 83),
			FromCommunity: makeNames("c", 83),
		}}},
	}
	err = runUniformGatesRoutingRibRPM(&ConfigTree{}, cfg5701, compileOpts{})
	if err == nil || !strings.Contains(err.Error(), "IPv6 destination with IPv4 next-hop") {
		t.Fatalf("family gate must win over #5701, got: %v", err)
	}
}

// Flat `set` cannot spell `@` (the lexer rejects it), so the `ip@iface`
// form reaches the compiler only as a hierarchical quoted value. The gate
// classifies its IP part.
func TestStaticNextHopFamilyQuotedAtFormRefused_9820(t *testing.T) {
	tree, perrs := NewParser(`
routing-options {
    static {
        route 2001:db8::/32 {
            next-hop "192.0.2.1@eth0";
        }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "IPv6 destination with IPv4 next-hop") {
		t.Fatalf("quoted ip@iface v4-NH must be refused by the family gate, got: %v", err)
	}
}

func TestStaticNextHopFamilyRejectsV4DestinationV6Gateway11421(t *testing.T) {
	cases := []struct {
		name string
		sets []string
	}{
		{"static", []string{
			"set routing-options static route 10.0.0.0/8 next-hop 2001:db8::1",
		}},
		{"qualified-next-hop", []string{
			"set routing-options static route 10.0.0.0/8 qualified-next-hop 2001:db8::1 preference 7",
		}},
		{"rib-inet", []string{
			"set routing-options rib inet.0 static route 10.0.0.0/8 next-hop 2001:db8::1",
		}},
		{"mapped-v6-literal", []string{
			"set routing-options static route 10.0.0.0/8 next-hop ::ffff:192.0.2.1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.sets...)
			assertCommitRejects(t, tree, "IPv4 destination with IPv6 next-hop")
		})
	}
}

func TestStaticRouteNextHopFamilyMismatchSharedExclusion11421(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sr        *StaticRoute
		want      string
		healthyNH string
	}{
		{
			name: "IPv4 destination with IPv6 next-hop",
			sr: &StaticRoute{
				Destination: "10.0.0.0/8",
				NextHops:    []NextHopEntry{{Address: "2001:db8::1"}},
			},
			want:      "IPv4 destination with IPv6 next-hop",
			healthyNH: "192.0.2.254",
		},
		{
			name: "IPv6 destination with IPv4 next-hop",
			sr: &StaticRoute{
				Destination: "2001:db8::/32",
				NextHops:    []NextHopEntry{{Address: "192.0.2.1"}},
			},
			want:      "IPv6 destination with IPv4 next-hop",
			healthyNH: "2001:db8::2",
		},
		{
			name: "IPv4-mapped literal classifies as IPv6",
			sr: &StaticRoute{
				Destination: "10.0.0.0/8",
				NextHops:    []NextHopEntry{{Address: "::ffff:192.0.2.1"}},
			},
			want:      "IPv4 destination with IPv6 next-hop",
			healthyNH: "192.0.2.254",
		},
		{
			name: "qualified interface is retained in reason",
			sr: &StaticRoute{
				Destination: "10.0.0.0/8",
				NextHops:    []NextHopEntry{{Address: "2001:db8::1", Interface: "ge-0/0/1.0"}},
			},
			want:      "ge-0/0/1.0",
			healthyNH: "192.0.2.254",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := StaticRouteNextHopFamilyMismatchReason(tc.sr)
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("family mismatch reason = %q, want it to contain %q", reason, tc.want)
			}
			if got := StaticRouteExcludedReason(tc.sr, false, nil); got != reason {
				t.Fatalf("per-route exclusion = %q, want the shared family reason %q", got, reason)
			}
			healthy := &StaticRoute{
				Destination: tc.sr.Destination,
				NextHops:    []NextHopEntry{{Address: tc.healthyNH}},
			}
			cfg := &Config{RoutingOptions: RoutingOptionsConfig{
				StaticRoutes: []*StaticRoute{tc.sr, healthy},
			}}
			exclusions := StaticRouteExclusions(cfg)
			if got := exclusions[tc.sr]; got != reason {
				t.Fatalf("whole-config exclusion = %q, want %q", got, reason)
			}
			if got := exclusions[healthy]; got != "" {
				t.Fatalf("same-family control route exclusion = %q, want empty", got)
			}
		})
	}

	nextTable := &StaticRoute{
		Destination: "10.0.0.0/8",
		NextTable:   "vrf-a",
		NextHops:    []NextHopEntry{{Address: "2001:db8::1"}},
	}
	if reason := StaticRouteNextHopFamilyMismatchReason(nextTable); reason != "" {
		t.Fatalf("next-table route does not use its next-hop as a forwarding gateway: %q", reason)
	}
}

func TestNegativeStaticRoutesIgnoreUnusedCrossFamilyNextHops11421(t *testing.T) {
	for _, tc := range []struct {
		name string
		sr   *StaticRoute
	}{
		{
			name: "discard",
			sr: &StaticRoute{
				Destination: "10.0.0.0/8",
				NextHops:    []NextHopEntry{{Address: "2001:db8::1"}},
				Discard:     true,
			},
		},
		{
			name: "reject",
			sr: &StaticRoute{
				Destination: "10.0.0.0/8",
				NextHops:    []NextHopEntry{{Address: "2001:db8::1"}},
				Reject:      true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := StaticRouteNextHopFamilyMismatchReason(tc.sr); reason != "" {
				t.Fatalf("unused gateway on %s route reported as family mismatch: %q", tc.name, reason)
			}
			if reason := StaticRouteExcludedReason(tc.sr, false, nil); reason != "" {
				t.Fatalf("negative route excluded instead of retaining its disposition: %q", reason)
			}
			cfg := &Config{RoutingOptions: RoutingOptionsConfig{StaticRoutes: []*StaticRoute{tc.sr}}}
			if reason := StaticRouteExclusions(cfg)[tc.sr]; reason != "" {
				t.Fatalf("whole-config exclusion dropped negative route: %q", reason)
			}
		})
	}
}
