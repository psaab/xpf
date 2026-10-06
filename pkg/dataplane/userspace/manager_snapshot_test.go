package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestConfigEqualIncludesPollMode(t *testing.T) {
	a := config.UserspaceConfig{
		Binary:        "/tmp/helper",
		ControlSocket: "/tmp/control.sock",
		EventSocket:   "/tmp/events.sock",
		StateFile:     "/tmp/state.json",
		Workers:       4,
		RingEntries:   1024,
		PollMode:      "busy-poll",
	}
	b := a
	b.PollMode = "epoll"
	if configEqual(a, b) {
		t.Fatal("configEqual() = true after PollMode change, want false")
	}
}

func TestBuildSnapshotSummary(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.HostName = "fw-test"
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}},
			},
		},
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "allow-all",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "src",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{{
			Name: "snat",
			Match: config.NATMatch{
				SourceAddresses: []string{"0.0.0.0/0"},
			},
			Then: config.NATThen{
				Type:      config.NATSource,
				Interface: true,
			},
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.0.1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:              "vrf1",
			TableID:           config.StableRoutingInstanceTableID("vrf1"),
			Inet6StaticRoutes: []*config.StaticRoute{{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0/0/0.0"}}}},
		},
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 11, 5)
	if snap.Generation != 11 {
		t.Fatalf("Generation = %d, want 11", snap.Generation)
	}
	if snap.FIBGeneration != 5 {
		t.Fatalf("FIBGeneration = %d, want 5", snap.FIBGeneration)
	}
	if snap.MapPins.Ctrl == "" || snap.MapPins.Bindings == "" || snap.MapPins.Heartbeat == "" || snap.MapPins.XSK == "" || snap.MapPins.LocalV4 == "" || snap.MapPins.LocalV6 == "" {
		t.Fatalf("MapPins = %+v, want all paths populated", snap.MapPins)
	}
	if snap.Summary.HostName != "fw-test" {
		t.Fatalf("HostName = %q", snap.Summary.HostName)
	}
	if snap.Summary.InterfaceCount != 2 {
		t.Fatalf("InterfaceCount = %d, want 2", snap.Summary.InterfaceCount)
	}
	if snap.Summary.ZoneCount != 2 {
		t.Fatalf("ZoneCount = %d, want 2", snap.Summary.ZoneCount)
	}
	if snap.Summary.PolicyCount != 1 {
		t.Fatalf("PolicyCount = %d, want 1", snap.Summary.PolicyCount)
	}
	if snap.Summary.SchedulerCount != 1 {
		t.Fatalf("SchedulerCount = %d, want 1", snap.Summary.SchedulerCount)
	}
	if !snap.Summary.HAEnabled {
		t.Fatal("HAEnabled = false, want true")
	}
	if len(snap.Interfaces) != 4 {
		t.Fatalf("len(Interfaces) = %d, want 4", len(snap.Interfaces))
	}
	if snap.Interfaces[0].Name != "ge-0/0/0" {
		t.Fatalf("Interfaces[0].Name = %q", snap.Interfaces[0].Name)
	}
	if snap.Interfaces[0].LinuxName != "ge-0-0-0" {
		t.Fatalf("Interfaces[0].LinuxName = %q", snap.Interfaces[0].LinuxName)
	}
	if snap.Interfaces[0].Zone != "untrust" {
		t.Fatalf("Interfaces[0].Zone = %q, want untrust", snap.Interfaces[0].Zone)
	}
	if len(snap.Routes) < 4 {
		t.Fatalf("len(Routes) = %d, want at least 4", len(snap.Routes))
	}
	var sawDefaultV4, sawDefaultV6, sawConnectedV4, sawConnectedV6 bool
	for _, route := range snap.Routes {
		switch {
		case route.Table == "inet.0" && route.Destination == "0.0.0.0/0":
			sawDefaultV4 = true
		case route.Table == "vrf1.inet6.0" && route.Destination == "::/0":
			sawDefaultV6 = true
		case route.Table == "inet.0" && route.Destination == "10.0.0.0/24":
			sawConnectedV4 = true
		case route.Table == "inet6.0" && route.Destination == "2001:db8::/64":
			sawConnectedV6 = true
		}
	}
	if !sawDefaultV4 || !sawDefaultV6 || !sawConnectedV4 || !sawConnectedV6 {
		t.Fatalf("Routes = %+v", snap.Routes)
	}
	if len(snap.SourceNAT) != 1 {
		t.Fatalf("len(SourceNAT) = %d, want 1", len(snap.SourceNAT))
	}
	if !snap.SourceNAT[0].InterfaceMode || snap.SourceNAT[0].FromZone != "trust" || snap.SourceNAT[0].ToZone != "untrust" {
		t.Fatalf("SourceNAT[0] = %+v", snap.SourceNAT[0])
	}
	if snap.DefaultPolicy != "deny" {
		t.Fatalf("DefaultPolicy = %q, want deny", snap.DefaultPolicy)
	}
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	if snap.Policies[0].Action != "deny" && snap.Policies[0].Action != "permit" {
		t.Fatalf("Policies[0].Action = %q", snap.Policies[0].Action)
	}
}

// TestSnapshotSummaryPolicyCountCountsRulesNotSets pins the #3625 fix:
// Summary.PolicyCount must reflect the number of enforced policy RULES,
// not the number of zone-pair policy SETS.
//
// RED-on-revert: with the pre-#3625 policyCount := len(cfg.Security.Policies)
//   - the multi-rule-per-set case reports 1 (one zone-pair set), want 3
//   - the global-only case reports 0 (no zone-pair sets), want 2
//
// The invariant also equals len(snap.Policies), so the summary count never
// drifts from the object count the Rust dataplane decodes (L07 integrity).
func TestSnapshotSummaryPolicyCountCountsRulesNotSets(t *testing.T) {
	mkPol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{
			Name: name,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: action,
		}
	}

	t.Run("multiple rules in one zone-pair set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.Policies = []*config.ZonePairPolicies{{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{
				mkPol("r1", config.PolicyPermit),
				mkPol("r2", config.PolicyPermit),
				mkPol("r3", config.PolicyDeny),
			},
		}}
		snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		if snap.Summary.PolicyCount != 3 {
			t.Fatalf("PolicyCount = %d, want 3 (rules, not the single zone-pair set)", snap.Summary.PolicyCount)
		}
		if snap.Summary.PolicyCount != len(snap.Policies) {
			t.Fatalf("PolicyCount = %d, want == len(Policies) = %d (summary must match decoded objects)",
				snap.Summary.PolicyCount, len(snap.Policies))
		}
	})

	t.Run("global-only config", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.GlobalPolicies = []*config.Policy{
			mkPol("g1", config.PolicyPermit),
			mkPol("g2", config.PolicyDeny),
		}
		snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		if snap.Summary.PolicyCount != 2 {
			t.Fatalf("PolicyCount = %d, want 2 (global rules; zero zone-pair sets must not report 0)", snap.Summary.PolicyCount)
		}
		if snap.Summary.PolicyCount != len(snap.Policies) {
			t.Fatalf("PolicyCount = %d, want == len(Policies) = %d (summary must match decoded objects)",
				snap.Summary.PolicyCount, len(snap.Policies))
		}
	})

	t.Run("mixed zone-pair sets and global", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{mkPol("a1", config.PolicyPermit), mkPol("a2", config.PolicyDeny)}},
			{FromZone: "dmz", ToZone: "untrust", Policies: []*config.Policy{mkPol("b1", config.PolicyPermit)}},
		}
		cfg.Security.GlobalPolicies = []*config.Policy{mkPol("g1", config.PolicyDeny)}
		snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		// 2 + 1 zone-pair rules + 1 global rule = 4 (not 2 zone-pair sets).
		if snap.Summary.PolicyCount != 4 {
			t.Fatalf("PolicyCount = %d, want 4 (2+1 zone-pair rules + 1 global)", snap.Summary.PolicyCount)
		}
		if snap.Summary.PolicyCount != len(snap.Policies) {
			t.Fatalf("PolicyCount = %d, want == len(Policies) = %d (summary must match decoded objects)",
				snap.Summary.PolicyCount, len(snap.Policies))
		}
	})
}

func TestSnapshotContentHashIgnoresVolatileFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
	}
	snap1 := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 1}, 1, 10)
	snap2 := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 1}, 99, 50)

	h1, ok1 := snapshotContentHash(snap1)
	h2, ok2 := snapshotContentHash(snap2)
	if !ok1 || !ok2 {
		t.Fatal("hash failed")
	}
	if h1 != h2 {
		t.Fatal("hashes differ despite identical stable content (only Generation/FIBGeneration changed)")
	}
}

func TestSnapshotContentHashDiffersOnForwardingChange(t *testing.T) {
	cfg1 := &config.Config{}
	cfg1.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
	}
	cfg2 := &config.Config{}
	cfg2.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}

	snap1 := mustBuildSnapshot(t, cfg1, config.UserspaceConfig{Workers: 1}, 1, 1)
	snap2 := mustBuildSnapshot(t, cfg2, config.UserspaceConfig{Workers: 1}, 1, 1)

	h1, ok1 := snapshotContentHash(snap1)
	h2, ok2 := snapshotContentHash(snap2)
	if !ok1 || !ok2 {
		t.Fatal("hash failed")
	}
	if h1 == h2 {
		t.Fatal("hashes match despite different zone config")
	}
}
