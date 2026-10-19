package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #15734: static routes follow RG ownership in the FRR render.
//
// The loss cluster splits RG1 (WAN reth0) and RG2 (LAN reth1). When the
// gate failed RG2 to node1, node1 became LAN owner while RG1 stayed on
// node0 — and every WAN static (the v6 default via 2001:559:8585:50::1
// on reth0.50, the GRE prefix via reth0.80) stayed in node1's FRR
// managed section with zebra marking them inactive (their egress
// connected prefixes belong to RG1, which node1 does not own), so
// zebra selected the cluster-mode blackhole default and LAN->WAN IPv6
// transit died on the kernel route while NA neighbor recovery worked.
//
// filterStaticRoutes (wired into assembleFRRConfig next to the
// dynamic-protocol HA filters) drops statics whose egress RG is not
// locally primary, prunes mixed next-hops, and keeps non-RETH routes.
// FAIL-ON-REVERT: unwire the filter from assembleFRRConfig (or make
// staticHopActive always true) and the RG1-secondary cells below see
// the WAN statics again.
func frrStaticHAConfig15734() *config.Config {
	cfg := frrRGShutdownConfig11415()
	// WAN reth0 (RG1) carries the transit prefixes; LAN reth1 (RG2) the
	// host prefix. Priorities mirror the loss cluster (node0 preferred).
	cfg.Chassis.Cluster.RedundancyGroups = append(cfg.Chassis.Cluster.RedundancyGroups,
		&config.RedundancyGroup{ID: 2, NodePriorities: map[int]int{0: 200, 1: 100}})
	cfg.Interfaces.Interfaces["reth0"].VlanTagging = true
	cfg.Interfaces.Interfaces["reth0"].Units = map[int]*config.InterfaceUnit{
		50: {Number: 50, VlanID: 50, Addresses: []string{"2001:db8:50::8/64", "172.16.50.8/24"}},
		80: {Number: 80, VlanID: 80, Addresses: []string{"2001:db8:80::8/64", "172.16.80.8/24"}},
	}
	cfg.Interfaces.Interfaces["reth1"] = &config.InterfaceConfig{
		Name: "reth1", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8:ef00::1/64", "10.0.61.1/24"}},
		},
	}
	cfg.Interfaces.Interfaces["ge-0/0/1"].RedundantParent = "reth1"
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8:50::1"}}},
		{Destination: "2001:db8:200::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:80::1"}}},
		// Mixed: one WAN hop (RG1) + one LAN hop (RG2) — pruned per-hop.
		{Destination: "2001:db8:300::/64", NextHops: []config.NextHopEntry{
			{Address: "2001:db8:50::1"}, {Address: "2001:db8:ef00::2"}}},
		// Non-RETH egress (plain interface): never RG-scoped.
		{Destination: "2001:db8:400::/64", NextHops: []config.NextHopEntry{{Address: "203.0.113.2"}}},
	}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
	}
	return cfg
}

func staticDests15734(routes []*config.StaticRoute) map[string][]string {
	out := make(map[string][]string)
	for _, r := range routes {
		if r == nil {
			continue
		}
		for _, h := range r.NextHops {
			out[r.Destination] = append(out[r.Destination], h.Address)
		}
	}
	return out
}

func TestFRRStaticsFollowRGOwnership15734(t *testing.T) {
	cfg := frrStaticHAConfig15734()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	d := &Daemon{cluster: cm}

	// All primary: everything renders (positive control).
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StatePrimary)
	fc := d.assembleFRRConfig(cfg, nil)
	v6 := staticDests15734(fc.Inet6StaticRoutes)
	for _, dest := range []string{"::/0", "2001:db8:200::/64", "2001:db8:300::/64", "2001:db8:400::/64"} {
		if _, ok := v6[dest]; !ok {
			t.Fatalf("all-primary render dropped %s: %v", dest, v6)
		}
	}
	if got := staticDests15734(fc.StaticRoutes)["0.0.0.0/0"]; len(got) != 1 {
		t.Fatalf("all-primary v4 default = %v, want the RG1 hop", got)
	}

	// The recorded split: RG2 (LAN) local, RG1 (WAN) on the peer. The
	// WAN statics must be ABSENT here (they reactivate on the owner via
	// the same render), the LAN-egress hop of the mixed route survives,
	// and the non-RETH route is untouched.
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	fc = d.assembleFRRConfig(cfg, nil)
	v6 = staticDests15734(fc.Inet6StaticRoutes)
	if _, ok := v6["::/0"]; ok {
		t.Errorf("RG1-secondary render kept the WAN v6 default %v — zebra marks it inactive and "+
			"selects the cluster blackhole, the #15734 transit blackhole", v6["::/0"])
	}
	if _, ok := v6["2001:db8:200::/64"]; ok {
		t.Errorf("RG1-secondary render kept the reth0.80 static: %v", v6)
	}
	if got := v6["2001:db8:300::/64"]; len(got) != 1 || got[0] != "2001:db8:ef00::2" {
		t.Errorf("mixed route hops = %v, want only the RG2 (LAN) hop retained", got)
	}
	if _, ok := v6["2001:db8:400::/64"]; !ok {
		t.Errorf("non-RETH static dropped: %v", v6)
	}
	if got := staticDests15734(fc.StaticRoutes)["0.0.0.0/0"]; len(got) != 0 {
		t.Errorf("RG1-secondary render kept the WAN v4 default: %v", got)
	}

	// Promotion restores the WAN statics through the same render.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	fc = d.assembleFRRConfig(cfg, nil)
	if _, ok := staticDests15734(fc.Inet6StaticRoutes)["::/0"]; !ok {
		t.Fatal("promoted render did not restore the WAN v6 default")
	}

	// The committed config must not be mutated by filtering.
	if len(cfg.RoutingOptions.Inet6StaticRoutes) != 4 ||
		len(cfg.RoutingOptions.Inet6StaticRoutes[2].NextHops) != 2 {
		t.Fatal("HA static filtering mutated the committed config")
	}
}

// The zebra-visible consequence, at the managed-section level: on the
// RG1-secondary node the rendered FRR config must not contain the WAN
// static lines at all (pre-fix they rendered and zebra selected the
// Null0 cluster default over the inactive statics).
func TestFRRStaticsAbsentFromDemotedRender15734(t *testing.T) {
	cfg := frrStaticHAConfig15734()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	cm.SetGroupStateForTesting(2, cluster.StatePrimary)
	d := &Daemon{cluster: cm}

	fc := d.assembleFRRConfig(cfg, nil)
	var rendered strings.Builder
	for _, r := range fc.Inet6StaticRoutes {
		rendered.WriteString(r.Destination + "\n")
	}
	if strings.Contains(rendered.String(), "::/0") {
		t.Fatalf("demoted render still carries ::/0:\n%s", rendered.String())
	}
}
