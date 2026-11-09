package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #19050 D1: make-before-break for static routes on an RG move.
//
// The #15734 filter keeps a non-owner's RETH statics out of FRR, so after a
// move the new owner's kernel default stays the cluster Null0 until the next
// HA render plus frr-reload installs the static (1.4-4.8 s on loss). An
// ADDRESS-ONLY hop into an inactive RG's RETH prefix is safe to render on the
// standby, because zebra's next-hop tracking holds it inactive there (in
// direct mode the standby holds no RETH VIP, so its gateway has no connected
// route) and activates it the moment the VIP lands. It goes into its own
// render-only list, NHTGatedStaticRoutes; StaticRoutes (the owned set the
// DHCP suppression reads) is unchanged, which is why the #15734/#15783 cells
// are untouched.
//
// Interface-qualified hops are resolved over an interface that is up on the
// standby too, so zebra would install them there: they stay filtered. So do
// IPv6 hops with an inferred interface, qualified-next-hop metric/preference
// hops, and every hop in legacy VRRP-backed RETH mode.
//
// FAIL-ON-REVERT: making nhtGatedStaticRoutes return nil (the pre-#19050
// render) reds the gated-presence cells. Dropping the interface or v6
// inference exclusions reds the "stays filtered" cells. Ignoring
// nhtGatesAddressHops reds the VRRP-mode cell.

func directMode19050(cfg *config.Config) *config.Config {
	cfg.Chassis.Cluster.PrivateRGElection = true
	return cfg
}

func nhtManager19050(cfg *config.Config, primary map[int]bool) *Daemon {
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for rg, p := range primary {
		if p {
			cm.SetGroupStateForTesting(rg, cluster.StatePrimary)
		} else {
			cm.SetGroupStateForTesting(rg, cluster.StateSecondary)
		}
	}
	return &Daemon{cluster: cm}
}

func gatedHops19050(routes []*config.StaticRoute, dest string) []string {
	var out []string
	for _, r := range routes {
		if r == nil || r.Destination != dest {
			continue
		}
		for _, h := range r.NextHops {
			out = append(out, h.Address+"|"+h.Interface)
		}
	}
	return out
}

func TestNHTGatedStaticsRenderAheadOnTheStandby19050(t *testing.T) {
	cfg := directMode19050(frrStaticHAConfig15734())
	d := nhtManager19050(cfg, map[int]bool{0: true, 1: false, 2: true})
	fc := d.assembleFRRConfig(cfg, nil)

	if got := gatedHops19050(fc.NHTGatedStaticRoutes, "0.0.0.0/0"); len(got) != 1 || got[0] != "172.16.50.1|" {
		t.Fatalf("RG1-secondary (direct mode) did not render the address-only v4 default ahead of "+
			"activation: NHT-gated 0.0.0.0/0 = %v, want [172.16.50.1|] (#19050)", got)
	}
	// The owned set is unchanged: the DHCP default/classless suppression and
	// the #15734 contract read it.
	if got := staticDests15734(fc.StaticRoutes)["0.0.0.0/0"]; len(got) != 0 {
		t.Errorf("the gated v4 default leaked into the OWNED static set %v; it must stay render-only", got)
	}
	// The v6 default's hop gets an inferred egress interface (reth0.50), so
	// zebra would resolve it over the standby's up interface: it stays out.
	if got := gatedHops19050(fc.NHTGatedStaticRoutes, "::/0"); len(got) != 0 {
		t.Errorf("the interface-inferred v6 default was rendered on the standby: %v", got)
	}
	if got := gatedHops19050(fc.NHTGatedStaticRoutes, "2001:db8:200::/64"); len(got) != 0 {
		t.Errorf("the interface-inferred reth0.80 v6 static was rendered on the standby: %v", got)
	}

	// Promotion: the hop is owned, so it moves to the owned set and nothing
	// stays gated.
	d = nhtManager19050(cfg, map[int]bool{0: true, 1: true, 2: true})
	fc = d.assembleFRRConfig(cfg, nil)
	if len(fc.NHTGatedStaticRoutes) != 0 {
		t.Errorf("all-primary render still carries NHT-gated statics: %+v", fc.NHTGatedStaticRoutes)
	}
	if got := staticDests15734(fc.StaticRoutes)["0.0.0.0/0"]; len(got) != 1 {
		t.Errorf("all-primary owned v4 default = %v, want the RG1 hop", got)
	}
}

func TestNHTGateKeepsQualifiedHopsFiltered19050(t *testing.T) {
	cfg := directMode19050(frrStaticHAConfig15783())
	// A qualified-next-hop with a metric into the RG1 prefix: rendered by the
	// #11447 metric tiers, so it is not gated here.
	cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
		&config.StaticRoute{Destination: "10.83.5.0/24",
			NextHops: []config.NextHopEntry{{Address: "172.16.50.1", Metric: 10, HasMetric: true}}})
	// A VRF static whose gateway is in the same RG1 prefix, address-only.
	cfg.RoutingInstances[0].StaticRoutes = append(cfg.RoutingInstances[0].StaticRoutes,
		&config.StaticRoute{Destination: "10.84.0.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}})
	d := nhtManager19050(cfg, map[int]bool{0: false, 1: false})
	fc := d.assembleFRRConfig(cfg, nil)

	// Gated: address-only hops into the RG1 prefix (configured RETH address
	// and vrrp-group virtual-address subnet).
	for _, dest := range []string{"10.83.2.0/24", "10.83.3.0/24"} {
		if got := gatedHops19050(fc.NHTGatedStaticRoutes, dest); len(got) != 1 {
			t.Errorf("address-only RG1 hop for %s not rendered ahead: %v", dest, got)
		}
	}
	// Stays filtered: interface-qualified RETH hop and the metric-carrying
	// qualified next hop. (The inferred-interface v6 exclusion is pinned by
	// the #15734-fixture cell above. Here reth0.0 belongs to the tenant VRF,
	// so the global-table v6 hop 2001:db8:50::1 gets NO inferred interface:
	// it renders address-only, and in the default table no connected route
	// can resolve it on either node, so gating it is the same inert render.)
	if got := gatedHops19050(fc.NHTGatedStaticRoutes, "10.83.4.0/24"); len(got) != 0 {
		t.Errorf("interface-qualified RETH hop rendered on the standby: %v; zebra would install it there", got)
	}
	if got := gatedHops19050(fc.NHTGatedStaticRoutes, "10.83.5.0/24"); len(got) != 0 {
		t.Errorf("qualified-next-hop metric hop rendered outside the #11447 tiers: %v", got)
	}
	// Node-local hops were never filtered, so they are not gated either.
	if got := gatedHops19050(fc.NHTGatedStaticRoutes, "10.83.1.0/24"); len(got) != 0 {
		t.Errorf("node-local hop duplicated into the gated list: %v", got)
	}
	// The VRF: its address-only RG1 hop is gated in the instance, and the
	// node-local qualified hop stays in its owned set.
	if len(fc.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(fc.Instances))
	}
	if got := gatedHops19050(fc.Instances[0].NHTGatedStaticRoutes, "10.84.0.0/24"); len(got) != 1 {
		t.Errorf("VRF address-only RG1 hop not rendered ahead: %v", got)
	}
	if !hasDest15783(fc.Instances[0].StaticRoutes, "10.83.0.0/24") {
		t.Errorf("VRF lost its node-local static: %+v", fc.Instances[0].StaticRoutes)
	}
}

func TestNHTGateIsOffInLegacyVRRPMode19050(t *testing.T) {
	// The #15734 fixture as built: no private-RG election, no no-reth-vrrp,
	// so RETH VRRP mode. The standby's RETH address ownership there is not
	// established by this change, so the #15734 filter stands unchanged.
	cfg := frrStaticHAConfig15734()
	if !cfg.Chassis.Cluster.UsesRethVRRP() {
		t.Fatal("fixture premise: the #15734 fixture is RETH-VRRP mode")
	}
	d := nhtManager19050(cfg, map[int]bool{0: true, 1: false, 2: true})
	fc := d.assembleFRRConfig(cfg, nil)
	if len(fc.NHTGatedStaticRoutes) != 0 {
		t.Errorf("legacy VRRP mode rendered NHT-gated statics %+v; D1 is direct-mode only", fc.NHTGatedStaticRoutes)
	}
	// Control: the same config in direct mode does gate the v4 default, so
	// the assertion above can fail.
	cfg2 := directMode19050(frrStaticHAConfig15734())
	d2 := nhtManager19050(cfg2, map[int]bool{0: true, 1: false, 2: true})
	if got := gatedHops19050(d2.assembleFRRConfig(cfg2, nil).NHTGatedStaticRoutes, "0.0.0.0/0"); len(got) != 1 {
		t.Fatalf("CONTROL: direct mode did not gate the v4 default: %v", got)
	}
}
