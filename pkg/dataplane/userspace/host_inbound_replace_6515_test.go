package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6515: the ENFORCEMENT side of the union→replace flip. A per-interface
// `host-inbound-traffic` stanza describes that interface entirely; the
// zone-level stanza governs only the interfaces that declare none.
//
// Test_3362_ReplaceZoneLevel already pins the ordinary narrowing on the kernel
// nft view builder. This file covers the two cases nothing else reaches: the
// EMPTY-stanza deny-all override (which distinguishes stanza presence from token
// emptiness) and the per-interface classifier that answers operator queries.

// hostInboundReplaceCfg6515 builds a zone admitting ssh AND ping at the zone
// level over two addressed units, with only the first declaring an override.
// override==nil leaves the first unit un-overridden.
func hostInboundReplaceCfg6515(override *config.HostInboundTraffic) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
		}},
	}
	zone := &config.ZoneConfig{
		Name:               "trust",
		Interfaces:         []string{"ge-0/0/0.0", "ge-0/0/1.0"},
		HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
	}
	if override != nil {
		zone.InterfaceHostInbound = map[string]*config.HostInboundTraffic{"ge-0/0/0.0": override}
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": zone}
	return cfg
}

// servicesByAddr6515 maps each firewall-local address to the admitted
// system-services of the view that scopes it.
func servicesByAddr6515(cfg *config.Config) map[string][]string {
	out := map[string][]string{}
	for _, v := range BuildZoneHostInboundViews(cfg) {
		for _, a := range v.V4Addrs {
			out[a] = v.SystemServices
		}
	}
	return out
}

// TestEmptyInterfaceStanzaIsDenyAllNotFallback_6515 is the discriminator between
// "the interface declares a stanza" and "the interface's token list is
// non-empty". An explicit `host-inbound-traffic { }` on an interface is a
// deny-all override in Junos; resolving on emptiness instead of presence would
// silently fall back to the zone set and admit ssh on an interface the operator
// closed. parseHostInboundNode already compiles a present-but-empty stanza to a
// non-nil empty struct, which is exactly what this fixture supplies.
func TestEmptyInterfaceStanzaIsDenyAllNotFallback_6515(t *testing.T) {
	got := servicesByAddr6515(hostInboundReplaceCfg6515(&config.HostInboundTraffic{}))
	if n := len(got["10.0.0.1"]); n != 0 {
		t.Fatalf("overridden address admits %v, want nothing: an explicit empty interface "+
			"host-inbound-traffic stanza is a deny-all override, never a fallback to the "+
			"zone set (#6515)", got["10.0.0.1"])
	}
	// Control: the sibling with no stanza still gets the zone set, so the test
	// above cannot be satisfied by the zone stanza having stopped applying.
	if !eqStr(got["10.0.1.1"], []string{"ssh", "ping"}) {
		t.Fatalf("non-overridden sibling admits %v, want the zone set [ssh ping]", got["10.0.1.1"])
	}
}

// TestNoInterfaceStanzaKeepsZoneSet_6515 is the other half of the discriminator:
// with no override at all, both addresses carry the zone set. Without it, an
// implementation that simply dropped the zone-level stanza from every view would
// pass every replace assertion in this package.
func TestNoInterfaceStanzaKeepsZoneSet_6515(t *testing.T) {
	got := servicesByAddr6515(hostInboundReplaceCfg6515(nil))
	for _, addr := range []string{"10.0.0.1", "10.0.1.1"} {
		if !eqStr(got[addr], []string{"ssh", "ping"}) {
			t.Fatalf("addr %s admits %v, want the zone set [ssh ping]: replace narrows only "+
				"interfaces that DECLARE a stanza", addr, got[addr])
		}
	}
}

// TestClassifyHostInboundForInterfaceReplaces_6515 binds the operator-facing
// per-interface diagnostic to the same rule enforcement uses. A diagnostic that
// reported the union while the kernel enforced the replace would tell the
// operator their SSH is admitted on an interface the firewall drops it on —
// worse than no diagnostic. Both directions are asserted on ONE config so the
// test says which interface disagreed.
func TestClassifyHostInboundForInterfaceReplaces_6515(t *testing.T) {
	cfg := hostInboundReplaceCfg6515(&config.HostInboundTraffic{SystemServices: []string{"https"}})

	// ssh (tcp/22) on the OVERRIDDEN interface: the override lists only https,
	// so the zone's ssh no longer reaches it.
	if a := ClassifyHostInboundForInterface(cfg, "trust", "ge-0/0/0.0",
		config.HostInboundProtoTCP, true, 22, true, nil, "ip"); a.Status != HostInboundDenied {
		t.Fatalf("ssh on the overridden interface = %+v, want denied: the interface stanza "+
			"lists only https, replacing the zone's ssh (#6515)", a)
	}
	// https (tcp/443) on the same interface is admitted by its own stanza.
	if a := ClassifyHostInboundForInterface(cfg, "trust", "ge-0/0/0.0",
		config.HostInboundProtoTCP, true, 443, true, nil, "ip"); a.Status != HostInboundTokenAdmit {
		t.Fatalf("https on the overridden interface = %+v, want token-admit via its own stanza", a)
	}
	// ssh on the NON-overridden sibling is still admitted by the zone stanza.
	if a := ClassifyHostInboundForInterface(cfg, "trust", "ge-0/0/1.0",
		config.HostInboundProtoTCP, true, 22, true, nil, "ip"); a.Status != HostInboundTokenAdmit {
		t.Fatalf("ssh on the non-overridden sibling = %+v, want token-admit: the zone stanza "+
			"still governs interfaces that declare none", a)
	}
}
