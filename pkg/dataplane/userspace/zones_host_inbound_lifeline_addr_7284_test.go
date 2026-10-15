package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7284: the lifeline exclusion in the REAL host-inbound table was an INTERFACE
// exclusion, not an address-VALUE one. Every host-inbound drop is
// destination-address-only with no iifname (#3718), so a management address
// shared onto a second interface was denied by the real table regardless of the
// lifeline it also lives on — and, through the shared #5566 set, its ESTABLISHED
// session was torn down on the next apply.
//
// The FENCE already partitioned per address value (#6492); these tests pin the
// real table to the same rule, with two deliberate limits: it applies only where
// a view would deny with NO accept, and only to addresses actually on a
// lifeline.

const (
	mgmtAddr7284 = "192.0.2.1"
	plainAddr    = "198.51.100.1"
)

// cfg7284NoStanzaZone: the management address on fxp0 AND on an interface in a
// zone with no host-inbound-traffic stanza (case b), plus a NON-lifeline address
// in the same zone as the negative control.
func cfg7284NoStanzaZone() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{mgmtAddr7284 + "/24"}}}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{mgmtAddr7284 + "/24", plainAddr + "/24"}}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"ge-0/0/0.0"}}, // no stanza
	}
	return cfg
}

func viewByZone(t *testing.T, views []ZoneHostInboundView, zone string) ZoneHostInboundView {
	t.Helper()
	for _, v := range views {
		if v.Zone == zone {
			return v
		}
	}
	t.Fatalf("no view for zone %q", zone)
	return ZoneHostInboundView{}
}

func hasAddr(addrs []string, want string) bool {
	for _, a := range addrs {
		if a == want {
			return true
		}
	}
	return false
}

// TestNoStanzaZoneWithholdsLifelineSharedAddr covers case (b) AND its negative
// control in one fixture. The control is the load-bearing half: withholding
// every address would be a blanket hole in the #3405 default-deny, so an
// address that is NOT on a lifeline must still be denied by the same view.
func TestNoStanzaZoneWithholdsLifelineSharedAddr(t *testing.T) {
	v := viewByZone(t, BuildZoneHostInboundViews(cfg7284NoStanzaZone()), "lan")

	if len(v.SystemServices) != 0 || len(v.Protocols) != 0 {
		t.Fatalf("fixture must be an EMPTY-admit view or it does not exercise the "+
			"pure-drop case; got services=%v protocols=%v", v.SystemServices, v.Protocols)
	}
	if hasAddr(v.V4Addrs, mgmtAddr7284) {
		t.Errorf("management address %s is on fxp0 and must be withheld from a "+
			"no-stanza zone's catch-all drop; got %v", mgmtAddr7284, v.V4Addrs)
	}
	if !hasAddr(v.V4Addrs, plainAddr) {
		t.Errorf("NEGATIVE CONTROL: %s is not on any lifeline and must still be "+
			"denied by the #3405 default-deny; got %v", plainAddr, v.V4Addrs)
	}
}

// TestUnzonedSetWithholdsLifelineSharedAddr covers case (c) and its control.
// The address must not sit on a zoned interface, or BuildUnzonedHostInboundAddrs
// excludes it via its `zoned[host]` filter and the fixture proves nothing.
func TestUnzonedSetWithholdsLifelineSharedAddr(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{mgmtAddr7284 + "/24"}}}},
		// Unzoned, carrying BOTH the shared management address and a plain one.
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{mgmtAddr7284 + "/24", plainAddr + "/24"}}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}

	v4, _ := BuildUnzonedHostInboundAddrs(cfg)
	if hasAddr(v4, mgmtAddr7284) {
		t.Errorf("management address %s is on fxp0 and must be withheld from the "+
			"unzoned catch-all drop; got %v", mgmtAddr7284, v4)
	}
	if !hasAddr(v4, plainAddr) {
		t.Errorf("NEGATIVE CONTROL: %s is not on any lifeline and must still be in "+
			"the unzoned deny set, or the #4420 HI-2 fail-open is reopened; got %v",
			plainAddr, v4)
	}
}

// TestAdmittingZoneWithholdsLifelineSharedAddr pins address-value partitioning
// for an admitting view too: destination-only accepts/drops are not safe when
// the address is on a lifeline; the data-zone's policy is carried by the
// ingress-scoped rules instead.
func TestAdmittingZoneWithholdsLifelineSharedAddr(t *testing.T) {
	cfg := cfg7284NoStanzaZone()
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{
		SystemServices: []string{"ssh"},
	}
	v := viewByZone(t, BuildZoneHostInboundViews(cfg), "lan")
	if hasAddr(v.V4Addrs, mgmtAddr7284) || !hasAddr(v.IngressDenyV4, mgmtAddr7284) {
		t.Fatalf("an admitting zone must keep shared lifeline address only in ingress-deny destinations: %+v", v)
	}
	if !hasAddr(v.V4Addrs, plainAddr) {
		t.Fatalf("negative control: non-lifeline address must remain in destination policy: %+v", v)
	}
}

// TestLifelineSharedAddrsIncludesVIPs guards the VRRP half of the shared walk.
// A VIP is live on the RG master only, so on a backup node the interface
// snapshot misses it (#3172) — the fence walks configured VIPs for exactly that
// reason, and the value set must too or a management VIP is withheld on one
// node and denied on the other.
func TestLifelineSharedAddrsIncludesVIPs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VRRPGroups: map[string]*config.VRRPGroup{
				"1": {VirtualAddresses: []string{mgmtAddr7284}},
			}}}},
	}
	shared := hostInboundLifelineSharedAddrs(cfg)
	if !shared[mgmtAddr7284] {
		t.Errorf("a VRRP VIP configured on a lifeline must count as a lifeline "+
			"address value; got %v", shared)
	}
	if shared[plainAddr] {
		t.Errorf("NEGATIVE CONTROL: %s was never configured and must not appear", plainAddr)
	}
}
