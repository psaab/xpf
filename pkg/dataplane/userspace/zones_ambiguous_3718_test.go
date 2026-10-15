// #3718 (Option B): AmbiguousHostInboundAddresses is the runtime SSOT that
// surfaces a firewall-local address reachable from multiple zones with DIFFERING
// host-inbound service sets — the kernel destination-address-only host-inbound
// verdict is then order-dependent and can disagree with the ingress-scoped
// userspace-dp path. It reads BuildZoneHostInboundViews (the same builder that
// drives nft emission) so the signal matches what is actually rendered. These
// tests are fail-on-revert: drop the detection and the ambiguous address stops
// surfacing; widen it and the identical-service / same-zone deliberate
// duplicates start surfacing.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAmbiguousHostInboundAddressesDifferingServices: the same IPv4 in two zones
// with differing host-inbound sets (aaa default-deny, zzz ssh) is reported, with
// both zones listed.
func TestAmbiguousHostInboundAddressesDifferingServices(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"aaa": {Name: "aaa", Interfaces: []string{"ge-0-0-0.0"}},
		"zzz": {Name: "zzz", Interfaces: []string{"ge-0-0-1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	got := AmbiguousHostInboundAddresses(cfg)
	if len(got) != 1 {
		t.Fatalf("AmbiguousHostInboundAddresses = %+v, want exactly 1", got)
	}
	if got[0].Address != "192.0.2.1" || got[0].Family != "inet" {
		t.Fatalf("reported = %+v, want 192.0.2.1/inet", got[0])
	}
	if len(got[0].Zones) != 2 || got[0].Zones[0] != "aaa" || got[0].Zones[1] != "zzz" {
		t.Errorf("zones = %v, want [aaa zzz]", got[0].Zones)
	}
}

// TestAmbiguousHostInboundAddressesIdenticalServicesNotReported guards the
// low-noise contract: identical host-inbound sets render the same block twice
// (order-independent) and must NOT be reported.
func TestAmbiguousHostInboundAddressesIdenticalServicesNotReported(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"aaa": {Name: "aaa", Interfaces: []string{"ge-0-0-0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"zzz": {Name: "zzz", Interfaces: []string{"ge-0-0-1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	if got := AmbiguousHostInboundAddresses(cfg); len(got) != 0 {
		t.Fatalf("identical-service duplicate must not be reported, got: %+v", got)
	}
}

// TestAmbiguousHostInboundAddressesVRRPVIP: a duplicate VRRP VIP across zones
// with differing sets is reported (M03), resolved from config on both nodes.
func TestAmbiguousHostInboundAddressesVRRPVIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.2/24"}, VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.0.2/24": {ID: 1, VirtualAddresses: []string{"10.0.0.1"}},
			}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.3/24"}, VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.0.3/24": {ID: 2, VirtualAddresses: []string{"10.0.0.1"}},
			}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"aaa": {Name: "aaa", Interfaces: []string{"reth0.0"}},
		"zzz": {Name: "zzz", Interfaces: []string{"reth1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	got := AmbiguousHostInboundAddresses(cfg)
	if len(got) != 1 || got[0].Address != "10.0.0.1" {
		t.Fatalf("AmbiguousHostInboundAddresses = %+v, want [10.0.0.1]", got)
	}
}

// #13159 (D3-13): a lifeline-shared address withheld into IngressDenyV4 by an
// empty-admit zone (wan) must still count in ambiguity detection when another
// zone (dmz) also owns it with a differing token set. It is no longer in wan's
// destination-only policy, which would also apply to lifeline traffic; without
// recording IngressDeny the conflict goes unreported.
func TestAmbiguousLifelineSharedWithheldAddressReported13159(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}}}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/0.0"}},
		"dmz": {Name: "dmz", Interfaces: []string{"ge-0/0/1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"https"}}},
	}
	views := BuildZoneHostInboundViews(cfg)
	wan := viewByZone(t, views, "wan")
	if hasAddr(wan.V4Addrs, "10.0.0.1") || !hasAddr(wan.IngressDenyV4, "10.0.0.1") {
		t.Fatalf("wan must withhold the shared address for ingress-only deny: %+v", wan)
	}
	got := AmbiguousHostInboundAddresses(cfg)
	if len(got) != 1 || got[0].Address != "10.0.0.1" || len(got[0].Zones) != 2 {
		t.Fatalf("AmbiguousHostInboundAddresses = %+v, want 10.0.0.1 with [dmz wan]", got)
	}
}

// TestAmbiguousHostInboundAddressesEmpty guards the nil / no-zone fast paths.
func TestAmbiguousHostInboundAddressesEmpty(t *testing.T) {
	if got := AmbiguousHostInboundAddresses(nil); got != nil {
		t.Errorf("nil cfg = %v, want nil", got)
	}
	if got := AmbiguousHostInboundAddresses(&config.Config{}); got != nil {
		t.Errorf("no-zone cfg = %v, want nil", got)
	}
}
