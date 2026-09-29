package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func sliceHas(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// TestBuildUnzonedHostInboundAddrs is the #4420 / #11068 fail-on-revert proof:
// every addressed non-lifeline interface outside surviving zones enters the
// unzoned default-deny set, even with no security zones. A zoned address remains
// in its zone rule, fxp0 stays exempt, and bare em0/fab names are not exemptions.
func TestBuildUnzonedHostInboundAddrs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// zoned data interface (its addr must NOT appear in the unzoned deny).
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
		// addressed interface in NO zone — fail-open closes, including no-zone configs.
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8:99::1/64"}},
		}},
		// A bare em0 name is not evidence of the cluster-control role.
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
		}},
		// A bare fabric-looking name is not a configured cluster lifeline.
		"fab5": {Name: "fab5", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.5.5.5/24"}},
		}},
		// fxp0 remains the unconditional out-of-band management lifeline.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.5/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// no host-inbound stanza => #3405 default-deny still scopes 10.0.1.10.
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}

	v4, v6 := BuildUnzonedHostInboundAddrs(cfg)
	for _, want := range []string{"192.0.2.1", "198.51.100.1", "10.5.5.5"} {
		if !sliceHas(v4, want) {
			t.Errorf("unzoned v4 addr %s missing from unzoned deny set: %v", want, v4)
		}
	}
	if !sliceHas(v6, "2001:db8:99::1") {
		t.Errorf("unzoned v6 addr 2001:db8:99::1 missing from unzoned deny set: %v", v6)
	}
	if sliceHas(v4, "10.0.1.10") {
		t.Errorf("ZONED addr 10.0.1.10 must not be in the unzoned deny set: %v", v4)
	}
	if sliceHas(v4, "10.0.0.5") {
		t.Errorf("fxp0 lifeline addr 10.0.0.5 must not be in the unzoned deny set: %v", v4)
	}

	// A zone-less config still denies each addressed non-lifeline interface.
	nozone := &config.Config{}
	nozone.Interfaces.Interfaces = cfg.Interfaces.Interfaces
	nv4, nv6 := BuildUnzonedHostInboundAddrs(nozone)
	for _, want := range []string{"10.0.1.10", "192.0.2.1", "198.51.100.1", "10.5.5.5"} {
		if !sliceHas(nv4, want) {
			t.Errorf("zone-less config v4 addr %s missing from unzoned deny set: %v", want, nv4)
		}
	}
	if !sliceHas(nv6, "2001:db8:99::1") {
		t.Errorf("zone-less config v6 addr 2001:db8:99::1 missing from unzoned deny set: %v", nv6)
	}
	if sliceHas(nv4, "10.0.0.5") {
		t.Errorf("zone-less config included fxp0 lifeline addr: %v", nv4)
	}
}
