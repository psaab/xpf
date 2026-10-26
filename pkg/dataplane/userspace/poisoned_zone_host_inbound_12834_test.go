package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12834's narrow-quarantine caveat: a bare zone member claims its physical
// interface and every configured unit. A bare/unit cross-zone claim therefore
// quarantines the shared identity, rather than leaving either raw host-inbound
// override authoritative. Exercise the snapshot consumer with the unzoned
// result and verify the kernel view fails closed.
func TestPoisonedZoneOverrideAbsentFromKernelHostInboundView12834(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone zulu interfaces ge-0/0/0.0",
		"set security zones security-zone zulu interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone alpha interfaces ge-0/0/0 host-inbound-traffic system-services all",
		"set security zones security-zone alpha bogus-child-keyword",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse set command %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set path %q: %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}

	snaps := []InterfaceSnapshot{
		{
			Name: "ge-0/0/0", LinuxName: "ge-0/0/0",
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.1/24"}},
		},
		{
			Name: "ge-0/0/0.0", LinuxName: "ge-0/0/0", IsUnit: true,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.1/24"}},
		},
	}
	conflicts := config.ZoneInterfaceQuarantineExclusions(cfg)
	if zones, ok := conflicts["ge-0/0/0.0"]; !ok || len(zones) != 2 ||
		zones[0] != "alpha" || zones[1] != "zulu" {
		t.Fatalf("bare/unit zone conflict = %v, want [alpha zulu] quarantine", conflicts)
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	for _, view := range views {
		if len(view.Interfaces) != 0 {
			t.Fatalf("conflicted zone published host-inbound interfaces: %+v", view)
		}
	}

	// The quarantined bare/unit identities are bounded-deny in the classifier,
	// never inherited admits from either conflicting zone.
	for _, iface := range []string{"ge-0/0/0", "ge-0/0/0.0"} {
		got := ClassifyHostInboundForInterface(cfg, "zulu", iface, 6, true, 7000, nil, "inet")
		if got.Status != HostInboundDenied {
			t.Errorf("tcp/7000 on %s = %v, want denied after zone-ownership quarantine", iface, got.Status)
		}
	}
}
