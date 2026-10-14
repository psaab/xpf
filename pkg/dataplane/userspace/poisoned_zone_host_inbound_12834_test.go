package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12834's narrow-quarantine caveat: a stray bare-physical override visible
// in config.ResolveInterfaceHostInbound alone does not prove traffic leaked.
// Exercise the address-snapshot -> zone host-inbound enforcement view for the
// bare ge ingress identity and its ge.0 unit, owned by a healthy zone.
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
			Name: "ge-0/0/0", Zone: "zulu", LinuxName: "ge-0/0/0",
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.1/24"}},
		},
		{
			Name: "ge-0/0/0.0", Zone: "zulu", LinuxName: "ge-0/0/0", IsUnit: true,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.1/24"}},
		},
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	var sawUnit bool
	for _, view := range views {
		if view.Zone == "alpha" && len(view.Interfaces) != 0 {
			t.Fatalf("poisoned alpha still owns kernel host-inbound view interfaces %v", view.Interfaces)
		}
		if view.Zone != "zulu" {
			continue
		}
		for _, iface := range view.Interfaces {
			if iface == "ge-0/0/0" {
				for _, service := range view.SystemServices {
					if strings.EqualFold(service, "all") {
						t.Fatalf("poisoned alpha's all override reached bare ingress view: %+v", view)
					}
				}
			}
			if iface == "ge-0/0/0.0" {
				sawUnit = true
				if len(view.SystemServices) != 1 || !strings.EqualFold(view.SystemServices[0], "ssh") {
					t.Fatalf("healthy zulu unit host-inbound view = %v, want [ssh]", view.SystemServices)
				}
			}
		}
	}
	if !sawUnit {
		t.Fatalf("snapshot produced no healthy ge-0/0/0.0 host-inbound view: %+v", views)
	}

	// The bounded classifier control checks both identities as well: arbitrary
	// tcp/7000 is not admitted by zulu's ssh-only unit policy, nor may alpha's
	// orphaned bare override turn the physical query into an admit.
	for _, iface := range []string{"ge-0/0/0", "ge-0/0/0.0"} {
		got := ClassifyHostInboundForInterface(cfg, "zulu", iface, 6, true, 7000, nil, "inet")
		if got.Status != HostInboundDenied {
			t.Errorf("tcp/7000 on %s = %v, want denied by zulu's effective policy", iface, got.Status)
		}
	}
}
