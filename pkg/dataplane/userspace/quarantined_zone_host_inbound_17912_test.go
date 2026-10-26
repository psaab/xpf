package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestQuarantinedZoneHasNoHostInboundView17912(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone zulu interfaces ge-0/0/0.0",
		"set security zones security-zone alpha interfaces ge-0/0/0 host-inbound-traffic system-services all",
		"set security zones security-zone alpha interfaces ge-0/0/2",
		"set security zones security-zone alpha bogus-child-keyword",
		"set security zones security-zone healthy interfaces ge-0/0/1.0",
		"set security zones security-zone healthy interfaces ge-0/0/2.0",
		"set security zones security-zone healthy host-inbound-traffic system-services ssh",
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
		{
			Name: "ge-0/0/1.0", Zone: "healthy", LinuxName: "ge-0/0/1", IsUnit: true,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.1.1/24"}},
		},
		{
			Name: "ge-0/0/2.0", Zone: "healthy", LinuxName: "ge-0/0/2", IsUnit: true,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.2.1/24"}},
		},
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	seenHealthy := false
	for _, view := range views {
		if view.Zone == "zulu" {
			t.Fatalf("quarantined zulu published host-inbound view: %+v", view)
		}
		if view.Zone == "healthy" {
			seenHealthy = true
			if len(view.V4Addrs) != 1 || view.V4Addrs[0] != "10.0.1.1" {
				t.Errorf("healthy sibling host-inbound addresses = %v, want [10.0.1.1]", view.V4Addrs)
			}
			if len(view.SystemServices) != 1 || view.SystemServices[0] != "ssh" {
				t.Errorf("healthy sibling services = %v, want [ssh]", view.SystemServices)
			}
		}
		for _, iface := range view.Interfaces {
			if iface == "ge-0/0/0" || iface == "ge-0/0/0.0" || iface == "ge-0/0/2.0" {
				t.Errorf("quarantined identity %s was published in view %s", iface, view.Zone)
			}
		}
		for _, addr := range view.V4Addrs {
			if addr == "10.0.0.1" || addr == "10.0.2.1" {
				t.Errorf("quarantined address %s was published in view %s", addr, view.Zone)
			}
		}
	}
	if !seenHealthy {
		t.Fatalf("healthy sibling has no host-inbound view: %+v", views)
	}
}
