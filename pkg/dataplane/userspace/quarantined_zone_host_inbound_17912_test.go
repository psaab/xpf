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
		"set security zones security-zone healthy interfaces ge-0/0/3",
		"set interfaces ge-0/0/3 family inet address 10.0.3.1/24",
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
			Name: "ge-0/0/2", Zone: "healthy", LinuxName: "ge-0/0/2",
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.2.1/24"}},
		},
		{
			Name: "ge-0/0/2.0", Zone: "healthy", LinuxName: "ge-0/0/2", IsUnit: true,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.2.1/24"}},
		},
		{
			Name: "ge-0/0/3", Zone: "healthy", LinuxName: "ge-0/0/3",
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.3.1/24"}},
		},
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	unzonedV4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	if !sliceHas(unzonedV4, "10.0.0.1") {
		t.Errorf("quarantined zulu address missing from real-table unzoned catch-all: %v", unzonedV4)
	}
	unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
	if !sliceHas(unzonedIngress, "ge-0/0/0") {
		t.Errorf("quarantined zulu ingress missing from real-table unzoned catch-all: %v", unzonedIngress)
	}
	if !sliceHas(unzonedV4, "10.0.2.1") {
		t.Errorf("quarantined interface with healthy stale zone label missing from unzoned catch-all: %v", unzonedV4)
	}
	if sliceHas(unzonedV4, "10.0.1.1") || sliceHas(unzonedV4, "10.0.3.1") {
		t.Errorf("surviving healthy addresses leaked into unzoned catch-all: %v", unzonedV4)
	}
	if !sliceHas(unzonedIngress, "ge-0/0/2") {
		t.Errorf("quarantined interface with healthy stale zone label missing from unzoned ingress: %v", unzonedIngress)
	}
	if sliceHas(unzonedIngress, "ge-0/0/1") || sliceHas(unzonedIngress, "ge-0/0/3") {
		t.Errorf("surviving healthy ingress leaked into unzoned catch-all: %v", unzonedIngress)
	}
	seenHealthy := false
	for _, view := range views {
		if view.Zone == "zulu" {
			t.Fatalf("quarantined zulu published host-inbound view: %+v", view)
		}
		if view.Zone == "healthy" {
			seenHealthy = true
			if len(view.V4Addrs) != 2 || view.V4Addrs[0] != "10.0.1.1" || view.V4Addrs[1] != "10.0.3.1" {
				t.Errorf("healthy sibling host-inbound addresses = %v, want surviving unit and bare-only addresses [10.0.1.1 10.0.3.1]", view.V4Addrs)
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

func TestQuarantinedUnitZeroParentNotPublishedWithSurvivingZoneInterface17912(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.254/32",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone zulu interfaces ge-0/0/0.0",
		"set security zones security-zone alpha interfaces ge-0/0/0 host-inbound-traffic system-services all",
		"set security zones security-zone alpha bogus-child-keyword",
		"set security zones security-zone zulu interfaces ge-0/0/1.0",
		"set security zones security-zone zulu host-inbound-traffic system-services ssh",
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
			Name: "ge-0/0/1.0", Zone: "zulu", LinuxName: "ge-0/0/1", IsUnit: true,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.1.1/24"}},
		},
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	unzonedV4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	if !sliceHas(unzonedV4, "10.0.0.1") {
		t.Errorf("quarantined unit-zero address missing from real-table unzoned catch-all: %v", unzonedV4)
	}
	unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
	if !sliceHas(unzonedIngress, "ge-0/0/0") {
		t.Errorf("quarantined unit-zero ingress missing from real-table unzoned catch-all: %v", unzonedIngress)
	}
	var seenZulu bool
	for _, view := range views {
		if view.Zone != "zulu" {
			continue
		}
		seenZulu = true
		if len(view.V4Addrs) != 1 || view.V4Addrs[0] != "10.0.1.1" {
			t.Errorf("zulu addresses = %v, want only surviving interface address [10.0.1.1]", view.V4Addrs)
		}
		for _, iface := range view.Interfaces {
			if iface == "ge-0/0/0" || iface == "ge-0/0/0.0" {
				t.Errorf("quarantined unit-zero identity %s was published: %+v", iface, view)
			}
		}
	}
	if !seenZulu {
		t.Fatalf("zulu's surviving interface has no host-inbound view: %+v", views)
	}
}

