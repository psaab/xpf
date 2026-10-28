package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12834's duplicate-membership fixture now also pins #17912: the conflicted
// ge.0 identity belongs to neither zulu nor the poisoned alpha zone, so neither
// zone may publish a host-inbound view for its address or ingress.
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
	unzonedV4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	if !sliceHas(unzonedV4, "10.0.0.1") {
		t.Errorf("quarantined zulu address missing from real-table unzoned catch-all: %v", unzonedV4)
	}
	unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
	if !sliceHas(unzonedIngress, "ge-0/0/0") {
		t.Errorf("quarantined zulu ingress missing from real-table unzoned catch-all: %v", unzonedIngress)
	}
	for _, view := range views {
		if view.Zone == "alpha" && len(view.Interfaces) != 0 {
			t.Fatalf("poisoned alpha still owns kernel host-inbound view interfaces %v", view.Interfaces)
		}
		if view.Zone == "zulu" {
			t.Fatalf("quarantined zulu still owns a kernel host-inbound view: %+v", view)
		}
	}
	// The bounded classifier control confirms the quarantined unit is denied
	// and the ambiguous bare identity is not interpreted as an admit.
	for _, tc := range []struct {
		iface string
		want  HostInboundStatus
	}{
		{iface: "ge-0/0/0", want: HostInboundNotComputed},
		{iface: "ge-0/0/0.0", want: HostInboundDenied},
	} {
		got := ClassifyHostInboundForInterface(cfg, "zulu", tc.iface, 6, true, 7000, true, nil, "inet")
		if got.Status != tc.want {
			t.Errorf("tcp/7000 on %s = %v, want %v for quarantined identity", tc.iface, got.Status, tc.want)
		}
	}
}
