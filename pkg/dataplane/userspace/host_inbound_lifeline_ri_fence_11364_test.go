package userspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestLifelineRIMemberFencePreservesCoMemberIngressScope11364(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/4 unit 0 family inet address 10.4.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.1.0.1/24",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-1234567890",
		"set chassis cluster node 0",
		"set chassis cluster control-interface ge-0/0/4",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/4.0",
		"set routing-instances blue interface ge-0/0/1.0",
		"set security zones security-zone control interfaces ge-0/0/4.0",
		"set security zones security-zone control host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := cfg.RoutingInstances[0].Interfaces; !slices.Equal(got, []string{"ge-0/0/1.0"}) {
		t.Fatalf("compiled RI members = %v, want only the ordinary co-member", got)
	}
	var warned bool
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11364") && strings.Contains(warning, "ge-0/0/4") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("tolerant compile did not report the lifeline membership: %v", cfg.Warnings)
	}

	views := BuildZoneHostInboundViews(cfg)
	for _, view := range views {
		if view.Zone != "trust" {
			continue
		}
		if !slices.Contains(view.IngressNetdevs, "vrf-blue") {
			t.Fatalf("co-member lost matchable LOCAL_IN scope after lifeline fencing: %+v", view)
		}
		if !slices.Contains(view.V4Addrs, "10.1.0.1") {
			t.Fatalf("co-member's host-inbound address scope was lost: %+v", view)
		}
		return
	}
	t.Fatalf("compiled co-member zone has no host-inbound view: %+v", views)
}
