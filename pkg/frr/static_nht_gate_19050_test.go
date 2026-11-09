package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #19050 D1: the render side of the NHT-gated statics. The daemon decides
// WHICH hops are gated (pkg/daemon frr_static_nht_gate_19050_test.go); these
// cells pin that the managed section emits them, in the default context and
// in an instance, and that they do NOT act as an owned static: a gated
// default must not suppress a DHCP default the way an owned static default
// does (#5519), because on the standby it is inactive in zebra.

func gatedDefault19050() *config.StaticRoute {
	return &config.StaticRoute{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}}
}

func TestNHTGatedStaticRendersInTheManagedSection19050(t *testing.T) {
	out := New().buildManagedSection(&FullConfig{
		ClusterMode:          true,
		NHTGatedStaticRoutes: []*config.StaticRoute{gatedDefault19050()},
	})
	// Preference 0 is an omitted Junos preference: FRR distance 5.
	if !strings.Contains(out, "ip route 0.0.0.0/0 172.16.50.1 5\n") {
		t.Errorf("NHT-gated v4 default missing from the managed section (#19050):\n%s", out)
	}
	if !strings.Contains(out, "ip route 0.0.0.0/0 Null0 tag 2500 250\n") {
		t.Errorf("cluster Null0 default missing beside the gated static:\n%s", out)
	}
}

func TestNHTGatedStaticRendersInItsInstance19050(t *testing.T) {
	out := New().buildManagedSection(&FullConfig{
		ClusterMode: true,
		Instances: []InstanceConfig{{Name: "t", VRFName: "vrf-t",
			NHTGatedStaticRoutes: []*config.StaticRoute{gatedDefault19050()}}},
	})
	if !strings.Contains(out, "ip route 0.0.0.0/0 172.16.50.1 5 vrf vrf-t\n") {
		t.Errorf("instance NHT-gated static missing or not in its VRF (#19050):\n%s", out)
	}
}

func TestNHTGatedStaticDoesNotSuppressDHCPDefault19050(t *testing.T) {
	dhcp := []DHCPRoute{{Gateway: "10.9.9.1", Interface: "ge-0/0/2"}}
	gated := renderDHCP8963(t, &FullConfig{
		NHTGatedStaticRoutes: []*config.StaticRoute{gatedDefault19050()},
		DHCPRoutes:           dhcp,
	})
	if !strings.Contains(gated, "10.9.9.1") {
		t.Errorf("an NHT-gated (inactive on this node) static default suppressed the DHCP default; "+
			"only an OWNED static may (#19050):\n%s", gated)
	}
	// CONTROL: the same static as an OWNED route does suppress it, so the
	// assertion above can fail.
	owned := renderDHCP8963(t, &FullConfig{
		StaticRoutes: []*config.StaticRoute{gatedDefault19050()},
		DHCPRoutes:   dhcp,
	})
	if strings.Contains(owned, "10.9.9.1") {
		t.Fatalf("CONTROL FAILED: an owned static default no longer suppresses the DHCP default:\n%s", owned)
	}
}
