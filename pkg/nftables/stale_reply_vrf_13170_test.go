package nftables

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestHostInboundStaleReplyGuardRulesVRFScoped13170(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "strict-vrf", SystemServices: []string{"ping"}, V4Addrs: []string{"192.0.2.1"},
			IngressNetdevs:   []string{"vrf-blue"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"ge-0-0-1"}}}},
		{Zone: "open-vrf", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.2"},
			IngressNetdevs:   []string{"vrf-blue"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"ge-0-0-2"}}}},
	}
	rules := HostInboundStaleReplyGuardRules(views, nil, nil, nil, false)
	foundStrictSSHGuard := false
	foundFallback := false
	for _, r := range rules {
		if r.Family != "ip" || r.Proto != config.HostInboundProtoTCP {
			continue
		}
		address := false
		for _, a := range r.Addresses {
			address = address || a == "192.0.2.1"
		}
		port := false
		for _, p := range r.Ports {
			port = port || p == 22
		}
		if !address || !port {
			continue
		}
		if !r.IngressNegated && len(r.IngressVRFScopes) > 0 {
			scope := r.IngressVRFScopes[0]
			if scope.Master == "vrf-blue" && len(scope.Slaves) == 1 && scope.Slaves[0] == "ge-0-0-1" {
				foundStrictSSHGuard = true
			}
		}
		if r.IngressVRFNegated && len(r.IngressVRFScopes) == 1 {
			scope := r.IngressVRFScopes[0]
			if scope.Master != "vrf-blue" || len(scope.Slaves) != 2 ||
				scope.Slaves[0] != "ge-0-0-1" || scope.Slaves[1] != "ge-0-0-2" {
				t.Fatalf("VRF fallback does not exclude only zone-owned slaves: %+v", r)
			}
			foundFallback = true
		}
	}
	if !foundStrictSSHGuard {
		t.Fatal("strict-zone stale-reply guard for denied SSH reply missing")
	}
	if !foundFallback {
		t.Fatal("uncovered ingress stale-reply guard missing")
	}
}

func TestHostInboundStaleReplyGuardRulesVRFMasterExcludedFromDirectFallback13411(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "strict-vrf", SystemServices: []string{"ping"}, V4Addrs: []string{"192.0.2.1"},
			IngressNetdevs:   []string{"vrf-blue"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"ge-0-0-1"}}}},
		{Zone: "open-vrf", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.2"},
			IngressNetdevs:   []string{"vrf-blue"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"ge-0-0-2"}}}},
		{Zone: "direct-view", SystemServices: []string{"ping"}, V4Addrs: []string{"192.0.2.3"},
			IngressNetdevs: []string{"eth-direct"}},
	}
	rules := HostInboundStaleReplyGuardRules(views, nil, nil, nil, true)
	foundFallback := false
	for _, r := range rules {
		if !r.IngressNegated || len(r.IngressVRFScopes) != 0 {
			continue
		}
		foundFallback = true
		for _, want := range []string{"eth-direct", "vrf-blue", HostInboundReinjectIfname} {
			found := false
			for _, got := range r.Ingress {
				found = found || got == want
			}
			if !found {
				t.Errorf("direct fallback does not exclude %q: %+v", want, r)
			}
		}
	}
	if !foundFallback {
		t.Fatal("mixed direct/VRF trusted-reinject fallback missing")
	}
}
