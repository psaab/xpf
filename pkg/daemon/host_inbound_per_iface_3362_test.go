package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// Test_3362_NftScopesPerInterfaceOverride is the kernel-nftables PRIMARY-path
// proof for per-interface host-inbound (#3362). Zone "corp" has TWO interfaces,
// no zone-level stanza, and an ssh override on ONLY the uplink (reth0.50):
//   - the uplink address (172.16.50.8) ACCEPTs tcp/22 (ssh) and DROPs the rest;
//   - the other interface (10.0.61.1) gets a catch-all DROP with NO ssh accept.
//
// This is the motivating use case: expose management on one interface of a zone,
// deny it on another. Fail-on-revert: collapse the per-interface grouping (one
// zone-wide view) and either both addresses share one token set (10.0.61.1 would
// wrongly accept ssh) or the zone is omitted entirely — both fail here.
func Test_3362_NftScopesPerInterfaceOverride(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"corp": {
			Name:       "corp",
			Interfaces: []string{"reth0.50", "reth1.0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.50": {SystemServices: []string{"ssh"}},
			},
		},
	}

	payload := buildHostInboundFilterPayload(buildAndCheckViews(t, cfg), nil, nil, nil, nil, true)

	corpDropV4 := "counter name \"" + xnft.HostInboundDenyCounterName("corp", "ip") + "\" drop"
	mustContain := []string{
		// uplink: ssh admitted + catch-all (counted) drop.
		"ip daddr 172.16.50.8 tcp dport 22 accept",
		"ip daddr 172.16.50.8 " + corpDropV4,
		// non-overridden interface: catch-all (counted) drop (deny-all).
		"ip daddr 10.0.61.1 " + corpDropV4,
	}
	for _, want := range mustContain {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q\n---\n%s", want, payload)
		}
	}
	// The non-overridden interface must NOT admit ssh.
	if strings.Contains(payload, "ip daddr 10.0.61.1 tcp dport 22 accept") {
		t.Errorf("non-overridden interface 10.0.61.1 must NOT accept ssh:\n%s", payload)
	}
}

// Test_3362_NftDeclaresEachCounterOnce guards the integration bug exposed by
// merging #3362 onto master's #3361 host-inbound kernel-deny counters: a zone
// with a per-interface override yields MULTIPLE views sharing the same v.Zone
// (the override view + the zone-default view), each emitting a catch-all DROP
// that references the same "<zone>_<fam>" named counter. The counter is keyed
// only on (zone, family), so buildHostInboundFilterPayload must DECLARE the
// `counter "<name>" {}` object EXACTLY ONCE — nft rejects a table body that
// declares the same named counter twice ("File exists"), which would silently
// break host-inbound apply for exactly the zones this feature targets.
//
// Before the dedup fix the pre-pass appended the name once per view, so the
// declaration count for the multi-view zone was 2 (RED). After the fix it is 1.
func Test_3362_NftDeclaresEachCounterOnce(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24", "2001:db8:61::1/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"corp": {
			Name:       "corp",
			Interfaces: []string{"reth0.50", "reth1.0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.50": {SystemServices: []string{"ssh"}},
			},
		},
	}

	views := buildAndCheckViews(t, cfg)
	// Sanity: the override must actually produce more than one view sharing the
	// zone, otherwise this test would not exercise the dup-declaration path.
	corpViews := 0
	for _, v := range views {
		if v.Zone == "corp" {
			corpViews++
		}
	}
	if corpViews < 2 {
		t.Fatalf("expected >=2 views for zone corp (override + default), got %d", corpViews)
	}

	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)

	// Each named DROP counter for the zone must be DECLARED exactly once.
	for _, fam := range []string{"ip", "ip6"} {
		decl := "  counter " + xnft.HostInboundDenyCounterName("corp", fam) + " {"
		if n := strings.Count(payload, decl); n != 1 {
			t.Errorf("counter declaration for (corp,%s) appears %d times, want exactly 1 (nft rejects a duplicate declaration):\n---\n%s", fam, n, payload)
		}
	}
}
