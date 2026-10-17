package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14584 (Y08-01): FRR bgpd defaults to `bgp ebgp-requires-policy`
// (RFC 8212) unless told otherwise. An eBGP neighbor with no inbound
// route-map has every inbound update discarded
// (inboundEbgpRequiresPolicy) and a policy-less eBGP neighbor is mute in
// both directions (outbound also discarded). Junos — and this renderer's
// own #6807/#7625 comments — treat an ABSENT route-map attachment as the
// Junos default accept/advertise. Without `no bgp ebgp-requires-policy`
// under every `router bgp`, the common Junos shapes (export-only,
// policy-less) establish a session that accepts/advertises nothing.
//
// The fix emits `no bgp ebgp-requires-policy` in every rendered
// `router bgp` stanza (default instance and each VRF). Controls below:
// an import+export eBGP peer and an iBGP peer already worked at the
// bgpd level, but they too must carry the line — it is a router-level
// opt-out, harmless when policies are present, and keeps the stanza
// invariant uniform so a later policy removal cannot silently re-arm
// the discard. LocalAS==0 renders no stanza and therefore no line.

func routerBGPBlocks14584(t *testing.T, section string) []string {
	t.Helper()
	var blocks []string
	var cur []string
	inBGP := false
	for _, line := range strings.Split(section, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "router bgp ") {
			if inBGP && len(cur) > 0 {
				blocks = append(blocks, strings.Join(cur, "\n"))
			}
			cur = []string{line}
			inBGP = true
			continue
		}
		if inBGP {
			if trimmed == "exit" {
				blocks = append(blocks, strings.Join(cur, "\n"))
				cur = nil
				inBGP = false
				continue
			}
			cur = append(cur, line)
		}
	}
	if inBGP && len(cur) > 0 {
		blocks = append(blocks, strings.Join(cur, "\n"))
	}
	return blocks
}

func assertEveryRouterBGPCarriesNoRequiresPolicy14584(t *testing.T, section string) {
	t.Helper()
	blocks := routerBGPBlocks14584(t, section)
	if len(blocks) == 0 {
		t.Fatalf("no router bgp stanza rendered:\n%s", section)
	}
	for _, blk := range blocks {
		if !strings.Contains(blk, "\n no bgp ebgp-requires-policy\n") &&
			!strings.HasSuffix(blk, "\n no bgp ebgp-requires-policy") {
			t.Errorf("router bgp stanza missing `no bgp ebgp-requires-policy`:\n%s\n--- full section ---\n%s", blk, section)
		}
	}
}

// Decisive cell: export-only eBGP (the common Junos shape) through the
// full managed-section path.
func TestEBGPRequiresPolicyDisabledExportOnly14584(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "t1", Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			// Export only, no import: pre-fix bgpd discards every
			// inbound update for this peer.
			{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"}},
			// Policy-less eBGP: pre-fix bgpd discards both directions.
			{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true},
			// Control: import+export eBGP already exchanged routes.
			{Address: "192.0.2.4", PeerAS: 65004, FamilyInet: true, Export: []string{"EXP"}, Import: []string{"EXP"}},
			// Control: iBGP is unaffected by ebgp-requires-policy.
			{Address: "192.0.2.5", PeerAS: 65001, FamilyInet: true},
		},
	}
	section := New().buildManagedSection(&FullConfig{BGP: bgp, PolicyOptions: po})
	// Anti-vacuity: the export-only neighbor really has an outbound
	// attachment and no inbound one, so the fixture exercises the bug.
	if !strings.Contains(section, "neighbor 192.0.2.2 route-map EXP out") {
		t.Fatalf("export-only fixture lost its outbound route-map:\n%s", section)
	}
	if strings.Contains(section, "neighbor 192.0.2.2 route-map") &&
		strings.Contains(section, "neighbor 192.0.2.2 route-map EXP in") {
		t.Fatalf("export-only fixture unexpectedly gained an inbound route-map:\n%s", section)
	}
	assertEveryRouterBGPCarriesNoRequiresPolicy14584(t, section)
	if n := strings.Count(section, "no bgp ebgp-requires-policy"); n != 1 {
		t.Errorf("default instance: want exactly 1 `no bgp ebgp-requires-policy`, got %d:\n%s", n, section)
	}
}

// VRF instances render their own `router bgp <as> vrf <name>` stanza;
// each must carry the line too.
func TestEBGPRequiresPolicyDisabledVRF14584(t *testing.T) {
	fc := &FullConfig{
		BGP: &config.BGPConfig{
			LocalAS:   65001,
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
		},
		Instances: []InstanceConfig{
			{
				VRFName: "vrf-1",
				BGP: &config.BGPConfig{
					LocalAS:   65001,
					Neighbors: []*config.BGPNeighbor{{Address: "10.1.1.2", PeerAS: 65003, FamilyInet: true}},
				},
			},
			{
				VRFName: "vrf-2",
				BGP: &config.BGPConfig{
					LocalAS:   65002,
					Neighbors: []*config.BGPNeighbor{{Address: "10.2.2.2", PeerAS: 65004, FamilyInet: true}},
				},
			},
		},
	}
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "router bgp 65001 vrf vrf-1\n") ||
		!strings.Contains(section, "router bgp 65002 vrf vrf-2\n") {
		t.Fatalf("VRF router bgp stanzas missing (anti-vacuity):\n%s", section)
	}
	assertEveryRouterBGPCarriesNoRequiresPolicy14584(t, section)
	if n := strings.Count(section, "no bgp ebgp-requires-policy"); n != 3 {
		t.Errorf("want exactly 3 `no bgp ebgp-requires-policy` (default + 2 VRF), got %d:\n%s", n, section)
	}
}

// Direct generateProtocols path (the render unit most BGP tests use),
// including the LocalAS==0 negative control.
func TestEBGPRequiresPolicyDisabledDirectRender14584(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	assertEveryRouterBGPCarriesNoRequiresPolicy14584(t, got)

	zero := m.generateProtocols(nil, nil, &config.BGPConfig{
		LocalAS:   0,
		Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
	}, nil, nil, "", 0, nil, nil)
	if strings.Contains(zero, "ebgp-requires-policy") {
		t.Errorf("LocalAS==0 renders no router bgp and must not render the opt-out:\n%s", zero)
	}
}
