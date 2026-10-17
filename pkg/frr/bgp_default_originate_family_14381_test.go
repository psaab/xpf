package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14381: DefaultOriginate is an address-family neighbor attribute, but the
// family-membership predicate did not count it. A family-less IPv4 neighbor
// whose only activation reason was `default-originate` landed in neither
// the ipv4 nor ipv6 set, so FRR never received `activate`/`default-originate`
// and no default route was advertised.
func TestGenerateProtocols_BGPDefaultOriginateFamilyLess14381(t *testing.T) {
	m := New()

	t.Run("family-less ipv4 default-originate alone activates ipv4", func(t *testing.T) {
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65002, DefaultOriginate: true},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
		if !strings.Contains(got, " address-family ipv4 unicast\n") {
			t.Fatalf("missing ipv4 unicast block:\n%s", got)
		}
		if !strings.Contains(got, "  neighbor 192.0.2.1 activate\n") {
			t.Errorf("missing activate under ipv4 unicast:\n%s", got)
		}
		if !strings.Contains(got, "  neighbor 192.0.2.1 default-originate\n") {
			t.Errorf("missing default-originate under ipv4 unicast:\n%s", got)
		}
		// Must not leak into the ipv6 family.
		if strings.Contains(got, "neighbor 192.0.2.1 default-originate") &&
			strings.Contains(got, " address-family ipv6 unicast\n") {
			// Verify the default-originate line is not inside ipv6 block by
			// checking it precedes any ipv6 block header.
			if idxV4 := strings.Index(got, " address-family ipv4 unicast\n"); idxV4 >= 0 {
				rest := got[idxV4:]
				if end := strings.Index(rest, " exit-address-family\n"); end >= 0 {
					block := rest[:end]
					if !strings.Contains(block, "neighbor 192.0.2.1 default-originate") {
						t.Errorf("default-originate not inside ipv4 block:\n%s", got)
					}
				}
			}
		}
	})

	t.Run("family-less policyless ipv4 without AF attributes keeps no-block behaviour", func(t *testing.T) {
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65002},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
		if strings.Contains(got, " address-family ipv4 unicast\n") {
			t.Errorf("policyless family-less neighbor must not open an ipv4 block:\n%s", got)
		}
		if strings.Contains(got, "192.0.2.1 activate") || strings.Contains(got, "192.0.2.1 default-originate") {
			t.Errorf("policyless family-less neighbor must not render AF lines:\n%s", got)
		}
	})

	t.Run("explicit family inet default-originate still renders (control)", func(t *testing.T) {
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, DefaultOriginate: true},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
		if !strings.Contains(got, "  neighbor 192.0.2.1 activate\n") ||
			!strings.Contains(got, "  neighbor 192.0.2.1 default-originate\n") {
			t.Errorf("explicit inet control broken:\n%s", got)
		}
	})

	t.Run("family-less ipv6 default-originate stays in ipv6 only", func(t *testing.T) {
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "2001:db8::1", PeerAS: 65002, DefaultOriginate: true},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
		if !strings.Contains(got, " address-family ipv6 unicast\n") ||
			!strings.Contains(got, "  neighbor 2001:db8::1 activate\n") ||
			!strings.Contains(got, "  neighbor 2001:db8::1 default-originate\n") {
			t.Errorf("ipv6 default-originate must activate under ipv6:\n%s", got)
		}
		if idx := strings.Index(got, " address-family ipv4 unicast\n"); idx >= 0 {
			rest := got[idx:]
			if end := strings.Index(rest, " exit-address-family\n"); end >= 0 {
				if strings.Contains(rest[:end], "2001:db8::1 default-originate") {
					t.Errorf("ipv6 peer default-originate leaked into ipv4 block:\n%s", got)
				}
			}
		}
	})

	t.Run("family-less ipv4 prefix limit alone stays no-block (scope guard)", func(t *testing.T) {
		// Prefix limits are only set together with an explicit family by the
		// compiler, so they are not an independent activation trigger for
		// #14381; this pins that the fix does not widen beyond default-originate.
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65002, PrefixLimitInet: 100},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
		if strings.Contains(got, "192.0.2.1 maximum-prefix") {
			t.Errorf("family-less prefix-limit-only neighbor changed behaviour:\n%s", got)
		}
	})
}
