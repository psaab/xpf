package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateProtocols_BGPNeighborAttributesAreAddressFamilyScoped11460(t *testing.T) {
	attributes := func(address string) *config.BGPNeighbor {
		return &config.BGPNeighbor{
			Address:              address,
			PeerAS:               65002,
			RouteReflectorClient: true,
			AllowASIn:            2,
			RemovePrivateAS:      true,
		}
	}

	tests := []struct {
		name     string
		neighbor *config.BGPNeighbor
		family   string
	}{
		{
			name: "IPv4 explicit family",
			neighbor: func() *config.BGPNeighbor {
				n := attributes("192.0.2.2")
				n.FamilyInet = true
				return n
			}(),
			family: "ipv4",
		},
		{
			name:     "IPv4 implicit default family",
			neighbor: attributes("192.0.2.3"),
			family:   "ipv4",
		},
		{
			name: "IPv6 explicit family",
			neighbor: func() *config.BGPNeighbor {
				n := attributes("2001:db8::2")
				n.FamilyInet6 = true
				return n
			}(),
			family: "ipv6",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{tc.neighbor}}
			got := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
			familyHeader := " address-family " + tc.family + " unicast\n"
			familyStart := strings.Index(got, familyHeader)
			if familyStart < 0 {
				t.Fatalf("missing %q in generated config:\n%s", strings.TrimSpace(familyHeader), got)
			}
			familyEnd := strings.Index(got[familyStart:], " exit-address-family\n")
			if familyEnd < 0 {
				t.Fatalf("unterminated %s address-family block:\n%s", tc.family, got)
			}
			afBlock := got[familyStart : familyStart+familyEnd]
			want := []string{
				"  neighbor " + tc.neighbor.Address + " route-reflector-client\n",
				"  neighbor " + tc.neighbor.Address + " allowas-in 2\n",
				"  neighbor " + tc.neighbor.Address + " remove-private-AS\n",
			}
			for _, line := range want {
				if !strings.Contains(afBlock, line) {
					t.Errorf("%s AF missing %q:\n%s", tc.family, line, afBlock)
				}
				if strings.Contains(got[:familyStart], strings.TrimPrefix(line, "  ")) {
					t.Errorf("AF-scoped neighbor attribute rendered at router level: %q\n%s", line, got[:familyStart])
				}
			}
		})
	}
}
