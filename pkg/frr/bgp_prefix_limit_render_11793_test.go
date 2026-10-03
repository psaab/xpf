package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11793: a caller can construct Config without the schema/compiler gates, and
// tolerant loads may carry malformed values. Never pass an operand above
// FRR's unsigned 32-bit maximum to vtysh: a rejected line aborts the managed
// routing section. The largest legal value still renders exactly.
func TestGenerateProtocolsBGPMaximumPrefixBounds11793(t *testing.T) {
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
		{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: int(^uint32(0))},
		{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: int(^uint32(0)) + 1},
		{Address: "2001:db8::1", PeerAS: 65003, FamilyInet6: true, PrefixLimitInet6: int(^uint32(0)) + 1},
	}}
	got := New().generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "neighbor 192.0.2.1 maximum-prefix 4294967295\n") {
		t.Fatalf("legal uint32 maximum was not rendered verbatim:\n%s", got)
	}
	if strings.Contains(got, "neighbor 192.0.2.2 maximum-prefix") ||
		strings.Contains(got, "neighbor 2001:db8::1 maximum-prefix") ||
		strings.Contains(got, "maximum-prefix 4294967296") {
		t.Fatalf("out-of-range prefix limit reached FRR output:\n%s", got)
	}
}
