package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Zoned IPv6 literals are rejected by the strict config gate and must also be
// omitted from tolerant static-route rendering.
func TestZonedStaticNextHopsOmitted_9820(t *testing.T) {
	m := &Manager{}
	out := m.generateStaticRoute(&config.StaticRoute{
		Destination: "2001:db8::/32",
		Preference:  5,
		NextHops:    []config.NextHopEntry{{Address: "fe80::1%eth0"}},
	}, "", nil, nil, nil)
	if strings.TrimSpace(out) != "" {
		t.Fatalf("zoned static next-hop must render nothing, got:\n%s", out)
	}
}
