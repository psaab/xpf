package frr

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestFamilylessIPv6NeighborWithoutPolicyIsV6Only11564 proves that an IPv6
// peer with no family or policy is explicitly kept out of FRR's default IPv4
// unicast AF and activated only under IPv6 unicast.
func TestFamilylessIPv6NeighborWithoutPolicyIsV6Only11564(t *testing.T) {
	const peer = "2001:db8::1"
	bgp := &config.BGPConfig{
		LocalAS:   65000,
		Neighbors: []*config.BGPNeighbor{{Address: peer, PeerAS: 65001}},
	}
	rendered := New().buildManagedSection(&FullConfig{BGP: bgp})

	v4 := bgpAFBlock11374(rendered, bgpInet4AF11374)
	v6 := bgpAFBlock11374(rendered, bgpInet6AF11374)
	if !strings.Contains(v4, "no neighbor "+peer+" activate\n") {
		t.Fatalf("family-less IPv6 peer must be explicitly disabled in FRR's default IPv4 AF:\n%s", rendered)
	}
	if strings.Contains(v4, "  neighbor "+peer+" activate\n") {
		t.Fatalf("family-less IPv6 peer must not be activated in IPv4 unicast:\n%s", rendered)
	}
	if !strings.Contains(v6, "neighbor "+peer+" activate\n") {
		t.Fatalf("family-less IPv6 peer must activate in IPv6 unicast:\n%s", rendered)
	}

	bgpd := os.Getenv("FRR_BGPD_BINARY")
	if bgpd == "" {
		var err error
		bgpd, err = exec.LookPath("bgpd")
		if err != nil {
			for _, candidate := range []string{"/usr/lib/frr/bgpd", "/usr/libexec/frr/bgpd"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					bgpd = candidate
					break
				}
			}
		}
	}
	if bgpd == "" {
		t.Skip("FRR bgpd is not installed; FRR config-load validation unavailable")
	}

	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, bgpd, "-C", "-f", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("FRR rejected the family-less IPv6 BGP config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
}
