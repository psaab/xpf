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

const (
	bgpInet4AF11374 = "ipv4 unicast"
	bgpInet6AF11374 = "ipv6 unicast"
	bgpPeer11374    = "10.0.0.2"
)

func bgpConfig11374(familyInet, familyInet6 bool) (*config.BGPConfig, *config.PolicyOptionsConfig) {
	return &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{
				Address: bgpPeer11374, PeerAS: 65002, FamilyInet: familyInet, FamilyInet6: familyInet6,
				Export: []string{"OUT"}, Import: []string{"IN"},
			}},
		}, &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"OUT": {Name: "OUT", Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}},
				"IN":  {Name: "IN", Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}},
			},
		}
}

func bgpAFBlock11374(rendered, family string) string {
	var block strings.Builder
	inFamily := false
	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "address-family "+family {
			inFamily = true
			continue
		}
		if inFamily && trimmed == "exit-address-family" {
			return block.String()
		}
		if inFamily {
			block.WriteString(line)
			block.WriteByte('\n')
		}
	}
	return block.String()
}

func bgpNeighborActivated11374(block string) bool {
	want := "neighbor " + bgpPeer11374 + " activate"
	for _, line := range strings.Split(block, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func TestBGPInet6OnlyNeighborIsIPv4Deactivated11374(t *testing.T) {
	bgp, po := bgpConfig11374(false, true)
	rendered := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	v4 := bgpAFBlock11374(rendered, bgpInet4AF11374)
	v6 := bgpAFBlock11374(rendered, bgpInet6AF11374)
	if bgpNeighborActivated11374(v4) || strings.Contains(v4, "neighbor "+bgpPeer11374+" route-map ") {
		t.Errorf("inet6-only peer is IPv4-active or has an IPv4 route-map:\n%s", rendered)
	}

	if !strings.Contains(v4, "no neighbor "+bgpPeer11374+" activate\n") {
		t.Fatalf("inet6-only peer lacks explicit IPv4 deactivation:\n%s", rendered)
	}
	for _, want := range []string{
		"neighbor " + bgpPeer11374 + " activate\n",
		"neighbor " + bgpPeer11374 + " route-map OUT out\n",
		"neighbor " + bgpPeer11374 + " route-map IN in\n",
	} {
		if !strings.Contains(v6, want) {
			t.Errorf("IPv6 AF missing %q:\n%s", want, rendered)
		}
	}
}

func TestBGPNeighborActivationMatchesDeclaredFamilies11374(t *testing.T) {
	for _, tc := range []struct {
		name               string
		familyInet         bool
		familyInet6        bool
		wantIPv4, wantIPv6 bool
	}{
		{name: "inet", familyInet: true, wantIPv4: true},
		{name: "inet6", familyInet6: true, wantIPv6: true},
		{name: "dual", familyInet: true, familyInet6: true, wantIPv4: true, wantIPv6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bgp, po := bgpConfig11374(tc.familyInet, tc.familyInet6)
			rendered := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
			for _, af := range []struct {
				family string
				want   bool
			}{{bgpInet4AF11374, tc.wantIPv4}, {bgpInet6AF11374, tc.wantIPv6}} {
				activated := bgpNeighborActivated11374(bgpAFBlock11374(rendered, af.family))
				if activated != af.want {
					t.Errorf("neighbor activation in %s = %v, want %v:\n%s", af.family, activated, af.want, rendered)
				}
			}
		})
	}
}

func TestFRRLoadInet6OnlyNeighborIPv4Deactivation11374(t *testing.T) {
	bgp, po := bgpConfig11374(false, true)
	rendered := New().buildManagedSection(&FullConfig{BGP: bgp, PolicyOptions: po})
	v4 := bgpAFBlock11374(rendered, bgpInet4AF11374)
	if !strings.Contains(v4, "no neighbor "+bgpPeer11374+" activate\n") ||
		strings.Contains(v4, "neighbor "+bgpPeer11374+" route-map ") {
		t.Fatalf("config does not explicitly keep the peer inactive in IPv4 without an IPv4 route-map:\n%s", rendered)
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
		t.Fatalf("FRR rejected the inet6-only BGP config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
}
