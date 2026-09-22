package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestJunosHostLifelineMixedOracle10521 pins the unchanged emission side of
// Option A: the global deny renders only for untrust, while the coarse direct
// host-inbound SSH accept remains present for the ordinary destination. The
// warning change is projection/validator-only; it must not manufacture an fxp0
// DROP or jump.
func TestJunosHostLifelineMixedOracle10521(t *testing.T) {
	t.Run("arm A lifeline only drops program", func(t *testing.T) {
		cfg := junosHostDenyTestConfig()
		delete(cfg.Security.Zones, "untrust")
		delete(cfg.Interfaces.Interfaces, "ge-0/0/1")
		cfg.Security.GlobalPolicies = []*config.Policy{{
			Name:   "global-block",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
				ToZones:              []string{"junos-host"},
			},
		}}
		if _, programs := junosHostPayload(t, cfg); len(programs) != 0 {
			t.Fatalf("lifeline-only Arm A must produce no daemon program: %+v", programs)
		}
	})

	cfg := junosHostDenyTestConfig()
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:   "global-block",
		Action: config.PolicyDeny,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
			ToZones:              []string{"junos-host"},
		},
	}}

	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("lifeline-only mgmt must be dropped while untrust renders: %+v", programs)
	}
	if got := programs[0].Zone; got != "untrust" {
		t.Fatalf("rendered program zone = %q, want untrust", got)
	}
	if got := strings.Join(programs[0].IngressIfnames, ","); got != "ge-0-0-1" {
		t.Fatalf("rendered ingress ifnames = %q, want ge-0-0-1", got)
	}
	wantJump := `iifname "ge-0-0-1" jump ` + xnft.HostInboundJunosHostChainName(0, "untrust")
	if !strings.Contains(payload, wantJump) {
		t.Fatalf("payload missing ordinary-zone junos-host jump %q:\n%s", wantJump, payload)
	}
	if strings.Contains(payload, `iifname "fxp0" jump`) {
		t.Fatalf("lifeline-only mgmt must not gain an fxp0 junos-host jump:\n%s", payload)
	}
	if !strings.Contains(payload, `ip daddr 10.0.2.10 tcp dport 22 accept`) {
		t.Fatalf("ordinary destination-only SSH coarse accept must remain present:\n%s", payload)
	}
	if strings.Contains(payload, `iifname "fxp0"`) || strings.Contains(payload, `ip daddr 192.0.2.10`) {
		t.Fatalf("lifeline fxp0 must not gain a scoped kernel rule:\n%s", payload)
	}
}
