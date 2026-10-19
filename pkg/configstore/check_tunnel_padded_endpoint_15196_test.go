package configstore

import (
	"strings"
	"testing"
)

// #15196 A02-01: strict CheckText — the real commit gate — must reject a
// padded GRE tunnel endpoint (the quoted padded literal commits clean at
// base while pkg/routing parses the raw string and creates no tunnel),
// and accept the bare control.
func TestCheckTextTunnelPaddedEndpoint15196(t *testing.T) {
	paddedSrc := `interfaces { gr-0/0/0 { tunnel { source " 192.0.2.1 "; destination 192.0.2.2; mode gre; } unit 0 { family { inet { address 10.1.0.1/30; } } } } }`
	if _, err := CheckText(paddedSrc, -1); err == nil {
		t.Errorf("CheckText ACCEPTED padded tunnel source %q", paddedSrc)
	} else if !strings.Contains(err.Error(), " 192.0.2.1 ") {
		t.Errorf("CheckText rejection must name the padded value: %v", err)
	}
	paddedDst := `interfaces { gr-0/0/0 { unit 0 { tunnel { source 192.0.2.1; destination " 192.0.2.2 "; mode gre; } family { inet { address 10.1.0.1/30; } } } } }`
	if _, err := CheckText(paddedDst, -1); err == nil {
		t.Errorf("CheckText ACCEPTED padded tunnel destination %q", paddedDst)
	} else if !strings.Contains(err.Error(), " 192.0.2.2 ") {
		t.Errorf("CheckText rejection must name the padded value: %v", err)
	}
	bare := `interfaces { gr-0/0/0 { tunnel { source 192.0.2.1; destination 192.0.2.2; mode gre; } unit 0 { family { inet { address 10.1.0.1/30; } } } } }`
	cfg, err := CheckText(bare, -1)
	if err != nil {
		t.Fatalf("bare control must pass CheckText: %v", err)
	}
	tun := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel
	if tun == nil || tun.Source != "192.0.2.1" || tun.Destination != "192.0.2.2" {
		t.Errorf("control tunnel = %+v, want source 192.0.2.1 destination 192.0.2.2", tun)
	}
}
