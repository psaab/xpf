package config

import (
	"strings"
	"testing"
)

// #11076: a WireGuard tunnel on an unzoned interface gets no host-inbound
// accept (admission scopes to the tunnel's zone) — the commit must warn.
func TestWireGuardUnzonedTunnelWarns11076(t *testing.T) {
	priv := strings.Repeat("e4", 32)
	peer := strings.Repeat("f1", 32)
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + priv,
		"set interfaces wg0 tunnel wireguard peer " + peer + " allowed-ips 10.100.0.0/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	}
	cfg, err := CompileConfig(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "wg0") && strings.Contains(w, "unzoned") && strings.Contains(w, "11076") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an unzoned-WG warning naming wg0; warnings=%v", cfg.Warnings)
	}

	// CONTROL: zoning the tunnel interface silences the warning.
	zoned := append(append([]string{}, lines...),
		"set security zones security-zone trust interfaces wg0")
	cfg2, err := CompileConfig(buildTree4953(t, zoned))
	if err != nil {
		t.Fatalf("CompileConfig(zoned): %v", err)
	}
	for _, w := range cfg2.Warnings {
		if strings.Contains(w, "11076") {
			t.Errorf("zoned tunnel must not warn; got %q", w)
		}
	}
	if got := cfg2.WireGuardZonePorts(); len(got["trust"]) != 1 || got["trust"][0] != 51820 {
		t.Errorf("WireGuardZonePorts() = %v, want map[trust:[51820]]", got)
	}
}
