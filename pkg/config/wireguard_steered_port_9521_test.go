package config

import (
	"fmt"
	"strings"
	"testing"
)

// #9521: SteeredWireGuardListenPort is the ONE derivation of the steered
// WireGuard listen port. The commit warning names it, the dataplane snapshot
// carries it (ConfigSnapshot.WgSteeredListenPort), the shim ctrl block is
// programmed from that field, and the helper gates kernel-path transport
// plaintext on the same field. These cells pin what it returns;
// TestSnapshotProgramsTheWarnedWireGuardPort9521 in pkg/dataplane/userspace
// pins that the dataplane programs exactly this value.

func wgSteeredConfig9521(t *testing.T, tunnels ...[2]string) *Config {
	t.Helper()
	keys := []string{wgKeyA, wgKeyB}
	var lines []string
	for i, tun := range tunnels {
		name, port := tun[0], tun[1]
		lines = append(lines,
			"set interfaces "+name+" tunnel mode wireguard",
			"set interfaces "+name+" tunnel wireguard listen-port "+port,
			"set interfaces "+name+" tunnel wireguard private-key "+keys[i%2],
			fmt.Sprintf("set interfaces %s tunnel wireguard peer %s allowed-ips 10.%d.0.0/24",
				name, keys[(i+1)%2], i+1),
		)
	}
	lines = append(lines, "set system dataplane-type userspace")
	cfg, err := CompileConfig(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestSteeredWireGuardListenPortIsTheEmitterFirst9521(t *testing.T) {
	// wg1 authored FIRST, on the HIGHER port. The emitter walks interfaces in
	// sorted NAME order, so wg0 is the steered tunnel.
	cfg := wgSteeredConfig9521(t, [2]string{"wg1", "51900"}, [2]string{"wg0", "51820"})
	if port, name := SteeredWireGuardListenPort(cfg); port != 51820 || name != "wg0" {
		t.Fatalf("SteeredWireGuardListenPort = (%d, %q), want (51820, %q)", port, name, "wg0")
	}
	// Swap the port VALUES. If the derivation were "lowest port" rather than
	// "first tunnel in name order", the case above would pass by accident; here
	// it would pick 51820 and name wg1.
	swapped := wgSteeredConfig9521(t, [2]string{"wg1", "51820"}, [2]string{"wg0", "51900"})
	if port, name := SteeredWireGuardListenPort(swapped); port != 51900 || name != "wg0" {
		t.Fatalf("ports swapped: SteeredWireGuardListenPort = (%d, %q), want (51900, %q) — "+
			"the steered tunnel is chosen by name order, not by port value", port, name, "wg0")
	}
	// A single tunnel is the ordinary case and is steered.
	one := wgSteeredConfig9521(t, [2]string{"wg3", "51830"})
	if port, name := SteeredWireGuardListenPort(one); port != 51830 || name != "wg3" {
		t.Fatalf("single tunnel: SteeredWireGuardListenPort = (%d, %q), want (51830, %q)", port, name, "wg3")
	}
	// No WireGuard tunnel: nothing is steered.
	none, err := CompileConfig(buildTree4953(t, []string{"set system dataplane-type userspace"}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if port, name := SteeredWireGuardListenPort(none); port != 0 || name != "" {
		t.Fatalf("no WireGuard tunnel: SteeredWireGuardListenPort = (%d, %q), want (0, \"\")", port, name)
	}
	if port, name := SteeredWireGuardListenPort(nil); port != 0 || name != "" {
		t.Fatalf("nil config: SteeredWireGuardListenPort = (%d, %q), want (0, \"\")", port, name)
	}
}

// The warning must name exactly what SteeredWireGuardListenPort returns, in
// both port assignments — otherwise the warning and the dataplane can name
// different ports again, which is the second half of #9521.
func TestMultiportWarningNamesTheSteeredPortDerivation9521(t *testing.T) {
	for _, cfg := range []*Config{
		wgSteeredConfig9521(t, [2]string{"wg1", "51900"}, [2]string{"wg0", "51820"}),
		wgSteeredConfig9521(t, [2]string{"wg1", "51820"}, [2]string{"wg0", "51900"}),
	} {
		port, name := SteeredWireGuardListenPort(cfg)
		adv := validateWireguardSingleSteeredPort(cfg)
		if len(adv) != 1 {
			t.Fatalf("want exactly one multi-port advisory, got %d: %v", len(adv), adv)
		}
		if want := fmt.Sprintf("listen-port %d (%s) IS steered", port, name); !strings.Contains(adv[0], want) {
			t.Fatalf("advisory does not name the derived steered port %q:\n\n%s", want, adv[0])
		}
	}
}
