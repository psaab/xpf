package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// #9587: SteeredWireGuardListenPorts is the ONE derivation of the steered
// WireGuard listen-port SET. The commit warning names the SplitSteeredPorts
// triple built from it, the dataplane snapshot carries the selected set
// (ConfigSnapshot.WgSteeredListenPorts), the shim ctrl block is encoded from
// that field, and the helper gates kernel-path transport plaintext on the
// same field. These cells pin the derivation;
// TestSnapshotProgramsTheWarnedWireGuardSet9587 in pkg/dataplane/userspace
// pins that the dataplane programs exactly this triple.

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

// wgNinePortConfig9587 builds a config with nine WireGuard tunnels on nine
// distinct ports — one more than the steered bound — so the warning, the
// triple and the overflow vector have a fixture. Keys are generated per
// tunnel (local and peer) so no uniqueness gate can collapse two tunnels.
func wgNinePortConfig9587(t *testing.T, firstName string, firstPort uint16) *Config {
	t.Helper()
	var lines []string
	for i := 0; i < 9; i++ {
		name := fmt.Sprintf("wg%d", i)
		port := 51001 + i
		if i == 0 {
			name = firstName
			port = int(firstPort)
		}
		lines = append(lines,
			"set interfaces "+name+" tunnel mode wireguard",
			fmt.Sprintf("set interfaces %s tunnel wireguard listen-port %d", name, port),
			fmt.Sprintf("set interfaces %s tunnel wireguard private-key %064x", name, 0xa0+i),
			fmt.Sprintf("set interfaces %s tunnel wireguard peer %064x allowed-ips 10.%d.0.0/24",
				name, 0xb0+i, i+1),
		)
	}
	lines = append(lines, "set system dataplane-type userspace")
	cfg, err := CompileConfig(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestSteeredWireGuardListenPortsIsEmitterOrdered9521(t *testing.T) {
	// wg1 authored FIRST, on the HIGHER port. The emitter walks interfaces in
	// sorted NAME order, so wg0's port leads the set regardless of authoring
	// order — and the set is NOT sorted: it preserves emitter order.
	cfg := wgSteeredConfig9521(t, [2]string{"wg1", "51900"}, [2]string{"wg0", "51820"})
	if got := SteeredWireGuardListenPorts(cfg); !reflect.DeepEqual(got, []uint16{51820, 51900}) {
		t.Fatalf("SteeredWireGuardListenPorts = %v, want [51820 51900] in emitter order", got)
	}
	// Swap the port VALUES. If the derivation were "sorted ports" rather than
	// "emitter order", both cases above would return the same slice; here it
	// must lead with wg0's 51900.
	swapped := wgSteeredConfig9521(t, [2]string{"wg1", "51820"}, [2]string{"wg0", "51900"})
	if got := SteeredWireGuardListenPorts(swapped); !reflect.DeepEqual(got, []uint16{51900, 51820}) {
		t.Fatalf("ports swapped: SteeredWireGuardListenPorts = %v, want [51900 51820] — "+
			"emitter order, not sorted order", got)
	}
	// A single tunnel is the ordinary case.
	one := wgSteeredConfig9521(t, [2]string{"wg3", "51830"})
	if got := SteeredWireGuardListenPorts(one); !reflect.DeepEqual(got, []uint16{51830}) {
		t.Fatalf("single tunnel: SteeredWireGuardListenPorts = %v, want [51830]", got)
	}
	// No WireGuard tunnel: nothing is steered.
	none, err := CompileConfig(buildTree4953(t, []string{"set system dataplane-type userspace"}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := SteeredWireGuardListenPorts(none); len(got) != 0 {
		t.Fatalf("no WireGuard tunnel: SteeredWireGuardListenPorts = %v, want empty", got)
	}
	if got := SteeredWireGuardListenPorts(nil); len(got) != 0 {
		t.Fatalf("nil config: SteeredWireGuardListenPorts = %v, want empty", got)
	}
}

// TestSteeredWireGuardListenPortsSkipsZeroAndDedups9587 pins the two skip
// rules at the derivation boundary, on a literal Config so no compiler gate
// can interfere: a zero listen-port contributes nothing (it only arises on a
// tolerant load — strict commit rejects it), two tunnels sharing one port
// contribute one entry, and a non-WireGuard tunnel contributes nothing.
func TestSteeredWireGuardListenPortsSkipsZeroAndDedups9587(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"gre0": {Tunnel: &TunnelConfig{Mode: "gre", Source: "10.0.0.1", Destination: "10.0.0.2"}},
		"wg0":  {Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 0}},
		"wg1": {Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51820},
			Units: map[int]*InterfaceUnit{
				0: {Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51821}},
			}},
		"wg2": {Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51820}},
	}}}
	// Emitter order is wg0, wg1, wg2 (gre0 sorts first but is not WireGuard):
	// wg0's zero port is skipped, wg1 contributes 51820, the unit row for an
	// interface-level WireGuard tunnel adds no endpoint (#1910 single-TUN
	// pick), and wg2's shared port dedups to the same entry.
	if got := SteeredWireGuardListenPorts(cfg); !reflect.DeepEqual(got, []uint16{51820}) {
		t.Fatalf("SteeredWireGuardListenPorts = %v, want [51820] (zero skipped, shared deduped)", got)
	}
}

func TestSplitSteeredPortsVectors9587(t *testing.T) {
	cases := []struct {
		name                   string
		in                     []uint16
		wantFull, wantSelected []uint16
		wantOverflow           []uint16
	}{
		{"nil", nil, nil, nil, nil},
		{"empty", []uint16{}, nil, nil, nil},
		{"single", []uint16{51820}, []uint16{51820}, []uint16{51820}, nil},
		{"within bound keeps emitter order",
			[]uint16{51900, 51820}, []uint16{51900, 51820}, []uint16{51820, 51900}, nil},
		{"exactly bound",
			[]uint16{51008, 51001, 51002, 51003, 51004, 51005, 51006, 51007},
			[]uint16{51008, 51001, 51002, 51003, 51004, 51005, 51006, 51007},
			[]uint16{51001, 51002, 51003, 51004, 51005, 51006, 51007, 51008}, nil},
		{"nine appends displaces nothing",
			[]uint16{51820, 51821, 51822, 51823, 51824, 51825, 51826, 51827, 51828},
			[]uint16{51820, 51821, 51822, 51823, 51824, 51825, 51826, 51827, 51828},
			[]uint16{51820, 51821, 51822, 51823, 51824, 51825, 51826, 51827},
			[]uint16{51828}},
		// HOSTILE: the emitter-first port is numerically LARGEST. A
		// smallest-8 truncation would evict the one port that worked before
		// any bound existed; emitter-order selection keeps it.
		{"emitter-first largest survives",
			[]uint16{51900, 51001, 51002, 51003, 51004, 51005, 51006, 51007, 51008},
			[]uint16{51900, 51001, 51002, 51003, 51004, 51005, 51006, 51007, 51008},
			[]uint16{51001, 51002, 51003, 51004, 51005, 51006, 51007, 51900},
			[]uint16{51008}},
	}
	for _, tc := range cases {
		full, selected, overflow := SplitSteeredPorts(tc.in)
		if !reflect.DeepEqual(full, tc.wantFull) ||
			!reflect.DeepEqual(selected, tc.wantSelected) ||
			!reflect.DeepEqual(overflow, tc.wantOverflow) {
			t.Errorf("%s: SplitSteeredPorts(%v) = (%v, %v, %v), want (%v, %v, %v)",
				tc.name, tc.in, full, selected, overflow,
				tc.wantFull, tc.wantSelected, tc.wantOverflow)
		}
	}
}

// The warning must name exactly the triple SplitSteeredPorts returns —
// otherwise the warning and the dataplane can name different ports again,
// which is the second half of #9521.
func TestMultiportWarningNamesTheSteeredSetDerivation9587(t *testing.T) {
	cfg := wgNinePortConfig9587(t, "wg0", 51900)
	full, selected, overflow := SplitSteeredPorts(SteeredWireGuardListenPorts(cfg))
	if len(full) != 9 || len(selected) != 8 || len(overflow) != 1 {
		t.Fatalf("fixture premise: triple = (%v, %v, %v), want 9/8/1", full, selected, overflow)
	}
	adv := validateWireguardSteeredPortSet(cfg)
	if len(adv) != 1 {
		t.Fatalf("want exactly one multi-port advisory, got %d: %v", len(adv), adv)
	}
	for _, p := range selected {
		var owner string
		for _, ep := range EmitTunnelEndpointNames(cfg) {
			if ep.Tunnel.WgListenPort == p {
				owner = ep.Name
				break
			}
		}
		if want := fmt.Sprintf("%d (%s)", p, owner); !strings.Contains(adv[0], want) {
			t.Fatalf("advisory does not name selected port %q:\n\n%s", want, adv[0])
		}
	}
	for _, p := range overflow {
		if want := fmt.Sprintf("%d (", p); !strings.Contains(adv[0], want) {
			t.Fatalf("advisory does not name overflow port %d:\n\n%s", p, adv[0])
		}
	}
	// A config that fits the bound draws no advisory at all.
	fitting := wgSteeredConfig9521(t, [2]string{"wg1", "51900"}, [2]string{"wg0", "51820"})
	if adv := validateWireguardSteeredPortSet(fitting); len(adv) != 0 {
		t.Fatalf("a two-port config fits the steered set; want no advisory, got: %v", adv)
	}
}
