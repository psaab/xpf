package config

import (
	"strings"
	"testing"
)

// #9997: duplicate-pubkey validation was scoped to one tunnel's peer list /
// one unit; no validator saw two units together. Two sibling units under one
// interface-level WireGuard tunnel could each author the SAME peer pubkey
// (with different allowed-ips) and pass even strict commit; the merged
// emission (mergeWireguardUnitPeers, first-wins by pubkey) then silently
// discarded the later unit's routing intent.
//
// The fix is a merged-view gate in validateWireguardPeersStrict that sees all
// units of an interface-level WireGuard tunnel together and refuses with a
// diagnostic naming BOTH units.

var (
	wg9997Priv  = strings.Repeat("e4", 32)
	wg9997PeerX = strings.Repeat("f1", 32) // interface-level (inherited) peer
	wg9997PeerA = strings.Repeat("a5", 32) // the cross-unit duplicate
	wg9997PeerB = strings.Repeat("b6", 32) // a distinct second unit peer
)

func wg9997Base() []string {
	return []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wg9997Priv,
		"set interfaces wg0 tunnel wireguard peer " + wg9997PeerX + " allowed-ips 10.100.0.0/24",
	}
}

// TestWireguardCrossUnitDuplicatePubkeyRefused9997 is the #9997 fail-on-revert
// gate: two units sharing one pubkey (with DIVERGENT allowed-ips, so the
// dropped peer's routing intent is real) must be refused at strict commit
// with a diagnostic naming BOTH units.
//
// Fail-on-revert: remove the merged-view gate and this goes RED — the config
// compiles clean and the merge silently drops unit 2's 10.200.2.0/24.
func TestWireguardCrossUnitDuplicatePubkeyRefused9997(t *testing.T) {
	lines := append(wg9997Base(),
		"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.200.1.0/24",
		"set interfaces wg0 unit 2 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.200.2.0/24",
	)
	_, err := CompileConfig(buildTree4953(t, lines))
	if err == nil {
		t.Fatal("strict commit must refuse two units sharing one WireGuard peer pubkey " +
			"(merged emission would silently drop one unit's routing intent)")
	}
	msg := err.Error()
	for _, want := range []string{"duplicate peer public key", wg9997PeerA, "wg0.1", "wg0.2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("strict error must name %q, got: %v", want, err)
		}
	}
}

// TestWireguardSingleUnitDuplicateBehaviorUnchanged9997 pins that the
// merged-view gate changes nothing about single-tunnel behavior: the
// per-tunnel duplicate message is byte-stable, distinct per-unit peers still
// compile and merge, and the same pubkey on two DIFFERENT interfaces (separate
// endpoints, no merge) still compiles.
func TestWireguardSingleUnitDuplicateBehaviorUnchanged9997(t *testing.T) {
	t.Run("per-tunnel duplicate message unchanged", func(t *testing.T) {
		src := `
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key ` + wg9997Priv + `;
                peer ` + wg9997PeerA + ` { allowed-ips 10.1.0.0/16; }
                peer ` + wg9997PeerA + ` { allowed-ips 10.2.0.0/16; }
            }
        }
    }
}`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("Parse: %v", perrs)
		}
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("a duplicate pubkey within one tunnel must still be a commit error")
		}
		// The per-tunnel gate owns this diagnostic; the merged-view gate
		// must not shadow or reword it.
		if !strings.Contains(err.Error(), "each peer on a WireGuard tunnel must have a unique public key") {
			t.Errorf("single-tunnel dup error changed: %v", err)
		}
	})

	t.Run("parent and one unit redeclaration unchanged", func(t *testing.T) {
		lines := append(wg9997Base(),
			"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9997PeerX+" allowed-ips 10.200.1.0/24",
		)
		_, err := CompileConfig(buildTree4953(t, lines))
		if err == nil {
			t.Fatal("a unit re-declaring an inherited peer must still be a commit error")
		}
		// This remains the existing per-tunnel duplicate diagnostic. The
		// merged-view gate must not shadow or reword a single-unit failure.
		for _, want := range []string{
			"duplicate peer public key",
			wg9997PeerX,
			"each peer on a WireGuard tunnel must have a unique public key",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("single-unit redeclaration error must contain %q, got: %v", want, err)
			}
		}
	})

	t.Run("distinct per-unit peers still compile and merge", func(t *testing.T) {
		lines := append(wg9997Base(),
			"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.200.1.0/24",
			"set interfaces wg0 unit 2 tunnel wireguard peer "+wg9997PeerB+" allowed-ips 10.200.2.0/24",
		)
		cfg, err := CompileConfig(buildTree4953(t, lines))
		if err != nil {
			t.Fatalf("distinct per-unit peers must still compile: %v", err)
		}
		// The interface-level peer X is inherited by BOTH units (#7786);
		// that value-identical sharing must not trip the merged-view gate.
		eps := EmitTunnelEndpointNames(cfg)
		if len(eps) != 1 {
			t.Fatalf("interface-level WireGuard emits exactly one endpoint, got %d", len(eps))
		}
		counts := map[string]int{}
		for _, p := range eps[0].Tunnel.WgPeers {
			counts[p.PublicKeyHex]++
		}
		for _, want := range []string{wg9997PeerX, wg9997PeerA, wg9997PeerB} {
			if counts[want] != 1 {
				t.Errorf("peer %s appears %d times in the merged endpoint, want once: %v",
					want, counts[want], eps[0].Tunnel.WgPeers)
			}
		}
	})

	t.Run("same pubkey on different interfaces still compiles", func(t *testing.T) {
		lines := append(wg9997Base(),
			"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.200.1.0/24",
			"set interfaces wg1 tunnel mode wireguard",
			"set interfaces wg1 tunnel wireguard listen-port 51821",
			"set interfaces wg1 tunnel wireguard private-key "+wg9997Priv,
			"set interfaces wg1 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.201.0.0/24",
		)
		if _, err := CompileConfig(buildTree4953(t, lines)); err != nil {
			t.Fatalf("the same pubkey on two different interfaces is two separate "+
				"endpoints with no merge; must still compile: %v", err)
		}
	})
}

// TestWireguardCrossUnitDuplicateLenientWarns9997 states the lenient-path
// behavior: a persisted cross-unit duplicate must still LOAD (#1960
// no-brick) with a warning naming the pubkey and BOTH units. The merged
// endpoint still installs the pubkey once (first-wins, lowest unit wins);
// the warning is what makes that drop visible instead of silent.
func TestWireguardCrossUnitDuplicateLenientWarns9997(t *testing.T) {
	lines := append(wg9997Base(),
		"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.200.1.0/24",
		"set interfaces wg0 unit 2 tunnel wireguard peer "+wg9997PeerA+" allowed-ips 10.200.2.0/24",
	)
	tree := buildTree4953(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a persisted cross-unit duplicate: %v", err)
	}
	if cfg == nil {
		t.Fatal("CompileConfigLenient returned nil config")
	}
	for _, want := range []string{"duplicate peer public key", wg9997PeerA, "wg0.1", "wg0.2"} {
		if !warningsContain(cfg.Warnings, want) {
			t.Errorf("lenient warnings must name %q, got: %v", want, cfg.Warnings)
		}
	}

	// The tolerant emission still first-wins, deterministically: units merge
	// in ascending order, so the LOWEST-numbered unit's copy survives. Pin
	// the survivor IDENTITY (unit 1's AllowedIPs), not just cardinality, so
	// the lenient behavior stays STATED rather than drifting.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 {
		t.Fatalf("interface-level WireGuard emits exactly one endpoint, got %d", len(eps))
	}
	var survivor *WgPeerConfig
	for i := range eps[0].Tunnel.WgPeers {
		if p := &eps[0].Tunnel.WgPeers[i]; p.PublicKeyHex == wg9997PeerA {
			if survivor != nil {
				t.Fatalf("lenient merged endpoint installs the duplicate pubkey more than once: %+v", eps[0].Tunnel.WgPeers)
			}
			survivor = p
		}
	}
	if survivor == nil {
		t.Fatalf("lenient merged endpoint dropped the duplicate pubkey entirely; want unit 1's copy installed once")
	}
	if len(survivor.AllowedIPs) != 1 || survivor.AllowedIPs[0] != "10.200.1.0/24" {
		t.Errorf("lenient survivor must be unit 1's copy (AllowedIPs [10.200.1.0/24]), got %v — lowest-unit-wins moved", survivor.AllowedIPs)
	}

	// Node-aware tolerant path (HA SyncApply) must also load.
	if _, err := CompileConfigForNodeLenient(tree, 0); err != nil {
		t.Fatalf("CompileConfigForNodeLenient must not fail on a persisted cross-unit duplicate: %v", err)
	}
}
