package config

import (
	"strings"
	"testing"
)

// #14450 (DR20-H5): two `tunnel` blocks under one interface/unit.
// First-only FindChild("tunnel") dropped the second block entirely, so
// `tunnel { mode gre; } tunnel { mode wireguard; wireguard {...} }`
// compiled as plaintext GRE. Fix merges blocks in order (last-wins
// scalars, peers accumulate); single block unchanged.

const (
	dup14450Priv  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dup14450Peer  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dup14450Peer2 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func compileDup14450(t *testing.T, src string) (*Config, error) {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	return CompileConfig(tree)
}

func TestDupTunnelBlocksInterfaceMerge14450(t *testing.T) {
	cfg, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        tunnel { mode gre; destination 10.0.0.1; }
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key `+dup14450Priv+`;
                peer `+dup14450Peer+` {
                    allowed-ips 10.9.0.0/24;
                    endpoint 192.0.2.1:51820;
                }
            }
        }
    }
}
`)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	tc := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel
	if tc == nil {
		t.Fatalf("no interface tunnel")
	}
	if tc.Mode != "wireguard" {
		t.Errorf("Mode=%q want wireguard (second block dropped -> plaintext GRE)", tc.Mode)
	}
	if tc.Destination != "10.0.0.1" {
		t.Errorf("Destination=%q want 10.0.0.1 (first block scalar retained)", tc.Destination)
	}
	if tc.WgListenPort != 51820 {
		t.Errorf("WgListenPort=%d want 51820", tc.WgListenPort)
	}
	if len(tc.WgPeers) != 1 || tc.WgPeers[0].PublicKeyHex != dup14450Peer {
		t.Errorf("WgPeers=%+v want 1 peer %s", tc.WgPeers, dup14450Peer)
	}
}

func TestDupTunnelBlocksReverseGreWinsButPeersRetained14450(t *testing.T) {
	cfg, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key `+dup14450Priv+`;
                peer `+dup14450Peer+` { allowed-ips 10.9.0.0/24; }
            }
        }
        tunnel { mode gre; destination 10.0.0.1; source 10.0.0.2; }
    }
}
`)
	// Mode wireguard->gre with retained peers: compile must succeed or
	// fail only for WG validation? Reverse: final mode gre so WG gate
	// does not run. Expect success with gre + inert peers retained.
	if err != nil {
		t.Fatalf("CompileConfig reverse: %v", err)
	}
	tc := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel
	if tc.Mode != "gre" {
		t.Errorf("Mode=%q want gre (last-wins)", tc.Mode)
	}
	if len(tc.WgPeers) != 1 {
		t.Errorf("WgPeers len=%d want 1 retained inert", len(tc.WgPeers))
	}
	if tc.Destination != "10.0.0.1" || tc.Source != "10.0.0.2" {
		t.Errorf("src/dst=%q/%q", tc.Source, tc.Destination)
	}
}

func TestDupTunnelBlocksUnitMerge14450(t *testing.T) {
	cfg, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        unit 0 {
            tunnel { mode gre; destination 10.0.0.1; }
            tunnel {
                mode wireguard;
                wireguard {
                    listen-port 51820;
                    private-key `+dup14450Priv+`;
                    peer `+dup14450Peer+` { allowed-ips 10.9.0.0/24; }
                }
            }
        }
    }
}
`)
	if err != nil {
		t.Fatalf("CompileConfig unit: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["gr-0/0/0"].Units[0]
	if unit == nil || unit.Tunnel == nil {
		t.Fatalf("no unit tunnel")
	}
	if unit.Tunnel.Mode != "wireguard" || len(unit.Tunnel.WgPeers) != 1 || unit.Tunnel.WgListenPort != 51820 {
		t.Errorf("unit tunnel=%+v want wireguard 1 peer port 51820", unit.Tunnel)
	}
	if unit.Tunnel.Destination != "10.0.0.1" {
		t.Errorf("unit Destination=%q want 10.0.0.1", unit.Tunnel.Destination)
	}
}

func TestDupTunnelBlocksSingleUnchanged14450(t *testing.T) {
	cfg, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        tunnel { mode gre; source 10.0.0.2; destination 10.0.0.1; }
    }
}
`)
	if err != nil {
		t.Fatalf("CompileConfig single: %v", err)
	}
	tc := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel
	if tc.Mode != "gre" || tc.Source != "10.0.0.2" || tc.Destination != "10.0.0.1" || len(tc.WgPeers) != 0 {
		t.Errorf("single tunnel=%+v", tc)
	}
}

func TestDupTunnelBlocksSamePubkeyRejected14450(t *testing.T) {
	_, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key `+dup14450Priv+`;
                peer `+dup14450Peer+` { allowed-ips 10.9.0.0/24; }
            }
        }
        tunnel {
            mode wireguard;
            wireguard {
                peer `+dup14450Peer+` { allowed-ips 10.10.0.0/24; }
            }
        }
    }
}
`)
	if err == nil {
		t.Fatalf("duplicate peer pubkey across blocks must be rejected by existing validateWireguardPeers gate")
	}
	if !strings.Contains(err.Error(), "duplicate peer") {
		t.Errorf("err=%v want duplicate peer", err)
	}
}

func TestDupTunnelBlocksPeersAccumulate14450(t *testing.T) {
	cfg, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key `+dup14450Priv+`;
                peer `+dup14450Peer+` { allowed-ips 10.9.0.0/24; }
            }
        }
        tunnel {
            wireguard {
                peer `+dup14450Peer2+` { allowed-ips 10.10.0.0/24; }
            }
        }
    }
}
`)
	if err != nil {
		t.Fatalf("CompileConfig accumulate: %v", err)
	}
	tc := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel
	if len(tc.WgPeers) != 2 {
		t.Errorf("WgPeers len=%d want 2 accumulated", len(tc.WgPeers))
	}
}

// Unit >0 shares-device decision must use the MERGED mode, not the
// last block's raw mode leaf: interface is wireguard, unit authors
// `mode gre` in block 1 and no mode in block 2 -> merged mode gre ->
// own uN device. Conversely gre-then-wireguard -> wireguard.
func TestDupTunnelBlocksUnitModeNodeShares14450(t *testing.T) {
	// Merged wireguard: unit 1's second block sets wireguard; expect
	// shared device name (no u1) when interface is also wireguard?
	// Simpler decisive shape: no interface tunnel; unit 1 with merged
	// wireguard gets its OWN device (per-unit WG branch) -> name u1.
	// That is covered by name check below via unit tunnel name.
	cfg, err := compileDup14450(t, `
interfaces {
    gr-0/0/0 {
        unit 1 {
            tunnel { mode gre; destination 10.0.0.1; }
            tunnel {
                mode wireguard;
                wireguard {
                    listen-port 51820;
                    private-key `+dup14450Priv+`;
                    peer `+dup14450Peer+` { allowed-ips 10.9.0.0/24; }
                }
            }
        }
    }
}
`)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["gr-0/0/0"].Units[1]
	if unit == nil || unit.Tunnel == nil {
		t.Fatalf("no unit1 tunnel")
	}
	if unit.Tunnel.Mode != "wireguard" {
		t.Errorf("unit1 Mode=%q want wireguard", unit.Tunnel.Mode)
	}
	// No interface WG device to share, so per-unit device keeps u1.
	if unit.Tunnel.Name != "gr-0-0-0u1" {
		t.Errorf("unit1 Name=%q want gr-0-0-0u1", unit.Tunnel.Name)
	}
}

// Interface wireguard + unit blocks where the LAST block has no mode
// but an earlier block sets gre: merged mode is gre, so the unit keeps
// its own device (does NOT share the interface WG device).
func TestDupTunnelBlocksUnitLastBlockNoModeShares14450(t *testing.T) {
	cfg, err := compileDup14450(t, `
interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key `+dup14450Priv+`;
                peer `+dup14450Peer+` { allowed-ips 10.9.0.0/24; }
            }
        }
        unit 1 {
            tunnel { mode gre; destination 10.0.0.1; source 10.0.0.2; }
            tunnel { destination 10.0.0.3; }
        }
    }
}
`)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["wg0"].Units[1]
	if unit == nil || unit.Tunnel == nil {
		t.Fatalf("no wg0 unit1 tunnel")
	}
	if unit.Tunnel.Mode != "gre" {
		t.Errorf("unit1 Mode=%q want gre (earlier block, last block silent)", unit.Tunnel.Mode)
	}
	if unit.Tunnel.Destination != "10.0.0.3" {
		t.Errorf("unit1 Destination=%q want 10.0.0.3 (last block wins)", unit.Tunnel.Destination)
	}
	if unit.Tunnel.Name != "wg0u1" {
		t.Errorf("unit1 Name=%q want wg0u1 (merged gre must not share WG device)", unit.Tunnel.Name)
	}
}

// Collision-gate View 1 must agree with the merged compiler: a second
// block's `mode wireguard` selects single-endpoint naming, and a later
// `mode gre` un-selects it.
func TestDupTunnelBlocksCollisionGateMergedMode14450(t *testing.T) {
	mk := func(blocks string) map[string]struct{} {
		tree, perrs := NewParser("interfaces { gr-0/0/0 { " + blocks + " unit 0 { family inet { address 10.0.0.1/24; } } unit 1 { family inet { address 10.0.1.1/24; } } } }").Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		out := map[string]struct{}{}
		for _, n := range tree.Children {
			if n.Name() == "interfaces" {
				collectTunnelEndpointNamesAST(n, out)
			}
		}
		return out
	}
	wg := mk("tunnel { mode gre; } tunnel { mode wireguard; }")
	if len(wg) != 1 {
		t.Fatalf("merged wireguard refs=%v want exactly 1 (lowest unit)", wg)
	}
	if _, ok := wg["gr-0/0/0.0"]; !ok {
		t.Errorf("merged wireguard refs=%v want gr-0/0/0.0 only", wg)
	}
	gre := mk("tunnel { mode wireguard; } tunnel { mode gre; }")
	if len(gre) != 2 {
		t.Errorf("merged gre refs=%v want 2 per-unit refs", gre)
	}
}
