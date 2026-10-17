package config

import (
	"fmt"
	"strings"
	"testing"
)

// #14409 (DR13-H2): BGP per-neighbor `authentication-key` dropped on a
// packed neighbor line. The reader in applyBGPNeighborProps9192 iterates
// only child.Children, so a packed neighbor node (Children == []) installs
// nothing at all — no passive, no peer-as, no key, no export. That is a
// fail-open: the session comes up with no TCP-MD5 while `show
// configuration` still displays the authored key.
//
// Regression property: for every neighbor head keyword and every
// following-sibling keyword, the packed line must compile identically to
// the braced spelling.

func bgpNeighborsStrict14409(t *testing.T, text string) []*BGPNeighbor {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatal("no BGP compiled")
	}
	// Guard against an empty neighbor slice silently passing below.
	if len(cfg.Protocols.BGP.Neighbors) == 0 {
		t.Fatal("no BGP neighbors compiled — fixture is broken")
	}
	return cfg.Protocols.BGP.Neighbors
}

func bgpNeighborsStrictCompile14409(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) == 0 {
		t.Fatal("no BGP neighbors compiled — fixture is broken")
	}
	return cfg
}

const bracedControl14409 = `protocols { bgp { group G1 { peer-as 65001;
	neighbor 10.0.0.1 { passive; authentication-key NEIGHBORKEY; } } } }`

func TestBGPNeighborPackedAuthKey14409(t *testing.T) {
	// Control: braced spelling installs the key.
	ctrl := bgpNeighborsStrict14409(t, bracedControl14409)
	if got := string(ctrl[0].AuthPassword); got != "NEIGHBORKEY" {
		t.Fatalf("control (braced) AuthPassword = %q, want NEIGHBORKEY", got)
	}
	if !ctrl[0].Passive {
		t.Fatalf("control (braced) Passive = false, want true")
	}

	// Fixture A: unscoped head (passive is not a scoped pair, so the
	// #8662 fold never fires for this line).
	a := bgpNeighborsStrict14409(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 passive authentication-key NEIGHBORKEY; } } }`)
	if got := string(a[0].AuthPassword); got != "NEIGHBORKEY" {
		t.Errorf("fixture A (passive head) AuthPassword = %q, want NEIGHBORKEY", got)
	}
	if !a[0].Passive {
		t.Errorf("fixture A (passive head) Passive = false, want true")
	}

	// Fixture B: scoped head + following group-level export sibling
	// (#8880 decline trips, so the fold is declined).
	b := bgpNeighborsStrict14409(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 peer-as 65001 authentication-key NEIGHBORKEY;
		export EP; } } }`)
	if got := string(b[0].AuthPassword); got != "NEIGHBORKEY" {
		t.Errorf("fixture B (peer-as head + group export) AuthPassword = %q, want NEIGHBORKEY", got)
	}
	if b[0].PeerAS != 65001 {
		t.Errorf("fixture B PeerAS = %d, want 65001", b[0].PeerAS)
	}
}

// TestBGPNeighborPackedSpellingDifferential14409 is the full matrix: every
// neighbor head keyword x several packed continuations, and fixture B
// across several following-sibling keywords. Each packed spelling must
// compile identically (on the neighbor's principal fields) to its braced
// spelling.
func TestBGPNeighborPackedSpellingDifferential14409(t *testing.T) {
	// Each head is a full packed tail fragment that itself carries
	// authentication-key NEIGHBORKEY plus companion state, so the braced
	// control and the packed form can be compared field-by-field.
	heads := []struct {
		name string
		// braced body (statements inside neighbor { ... })
		braced string
		// packed tail (tokens after `neighbor 10.0.0.1`)
		packed string
		check  func(t *testing.T, n *BGPNeighbor)
	}{
		{
			name:   "passive head",
			braced: `passive; authentication-key NEIGHBORKEY;`,
			packed: `passive authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.Passive {
					t.Error("Passive = false, want true")
				}
			},
		},
		{
			name:   "peer-as head",
			braced: `peer-as 65002; authentication-key NEIGHBORKEY;`,
			packed: `peer-as 65002 authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if n.PeerAS != 65002 {
					t.Errorf("PeerAS = %d, want 65002", n.PeerAS)
				}
			},
		},
		{
			name:   "authentication-key head",
			braced: `authentication-key NEIGHBORKEY; passive;`,
			packed: `authentication-key NEIGHBORKEY passive`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.Passive {
					t.Error("Passive = false, want true")
				}
			},
		},
		{
			name:   "description head",
			braced: `description hello; authentication-key NEIGHBORKEY;`,
			packed: `description hello authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if n.Description != "hello" {
					t.Errorf("Description = %q, want hello", n.Description)
				}
			},
		},
		{
			name:   "hold-time head",
			braced: `hold-time 45; authentication-key NEIGHBORKEY;`,
			packed: `hold-time 45 authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if n.HoldTime != 45 {
					t.Errorf("HoldTime = %d, want 45", n.HoldTime)
				}
			},
		},
		{
			name:   "route-reflector-client head",
			braced: `route-reflector-client; authentication-key NEIGHBORKEY;`,
			packed: `route-reflector-client authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.RouteReflectorClient {
					t.Error("RouteReflectorClient = false, want true")
				}
			},
		},
		{
			name:   "default-originate head",
			braced: `default-originate; authentication-key NEIGHBORKEY;`,
			packed: `default-originate authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.DefaultOriginate {
					t.Error("DefaultOriginate = false, want true")
				}
			},
		},
		{
			name:   "remove-private head",
			braced: `remove-private; authentication-key NEIGHBORKEY;`,
			packed: `remove-private authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.RemovePrivateAS {
					t.Error("RemovePrivateAS = false, want true")
				}
			},
		},
		{
			name:   "local-address head",
			braced: `local-address 10.0.0.9; authentication-key NEIGHBORKEY;`,
			packed: `local-address 10.0.0.9 authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if n.LocalAddress != "10.0.0.9" {
					t.Errorf("LocalAddress = %q, want 10.0.0.9", n.LocalAddress)
				}
			},
		},
		{
			name:   "family head",
			braced: `family inet { unicast; } authentication-key NEIGHBORKEY;`,
			packed: `family inet unicast authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.FamilyInet {
					t.Error("FamilyInet = false, want true")
				}
			},
		},
		{
			name:   "bfd head",
			braced: `bfd-liveness-detection { minimum-interval 300; } authentication-key NEIGHBORKEY;`,
			packed: `bfd-liveness-detection minimum-interval 300 authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if !n.BFD {
					t.Error("BFD = false, want true")
				}
				if n.BFDInterval != 300 {
					t.Errorf("BFDInterval = %d, want 300", n.BFDInterval)
				}
			},
		},
		{
			name:   "export head",
			braced: `export EP; authentication-key NEIGHBORKEY;`,
			packed: `export EP authentication-key NEIGHBORKEY`,
			check: func(t *testing.T, n *BGPNeighbor) {
				if len(n.Export) != 1 || n.Export[0] != "EP" {
					t.Errorf("Export = %v, want [EP]", n.Export)
				}
			},
		},
	}

	for _, h := range heads {
		t.Run(h.name, func(t *testing.T) {
			bracedText := fmt.Sprintf(`protocols { bgp { group G1 { peer-as 65001;
				neighbor 10.0.0.1 { %s } } } }`, h.braced)
			packedText := fmt.Sprintf(`protocols { bgp { group G1 { peer-as 65001;
				neighbor 10.0.0.1 %s; } } }`, h.packed)

			bn := bgpNeighborsStrict14409(t, bracedText)
			pn := bgpNeighborsStrict14409(t, packedText)
			if len(bn) != 1 || len(pn) != 1 {
				t.Fatalf("braced=%d packed=%d neighbors, want 1 each", len(bn), len(pn))
			}
			// Positive control: the braced spelling must install the key,
			// otherwise this row cannot observe the field.
			if got := string(bn[0].AuthPassword); got != "NEIGHBORKEY" {
				t.Fatalf("braced control AuthPassword = %q, want NEIGHBORKEY (row cannot observe)", got)
			}
			if got := string(pn[0].AuthPassword); got != "NEIGHBORKEY" {
				t.Errorf("packed AuthPassword = %q, want NEIGHBORKEY (braced installs it)", got)
			}
			h.check(t, pn[0])
			// Spelling differential on the companion field as well.
			if fmt.Sprint(bn[0].Passive) != fmt.Sprint(pn[0].Passive) ||
				bn[0].PeerAS != pn[0].PeerAS || bn[0].HoldTime != pn[0].HoldTime ||
				bn[0].Description != pn[0].Description || bn[0].LocalAddress != pn[0].LocalAddress ||
				bn[0].FamilyInet != pn[0].FamilyInet || bn[0].BFD != pn[0].BFD {
				t.Errorf("packed neighbor differs from braced: packed=%+v braced=%+v", pn[0], bn[0])
			}
		})
	}

	// Following-sibling matrix for fixture B: a group-level statement
	// after the packed neighbor line must not strand the neighbor's key.
	siblings := []string{"export EP;", "import IP;", "peer-as 65001;", "description grp;", "authentication-key GROUPKEY;", "hold-time 90;"}
	for _, sib := range siblings {
		t.Run("following sibling "+strings.Fields(sib)[0], func(t *testing.T) {
			text := fmt.Sprintf(`protocols { bgp { group G1 { peer-as 65001;
				neighbor 10.0.0.1 peer-as 65001 authentication-key NEIGHBORKEY;
				%s } } }`, sib)
			ns := bgpNeighborsStrict14409(t, text)
			if got := string(ns[0].AuthPassword); got != "NEIGHBORKEY" {
				t.Errorf("with following sibling %q: AuthPassword = %q, want NEIGHBORKEY", sib, got)
			}
		})
	}

	// Strict entry point must also install the key for fixture A.
	// A router AS is required for strict compile, hence local-as here.
	cfg := bgpNeighborsStrictCompile14409(t, `protocols { bgp { local-as 65000; group G1 { peer-as 65001;
		neighbor 10.0.0.1 passive authentication-key NEIGHBORKEY; } } }`)
	if got := string(cfg.Protocols.BGP.Neighbors[0].AuthPassword); got != "NEIGHBORKEY" {
		t.Errorf("strict CompileConfig fixture A AuthPassword = %q, want NEIGHBORKEY", got)
	}

	// Mixed: braced children and a packed sibling on the same neighbor.
	// `neighbor 10.0.0.1 { passive; }` plus a second packed node for the
	// same neighbor (the #9192 multi-node shape) must union.
	mixed := bgpNeighborsStrict14409(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 { passive; }
		neighbor 10.0.0.1 authentication-key NEIGHBORKEY; } } }`)
	if len(mixed) != 1 {
		t.Fatalf("mixed braced+packed: %d neighbors, want 1", len(mixed))
	}
	if !mixed[0].Passive {
		t.Errorf("mixed braced+packed: Passive = false, want true")
	}
	if got := string(mixed[0].AuthPassword); got != "NEIGHBORKEY" {
		t.Errorf("mixed braced+packed: AuthPassword = %q, want NEIGHBORKEY", got)
	}
	// Controls that must stay green:
	// - single braced neighbor with key (already asserted as control)
	// - neighbor with no key stays keyless (no invented key)
	noKey := bgpNeighborsStrict14409(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 passive; } } }`)
	if got := string(noKey[0].AuthPassword); got != "" {
		t.Errorf("no-key control AuthPassword = %q, want empty", got)
	}
	if !noKey[0].Passive {
		t.Errorf("no-key control Passive = false, want true")
	}
	// - group key still applies as fallback when neighbor has no own key
	grp := bgpNeighborsStrict14409(t, `protocols { bgp { group G1 { peer-as 65001; authentication-key GROUPKEY;
		neighbor 10.0.0.1 passive; } } }`)
	if got := string(grp[0].AuthPassword); got != "GROUPKEY" {
		t.Errorf("group-key fallback AuthPassword = %q, want GROUPKEY", got)
	}
	// - group key must NOT override an explicit packed neighbor key
	over := bgpNeighborsStrict14409(t, `protocols { bgp { group G1 { peer-as 65001; authentication-key GROUPKEY;
		neighbor 10.0.0.1 passive authentication-key NEIGHBORKEY; } } }`)
	if got := string(over[0].AuthPassword); got != "NEIGHBORKEY" {
		t.Errorf("neighbor-over-group AuthPassword = %q, want NEIGHBORKEY", got)
	}
}
