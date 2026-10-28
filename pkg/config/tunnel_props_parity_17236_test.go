// #17236 (R4-Q23-04): the tunnel property reader existed twice inside
// compileInterfaces — an interface-level switch and a unit-level switch
// over the same 10 leaves. #13215 fixed one copy and the unit twin
// shipped the inherited-peer / plaintext-GRE bug until #14440, which
// extracted the braced pre-pass but left the main switch duplicated.
// applyTunnelProps17236 is now the single reader; both call sites
// decide only whether a numeric quarantine skips the interface or
// the unit.
//
// This file pins the two acceptance guards:
//  1. a source guard: exactly one tunnel property switch exists in
//     the non-test package, compiler_interfaces.go holds none of it,
//     and both compileInterfaces tunnel sites call the shared helper
//     (so a future edit cannot re-fork the reader silently);
//  2. a parity table: every tunnel leaf compiles identically at
//     interface and unit level in braced, packed and flat-set
//     spellings, including the strict/lenient numeric outcomes.
package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestTunnelPropertySwitchIsSingle17236 is the source guard for
// #17236's acceptance: `grep -c 'case "keepalive-retry"'
// pkg/config/compiler_interfaces.go` == 0 and exactly one tunnel
// property switch exists in the package.
func TestTunnelPropertySwitchIsSingle17236(t *testing.T) {
	ci, err := os.ReadFile("compiler_interfaces.go")
	if err != nil {
		t.Fatalf("read compiler_interfaces.go: %v", err)
	}
	if n := strings.Count(string(ci), `case "keepalive-retry"`); n != 0 {
		t.Errorf("compiler_interfaces.go has %d `case \"keepalive-retry\"`, want 0 (tunnel switch must live only in applyTunnelProps17236)", n)
	}
	if n := strings.Count(string(ci), "applyTunnelProps17236("); n != 2 {
		t.Errorf("compiler_interfaces.go calls applyTunnelProps17236 %d times, want 2 (interface + unit sites)", n)
	}

	tf, err := os.ReadFile("tunnel_flat_run_9156.go")
	if err != nil {
		t.Fatalf("read tunnel_flat_run_9156.go: %v", err)
	}
	// The shared switch is the only `case "keepalive-retry"` in the
	// helper file besides the braced-scalar pre-pass (which handles
	// only source/destination/mode/keepalive/keepalive-retry and is
	// not a property switch: no key/ttl/routing-instance/wireguard).
	if n := strings.Count(string(tf), `case "keepalive-retry"`); n != 2 {
		t.Errorf("tunnel_flat_run_9156.go has %d `case \"keepalive-retry\"`, want 2 (shared switch + braced pre-pass)", n)
	}
	// Leaves the pre-pass does NOT handle must appear exactly once
	// (the shared switch). source/destination/mode/keepalive/
	// keepalive-retry appear twice (pre-pass + switch) by design.
	for _, leaf := range []string{
		`case "key"`, `case "ttl"`, `case "routing-instance"`,
		`case "wireguard"`, `case "clear-dont-fragment-bit"`,
	} {
		if n := strings.Count(string(tf), leaf); n != 1 {
			t.Errorf("tunnel_flat_run_9156.go has %d %s, want exactly 1 (single tunnel property switch)", n, leaf)
		}
	}
	for _, leaf := range []string{
		`case "source"`, `case "destination"`, `case "mode"`,
	} {
		if n := strings.Count(string(tf), leaf); n != 2 {
			t.Errorf("tunnel_flat_run_9156.go has %d %s, want 2 (braced pre-pass + shared switch)", n, leaf)
		}
	}
}

// tunnelLeaf17236 is one row of the parity table: a leaf spelling in
// each of the three AST shapes, plus whether the strict channel must
// reject it and the lenient channel must warn-and-quarantine.
type tunnelLeaf17236 struct {
	name string
	// braced is the hierarchical spelling inside `tunnel { ... }`.
	braced string
	// flat is the `set interfaces gr-0/0/0 [unit 0] tunnel ...` tail.
	flat string
	// numeric marks key/ttl rows where strict rejects and lenient
	// quarantines; wantKey/wantTTL carry the expected bad raw token.
	badRaw string
	// check asserts the leaf landed on tc (called for good rows).
	check func(t *testing.T, tc *TunnelConfig)
}

func tunnelLeaves17236() []tunnelLeaf17236 {
	return []tunnelLeaf17236{
		{
			name:   "source",
			braced: "source 10.9.0.1;",
			flat:   "source 10.9.0.1",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Source != "10.9.0.1" {
					t.Errorf("Source = %q, want 10.9.0.1", tc.Source)
				}
			},
		},
		{
			name:   "destination",
			braced: "destination 10.9.0.2;",
			flat:   "destination 10.9.0.2",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Destination != "10.9.0.2" {
					t.Errorf("Destination = %q, want 10.9.0.2", tc.Destination)
				}
			},
		},
		{
			name:   "mode",
			braced: "mode ipip;",
			flat:   "mode ipip",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Mode != TunnelModeIPIP {
					t.Errorf("Mode = %q, want ipip", tc.Mode)
				}
			},
		},
		{
			name:   "key good",
			braced: "key 4242;",
			flat:   "key 4242",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Key != 4242 {
					t.Errorf("Key = %d, want 4242", tc.Key)
				}
			},
		},
		{
			name:   "key bad strict+lenient",
			braced: "key 4294967296;",
			flat:   "key 4294967296",
			badRaw: "key",
		},
		{
			name:   "ttl good",
			braced: "ttl 99;",
			flat:   "ttl 99",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.TTL != 99 {
					t.Errorf("TTL = %d, want 99", tc.TTL)
				}
			},
		},
		{
			name:   "ttl bad strict+lenient",
			braced: "ttl 0;",
			flat:   "ttl 0",
			badRaw: "ttl",
		},
		{
			name:   "keepalive",
			braced: "keepalive 17;",
			flat:   "keepalive 17",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Keepalive != 17 {
					t.Errorf("Keepalive = %d, want 17", tc.Keepalive)
				}
			},
		},
		{
			name:   "keepalive-retry",
			braced: "keepalive-retry 4;",
			flat:   "keepalive-retry 4",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.KeepaliveRetry != 4 {
					t.Errorf("KeepaliveRetry = %d, want 4", tc.KeepaliveRetry)
				}
			},
		},
		{
			name:   "routing-instance",
			braced: "routing-instance { destination VR1; }",
			flat:   "routing-instance destination VR1",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.RoutingInstance != "VR1" {
					t.Errorf("RoutingInstance = %q, want VR1", tc.RoutingInstance)
				}
			},
		},
		{
			name:   "clear-dont-fragment-bit",
			braced: "clear-dont-fragment-bit;",
			flat:   "clear-dont-fragment-bit",
			check: func(t *testing.T, tc *TunnelConfig) {
				if !tc.ClearDontFragmentBit {
					t.Errorf("ClearDontFragmentBit = false, want true")
				}
			},
		},
		{
			name:   "wireguard",
			braced: "mode wireguard; wireguard { listen-port 51820; private-key " + wgKeyA + "; peer " + wgKeyB + " { allowed-ips 10.9.0.0/24; } }",
			flat:   "mode wireguard",
			check: func(t *testing.T, tc *TunnelConfig) {
				if tc.Mode != TunnelModeWireGuard {
					t.Errorf("Mode = %q, want wireguard", tc.Mode)
				}
			},
		},
	}
}

// ifaceTunnel17236 returns the interface-level tunnel of gr-0/0/0.
// The unit tunnel inherits via cloneForUnit, so parity is compared
// after stripping the caller-owned fields (Name, Addresses).
func ifaceTunnel17236(t *testing.T, cfg *Config) *TunnelConfig {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatalf("gr-0/0/0 missing: %v", cfg.Interfaces.Interfaces)
	}
	return ifc.Tunnel
}

func unitTunnel17236(t *testing.T, cfg *Config) *TunnelConfig {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatalf("gr-0/0/0 missing: %v", cfg.Interfaces.Interfaces)
	}
	u := ifc.Units[0]
	if u == nil {
		return nil
	}
	return u.Tunnel
}

// stripCallerOwned17236 removes the fields the two call sites own
// differently (device name; addresses appended later) so the
// property-read result can be DeepEqual-compared across levels.
func stripCallerOwned17236(tc *TunnelConfig) *TunnelConfig {
	if tc == nil {
		return nil
	}
	c := *tc
	c.Name = ""
	c.Addresses = nil
	if len(c.WgPeers) == 0 {
		c.WgPeers = nil
	}
	return &c
}

func compileBraced17236(t *testing.T, unit bool, leaf string) *Config {
	t.Helper()
	var body string
	if unit {
		body = "interfaces { gr-0/0/0 { unit 0 { tunnel { " + leaf + " } } } } routing-instances { VR1 { instance-type virtual-router; } }"
	} else {
		body = "interfaces { gr-0/0/0 { tunnel { " + leaf + " } } } routing-instances { VR1 { instance-type virtual-router; } }"
	}
	cfg, err := CompileConfig(parseHierText(t, body))
	if err != nil {
		t.Fatalf("braced unit=%v leaf %q: %v", unit, leaf, err)
	}
	return cfg
}

func compileFlat17236(t *testing.T, unit bool, leaf string) *Config {
	t.Helper()
	prefix := "set interfaces gr-0/0/0 tunnel "
	if unit {
		prefix = "set interfaces gr-0/0/0 unit 0 tunnel "
	}
	cfg, err := CompileConfig(parseSetCommands(t,
		prefix+leaf,
		"set routing-instances VR1 instance-type virtual-router",
	))
	if err != nil {
		t.Fatalf("flat unit=%v leaf %q: %v", unit, leaf, err)
	}
	return cfg
}

// compilePacked17236 builds the packed spelling: the whole tunnel
// stanza on one hierarchical line (`tunnel { <leaf> ... };` inside a
// one-line interface body), which packedBody expands.
func compilePacked17236(t *testing.T, unit bool, leaf string) *Config {
	t.Helper()
	// Packed = several leaves packed into one tunnel block on a
	// single line; the leaf under test rides with a source so the
	// tunnel is well-formed.
	var body string
	if unit {
		body = "interfaces { gr-0/0/0 { unit 0 { tunnel { source 10.9.0.1; " + leaf + " } } } } routing-instances { VR1 { instance-type virtual-router; } }"
	} else {
		body = "interfaces { gr-0/0/0 { tunnel { source 10.9.0.1; " + leaf + " } } } routing-instances { VR1 { instance-type virtual-router; } }"
	}
	cfg, err := CompileConfig(parseHierText(t, body))
	if err != nil {
		t.Fatalf("packed unit=%v leaf %q: %v", unit, leaf, err)
	}
	return cfg
}

func TestTunnelPropsParity17236(t *testing.T) {
	for _, leaf := range tunnelLeaves17236() {
		t.Run(leaf.name, func(t *testing.T) {
			if leaf.badRaw != "" {
				// Strict must reject at BOTH levels naming the leaf;
				// lenient must warn and quarantine (interface: no
				// tunnel survives / unit: unit skipped).
				for _, unit := range []bool{false, true} {
					func() {
						prefix := "set interfaces gr-0/0/0 tunnel "
						if unit {
							prefix = "set interfaces gr-0/0/0 unit 0 tunnel "
						}
						tree := parseSetCommands(t, prefix+leaf.flat)
						if _, err := CompileConfig(tree); err == nil {
							t.Errorf("strict unit=%v %q accepted, want rejection", unit, leaf.flat)
						} else if !strings.Contains(err.Error(), leaf.badRaw) {
							t.Errorf("strict unit=%v error %q must name %q", unit, err, leaf.badRaw)
						}
						ltree := parseSetCommands(t, prefix+leaf.flat)
						cfg, err := CompileConfigLenient(ltree)
						if err != nil {
							t.Fatalf("lenient unit=%v %q: %v", unit, leaf.flat, err)
						}
						joined := strings.Join(cfg.Warnings, "\n")
						if !strings.Contains(joined, leaf.badRaw) {
							t.Errorf("lenient unit=%v warnings %q must name %q", unit, joined, leaf.badRaw)
						}
						if unit {
							// Unit may be absent (quarantined) — do
							// not fatal on the missing interface.
							if cfg.Interfaces.Interfaces["gr-0/0/0"] != nil {
								if u := unitTunnel17236(t, cfg); u != nil {
									t.Errorf("lenient unit tunnel survived quarantine: %+v", u)
								}
							}
							if !strings.Contains(joined, "skipping unit 0") {
								t.Errorf("lenient unit warnings %q must say skipping unit 0", joined)
							}
						} else {
							if cfg.Interfaces.Interfaces["gr-0/0/0"] != nil {
								if tc := ifaceTunnel17236(t, cfg); tc != nil {
									t.Errorf("lenient iface tunnel survived quarantine: %+v", tc)
								}
							}
							if !strings.Contains(joined, "quarantining interface") {
								t.Errorf("lenient iface warnings %q must say quarantining interface", joined)
							}
						}
					}()
				}
				return
			}

			// Good leaf: braced, packed and flat-set must agree at
			// each level, and interface vs unit must agree after
			// stripping caller-owned fields. The unit fixture has
			// no interface tunnel, so nothing is inherited.
			if leaf.name == "wireguard" {
				// Flat wireguard needs its key material spelled as
				// separate set lines; the braced row above already
				// covers the leaf, so compare braced iface vs unit
				// only (plus packed, which reuses the braced body).
				ib := stripCallerOwned17236(ifaceTunnel17236(t, compileBraced17236(t, false, leaf.braced)))
				ub := stripCallerOwned17236(unitTunnel17236(t, compileBraced17236(t, true, leaf.braced)))
				if ib == nil || ub == nil {
					t.Fatalf("wireguard tunnels: iface=%+v unit=%+v", ib, ub)
				}
				leaf.check(t, ib)
				if !reflect.DeepEqual(ib, ub) {
					t.Errorf("wireguard parity: iface %+v != unit %+v", ib, ub)
				}
				return
			}

			ib := stripCallerOwned17236(ifaceTunnel17236(t, compileBraced17236(t, false, leaf.braced)))
			ub := stripCallerOwned17236(unitTunnel17236(t, compileBraced17236(t, true, leaf.braced)))
			if ib == nil {
				t.Fatalf("iface braced %q: tunnel nil", leaf.braced)
			}
			if ub == nil {
				t.Fatalf("unit braced %q: tunnel nil", leaf.braced)
			}
			leaf.check(t, ib)
			leaf.check(t, ub)
			if !reflect.DeepEqual(ib, ub) {
				t.Errorf("braced parity %s: iface %+v != unit %+v", leaf.name, ib, ub)
			}

			ip := stripCallerOwned17236(ifaceTunnel17236(t, compilePacked17236(t, false, leaf.braced)))
			up := stripCallerOwned17236(unitTunnel17236(t, compilePacked17236(t, true, leaf.braced)))
			if ip == nil || up == nil {
				t.Fatalf("packed %s: iface=%+v unit=%+v", leaf.name, ip, up)
			}
			// Packed rides with a `source 10.9.0.1` sibling (see
			// compilePacked17236); expect it on top of the braced
			// result unless the leaf itself is source.
			wantPI, wantPU := *ib, *ub
			if leaf.name != "source" {
				wantPI.Source = "10.9.0.1"
				wantPU.Source = "10.9.0.1"
			}
			if !reflect.DeepEqual(&wantPI, ip) {
				t.Errorf("packed vs braced iface %s: %+v != %+v", leaf.name, ip, &wantPI)
			}
			if !reflect.DeepEqual(&wantPU, up) {
				t.Errorf("packed vs braced unit %s: %+v != %+v", leaf.name, up, &wantPU)
			}

			ifl := stripCallerOwned17236(ifaceTunnel17236(t, compileFlat17236(t, false, leaf.flat)))
			ufl := stripCallerOwned17236(unitTunnel17236(t, compileFlat17236(t, true, leaf.flat)))
			if ifl == nil || ufl == nil {
				t.Fatalf("flat %s: iface=%+v unit=%+v", leaf.name, ifl, ufl)
			}
			// Flat-set carries no source sibling, so the packed/
			// braced `source 10.9.0.1` rider is absent; compare
			// against the braced result with Source cleared when
			// the leaf itself is not source.
			wantI, wantU := ib, ub
			if leaf.name != "source" {
				wi, wu := *ib, *ub
				wi.Source, wu.Source = "", ""
				wantI, wantU = &wi, &wu
			}
			if !reflect.DeepEqual(wantI, ifl) {
				t.Errorf("flat vs braced iface %s: %+v != %+v", leaf.name, ifl, wantI)
			}
			if !reflect.DeepEqual(wantU, ufl) {
				t.Errorf("flat vs braced unit %s: %+v != %+v", leaf.name, ufl, wantU)
			}
		})
	}
}
