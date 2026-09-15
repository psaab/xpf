package config

import (
	"strings"
	"testing"
)

// #9883: a braced filter under an UNKNOWN address family folded into the IPv4
// pool on the tolerant path while the #9017 warning told the operator it
// compiles to NOTHING — an inverted diagnostic. The fix quarantines
// undeclared families out of BOTH pools in compileFirewall, making the message
// true on every route. Each cell below asserts the message text and the pool
// membership AGREE (the issue's acceptance), on both ingress routes.

func hier9883(t *testing.T, text string) *ConfigTree {
	t.Helper()
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse hierarchical: %v", perrs)
	}
	return &ConfigTree{Children: root.Children}
}

// TestUnknownFamilyMessageAndPoolsAgree9883 is the defect itself, one cell per
// route: flat-set and braced spellings of a filter under `family inett` must
// both warn (lenient) / reject (strict) with the NOTHING message AND leave the
// filter out of both pools. Before the fix the braced lenient cell installed
// BAD into FiltersInet while warning it enforces nothing.
func TestUnknownFamilyMessageAndPoolsAgree9883(t *testing.T) {
	const filter = "BAD"
	routes := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"flat-set", func(t *testing.T) *ConfigTree {
			return buildTree(t, []string{
				"set firewall family inett filter BAD term T1 from protocol tcp",
				"set firewall family inett filter BAD term T1 then discard",
			})
		}},
		{"braced", func(t *testing.T) *ConfigTree {
			return hier9883(t, `firewall {
				family inett {
					filter BAD {
						term T1 {
							from { protocol tcp; }
							then { discard; }
						}
					}
				}
			}`)
		}},
	}
	for _, r := range routes {
		t.Run(r.name+"/strict-rejects", func(t *testing.T) {
			_, err := CompileConfig(r.tree(t))
			if err == nil {
				t.Fatalf("strict compile accepted family %q", "inett")
			}
			if !strings.Contains(err.Error(), "inett") ||
				!strings.Contains(err.Error(), "compiles to NOTHING") {
				t.Fatalf("strict refusal must name the token and say NOTHING: %v", err)
			}
		})
		t.Run(r.name+"/lenient-warns-and-installs-nothing", func(t *testing.T) {
			cfg, err := CompileConfigLenient(r.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must not brick on an unknown family (#1960): %v", err)
			}
			var warned bool
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "inett") && strings.Contains(w, "compiles to NOTHING") {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("lenient path said NOTHING about family %q (warnings=%v)", "inett", cfg.Warnings)
			}
			// THE AGREEMENT: the message says NOTHING is installed, so neither
			// pool may carry the filter.
			if _, ok := cfg.Firewall.FiltersInet[filter]; ok {
				t.Errorf("quarantine breach: %q landed in FiltersInet while the warning says NOTHING", filter)
			}
			if _, ok := cfg.Firewall.FiltersInet6[filter]; ok {
				t.Errorf("quarantine breach: %q landed in FiltersInet6 while the warning says NOTHING", filter)
			}
			if got := len(cfg.Firewall.FiltersInet) + len(cfg.Firewall.FiltersInet6); got != 0 {
				t.Errorf("unknown-family filter minted %d pool entries, want 0", got)
			}
		})
	}
}

// TestDeclaredFamiliesStillInstall9883 guards the quarantine against
// overreach: inet/inet6/any must keep installing exactly where they did, with
// no unknown-token warning, on both routes.
func TestDeclaredFamiliesStillInstall9883(t *testing.T) {
	for _, tc := range []struct {
		family      string
		inet, inet6 int
	}{
		{"inet", 1, 0},
		{"inet6", 0, 1},
		{"any", 1, 1},
	} {
		t.Run("flat-"+tc.family, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, []string{
				"set firewall family " + tc.family + " filter OK term T1 from protocol tcp",
				"set firewall family " + tc.family + " filter OK term T1 then discard",
			}))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			assertDeclaredInstall9883(t, cfg, tc.family, tc.inet, tc.inet6)
		})
		t.Run("braced-"+tc.family, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hier9883(t, `firewall {
				family `+tc.family+` {
					filter OK {
						term T1 {
							from { protocol tcp; }
							then { discard; }
						}
					}
				}
			}`))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			assertDeclaredInstall9883(t, cfg, tc.family, tc.inet, tc.inet6)
		})
	}
}

func assertDeclaredInstall9883(t *testing.T, cfg *Config, family string, wantInet, wantInet6 int) {
	t.Helper()
	if got := len(cfg.Firewall.FiltersInet); got != wantInet {
		t.Errorf("family %s: FiltersInet = %d, want %d", family, got, wantInet)
	}
	if got := len(cfg.Firewall.FiltersInet6); got != wantInet6 {
		t.Errorf("family %s: FiltersInet6 = %d, want %d", family, got, wantInet6)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "not a known address family") {
			t.Errorf("family %s: declared family drew an unknown-token warning: %s", family, w)
		}
	}
}

// TestUnknownFamilyEscapesCollisionGate9883: the #3884 gate exists to catch
// last-write-wins overwrites in FiltersInet. A quarantined family writes
// nothing, so `inett/X` + `inet/X` must NOT draw the collision warning —
// otherwise the two gates contradict each other on one config (the same
// defect class, moved not fixed). The token gate names the typo instead, and
// the declared filter installs alone.
func TestUnknownFamilyEscapesCollisionGate9883(t *testing.T) {
	text := `firewall {
		family inett {
			filter X { term T1 { then { discard; } } }
		}
		family inet {
			filter X { term T1 { then { accept; } } }
		}
	}`
	t.Run("strict-names-the-token", func(t *testing.T) {
		_, err := CompileConfig(hier9883(t, text))
		if err == nil {
			t.Fatal("strict compile accepted an unknown family, want rejection")
		}
		if !strings.Contains(err.Error(), "inett") {
			t.Fatalf("strict refusal must name the unknown token: %v", err)
		}
		if strings.Contains(err.Error(), "#3884") || strings.Contains(err.Error(), "silently overwrites") {
			t.Fatalf("strict refusal blamed the collision gate instead of the typo: %v", err)
		}
	})
	t.Run("lenient-token-warning-only", func(t *testing.T) {
		cfg, err := CompileConfigLenient(hier9883(t, text))
		if err != nil {
			t.Fatalf("lenient compile must not brick (#1960): %v", err)
		}
		var tokenWarned bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "inett") {
				tokenWarned = true
			}
			if strings.Contains(w, "#3884") || strings.Contains(w, "silently overwrites") {
				t.Errorf("quarantined family drew a collision warning for an overwrite that cannot happen: %s", w)
			}
		}
		if !tokenWarned {
			t.Fatalf("lenient path did not warn about family %q (warnings=%v)", "inett", cfg.Warnings)
		}
		// The declared definition installs alone — nothing overwrote it.
		got, ok := cfg.Firewall.FiltersInet["X"]
		if !ok {
			t.Fatalf("declared family inet filter X was not installed (pools: inet=%d inet6=%d)",
				len(cfg.Firewall.FiltersInet), len(cfg.Firewall.FiltersInet6))
		}
		if len(got.Terms) != 1 || got.Terms[0].Action != "accept" {
			t.Errorf("inet/X installed with wrong terms (quarantined copy leaked in?): %+v", got.Terms)
		}
	})
}

// TestHookedQuarantinedFilterDanglesLenient9883: an interface hook naming a
// quarantined filter dangles. Strict rejects the token; lenient boots with
// BOTH warnings true at once (unknown token + dangling reference) and empty
// pools — the snapshot-integrity backstop then refuses to publish (fail-closed,
// #3296), so the hook never degrades to Accept.
func TestHookedQuarantinedFilterDanglesLenient9883(t *testing.T) {
	text := `firewall {
		family inett {
			filter BAD { term T1 { then { discard; } } }
		}
	}
	interfaces {
		ge-0/0/0 {
			unit 0 {
				family inet {
					filter { input BAD; }
				}
			}
		}
	}`
	t.Run("strict-rejects", func(t *testing.T) {
		_, err := CompileConfig(hier9883(t, text))
		if err == nil {
			t.Fatal("strict compile accepted an unknown family with a hook, want rejection")
		}
		if !strings.Contains(err.Error(), "inett") {
			t.Fatalf("strict refusal must name the unknown token: %v", err)
		}
	})
	t.Run("lenient-warns-twice-pools-empty", func(t *testing.T) {
		cfg, err := CompileConfigLenient(hier9883(t, text))
		if err != nil {
			t.Fatalf("lenient compile must not brick (#1960): %v", err)
		}
		var tokenWarned, danglingWarned bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "inett") {
				tokenWarned = true
			}
			if strings.Contains(w, "undefined filter") {
				danglingWarned = true
			}
		}
		if !tokenWarned {
			t.Errorf("missing unknown-token warning (warnings=%v)", cfg.Warnings)
		}
		if !danglingWarned {
			t.Errorf("missing dangling-reference warning for the hooked quarantine (warnings=%v)", cfg.Warnings)
		}
		if _, ok := cfg.Firewall.FiltersInet["BAD"]; ok {
			t.Errorf("quarantine breach: hooked BAD landed in FiltersInet")
		}
		if _, ok := cfg.Firewall.FiltersInet6["BAD"]; ok {
			t.Errorf("quarantine breach: hooked BAD landed in FiltersInet6")
		}
		// The hook itself is still recorded — only its target is absent.
		u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
		if u.FilterInputV4 != "BAD" {
			t.Errorf("interface hook lost: FilterInputV4=%q, want %q", u.FilterInputV4, "BAD")
		}
	})
}
