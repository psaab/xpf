package config

import (
	"strings"
	"testing"
)

// #16001 (EX-4): the #4426 gate warned on the tolerant path but the
// dual-compiled term still installed, so a v4-only `except` prefix-list
// under `family any` evaluated `except` over an empty v6 set in the inet6
// pool and matched EVERY v6 packet (fail-open over-accept on `then
// accept`). The fix marks the uncovered pool's term
// UncoveredFamilyExcept16001; builders refuse the candidate whole.
//
// FAIL-ON-REVERT: dropping the site collection (or the marking) makes the
// marker assertions below go RED while the warning assertions stay green
// — exactly the pre-fix warn-but-install behavior.

const uncoveredExceptTree16001 = `
policy-options {
    prefix-list mgmt-v4 {
        10.0.0.0/8;
    }
}
firewall {
    family any {
        filter permitMgmt {
            term t {
                from {
                    source-prefix-list {
                        mgmt-v4 except;
                    }
                }
                then {
                    accept;
                }
            }
        }
    }
}
`

func TestUncoveredFamilyExceptLenientMarksInet6Only16001(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHierText(t, uncoveredExceptTree16001))
	if err != nil {
		t.Fatalf("CompileConfigLenient must still boot (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") && strings.Contains(w, "mgmt-v4") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the #4426 lenient warning to remain, got: %v", cfg.Warnings)
	}
	v6 := cfg.Firewall.FiltersInet6["permitMgmt"]
	if v6 == nil || len(v6.Terms) != 1 {
		t.Fatalf("inet6 pool must still carry the dual-compiled filter, got %+v", v6)
	}
	if !v6.Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("the uncovered inet6 arm must be marked UncoveredFamilyExcept16001 (#16001)")
	}
	v4 := cfg.Firewall.FiltersInet["permitMgmt"]
	if v4 == nil || len(v4.Terms) != 1 {
		t.Fatalf("inet pool must still carry the dual-compiled filter, got %+v", v4)
	}
	if v4.Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("the covered inet arm (the list DOES cover v4) must NOT be marked — its authored except semantics survive")
	}
}

// The mirror: a v6-only `except` list under `family any` marks the inet
// arm only.
func TestUncoveredFamilyExceptV6OnlyMarksInetOnly16001(t *testing.T) {
	tree := parseHierText(t, `
policy-options {
    prefix-list mgmt-v6 {
        2001:db8::/32;
    }
}
firewall {
    family any {
        filter permitMgmt6 {
            term t {
                from {
                    destination-prefix-list {
                        mgmt-v6 except;
                    }
                }
                then {
                    accept;
                }
            }
        }
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if !cfg.Firewall.FiltersInet["permitMgmt6"].Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("v6-only except under family any must mark the uncovered inet arm")
	}
	if cfg.Firewall.FiltersInet6["permitMgmt6"].Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("the covered inet6 arm must NOT be marked")
	}
}

// Single-family wrong-family `except` (#14446 shape) marks its own pool.
func TestUncoveredFamilyExceptSingleFamilyPool16001(t *testing.T) {
	tree := parseHierText(t, `
policy-options {
    prefix-list v4-only {
        10.0.0.0/8;
    }
}
firewall {
    family inet6 {
        filter f {
            term t {
                from {
                    source-prefix-list v4-only except;
                }
                then accept;
            }
        }
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	f := cfg.Firewall.FiltersInet6["f"]
	if f == nil || len(f.Terms) != 1 || !f.Terms[0].UncoveredFamilyExcept16001 {
		t.Fatalf("inet6 term with a v4-only except scope must be marked, got %+v", f)
	}
}

// A single-family POSITIVE list merely under-blocks (its arm matches
// nothing and falls through — the posture the committing binary already
// had), so it must NOT be poisoned: warn-but-apply stays correct there.
func TestUncoveredFamilyPositiveNotMarked16001(t *testing.T) {
	tree := parseHierText(t, `
policy-options {
    prefix-list v4-blocks {
        10.0.0.0/8;
    }
}
firewall {
    family any {
        filter blockNet {
            term t {
                from {
                    source-prefix-list v4-blocks;
                }
                then discard;
            }
        }
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	for pool, filters := range map[string]map[string]*FirewallFilter{
		"inet": cfg.Firewall.FiltersInet, "inet6": cfg.Firewall.FiltersInet6,
	} {
		term := filters["blockNet"].Terms[0]
		if term.UncoveredFamilyExcept16001 {
			t.Fatalf("positive single-family list must NOT be marked (%s pool)", pool)
		}
	}
}

// Controls: a mixed-family `except` list and a matched single-family
// `except` list cover their pools and must NOT be marked (anti-over-fix).
func TestUncoveredFamilyExceptControlsNotMarked16001(t *testing.T) {
	tree := parseHierText(t, `
policy-options {
    prefix-list dual {
        10.0.0.0/8;
        2001:db8::/32;
    }
    prefix-list v4-only {
        10.0.0.0/8;
    }
}
firewall {
    family any {
        filter mixed {
            term t {
                from {
                    source-prefix-list dual except;
                }
                then discard;
            }
        }
    }
    family inet {
        filter matched {
            term t {
                from {
                    source-prefix-list v4-only except;
                }
                then discard;
            }
        }
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if cfg.Firewall.FiltersInet["mixed"].Terms[0].UncoveredFamilyExcept16001 ||
		cfg.Firewall.FiltersInet6["mixed"].Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("mixed-family except covers both families and must NOT be marked")
	}
	if cfg.Firewall.FiltersInet["matched"].Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("a v4 except list under family inet covers its pool and must NOT be marked")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") {
			t.Fatalf("unexpected #4426 warning on covering controls: %q", w)
		}
	}
}

// Fold (PR #16342, Opus): a term carrying a SPECIFIC positive literal
// alongside an opposite-family sole-`except` list must NOT be marked.
// The resolver is positive-wins for that direction (#3359): the literal
// is preserved as the scope and the `except` list is dropped, so no
// empty-except match-all ever forms. Over-refusing it would discard a
// candidate whose uncovered arm is a plain constrained positive match.
// A match-any literal (0.0.0.0/0) composes INTO the sole-except form
// (#4338) and must STAY marked — the control half of the fixture.
func TestUncoveredFamilyExceptSpecificLiteralExempt16001(t *testing.T) {
	build := func(srcAddr string) *ConfigTree {
		return parseHierText(t, `
policy-options {
    prefix-list mgmt-v6 {
        2001:db8::/32;
    }
}
firewall {
    family any {
        filter mixed {
            term t {
                from {
                    source-address `+srcAddr+`;
                    source-prefix-list mgmt-v6 except;
                }
                then accept;
            }
        }
    }
}
`)
	}
	// Specific v4 literal + v6-only except: positive-wins on both arms.
	cfg, err := CompileConfigLenient(build("10.0.0.0/8"))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	for pool, filters := range map[string]map[string]*FirewallFilter{
		"inet": cfg.Firewall.FiltersInet, "inet6": cfg.Firewall.FiltersInet6,
	} {
		f := filters["mixed"]
		if f == nil || len(f.Terms) != 1 {
			t.Fatalf("%s pool must carry the mixed filter, got %+v", pool, f)
		}
		if f.Terms[0].UncoveredFamilyExcept16001 {
			t.Fatalf("specific-literal + except term must NOT be marked (%s pool): the resolver preserves the literal (positive-wins, #3359)", pool)
		}
		if len(f.Terms[0].SourceAddresses) != 1 || f.Terms[0].SourceAddresses[0] != "10.0.0.0/8" {
			t.Fatalf("the specific literal must survive compilation (%s pool), got %v", pool, f.Terms[0].SourceAddresses)
		}
	}
	// Control: match-any literal + same except composes to sole-except
	// (#4338), so the uncovered (inet) arm STAYS marked.
	cfg2, err := CompileConfigLenient(build("0.0.0.0/0"))
	if err != nil {
		t.Fatalf("CompileConfigLenient (match-any control): %v", err)
	}
	if !cfg2.Firewall.FiltersInet["mixed"].Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("match-any literal + v6-only except must STAY marked on the uncovered inet arm (#4338 compose)")
	}
	if cfg2.Firewall.FiltersInet6["mixed"].Terms[0].UncoveredFamilyExcept16001 {
		t.Fatal("the covered inet6 arm of the match-any control must NOT be marked")
	}
}

// Strict commit still rejects outright (the marker is a tolerant-path
// channel only; a strict config never carries it because compile fails).
func TestUncoveredFamilyExceptStrictStillRejects16001(t *testing.T) {
	if _, err := CompileConfig(parseHierText(t, uncoveredExceptTree16001)); err == nil {
		t.Fatal("strict CompileConfig must still reject the v4-only except under family any (#4426)")
	}
}
