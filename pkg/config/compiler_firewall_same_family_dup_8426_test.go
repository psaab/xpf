package config

import (
	"strings"
	"testing"
)

// #8426: a filter name defined TWICE under ONE family.
//
// #3884 rejects the same name under multiple non-inet6 families. It is
// structurally blind to this case, and deliberately so: the set it walks is
// documented as "the ordered set of DISTINCT non-inet6 families", and `record`
// returns early on a family it has already seen — "not a cross-family reuse".
// So two `family inet filter F` blocks yield len(fams) == 1, the `len(fams) < 2`
// guard skips them, and compilation reaches the unconditional
// `dest[filter.Name] = filter`.
//
// The consequence is the one #3884's own message describes: the later block
// replaces the earlier WHOLE, so a `then discard` becomes accept-all.
//
// Fixtures are HIERARCHICAL for the reason #4287 records: the flat `set` parser
// does not mint two structured filter instances for one name.

// RED-on-revert: strict commit must refuse. Reverting the #8426 gate compiles
// clean and silently drops the discard.
func TestDuplicateSameFamilyFilterRejectedStrict8426(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
        filter blockX {
            term t2 {
                then {
                    accept;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: a filter name defined twice under ONE family must be " +
			"rejected — the second block replaces the first whole, so the `then discard` " +
			"is silently dropped and the effective filter is accept-all (#8426)")
	}
	if !strings.Contains(err.Error(), "blockX") || !strings.Contains(err.Error(), "#8426") {
		t.Fatalf("the refusal must name the filter and the issue so an operator can act "+
			"on it; got: %v", err)
	}
}

// The inet6 half. inet6 filters live in their own FiltersInet6 pool so they
// cannot collide cross-family — but the write into that pool is the same
// last-writer-wins, and the pre-#8426 code recorded inet6 names into a BOOL set
// (`inet6Names`), which cannot count. Without this cell a fix that guarded only
// the non-inet6 branch would pass.
func TestDuplicateSameFamilyFilterRejectedStrictInet6_8426(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet6 {
        filter block6 {
            term t1 {
                then {
                    discard;
                }
            }
        }
        filter block6 {
            term t2 {
                then {
                    accept;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: a duplicate inet6 filter name must be rejected too — " +
			"FiltersInet6 takes the same unconditional last-write-wins assignment (#8426)")
	}
	if !strings.Contains(err.Error(), "block6") {
		t.Fatalf("the refusal must name the filter; got: %v", err)
	}
}

// Lenient path (load / peer-sync): an already-persisted config must still
// BOOT, warning instead of refusing, but #15997 quarantines the colliding
// name out of both pools so the accept winner is not enforceable.
func TestDuplicateSameFamilyFilterLenientWarns8426(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
        filter blockX {
            term t2 {
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
		t.Fatalf("CompileConfigLenient: a same-family duplicate must downgrade to a "+
			"warning so a persisted config still boots, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "blockX") && strings.Contains(w, "#8426") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected an #8426 same-family duplicate warning on the lenient path, "+
			"got: %v", cfg.Warnings)
	}
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; !ok {
		t.Fatalf("same-family colliding name not quarantined: %v", cfg.Firewall.CollidingNames)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; ok {
		t.Fatal("colliding blockX must be omitted from FiltersInet (#15997 quarantine)")
	}
}

// CONTROL 1: a single filter must still compile. Without this a gate that
// rejects every filter passes both cells above.
func TestSingleFilterStillCompiles8426(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
}
`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a single filter must compile; the #8426 gate must fire on a DUPLICATE, "+
			"not on the presence of a filter: %v", err)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; !ok {
		t.Fatal("the single filter must land in FiltersInet")
	}
}

// CONTROL 2: the #3884 cross-family gate must still fire. The #8426 change
// touches `record`'s neighbourhood, and a new early-return there could silence
// the older gate while every #8426 cell stays green.
func TestCrossFamilyGateStillFires8426(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
    family any {
        filter blockX {
            term t1 {
                then {
                    accept;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("the #3884 cross-family gate must still reject — #8426 must not have " +
			"displaced it")
	}
	if !strings.Contains(err.Error(), "#3884") {
		t.Fatalf("a cross-family collision must still be reported as #3884, not "+
			"reclassified; got: %v", err)
	}
}
