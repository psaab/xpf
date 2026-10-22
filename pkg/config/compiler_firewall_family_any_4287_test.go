package config

import (
	"strings"
	"testing"
)

// #4287 (fable-review-167 F-1): a Junos `family any` firewall filter is
// protocol-independent — it matches BOTH IPv4 and IPv6. Before #4287
// compileFirewall folded every non-inet6 family (including `any`) into the
// single FiltersInet (IPv4) pool, so a `family any` discard/deny filter was
// enforced on IPv4 ONLY and silently let IPv6 through — a security fail-open.
// The fix compiles a `family any` filter into BOTH FiltersInet and
// FiltersInet6 so the deny applies to both address families.
//
// Reachability note: the schema-driven flat `set` parser does not model
// `family any` (schema_cos.go firewall family has only inet/inet6), so a flat
// `set firewall family any ...` collapses and never mints a structured filter.
// A `family any` filter reaches compileFirewall's structured path only via a
// HIERARCHICAL config-file parse or a directly-built / peer-synced AST — the
// same paths #3884 documents — so the fixtures use parseHierText.

// RED-on-revert: a `family any` discard filter must land in BOTH the IPv4 and
// IPv6 pools. On revert of the #4287 fix this goes RED — the filter compiles
// into FiltersInet only and the IPv6 forwarding path (FilterInputV6 →
// FiltersInet6) never sees it, so v6 passes (fail-open).
func TestFirewallFilterFamilyAnyAppliesToBothPools(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family any {
        filter drop6 {
            term t {
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
		t.Fatalf("CompileConfig: family any filter must commit cleanly, got error: %v", err)
	}
	v4, ok4 := cfg.Firewall.FiltersInet["drop6"]
	if !ok4 {
		t.Fatal("family any filter drop6 must land in FiltersInet (IPv4)")
	}
	v6, ok6 := cfg.Firewall.FiltersInet6["drop6"]
	if !ok6 {
		t.Fatal("family any filter drop6 must land in FiltersInet6 (IPv6) — losing the v6 arm is the fail-open")
	}
	// Both must carry the discard action (the deny must apply to both families).
	for fam, f := range map[string]*FirewallFilter{"inet": v4, "inet6": v6} {
		if len(f.Terms) != 1 || f.Terms[0].Action != FilterActionDiscard {
			t.Fatalf("family any drop6 (%s pool): expected one discard term, got %+v", fam, f.Terms)
		}
	}
}

// A `family any` filter that shares a NAME with a distinct `family inet6`
// filter now collides in the FiltersInet6 pool (any folds there too), so it is
// hard-rejected at strict commit — otherwise one silently overwrites the other
// (fail-open on the v6 side). On revert this goes RED (no error, silent
// overwrite).
func TestFirewallFilterFamilyAnyInet6NameCollisionRejected(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet6 {
        filter blockV6 {
            term t1 {
                then {
                    accept;
                }
            }
        }
    }
    family any {
        filter blockV6 {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of family any + family inet6 same-name collision, got nil")
	}
	if !strings.Contains(err.Error(), "blockV6") || !strings.Contains(err.Error(), "#4287") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Lenient (load / peer-sync): the any+inet6 collision downgrades to a warning
// so an already-persisted or peer-synced config still boots.
func TestFirewallFilterFamilyAnyInet6NameCollisionLenientWarns(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet6 {
        filter blockV6 {
            term t1 {
                then {
                    accept;
                }
            }
        }
    }
    family any {
        filter blockV6 {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
}
`)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: any+inet6 collision must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "blockV6") && strings.Contains(w, "#4287") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #4287 any+inet6 collision warning on the lenient path, got: %v", cfg.Warnings)
	}
}

// A `family any` filter whose name does NOT collide with any inet/inet6 filter
// commits cleanly with no collision error/warning — the gate must not
// over-reject the legitimate dual-family case.
func TestFirewallFilterFamilyAnyNoCollisionCommits(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family any {
        filter dropBoth {
            term t {
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
		t.Fatalf("CompileConfig: lone family any filter must commit cleanly, got error: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4287") || strings.Contains(w, "#3884") {
			t.Fatalf("unexpected collision warning on a valid lone family any config: %q", w)
		}
	}
	if cfg.Firewall.FiltersInet["dropBoth"] == nil || cfg.Firewall.FiltersInet6["dropBoth"] == nil {
		t.Fatal("lone family any dropBoth must land in both pools")
	}
}
