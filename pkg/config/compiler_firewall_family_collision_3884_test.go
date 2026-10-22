package config

import (
	"strings"
	"testing"
)

// #3884 (fable-review-161 F-030): compileFirewall folds every DECLARED
// firewall-filter family except inet6 (inet, any) into ONE name-keyed map
// (fw.FiltersInet) with an unconditional `dest[name] = filter` write, so two
// same-name filters authored under DIFFERENT declared non-inet6 families
// silently collapse — the later definition overwrites the earlier with no
// commit error. (An UNDECLARED token like `mpls` no longer folds at all: it
// is quarantined out of both pools by compileFirewall (#9883) and named by
// the #9017 token gate instead, so it cannot collide — that scoping is pinned
// in firewall_family_unknown_9883_test.go, not here.)
// If the IPv4 (`family inet`) filter was a `discard`/deny and the
// colliding-family filter is accept-all, the effective IPv4 filter becomes
// accept-all (a security fail-open). These
// fixtures pin the strict reject at commit and the lenient warn on the tolerant
// load / peer-sync path, and confirm the legitimate single-family and
// inet/inet6 dual-stack cases are unaffected.
//
// Note on parse shape: the reproduction uses parseHier (how a config file
// loads) and directly-built ASTs (how a peer-synced tree arrives) — the paths
// where structured multi-family filter subtrees reach the gate. (An undeclared
// token like `mpls` reaches a structured subtree the same way, but it is
// quarantined before it can fold or collide — #9883.)

// Strict commit: a filter name reused across family inet (discard) and family
// any (accept) is hard-rejected. On revert of the #3884 gate this goes RED —
// the second definition silently overwrites the first (discard → accept-all)
// and CompileConfig returns no error.
func TestFirewallFilterCrossFamilyNameCollisionRejected(t *testing.T) {
	tree := parseHier(t, `
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
		t.Fatal("CompileConfig: expected rejection of cross-family firewall filter name collision, got nil")
	}
	if !strings.Contains(err.Error(), "blockX") ||
		!strings.Contains(err.Error(), "#3884") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Cross-family collision split across two hierarchical `firewall {}` blocks. The
// compiler compiles every top-level firewall node into the same fw.FiltersInet
// map, so a walker that stopped at the first block would miss it.
func TestFirewallFilterCrossFamilyCollisionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
firewall {
    family inet {
        filter blockZ {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
}
firewall {
    family any {
        filter blockZ {
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
		t.Fatal("CompileConfig: expected rejection of cross-family collision split across firewall blocks, got nil")
	}
	if !strings.Contains(err.Error(), "blockZ") ||
		!strings.Contains(err.Error(), "#3884") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Lenient path (load / peer-sync): the collision downgrades to a warning so
// an already-persisted or peer-synced config still BOOTS, but #15997
// quarantines the colliding name out of BOTH pools — neither the discard
// nor the accept winner stays enforceable.
func TestFirewallFilterCrossFamilyNameCollisionLenientWarns(t *testing.T) {
	tree := parseHier(t, `
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

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: cross-family collision must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "blockX") && strings.Contains(w, "#3884") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #3884 cross-family collision warning on the lenient path, got: %v", cfg.Warnings)
	}
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; !ok {
		t.Fatalf("colliding name not quarantined: %v", cfg.Firewall.CollidingNames)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; ok {
		t.Fatal("lenient path: colliding blockX must be omitted from FiltersInet (#15997 quarantine)")
	}
	if _, ok := cfg.Firewall.FiltersInet6["blockX"]; ok {
		t.Fatal("lenient path: colliding blockX must be omitted from FiltersInet6 (#15997 quarantine)")
	}
}

// #15997: identical-body duplicates are unaffected — one unambiguous meaning,
// so the name stays enforceable on the tolerant path.
func TestFirewallFilterIdenticalDuplicateUnaffected15997(t *testing.T) {
	tree := parseHier(t, `
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
                    discard;
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
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; ok {
		t.Fatalf("identical-body duplicate must not be quarantined: %v", cfg.Firewall.CollidingNames)
	}
	f, ok := cfg.Firewall.FiltersInet["blockX"]
	if !ok || len(f.Terms) != 1 || f.Terms[0].Action != FilterActionDiscard {
		t.Fatalf("identical-body duplicate must stay enforceable as discard, got %+v ok=%v", f, ok)
	}
}

// #15997 fold (#16091): text-identical inet6 vs any bodies are NOT effectively
// identical — icmp-type echo-request resolves 128 under inet6 vs 8 under any.
// The dedupe key is the family-resolved compiled form, so this name stays
// quarantined and FiltersInet6 must not silently carry type 8.
func TestFirewallFilterInet6AnyEchoRequestNotIdentical15997(t *testing.T) {
	tree := parseHier(t, `
firewall {
    family inet6 {
        filter F {
            term t {
                from {
                    icmp-type echo-request;
                }
                then {
                    discard;
                }
            }
        }
    }
    family any {
        filter F {
            term t {
                from {
                    icmp-type echo-request;
                }
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
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if _, ok := cfg.Firewall.CollidingNames["F"]; !ok {
		t.Fatalf("inet6/any echo-request counterexample must stay quarantined (effective forms differ 128 vs 8): %v", cfg.Firewall.CollidingNames)
	}
	if f, ok := cfg.Firewall.FiltersInet6["F"]; ok {
		t.Fatalf("quarantined F must be omitted from FiltersInet6, got %+v (icmp types %v)", f, f.Terms[0].ICMPTypes)
	}
	if f, ok := cfg.Firewall.FiltersInet["F"]; ok {
		t.Fatalf("quarantined F must be omitted from FiltersInet, got %+v", f)
	}
	// Warning must not falsely claim quarantine for a pruned identical case;
	// here quarantine is real, so the suffix must be present.
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "\"F\"") && strings.Contains(w, "quarantined") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected quarantine warning for F, got %v", cfg.Warnings)
	}
}

// Control: same-family identical effective duplicates stay enforceable and
// their warning must not claim they were quarantined/omitted.
func TestFirewallFilterIdenticalWarningTruthful15997(t *testing.T) {
	tree := parseHier(t, `
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
                    discard;
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
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; !ok {
		t.Fatal("identical effective duplicate must stay in FiltersInet")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "blockX") && strings.Contains(w, "quarantined from both filter pools") {
			t.Fatalf("identical-body warning falsely claims quarantine: %q", w)
		}
	}
}

// #15997 fold 2: definitions differing ONLY in unexported term semantics must
// stay quarantined — JSON dropped unknownChildren / routing-instance
// conflict. Cell A: one body carries an unknown term child (#10294), the
// other is a clean accept with identical exported fields.
func TestFirewallFilterUnknownChildrenDifferNotIdentical15997(t *testing.T) {
	tree := parseHier(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    accept;
                }
            }
        }
        filter blockX {
            term t1 {
                bogus-child;
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
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; !ok {
		t.Fatalf("unknownChildren-differing duplicate must stay quarantined: %v", cfg.Firewall.CollidingNames)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; ok {
		t.Fatal("quarantined blockX must be omitted from FiltersInet")
	}
}

// Cell B: one body steers to two conflicting routing-instance targets
// (#11814, routingInstanceTargetConflict set), the other to one target,
// with identical exported RoutingInstance/Action.
func TestFirewallFilterRIConflictDifferNotIdentical15997(t *testing.T) {
	tree := parseHier(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    routing-instance RI-A;
                }
            }
        }
        filter blockX {
            term t1 {
                then {
                    routing-instance RI-A;
                    routing-instance RI-B;
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
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; !ok {
		t.Fatalf("RI-conflict-differing duplicate must stay quarantined: %v", cfg.Firewall.CollidingNames)
	}
	if _, ok := cfg.Firewall.FiltersInet["blockX"]; ok {
		t.Fatal("quarantined blockX must be omitted from FiltersInet")
	}
}

// #15997 fold 3: identical FlexMatch duplicates must be PRUNED — the nested
// *FlexMatchConfig pointers live at different addresses, so an address-
// printing comparator falsely quarantined them. Key must be by value.
func TestFirewallFilterIdenticalFlexMatchPruned15997(t *testing.T) {
	tree := parseHier(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                from {
                    flexible-match-range {
                        range r1 {
                            match-start layer-3;
                            byte-offset 12;
                            bit-length 16;
                            match-value 0x1234;
                            match-mask 0xFFFF;
                        }
                    }
                }
                then {
                    discard;
                }
            }
        }
        filter blockX {
            term t1 {
                from {
                    flexible-match-range {
                        range r1 {
                            match-start layer-3;
                            byte-offset 12;
                            bit-length 16;
                            match-value 0x1234;
                            match-mask 0xFFFF;
                        }
                    }
                }
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
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if _, ok := cfg.Firewall.CollidingNames["blockX"]; ok {
		t.Fatalf("identical FlexMatch duplicate falsely quarantined (pointer-address key?): %v", cfg.Firewall.CollidingNames)
	}
	f, ok := cfg.Firewall.FiltersInet["blockX"]
	if !ok || len(f.Terms) != 1 || f.Terms[0].FlexMatch == nil {
		t.Fatalf("identical FlexMatch duplicate must stay enforceable, got %+v ok=%v", f, ok)
	}
}

// A filter name shared between family inet and family inet6 is NOT a collision:
// inet6 has its own dest map (FiltersInet6), so the two coexist. This legitimate
// dual-stack case (the same filter name for the V4 and V6 path) must commit
// cleanly with no #3884 error/warning, and BOTH filters must survive.
func TestFirewallFilterInetInet6SameNameCommits(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set firewall family inet filter dualX term t1 then discard",
		"set firewall family inet6 filter dualX term t1 then accept",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: inet/inet6 same-name filters must commit cleanly, got error: %v", err)
	}
	if _, ok := cfg.Firewall.FiltersInet["dualX"]; !ok {
		t.Fatal("expected dualX in FiltersInet (V4)")
	}
	if _, ok := cfg.Firewall.FiltersInet6["dualX"]; !ok {
		t.Fatal("expected dualX in FiltersInet6 (V6)")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3884") {
			t.Fatalf("unexpected #3884 warning on a valid inet/inet6 dual-stack config: %q", w)
		}
	}
}

// A normal single-family filter compiles unchanged — the gate must not
// over-reject the common case.
func TestFirewallFilterSingleFamilyCommits(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set firewall family inet filter allowSSH term t1 from destination-port 22",
		"set firewall family inet filter allowSSH term t1 then accept",
		"set firewall family inet filter dropAll term t2 then discard",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: single-family filters must commit cleanly, got error: %v", err)
	}
	if _, ok := cfg.Firewall.FiltersInet["allowSSH"]; !ok {
		t.Fatal("expected allowSSH in FiltersInet")
	}
	if _, ok := cfg.Firewall.FiltersInet["dropAll"]; !ok {
		t.Fatal("expected dropAll in FiltersInet")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3884") {
			t.Fatalf("unexpected #3884 warning on a valid single-family config: %q", w)
		}
	}
}
