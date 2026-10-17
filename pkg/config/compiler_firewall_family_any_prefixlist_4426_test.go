package config

import (
	"strings"
	"testing"
)

// #4426 (audit codex-164 C164-H04): #4296 rejects a static family-specific
// match (address literal, per-family icmp type/code) under `family any`, but a
// `source-prefix-list` / `destination-prefix-list` reference is NOT a static
// family keyword — it was deliberately excluded because a named prefix-list may
// mix families. A reference whose RESOLVED prefixes cover only ONE family
// reproduces the exact same under-block: `family any` dual-compiles the term
// into BOTH the inet and inet6 pools (#4287), and the arm for the family the
// list does not cover has no matching prefixes, matches nothing, and falls
// through to the implicit ACCEPT — a silent under-block of that family.
//
// These configs are non-Junos and reach compileFirewall's structured path only
// via a HIERARCHICAL config-file / peer-synced AST (the flat `set` schema does
// not model `family any`), so the fixtures use parseHier.

// RED-on-revert: a `family any` filter whose source-prefix-list resolves to
// IPv4-only prefixes must be REJECTED at strict commit. On revert of the #4426
// content-aware check this goes GREEN (compiles cleanly) — the v6 arm is
// constrained by a v4-only list, matches no v6 packet, and falls through to
// ACCEPT (fail-open v6 under-block).
func TestFirewallFilterFamilyAnyV4OnlyPrefixListRejected(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list v4-blocks {
        10.0.0.0/8;
        192.168.0.0/16;
    }
}
firewall {
    family any {
        filter blockNet {
            term t {
                from {
                    source-prefix-list {
                        v4-blocks;
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
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a v4-only source-prefix-list under family any, got nil")
	}
	if !strings.Contains(err.Error(), "blockNet") || !strings.Contains(err.Error(), "family any") ||
		!strings.Contains(err.Error(), "#4426") || !strings.Contains(err.Error(), "v4-blocks") {
		t.Fatalf("unexpected error text: %v", err)
	}
	if !strings.Contains(err.Error(), "inet6 (v6)") {
		t.Fatalf("error should name the under-blocked inet6 arm: %v", err)
	}
}

// The mirror case: a v6-only destination-prefix-list under family any
// under-blocks the inet (v4) arm and is rejected.
func TestFirewallFilterFamilyAnyV6OnlyPrefixListRejected(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list v6-blocks {
        2001:db8::/32;
    }
}
firewall {
    family any {
        filter blockNet6 {
            term t {
                from {
                    destination-prefix-list {
                        v6-blocks;
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
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a v6-only destination-prefix-list under family any, got nil")
	}
	if !strings.Contains(err.Error(), "blockNet6") || !strings.Contains(err.Error(), "#4426") ||
		!strings.Contains(err.Error(), "destination-prefix-list") || !strings.Contains(err.Error(), "inet (v4)") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// RED-on-revert (coordinator review): a SOLE `except` single-family list under
// family any is a DIFFERENT failure from the positive case. The runtime
// clean-except lowering (resolvePrefixListAddrs, #4338) treats `except` over a
// prefix set with no v6 entries as MATCH-ALL for the v6 arm, so a v4-only
// `except` OVER-blocks v6 (discards every v6 packet) — never "under-blocks / no
// matching prefixes". The reject is kept (a real commit-time surprise), but the
// message must describe the OVER-match, not an under-block.
func TestFirewallFilterFamilyAnyExceptV4OnlyOverMatch(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list mgmt-v4 {
        10.0.0.0/8;
    }
}
firewall {
    family any {
        filter lockdown {
            term t {
                from {
                    source-prefix-list {
                        mgmt-v4 except;
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
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a v4-only except prefix-list under family any, got nil")
	}
	e := err.Error()
	if !strings.Contains(e, "lockdown") || !strings.Contains(e, "#4426") ||
		!strings.Contains(e, "except") || !strings.Contains(e, "mgmt-v4") {
		t.Fatalf("unexpected error text: %v", err)
	}
	// Must describe the OVER-match of the v6 arm, NOT an under-block.
	if !strings.Contains(e, "matches EVERY inet6 (v6)") {
		t.Fatalf("except message must describe the v6 over-match: %v", err)
	}
	if strings.Contains(e, "under-block") || strings.Contains(e, "no matching prefixes") {
		t.Fatalf("except message must NOT claim an under-block (factually inverted): %v", err)
	}
}

// The except+accept fail-open specifically: `from source-prefix-list mgmt-v4
// except; then accept` under family any → the v6 arm accepts EVERY v6 packet (a
// security fail-OPEN). The gate must catch it and describe the over-accept.
func TestFirewallFilterFamilyAnyExceptAcceptFailOpenCaught(t *testing.T) {
	tree := parseHier(t, `
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
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: except+accept fail-open under family any must be rejected, got nil")
	}
	e := err.Error()
	if !strings.Contains(e, "permitMgmt") || !strings.Contains(e, "#4426") ||
		!strings.Contains(e, "matches EVERY inet6 (v6)") || !strings.Contains(e, "over-accept") {
		t.Fatalf("except+accept message must describe the v6 over-accept fail-open: %v", err)
	}
}

// The positive case must STILL produce the under-block message (regression guard
// that the except branch did not change the positive wording).
func TestFirewallFilterFamilyAnyPositiveKeepsUnderBlockMessage(t *testing.T) {
	tree := parseHier(t, `
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
                    source-prefix-list {
                        v4-blocks;
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
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a positive v4-only prefix-list, got nil")
	}
	e := err.Error()
	if !strings.Contains(e, "under-blocks") || !strings.Contains(e, "no matching prefixes") {
		t.Fatalf("positive message must keep the under-block wording: %v", err)
	}
	if strings.Contains(e, "matches EVERY") {
		t.Fatalf("positive message must NOT use the over-match wording: %v", err)
	}
}

// A MIXED-family `except` list under family any is symmetric (each arm excludes
// its own family's prefixes and matches the rest) — must NOT be flagged.
func TestFirewallFilterFamilyAnyExceptMixedCommits(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list dual {
        10.0.0.0/8;
        2001:db8::/32;
    }
}
firewall {
    family any {
        filter lockdown {
            term t {
                from {
                    source-prefix-list {
                        dual except;
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: a mixed-family except list under family any must commit, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") {
			t.Fatalf("unexpected #4426 warning on a mixed-family except config: %q", w)
		}
	}
}

// A MIXED-family prefix-list (v4 AND v6 prefixes in one list) under family any
// is legitimate — both arms have matching prefixes — and must NOT be flagged.
func TestFirewallFilterFamilyAnyMixedPrefixListCommits(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list dual {
        10.0.0.0/8;
        2001:db8::/32;
    }
}
firewall {
    family any {
        filter blockDual {
            term t {
                from {
                    source-prefix-list {
                        dual;
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: a mixed-family prefix-list under family any must commit, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") {
			t.Fatalf("unexpected #4426 warning on a valid mixed-family config: %q", w)
		}
	}
	if cfg.Firewall.FiltersInet["blockDual"] == nil || cfg.Firewall.FiltersInet6["blockDual"] == nil {
		t.Fatal("family any blockDual must land in both pools (#4287)")
	}
}

// Two SEPARATE single-family prefix-lists in ONE direction together cover both
// families — the term is correct for both arms and must NOT be flagged.
func TestFirewallFilterFamilyAnyTwoSingleFamilyListsCommit(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list v4-blocks {
        10.0.0.0/8;
    }
    prefix-list v6-blocks {
        2001:db8::/32;
    }
}
firewall {
    family any {
        filter blockBoth {
            term t {
                from {
                    source-prefix-list {
                        v4-blocks;
                        v6-blocks;
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: two single-family lists covering both families must commit, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") {
			t.Fatalf("unexpected #4426 warning when both families are covered: %q", w)
		}
	}
}

// Lenient (load / peer-sync): a v4-only prefix-list under family any downgrades
// to a warning so an already-persisted or peer-synced config still boots — the
// dual-compile behavior is preserved (the v6 arm merely never matches).
func TestFirewallFilterFamilyAnyV4OnlyPrefixListLenientWarns(t *testing.T) {
	tree := parseHier(t, `
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
                    source-prefix-list {
                        v4-blocks;
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
		t.Fatalf("CompileConfigLenient: a v4-only family-any prefix-list must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "blockNet") && strings.Contains(w, "#4426") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #4426 family-any prefix-list warning on the lenient path, got: %v", cfg.Warnings)
	}
	// Behavior preserved: both pools still carry the filter.
	if cfg.Firewall.FiltersInet["blockNet"] == nil || cfg.Firewall.FiltersInet6["blockNet"] == nil {
		t.Fatal("lenient path must preserve the #4287 dual-compile")
	}
}

// A single-family prefix-list under a NORMAL single-family filter (family inet
// with a v4-only list) is legitimate and must NOT be flagged — the gate is
// scoped to `family any` only.
func TestFirewallFilterSingleFamilyPrefixListNotFlagged(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list v4-blocks {
        10.0.0.0/8;
    }
    prefix-list v6-blocks {
        2001:db8::/32;
    }
}
firewall {
    family inet {
        filter v4 {
            term t {
                from {
                    source-prefix-list {
                        v4-blocks;
                    }
                }
                then {
                    discard;
                }
            }
        }
    }
    family inet6 {
        filter v6 {
            term t {
                from {
                    source-prefix-list {
                        v6-blocks;
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: single-family filters with single-family prefix-lists must commit, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") {
			t.Fatalf("unexpected #4426 warning on a valid single-family config: %q", w)
		}
	}
}

// #14446 (DR19-H2): single-family wrong-family-only prefix-list cases.
func TestFirewallFilterSingleFamilyWrongFamilyPrefixListRejected14446(t *testing.T) {
	cases := []struct {
		name string
		tree string
		want []string
	}{
		{name: "inet6 source positive v4-only", tree: "\npolicy-options { prefix-list v4-only { 10.0.0.0/8; } }\nfirewall { family inet6 { filter f { term t { from { source-prefix-list v4-only; } then discard; } } } }\n", want: []string{"f", "t", "v4-only", "inet6", "#4426"}},
		{name: "inet6 destination positive v4-only", tree: "\npolicy-options { prefix-list v4-only { 10.0.0.0/8; } }\nfirewall { family inet6 { filter f { term t { from { destination-prefix-list v4-only; } then discard; } } } }\n", want: []string{"f", "t", "v4-only", "inet6", "#4426"}},
		{name: "inet6 source except v4-only", tree: "\npolicy-options { prefix-list v4-only { 10.0.0.0/8; } }\nfirewall { family inet6 { filter f { term t { from { source-prefix-list v4-only except; } then accept; } } } }\n", want: []string{"f", "t", "v4-only", "inet6", "#4426"}},
		{name: "inet6 destination except v4-only", tree: "\npolicy-options { prefix-list v4-only { 10.0.0.0/8; } }\nfirewall { family inet6 { filter f { term t { from { destination-prefix-list v4-only except; } then accept; } } } }\n", want: []string{"f", "t", "v4-only", "inet6", "#4426"}},
		{name: "inet source positive v6-only", tree: "\npolicy-options { prefix-list v6-only { 2001:db8::/32; } }\nfirewall { family inet { filter g { term t { from { source-prefix-list v6-only; } then discard; } } } }\n", want: []string{"g", "t", "v6-only", "inet", "#4426"}},
		{name: "inet destination except v6-only", tree: "\npolicy-options { prefix-list v6-only { 2001:db8::/32; } }\nfirewall { family inet { filter g { term t { from { destination-prefix-list v6-only except; } then accept; } } } }\n", want: []string{"g", "t", "v6-only", "inet", "#4426"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHier(t, tc.tree))
			if err == nil {
				t.Fatal("CompileConfig: expected strict rejection of wrong-family-only prefix-list under single-family filter, got nil")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q must contain %q", err.Error(), w)
				}
			}
		})
	}
}

func TestFirewallFilterSingleFamilyWrongFamilyPrefixListLenientWarns14446(t *testing.T) {
	tree := parseHier(t, "\npolicy-options { prefix-list v4-only { 10.0.0.0/8; } }\nfirewall { family inet6 { filter f { term t { from { source-prefix-list v4-only; } then discard; } } } }\n")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: wrong-family single-family prefix-list must downgrade to warning, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") && strings.Contains(w, "v4-only") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected #4426 lenient warning, got: %v", cfg.Warnings)
	}
	if cfg.Firewall.FiltersInet6["f"] == nil {
		t.Fatal("lenient path must preserve the inet6 filter (Rust preflight fails the snapshot closed)")
	}
}

func TestFirewallFilterSingleFamilyMatchedAndMixedPrefixListCommits14446(t *testing.T) {
	tree := parseHier(t, `
policy-options {
    prefix-list v4-only { 10.0.0.0/8; }
    prefix-list v6-only { 2001:db8::/32; }
    prefix-list mixed { 10.0.0.0/8; 2001:db8::/32; }
}
firewall {
    family inet6 {
        filter f {
            term matched { from { source-prefix-list v6-only; } then discard; }
            term mixed-src { from { source-prefix-list mixed; } then discard; }
            term mixed-dst { from { destination-prefix-list mixed; } then discard; }
            term mixed-except { from { source-prefix-list mixed except; } then accept; }
        }
    }
    family inet {
        filter g {
            term matched { from { source-prefix-list v4-only; } then discard; }
            term mixed-src { from { source-prefix-list mixed; } then discard; }
        }
    }
}
`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: matched/mixed prefix-lists under single-family filters must commit, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") {
			t.Fatalf("unexpected #4426 warning on matched/mixed config: %q", w)
		}
	}
}
