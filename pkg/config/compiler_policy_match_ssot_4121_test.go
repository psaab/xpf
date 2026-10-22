package config

import (
	"sort"
	"testing"
)

// #4121: compilePolicy's source-address / destination-address / application
// match reads route through the firewallMatchValues SSOT — the SAME read-both
// reader the strict match gates use — instead of a per-arm either/or
// (`if len(Keys)>=2 { Keys[1:] } else { Children }`). The either/or read was
// correct for every shape the parser actually emits (bracket/inline collapse
// onto Keys, a hierarchical block yields Children, repeated statements yield
// sibling nodes — all mutually exclusive), so this is a divergence-elimination
// / hardening change, not a fail-open fix: the #2419 bracketed-list class
// (`source-address [ a b c ]`) was already read in full. The ONE shape where
// either/or diverged from read-both — a node carrying members in BOTH slots
// (`source-address a1 { a2; }`) — dropped the child members; the last subtest
// pins that as the genuine fail-on-revert case.
//
// fail-on-revert: reverting the three arms to the either/or read leaves the
// realistic-shape subtests GREEN (they always were) but turns
// TestPolicyMatchSSOT_4121/both_slots RED (a2 is dropped).

// compiledPolicyMatch returns the compiled source-address, destination-address
// and application match value sets for the named policy (searching both
// zone-pair and global policies).
func compiledPolicyMatch(t *testing.T, tree *ConfigTree, name string) (src, dst, apps []string) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	collect := func(p *Policy) {
		if p.Name != name {
			return
		}
		src = append([]string(nil), p.Match.SourceAddresses...)
		dst = append([]string(nil), p.Match.DestinationAddresses...)
		apps = append([]string(nil), p.Match.Applications...)
	}
	for _, pr := range cfg.Security.Policies {
		for _, p := range pr.Policies {
			collect(p)
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		collect(p)
	}
	sort.Strings(src)
	sort.Strings(dst)
	sort.Strings(apps)
	return src, dst, apps
}

func eqStrs4121(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPolicyMatchSSOT_4121(t *testing.T) {
	scaffold := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address a1 10.0.1.0/24",
		"set security address-book global address a2 10.0.2.0/24",
		"set security address-book global address a3 10.0.3.0/24",
		"set security address-book global address d1 10.0.10.0/24",
		"set security address-book global address d2 10.0.11.0/24",
	}
	wantSrc := []string{"a1", "a2", "a3"}
	wantDst := []string{"d1", "d2"}
	wantApps := []string{"junos-http", "junos-https", "junos-ssh"}

	// Flat-set bracket lists collapse onto one leaf's Keys (#2419) — the
	// either/or read already handled this via the Keys[1:] arm; this guards it.
	t.Run("flat_bracket", func(t *testing.T) {
		tree := buildTree3846(t, append(append([]string(nil), scaffold...),
			"set security policies from-zone trust to-zone untrust policy p1 match source-address [ a1 a2 a3 ]",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address [ d1 d2 ]",
			"set security policies from-zone trust to-zone untrust policy p1 match application [ junos-http junos-https junos-ssh ]",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		)...)
		src, dst, apps := compiledPolicyMatch(t, tree, "p1")
		if !eqStrs4121(src, wantSrc) || !eqStrs4121(dst, wantDst) || !eqStrs4121(apps, wantApps) {
			t.Fatalf("flat_bracket: src=%v dst=%v apps=%v; want %v %v %v", src, dst, apps, wantSrc, wantDst, wantApps)
		}
	})

	// Repeated flat-set lines yield one sibling leaf per value.
	t.Run("flat_repeated", func(t *testing.T) {
		tree := buildTree3846(t, append(append([]string(nil), scaffold...),
			"set security policies from-zone trust to-zone untrust policy p1 match source-address a1",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address a2",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address a3",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address d1",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address d2",
			"set security policies from-zone trust to-zone untrust policy p1 match application junos-http",
			"set security policies from-zone trust to-zone untrust policy p1 match application junos-https",
			"set security policies from-zone trust to-zone untrust policy p1 match application junos-ssh",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		)...)
		src, dst, apps := compiledPolicyMatch(t, tree, "p1")
		if !eqStrs4121(src, wantSrc) || !eqStrs4121(dst, wantDst) || !eqStrs4121(apps, wantApps) {
			t.Fatalf("flat_repeated: src=%v dst=%v apps=%v; want %v %v %v", src, dst, apps, wantSrc, wantDst, wantApps)
		}
	})

	// Hierarchical bracket list — parser collapses onto Keys (Keys[1:] arm).
	t.Run("hier_bracket", func(t *testing.T) {
		tree := parseHierText(t, `security {
    zones { security-zone trust; security-zone untrust; }
    address-book { global {
        address a1 10.0.1.0/24; address a2 10.0.2.0/24; address a3 10.0.3.0/24;
        address d1 10.0.10.0/24; address d2 10.0.11.0/24;
    } }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match {
                    source-address [ a1 a2 a3 ];
                    destination-address [ d1 d2 ];
                    application [ junos-http junos-https junos-ssh ];
                }
                then { permit; }
            }
        }
    }
}`)
		src, dst, apps := compiledPolicyMatch(t, tree, "p1")
		if !eqStrs4121(src, wantSrc) || !eqStrs4121(dst, wantDst) || !eqStrs4121(apps, wantApps) {
			t.Fatalf("hier_bracket: src=%v dst=%v apps=%v; want %v %v %v", src, dst, apps, wantSrc, wantDst, wantApps)
		}
	})

	// Hierarchical block shape `source-address { a1; a2; a3; }` — a child node
	// per member (Keys=["source-address"], len 1 → the old Children arm).
	t.Run("hier_block", func(t *testing.T) {
		tree := parseHierText(t, `security {
    zones { security-zone trust; security-zone untrust; }
    address-book { global {
        address a1 10.0.1.0/24; address a2 10.0.2.0/24; address a3 10.0.3.0/24;
        address d1 10.0.10.0/24; address d2 10.0.11.0/24;
    } }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match {
                    source-address { a1; a2; a3; }
                    destination-address { d1; d2; }
                    application { junos-http; junos-https; junos-ssh; }
                }
                then { permit; }
            }
        }
    }
}`)
		src, dst, apps := compiledPolicyMatch(t, tree, "p1")
		if !eqStrs4121(src, wantSrc) || !eqStrs4121(dst, wantDst) || !eqStrs4121(apps, wantApps) {
			t.Fatalf("hier_block: src=%v dst=%v apps=%v; want %v %v %v", src, dst, apps, wantSrc, wantDst, wantApps)
		}
	})

	// The genuine fail-on-revert case: a node with members in BOTH slots
	// (`source-address a1 { a2; }`). The either/or read reads only Keys[1:]
	// (["a1"]) and drops the child a2 — read-both (firewallMatchValues) keeps
	// both. No canonical Junos emits this, but the tolerant load / group-merge
	// paths must not silently narrow a policy when it appears.
	t.Run("both_slots", func(t *testing.T) {
		tree := parseHierText(t, `security {
    zones { security-zone trust; security-zone untrust; }
    address-book { global {
        address a1 10.0.1.0/24; address a2 10.0.2.0/24;
    } }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match {
                    source-address a1 { a2; }
                    destination-address any;
                    application any;
                }
                then { permit; }
            }
        }
    }
}`)
		src, _, _ := compiledPolicyMatch(t, tree, "p1")
		want := []string{"a1", "a2"}
		if !eqStrs4121(src, want) {
			t.Fatalf("both_slots: src=%v; want %v (either/or drops the child member)", src, want)
		}
	})
}
