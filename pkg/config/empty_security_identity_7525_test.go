package config

import (
	"strings"
	"testing"
)

// #7525: an empty security identity — zone name, zone-pair from-zone/to-zone,
// or policy name — committed cleanly and then diverged from what was written.
//
// MEASURED at master before the fix, with the fixture built up until nothing
// EARLIER rejected it (two other gates fired first and had to be satisfied in
// the fixture, or the probe would have reported a rejection that says nothing
// about this subject):
//
//	from-zone ""     ACCEPTED -> FromZone:"" ToZone:"trust"
//	to-zone ""       ACCEPTED -> FromZone:"trust" ToZone:""
//	policy ""        ACCEPTED
//	security-zone "" ACCEPTED
//	global match from-zone ""   REJECTED — #6526 already covers it
//
// The consequence is a WIDENING, not an error: sortDedupZones strips the empty
// string, and ZoneScopeSetLabel renders an empty zone set as the idiomatic
// Junos `any`. So the pair applies to every zone. The Rust preflight rejects
// the same reference outright, so the two halves disagree about the same
// config and the operator finds out at runtime.

func buildTree7525(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

// fullPolicy7525 returns a policy complete enough to get PAST the #3044
// required-dimension gate and the zone-reference gate. Both fire before the
// identity question, and a fixture that trips either measures nothing about
// #7525 — the first draft of this probe was rejected three times for reasons
// that had nothing to do with the subject.
func fullPolicy7525(prefix string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		prefix + " match source-address any",
		prefix + " match destination-address any",
		prefix + " match application any",
		prefix + " then permit",
	}
}

func TestEmptySecurityIdentitiesRejectedAtCommit7525(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			"empty zone name",
			[]string{`set security zones security-zone "" host-inbound-traffic system-services ping`},
			"security zones security-zone",
		},
		{
			"empty from-zone",
			fullPolicy7525(`set security policies from-zone "" to-zone trust policy p`),
			"from-zone",
		},
		{
			"empty to-zone",
			fullPolicy7525(`set security policies from-zone trust to-zone "" policy p`),
			"to-zone",
		},
		{
			"empty policy name",
			fullPolicy7525(`set security policies from-zone trust to-zone untrust policy ""`),
			"policy",
		},
		{
			"empty global policy name",
			append(fullPolicy7525(`set security policies global policy ""`),
				`set security policies global policy "" match from-zone trust`),
			"global policy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree7525(t, tc.lines...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("an empty identity COMMITTED. It is stripped during " +
					"normalization and an empty zone set matches as `any`, so this " +
					"widens silently rather than failing — and the userspace preflight " +
					"rejects the same reference, so the two halves disagree (#7525)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the rejection does not name the offending identity %q: %v",
					tc.want, err)
			}
			if !strings.Contains(err.Error(), "7525") {
				t.Errorf("the rejection is not attributable to #7525: %v", err)
			}
		})
	}
}

// THE OVER-REJECTION CONTROL, and it is the assertion that matters most for a
// reject-only fix: the worst case of one is a loud false rejection, so the
// bound has to be pinned. A fully-named configuration must still commit.
func TestNamedSecurityIdentitiesStillCommit7525(t *testing.T) {
	tree := buildTree7525(t, append(
		fullPolicy7525(`set security policies from-zone trust to-zone untrust policy p`),
		`set security zones security-zone dmz`,
	)...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a fully-named configuration was REJECTED — the gate is over-rejecting, "+
			"which for a reject-only fix is the entire risk: %v", err)
	}
}

// The LENIENT ingress must still boot. #1960: a config already persisted or
// arriving over peer-sync carrying an empty identity must not brick the node —
// it keeps today's widening compilation, now flagged as a warning.
func TestEmptyIdentityIsLenientOnLoad7525(t *testing.T) {
	tree := buildTree7525(t,
		fullPolicy7525(`set security policies from-zone "" to-zone trust policy p`)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant load path REJECTED an empty identity; an already-"+
			"persisted or peer-synced config must still boot (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "7525") {
			found = true
		}
	}
	if !found {
		t.Errorf("the lenient path booted but emitted NO warning naming #7525, so the "+
			"widening is still silent — which is the defect, not the fix. warnings: %v",
			cfg.Warnings)
	}
}

// The DUPLICATE-BLOCK bypass (#3562). parseStatements APPENDS a repeated block
// rather than merging it, and the compiler iterates siblings at each level, so
// a first-match-only walk is defeated by a benign first block followed by a
// second carrying the empty identity. Hierarchical input reaches this shape.
func TestEmptyIdentityInASecondSecurityBlock7525(t *testing.T) {
	hier := `security {
    zones {
        security-zone trust;
    }
}
security {
    zones {
        security-zone "";
    }
}
`
	tree, errs := NewParser(hier).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("an empty zone name in a SECOND `security` block committed. A " +
			"first-match-only walk is bypassable at every level the compiler " +
			"descends, because parseStatements appends duplicate blocks (#3562/#7525)")
	}
}

// BOTH AST SHAPES. The zone-pair has two: a single node with a four-element
// key (hierarchical, and the flat-set form collapses to it too), and a nested
// from-zone -> name -> to-zone -> name chain. compileSecurityPolicies reads
// both, so a gate that reads one covers only the spelling its author happened
// to test — the #2419 class. The first version of this validator read the
// nested shape alone and silently missed every empty to-zone and every empty
// policy name; these cells are what said so.
func TestEmptyIdentityCaughtInHierarchicalShape7525(t *testing.T) {
	for _, tc := range []struct {
		name, cfg, want string
	}{
		{
			"hierarchical empty to-zone",
			`security {
    zones { security-zone trust; }
    policies {
        from-zone trust to-zone "" {
            policy p {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`,
			"to-zone",
		},
		{
			"keyed empty to-zone under from-zone container",
			`security {
    zones { security-zone trust; }
    policies {
        from-zone { trust { to-zone "" { policy p {
            match { source-address any; destination-address any; application any; }
            then { permit; }
        } } } }
    }
}
`,
			"to-zone",
		},
		{
			"hierarchical empty policy name",
			`security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy "" {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`,
			"policy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.cfg).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs[0])
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("the hierarchical spelling COMMITTED with an empty identity. " +
					"A gate that reads only one of the two zone-pair AST shapes covers " +
					"only the spelling its author tested (#7525)")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "7525") {
				t.Errorf("rejection does not name %q and #7525: %v", tc.want, err)
			}
		})
	}
}
