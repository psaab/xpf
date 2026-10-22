package config

import (
	"strings"
	"testing"
)

// Tests for #3473: there was no duplicate-policy-name validator. compilePolicies
// appends every named instance for both zone-pair and global contexts without a
// uniqueness check, so two policies sharing a name in the SAME from/to-zone
// context (or in the global rulebase) both compiled. Junos/vSRX require unique
// policy names within a context. Because the userspace hit counter is name-keyed
// (RuleID = "<from>-><to>/<name>"), the duplicates coalesce onto one counter:
// `show security policies hit-count` cannot distinguish them, removing one hands
// its accumulated hits to the survivor, and the Go-side buildPolicyRuleCounterIndex
// is last-write-wins. validateDuplicatePolicyNamesStrict closes the gap.
//
// IMPORTANT shape note: a duplicate policy NAME is only expressible via the
// hierarchical / NewParser (and LoadOverride) path, where parseStatements APPENDS
// repeated sibling blocks. The flat-set ParseSetCommand + SetPath path MERGES two
// `set ... policy <name> ...` lines with an identical key-path into ONE node, so
// it is structurally immune to producing a duplicate name (covered by
// TestDuplicatePolicyNameFlatSetMergesToOnePolicy, which doubles as an over-reject
// negative control).

// Hierarchical trees are built via parseHierText (#16139 kit, NewParser —
// the correct builder for the duplicate-block / LoadOverride path; flat-set
// SetPath would merge same-name siblings).

// validPolicyBody is a minimal complete policy body (a match on each axis plus a
// terminal permit) so the duplicate-name gate — not the required-match /
// terminal-action gates, which run earlier — is the only reason a test config is
// rejected.
const validPolicyBody = `{ match { source-address any; destination-address any; application any; } then { permit; } }`

// TestDuplicatePolicyNameZonePairRejectedHierarchical is the primary RED-on-revert
// guard: two policies named `allow` in one trust->untrust stanza must be rejected
// at strict commit. Reverting the validateDuplicatePolicyNamesStrict call in
// compiler.go makes CompileConfig accept the duplicate and this test goes RED.
func TestDuplicatePolicyNameZonePairRejectedHierarchical(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy allow `+validPolicyBody+`
            policy allow `+validPolicyBody+`
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted two policies named \"allow\" in one zone-pair; want a strict reject (#3473)")
	}
	if !strings.Contains(err.Error(), "#3473") || !strings.Contains(err.Error(), "duplicate policy name") {
		t.Fatalf("reject error %q does not identify the #3473 duplicate-policy-name gate", err.Error())
	}
}

// TestDuplicatePolicyNameZonePairRejectedAcrossDuplicateSecurityBlocks proves the
// gate is duplicate-block-safe: the offending pair is SPLIT across two top-level
// `security {}` blocks (parseStatements appends the second instead of merging it,
// and compileSecurity runs for EVERY `security` root so the typed Policies slice
// aggregates both). A first-block-only check would miss this — the typed-config
// validator catches it because it reads the aggregated slice. Reverting the gate
// makes CompileConfig accept it and this test goes RED.
func TestDuplicatePolicyNameZonePairRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy allow `+validPolicyBody+`
        }
    }
}
security {
    policies {
        from-zone trust to-zone untrust {
            policy allow `+validPolicyBody+`
        }
    }
}`)
	// Premise: two top-level security blocks survived the parse (no merge).
	n := 0
	for _, c := range tree.Children {
		if c.Name() == "security" {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("expected >=2 top-level security blocks (the duplicate-block premise), got %d", n)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a duplicate policy name split across two security blocks; want a strict reject (#3473)")
	}
	if !strings.Contains(err.Error(), "#3473") || !strings.Contains(err.Error(), "duplicate policy name") {
		t.Fatalf("reject error %q does not identify the #3473 duplicate-policy-name gate", err.Error())
	}
}

// TestDuplicateGlobalPolicyNameRejectedHierarchical is the global-rulebase
// RED-on-revert guard: two global policies named `audit` must be rejected.
func TestDuplicateGlobalPolicyNameRejectedHierarchical(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        global {
            policy audit `+validPolicyBody+`
            policy audit `+validPolicyBody+`
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted two global policies named \"audit\"; want a strict reject (#3473)")
	}
	if !strings.Contains(err.Error(), "#3473") || !strings.Contains(err.Error(), "global") {
		t.Fatalf("reject error %q does not identify the #3473 global duplicate-policy-name gate", err.Error())
	}
}

// TestDuplicateGlobalPolicyNameRejectedAcrossDuplicateSecurityBlocks proves the
// global path is duplicate-block-safe too: each global `audit` lives in a
// separate `security {}` block and the typed GlobalPolicies slice aggregates
// both. Reverting the gate makes CompileConfig accept it and this test goes RED.
func TestDuplicateGlobalPolicyNameRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        global { policy audit `+validPolicyBody+` }
    }
}
security {
    policies {
        global { policy audit `+validPolicyBody+` }
    }
}`)
	n := 0
	for _, c := range tree.Children {
		if c.Name() == "security" {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("expected >=2 top-level security blocks (the duplicate-block premise), got %d", n)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a duplicate global policy name split across two security blocks; want a strict reject (#3473)")
	}
	if !strings.Contains(err.Error(), "#3473") || !strings.Contains(err.Error(), "global") {
		t.Fatalf("reject error %q does not identify the #3473 global duplicate-policy-name gate", err.Error())
	}
}

// TestDuplicatePolicyNameFlatSetMergesToOnePolicy is the flat-set shape coverage:
// two `set ... policy allow ...` lines with the same name MERGE into one policy
// (SetPath merges identical key-paths), so the flat-set path is structurally
// immune to producing a duplicate name and compiles CLEAN. This also doubles as
// an over-reject negative control — the gate must not flag a single policy whose
// leaves were assembled from several set lines.
func TestDuplicatePolicyNameFlatSetMergesToOnePolicy(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces eth1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application any",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		// A second "instance" of the SAME name — merges onto the node above.
		"set security policies from-zone trust to-zone untrust policy allow match application junos-http",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("flat-set same-name policy lines must merge and compile clean, got: %v", err)
	}
	total := 0
	for _, zpp := range cfg.Security.Policies {
		total += len(zpp.Policies)
	}
	if total != 1 {
		t.Fatalf("flat-set same-name lines should merge into exactly 1 policy, got %d", total)
	}
}

// TestPolicyNameReuseAcrossContextsCompilesClean is the over-reject negative
// control: the SAME name `allow` is legal in DIFFERENT zone-pairs and in the
// global rulebase (each is its own namespace). None of these is a duplicate, so
// CompileConfig must accept the config unchanged.
func TestPolicyNameReuseAcrossContextsCompilesClean(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust { policy allow `+validPolicyBody+` }
        from-zone untrust to-zone trust { policy allow `+validPolicyBody+` }
        global { policy allow `+validPolicyBody+` }
    }
}`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("reused name in different contexts must compile clean (no over-reject), got: %v", err)
	}
}

// TestDistinctPolicyNamesSameContextCompilesClean is the second over-reject
// negative control: two DIFFERENTLY-named policies in the same zone-pair are
// legal and must compile clean.
func TestDistinctPolicyNamesSameContextCompilesClean(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web `+validPolicyBody+`
            policy allow-dns `+validPolicyBody+`
        }
    }
}`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("distinct names in one zone-pair must compile clean (no over-reject), got: %v", err)
	}
}

// TestDuplicatePolicyNameLenientDowngradesToWarning confirms the #1960 model: the
// tolerant load / peer-sync path (CompileConfigLenient) downgrades the duplicate
// to a cfg.Warnings entry instead of failing the load, so an already-persisted or
// peer-synced config an older binary accepted still boots.
func TestDuplicatePolicyNameLenientDowngradesToWarning(t *testing.T) {
	tree := parseHierText(t, `
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy allow `+validPolicyBody+`
            policy allow `+validPolicyBody+`
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a duplicate policy name (#1960 no-brick), got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "duplicate policy name") && strings.Contains(w, "#3473") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile should record a duplicate-policy-name warning, warnings=%v", cfg.Warnings)
	}
}
