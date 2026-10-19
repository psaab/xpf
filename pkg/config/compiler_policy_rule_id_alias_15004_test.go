package config

import (
	"strings"
	"testing"
)

// Tests for #15004 (A07-01): the stable policy rule identity
// StablePolicyRuleID = "<from>-><to>/<name>" (pkg/dataplane/userspace,
// mirrored in userspace-dp/src/policy.rs stable_policy_rule_id) is built by
// unescaped concatenation, so distinct (zone, zone, policy-name) tuples can
// alias onto ONE identity:
//
//	from="a->b", to="c", name="p" -> "a->b->c/p"
//	from="a", to="b->c", name="p" -> "a->b->c/p"
//
// A policy name containing "->" or "/" likewise shifts a separator boundary
// (the daemon re-parses ids with SplitN on "/" then "->"). The Rust helper
// keys hit counters and rule_id_to_policy_id on that string and its
// integrity preflight rejects the WHOLE snapshot on a duplicate
// (DuplicateRuleId), so a strict-clean commit was refused whole by the
// helper: no new snapshot applied, default-deny after a fresh boot, with a
// misleading diagnosis. The only pre-existing zone-name charset gate banned
// '/' (zone-local address-book namespace, #3061/#4340); nothing banned "->"
// in zone names or "->"/"/" in policy names.
//
// Fix: validateStablePolicyRuleIdentityStrict rejects, at strict commit, any
// zone name containing "->" and any security-policy name containing "->" or
// "/", so every compiled (from,to,name) tuple maps injectively onto its
// stable id. Tolerant loads downgrade to a warning (#1960 no-brick); the
// helper still refuses such a leniently-loaded snapshot closed.
//
// All configs below define every zone they reference and give every policy a
// complete match + terminal permit, so the #15004 gate — not an earlier
// structural gate — is the only reason a strict compile is rejected.

func collideConfig15004(from1, to1, name1, from2, to2, name2 string) *ConfigTree {
	// Define the union of zone names referenced (definitions with a "->" name
	// must themselves parse; zone definitions carry no interfaces here).
	zones := map[string]bool{}
	for _, z := range []string{from1, to1, from2, to2} {
		zones[z] = true
	}
	var b strings.Builder
	b.WriteString("security {\n    zones {\n")
	for z := range zones {
		b.WriteString("        security-zone " + z + ";\n")
	}
	b.WriteString("    }\n    policies {\n")
	b.WriteString("        from-zone " + from1 + " to-zone " + to1 + " { policy " + name1 + " " + validPolicyBody + " }\n")
	b.WriteString("        from-zone " + from2 + " to-zone " + to2 + " { policy " + name2 + " " + validPolicyBody + " }\n")
	b.WriteString("    }\n}\n")
	return parseHierarchical15004(b.String())
}

func parseHierarchical15004(cfgText string) *ConfigTree {
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		panic(perrs[0])
	}
	return tree
}

// TestPolicyRuleIDArrowZonePairCollisionRejected15004 is the primary
// RED-on-revert guard: the two zone pairs (a->b, c, p) and (a, b->c, p)
// alias onto "a->b->c/p". On origin/master CompileConfig accepted this
// config and the helper then refused the whole snapshot. After the fix the
// strict commit itself rejects it, naming the offending zone.
func TestPolicyRuleIDArrowZonePairCollisionRejected15004(t *testing.T) {
	// Premise (documents the mechanism): the two tuples really do format to
	// the same stable id under the unescaped "%s->%s/%s" construction.
	id1 := "a->b" + "->" + "c" + "/" + "p"
	id2 := "a" + "->" + "b->c" + "/" + "p"
	if id1 != id2 {
		t.Fatalf("test premise broken: %q != %q", id1, id2)
	}
	tree := collideConfig15004("a->b", "c", "p", "a", "b->c", "p")
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted zone names containing \"->\" whose zone pairs alias onto one stable rule id %q; want a strict reject (#15004)", id1)
	}
	if !strings.Contains(err.Error(), "#15004") || !strings.Contains(err.Error(), "->") {
		t.Fatalf("reject error %q does not identify the #15004 stable-rule-id gate", err.Error())
	}
}

// TestPolicyNameArrowAndSlashRejected15004 covers the policy-name leg: a
// name containing "->" shifts the zone boundary inside the id, and a name
// containing "/" shifts the name boundary (consumers re-parse with SplitN
// on "/" then "->"). Either is rejected even as a single rule, because its
// id is ambiguous to every consumer that splits on those separators.
func TestPolicyNameArrowAndSlashRejected15004(t *testing.T) {
	for _, name := range []string{"p->q", "p/q"} {
		tree := parseHierarchical15004(`
security {
    zones { security-zone a; security-zone b; }
    policies {
        from-zone a to-zone b { policy ` + name + ` ` + validPolicyBody + ` }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted policy name %q containing a stable-rule-id separator; want a strict reject (#15004)", name)
		}
		if !strings.Contains(err.Error(), "#15004") {
			t.Fatalf("reject error %q does not identify the #15004 gate", err.Error())
		}
	}
}

// TestGlobalPolicyNameSeparatorRejected15004 covers the global rulebase,
// whose stable ids key on junos-global->junos-global/<name>.
func TestGlobalPolicyNameSeparatorRejected15004(t *testing.T) {
	tree := parseHierarchical15004(`
security {
    zones { security-zone a; security-zone b; }
    policies {
        global { policy g->x ` + validPolicyBody + ` }
    }
}`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted a global policy name containing \"->\"; want a strict reject (#15004)")
	} else if !strings.Contains(err.Error(), "#15004") {
		t.Fatalf("reject error %q does not identify the #15004 gate", err.Error())
	}
}

// TestPolicyRuleIDNormalNamesCompileClean15004 is the over-reject negative
// control: ordinary zone/policy names — including hyphens that are not the
// "->" separator and the same policy name reused across different pairs —
// must compile clean.
func TestPolicyRuleIDNormalNamesCompileClean15004(t *testing.T) {
	tree := parseHierarchical15004(`
security {
    zones { security-zone trust; security-zone untrust; security-zone dmz-1; }
    policies {
        from-zone trust to-zone untrust { policy allow-web ` + validPolicyBody + ` }
        from-zone untrust to-zone trust { policy allow-web ` + validPolicyBody + ` }
        from-zone trust to-zone dmz-1 { policy a-b-c ` + validPolicyBody + ` }
        global { policy allow-web ` + validPolicyBody + ` }
    }
}`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("ordinary zone/policy names must compile clean (no over-reject), got: %v", err)
	}
}

// TestPolicyRuleIDAliasLenientDowngrades15004 confirms the #1960 model: the
// tolerant load path downgrades the rejection to a warning so an
// already-persisted config still boots (the helper then refuses its
// snapshot closed, as before).
func TestPolicyRuleIDAliasLenientDowngrades15004(t *testing.T) {
	tree := collideConfig15004("a->b", "c", "p", "a", "b->c", "p")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a \"->\" zone name (#1960 no-brick), got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15004") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile should record a #15004 warning, warnings=%v", cfg.Warnings)
	}
}
