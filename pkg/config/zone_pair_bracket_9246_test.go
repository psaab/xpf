package config

import (
	"fmt"
	"strings"
	"testing"
)

func zones9246() []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	}
}

func policyLines9246(fz, tz string) []string {
	p := fmt.Sprintf("set security policies from-zone %s to-zone %s policy p1 ", fz, tz)
	return append(zones9246(),
		p+"match source-address any",
		p+"match destination-address any",
		p+"match application any",
		p+"then permit",
	)
}

func compile9246(t *testing.T, lines []string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		tree.SetPath(path)
	}
	return CompileConfig(tree)
}

// #9246: a bracketed to-zone list committed CLEAN and produced a zone pair with
// ZERO policies — the authored rule existed nowhere. The bracket lexes to the
// hierarchical 4-key shape and the residue swallows the whole rule onto one
// leaf, so the policy is never attached to any context.
//
// RED ON REVERT: drop the malformedZonePairShape9246 gate and this commits with
// trust->untrust carrying no policies, silently.
func TestBracketedToZoneIsRefused9246(t *testing.T) {
	_, err := compile9246(t, policyLines9246("trust", "[ untrust dmz ]"))
	if err == nil {
		t.Fatal("#9246: a bracketed to-zone list committed clean. The pair it builds carries " +
			"ZERO policies, so the authored rule is in force nowhere — a lost permit " +
			"blackholes traffic and a lost deny is a fail-open, depending only on the " +
			"default-policy sibling stanza.")
	}
	if !strings.Contains(err.Error(), "to-zone") || !strings.Contains(err.Error(), "bracketed") {
		t.Errorf("#9246: rejection does not name the bracketed to-zone, so the operator is "+
			"not told what to fix: %v", err)
	}
}

// from-zone was NOT measured on the issue, so it was measured here. It
// collapses the OTHER way -- the keys shift so Keys[3] becomes the literal
// string "to-zone" -- and it is ALREADY refused today, as an undefined zone
// named "to-zone".
//
// That message blames the wrong thing (it tells the operator to define a zone
// rather than remove a bracket), but it is LOUD, and the silent to-zone case is
// the defect this change fixes. Widening the detector to the from-zone shape
// also flags the #2419 census's synthetic `from-zone xpfarg xpfarg xpfarg`
// placeholder paths -- a real cost for a message improvement -- so the scope is
// deliberately the silent case.
//
// This cell pins the OUTCOME rather than the wording: from-zone bracketing must
// not commit. If someone later improves that message, this stays green.
func TestBracketedFromZoneIsStillRefused9246(t *testing.T) {
	if _, err := compile9246(t, policyLines9246("[ trust dmz ]", "untrust")); err == nil {
		t.Error("#9246: a bracketed from-zone list committed clean. It is refused today only " +
			"as a side effect (the collapse makes Keys[3] the literal \"to-zone\", which fails " +
			"the undefined-zone gate), so a change to that gate could silence it.")
	}
}

// THE LEVELLING CONTROL. A gate that refused every zone pair would satisfy both
// cases above. The unbracketed spelling must still compile AND still carry its
// policy — policies=1 is the half that catches a gate which admits the context
// but drops the rule, which is the defect itself.
func TestPlainZonePairStillCompiles9246(t *testing.T) {
	cfg, err := compile9246(t, policyLines9246("trust", "untrust"))
	if err != nil {
		t.Fatalf("#9246: the ordinary spelling was rejected: %v", err)
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("#9246: got %d contexts, want 1", len(cfg.Security.Policies))
	}
	if n := len(cfg.Security.Policies[0].Policies); n != 1 {
		t.Errorf("#9246: the context carries %d policies, want 1 — admitting the pair while "+
			"dropping the rule is the defect, not the fix", n)
	}
}

// The LEGITIMATE multi-zone spelling — one statement per zone — must survive.
// This is what an operator is told to write instead, so refusing it would make
// the message a lie.
func TestSeparateStatementsPerZoneStillWork9246(t *testing.T) {
	lines := append(zones9246(),
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone trust to-zone dmz policy p1 match source-address any",
		"set security policies from-zone trust to-zone dmz policy p1 match destination-address any",
		"set security policies from-zone trust to-zone dmz policy p1 match application any",
		"set security policies from-zone trust to-zone dmz policy p1 then permit",
	)
	cfg, err := compile9246(t, lines)
	if err != nil {
		t.Fatalf("#9246: the per-zone spelling the error message recommends was rejected: %v", err)
	}
	if len(cfg.Security.Policies) != 2 {
		t.Fatalf("#9246: got %d contexts, want 2", len(cfg.Security.Policies))
	}
	for _, zp := range cfg.Security.Policies {
		if len(zp.Policies) != 1 {
			t.Errorf("#9246: context %s->%s carries %d policies, want 1",
				zp.FromZone, zp.ToZone, len(zp.Policies))
		}
	}
}

// #1960 no-brick: the TOLERANT path (Store.Load / peer sync) must warn, not
// refuse, so a config an older binary accepted still boots and the operator is
// told rather than locked out.
func TestTolerantPathWarnsRatherThanRefusing9246(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range policyLines9246("trust", "[ untrust dmz ]") {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#9246: the tolerant path REFUSED a bracketed zone list. A persisted or "+
			"peer-synced config an older binary accepted must still boot (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bracketed") {
			found = true
		}
	}
	if !found {
		t.Errorf("#9246: tolerant path accepted the bracketed list with NO warning, so the "+
			"rule is silently in force nowhere and nothing says so. warnings=%v", cfg.Warnings)
	}
}

// The malformed statement must not leave a PHANTOM context behind on the
// tolerant path. The strict path refuses, so the difference is invisible there
// — but Store.Load and peer sync compile leniently, and without the skip the
// bogus `trust->untrust` pair is still built, carrying zero policies. An
// operator running `show security policies` would then see a context they never
// wrote, next to a warning about the one they did.
//
// Found by a SURVIVING mutant: recording the defect without skipping the build
// left every other cell green, because the strict gate rejects either way.
func TestMalformedPairLeavesNoPhantomContext9246(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range policyLines9246("trust", "[ untrust dmz ]") {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#9246: tolerant compile failed: %v", err)
	}
	for _, zp := range cfg.Security.Policies {
		t.Errorf("#9246: the tolerant path built a phantom context %s->%s with %d policies "+
			"from a statement it warned about. The operator sees a zone pair they never "+
			"wrote, and it carries none of the rule they did write.",
			zp.FromZone, zp.ToZone, len(zp.Policies))
	}
}

func groupedSetTree11366(t *testing.T, commands []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, quoted, grouped, err := ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
		}
	}
	return tree
}

func groupedPolicyZoneTree11366(t *testing.T, toZone string) *ConfigTree {
	return groupedSetTree11366(t, []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone A to-zone " + toZone + " policy p1 match source-address any",
		"set security policies from-zone A to-zone " + toZone + " policy p1 match destination-address any",
		"set security policies from-zone A to-zone " + toZone + " policy p1 match application any",
		"set security policies from-zone A to-zone " + toZone + " policy p1 then permit",
	})
}

func groupedZonePairTree11366(t *testing.T) *ConfigTree {
	return groupedPolicyZoneTree11366(t, "[ B C ]")
}

func TestGroupedToZoneMultiListRejected11366(t *testing.T) {
	tree := groupedZonePairTree11366(t)
	security := tree.FindChild("security")
	if security == nil || security.FindChild("policies") == nil {
		t.Fatal("grouped-set tree has no security policies stanza")
	}
	fromZones := security.FindChild("policies").FindChildren("from-zone")
	if len(fromZones) != 1 || len(fromZones[0].Keys) != 5 ||
		fromZones[0].Keys[3] != "B" || fromZones[0].Keys[4] != "C" {
		t.Fatalf("grouped-set path did not preserve the complete to-zone list: %+v", fromZones)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("grouped to-zone list committed silently; tree=%s", tree.FormatSet())
	}
	if !strings.Contains(err.Error(), "to-zone") || !strings.Contains(err.Error(), "bracketed") {
		t.Fatalf("grouped to-zone error must identify the invalid list, got %v", err)
	}
}

func TestGroupedToZoneMultiListWarnsAndQuarantines11366(t *testing.T) {
	tree := groupedZonePairTree11366(t)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must remain bootable: %v", err)
	}
	var warned bool
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "to-zone") && strings.Contains(warning, "bracketed") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("tolerant grouped to-zone load must warn with the rejected cause: %v", cfg.Warnings)
	}
	if len(cfg.Security.Policies) != 0 {
		t.Fatalf("quarantined grouped policy must not partially compile for one zone: %+v", cfg.Security.Policies)
	}
}

func TestGroupedSetSeparateZonePairsStillCompile11366(t *testing.T) {
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
	}
	for _, toZone := range []string{"B", "C"} {
		prefix := fmt.Sprintf("set security policies from-zone A to-zone %s policy p1 ", toZone)
		commands = append(commands,
			prefix+"match source-address any",
			prefix+"match destination-address any",
			prefix+"match application any",
			prefix+"then permit",
		)
	}
	cfg, err := CompileConfig(groupedSetTree11366(t, commands))
	if err != nil {
		t.Fatalf("separate grouped-set zone pairs must still commit: %v", err)
	}
	if len(cfg.Security.Policies) != 2 {
		t.Fatalf("separate zone statements produced %d contexts, want 2: %+v",
			len(cfg.Security.Policies), cfg.Security.Policies)
	}
	got := make(map[string]int, 2)
	for _, pair := range cfg.Security.Policies {
		got[pair.ToZone] += len(pair.Policies)
	}
	if got["B"] != 1 || got["C"] != 1 {
		t.Fatalf("separate zone statements must enforce one policy on each zone, got %v", got)
	}
}

func TestGroupedToZoneMultiListRejectedWithoutProvenance11366(t *testing.T) {
	tree := groupedZonePairTree11366(t)
	security := tree.FindChild("security")
	if security == nil || security.FindChild("policies") == nil {
		t.Fatal("grouped-set tree has no security policies stanza")
	}
	node := security.FindChild("policies").FindChild("from-zone")
	if node == nil || len(node.Keys) != 5 {
		t.Fatalf("expected grouped five-key context, got %+v", node)
	}
	node.KeysBracketed = nil
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "to-zone") ||
		!strings.Contains(err.Error(), "extra key tokens") {
		t.Fatalf("a provenance-less extra to-zone key must still be refused by shape, got %v", err)
	}
}

func TestGroupedSingleZoneBracketAndPlainPairRemainValid11366(t *testing.T) {
	for _, toZone := range []string{"[ B ]", "B"} {
		t.Run(toZone, func(t *testing.T) {
			cfg, err := CompileConfig(groupedPolicyZoneTree11366(t, toZone))
			if err != nil {
				t.Fatalf("single-zone pair %q must compile: %v", toZone, err)
			}
			if len(cfg.Security.Policies) != 1 {
				t.Fatalf("single-zone pair %q compiled %d contexts, want 1",
					toZone, len(cfg.Security.Policies))
			}
			pair := cfg.Security.Policies[0]
			if pair.FromZone != "A" || pair.ToZone != "B" || len(pair.Policies) != 1 {
				t.Fatalf("single-zone pair %q compiled incorrectly: %+v", toZone, pair)
			}
		})
	}
}

func TestHierarchicalToZoneMultiListRejected11366(t *testing.T) {
	const text = `security {
    zones {
        security-zone A;
        security-zone B;
        security-zone C;
    }
    policies {
        from-zone A to-zone [ B C ] {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}`
	tree, parseErrs := NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse errors: %v", parseErrs)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "to-zone") ||
		!strings.Contains(err.Error(), "bracketed") {
		t.Fatalf("hierarchical bracketed to-zone must be refused with cause, got %v", err)
	}
}

func TestHierarchicalSingleLeafPolicyIsNotSilentlyDropped11366(t *testing.T) {
	const text = `security {
    zones {
        security-zone A;
        security-zone B;
    }
    policies {
        from-zone A to-zone B policy p1;
    }
}`
	tree, parseErrs := NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse errors: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		if !strings.Contains(err.Error(), "#3044") &&
			!strings.Contains(err.Error(), "extra key tokens") {
			t.Fatalf("single-leaf policy was refused for an unrelated reason: %v", err)
		}
		return
	}
	if len(cfg.Security.Policies) == 0 {
		t.Fatal("single-leaf hierarchical policy vanished without rejection or a compiled context")
	}
	for _, pair := range cfg.Security.Policies {
		if len(pair.Policies) == 0 {
			t.Fatalf("single-leaf hierarchical policy compiled as an empty context: %+v", cfg.Security.Policies)
		}
	}
}
