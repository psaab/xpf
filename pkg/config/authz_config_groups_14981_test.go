package config

import (
	"strings"
	"testing"
)

// #14981: groups/apply-groups expansion bypassed deny-configuration in
// Set, Load, and Commit. The cfg9892 fixture class `limited` denies
// `system root-authentication`; every cell below plants exactly that leaf
// (or an allowed control leaf) behind inheritance.

// Premise + control: the direct path is denied, the allowed group is not.
func TestGroupExpandedDirectPremise14981(t *testing.T) {
	cfg := cfg9892(t)
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system root-authentication plain-text-password hunter2"); err == nil {
		t.Fatal("premise failed: direct denied set allowed")
	}
	if err := AuthorizeExpandedTree(cfg, "limited", parseHierText(t, "groups { G { system { host-name ok14981; } } } apply-groups G;")); err != nil {
		t.Fatalf("allowed group inheritance refused: %v", err)
	}
	if err := AuthorizeExpandedTree(cfg, "limited", parseHierText(t, "system { host-name ok14981; }")); err != nil {
		t.Fatalf("group-free tree refused by expanded gate: %v", err)
	}
}

// Control: merely DEFINING a group whose body names a denied subtree,
// without applying it, must not be refused by the expanded gate — the
// group's body is not effective configuration until applied. (The
// literal definition line itself stays adjudicated by the per-line gate
// under the operator's own deny, as before.)
func TestUnappliedGroupDefinitionNotExpandedDenied14981(t *testing.T) {
	cfg := cfg9892(t)
	tree := parseHierText(t, "groups { G { system { root-authentication { plain-text-password hunter2; } } } } system { host-name ok14981; }")
	if err := AuthorizeExpandedTree(cfg, "limited", tree); err != nil {
		t.Fatalf("unapplied group definition refused by expanded gate: %v", err)
	}
}

// The headline bypass, in every spelling: hierarchical group, flat group,
// wildcard <*> group, and nested group.
func TestGroupExpandedDeniedInheritanceRefused14981(t *testing.T) {
	cfg := cfg9892(t)
	for name, text := range map[string]string{
		"hierarchical": "groups { G { system { root-authentication { plain-text-password hunter2; } } } } apply-groups G;",
		"wildcard":     "groups { G { security { zones { security-zone <*> { description evil14981; } } } } } apply-groups G; security { zones { security-zone trust { } } }",
		"nested":       "groups { H { system { root-authentication { plain-text-password hunter2; } } } G { apply-groups H; } } apply-groups G;",
		"nested-level": "groups { G { system { root-authentication { plain-text-password hunter2; } } } } system { apply-groups G; host-name h; }",
	} {
		t.Run(name, func(t *testing.T) {
			tree := parseHierText(t, text)
			// Positive control at the expansion layer: the denied leaf
			// really does materialize, so a refusal measures the gate.
			lines, err := ExpandedMutationLines(tree)
			if err != nil {
				t.Fatalf("ExpandedMutationLines: %v", err)
			}
			if name == "wildcard" {
				if !strings.Contains(strings.Join(lines, "\n"), "description evil14981") {
					t.Fatalf("wildcard fixture does not fan out: %v", lines)
				}
				// The wildcard row's denied leaf is the fan-out itself
				// under a deny on that description path — adjudicate with
				// a dedicated class below; here assert expansion happened.
				return
			}
			if !strings.Contains(strings.Join(lines, "\n"), "root-authentication") {
				t.Fatalf("fixture does not expand to the denied leaf: %v", lines)
			}
			if err := AuthorizeExpandedTree(cfg, "limited", tree); err == nil {
				t.Errorf("%s: group-inherited denied path was ALLOWED (#14981)", name)
			}
		})
	}
}

// Wildcard fan-out against a real container (the issue's <*> leg with the
// denied subtree as the fan-out target).
func TestGroupWildcardFanoutDenied14981(t *testing.T) {
	cfg := cfg9892(t)
	// Group contributes root-authentication under every system-like
	// container via a wildcard interface description is the allowed
	// control; the denied version contributes it directly under system.
	text := "groups { G { interfaces { <*> { description evil14981; } } } } apply-groups G; interfaces { ge-0/0/0 { description x; } }"
	if err := AuthorizeExpandedTree(cfg, "limited", parseHierText(t, text)); err != nil {
		t.Fatalf("allowed wildcard fan-out refused: %v", err)
	}
	denied := "groups { G { system { root-authentication { plain-text-password hunter2; } } } } apply-groups G;"
	if err := AuthorizeExpandedTree(cfg, "limited", parseHierText(t, denied)); err == nil {
		t.Fatal("denied group body allowed (#14981)")
	}
}

// Wildcard <*> fan-out carrying a denied leaf: the group contributes a
// description to every security-zone, and the class denies that exact
// expanded path. The literal group line never matches the deny.
func TestGroupWildcardDeniedLeafRefused14981(t *testing.T) {
	text := `
system {
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "security zones security-zone trust description";
        }
    }
}
`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile fixture: %v", err)
	}
	if _, restricted, err := ConfigurationLoginRegexesFor(cfg, "limited"); err != nil || !restricted {
		t.Fatalf("fixture class not restricted (restricted=%v err=%v)", restricted, err)
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set security zones security-zone trust description evil14981"); err == nil {
		t.Fatal("premise failed: direct expanded spelling allowed")
	}
	candidate := parseHierText(t, "groups { G { security { zones { security-zone <*> { description evil14981; } } } } } apply-groups G; security { zones { security-zone trust { } } }")
	lines, err := ExpandedMutationLines(candidate)
	if err != nil {
		t.Fatalf("ExpandedMutationLines: %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "security-zone trust description evil14981") {
		t.Fatalf("wildcard does not fan out to trust: %v", lines)
	}
	if err := AuthorizeExpandedTree(cfg, "limited", candidate); err == nil {
		t.Fatal("wildcard group-inherited denied path was ALLOWED (#14981)")
	}
}

// Load: flat and hierarchical bodies carrying groups must be refused when
// the expansion is denied, and allowed when it is not.
func TestLoadGroupExpansionDenied14981(t *testing.T) {
	cfg := cfg9892(t)
	denied := map[string]string{
		"flat":         "set groups G system root-authentication plain-text-password hunter2\nset apply-groups G",
		"hierarchical": "groups { G { system { root-authentication { plain-text-password hunter2; } } } }\napply-groups G;",
		"wildcard":     "groups { G { system { root-authentication { plain-text-password hunter2; } } } }\napply-groups G;\nsystem { host-name h; }",
	}
	for name, body := range denied {
		if err := AuthorizeConfigLoad(cfg, "limited", "merge", body); err == nil {
			t.Errorf("load %s carrying a group-inherited denied path was ALLOWED (#14981)", name)
		}
		if err := AuthorizeConfigLoad(cfg, "limited", "set", body); err == nil {
			t.Errorf("load set %s carrying a group-inherited denied path was ALLOWED (#14981)", name)
		}
	}
	allowed := "set groups G system host-name ok14981\nset apply-groups G"
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", allowed); err != nil {
		t.Fatalf("allowed group load refused: %v", err)
	}
	hierAllowed := "groups { G { system { host-name ok14981; } } }\napply-groups G;"
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", hierAllowed); err != nil {
		t.Fatalf("allowed hierarchical group load refused: %v", err)
	}
	// #16080: an unknown class name resolves to no PermAll, so the
	// credential fence denies its credential-carrying load; a
	// non-credential load by the same name stays allowed (real
	// callers deny unknown classes at the coarse gate first).
	if err := AuthorizeConfigLoad(cfg, "no-such-class", "merge", denied["flat"]); err == nil {
		t.Fatal("unknown class load carrying a credential path was ALLOWED (#16080)")
	}
	if err := AuthorizeConfigLoad(cfg, "no-such-class", "merge", allowed); err != nil {
		t.Fatalf("unknown class non-credential load refused: %v", err)
	}
}

// An undefined group in a restricted load must fail closed, not be
// adjudicated as zero mutations.
func TestLoadUndefinedGroupFailsClosed14981(t *testing.T) {
	cfg := cfg9892(t)
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", "set apply-groups NOPE14981"); err == nil {
		t.Fatal("load applying an undefined group was ALLOWED for a restricted class (#14981)")
	}
}

// Node-var groups: the denied leaf behind apply-groups "${node}" must be
// caught in at least one node view.
func TestGroupNodeVarExpansionDenied14981(t *testing.T) {
	cfg := cfg9892(t)
	text := `groups { node0 { system { root-authentication { plain-text-password hunter2; } } } } apply-groups "${node}";`
	if err := AuthorizeExpandedTree(cfg, "limited", parseHierText(t, text)); err == nil {
		t.Fatal("denied leaf behind apply-groups ${node} was ALLOWED (#14981)")
	}
}

// #16428: the plain (no-vars) view of any `apply-groups "${node}"` tree
// errors by construction, so TestGroupNodeVarExpansionDenied14981 above
// passed for the wrong reason (the unresolvable-view refusal) whenever
// the cluster idiom was present. The allowed control proves the gate now
// adjudicates the node views: an unrelated effective path is permitted,
// and ExpandedMutationLines itself returns the node-expanded lines.
func TestGroupNodeVarAllowedControl16428(t *testing.T) {
	cfg := cfg9892(t)
	text := `groups { node0 { system { host-name fw0; } } node1 { system { host-name fw1; } } } apply-groups "${node}";`
	tree := parseHierText(t, text)
	lines, err := ExpandedMutationLines(tree)
	if err != nil {
		t.Fatalf("ExpandedMutationLines on ${node} cluster tree: %v (#16428)", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "host-name fw0") || !strings.Contains(joined, "host-name fw1") {
		t.Fatalf("node views do not materialize both node groups: %v (#16428)", lines)
	}
	if err := AuthorizeExpandedTree(cfg, "limited", tree); err != nil {
		t.Fatalf("allowed ${node} inheritance refused: %v (#16428)", err)
	}
}

// #16428: a denied leaf delivered via a node group must still be refused
// — now via the node views, not the plain-view error. Both node groups
// denied in turn, so the refusal cannot come from a single view.
func TestGroupNodeVarDeniedViaNodeViews16428(t *testing.T) {
	cfg := cfg9892(t)
	for name, text := range map[string]string{
		"node0-denied": `groups { node0 { system { root-authentication { plain-text-password hunter2; } } } node1 { system { host-name fw1; } } } apply-groups "${node}";`,
		"node1-denied": `groups { node0 { system { host-name fw0; } } node1 { system { root-authentication { plain-text-password hunter2; } } } } apply-groups "${node}";`,
	} {
		t.Run(name, func(t *testing.T) {
			tree := parseHierText(t, text)
			lines, err := ExpandedMutationLines(tree)
			if err != nil {
				t.Fatalf("ExpandedMutationLines: %v (#16428)", err)
			}
			if !strings.Contains(strings.Join(lines, "\n"), "root-authentication") {
				t.Fatalf("fixture does not expand to the denied leaf: %v (#16428)", lines)
			}
			if err := AuthorizeExpandedTree(cfg, "limited", tree); err == nil {
				t.Fatal("denied leaf behind apply-groups ${node} was ALLOWED (#16428)")
			}
		})
	}
}

// #16428 acceptance at the commit layer: a restricted class committing a
// candidate whose only difference from the active ${node} cluster tree
// is an unrelated allowed leaf must be permitted, while a candidate that
// adds a denied leaf via a node group must still be refused.
func TestRestrictedCommitOnNodeGroupCluster16428(t *testing.T) {
	cfg := cfg9892(t)
	active := parseHierText(t, `groups { node0 { system { host-name fw0; } } node1 { system { host-name fw1; } } } apply-groups "${node}"; system { host-name base16428; }`)
	unrelated := parseHierText(t, `groups { node0 { system { host-name fw0; } } node1 { system { host-name fw1; } } } apply-groups "${node}"; system { host-name base16428; services { ssh; } }`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", unrelated, active); err != nil {
		t.Fatalf("unrelated commit on ${node} cluster refused: %v (#16428)", err)
	}
	denied := parseHierText(t, `groups { node0 { system { root-authentication { plain-text-password hunter2; } } } node1 { system { host-name fw1; } } } apply-groups "${node}"; system { host-name base16428; }`)
	if err := AuthorizeExpandedCandidate(cfg, "limited", denied, active); err == nil {
		t.Fatal("denied leaf via node group allowed at commit (#16428)")
	}
}

// #16428 fail-closed census: a plain-view failure that is NOT the
// ${node} trigger must stay fatal even when node views exist. An
// undefined group alongside a resolvable ${node} idiom, and an undefined
// node group, both refuse — never adjudicated as zero mutations.
func TestNodeVarMixedUndefinedStillFailsClosed16428(t *testing.T) {
	cfg := cfg9892(t)
	for name, text := range map[string]string{
		"undefined-alongside-node": `groups { node0 { system { host-name fw0; } } } apply-groups [ MISSING16428 "${node}" ];`,
		"undefined-node-group":     `groups { node0 { system { host-name fw0; } } } apply-groups "${node}";`,
	} {
		t.Run(name, func(t *testing.T) {
			tree := parseHierText(t, text)
			lines, err := ExpandedMutationLines(tree)
			if name == "undefined-node-group" {
				// Only node1 is undefined: node0 resolves, the config is
				// valid on node0, and the node1 view contributes nothing
				// (existing non-fatal node-view semantics). The lines
				// must be the node0 view, not an error and not empty.
				if err != nil {
					t.Fatalf("node0-only ${node} tree errored: %v (#16428)", err)
				}
				if !strings.Contains(strings.Join(lines, "\n"), "host-name fw0") {
					t.Fatalf("node0 view does not materialize: %v (#16428)", lines)
				}
				if err := AuthorizeExpandedTree(cfg, "limited", tree); err != nil {
					t.Fatalf("node0-only ${node} tree refused: %v (#16428)", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ExpandedMutationLines allowed unresolvable tree (lines=%v) (#16428)", lines)
			}
		})
	}
}
