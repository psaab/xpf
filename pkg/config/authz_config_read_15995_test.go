package config

import (
	"strings"
	"testing"
)

// #15995 (A8-01): the *-configuration regexes were evaluated only on the
// joined requested path, so `deny-configuration "^security ipsec"`
// could not match a request for "security" — yet the subtree renderer
// (FormatPathRedacted and twins) renders the whole `security` subtree,
// ipsec included. ShowConfig / scoped Compare / scoped Rollback on
// gRPC+REST+CLI all inherited the leak through the shared gate, which
// adjudicated the requested path and never the rendered descendants.
//
// The fix prices every rendered descendant: AuthorizeConfigShowPathRendered
// (and the compare/rollback wrappers) walk the tree(s) that will actually
// be rendered and refuse the ancestor read when any strict descendant is
// denied by the *-configuration pair — or, for an allow-configuration
// allowlist, not covered by it. The operational pair stays charged once
// on the requested command (a descendant is not a command spelling).
//
// Fixture: deny-configuration "^security ipsec"; the rendered `security`
// tree carries zones (allowed sibling), ipsec (denied descendant) and
// policies (allowed sibling).

const tree15995Text = `
security {
    zones {
        security-zone trust {
            description "ZONE-DESC-15995";
        }
    }
    ipsec {
        vpn vpn1 {
            bind-interface st0.0;
            pre-shared-key ascii-text dummy15995;
        }
    }
    policies {
        from-zone trust to-zone trust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func cfg15995(t *testing.T, allow, deny string) *Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("system { login { class limited { permissions [ configure view ]; ")
	if allow != "" {
		b.WriteString("allow-configuration \"" + allow + "\"; ")
	}
	if deny != "" {
		b.WriteString("deny-configuration \"" + deny + "\"; ")
	}
	b.WriteString("} } }")
	tree, errs := NewParser(b.String()).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture class does not parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture class does not compile: %v", err)
	}
	if _, restricted, err := ConfigurationLoginRegexesFor(cfg, "limited"); err != nil || !restricted {
		t.Fatalf("fixture class is not configuration-restricted (restricted=%v err=%v)", restricted, err)
	}
	return cfg
}

func tree15995(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(tree15995Text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture tree does not parse: %v", errs)
	}
	// Premise: the unpriced render really does disclose the descendant.
	if out := tree.FormatPathRedacted([]string{"security"}); !strings.Contains(out, "ipsec") {
		t.Fatalf("premise broken: subtree render of [security] carries no ipsec:\n%s", out)
	}
	return tree
}

// Premise / control: pricing only the requested path (the pre-fix gate)
// admits the ancestor read. This cell documents the leak shape; if it
// ever starts failing, AuthorizeConfigShowPath itself changed meaning.
func TestConfigShowPathOnlyPricesRequestedPath15995(t *testing.T) {
	cfg := cfg15995(t, "", "^security ipsec")
	if err := AuthorizeConfigShowPath(cfg, "limited", []string{"security"}, ""); err != nil {
		t.Fatalf("requested-path-only pricing refused [security]: %v", err)
	}
	if err := AuthorizeConfigShowPath(cfg, "limited", []string{"security", "ipsec"}, ""); err == nil {
		t.Fatal("direct [security ipsec] read was ALLOWED under ^security ipsec")
	}
}

func TestConfigShowPathRenderedPricesDescendants15995(t *testing.T) {
	cfg := cfg15995(t, "", "^security ipsec")
	tree := tree15995(t)

	// Denied strict descendant below the requested ancestor: refuse.
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"security"}, "", tree); err == nil {
		t.Error("ShowConfig [security] was ALLOWED though it renders denied descendant security ipsec (#15995)")
	}
	// Same in display-set form (format must not change the price).
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"security"}, "display set", tree); err == nil {
		t.Error("ShowConfig [security] | display set was ALLOWED though it renders denied descendant (#15995)")
	}
	// Direct denied path still refused (control — already true pre-fix).
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"security", "ipsec"}, "", tree); err == nil {
		t.Error("ShowConfig [security ipsec] was ALLOWED under ^security ipsec")
	}
	// Allowed siblings still render: zones and policies carry no denied
	// descendant, and an unrelated top-level subtree is untouched.
	for _, path := range [][]string{
		{"security", "zones"},
		{"security", "policies"},
		{"interfaces"},
	} {
		if err := AuthorizeConfigShowPathRendered(cfg, "limited", path, "", tree); err != nil {
			t.Errorf("ShowConfig %v must stay admitted (no denied descendant): %v", path, err)
		}
	}
	// A path absent from the tree renders nothing: no descendant price.
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"routing-instances"}, "", tree); err != nil {
		t.Errorf("ShowConfig [routing-instances] (absent) must stay admitted: %v", err)
	}
	// Nil tree renders nothing.
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"security"}, "", nil); err != nil {
		t.Errorf("ShowConfig [security] with nil tree must stay admitted: %v", err)
	}
}

// The allowlist mirror: allow-configuration is an allowlist, so a
// descendant it does not cover is denied even though the requested
// ancestor itself matches the allow.
func TestConfigShowPathRenderedAllowlistDescendant15995(t *testing.T) {
	// Allow covers zones only; ipsec/policies descendants are uncovered.
	cfg := cfg15995(t, "^security zones", "")
	tree := tree15995(t)
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"security", "zones"}, "", tree); err != nil {
		t.Errorf("ShowConfig [security zones] must stay admitted under allow ^security zones: %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"security"}, "", tree); err == nil {
		t.Error("ShowConfig [security] was ALLOWED under allow ^security zones though it renders uncovered descendants (#15995)")
	}
}

func TestConfigShowCompareRollbackRendered15995(t *testing.T) {
	cfg := cfg15995(t, "", "^security ipsec")
	tree := tree15995(t)

	if err := AuthorizeConfigShowCompareAtPathRendered(cfg, "limited", []string{"security"}, tree); err == nil {
		t.Error("scoped ShowCompare [security] was ALLOWED though it diffs denied descendant (#15995)")
	}
	if err := AuthorizeConfigShowCompareAtPathRendered(cfg, "limited", []string{"security", "zones"}, tree); err != nil {
		t.Errorf("scoped ShowCompare [security zones] must stay admitted: %v", err)
	}
	// Denied descendant on EITHER arm refuses (here: second arm only).
	empty := mustTree14981(t, "security { zones { security-zone trust { description x; } } }")
	if err := AuthorizeConfigShowCompareAtPathRendered(cfg, "limited", []string{"security"}, empty, tree); err == nil {
		t.Error("scoped ShowCompare [security] was ALLOWED with denied descendant on one arm (#15995)")
	}
	if err := AuthorizeConfigShowRollbackAtPathRendered(cfg, "limited", []string{"security"}, "", tree); err == nil {
		t.Error("scoped ShowRollback [security] was ALLOWED though it renders denied descendant (#15995)")
	}
	if err := AuthorizeConfigShowRollbackAtPathRendered(cfg, "limited", []string{"security", "zones"}, "", tree); err != nil {
		t.Errorf("scoped ShowRollback [security zones] must stay admitted: %v", err)
	}
	// Empty path keeps the whole-render refusal for a restricted class.
	if err := AuthorizeConfigShowCompareAtPathRendered(cfg, "limited", nil, tree); err == nil {
		t.Error("global ShowCompare was ALLOWED for a configuration-restricted class")
	}
	if err := AuthorizeConfigShowRollbackAtPathRendered(cfg, "limited", nil, "", tree); err == nil {
		t.Error("whole-tree ShowRollback was ALLOWED for a configuration-restricted class")
	}
}

func TestConfigPathOnlyRendered15995(t *testing.T) {
	cfg := cfg15995(t, "", "^security ipsec")
	tree := tree15995(t)
	if err := AuthorizeConfigPathOnlyRendered(cfg, "limited", []string{"security"}, tree); err == nil {
		t.Error("AuthorizeConfigPathOnlyRendered [security] was ALLOWED though it renders denied descendant (#15995)")
	}
	if err := AuthorizeConfigPathOnlyRendered(cfg, "limited", []string{"security", "zones"}, tree); err != nil {
		t.Errorf("AuthorizeConfigPathOnlyRendered [security zones] must stay admitted: %v", err)
	}
}

// A class with no *-configuration regexes pays no descendant price, and
// the empty class is never gated.
func TestConfigShowRenderedUnrestricted15995(t *testing.T) {
	tree := tree15995(t)
	// Open class fixture: no regex leaves at all.
	cfg, err := func() (*Config, error) {
		tr, errs := NewParser("system { login { class open { permissions [ configure view ]; } } }").Parse()
		if len(errs) > 0 {
			t.Fatalf("open fixture parse: %v", errs)
		}
		return CompileConfig(tr)
	}()
	if err != nil {
		t.Fatalf("open fixture compile: %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(cfg, "open", []string{"security"}, "", tree); err != nil {
		t.Errorf("unrestricted class refused [security]: %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(cfg, "", []string{"security"}, "", tree); err != nil {
		t.Errorf("empty class refused [security]: %v", err)
	}
}
