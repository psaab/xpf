package config

import (
	"strings"
	"testing"
)

// #2217: commit-time strict validation of three previously-unvalidated
// firewall/application cross-references that each silently fail OPEN at the
// dataplane:
//
//   - Finding A: firewall filter term `then policer <name>` referencing a
//     policer that is not defined under `firewall policer` /
//     `firewall three-color-policer` (the rate-limit silently never applies).
//   - Finding B: `applications application-set <set>` member referencing
//     neither a defined application nor a defined nested application-set (a
//     policy matching the set silently fails to match the intended traffic).
//   - Finding C: firewall filter term `then routing-instance <name>` (FBF)
//     referencing a routing-instance not defined under `routing-instances`
//     (matched packets steer toward a routing table that does not exist).
//
// Each finding is tested for BOTH AST shapes (flat-set via ParseSetCommand +
// SetPath, hierarchical via NewParser), in both directions: an UNDEFINED
// reference is hard-rejected at commit (the fail-on-revert assertion — delete
// the validator and the reject disappears), and a DEFINED reference commits
// cleanly with no false reject.

// ---------------------------------------------------------------------------
// Finding A — `then policer <name>`
// ---------------------------------------------------------------------------

func TestPolicerRefUndefinedRejectedFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 then policer no-such-policer",
		"set firewall family inet filter f1 term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for `then policer no-such-policer`, got nil")
	}
	if !strings.Contains(err.Error(), "undefined policer") ||
		!strings.Contains(err.Error(), "no-such-policer") {
		t.Fatalf("error = %v, want it to name the undefined policer", err)
	}
}

func TestPolicerRefUndefinedRejectedHierarchical(t *testing.T) {
	input := `firewall {
    family inet {
        filter f1 {
            term t1 {
                then {
                    policer no-such-policer;
                    accept;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for `then policer no-such-policer`, got nil")
	}
	if !strings.Contains(err.Error(), "undefined policer") {
		t.Fatalf("error = %v, want undefined-policer rejection", err)
	}
}

func TestPolicerRefDefinedCommitsFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall policer p1 if-exceeding bandwidth-limit 1m burst-size-limit 15k",
		"set firewall policer p1 then discard",
		"set firewall family inet filter f1 term t1 then policer p1",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined policer must commit cleanly, got: %v", err)
	}
	if got := cfg.Firewall.FiltersInet["f1"].Terms[0].Policer; got != "p1" {
		t.Fatalf("term policer = %q, want p1", got)
	}
}

// A three-color-policer is also a valid `then policer` target.
func TestPolicerRefThreeColorCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall three-color-policer tcp1 single-rate color-blind",
		"set firewall three-color-policer tcp1 single-rate committed-information-rate 1m",
		"set firewall three-color-policer tcp1 single-rate committed-burst-size 15k",
		"set firewall three-color-policer tcp1 single-rate excess-burst-size 30k",
		"set firewall three-color-policer tcp1 then discard",
		"set firewall family inet filter f1 term t1 then policer tcp1",
		"set firewall family inet filter f1 term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("defined three-color-policer must commit cleanly, got: %v", err)
	}
}

// The strict reject is downgraded to a warning on the tolerant load path so an
// already-persisted config carrying the typo still boots (#1960).
func TestPolicerRefUndefinedLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 then policer no-such-policer",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through undefined policer, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "firewall policer reference") {
		t.Fatalf("expected a downgraded policer-reference warning, got: %v", cfg.Warnings)
	}
}

// ---------------------------------------------------------------------------
// Finding C — `then routing-instance <name>` (FBF)
// ---------------------------------------------------------------------------

func TestFBFRoutingInstanceRefUndefinedRejectedFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 then routing-instance no-such-ri",
		"set firewall family inet filter f1 term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for `then routing-instance no-such-ri`, got nil")
	}
	if !strings.Contains(err.Error(), "undefined routing-instance") ||
		!strings.Contains(err.Error(), "no-such-ri") {
		t.Fatalf("error = %v, want it to name the undefined routing-instance", err)
	}
}

func TestFBFRoutingInstanceRefUndefinedRejectedHierarchical(t *testing.T) {
	input := `firewall {
    family inet {
        filter f1 {
            term t1 {
                then {
                    routing-instance no-such-ri;
                    accept;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for `then routing-instance no-such-ri`, got nil")
	}
	if !strings.Contains(err.Error(), "undefined routing-instance") {
		t.Fatalf("error = %v, want undefined-routing-instance rejection", err)
	}
}

func TestFBFRoutingInstanceRefDefinedCommitsFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set firewall family inet filter f1 term t1 then routing-instance ISP-B",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined routing-instance must commit cleanly, got: %v", err)
	}
	if got := cfg.Firewall.FiltersInet["f1"].Terms[0].RoutingInstance; got != "ISP-B" {
		t.Fatalf("term routing-instance = %q, want ISP-B", got)
	}
}

func TestFBFRoutingInstanceRefUndefinedLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 then routing-instance no-such-ri",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through undefined routing-instance, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "firewall routing-instance reference") {
		t.Fatalf("expected a downgraded routing-instance-reference warning, got: %v", cfg.Warnings)
	}
}

func TestFBFDefaultRoutingInstanceAliasAcceptedStrictFlatSet11308(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 then routing-instance default",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile must accept Juniper's default-instance alias: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["f1"]
	if filter == nil || len(filter.Terms) == 0 || filter.Terms[0].RoutingInstance != "default" {
		t.Fatalf("compiled term must preserve the authored alias, got: %+v", filter)
	}
}

func TestFBFDefaultRoutingInstanceAliasAcceptedStrictHierarchicalInet6_11308(t *testing.T) {
	input := `firewall {
    family inet6 {
        filter f6 {
            term t6 {
                then {
                    routing-instance default;
                    accept;
                }
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict inet6 compile must accept the default-instance alias: %v", err)
	}
	filter := cfg.Firewall.FiltersInet6["f6"]
	if filter == nil || len(filter.Terms) == 0 || filter.Terms[0].RoutingInstance != "default" {
		t.Fatalf("compiled inet6 term must preserve the authored alias, got: %+v", filter)
	}
}

func TestFBFDefaultRoutingInstanceAliasLenientDoesNotWarn11308(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 then routing-instance default",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must accept the default-instance alias: %v", err)
	}
	if warningsContain(cfg.Warnings, "firewall routing-instance reference") {
		t.Fatalf("the documented default alias is not a dangling-reference warning: %v", cfg.Warnings)
	}
	filter := cfg.Firewall.FiltersInet["f1"]
	if filter == nil || len(filter.Terms) == 0 || filter.Terms[0].RoutingInstance != "default" {
		t.Fatalf("tolerant compile must preserve the authored alias, got: %+v", filter)
	}
}

func fbfDeclaredInstanceCommands11644(instance, target string) []string {
	cmds := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances " + instance + " instance-type virtual-router",
		"set routing-instances " + instance + " interface ge-0/0/1.0",
		"set routing-instances " + instance + " routing-options static route 198.51.100.0/24 discard",
	}
	if target != "" {
		cmds = append(cmds,
			"set firewall family inet filter f1 term t1 then routing-instance "+target,
			"set firewall family inet filter f1 term t1 then accept",
		)
	}
	return cmds
}

func requireFBFDefaultDeclarationCollision11644(t *testing.T, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted routing-instances default together with the FBF default alias")
	}
}

func requireDeclaredInstanceSurvives11644(t *testing.T, cfg *Config, name string) *RoutingInstanceConfig {
	t.Helper()
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("declared instance was lost or duplicated: %+v", cfg.RoutingInstances)
	}
	ri := cfg.RoutingInstances[0]
	if ri.Name != name || ri.InstanceType != "virtual-router" {
		t.Fatalf("declared instance changed: %+v", ri)
	}
	if ri.TableID != StableRoutingInstanceTableID(name) || ri.TableID == 254 {
		t.Fatalf("named instance table = %d, want stable non-main table %d", ri.TableID, StableRoutingInstanceTableID(name))
	}
	if len(ri.Interfaces) != 1 || ri.Interfaces[0] != "ge-0/0/1.0" {
		t.Fatalf("declared instance members were changed: %v", ri.Interfaces)
	}
	if len(ri.StaticRoutes) != 1 || !ri.StaticRoutes[0].Discard {
		t.Fatalf("declared instance static route was lost: %+v", ri.StaticRoutes)
	}
	if len(cfg.QuarantinedRoutingInstances) != 0 {
		t.Fatalf("declared instance was quarantined: %+v", cfg.QuarantinedRoutingInstances)
	}
	return ri
}

func TestFBFDefaultDeclarationCollisionRejectedStrictFlatSet11644(t *testing.T) {
	tree := buildTree(t, fbfDeclaredInstanceCommands11644("default", "default"))
	requireFBFDefaultDeclarationCollision11644(t, tree)
}

func TestFBFDefaultDeclarationCollisionRejectedStrictHierarchicalInet6_11644(t *testing.T) {
	input := `routing-instances {
    default {
        instance-type virtual-router;
    }
}
firewall {
    family inet6 {
        filter f6 {
            term t6 {
                then {
                    routing-instance default;
                    accept;
                }
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	requireFBFDefaultDeclarationCollision11644(t, tree)
}

func TestFBFDefaultDeclarationCollisionTolerantKeepsInstanceAndTerm11644(t *testing.T) {
	tree := buildTree(t, fbfDeclaredInstanceCommands11644("default", "default"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must keep the declared instance and FBF term: %v", err)
	}
	requireDeclaredInstanceSurvives11644(t, cfg, "default")
	filter := cfg.Firewall.FiltersInet["f1"]
	if filter == nil || len(filter.Terms) != 1 ||
		filter.Terms[0].Name != "t1" || filter.Terms[0].RoutingInstance != "default" ||
		filter.Terms[0].Action != "accept" {
		t.Fatalf("tolerant compile rewrote or dropped the FBF term: %+v", filter)
	}
}

func TestFBFDefaultDeclarationWithoutAliasStillCommits11644(t *testing.T) {
	tree := buildTree(t, fbfDeclaredInstanceCommands11644("default", ""))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a default declaration without an FBF default target must remain valid: %v", err)
	}
	requireDeclaredInstanceSurvives11644(t, cfg, "default")
}

func TestFBFDefaultNameCaseVariantRemainsNamedTarget11644(t *testing.T) {
	tree := buildTree(t, fbfDeclaredInstanceCommands11644("Default", "Default"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("case-variant named instance and target must remain valid: %v", err)
	}
	requireDeclaredInstanceSurvives11644(t, cfg, "Default")
	filter := cfg.Firewall.FiltersInet["f1"]
	if filter == nil || len(filter.Terms) != 1 || filter.Terms[0].RoutingInstance != "Default" {
		t.Fatalf("case-variant FBF term did not retain its named target: %+v", filter)
	}
}

// ---------------------------------------------------------------------------
// Finding B — application-set member
// ---------------------------------------------------------------------------

func TestAppSetMemberUndefinedRejectedFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set applications application-set web application no-such-app",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for app-set member `no-such-app`, got nil")
	}
	if !strings.Contains(err.Error(), "application-set \"web\"") ||
		!strings.Contains(err.Error(), "no-such-app") {
		t.Fatalf("error = %v, want it to name the undefined member", err)
	}
}

func TestAppSetMemberUndefinedRejectedHierarchical(t *testing.T) {
	input := `applications {
    application-set web {
        application no-such-app;
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for app-set member `no-such-app`, got nil")
	}
	if !strings.Contains(err.Error(), "no-such-app") {
		t.Fatalf("error = %v, want undefined-member rejection", err)
	}
}

// A nested application-set member that is undefined is also rejected.
func TestAppSetMemberNestedUndefinedRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application-set web application app1",
		"set applications application-set web application-set no-such-set",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined nested set member, got nil")
	}
	if !strings.Contains(err.Error(), "no-such-set") {
		t.Fatalf("error = %v, want it to name the undefined nested set", err)
	}
}

func TestAppSetMemberDefinedCommitsFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application-set web application app1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined app-set member must commit cleanly, got: %v", err)
	}
	if got := cfg.Applications.ApplicationSets["web"].Applications; len(got) != 1 || got[0] != "app1" {
		t.Fatalf("app-set members = %v, want [app1]", got)
	}
}

// A junos-* predefined application is a valid member with no user definition.
func TestAppSetMemberPredefinedCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set applications application-set web application junos-http",
		"set applications application-set web application junos-https",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("predefined junos-* members must commit cleanly, got: %v", err)
	}
}

func TestAppSetMemberUndefinedLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set applications application-set web application no-such-app",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through undefined app-set member, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "application-set member") {
		t.Fatalf("expected a downgraded app-set-member warning, got: %v", cfg.Warnings)
	}
}

// A multi-term user application mints an IMPLICIT application-set named after
// the parent application whose members are compiler-synthesized term names. The
// strict member gate must NOT false-reject those synthesized members.
func TestAppSetImplicitMultiTermNotFalseRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set applications application multi term t1 protocol tcp destination-port 80",
		"set applications application multi term t2 protocol udp destination-port 53",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("implicit multi-term application-set must commit cleanly, got: %v", err)
	}
	// The implicit set exists and carries the synthesized term apps.
	set := cfg.Applications.ApplicationSets["multi"]
	if set == nil || len(set.Applications) == 0 {
		t.Fatalf("expected an implicit application-set `multi` with members, got %+v", set)
	}
}

func warningsContain(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
