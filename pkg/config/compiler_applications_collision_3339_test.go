package config

import (
	"strings"
	"testing"
)

// #3339 (Codex review 080 M07/M08): the application compiler silently overwrote
// application / application-set definitions on a name collision (last-write-wins
// map writes) instead of rejecting at commit, letting policy expansion and the
// AppID catalog resolve a name to different definitions. These tests pin the
// strict reject at commit (CompileConfig) and the lenient downgrade-to-warning
// on the tolerant load / peer-sync path (CompileConfigLenient).

// buildTreeFromSet (shared with ipsec_proposal_ref_test.go) builds a candidate
// ConfigTree from flat `set` commands the way the configstore does
// (ParseSetCommand + SetPath), NOT NewParser — the parser merges newlines and
// would collapse separate set lines into one node.

// M07: an application and an application-set sharing a name. The set-command
// config tree keeps these as distinct stanzas (different keywords), so both
// reach the compiler and the application-set silently overwrites the
// application's map entry.
func TestApplicationVsApplicationSetNameCollisionRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application web protocol tcp",
		"set applications application web destination-port 80",
		"set applications application-set web application junos-https",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of application/application-set name collision, got nil")
	}
	if !strings.Contains(err.Error(), "web") ||
		!strings.Contains(err.Error(), "BOTH an application and an application-set") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// M07 variant: a MULTI-TERM application <X> mints an implicit application-set
// <X>; an explicit `application-set <X>` then silently replaces it. This is the
// exact implicit-set-overwrite case from the issue.
func TestImplicitSetOverwrittenByExplicitSetRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application multi term t1 protocol tcp destination-port 80",
		"set applications application multi term t2 protocol udp destination-port 53",
		"set applications application-set multi application junos-http",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of explicit set overwriting implicit multi-term set, got nil")
	}
	if !strings.Contains(err.Error(), "multi") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application definition (same name twice). Survives as distinct AST
// siblings on a hierarchical representation; built here directly so the gate is
// exercised independently of how the tree was produced.
func TestDuplicateApplicationDefinitionRejected(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"applications"}, Children: []*Node{
			{Keys: []string{"application", "dup"}, Children: []*Node{
				{Keys: []string{"protocol", "tcp"}, IsLeaf: true},
			}},
			{Keys: []string{"application", "dup"}, Children: []*Node{
				{Keys: []string{"protocol", "udp"}, IsLeaf: true},
			}},
		}},
	}}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application definition, got nil")
	}
	if !strings.Contains(err.Error(), "application \"dup\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application-set definition (same name twice).
func TestDuplicateApplicationSetDefinitionRejected(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"applications"}, Children: []*Node{
			{Keys: []string{"application", "a1"}, Children: []*Node{
				{Keys: []string{"protocol", "tcp"}, IsLeaf: true},
			}},
			{Keys: []string{"application-set", "dupset"}, Children: []*Node{
				{Keys: []string{"application", "a1"}, IsLeaf: true},
			}},
			{Keys: []string{"application-set", "dupset"}, Children: []*Node{
				{Keys: []string{"application", "junos-http"}, IsLeaf: true},
			}},
		}},
	}}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application-set definition, got nil")
	}
	if !strings.Contains(err.Error(), "application-set \"dupset\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// M08: two terms generating the same per-term application name. Built as
// distinct term siblings (the hierarchical shape) so both reach
// parseApplicationTerms and the later overwrites the earlier.
func TestDuplicateTermGeneratedNameRejected(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"applications"}, Children: []*Node{
			{Keys: []string{"application", "app"}, Children: []*Node{
				{Keys: []string{"term", "dup", "protocol", "tcp", "destination-port", "80"}, IsLeaf: true},
				{Keys: []string{"term", "dup", "protocol", "udp", "destination-port", "53"}, IsLeaf: true},
			}},
		}},
	}}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate term generated name, got nil")
	}
	if !strings.Contains(err.Error(), "app-dup") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Valid distinct names commit cleanly: an application, a same-config
// application-set with a DIFFERENT name, a multi-term application whose implicit
// set name is not reused, and a user application shadowing a predefined junos-*
// application (the legitimate shadow case must NOT be rejected).
func TestDistinctApplicationNamesCommit(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application web protocol tcp destination-port 80",
		"set applications application-set webset application web",
		"set applications application-set webset application junos-https",
		"set applications application multi term t1 protocol tcp destination-port 80",
		"set applications application multi term t2 protocol udp destination-port 53",
		// A user application shadowing a predefined name is legitimate, not a
		// collision: there is no application-set with this name.
		"set applications application junos-ssh protocol tcp destination-port 22",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: unexpected error on distinct names: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3339") {
			t.Fatalf("unexpected #3339 collision warning on a valid config: %q", w)
		}
	}
}

// A user application-set name also shadows a predefined application. Direct
// references resolve application-first, while nested application-set members
// resolve user-set-first; reject this cross-kind ambiguity at commit.
func applicationSetPredefinedApplicationShadowTree(t *testing.T) *ConfigTree {
	return buildTreeFromSet(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set applications application custom8443 protocol tcp destination-port 8443",
		"set applications application-set junos-http application custom8443",
		"set applications application-set parent application-set junos-http",
		"set security policies from-zone trust to-zone untrust policy direct match source-address any",
		"set security policies from-zone trust to-zone untrust policy direct match destination-address any",
		"set security policies from-zone trust to-zone untrust policy direct match application junos-http",
		"set security policies from-zone trust to-zone untrust policy direct then deny",
		"set security policies from-zone trust to-zone untrust policy nested match source-address any",
		"set security policies from-zone trust to-zone untrust policy nested match destination-address any",
		"set security policies from-zone trust to-zone untrust policy nested match application parent",
		"set security policies from-zone trust to-zone untrust policy nested then deny",
	})
}

func TestApplicationSetShadowsPredefinedApplicationRejected(t *testing.T) {
	_, err := CompileConfig(applicationSetPredefinedApplicationShadowTree(t))
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of application-set shadowing predefined application")
	}
	if !strings.Contains(err.Error(), `application-set "junos-http"`) ||
		!strings.Contains(err.Error(), `predefined application "junos-http"`) ||
		!strings.Contains(err.Error(), "#12220") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

func TestApplicationSetShadowsPredefinedApplicationLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(applicationSetPredefinedApplicationShadowTree(t))
	if err != nil {
		t.Fatalf("CompileConfigLenient: expected warning instead of rejection, got %v", err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, `application-set "junos-http"`) &&
			strings.Contains(warning, `predefined application "junos-http"`) &&
			strings.Contains(warning, "#12220") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected #12220 warning for predefined application shadow, got %v", cfg.Warnings)
	}
	if _, collision := cfg.Applications.CollidingNames["junos-http"]; !collision {
		t.Fatal("lenient compile did not quarantine the ambiguous application-set name")
	}

	directPolicy := findZonePairPolicy(t, cfg, "trust", "untrust", "direct")
	if len(directPolicy.Match.Applications) != 1 || directPolicy.Match.Applications[0] != "junos-http" {
		t.Fatalf("direct policy application = %v; want [junos-http]", directPolicy.Match.Applications)
	}
	nestedPolicy := findZonePairPolicy(t, cfg, "trust", "untrust", "nested")
	if len(nestedPolicy.Match.Applications) != 1 || nestedPolicy.Match.Applications[0] != "parent" {
		t.Fatalf("nested policy application = %v; want [parent]", nestedPolicy.Match.Applications)
	}

	// Preserve the base behavior in this regression cell: the direct name is
	// the predefined tcp/80 application, but the nested policy expands through
	// the user-defined junos-http set to custom8443. The diagnostic prevents
	// these meanings from silently reaching a commit.
	direct, ok := ResolveApplication("junos-http", cfg.Applications.Applications)
	if !ok || direct.Protocol != "tcp" || direct.DestinationPort != "80" {
		t.Fatalf("direct junos-http = %#v, %t; want predefined tcp/80", direct, ok)
	}
	nested, err := ExpandApplicationSet("parent", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(parent): %v", err)
	}
	if len(nested) != 1 || nested[0] != "custom8443" {
		t.Fatalf("nested parent expansion = %v; want [custom8443]", nested)
	}
	custom, ok := ResolveApplication(nested[0], cfg.Applications.Applications)
	if !ok || custom.Protocol != "tcp" || custom.DestinationPort != "8443" {
		t.Fatalf("nested application = %#v, %t; want custom tcp/8443", custom, ok)
	}
	if drops := ApplicationReferenceMatchDrops("junos-http", &cfg.Applications); len(drops) == 0 {
		t.Fatal("direct reference to ambiguous junos-http was not quarantined")
	}
	if drops := ApplicationReferenceMatchDrops("parent", &cfg.Applications); len(drops) == 0 {
		t.Fatal("nested reference to parent containing ambiguous junos-http was not quarantined")
	}
}

// parseHier (shared with vrrp_track_test.go) parses a hierarchical (braced)
// config string. A hierarchical parse can emit MULTIPLE top-level sibling
// `applications {}` nodes; the compiler compiles every one, so the collision
// gate must aggregate across all of them.

// Collision SPLIT across two top-level `applications {}` blocks: an application
// in the first block, an application-set of the same name in the second. The
// compiler compiles both blocks, so this must be rejected — a walker that
// stopped at the first `applications` node missed it.
func TestApplicationVsApplicationSetCollisionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application web {
        protocol tcp;
        destination-port 80;
    }
}
applications {
    application-set web {
        application junos-https;
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of app/app-set collision split across applications blocks, got nil")
	}
	if !strings.Contains(err.Error(), "web") ||
		!strings.Contains(err.Error(), "BOTH an application and an application-set") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application definition split across two `applications {}` blocks.
func TestDuplicateApplicationDefinitionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application dup {
        protocol tcp;
        destination-port 80;
    }
}
applications {
    application dup {
        protocol udp;
        destination-port 53;
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application split across blocks, got nil")
	}
	if !strings.Contains(err.Error(), "application \"dup\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application-set definition split across two `applications {}` blocks.
func TestDuplicateApplicationSetDefinitionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application a1 {
        protocol tcp;
        destination-port 80;
    }
    application-set dupset {
        application a1;
    }
}
applications {
    application-set dupset {
        application junos-http;
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application-set split across blocks, got nil")
	}
	if !strings.Contains(err.Error(), "application-set \"dupset\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Two distinct `applications {}` blocks with non-colliding names commit cleanly
// — the aggregation must not over-reject legitimately split definitions.
func TestDistinctApplicationNamesSplitAcrossBlocksCommit(t *testing.T) {
	tree := parseHier(t, `
applications {
    application web {
        protocol tcp;
        destination-port 80;
    }
}
applications {
    application ssh {
        protocol tcp;
        destination-port 22;
    }
    application-set webset {
        application web;
        application ssh;
    }
}
`)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: unexpected error on distinct names split across blocks: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3339") {
			t.Fatalf("unexpected #3339 collision warning on a valid split config: %q", w)
		}
	}
}

// #3472 (Codex review audit 116, H01/H02/H03 + M03): #3339's collision pass
// only counted AUTHORED application/application-set names, so a GENERATED
// per-term application name (`<parent>-<term>`, written into apps.Applications)
// was invisible to it and still silently last-write-wins. These fixtures pin the
// strict reject for the three generated-name collision classes and the warning
// for a generated name shadowing a predefined junos-* application.

// H01: a generated per-term application name overwrites an authored top-level
// application. Multi-term `app` term `ssh` mints `app-ssh`; an authored
// `application app-ssh` also exists. Both write apps.Applications["app-ssh"];
// before #3472 the later write silently won with no commit error.
func TestGeneratedTermNameOverwritesAuthoredApplicationRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application app term ssh protocol tcp destination-port 22",
		"set applications application app term web protocol tcp destination-port 80",
		"set applications application app-ssh protocol udp destination-port 53",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of generated term name overwriting authored application, got nil")
	}
	if !strings.Contains(err.Error(), "app-ssh") ||
		!strings.Contains(err.Error(), "authored application") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// H02: a generated per-term application name collides with an authored
// application-set. Generated `app-ssh` (apps.Applications) vs `application-set
// app-ssh` (apps.ApplicationSets) — the two resolution paths (application-first
// for policy expansion, set-first for the AppID catalog) then diverge.
func TestGeneratedTermNameCollidesWithApplicationSetRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application app term ssh protocol tcp destination-port 22",
		"set applications application app term web protocol tcp destination-port 80",
		"set applications application-set app-ssh application junos-https",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of generated term name colliding with application-set, got nil")
	}
	if !strings.Contains(err.Error(), "app-ssh") ||
		!strings.Contains(err.Error(), "authored application-set") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// H03: two DIFFERENT parents generate the same per-term application name.
// `application a-b term c` and `application a term b-c` both mint `a-b-c`;
// #3339's per-parent termSeen bucketed them separately so the later silently won.
func TestCrossParentGeneratedNameCollisionRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application a-b term c protocol tcp destination-port 22",
		"set applications application a-b term x protocol tcp destination-port 81",
		"set applications application a term b-c protocol udp destination-port 53",
		"set applications application a term y protocol udp destination-port 54",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of cross-parent generated name collision, got nil")
	}
	if !strings.Contains(err.Error(), "a-b-c") ||
		!strings.Contains(err.Error(), "collides across parents") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// M03: a generated per-term application name shadows a predefined junos-*
// application. `application junos term ssh` mints `junos-ssh`, which shadows the
// predefined junos-ssh service. This is a WARNING on BOTH paths (never a hard
// reject) — a user-defined application legitimately wins over predefined, so the
// strict commit must SUCCEED while surfacing the accidental shadow.
func TestGeneratedTermNameShadowsPredefinedWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application junos term ssh protocol tcp destination-port 22",
		"set applications application junos term web protocol tcp destination-port 80",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: a generated predefined shadow must warn, not reject: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "junos-ssh") && strings.Contains(w, "shadows the predefined") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #3472 predefined-shadow warning for junos-ssh, got: %v", cfg.Warnings)
	}
}

// The three generated-name collision classes must downgrade to a warning on the
// tolerant load / peer-sync path so an already-persisted config still BOOTS.
func TestGeneratedTermNameCollisionLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application app term ssh protocol tcp destination-port 22",
		"set applications application app term web protocol tcp destination-port 80",
		"set applications application app-ssh protocol udp destination-port 53",
	})

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: generated-name collision must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "app-ssh") && strings.Contains(w, "#3472") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #3472 generated-name collision warning on the lenient path, got: %v", cfg.Warnings)
	}
}

// A multi-term application whose generated names do NOT collide with anything
// must commit cleanly — the generated-name pass must not over-reject the normal
// multi-term case.
func TestGeneratedTermNamesNoCollisionCommit(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application app term ssh protocol tcp destination-port 22",
		"set applications application app term web protocol tcp destination-port 80",
		"set applications application other protocol udp destination-port 53",
		"set applications application-set myset application app",
		"set applications application-set myset application other",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: unexpected error on non-colliding generated names: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3472") {
			t.Fatalf("unexpected #3472 warning on a non-colliding config: %q", w)
		}
	}
}

// #3472 cross-BLOCK generated-name collision (the #3561/#3562/#3566 duplicate-
// block discipline). A hierarchical parse can emit MULTIPLE top-level sibling
// `applications {}` nodes; compileExpanded compiles every one, and the gate's
// genParents/genOrder table aggregates generated names across ALL of them. Here
// block A's multi-term `a-b` mints `a-b-c` and block B's multi-term `a` ALSO
// mints `a-b-c` (term `b-c`), so the two generated names collide across parents
// AND across blocks (H03). A gate that iterated only the first `applications`
// block — or did not aggregate genParents across blocks — would see only one
// producer of `a-b-c`, miss the collision, and compile clean. This pins the
// iterate-all aggregation against a future first-match regression. Uses NewParser
// (hierarchical) — ParseSetCommand would merge the blocks into one node.
func TestCrossParentGeneratedNameCollisionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application a-b {
        term c {
            protocol tcp;
            destination-port 22;
        }
        term x {
            protocol tcp;
            destination-port 81;
        }
    }
}
applications {
    application a {
        term b-c {
            protocol udp;
            destination-port 53;
        }
        term y {
            protocol udp;
            destination-port 54;
        }
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of cross-parent generated name collision split across applications blocks, got nil")
	}
	if !strings.Contains(err.Error(), "a-b-c") ||
		!strings.Contains(err.Error(), "collides across parents") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Lenient path (load / peer-sync) must WARN, not brick: an already-persisted
// colliding config still compiles, with the collision surfaced as a warning.
func TestApplicationNameCollisionLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application web protocol tcp destination-port 80",
		"set applications application-set web application junos-https",
	})

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: collision must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "web") && strings.Contains(w, "#3339") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #3339 collision warning on the lenient path, got: %v", cfg.Warnings)
	}
}
