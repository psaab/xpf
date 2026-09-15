package config

import (
	"reflect"
	"strings"
	"testing"
)

func firewallSetTree9899(t *testing.T, commands ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, quoted, grouped, err := ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatal(err)
		}
	}
	return tree
}

func TestQuotedSelfMatchValues9899(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keys   []string
		quoted []bool
		want   []string
	}{
		{"first quoted operand", []string{"protocol", "protocol", "tcp"}, []bool{false, true, false}, []string{"protocol", "tcp"}},
		{"later quoted operand", []string{"protocol", "tcp", "protocol"}, []bool{false, false, true}, []string{"tcp", "protocol"}},
		{"bare repeated keyword", []string{"protocol", "protocol", "tcp"}, nil, []string{"tcp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := &Node{Keys: tc.keys, KeysQuoted: tc.quoted, IsLeaf: true}
			if got := firewallMatchValues(node); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("match values = %q, want %q", got, tc.want)
			}
		})
	}
	for _, flat := range []bool{false, true} {
		var tree *ConfigTree
		if flat {
			tree = firewallSetTree9899(t,
				`set firewall family inet filter F term T from protocol [ tcp "protocol" ]`,
				`set firewall family inet filter F term T then discard`)
		} else {
			tree = fwTree9875(t, `term T { from { protocol [ tcp "protocol" ]; } then { discard; } }`)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("flat=%v: quoted self-named protocol silently disappeared at strict compile", flat)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatal(err)
		}
		if got := firstInetTerm(t, cfg, "F").Protocols; !reflect.DeepEqual(got, []string{"tcp", "protocol"}) {
			t.Errorf("flat=%v: tolerant compile lost refusal evidence: protocols=%q", flat, got)
		}
		if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "protocol") {
			t.Errorf("flat=%v: missing unknown-protocol warning", flat)
		}
	}
}

func TestImplicitInetFilter9899(t *testing.T) {
	spellings := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{"hierarchical", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { filter F { term T { from { protocol tcp; } then { discard; } } } }`)
		}},
		{"elided firewall root", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall filter F { term T { from { protocol tcp; } then { discard; } } }`)
		}},
		{"packed root and filter", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall filter F term T { from protocol tcp; then discard; }`)
		}},
		{"elided group firewall", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `groups { G { firewall filter F { term T { from { protocol tcp; } then { discard; } } } } } apply-groups G;`)
		}},
		{"nested names", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { filter { F { term { T { from { protocol tcp; } then { discard; } } } } } }`)
		}},
		{"flat set", func(t *testing.T) *ConfigTree {
			return firewallSetTree9899(t,
				`set firewall filter F term T from protocol tcp`,
				`set firewall filter F term T then discard`)
		}},
		{"group inheritance", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `groups { G { firewall { filter F { term T { from { protocol tcp; } then { discard; } } } } } } apply-groups G;`)
		}},
		{"flat group inheritance", func(t *testing.T) *ConfigTree {
			return firewallSetTree9899(t,
				`set groups G firewall filter F term T from protocol tcp`,
				`set groups G firewall filter F term T then discard`,
				`set apply-groups G`)
		}},
	}
	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			tree := sp.build(t)
			before := tree.Clone()
			for _, compile := range []func(*ConfigTree) (*Config, error){
				CompileConfig, CompileConfigLenient,
				func(tree *ConfigTree) (*Config, error) { return CompileConfigForNode(tree, 0) },
				func(tree *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tree, 0) },
			} {
				cfg, err := compile(tree)
				if err != nil {
					t.Fatal(err)
				}
				term := firstInetTerm(t, cfg, "F")
				if term.Action != "discard" || !reflect.DeepEqual(term.Protocols, []string{"tcp"}) {
					t.Fatalf("implicit inet changed filter behavior: %#v", term)
				}
				if len(cfg.Firewall.FiltersInet6) != 0 {
					t.Fatal("implicit inet leaked into inet6")
				}
			}
			if !reflect.DeepEqual(tree, before) {
				t.Fatal("compilation rewrote the candidate tree")
			}
		})
	}
}

func TestImplicitInetFilterGates9899(t *testing.T) {
	for _, tc := range []struct{ name, text, diagnostic string }{
		{"duplicate inet name", `firewall { filter F { term A { then { discard; } } } family inet { filter F { term B { then { accept; } } } } }`, "#8426"},
		{"any collision", `firewall { filter F { term A { then { discard; } } } family any { filter F { term B { then { accept; } } } } }`, "#3884"},
		{"unknown match", `firewall { filter F { term T { from { unknown-match 1; } then { accept; } } } }`, "unknown-match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := fwRawTree9875(t, tc.text)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("implicit inet bypassed existing strict filter gate")
			} else if !strings.Contains(err.Error(), tc.diagnostic) {
				t.Fatalf("wrong strict refusal: %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatal(err)
			}
			if warnings := strings.Join(cfg.Warnings, "\n"); !strings.Contains(warnings, tc.diagnostic) {
				t.Fatalf("tolerant compile hid %s: %s", tc.diagnostic, warnings)
			}
		})
	}
	tree := fwRawTree9875(t, `firewall {
		filter F { term T { then { discard; } } }
		family inet6 { filter F { term T { then { accept; } } } }
	}
	interfaces { ge-0/0/0 { unit 0 { family inet { filter { input F; } } } } }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("reference to implicit inet filter did not resolve: %v", err)
	}
	if firstInetTerm(t, cfg, "F").Action != "discard" || cfg.Firewall.FiltersInet6["F"].Terms[0].Action != "accept" {
		t.Fatal("implicit inet and explicit inet6 did not remain separate")
	}
}

// TestImplicitInetNestedGroupMultiFilter9899 pins P1: nested group inheritance
// with MORE THAN ONE filter. walkGroupToContext returns the FIRST matching
// scope only (ast_groups.go), so a group body normalized to one synthetic
// `family inet` wrapper PER implicit filter hides every later filter's
// template from a nested apply-groups lookup. Pre-fix RED: filter G loses its
// inherited term while F keeps its own.
func TestImplicitInetNestedGroupMultiFilter9899(t *testing.T) {
	termsOf := func(t *testing.T, cfg *Config, filter string) map[string]string {
		t.Helper()
		f := cfg.Firewall.FiltersInet[filter]
		if f == nil {
			t.Fatalf("filter %q missing after nested group expansion", filter)
		}
		out := make(map[string]string, len(f.Terms))
		for _, term := range f.Terms {
			out[term.Name] = term.Action
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		group string
		main  string
	}{
		{
			// The RED cell: group carries two IMPLICIT filters, main inherits
			// nested per-filter. Pre-fix the group normalizes to two
			// identically-keyed wrappers and G's lookup finds F's scope only.
			name:  "group implicit main explicit nested",
			group: `groups { G { firewall { filter F { term TG { then { accept; } } } filter G { term TG { then { accept; } } } } } }`,
			main:  `firewall { family inet { filter F { apply-groups G; term T1 { then { discard; } } } filter G { apply-groups G; term T1 { then { discard; } } } } }`,
		},
		{
			// Both sides implicit: same group-side cause, main-side wrappers
			// expand per-filter without cross-contamination.
			name:  "group implicit main implicit nested",
			group: `groups { G { firewall { filter F { term TG { then { accept; } } } filter G { term TG { then { accept; } } } } } }`,
			main:  `firewall { filter F { apply-groups G; term T1 { then { discard; } } } filter G { apply-groups G; term T1 { then { discard; } } } }`,
		},
		{
			// Group explicit (single navigable scope) with main implicit:
			// GREEN before and after; guards the main-side merge.
			name:  "group explicit main implicit nested",
			group: `groups { G { firewall { family inet { filter F { term TG { then { accept; } } } filter G { term TG { then { accept; } } } } } } }`,
			main:  `firewall { filter F { apply-groups G; term T1 { then { discard; } } } filter G { apply-groups G; term T1 { then { discard; } } } }`,
		},
		{
			// Top-level inheritance of two implicit filters: wholesale adoption
			// path, GREEN before and after; guards against over-correction.
			name:  "group implicit top-level two filters",
			group: `groups { G { firewall { filter F { term TG { then { accept; } } } filter G { term TG { then { accept; } } } } } }`,
			main:  `apply-groups G;`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := fwRawTree9875(t, tc.group+" "+tc.main)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatal(err)
			}
			for _, filter := range []string{"F", "G"} {
				terms := termsOf(t, cfg, filter)
				if tc.name == "group implicit top-level two filters" {
					if terms["TG"] != "accept" || len(terms) != 1 {
						t.Fatalf("filter %s inherited %v, want only TG=accept", filter, terms)
					}
					continue
				}
				if terms["T1"] != "discard" || terms["TG"] != "accept" {
					t.Fatalf("filter %s terms=%v, want T1=discard plus inherited TG=accept", filter, terms)
				}
			}
		})
	}
}

// TestQuotedSelfMatchValuesPackedTerm9899 pins P2: the F-105 quoted-operand
// preservation through a PACKED term body. packedBody synthesizes the `from`
// and `protocol` nodes from the term tail without quote provenance, so the
// firewallMatchValues KeyQuoted check reads the synthesized node as bare and
// drops the quoted self-named operand. Pre-fix RED: strict accepts (the
// unknown value vanished) and lenient keeps nothing. Single value isolates
// the quote bit: multi-value packed runs (`protocol tcp udp`) are a separate
// pre-existing consumeNodeKeys arity limitation, not this defect.
func TestQuotedSelfMatchValuesPackedTerm9899(t *testing.T) {
	tree := fwTree9875(t, `term T from protocol "protocol" then discard;`)
	if _, err := CompileConfig(tree); err == nil {
		t.Errorf("packed term: quoted self-named protocol silently disappeared at strict compile")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatal(err)
	}
	if got := firstInetTerm(t, cfg, "F").Protocols; !reflect.DeepEqual(got, []string{"protocol"}) {
		t.Errorf("packed term: tolerant compile protocols=%q, want [protocol]", got)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "protocol") {
		t.Errorf("packed term: missing unknown-protocol warning")
	}
}
