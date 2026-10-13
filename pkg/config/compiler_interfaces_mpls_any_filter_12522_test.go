package config

import (
	"fmt"
	"strings"
	"testing"
)

// FAIL-ON-REVERT (#12522): compileInterfaces reads interface filter bindings
// only under family inet/inet6, so `family mpls` and `family any` bindings
// have no consumer. The #12090 gate must reject them at strict commit and
// warn exactly once on tolerant loads, in every AST shape. Flat-set and
// split-packed `family any filter ...` reach the gate as a packed `any`
// child of a bare `family` node; dropping `any` from isInterfaceFamilyAF12090
// lets those shapes commit silently.
func TestInterfaceMplsAnyFilterBindingsReject12522(t *testing.T) {
	shapes := []struct {
		name  string
		build func(t *testing.T, family, direction string) *ConfigTree
	}{
		{"flat", func(t *testing.T, family, direction string) *ConfigTree {
			return flatTreeFromSets(t, fmt.Sprintf(
				"set interfaces ge-0/0/0 unit 0 family %s filter %s f", family, direction))
		}},
		{"flat-lo0", func(t *testing.T, family, direction string) *ConfigTree {
			return flatTreeFromSets(t, fmt.Sprintf(
				"set interfaces lo0 unit 0 family %s filter %s f", family, direction))
		}},
		{"flat-range-member", func(t *testing.T, family, direction string) *ConfigTree {
			return flatTreeFromSets(t,
				"set interfaces interface-range r member ge-0/0/1",
				fmt.Sprintf("set interfaces interface-range r unit 0 family %s filter %s f", family, direction))
		}},
		{"hier", func(t *testing.T, family, direction string) *ConfigTree {
			return hierTree(t, fmt.Sprintf(
				"interfaces { ge-0/0/0 { unit 0 { family %s { filter { %s f; } } } } }", family, direction))
		}},
		{"compact", func(t *testing.T, family, direction string) *ConfigTree {
			return hierTree(t, fmt.Sprintf(
				"interfaces { ge-0/0/0 { unit 0 { family %s filter %s f; } } }", family, direction))
		}},
		{"split", func(t *testing.T, family, direction string) *ConfigTree {
			return hierTree(t, fmt.Sprintf(
				"interfaces { ge-0/0/0 { unit 0 { family { %s { filter { %s f; } } } } } }", family, direction))
		}},
		{"split-packed", func(t *testing.T, family, direction string) *ConfigTree {
			return hierTree(t, fmt.Sprintf(
				"interfaces { ge-0/0/0 { unit 0 { family { %s filter %s f; } } } }", family, direction))
		}},
	}
	for _, family := range []string{"mpls", "any"} {
		for _, direction := range []string{"input", "output"} {
			for _, shape := range shapes {
				t.Run(family+"/"+direction+"/"+shape.name, func(t *testing.T) {
					assertSingleFilterDiagnostic12522(t, func(t *testing.T) *ConfigTree {
						return shape.build(t, family, direction)
					}, direction)
				})
			}
		}
	}
}

// The forwarding-options gate shares the packed-head AF list. Its flat-set
// and split-packed `family any filter ...` spellings committed silently
// while the braced twin already rejected (#12090).
func TestForwardingOptionsAnyFilterBindingsReject12522(t *testing.T) {
	for _, direction := range []string{"input", "output"} {
		for _, shape := range []struct {
			name  string
			build func(t *testing.T) *ConfigTree
		}{
			{"flat", func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t, fmt.Sprintf(
					"set forwarding-options family any filter %s f", direction))
			}},
			{"split-packed", func(t *testing.T) *ConfigTree {
				return hierTree(t, fmt.Sprintf(
					"forwarding-options { family { any filter %s f; } }", direction))
			}},
		} {
			t.Run(direction+"/"+shape.name, func(t *testing.T) {
				assertSingleFilterDiagnostic12522(t, shape.build, direction)
			})
		}
	}
}

// The inet/inet6 hook stays the one consumed binding: it commits strict,
// populates the typed unit field, and draws no filter diagnostic.
func TestInterfaceInetFilterBindingsRemainConsumed12522(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, direction := range []string{"input", "output"} {
			for _, shape := range []struct {
				name  string
				build func(t *testing.T) *ConfigTree
			}{
				{"flat", func(t *testing.T) *ConfigTree {
					return flatTreeFromSets(t,
						fmt.Sprintf("set firewall family %s filter f term t then accept", family),
						fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s filter %s f", family, direction))
				}},
				{"hier", func(t *testing.T) *ConfigTree {
					return hierTree(t, fmt.Sprintf(
						"firewall { family %s { filter f { term t { then accept; } } } } "+
							"interfaces { ge-0/0/0 { unit 0 { family %s { filter { %s f; } } } } }",
						family, family, direction))
				}},
			} {
				t.Run(family+"/"+direction+"/"+shape.name, func(t *testing.T) {
					cfg, err := CompileConfig(shape.build(t))
					if err != nil {
						t.Fatalf("strict compile rejected the consumed binding: %v", err)
					}
					u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
					got := map[string]string{
						"inet/input":   u.FilterInputV4,
						"inet/output":  u.FilterOutputV4,
						"inet6/input":  u.FilterInputV6,
						"inet6/output": u.FilterOutputV6,
					}[family+"/"+direction]
					if got != "f" {
						t.Fatalf("typed %s %s hook = %q, want %q", family, direction, got, "f")
					}
					for _, w := range cfg.Warnings {
						if strings.Contains(w, "filter "+direction) {
							t.Fatalf("consumed binding drew a diagnostic: %q", w)
						}
					}
				})
			}
		}
	}
}

// assertSingleFilterDiagnostic12522 requires strict compile to fail with one
// #12090 diagnostic naming the binding, and tolerant compile to accept with
// exactly one warning for it (no second gate double-reporting the stanza).
func assertSingleFilterDiagnostic12522(t *testing.T, build func(*testing.T) *ConfigTree, direction string) {
	t.Helper()
	label := "`filter " + direction + "`"
	_, err := CompileConfig(build(t))
	if err == nil {
		t.Fatalf("strict compile accepted an unconsumed filter %s binding", direction)
	}
	if msg := err.Error(); strings.Count(msg, "(#12090)") != 1 || !strings.Contains(msg, label) {
		t.Fatalf("strict error = %q; want one #12090 diagnostic naming %s", msg, label)
	}
	cfg, err := CompileConfigLenient(build(t))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var diags []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "filter "+direction) {
			diags = append(diags, w)
		}
	}
	if len(diags) != 1 || !strings.Contains(diags[0], label) || !strings.Contains(diags[0], "(#12090)") {
		t.Fatalf("lenient diagnostics for filter %s = %q; want exactly one #12090 warning", direction, diags)
	}
}
