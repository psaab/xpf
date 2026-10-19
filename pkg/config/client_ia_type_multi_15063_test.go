package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15063 (A01-02): `client-ia-type` kept only one IA in the flat and
// bracketed spellings. The leaf was `args: 1` without `multi: true`, so
// SetPath filed a bracket tail under ONE child (Keys=["ia-na","ia-pd"])
// and the compiler's nodeVal read only Keys[1]; a flat
// `client-ia-type ia-na ia-pd` likewise kept only the first. Hierarchical
// repeated statements already accumulated (two sibling nodes), which is
// why brace-authored tests stayed green while the WAN DHCPv6 client
// stopped requesting either IA_NA or IA_PD on the set/display-set path.
//
// FAIL-ON-REVERT: removing `multi: true` from the schema leaf or
// reverting the compiler to nodeVal turns the flat, bracketed and
// display-set cells RED (only [ia-na] survives).

func iaTypes15063(t *testing.T, cfg *Config) []string {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("ge-0/0/0 not compiled")
	}
	unit := ifc.Units[0]
	if unit == nil || unit.DHCPv6Client == nil {
		t.Fatal("DHCPv6Client not compiled")
	}
	return unit.DHCPv6Client.ClientIATypes
}

func TestClientIATypeEverySpelling15063(t *testing.T) {
	want := []string{"ia-na", "ia-pd"}

	t.Run("hierarchical repeated", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; client-ia-type ia-na; client-ia-type ia-pd; } } } } }`)
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ClientIATypes = %v, want %v", got, want)
		}
	})

	t.Run("hierarchical bracket", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; client-ia-type [ ia-na ia-pd ]; } } } } }`)
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ClientIATypes = %v, want %v", got, want)
		}
	})

	t.Run("hierarchical block", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; client-ia-type { ia-na; ia-pd; } } } } } }`)
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ClientIATypes = %v, want %v", got, want)
		}
	})

	t.Run("flat repeated", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type stateful",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-ia-type ia-na",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-ia-type ia-pd",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ClientIATypes = %v, want %v", got, want)
		}
	})

	t.Run("flat bracket", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type stateful",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-ia-type [ ia-na ia-pd ]",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ClientIATypes = %v, want %v", got, want)
		}
	})

	t.Run("flat packed tail", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type stateful",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-ia-type ia-na ia-pd",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ClientIATypes = %v, want %v", got, want)
		}
	})

	// Control: a single IA still compiles to exactly that one IA.
	t.Run("single ia-pd control", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-ia-type ia-pd",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, []string{"ia-pd"}) {
			t.Fatalf("ClientIATypes = %v, want [ia-pd]", got)
		}
	})

	// Display-set replay is identical: render the hierarchical tree as
	// set lines, replay them, and the compiled IA set must not shrink.
	t.Run("display-set replay identical", func(t *testing.T) {
		tree, perrs := NewParser(`interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; client-ia-type ia-na; client-ia-type ia-pd; prefix-delegating preferred-prefix-length 60; } } } } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		setText := tree.FormatSet()
		if !strings.Contains(setText, "client-ia-type") {
			t.Fatalf("display set lost client-ia-type:\n%s", setText)
		}
		replayed := &ConfigTree{}
		for _, line := range strings.Split(strings.TrimSpace(setText), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := replayed.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(replayed)
		if err != nil {
			t.Fatalf("CompileConfig(replayed): %v", err)
		}
		if got := iaTypes15063(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("replayed ClientIATypes = %v, want %v (set text:\n%s)", got, want, setText)
		}
	})
}
