package config

import (
	"strings"
	"testing"
)

// #17811: the source-pool range validator belongs to `port range`, not the
// containing `port` node. The compiler consumes range and port modifiers as
// separate siblings, so the schema must preserve them as separate values too.
func TestSourceNATPoolPortRangeWithNoTranslation17811(t *testing.T) {
	for _, tc := range []struct {
		name       string
		commands   []string
		wantLow    int
		wantHigh   int
		wantNoPort bool
	}{
		{
			name: "range then modifier",
			commands: []string{
				"set security nat source pool p1 port range 1024 to 2047",
				"set security nat source pool p1 port no-translation",
			},
			wantNoPort: true,
		},
		{
			name: "modifier then range",
			commands: []string{
				"set security nat source pool p1 port no-translation",
				"set security nat source pool p1 port range 1024 to 2047",
			},
			wantLow:  1024,
			wantHigh: 2047,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append([]string{"set security nat source pool p1 address 203.0.113.5/32"}, tc.commands...)
			tree := snatPoolTree(t, cmds...)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate(%v): %v; range and sibling modifier must be validated separately", tc.commands, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig(%v): %v", tc.commands, err)
			}
			pool := cfg.Security.NAT.SourcePools["p1"]
			if pool == nil {
				t.Fatal("pool p1 missing")
			}
			if pool.PortLow != tc.wantLow || pool.PortHigh != tc.wantHigh || pool.PortNoTranslation != tc.wantNoPort {
				t.Fatalf("compiled port = (%d,%d,no-translation=%v), want (%d,%d,no-translation=%v)",
					pool.PortLow, pool.PortHigh, pool.PortNoTranslation,
					tc.wantLow, tc.wantHigh, tc.wantNoPort)
			}
		})
	}

	hierarchical := `security {
 nat {
  source {
   pool p1 {
    address 203.0.113.5/32;
    port {
     range 1024 to 2047;
     no-translation;
    }
   }
  }
 }
}
`
	tree, parseErrs := NewParser(hierarchical).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("hierarchical parse: %v", parseErrs)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate(hierarchical range + no-translation): %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(hierarchical range + no-translation): %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil || !pool.PortNoTranslation || pool.PortLow != 0 || pool.PortHigh != 0 {
		t.Fatalf("hierarchical range + no-translation compiled to %+v", pool)
	}
}

func TestSourceNATPoolPortSiblingStillSchemaValidated17811(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands []string
	}{
		{
			name: "modifier before range",
			commands: []string{
				"set security nat source pool p1 port deterministic block-size 0",
				"set security nat source pool p1 port range 1024 to 2047",
			},
		},
		{
			name: "range before modifier",
			commands: []string{
				"set security nat source pool p1 port range 1024 to 2047",
				"set security nat source pool p1 port deterministic block-size 0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append([]string{"set security nat source pool p1 address 203.0.113.5/32"}, tc.commands...)
			err := SchemaValidate(snatPoolTree(t, cmds...))
			if err == nil || !strings.Contains(err.Error(), "deterministic") {
				t.Fatalf("SchemaValidate(%v) = %v, want the deterministic child-schema error", tc.commands, err)
			}
		})
	}
}
