package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRoutingOptionsPackedSiblingsPreserveValues11314(t *testing.T) {
	rows := []struct {
		name         string
		tree         func(*testing.T) *config.ConfigTree
		rejectStrict bool
	}{
		{
			name:         "braced_requires_separator_but_tolerant_load_warns",
			rejectStrict: true,
			tree: func(t *testing.T) *config.ConfigTree {
				tree, errs := config.NewParser(`routing-options { router-id 10.255.0.1 autonomous-system 65000; }
protocols { bgp { local-as 65000; } }`).Parse()
				if len(errs) != 0 {
					t.Fatalf("parse: %v", errs)
				}
				return tree
			},
		},
		{
			name: "flat-set",
			tree: func(t *testing.T) *config.ConfigTree {
				tree := &config.ConfigTree{}
				for _, command := range []string{
					"set routing-options router-id 10.255.0.1 autonomous-system 65000",
					"set protocols bgp local-as 65000",
				} {
					path, err := config.ParseSetCommand(command)
					if err != nil {
						t.Fatalf("ParseSetCommand(%q): %v", command, err)
					}
					if err := tree.SetPath(path); err != nil {
						t.Fatalf("SetPath(%q): %v", command, err)
					}
				}
				return tree
			},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := row.tree(t)
			store := newTestStore(t)
			compiled, strictErr := store.compileTree(tree)
			if row.rejectStrict {
				if strictErr == nil {
					t.Fatal("strict compile accepted a braced run missing the router-id semicolon")
				}
				for _, marker := range []string{"autonomous-system", "silently dropped", "#8437"} {
					if !strings.Contains(strictErr.Error(), marker) {
						t.Errorf("strict error %q does not name %q", strictErr, marker)
					}
				}
				logs := captureWarnLogs(t)
				var err error
				compiled, err = store.compileTreeLenient(tree)
				if err != nil {
					t.Fatalf("tolerant compile rejected a stored packed leaf run: %v", err)
				}
				for _, marker := range []string{"typed-leaf schema violation", "router-id", "autonomous-system"} {
					if !strings.Contains(logs.String(), marker) {
						t.Errorf("tolerant store log %q does not identify %q", logs.String(), marker)
					}
				}
			} else if strictErr != nil {
				t.Fatalf("strict flat-set compile rejected valid sibling leaves: %v", strictErr)
			}
			if got := compiled.RoutingOptions.AutonomousSystem; got != 65000 {
				t.Errorf("routing-options autonomous-system = %d, want 65000", got)
			}
			if compiled.Protocols.BGP == nil || compiled.Protocols.BGP.RouterID != "10.255.0.1" {
				t.Errorf("BGP did not inherit router-id from routing-options: %+v", compiled.Protocols.BGP)
			}
		})
	}
}
