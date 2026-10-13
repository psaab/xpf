package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// groupedFromListTree12510 writes one `from-zone [ A C ] to-zone <toZone>`
// policy p1 context per destination as grouped set commands, the CLI
// producer: the context node ends at `to-zone` and each statement's
// destination is folded into its body.
func groupedFromListTree12510(t *testing.T, toZones ...string) *config.ConfigTree {
	t.Helper()
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security zones security-zone D",
		"set security zones security-zone E",
		"set security policies default-policy permit-all",
	}
	for _, toZone := range toZones {
		prefix := "set security policies from-zone [ A C ] to-zone " + toZone + " policy p1 "
		commands = append(commands,
			prefix+"match source-address any",
			prefix+"match destination-address any",
			prefix+"match application any",
			prefix+"then deny")
	}
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
		}
	}
	return tree
}

// hierarchicalFromListTree12510 writes the same context as hierarchical text
// through config.NewParser, the producer behind Store.Load, load and HA sync:
// every token between `to-zone` and `{` stays on the context node.
func hierarchicalFromListTree12510(t *testing.T, toZone string) *config.ConfigTree {
	t.Helper()
	text := `security {
    zones {
        security-zone A;
        security-zone B;
        security-zone C;
        security-zone D;
        security-zone E;
    }
    policies {
        from-zone [ A C ] to-zone ` + toZone + ` {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
        default-policy {
            permit-all;
        }
    }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("NewParser(to-zone %s): %v", toZone, errs)
	}
	return tree
}

// fromListMirrorReason12510 compiles tree on the tolerant path and returns the
// mirror reason of its single malformed from-list context.
func fromListMirrorReason12510(t *testing.T, tree *config.ConfigTree) string {
	t.Helper()
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 1 {
		t.Fatalf("want one malformed context, got %q", cfg.Security.MalformedZonePairs)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 {
		t.Fatalf("want one mirror reason, got %q", reasons)
	}
	if repeat := PolicyContentRejectionReasons(cfg, nil); len(repeat) != 1 || repeat[0] != reasons[0] {
		t.Fatalf("mirror reason is not deterministic: first=%q repeat=%q", reasons, repeat)
	}
	return reasons[0]
}

// Prefix-identical grouped contexts share one AST node and one diagnostic, so
// that diagnostic must name every destination.
func TestMergedFromListContextsRetainEachDestination12510(t *testing.T) {
	reason := fromListMirrorReason12510(t, groupedFromListTree12510(t, "B", "D"))
	if !strings.Contains(reason, "from-zone [ A C ] to-zone B, D: ") {
		t.Errorf("merged mirror reason does not name both destinations: %s", reason)
	}
}

// Both producers must name the destination exactly as authored. Matching the
// whole `to-zone ...:` segment also rules out a phantom destination such as
// the `policy` keyword the hierarchical body starts with.
func TestMalformedFromZoneMirrorNamesDestination12510(t *testing.T) {
	producers := []struct {
		name string
		tree func(*testing.T, string) *config.ConfigTree
	}{
		{"grouped set", func(t *testing.T, toZone string) *config.ConfigTree {
			return groupedFromListTree12510(t, toZone)
		}},
		{"hierarchical text", hierarchicalFromListTree12510},
	}
	cases := []struct{ name, toZone string }{
		{name: "scalar B", toZone: "B"},
		{name: "scalar D", toZone: "D"},
		{name: "destination list", toZone: "[ B D ]"},
		{name: "scalar then list", toZone: "E [ B D ]"},
		{name: "list then scalar", toZone: "[ B D ] E"},
	}
	for _, p := range producers {
		seen := make(map[string]string, len(cases))
		for _, tc := range cases {
			t.Run(p.name+"/"+tc.name, func(t *testing.T) {
				reason := fromListMirrorReason12510(t, p.tree(t, tc.toZone))
				if want := "from-zone [ A C ] to-zone " + tc.toZone + ": "; !strings.Contains(reason, want) {
					t.Errorf("reason does not name destination %q as authored (want %q): %s", tc.toZone, want, reason)
				}
				if prev, dup := seen[reason]; dup {
					t.Errorf("destinations %q and %q produced the identical mirror reason %s", prev, tc.toZone, reason)
				}
				seen[reason] = tc.toZone
			})
		}
	}
}

// An empty destination list authors no zone. The grouped parser marks the
// following `policy` key with the bracket's delimiter loss, and text formatted
// from that tree reparses without the mark; no producer may turn the policy
// statement into a destination.
func TestMalformedFromZoneEmptyDestinationNamesNoZone12510(t *testing.T) {
	producers := []struct {
		name string
		tree func(*testing.T) *config.ConfigTree
	}{
		{"grouped set", func(t *testing.T) *config.ConfigTree {
			return groupedFromListTree12510(t, "[ ]")
		}},
		{"hierarchical text", func(t *testing.T) *config.ConfigTree {
			return hierarchicalFromListTree12510(t, "[ ]")
		}},
		{"grouped set reloaded as text", func(t *testing.T) *config.ConfigTree {
			text := groupedFromListTree12510(t, "[ ]").Format()
			tree, errs := config.NewParser(text).Parse()
			if len(errs) > 0 {
				t.Fatalf("NewParser(formatted grouped tree): %v\n%s", errs, text)
			}
			return tree
		}},
	}
	for _, p := range producers {
		t.Run(p.name, func(t *testing.T) {
			reason := fromListMirrorReason12510(t, p.tree(t))
			if !strings.Contains(reason, "from-zone [ A C ] to-zone: ") || strings.Contains(reason, "to-zone policy") ||
				strings.Contains(reason, "[ policy") {
				t.Errorf("empty destination list must name no zone: %s", reason)
			}
		})
	}
}
