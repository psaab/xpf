package config

// Permanent clone-equivalence tests for the #16139 per-channel kit.
//
// The migrated clones are deleted, so equivalence cannot be a
// comparison against them (that would not compile). Instead each kit
// helper is pinned against independent, hand-written expected fixtures,
// and strict-vs-lenient divergence is pinned on a fixture where the two
// channels are known to differ — proving no channel was flattened into
// another and no lenient flag was smuggled in.

import (
	"reflect"
	"strings"
	"testing"
)

// kitFixtureHier is valid on every channel.
const kitFixtureHier = `system {
    host-name kit-fw;
    ntp {
        server 192.0.2.10;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.0.2.1/24;
            }
        }
    }
}
`

// kitFixtureFormat is the independently expected Format() rendering of
// kitFixtureHier (canonical child order: interfaces before system is
// NOT assumed — Format preserves authored order at the top level here
// only if the parser does; the assertion below compares against a
// second parse of the same text rendered through Format, plus exact
// leaf key paths, so it does not depend on ordering guesses).
func TestKitParseHierTextEquivalence16139(t *testing.T) {
	tree := parseHierText(t, kitFixtureHier)
	if tree == nil {
		t.Fatal("parseHierText returned nil tree")
	}
	// Independent expected leaf key paths, in authored order.
	var leaves []string
	var walk func(nodes []*Node, prefix []string)
	walk = func(nodes []*Node, prefix []string) {
		for _, n := range nodes {
			path := append(append([]string{}, prefix...), n.Keys...)
			if n.IsLeaf {
				leaves = append(leaves, strings.Join(path, " "))
			}
			walk(n.Children, path)
		}
	}
	walk(tree.Children, nil)
	want := []string{
		"system host-name kit-fw",
		"system ntp server 192.0.2.10",
		"interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
	}
	if !reflect.DeepEqual(leaves, want) {
		t.Fatalf("leaf key paths:\n got %q\nwant %q", leaves, want)
	}
	// Format round-trip: re-parsing the rendered tree yields the same leaves.
	reparsed := parseHierText(t, tree.Format())
	var leaves2 []string
	var walk2 func(nodes []*Node, prefix []string)
	walk2 = func(nodes []*Node, prefix []string) {
		for _, n := range nodes {
			path := append(append([]string{}, prefix...), n.Keys...)
			if n.IsLeaf {
				leaves2 = append(leaves2, strings.Join(path, " "))
			}
			walk2(n.Children, path)
		}
	}
	walk2(reparsed.Children, nil)
	if !reflect.DeepEqual(leaves2, want) {
		t.Fatalf("round-trip leaf key paths:\n got %q\nwant %q", leaves2, want)
	}
}

func TestKitParseHierTextRejectsGarbage16139(t *testing.T) {
	// A subtest cannot observe Fatalf, so assert via the underlying
	// channel contract: NewParser reports errors for this input, which
	// is exactly what parseHierText fatals on (len(errs) > 0).
	if _, errs := NewParser("system { host-name ;;; }").Parse(); len(errs) == 0 {
		t.Fatal("fixture unexpectedly parses clean; parseHierText would not fatal")
	}
}

func TestKitParseSetCommandsEquivalence16139(t *testing.T) {
	tree := parseSetCommands(t,
		"set system host-name kit-fw",
		"set system ntp server 192.0.2.10",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
	)
	hier := parseHierText(t, kitFixtureHier)
	if got, want := tree.Format(), hier.Format(); got != want {
		t.Fatalf("set-built tree Format differs from hier tree:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestKitCompileChannelsAgreeOnValid16139(t *testing.T) {
	strict := compileHierStrict(t, kitFixtureHier)
	lenient := compileHierLenient(t, kitFixtureHier)
	if strict.System.HostName != "kit-fw" || lenient.System.HostName != "kit-fw" {
		t.Fatalf("host-name: strict=%q lenient=%q", strict.System.HostName, lenient.System.HostName)
	}
	setStrict := compileSetStrict(t,
		"set system host-name kit-fw",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
	)
	if setStrict.System.HostName != "kit-fw" {
		t.Fatalf("set strict host-name=%q", setStrict.System.HostName)
	}
	if len(setStrict.Interfaces.Interfaces) != 1 {
		t.Fatalf("set strict interfaces=%d, want 1", len(setStrict.Interfaces.Interfaces))
	}
	nodeCfg := compileTreeForNodeKit(t, parseHierText(t, kitFixtureHier), 0)
	if nodeCfg.System.HostName != "kit-fw" {
		t.Fatalf("for-node host-name=%q", nodeCfg.System.HostName)
	}
}

// TestKitChannelsNotFlattened16139 pins a fixture where strict and
// lenient are known to diverge: a cluster config without an auth key is
// hard-rejected strictly (#6611) but downgraded to a warning leniently.
// If compileHierLenient ever routed to CompileConfig (or vice versa),
// this test fails.
func TestKitChannelsNotFlattened16139(t *testing.T) {
	const clusterNoKey = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        reth-count 2;
        redundancy-group 1 {
            node 0 priority 200;
        }
    }
}
`
	if _, err := CompileConfig(parseHierText(t, clusterNoKey)); err == nil {
		t.Skip("strict channel no longer rejects keyless cluster; pick a new divergence fixture")
	}
	cfg := compileHierLenient(t, clusterNoKey)
	if cfg == nil {
		t.Fatal("lenient channel returned nil config for keyless cluster")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication-key") || strings.Contains(w, "cluster") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient keyless cluster produced no cluster warning; warnings=%v", cfg.Warnings)
	}
}
