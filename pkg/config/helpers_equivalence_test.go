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
	"os"
	"os/exec"
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

// kitChildMode16139 selects which kit-helper failure leg a child copy of
// a test runs (see runKitChild16139). Empty means parent mode.
const kitChildMode16139 = "XPF_KIT_CHILD_16139"

// runKitChild16139 re-runs testName in a child copy of this test binary
// with kitChildMode16139=mode, and requires the child to FAIL with output
// containing wantSubstr (the helper's own fatal prefix). Kit helpers
// report failure via t.Fatalf, which the calling test cannot observe, so
// every "helper must reject" cell goes through the kit helper itself in
// the child — never through the raw channel the helper wraps. A child
// that succeeds means the helper accepted input it must reject (guard
// dropped or channel flattened); a child that fails without wantSubstr
// means it failed for the wrong reason.
func runKitChild16139(t *testing.T, testName, mode, wantSubstr string) {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	child.Env = append(os.Environ(), kitChildMode16139+"="+mode)
	out, err := child.CombinedOutput()
	if err == nil {
		t.Fatalf("%s child (mode %q) unexpectedly succeeded; helper accepted input it must reject:\n%s", testName, mode, out)
	}
	if !strings.Contains(string(out), wantSubstr) {
		t.Fatalf("%s child (mode %q) failed without %q in output:\n%s", testName, mode, wantSubstr, out)
	}
}

func TestKitParseHierTextRejectsGarbage16139(t *testing.T) {
	if os.Getenv(kitChildMode16139) == "parse-garbage" {
		// Child: must not return — parseHierText must fatal on the
		// []ParseError from NewParser. Returning means the helper's
		// len(errs) guard was dropped.
		_ = parseHierText(t, "system { host-name ;;; }")
		return
	}
	runKitChild16139(t, "TestKitParseHierTextRejectsGarbage16139", "parse-garbage", "parse errors for")
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

// kitClusterNoKey is the strict-vs-lenient divergence fixture: a cluster
// config without an auth key is hard-rejected strictly (#6611) but
// downgraded to a warning leniently.
const kitClusterNoKey = `chassis {
    cluster {
        control-interface em0;
        peer-address 10.99.0.2;
        cluster-id 1;
        node 0;
        reth-count 2;
        redundancy-group 1 {
            node 0 priority 200;
        }
    }
}
`

// kitNodeFixture is node-distinguishing (#4329): ge-0/0/0 is node 0's FPC-0
// member and ge-7/0/0 is node 1's FPC-7 member, both redundant-parent of
// reth0, in a leaf-less cluster (no `chassis cluster node` leaf). Compiled
// for node 0 it must bind reth0 to ge-0/0/0; for node 1, to ge-7/0/0. On a
// node-indistinguishable fixture compileTreeForNodeKit could route to plain
// CompileConfig and still pass — here it cannot.
const kitNodeFixture = `chassis {
    cluster {
        control-interface em0;
        peer-address 10.99.0.2;
        cluster-id 1;
        authentication-key test-cluster-psk-6611;
        reth-count 2;
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
        }
    }
}
interfaces {
    ge-0/0/0 {
        gigether-options {
            redundant-parent reth0;
        }
    }
    ge-7/0/0 {
        gigether-options {
            redundant-parent reth0;
        }
    }
    reth0 {
        redundant-ether-options {
            redundancy-group 1;
        }
    }
}
`

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
	// The tolerant set channel must produce the same compiled shape on a
	// valid fixture (compileSetLenient previously had no caller).
	setLenient := compileSetLenient(t,
		"set system host-name kit-fw",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
	)
	if setLenient.System.HostName != "kit-fw" {
		t.Fatalf("set lenient host-name=%q", setLenient.System.HostName)
	}
	if len(setLenient.Interfaces.Interfaces) != 1 {
		t.Fatalf("set lenient interfaces=%d, want 1", len(setLenient.Interfaces.Interfaces))
	}
	// Tree channels on an already-parsed tree agree on a valid fixture.
	if got := compileTreeStrictKit(t, parseHierText(t, kitFixtureHier)).System.HostName; got != "kit-fw" {
		t.Fatalf("tree strict host-name=%q", got)
	}
	if got := compileTreeLenientKit(t, parseHierText(t, kitFixtureHier)).System.HostName; got != "kit-fw" {
		t.Fatalf("tree lenient host-name=%q", got)
	}
	// Node channel on the plain fixture still compiles (node 0).
	nodeCfg := compileTreeForNodeKit(t, parseHierText(t, kitFixtureHier), 0)
	if nodeCfg.System.HostName != "kit-fw" {
		t.Fatalf("for-node host-name=%q", nodeCfg.System.HostName)
	}
}

// TestKitForNodeDistinguishesNodes16139 proves compileTreeForNodeKit really
// routes through CompileConfigForNode: the same fixture compiled for node 0
// and node 1 binds reth0 to different physical members (ge-0/0/0 vs
// ge-7/0/0). If the helper ignored nodeID (e.g. routed to CompileConfig),
// both would bind ge-0/0/0 and this test fails.
func TestKitForNodeDistinguishesNodes16139(t *testing.T) {
	cfg0 := compileTreeForNodeKit(t, parseHierText(t, kitNodeFixture), 0)
	if got := cfg0.RethToPhysical()["reth0"]; got != "ge-0/0/0" {
		t.Fatalf("node 0: reth0 -> %q, want ge-0/0/0", got)
	}
	if cfg0.Chassis.Cluster == nil || cfg0.Chassis.Cluster.NodeID != 0 {
		t.Fatalf("node 0: stamped NodeID = %+v, want 0", cfg0.Chassis.Cluster)
	}
	cfg1 := compileTreeForNodeKit(t, parseHierText(t, kitNodeFixture), 1)
	if got := cfg1.RethToPhysical()["reth0"]; got != "ge-7/0/0" {
		t.Fatalf("node 1: reth0 -> %q, want ge-7/0/0 (helper must not ignore nodeID)", got)
	}
	if cfg1.Chassis.Cluster == nil || cfg1.Chassis.Cluster.NodeID != 1 {
		t.Fatalf("node 1: stamped NodeID = %+v, want 1", cfg1.Chassis.Cluster)
	}
}

// TestKitChannelsNotFlattened16139 pins a fixture where strict and lenient
// are known to diverge: a cluster config without an auth key is
// hard-rejected strictly (#6611) but downgraded to a warning leniently.
// The strict leg goes through the compileHierStrict kit helper itself:
// because the helper reports failure via t.Fatalf, the strict leg runs in
// a child copy of this test (env-gated) and the parent requires the child
// to FAIL with the helper's own "CompileConfig:" fatal. If
// compileHierStrict ever routed to CompileConfigLenient, the child would
// succeed and this test fails; if compileHierLenient ever routed to
// CompileConfig, the lenient leg below fatals in-process.
func TestKitChannelsNotFlattened16139(t *testing.T) {
	switch os.Getenv(kitChildMode16139) {
	case "hier-strict":
		// Child: must not return. compileHierStrict fatals on the strict
		// CompileConfig rejection; returning here means the helper
		// accepted (flattened to lenient) and the child test passes,
		// which the parent treats as failure.
		_ = compileHierStrict(t, kitClusterNoKey)
		return
	case "set-strict":
		// Child: must not return. compileSetStrict must reject the flat
		// `set` form of the same keyless cluster; returning means the
		// strict set channel was flattened to lenient.
		_ = compileSetStrict(t,
			"set chassis cluster cluster-id 1",
			"set chassis cluster control-interface em0",
			"set chassis cluster peer-address 10.99.0.2",
			"set chassis cluster node 0",
			"set chassis cluster reth-count 2",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
		)
		return
	}
	runKitChild16139(t, "TestKitChannelsNotFlattened16139", "hier-strict", "CompileConfig:")
	runKitChild16139(t, "TestKitChannelsNotFlattened16139", "set-strict", "CompileConfig:")
	cfg := compileHierLenient(t, kitClusterNoKey)
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
	// The set channel is not flattened either: the strict set leg was
	// pinned above through compileSetStrict itself (set-strict child),
	// and the flat `set` form of the same keyless cluster compiles
	// leniently through compileSetLenient here.
	setCfg := compileSetLenient(t,
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	)
	if setCfg == nil {
		t.Fatal("set lenient channel returned nil config for keyless cluster")
	}
	found = false
	for _, w := range setCfg.Warnings {
		if strings.Contains(w, "authentication-key") || strings.Contains(w, "cluster") {
			found = true
		}
	}
	if !found {
		t.Fatalf("set lenient keyless cluster produced no cluster warning; warnings=%v", setCfg.Warnings)
	}
}
