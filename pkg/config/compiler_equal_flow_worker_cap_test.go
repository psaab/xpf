package config

import (
	"strings"
	"testing"
)

// #1830 (e): the #1733 equal-flow worker-cap gate
// (MaxEqualFlowWorkers / validateEqualFlowWorkerCapStrict, plus the
// lenient warning downgrade) is retired — the v8 lease rotation now
// heap-sizes its per-worker scratch to the true worker count, so
// equal-flow-enforcement is supported at any configured worker count.
// These tests pin the retirement: a >32-worker + equal-flow config must
// compile cleanly on the STRICT path with no cap rejection and no cap
// warning, symmetrically per node.

// buildTree parses a sequence of `set ...` commands into a ConfigTree
// using the production ParseSetCommand + SetPath path (never NewParser,
// per the flat-set testing gotcha in CLAUDE.md).
func buildTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	lines = prependNATZoneDefs15001(lines)
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// validEqualFlowScheduler returns the set lines for a scheduler that
// passes validateClassOfServiceStrict (positive transmit-rate exact, no
// surplus-sharing).
func validEqualFlowScheduler(name string) []string {
	return []string{
		"set class-of-service schedulers " + name + " transmit-rate 10m exact",
		"set class-of-service schedulers " + name + " equal-flow-enforcement",
	}
}

func hasWorkerCapWarning(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-enforcement is unsupported") {
			return true
		}
	}
	return false
}

// TestCompileAcceptsEqualFlowAboveLegacyWorkerCap is the #1830 (e)
// retirement pin: workers far above the former 32-worker cap with
// equal-flow-enforcement must compile cleanly on the STRICT path —
// no rejection, no warning, and the equal-flow leaf preserved.
func TestCompileAcceptsEqualFlowAboveLegacyWorkerCap(t *testing.T) {
	for _, workers := range []string{"33", "64", "128"} {
		lines := append([]string{
			"set system dataplane-type userspace",
			"set system dataplane workers " + workers,
		}, validEqualFlowScheduler("ef-sched")...)
		tree := buildTree(t, lines)

		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(workers %s + equal-flow) returned error "+
				"(the #1733 cap is retired by #1830 (e)): %v", workers, err)
		}
		if hasWorkerCapWarning(cfg) {
			t.Fatalf("workers %s: unexpected retired worker-cap warning: %v",
				workers, cfg.Warnings)
		}
		sched := cfg.ClassOfService.Schedulers["ef-sched"]
		if sched == nil || !sched.EqualFlowEnforcement {
			t.Fatalf("workers %s: equal-flow-enforcement leaf was not preserved", workers)
		}
	}
}

// TestCompileEqualFlowAboveLegacyCapPerNodeParity verifies the per-node
// compile paths (strict AND lenient) accept a groups-scoped >32-worker
// + equal-flow config symmetrically — neither node may see a retired
// cap rejection or warning.
func TestCompileEqualFlowAboveLegacyCapPerNodeParity(t *testing.T) {
	lines := append([]string{
		"set system dataplane-type userspace",
		`set apply-groups "${node}"`,
		"set groups node0 system dataplane workers 64",
		"set groups node1 system host-name fw1",
	}, validEqualFlowScheduler("ef-sched")...)
	tree := buildTree(t, lines)

	for node := 0; node <= 1; node++ {
		cfg, err := CompileConfigForNode(tree, node)
		if err != nil {
			t.Fatalf("node%d strict compile errored (cap retired by #1830 (e)): %v", node, err)
		}
		if hasWorkerCapWarning(cfg) {
			t.Fatalf("node%d strict compile has retired worker-cap warning: %v",
				node, cfg.Warnings)
		}
		cfgL, err := CompileConfigForNodeLenient(tree, node)
		if err != nil {
			t.Fatalf("node%d lenient compile errored: %v", node, err)
		}
		if hasWorkerCapWarning(cfgL) {
			t.Fatalf("node%d lenient compile has retired worker-cap warning: %v",
				node, cfgL.Warnings)
		}
	}
}
