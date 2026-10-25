package config

import (
	"fmt"
	"strings"
	"testing"
)

// #16672: a missing `;` between two `node <n> priority <p>` statements
// fuses them into ONE node whose Keys carry the second `node` token.
// The #8437 fused-statement gate exempts a same-keyword repeat
// (`tok == keyword { continue }`), and `priority` is a child of `node`,
// not a sibling, so neither token is flagged. compileRGNodePriority
// then reads nodeID from the FIRST `node` token and assigns EVERY
// `priority` value in the tail to it, last-wins: the second node's
// priority lands on the first node and the second node gets none,
// which can invert RG primary placement (the absent node clamps to 1
// in pkg/cluster/group_state.go).
//
// The gate is an AST pre-walk mirroring validateChassisClusterIdentitiesAST:
// strict commit rejects, tolerant load warns and the compiler's new
// first-priority-only scan keeps the first node's own priority (the
// authored statement) instead of the fused second one.
//
// FAIL-ON-REVERT: drop the validateRGNodePriorityShapeAST call from
// runPreWalkGates and the strict cells compile clean (RED); restore
// the scan-all-priorities loop in compileRGNodePriority and the
// lenient cells show {1:200} instead of {1:100} (RED).

const rgFused16672 = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key test-cluster-psk-16672;
        redundancy-group 1 {
            %s
        }
    }
}`

func TestRGFusedNodePriorityRejected16672(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"node1 then node0", `node 1 priority 100 node 0 priority 200;`},
		{"node0 then node1", `node 0 priority 200 node 1 priority 100;`},
		{"packed on RG line", ``}, // handled separately below
		{"missing priority value", `node 1 priority;`},
		{"non-numeric priority", `node 1 priority nope;`},
		{"trailing garbage after priority", `node 1 priority 100 bogus;`},
		{"duplicate priority same node", `node 1 priority 100 priority 200;`},
	}
	for _, tc := range cases[:2] {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, fmt.Sprintf(rgFused16672, tc.body))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("fused %q committed clean; want strict rejection", tc.body)
			}
			if !strings.Contains(err.Error(), "#16672") {
				t.Fatalf("error should cite #16672: %v", err)
			}
			if !strings.Contains(err.Error(), "node") {
				t.Fatalf("error should name the node statement: %v", err)
			}
		})
	}
	// Packed on the RG instance line: `redundancy-group 1 node 1 priority 100 node 0 priority 200;`
	t.Run("packed on RG line", func(t *testing.T) {
		tree := hierTree(t, `chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key test-cluster-psk-16672;
        redundancy-group 1 node 1 priority 100 node 0 priority 200;
    }
}`)
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#16672") {
			t.Fatalf("packed fused node statements must be rejected with #16672, got: %v", err)
		}
	})
	for _, tc := range cases[3:] {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, fmt.Sprintf(rgFused16672, tc.body))
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#16672") {
				t.Fatalf("%q must be rejected with #16672, got: %v", tc.body, err)
			}
		})
	}
	// Flat-set fused spelling: one set line carrying both statements.
	t.Run("flat set fused", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set chassis cluster cluster-id 1",
			"set chassis cluster node 0",
			"set chassis cluster authentication-key test-cluster-psk-16672",
			"set chassis cluster redundancy-group 1 node 1 priority 100 node 0 priority 200")
		// The flat path splits on statement keywords, so this may arrive
		// as two nodes; if it compiles, both priorities must be present.
		cfg, err := CompileConfig(tree)
		if err != nil {
			if !strings.Contains(err.Error(), "#16672") {
				t.Fatalf("flat fused rejection should cite #16672: %v", err)
			}
			return
		}
		rg := findRG16672(t, cfg)
		if rg.NodePriorities[1] != 100 || rg.NodePriorities[0] != 200 {
			t.Fatalf("flat fused compiled to %v, want {0:200 1:100} or rejection", rg.NodePriorities)
		}
	})
}

func findRG16672(t *testing.T, cfg *Config) *RedundancyGroup {
	t.Helper()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("no cluster compiled")
	}
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg.ID == 1 {
			return rg
		}
	}
	t.Fatalf("no redundancy-group 1 in %+v", cfg.Chassis.Cluster.RedundancyGroups)
	return nil
}

func TestRGSeparateNodePriorityControlCommits16672(t *testing.T) {
	tree := hierTree(t, fmt.Sprintf(rgFused16672, `node 1 priority 100; node 0 priority 200; preempt;`))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("separate-statement control must commit: %v", err)
	}
	rg := findRG16672(t, cfg)
	if rg.NodePriorities[1] != 100 || rg.NodePriorities[0] != 200 {
		t.Fatalf("control priorities = %v, want {0:200 1:100}", rg.NodePriorities)
	}
	if !rg.Preempt {
		t.Fatal("control lost preempt")
	}
}

func TestRGFusedNodePriorityLenientWarnsAndKeepsFirst16672(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want map[int]int
	}{
		{"node1 then node0", `node 1 priority 100 node 0 priority 200;`, map[int]int{1: 100}},
		{"node0 then node1", `node 0 priority 200 node 1 priority 100;`, map[int]int{0: 200}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, fmt.Sprintf(rgFused16672, tc.body))
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient load must boot (#1960): %v", err)
			}
			assertWarns(t, cfg.Warnings, "#16672")
			rg := findRG16672(t, cfg)
			if len(rg.NodePriorities) != len(tc.want) {
				t.Fatalf("lenient priorities = %v, want %v (first statement only)", rg.NodePriorities, tc.want)
			}
			for k, v := range tc.want {
				if rg.NodePriorities[k] != v {
					t.Fatalf("lenient priorities = %v, want %v", rg.NodePriorities, tc.want)
				}
			}
		})
	}
}
