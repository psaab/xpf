package config

import (
	"strings"
	"testing"
)

// #9723: the tolerant path keeps a config carrying a negative redundancy-group
// id booting, but drops the group, because on the heartbeat wire it aliases RG0.
func TestTolerantPathDropsNegativeRedundancyGroup_9723(t *testing.T) {
	cmds := []string{
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group -1 node 0 priority 200",
		"set chassis cluster redundancy-group -1 node 1 priority 100",
	}
	// The #5694 identity gate refuses the token first, naming it; either way the
	// strict path must refuse.
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil || !strings.Contains(err.Error(), "-1") {
		t.Fatalf("precondition: strict commit must still refuse redundancy-group -1, got %v", err)
	}
	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("the tolerant path must not refuse: %v", err)
	}
	var ids []int
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		ids = append(ids, rg.ID)
	}
	if len(ids) != 1 || ids[0] != 0 {
		t.Fatalf("tolerant compile kept redundancy groups %v, want only [0]", ids)
	}
	warned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "redundancy-group -1 dropped") && strings.Contains(w, "#9723") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the drop must be announced: %v", cfg.Warnings)
	}
}

// TestTolerantPathKeepsSaturatingHighRedundancyGroup_9723 is the scope control:
// an id above 255 saturates onto byte 255, which no valid group uses, and #8337
// keeps and advertises it on purpose.
func TestTolerantPathKeepsSaturatingHighRedundancyGroup_9723(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 300 node 0 priority 200",
	}))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var ids []int
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		ids = append(ids, rg.ID)
	}
	if len(ids) != 2 {
		t.Errorf("an id above 255 must be kept (#8337), got %v", ids)
	}
}
