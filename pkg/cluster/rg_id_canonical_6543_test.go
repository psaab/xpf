package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6543: the runtime half of the canonical-redundancy-group-id property.
//
// UpdateConfig walks cfg.RedundancyGroups and keys m.groups by rg.ID, so two
// compiled records sharing one id are a LAST-WINS overwrite:
//
//	existing.LocalPriority = rg.NodePriorities[m.nodeID]
//
// Before the compiler folded instances by canonical id, spelling the group
// two ways (`redundancy-group 1 node 0 priority 200` plus
// `redundancy-group 01 preempt`) produced a second ID=1 record with an EMPTY
// NodePriorities map, and this line overwrote the configured 200 with the
// map-miss ZERO. Node 0 then ran RG 1 at priority 0 — it loses an election it
// was configured to win, which is a real failover behaviour change that
// survives commit-check silently.
//
// This test drives the REAL compiler (set lines -> CompileConfig) into the
// REAL Manager rather than hand-building typed records, so it binds the
// end-to-end path the operator actually travels.
//
// FAIL-ON-REVERT: restore the per-instance append in compileChassis and
// LocalPriority comes back 0 here.

// compileClusterCfg compiles flat-set lines into the typed ClusterConfig.
func compileClusterCfg(t *testing.T, lines []string) *config.ClusterConfig {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected: %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("no chassis cluster compiled")
	}
	return cfg.Chassis.Cluster
}

func localPriority(t *testing.T, m *Manager, rgID int) int {
	t.Helper()
	for _, gs := range m.GroupStates() {
		if gs.GroupID == rgID {
			return gs.LocalPriority
		}
	}
	t.Fatalf("redundancy group %d not present in GroupStates()", rgID)
	return 0
}

func TestTwoSpellingsOfOneRGIDKeepTheConfiguredPriority(t *testing.T) {
	for _, alt := range []string{"01", "001", "+1"} {
		t.Run("alt="+alt, func(t *testing.T) {
			cc := compileClusterCfg(t, []string{
				"set chassis cluster cluster-id 1",
				"set chassis cluster authentication-key test-cluster-psk-6543",
				"set chassis cluster no-private-rg-election",
				"set chassis cluster node 0",
				"set chassis cluster redundancy-group 1 node 0 priority 200",
				"set chassis cluster redundancy-group 1 node 1 priority 100",
				"set chassis cluster redundancy-group " + alt + " preempt",
			})

			m := NewManager(0, 1)
			m.UpdateConfig(cc)
			drainEvents(m, 4)

			if got := localPriority(t, m, 1); got != 200 {
				t.Fatalf("node 0 runs RG 1 at LocalPriority %d, want 200 — a "+
					"second ID=1 record spelled %q overwrote the configured "+
					"priority with the map-miss zero, so this node loses an "+
					"election it was configured to win", got, alt)
			}
			// The alternate spelling's own statement must still be in effect.
			found := false
			for _, gs := range m.GroupStates() {
				if gs.GroupID == 1 {
					found = true
					if !gs.Preempt {
						t.Errorf("preempt from spelling %q did not reach the "+
							"group state", alt)
					}
				}
			}
			if !found {
				t.Fatal("redundancy group 1 missing from GroupStates()")
			}
		})
	}
}

// TestSpellingOrderDoesNotChangeTheOutcome: the split was order-sensitive —
// whichever record UpdateConfig visited LAST won. The merged record must be
// insensitive to which spelling the operator wrote first.
func TestSpellingOrderDoesNotChangeTheOutcome(t *testing.T) {
	base := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6543",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster node 0",
	}
	orders := [][]string{
		{"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 01 preempt"},
		{"set chassis cluster redundancy-group 01 preempt",
			"set chassis cluster redundancy-group 1 node 0 priority 200"},
	}
	for i, tail := range orders {
		m := NewManager(0, 1)
		m.UpdateConfig(compileClusterCfg(t, append(append([]string{}, base...), tail...)))
		drainEvents(m, 4)
		if got := localPriority(t, m, 1); got != 200 {
			t.Errorf("order %d: LocalPriority %d, want 200", i, got)
		}
	}
}

// TestDistinctRGIDsKeepDistinctPriorities is the negative control: the fold
// must not collapse genuinely different groups into one.
func TestDistinctRGIDsKeepDistinctPriorities(t *testing.T) {
	cc := compileClusterCfg(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6543",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 150",
		"set chassis cluster redundancy-group 2 node 0 priority 100",
	})
	m := NewManager(0, 1)
	m.UpdateConfig(cc)
	drainEvents(m, 8)

	for id, want := range map[int]int{0: 200, 1: 150, 2: 100} {
		if got := localPriority(t, m, id); got != want {
			t.Errorf("rg %d LocalPriority %d, want %d", id, got, want)
		}
	}
	if n := len(m.GroupStates()); n != 3 {
		t.Errorf("%d redundancy groups in state, want 3", n)
	}
}
