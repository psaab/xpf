// #3906: the source-NAT snapshot must carry the pool's configured `port range
// <low> to <high>` and the `port no-translation` flag to the dataplane. Before
// #3906 the range was silently ignored (defaulted to 1024-65535 PAT) and
// no-translation was dropped. These tests drive a real compiled config through
// buildSourceNATSnapshots to assert the wire slots.
//
// RED-on-revert (config parse reverted): PortLow/PortHigh come back 1024/65535
// and PoolNoTranslation stays false.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileSNATPool(t *testing.T, poolCmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := append([]string{}, poolCmds...)
	cmds = append(cmds,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool p1",
	)
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestSourceNATSnapshotPortRange_3906: a configured range reaches the wire.
func TestSourceNATSnapshotPortRange_3906(t *testing.T) {
	cfg := compileSNATPool(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 5000 to 6000")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PortLow != 5000 || s.PortHigh != 6000 {
		t.Fatalf("snapshot PortLow/PortHigh = %d/%d, want 5000/6000 (range silently ignored -> 1024/65535 default on revert)",
			s.PortLow, s.PortHigh)
	}
	if s.PoolNoTranslation {
		t.Fatalf("PoolNoTranslation = true, want false (only a range configured)")
	}
	if s.PoolUnusable {
		t.Fatalf("PoolUnusable = true, want false: %s", s.PoolUnusableReason)
	}
}

// TestSourceNATSnapshotNoTranslation_3906: the preserve-port flag reaches the
// wire. RED-on-revert: PoolNoTranslation stays false.
func TestSourceNATSnapshotNoTranslation_3906(t *testing.T) {
	cfg := compileSNATPool(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port no-translation")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	if !snaps[0].PoolNoTranslation {
		t.Fatalf("PoolNoTranslation = false, want true (no-translation silently ignored on revert)")
	}
}

// TestSourceNATSnapshotDefaultPortRange_3906: a pool with no port config carries
// the 1024-65535 default and no preserve flag.
func TestSourceNATSnapshotDefaultPortRange_3906(t *testing.T) {
	cfg := compileSNATPool(t,
		"set security nat source pool p1 address 203.0.113.5/32")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PortLow != 1024 || s.PortHigh != 65535 {
		t.Fatalf("default snapshot PortLow/PortHigh = %d/%d, want 1024/65535", s.PortLow, s.PortHigh)
	}
	if s.PoolNoTranslation {
		t.Fatalf("PoolNoTranslation = true, want false (no port config)")
	}
}
