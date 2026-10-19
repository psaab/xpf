// #15283 (V52-S1): a source pool's `port range` was silently ignored when
// the pool was used by a NAT64 rule-set: NAT64RuleSnapshot carried no port
// range, deterministicNAT64V6Fields computed mode-2 blocks against the
// fixed 1024-65535 window, and the Rust allocator used the fixed
// NAT64_PORT_LOW/HIGH constants, so translated ports spanned 1024-65535
// regardless of the operator's range. These cells pin the Go half of the
// fix: the builder stamps the pool range onto the snapshot and the mode-2
// block math is computed against it. The Rust half is pinned by
// nat64_15283_* in userspace-dp/src/nat64_tests.rs.
//
// RED-on-revert: reverting the PortLow/PortHigh stamping (or the
// deterministic range) makes the narrowed-range cells see 1024/65535 (or
// the default-derived blocks-per-IP) and fail.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileNAT64PoolWithRange builds a config with a NAT64 rule-set whose
// source pool carries `port range <range>` (Junos `<low> to <high>`), or no
// range when rangeSpec is empty. deterministic adds a mode-2 deterministic
// stanza with the given block size.
func compileNAT64PoolWithRange(t *testing.T, rangeSpec string, deterministic bool) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source pool p64 address 198.51.100.1/32 to 198.51.100.4/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	}
	if rangeSpec != "" {
		cmds = append(cmds, "set security nat source pool p64 port range "+rangeSpec)
	}
	if deterministic {
		cmds = append(cmds,
			"set security nat source pool p64 port deterministic block-size 100",
			"set security nat source pool p64 port deterministic host address 2001:db8::/64",
		)
	}
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

func TestNAT64SnapshotHonoursPoolPortRange15283(t *testing.T) {
	cfg := compileNAT64PoolWithRange(t, "2000 to 3000", false)
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("nat64 snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PortLow != 2000 || s.PortHigh != 3000 {
		t.Fatalf("snapshot PortLow/PortHigh = %d/%d, want 2000/3000 (pool range silently dropped -> 1024/65535 or 0/0 on revert)",
			s.PortLow, s.PortHigh)
	}
	if s.PoolUnusable {
		t.Fatalf("pool must stay usable, got reason %q", s.PoolUnusableReason)
	}
}

// Control: a pool with no explicit `port range` keeps the default
// 1024-65535 window, byte-identical to pre-#15283.
func TestNAT64SnapshotDefaultPortRange15283(t *testing.T) {
	cfg := compileNAT64PoolWithRange(t, "", false)
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("nat64 snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PortLow != 1024 || s.PortHigh != 65535 {
		t.Fatalf("default snapshot PortLow/PortHigh = %d/%d, want 1024/65535", s.PortLow, s.PortHigh)
	}
}

// Mode 2: block math must be computed against the pool range. Range
// 2000-3000 is 1001 ports; block-size 100 => 10 blocks/IP (the default
// window would give 645).
func TestNAT64DeterministicBlocksUsePoolRange15283(t *testing.T) {
	cfg := compileNAT64PoolWithRange(t, "2000 to 3000", true)
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("nat64 snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PortLow != 2000 || s.PortHigh != 3000 {
		t.Fatalf("snapshot PortLow/PortHigh = %d/%d, want 2000/3000", s.PortLow, s.PortHigh)
	}
	if s.DeterministicBlockSize != 100 {
		t.Fatalf("DeterministicBlockSize = %d, want 100", s.DeterministicBlockSize)
	}
	if s.DeterministicBlocksPerIP != 10 {
		t.Fatalf("DeterministicBlocksPerIP = %d, want 10 (1001/100 against the pool range; 645 against the fixed default on revert)",
			s.DeterministicBlocksPerIP)
	}
}

// Helper-level pin: a narrowed pool range yields narrowed blocks-per-IP
// directly from deterministicNAT64V6Fields.
func TestDeterministicNAT64V6FieldsPoolRange15283(t *testing.T) {
	pool := &config.NATPool{
		Name:          "p",
		PortLow:       2000,
		PortHigh:      3000,
		Deterministic: &config.DeterministicNATConfig{BlockSize: 100, HostAddress: "2001:db8::/64"},
	}
	bs, bpi, pl, _, ok := deterministicNAT64V6Fields(pool)
	if !ok || bs != 100 || bpi != 10 || pl != 64 {
		t.Fatalf("got ok=%v bs=%d bpi=%d pl=%d, want ok=true bs=100 bpi=10 pl=64", ok, bs, bpi, pl)
	}
}
