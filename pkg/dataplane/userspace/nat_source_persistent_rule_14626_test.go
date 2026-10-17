package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14626: a rule-level `then source-nat pool p1 persistent-nat ...` tail must
// reach the snapshot (persistent_nat=true with the authored permit/timeout)
// instead of committing clean with persistent_nat=false. The pool-level
// control row must stay unchanged. RED on revert: the rule-tail snapshot
// comes back PersistentNAT=false.

func compileRulePNAT14626(t *testing.T, extraRuleCmds []string, poolCmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{"set security nat source pool p1 address 203.0.113.5/32"}
	cmds = append(cmds, poolCmds...)
	cmds = append(cmds,
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
	)
	cmds = append(cmds, extraRuleCmds...)
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

func TestRuleLevelPersistentNATSnapshot14626(t *testing.T) {
	cfg := compileRulePNAT14626(t, []string{
		"set security nat source rule-set RS rule R1 then source-nat pool p1 persistent-nat permit any-remote-host inactivity-timeout 900",
	})
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if !s.PersistentNAT {
		t.Fatalf("PersistentNAT = false, want true (rule-level tail was inert, #14626)")
	}
	if s.PersistentNATPermit != "any-remote-host" || s.PersistentNATInactivityTimeout != 900 {
		t.Fatalf("permit/timeout = %q/%d, want any-remote-host/900", s.PersistentNATPermit, s.PersistentNATInactivityTimeout)
	}
	if !s.PersistentNATPermitAnyRemoteHost {
		t.Fatalf("PersistentNATPermitAnyRemoteHost = false, want true")
	}
	// Pool definition itself must be untouched.
	if cfg.Security.NAT.SourcePools["p1"].PersistentNAT != nil {
		t.Fatalf("pool PersistentNAT mutated: %+v", cfg.Security.NAT.SourcePools["p1"].PersistentNAT)
	}
}

func TestRuleLevelPersistentNATSnapshotPoolControl14626(t *testing.T) {
	cfg := compileRulePNAT14626(t,
		[]string{"set security nat source rule-set RS rule R1 then source-nat pool p1"},
		"set security nat source pool p1 persistent-nat permit any-remote-host",
		"set security nat source pool p1 persistent-nat inactivity-timeout 300",
	)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if !s.PersistentNAT || s.PersistentNATPermit != "any-remote-host" || s.PersistentNATInactivityTimeout != 300 {
		t.Fatalf("pool control snapshot = %+v, want persistent any-remote-host/300", s)
	}
}
