package config

import (
	"strings"
	"testing"
)

// #15040 (A24-01): configuration-synchronize with no redundancy-group 0
// committed cleanly and then never pushed. rg0ConfigSyncAuthority requires
// IsLocalPrimary(0); with no RG0 that is never true, reconcileRG0ConfigOwnership
// returns early with no gate owner, so both nodes stay writable and diverge
// silently. A runtime delete of RG0 hit the same hole post-apply.
//
// Fix: validateChassisClusterStrict rejects ConfigSync without RG0 on the
// strict path; the tolerant load/peer-sync path warns (#1960 no-brick).

func rg0SyncLines15040(extra ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster configuration-synchronize",
	}
	return append(lines, extra...)
}

func TestConfigSyncWithoutRG0FailsCommit15040(t *testing.T) {
	// RG1-only + configuration-synchronize: the exact A24-01 shape.
	tree := buildTree(t, rg0SyncLines15040(
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
	))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject configuration-synchronize without " +
			"redundancy-group 0 (no RG0 primary can ever own config sync, so the " +
			"commit would succeed and never push), got nil error")
	} else if !strings.Contains(err.Error(), "redundancy-group 0") ||
		!strings.Contains(err.Error(), "configuration-synchronize") {
		t.Fatalf("error %q does not name RG0 / configuration-synchronize", err.Error())
	}

	// No redundancy groups at all + configuration-synchronize: same hole.
	tree = buildTree(t, rg0SyncLines15040())
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject configuration-synchronize with no redundancy-groups, got nil")
	}
}

func TestConfigSyncWithoutRG0TolerantWarns15040(t *testing.T) {
	tree := buildTree(t, rg0SyncLines15040(
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick a persisted RG1-only config-sync config: %v", err)
	}
	if !warningsContain(cfg.Warnings, "redundancy-group 0") {
		t.Fatalf("lenient compile should warn about missing RG0; warnings=%v", cfg.Warnings)
	}
}

func TestConfigSyncControlsCommit15040(t *testing.T) {
	// Control: RG0 present + configuration-synchronize commits cleanly.
	tree := buildTree(t, rg0SyncLines15040(
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected RG0+RG1 configuration-synchronize: %v", err)
	}

	// Control: RG1-only WITHOUT configuration-synchronize commits cleanly —
	// the gate must not over-reject legitimate non-sync cluster configs.
	tree = buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected RG1-only cluster without configuration-synchronize: %v", err)
	}

	// Control: no cluster stanza at all is unaffected.
	tree = buildTree(t, []string{"set system host-name solo"})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected standalone config: %v", err)
	}
}
