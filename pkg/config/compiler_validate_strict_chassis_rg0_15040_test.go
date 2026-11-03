package config

import (
	"strings"
	"testing"
)

// #18964: literal head and per-arm tail pins, independent of the builder,
// so swapping the strict refusal and tolerant commit-succeeds outcomes reds
// both arms rather than moving the expectations with the implementation.
const (
	configSyncHead18964        = "chassis cluster: configuration-synchronize requires redundancy-group 0"
	configSyncStrictTail18964  = "without it the commit is refused) — add `redundancy-group 0` or remove `configuration-synchronize`"
	configSyncLenientTail18964 = "without it a commit succeeds but is never pushed to the peer and both nodes stay writable) — add `redundancy-group 0` or remove `configuration-synchronize`"
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
		// #16746: opt out of private-RG election so the RG0 gate is
		// the error under test, not the control-link gate.
		"set chassis cluster no-private-rg-election",
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
	} else if !strings.Contains(err.Error(), configSyncHead18964) ||
		!strings.Contains(err.Error(), configSyncStrictTail18964) {
		t.Fatalf("error %q lacks the literal #18964 head/refused tail", err.Error())
	}

	// No redundancy groups at all + configuration-synchronize: same hole.
	tree = buildTree(t, rg0SyncLines15040())
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject configuration-synchronize with no redundancy-groups, got nil")
	} else if !strings.Contains(err.Error(), configSyncHead18964) ||
		!strings.Contains(err.Error(), configSyncStrictTail18964) {
		t.Fatalf("error %q lacks the literal #18964 head/refused tail", err.Error())
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
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, configSyncHead18964) &&
			strings.Contains(warning, configSyncLenientTail18964) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile should warn with the literal #18964 head/commit-succeeds tail; warnings=%v", cfg.Warnings)
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
		"set chassis cluster no-private-rg-election",
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
