package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #5790: a SUCCESSFUL no-enforcement teardown of the xpf_hostinbound table must
// clear hostInboundEnforced. Before the fix the flag stayed sticky-true after a
// teardown even though NO table remained, so a later enforceable generation whose
// FIRST real nft load failed took the day-2 RETENTION branch (which assumes a
// retained table still protects the addresses) and SKIPPED the cold-boot fence —
// leaving newly reachable firewall-local addresses UNPROTECTED (fail-open). The
// nft-apply/delete seams (nftApplyPayload / nftDeleteTable) are the package-level
// fakes the existing #5644 host-inbound tests use.

// TestHostInboundTeardownClearsEnforcedThenFailedReinstallFences_5790 is the
// primary fail-on-revert proof for the whole install -> teardown -> failed
// reinstall ordering: an enforceable config installs a real table (flag true), a
// non-enforceable config tears it down (flag must go FALSE), then an enforceable
// config whose real load FAILS must take the cold-boot fence path (fail-closed),
// NOT the day-2 retention branch (there is no retained table after the teardown).
// Reverting the teardown Store(false) makes the flag stay true: the teardown
// assertion goes RED, AND the failed reinstall skips the fence (fencePayload stays
// empty) — a second RED that pins the fail-open the issue describes.
func TestHostInboundTeardownClearsEnforcedThenFailedReinstallFences_5790(t *testing.T) {
	orig := nftInstaller
	defer func() { nftInstaller = orig }()

	enforceable := hostInboundTestConfig()
	d := &Daemon{}

	// --- Step 1: enforceable config, real install succeeds -> flag TRUE. ---
	nftInstaller = &fakeNftInstaller{} // all succeed
	if err := d.applyHostInboundFilter(enforceable); err != nil {
		t.Fatalf("step 1 (install) apply: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 1: hostInboundEnforced must be true after a successful real install")
	}

	// --- Step 2: non-enforceable config -> table teardown succeeds -> flag FALSE. ---
	// The teardown deletes BOTH the main and the additive gap table (#5789), so
	// accept either target and record which were removed. No install op may run.
	deleted := map[string]bool{}
	nftInstaller = &fakeNftInstaller{
		del: func(name string) error {
			if name != xnft.HostInboundTableName && name != xnft.HostInboundGapTableName {
				t.Fatalf("step 2: unexpected delete target %q", name)
			}
			deleted[name] = true
			return nil // teardown succeeds
		},
		hostInbound: func(xnft.HostInboundSpec) error {
			t.Fatal("step 2: the no-enforcement teardown path must not install a host-inbound table")
			return nil
		},
	}
	if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
		t.Fatalf("step 2 (teardown) apply: %v", err)
	}
	if !deleted[xnft.HostInboundTableName] {
		t.Fatalf("step 2: teardown must delete the main xpf_hostinbound table, deleted=%v", deleted)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatal("step 2 (THE #5790 BUG): a successful teardown must CLEAR hostInboundEnforced; " +
			"it stayed sticky-true after the table was deleted")
	}

	// --- Step 3: enforceable again, real install FAILS -> cold-boot fence path. ---
	injected := errors.New("nftables: reinstall real load failed")
	var realCalls, fenceCalls int
	var fenceSpec xnft.FenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { realCalls++; return injected },
		coldBootFence: func(spec xnft.FenceSpec) error {
			fenceCalls++
			fenceSpec = spec // the fence loads
			return nil
		},
		del: func(string) error {
			t.Fatal("step 3: an enforceable generation must not tear down the table")
			return nil
		},
	}

	err := d.applyHostInboundFilter(enforceable)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("step 3: the failed reinstall must surface the netlink error, got %v", err)
	}
	if fenceCalls != 1 {
		t.Fatalf("step 3 (THE #5790 FAIL-OPEN): after the teardown cleared the flag, a failed real "+
			"reinstall MUST take the cold-boot fence path; installed %d fences — a stale-true flag "+
			"would take the day-2 retention branch over a table that no longer exists", fenceCalls)
	}
	if realCalls != 1 {
		t.Errorf("step 3: expected exactly one real install attempt, got %d", realCalls)
	}
	// The fence must DENY the enforced wan addresses (both families) — fail-closed.
	// A FenceSpec structurally carries no host-service accept.
	if !sliceContains(fenceViewAddrs(fenceSpec, false), "172.16.50.8") {
		t.Errorf("step 3 fence must fence the enforced wan v4 address 172.16.50.8:\n%+v", fenceSpec)
	}
	if !sliceContains(fenceViewAddrs(fenceSpec, true), "2001:db8:50::8") {
		t.Errorf("step 3 fence must fence the enforced wan v6 address 2001:db8:50::8:\n%+v", fenceSpec)
	}
	// The address-scoped fallback fence established enforcement.
	if !d.hostInboundEnforced.Load() {
		t.Error("step 3: hostInboundEnforced must be true after the address-scoped fence installs")
	}
}

// TestHostInboundTeardownFailureKeepsEnforced_5790 pins the other half of the
// contract: a FAILED teardown must NOT clear hostInboundEnforced, because a table
// the delete could not remove may still be installed and protecting the
// addresses. Clearing it unconditionally would let a later failed install fence
// over (or fail-open relative to) a live table. Moving the Store(false) out of the
// success-only path makes this RED.
func TestHostInboundTeardownFailureKeepsEnforced_5790(t *testing.T) {
	orig := nftInstaller
	defer func() { nftInstaller = orig }()

	// Establish enforcement (flag true).
	nftInstaller = &fakeNftInstaller{} // all succeed
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("setup install: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("setup: hostInboundEnforced must be true after a successful real install")
	}

	// Non-enforceable config, but the teardown FAILS.
	injected := errors.New("nftables: delete table failed")
	nftInstaller = &fakeNftInstaller{
		del: func(string) error { return injected },
	}
	err := d.applyHostInboundFilter(&config.Config{})
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("teardown failure must be surfaced as an error, got %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Error("teardown FAILURE must NOT clear hostInboundEnforced — a table the delete could " +
			"not remove may still be installed")
	}
}
