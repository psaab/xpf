package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ra"
)

// TestRunStartupGoodbyeRetainsRetryDebtOnFailure proves the cold-boot one-shot
// goodbye is marked done ONLY after the lifetime-0 RA provably goes out. Before
// #5093 the reconcile loop set startupGoodbyeRA[rg]=true BEFORE launching the
// async WithdrawOnce, so a bind/write failure was never retried and the stale
// IPv6 default-router identity lingered on hosts until Router Lifetime expiry.
// Here WithdrawOnce reports a per-interface Err; the sticky bit MUST stay unset
// (retry debt kept) and the in-flight slot MUST clear so the reconcile ticker
// retries. Reverting the fix (set-before-launch) fails this test RED.
func TestRunStartupGoodbyeRetainsRetryDebtOnFailure(t *testing.T) {
	d := &Daemon{startupGoodbyeInflight: map[int]bool{1: true}}
	d.startupGoodbyeWithdrawFn = func([]*config.RAInterfaceConfig) []ra.GoodbyeResult {
		return []ra.GoodbyeResult{{Interface: "reth0.50", Err: errors.New("write failed")}}
	}

	d.runStartupGoodbye(1, []*config.RAInterfaceConfig{{Interface: "reth0.50"}})

	if d.startupGoodbyeRA[1] {
		t.Fatal("goodbye failed but startupGoodbyeRA[1]=true — retry debt lost (swallowed failure)")
	}
	if d.startupGoodbyeInflight[1] {
		t.Fatal("in-flight slot not cleared after the goodbye goroutine finished")
	}
	if !d.startupGoodbyeNeeded(1) {
		t.Fatal("startupGoodbyeNeeded=false after a failed goodbye — retry is blocked")
	}
}

// TestRunStartupGoodbyeMarksDoneOnSuccess proves a goodbye that actually went
// out (Sent) — or was intentionally skipped because another owner holds the
// interface — marks the RG done so it is not re-emitted on every reconcile tick.
func TestRunStartupGoodbyeMarksDoneOnSuccess(t *testing.T) {
	d := &Daemon{startupGoodbyeInflight: map[int]bool{2: true}}
	d.startupGoodbyeWithdrawFn = func([]*config.RAInterfaceConfig) []ra.GoodbyeResult {
		return []ra.GoodbyeResult{
			{Interface: "reth0.50", Sent: true},
			{Interface: "reth0.80", Skipped: true},
		}
	}

	d.runStartupGoodbye(2, []*config.RAInterfaceConfig{
		{Interface: "reth0.50"}, {Interface: "reth0.80"},
	})

	if !d.startupGoodbyeRA[2] {
		t.Fatal("goodbye succeeded but startupGoodbyeRA[2] unset — would re-emit every tick")
	}
	if d.startupGoodbyeInflight[2] {
		t.Fatal("in-flight slot not cleared")
	}
	if d.startupGoodbyeNeeded(2) {
		t.Fatal("startupGoodbyeNeeded=true after a successful goodbye — would re-emit")
	}
}

// TestStartupGoodbyeBeginSerializesInFlight proves at most one goodbye goroutine
// is launched per RG at a time: a second Begin while one is in flight returns
// false. Without this guard a later reconcile tick would launch a duplicate
// WithdrawOnce that self-skips on the held tombstone and falsely records success
// while the first goroutine is still trying (#5093).
func TestStartupGoodbyeBeginSerializesInFlight(t *testing.T) {
	d := &Daemon{}
	if !d.startupGoodbyeNeeded(3) {
		t.Fatal("fresh RG should need a goodbye")
	}
	if !d.startupGoodbyeBegin(3) {
		t.Fatal("first Begin should claim the in-flight slot")
	}
	if d.startupGoodbyeBegin(3) {
		t.Fatal("second Begin while in flight must return false")
	}
	if d.startupGoodbyeNeeded(3) {
		t.Fatal("an in-flight RG must not be reported as needing a goodbye")
	}
}

func TestRunStartupGoodbyeSkipsSharedRouterIdentity10789(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1::/64")
	d := &Daemon{
		store:                  store,
		startupGoodbyeInflight: map[int]bool{1: true},
	}
	called := false
	d.startupGoodbyeWithdrawFn = func(configs []*config.RAInterfaceConfig) []ra.GoodbyeResult {
		called = true
		if len(configs) != 1 {
			t.Errorf("WithdrawOnce received %d configs, want one", len(configs))
			return nil
		}
		return []ra.GoodbyeResult{{Interface: configs[0].Interface, Sent: true}}
	}

	cfg := d.buildRAConfigs(store.ActiveConfig())
	if len(cfg) != 1 {
		t.Fatalf("buildRAConfigs returned %d entries, want one", len(cfg))
	}
	wantLL := cluster.StableRethLinkLocal(1, 1).String()
	if cfg[0].SourceLinkLocal != wantLL {
		t.Fatalf("test precondition: SourceLinkLocal=%q, want shared identity %q",
			cfg[0].SourceLinkLocal, wantLL)
	}

	d.runStartupGoodbye(1, cfg)
	if called {
		t.Fatal("WithdrawOnce ran for the cluster-shared router identity")
	}
	if !d.startupGoodbyeRA[1] {
		t.Fatal("shared-identity suppression did not mark startup cleanup complete")
	}
	if d.startupGoodbyeInflight[1] {
		t.Fatal("startup goodbye in-flight marker remained set")
	}
}

func TestRunStartupGoodbyeKeepsDistinctIdentityWithdraw10789(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1::/64")
	d := &Daemon{
		store:                  store,
		startupGoodbyeInflight: map[int]bool{1: true},
	}
	called := false
	d.startupGoodbyeWithdrawFn = func(configs []*config.RAInterfaceConfig) []ra.GoodbyeResult {
		called = true
		if len(configs) != 1 {
			t.Errorf("WithdrawOnce received %d configs, want one distinct source fe80::1234", len(configs))
			return nil
		}
		if configs[0].SourceLinkLocal != "fe80::1234" {
			t.Errorf("WithdrawOnce source=%q, want distinct source fe80::1234", configs[0].SourceLinkLocal)
		}
		return []ra.GoodbyeResult{{Interface: configs[0].Interface, Sent: true}}

	}
	cfg := d.buildRAConfigs(store.ActiveConfig())
	cfg[0].SourceLinkLocal = "fe80::1234"
	d.runStartupGoodbye(1, cfg)
	if !called {
		t.Fatal("WithdrawOnce was suppressed for a distinct router identity")
	}
	if !d.startupGoodbyeRA[1] {
		t.Fatal("successful distinct-identity goodbye did not complete startup cleanup")
	}
}
