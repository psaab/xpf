package daemon

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

// healedConfig9884 is the expired-recovery healed shape: a committed,
// interfaces-carrying config. On a compile-failed Load with an expired
// confirm record the store heals ActiveConfig to exactly this (the prev
// tree) while STILL reporting ErrConfigCompile, so the daemon sits in
// bootstrap mode with a non-nil, takeover-eligible active config.
const healedConfig9884 = `
system {
    host-name healed-9884;
}
interfaces {
    em0 {
        unit 0 { family inet { address 10.99.12.1/30; } }
    }
}
`

// healedBootstrapDaemon9884 builds a daemon over a committed
// interfaces-carrying config with the apply body stubbed to a counter,
// in bootstrap mode when bootstrap is set.
func healedBootstrapDaemon9884(t *testing.T, bootstrap bool) (*Daemon, *atomic.Int32) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(healedConfig9884); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(healed fixture): %v", err)
	}
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("fixture did not compile: ActiveConfig is nil")
	}
	if len(cfg.Interfaces.Interfaces) == 0 {
		t.Fatal("fixture degenerated: no interfaces, so the bootstrap-exit block " +
			"would no-op and the cell would prove nothing")
	}
	var applies atomic.Int32
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		store:     s,
		daemonCtx: context.Background(),
	}
	d.applyBodyForTest = func(_ *config.Config) { applies.Add(1) }
	if bootstrap {
		d.bootstrapMode.Store(true)
	}
	return d, &applies
}

// TestBootstrapHealedBackgroundAppliesRefused9884 pins the #9884 parent-review
// finding: error classification alone does not preserve fail-closed startup
// once recovery heals ActiveConfig to non-nil, because a background apply
// (feed refresh, DHCP lease change, config poll) would reach the
// bootstrap-exit block in applyConfigLocked and take over with no commit or
// sync. Every background entry point must refuse while in bootstrap — the
// feed leg driven through its REAL callback (onFeedUpdate).
//
// FAIL-ON-REVERT: removing the bootstrap check from beginBackgroundApply
// lets every arm apply and the counter reaches 4.
func TestBootstrapHealedBackgroundAppliesRefused9884(t *testing.T) {
	d, applies := healedBootstrapDaemon9884(t, true)

	d.applyConfig(d.store.ActiveConfig())
	d.applyActiveConfig()
	if err := d.onFeedUpdate(); err != nil {
		t.Fatalf("onFeedUpdate in bootstrap = %v, want nil vacuous success "+
			"(an error records publication DEBT and spins the feed manager)", err)
	}
	if err := d.applyActiveConfigResult(); err != nil {
		t.Fatalf("applyActiveConfigResult in bootstrap = %v, want nil vacuous success", err)
	}

	if got := applies.Load(); got != 0 {
		t.Fatalf("%d background apply/applies ran in bootstrap mode on a healed config; "+
			"any one of them reaches the bootstrap-exit block and takes over with no "+
			"commit or sync (#9884)", got)
	}
	if !d.inBootstrap() {
		t.Fatal("daemon left bootstrap mode with no authorized recovery transition (#9884)")
	}
}

// TestBootstrapHealedBackgroundAppliesRunWhenNotBootstrap9884 is the
// tightening control. Without it, a gate that refuses background applies
// unconditionally satisfies every assertion above while disabling DHCP lease
// reconciliation, dynamic feeds, and the config-poll applier for the
// daemon's entire lifetime.
func TestBootstrapHealedBackgroundAppliesRunWhenNotBootstrap9884(t *testing.T) {
	d, applies := healedBootstrapDaemon9884(t, false)

	if err := d.onFeedUpdate(); err != nil {
		t.Fatalf("onFeedUpdate out of bootstrap = %v, want nil", err)
	}
	if got := applies.Load(); got != 1 {
		t.Fatalf("out-of-bootstrap feed update ran %d applies, want 1; the #9884 gate "+
			"must be scoped to bootstrap, not applied always", got)
	}
}
