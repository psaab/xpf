package daemon

import (
	"context"
	"testing"

	"golang.org/x/sync/semaphore"
)

// #16842: the #15687 fab1 debt must not re-drive the #11448 30 s
// reassert into tearing down and rebuilding a working single-fabric
// epoch while fab1 stays unaddressed, and must upgrade to dual exactly
// once when fab1 becomes resolvable.
//
// The harness mirrors the source report's probe: one real
// startClusterComms epoch (fab0 on lo, fab1 on a nonexistent interface,
// polls shortened via the #15687 seam), then N reassertMgmtVRFOnce
// calls (one call = one 30 s tick). Restarts are counted as
// SessionSync object replacements — the observable the probe used —
// rather than clusterCommsGen, which stopClusterComms bumps even for a
// teardown that never comes back up (#6878).
//
// RED on the pre-#16842 shape (fab1 debt on BindingChanged): the
// fabric-mode dual cell counts 5 restarts over 5 ticks with the epoch
// re-marking its debt every cycle. Controls (fabric-mode single, and
// control-link transport with fab1 configured) count 0 on both shapes.

func fab1ChurnCfg16842(fab0, fab1, extra string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key 16842-test-cluster-psk",
	}
	if extra == "control" {
		lines = append(lines,
			"set chassis cluster control-interface lo",
			"set chassis cluster peer-address 127.0.0.2",
		)
	} else {
		lines = append(lines,
			"set chassis cluster fabric-interface "+fab0,
			"set chassis cluster fabric-peer-address 127.0.0.2",
		)
	}
	if fab1 != "" {
		lines = append(lines,
			"set chassis cluster fabric1-interface "+fab1,
			"set chassis cluster fabric1-peer-address 127.0.0.3",
		)
	}
	return lines
}

func TestFab1DebtDoesNotChurnReassert16842(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	if resolveClusterInterfaceAddr(nil, "lo", "127.0.0.1", "") == "" {
		t.Skip("loopback has no usable IPv4 address")
	}

	cells := []struct {
		name string
		cfg  []string
	}{
		{"fabric dual fab1 unaddressed", fab1ChurnCfg16842("lo", "xpf-nonexistent-16842", "")},
		{"fabric single no fab1", fab1ChurnCfg16842("lo", "", "")},
		{"control-link fab1 unaddressed", fab1ChurnCfg16842("", "xpf-nonexistent-16842", "control")},
	}
	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			d := newVRFBindingRetryDaemon12168(t, tc.cfg, false)
			d.applySem = semaphore.NewWeighted(1)

			d.startClusterComms(d.daemonCtx)
			waitVRFCommsConstructor12168(t, d)

			ss := d.getSessionSync()
			if ss == nil {
				t.Fatal("epoch published no session sync (fab0/control on lo must start)")
			}
			if ss.IsDualFabric() {
				t.Fatal("epoch is dual despite fab1 being unaddressed/absent")
			}
			active0 := d.activeTransport()
			gen0 := warmVRFCommsGeneration12168(d)

			const ticks = 5
			for i := range ticks {
				d.reassertMgmtVRFOnce(context.Background())
				waitVRFCommsConstructor12168(t, d)
				if got := d.getSessionSync(); got != ss {
					t.Fatalf("tick %d rebuilt session sync (%p -> %p): fab1 debt churned the working epoch (#16842)",
						i+1, ss, got)
				}
			}
			if gen := warmVRFCommsGeneration12168(d); gen != gen0 {
				t.Fatalf("comms epoch advanced over %d reassert ticks (%d -> %d) with fab1 still unaddressed (#16842)",
					ticks, gen0, gen)
			}
			if got := d.activeTransport(); got != active0 {
				t.Fatalf("active transport changed over %d ticks: %+v -> %+v (#16842)", ticks, active0, got)
			}
			// The defect cell must actually carry the debt premise;
			// controls must not.
			if tc.name == "fabric dual fab1 unaddressed" {
				if !active0.Fab1Debt {
					t.Fatal("premise: fab1-unaddressed epoch recorded no Fab1Debt")
				}
				if active0.BindingChanged {
					t.Fatal("premise: fab1 debt rode on BindingChanged (#16842 defect shape)")
				}
			} else if active0.Fab1Debt || active0.BindingChanged {
				t.Fatalf("control epoch carries transport debt: %+v", active0)
			}
		})
	}
}

// TestFab1DebtUpgradesOnceWhenAddressArrives16842 pins the positive
// half of #16842 acceptance: while fab1 stays unaddressed, N reassert
// ticks restart 0 times (covered above); once fab1 resolves (store now
// names lo for fab1, the #15687 late-arrival model), the next tick
// performs exactly one restart landing on a dual SessionSync, and
// further ticks are stable.
func TestFab1DebtUpgradesOnceWhenAddressArrives16842(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	if resolveClusterInterfaceAddr(nil, "lo", "127.0.0.1", "") == "" {
		t.Skip("loopback has no usable IPv4 address")
	}
	d := newVRFBindingRetryDaemon12168(t,
		fab1ChurnCfg16842("lo", "xpf-nonexistent-16842", ""), false)
	d.applySem = semaphore.NewWeighted(1)

	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)
	ss1 := d.getSessionSync()
	if ss1 == nil || ss1.IsDualFabric() {
		t.Fatalf("epoch 1 session sync = %v dual=%v, want single", ss1, ss1 != nil && ss1.IsDualFabric())
	}
	if !d.activeTransport().Fab1Debt {
		t.Fatal("premise: epoch 1 recorded no Fab1Debt")
	}

	// Still unaddressed: two ticks, no restart.
	for i := range 2 {
		d.reassertMgmtVRFOnce(context.Background())
		waitVRFCommsConstructor12168(t, d)
		if got := d.getSessionSync(); got != ss1 {
			t.Fatalf("unaddressed tick %d rebuilt session sync (#16842)", i+1)
		}
	}

	// Fab1 becomes addressed: swap the store to the lo-named config
	// (same model as the #15687 test), then one tick upgrades.
	d.store = testStoreWithSetConfig(t, fab1ChurnCfg16842("lo", "lo", ""))
	d.reassertMgmtVRFOnce(context.Background())
	waitVRFCommsConstructor12168(t, d)
	ss2 := d.getSessionSync()
	if ss2 == nil {
		t.Fatal("upgrade tick published no session sync")
	}
	if ss2 == ss1 {
		t.Fatal("upgrade tick did not rebuild session sync once fab1 resolved (#16842)")
	}
	if !ss2.IsDualFabric() {
		t.Fatal("upgraded session sync is not dual (#16842/#15687)")
	}
	if active := d.activeTransport(); active.Fab1Debt || active.BindingChanged {
		t.Fatalf("healthy dual epoch still carries debt: %+v", active)
	}

	// Exactly once: further ticks keep the dual epoch.
	gen := warmVRFCommsGeneration12168(d)
	for i := range 3 {
		d.reassertMgmtVRFOnce(context.Background())
		waitVRFCommsConstructor12168(t, d)
		if got := d.getSessionSync(); got != ss2 {
			t.Fatalf("post-upgrade tick %d rebuilt session sync again (#16842)", i+1)
		}
	}
	if got := warmVRFCommsGeneration12168(d); got != gen {
		t.Fatalf("post-upgrade ticks advanced the comms epoch (%d -> %d) (#16842)", gen, got)
	}
}

// TestReconcileFab1DebtOnlyFiresWhenReady16842 pins reconcile directly
// (no reassert plumbing): a fab1-debt epoch with fab1 still
// unaddressed must not restart through step 20 either — a commit is not
// a licence to churn — while the same epoch with fab1 resolvable, or
// with an unrelated key difference (fab1 removed), restarts exactly
// once.
func TestReconcileFab1DebtOnlyFiresWhenReady16842(t *testing.T) {
	if resolveClusterInterfaceAddr(nil, "lo", "127.0.0.1", "") == "" {
		t.Skip("loopback has no usable IPv4 address")
	}
	newDaemon := func(t *testing.T, cfgLines []string) (*Daemon, *int) {
		d := newVRFBindingRetryDaemon12168(t, cfgLines, false)
		starts := new(int)
		d.startClusterCommsFn = func(ctx context.Context) {
			*starts++
			cfg := d.store.ActiveConfig()
			_, gen, _ := d.beginClusterCommsEpoch(ctx)
			if !d.setActiveTransportIfCurrent(gen, d.clusterTransportForConfig(cfg)) {
				t.Errorf("replacement epoch %d failed to publish its transport", gen)
			}
		}
		// Publish the debt epoch through the real epoch-gated path,
		// then mark its fab1 debt as the constructor would.
		_, gen, _ := d.beginClusterCommsEpoch(d.daemonCtx)
		cfg := d.store.ActiveConfig()
		if !d.setActiveTransportIfCurrent(gen, d.clusterTransportForConfig(cfg)) {
			t.Fatal("fixture could not publish the initial transport key")
		}
		d.markClusterCommsFab1Debt(gen)
		if !d.activeTransport().Fab1Debt {
			t.Fatal("fixture failed to record Fab1Debt")
		}
		return d, starts
	}

	t.Run("unaddressed no restart", func(t *testing.T) {
		cfgLines := fab1ChurnCfg16842("lo", "xpf-nonexistent-16842", "")
		d, starts := newDaemon(t, cfgLines)
		d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
		if *starts != 0 {
			t.Fatalf("reconcile restarted a fab1-debt epoch %d times while fab1 unaddressed (#16842)", *starts)
		}
		if !d.activeTransport().Fab1Debt {
			t.Fatal("unaddressed reconcile cleared the fab1 debt without upgrading")
		}
	})

	t.Run("addressed restarts once", func(t *testing.T) {
		d, starts := newDaemon(t, fab1ChurnCfg16842("lo", "lo", ""))
		d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
		if *starts != 1 {
			t.Fatalf("reconcile restarted %d times with fab1 resolvable, want 1 (#16842)", *starts)
		}
	})

	t.Run("fab1 removed restarts once", func(t *testing.T) {
		d, starts := newDaemon(t, fab1ChurnCfg16842("lo", "xpf-nonexistent-16842", ""))
		d.store = testStoreWithSetConfig(t, fab1ChurnCfg16842("lo", "", ""))
		d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
		if *starts != 1 {
			t.Fatalf("reconcile restarted %d times after fab1 removal, want 1 (config change)", *starts)
		}
	})
	t.Run("unaddressed restart owed", func(t *testing.T) {
		d, starts := newDaemon(t, fab1ChurnCfg16842("lo", "xpf-nonexistent-16842", ""))
		cfg := d.store.ActiveConfig()
		d.markClusterCommsRestartNeeded()
		d.reconcileClusterTransportBinding(cfg, d.takeClusterCommsRestartNeeded())
		if *starts != 1 {
			t.Fatalf("owed restart recovered comms %d times while fab1 unaddressed, want 1 (#17871)", *starts)
		}
		if d.activeTransport().Fab1Debt {
			t.Fatal("recovery left Fab1Debt set on the replacement epoch")
		}
		d.reconcileClusterTransportBinding(cfg, d.takeClusterCommsRestartNeeded())
		if *starts != 1 {
			t.Fatalf("unowed follow-up restarted comms %d times, want no additional restart (#16842/#17871)", *starts)
		}
	})
}
