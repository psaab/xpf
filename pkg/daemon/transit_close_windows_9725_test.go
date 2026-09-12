package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// #9725, the close WINDOWS. The gate is a predicate (armed AND a live attached
// link), so it is only correct where something re-reads it. Two paths destroyed
// the last shim XDP link with kernel transit still open and nothing re-reading
// until after the damage:
//
//   - a hitless stop closes the Go handles and leaves forwarding open, because
//     "the shim keeps dropping transit" (#9686). That premise is about PINS, and
//     an unpinned link does not survive Close, so Close REPORTS what outlives it
//     and the gate follows that number.
//   - the bootstrap rollback tore the dataplane down and closed the gate
//     AFTERWARDS, so the whole teardown ran with forwarding on and nothing
//     attached.
//
// Both are witnessed the same way: transitWitnessDP records the sysctls and the
// barrier calls AT THE MOMENT the lifecycle call runs, so these cells fail if the
// close moves back after it, which is what a plain end-state assertion would miss.

// pinWitnessDP9725 is the #9686 witness plus the #9725 link REPORT. It stands in
// for the real Manager, whose Close reports the links that outlive it (the ones
// whose pin still names them) before it closes any handle.
type pinWitnessDP9725 struct {
	transitWitnessDP

	attached  int
	surviving int
	observer  func(int)
}

func (d *pinWitnessDP9725) AttachedXDPLinkCount() int { return d.attached }

func (d *pinWitnessDP9725) SetAttachedLinksObserver(fn func(int)) { d.observer = fn }

func (d *pinWitnessDP9725) Close() error {
	if d.observer != nil {
		d.observer(d.surviving)
	}
	d.snapshot("Close")
	return nil
}

// A hitless stop must close kernel transit when its attached links carry no pin,
// and must still leave a genuine hitless upgrade alone. The two rows differ ONLY
// in the unpinned count, so a fix that closes unconditionally fails the first row
// and the pre-#9725 behaviour fails the second.
func TestAHitlessStopClosesTransitOnlyWhenItsLinksHaveNoPin9725(t *testing.T) {
	for _, tc := range []struct {
		name        string
		surviving   int
		wantSysctl  string
		wantBarrier []string
	}{
		{
			name:        "a link survives the close: a true hitless upgrade",
			surviving:   1,
			wantSysctl:  "1",
			wantBarrier: []string{"remove"},
		},
		{
			name:        "nothing survives the close: the links were unpinned",
			surviving:   0,
			wantSysctl:  "0",
			wantBarrier: []string{"install"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6, fake := seamTransitClose9686(t)
			store := commitShutdownFixture9686(t, "system {\n    host-name fw9725;\n}\n")
			if cfg := store.ActiveConfig(); cfg == nil || cfg.Chassis.Cluster != nil {
				t.Fatal("fixture: this must be a standalone config, so the stop is hitless")
			}

			daemonCtx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			dp := &pinWitnessDP9725{
				transitWitnessDP: transitWitnessDP{v4: v4, v6: v6, nft: fake},
				attached:         1,
				surviving:        tc.surviving,
			}
			d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), daemonCtx: daemonCtx}
			d.setDataplane(dp)
			d.dataplaneArmed.Store(true)

			var wg sync.WaitGroup
			_, stopRun := context.WithCancel(context.Background())
			sentinel := errors.New("run-error-passthrough")
			done := make(chan error, 1)
			go func() { done <- d.runShutdownSequence(&wg, stopRun, sentinel) }()
			select {
			case got := <-done:
				if !errors.Is(got, sentinel) {
					t.Fatalf("runShutdownSequence returned %v, want the run error passed through", got)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("runShutdownSequence did not return within 30s")
			}

			if dp.called != "Close" || dp.lifecycleCalls != 1 {
				t.Fatalf("premise: dataplane lifecycle called %q %d time(s), want Close once — this row must be the hitless path",
					dp.called, dp.lifecycleCalls)
			}
			for i, fam := range []string{"IPv4 ip_forward", "IPv6 conf.all.forwarding"} {
				if dp.sysctlsAtCall[i] != tc.wantSysctl {
					t.Errorf("#9725: %s read %q when Close ran, want %q (Close reported %d surviving link(s)). "+
						"Close reports what OUTLIVES it, and the gate follows that number: nothing surviving must "+
						"close transit, because the kernel detaches an unpinned link as soon as this process drops "+
						"its handle; a surviving link must leave forwarding alone, or the hitless upgrade this "+
						"path exists for is broken",
						fam, dp.sysctlsAtCall[i], tc.wantSysctl, tc.surviving)
				}
			}
			if got := strings.Join(dp.barrierAtCall, ","); got != strings.Join(tc.wantBarrier, ",") {
				t.Errorf("#7191 barrier calls before Close = %v, want %v", dp.barrierAtCall, tc.wantBarrier)
			}
		})
	}
}

// The bootstrap rollback must close the gate BEFORE it tears the dataplane down.
// Teardown destroys the last link, and the gate was closed after it returned, so
// forwarding ran with nothing adjudicating it for the whole teardown.
func TestABootstrapRollbackClosesTransitBeforeItTearsDown9725(t *testing.T) {
	v4, v6, fake := seamTransitClose9686(t)
	prevLinkDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = prevLinkDir })

	d := &Daemon{}
	dp := &transitWitnessDP{v4: v4, v6: v6, nft: fake}
	d.setDataplane(dp)
	d.dataplaneArmed.Store(true)

	d.runBootstrapTeardownSteps()

	if dp.called != "Teardown" || dp.lifecycleCalls != 1 {
		t.Fatalf("premise: dataplane lifecycle called %q %d time(s), want Teardown once", dp.called, dp.lifecycleCalls)
	}
	for i, fam := range []string{"IPv4 ip_forward", "IPv6 conf.all.forwarding"} {
		if dp.sysctlsAtCall[i] != "0" {
			t.Errorf("#9725: %s read %q at the moment the rollback tore the dataplane down, want \"0\". "+
				"Teardown destroys the last shim XDP link, and nothing re-reads the gate while it runs, so "+
				"closing afterwards leaves the node forwarding transit with nothing attached for the whole teardown",
				fam, dp.sysctlsAtCall[i])
		}
	}
	if len(dp.barrierAtCall) == 0 || dp.barrierAtCall[len(dp.barrierAtCall)-1] != "install" {
		t.Errorf("#7191 barrier calls before the teardown = %v, want the barrier installed first", dp.barrierAtCall)
	}
	if d.dataplaneArmed.Load() {
		t.Errorf("the rollback left the dataplane marked armed, so the next apply tail would reopen the gate")
	}
}
