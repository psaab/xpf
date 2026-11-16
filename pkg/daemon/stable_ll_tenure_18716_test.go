package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/vrrp"
)

// #18716 fold 3 (codex-e P2-1, P2-2; the user's targeted fold): one remover
// for the stable router link-local, fenced by tenure.

func countEvents18716(ev []string, name string) int {
	n := 0
	for _, e := range ev {
		if e == name {
			n++
		}
	}
	return n
}

// (a) The BACKUP event is published BEFORE the forced resign's priority-0
// burst, and the burst's IPv6 source is the stable link-local. With the burst
// still open (barrier unsettled) the BACKUP arm runs to completion against a
// helper write that fails AT ONCE, then a reconcile tick runs: neither may
// remove the address. It leaves exactly once, after the barrier settles. Both
// the helper-down resign and the plain (healthy helper) resign own it.
func TestBackupArmDuringTheBurstLeavesTheLinkLocal18716(t *testing.T) {
	for _, tc := range []struct {
		name     string
		notReady bool
	}{
		{name: "helper-down-resign", notReady: true},
		{name: "plain-resign", notReady: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := legacyDemotion18716(t, tc.notReady, 0)
			d.dataplane().(*readinessDP18701).ha.err = errors.New("helper refuses the write")
			d.rethVIPReleaseTimeout = 5 * time.Second
			barrier := newFakeVIPRelease()
			t.Cleanup(func() { barrier.release(nil) })
			d.resignRethRGFn = func(rg int) vipReleaseBarrier {
				log.add(fmt.Sprintf("resign:%d", rg))
				return barrier
			}
			primeRG1PrimaryVRRPMaster18716(t, d)
			handled := make(chan struct{})
			go func() { defer close(handled); demoteRG1(t, d) }()
			waitFor18716d(t, log, "resign:1", 2*time.Second)

			_, armEv := vrrpBackupRG1_18716(d, log)
			if !slices.Contains(armEv, "rg_active=false sent") {
				t.Fatalf("setup: arm events %v: the BACKUP arm never reached its (failing) write", armEv)
			}
			d.reconcileRGState()
			if ev := log.snapshot(); slices.Contains(ev, "ll-removed:1") {
				t.Fatalf("events %v: the stable link-local left while the resign's burst was still open; the priority-0 adverts would lose their source", ev)
			}
			barrier.release(nil)
			waitFor18716d(t, log, "ll-removed:1", time.Second)
			<-handled
			if n := countEvents18716(log.snapshot(), "ll-removed:1"); n != 1 {
				t.Fatalf("events %v: the stable link-local was removed %d times, want once (by the resign, after its burst)", log.snapshot(), n)
			}
		})
	}
}

// (b) A resign's release is parked after its barrier settled and before its
// check. A new activation then completes (the VRRP MASTER arm adds the stable
// link-local for the new tenure). Released, the old resign must keep the new
// tenure's address and report errStableLLSuperseded, not nil. The control:
// without the re-activation the same release removes the address and reports
// nil.
func TestDelayedLinkLocalReleaseKeepsANewTenure18716(t *testing.T) {
	for _, reactivate := range []bool{true, false} {
		t.Run(fmt.Sprintf("reactivate=%v", reactivate), func(t *testing.T) {
			d, log := legacyDemotion18716(t, false, 0)
			d.rethVIPReleaseTimeout = 5 * time.Second
			d.addStableRethLLFn = func(rg int) { log.add(fmt.Sprintf("ll-added:%d", rg)) }
			barrier := newFakeVIPRelease()
			t.Cleanup(func() { barrier.release(nil) })
			d.resignRethRGFn = func(rg int) vipReleaseBarrier {
				log.add(fmt.Sprintf("resign:%d", rg))
				return barrier
			}
			parked := make(chan struct{})
			hold := make(chan struct{})
			var parkOnce sync.Once
			d.stableLLReleaseHoldFn = func(int) {
				parkOnce.Do(func() { close(parked) })
				<-hold
			}
			primeRG1PrimaryVRRPMaster18716(t, d)

			_, withLL := d.resignRethRGReleasingLL(1, d.resignRethRG)
			if withLL == nil {
				t.Fatal("setup: no link-local release barrier")
			}
			// The old tenure ends: cluster secondary, VRRP BACKUP.
			d.getOrCreateRGState(1).SetCluster(false)
			vrrpBackupRG1_18716(d, log)
			barrier.release(nil)
			select {
			case <-parked:
			case <-time.After(2 * time.Second):
				t.Fatal("the release never reached its check")
			}
			if reactivate {
				before := len(log.snapshot())
				d.handleVRRPEvent(context.Background(),
					vrrp.VRRPEvent{Interface: "reth1", GroupID: rethVRIDBase + 1, State: vrrp.StateMaster}, rgTransition{})
				if !slices.Contains(log.snapshot()[before:], "ll-added:1") {
					t.Fatalf("setup: events %v: the MASTER activation did not add the stable link-local", log.snapshot()[before:])
				}
			}
			close(hold)
			select {
			case <-withLL.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("the release never settled")
			}
			ev := log.snapshot()
			if reactivate {
				if slices.Contains(ev, "ll-removed:1") {
					t.Fatalf("events %v: the delayed release removed the NEW tenure's stable link-local", ev)
				}
				if !errors.Is(withLL.Err(), errStableLLSuperseded) {
					t.Fatalf("release verdict %v, want errStableLLSuperseded", withLL.Err())
				}
				return
			}
			if !slices.Contains(ev, "ll-removed:1") || withLL.Err() != nil {
				t.Fatalf("control: events %v, verdict %v: with no re-activation the release must remove the address and report nil", ev, withLL.Err())
			}
		})
	}
}

// Every daemon-initiated forced RETH resign must go through
// resignRethRGReleasingLL, or the BACKUP arm's removal is no longer deferred
// behind its burst. Mechanical census of pkg/daemon's non-test sources: a
// ResignRG( call may appear only inside resignRethRG's own body or on a
// resignRethRGReleasingLL line, and resignRethRG( is never called directly
// outside its definition.
func TestEveryForcedResignOwnsTheLinkLocal18716(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	inDef := false
	sites := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "func ") {
				// A declaration line is neither a call site nor a bypass.
				inDef = strings.HasPrefix(line, "func (d *Daemon) resignRethRG(")
				continue
			}
			if inDef && strings.HasPrefix(line, "}") {
				inDef = false
			}
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if strings.Contains(code, "resignRethRGReleasingLL(") {
				sites++
				continue
			}
			if inDef {
				continue
			}
			if strings.Contains(code, "ResignRG(") || strings.Contains(code, "resignRethRG(") {
				bad = append(bad, fmt.Sprintf("%s:%d: %s", f, i+1, strings.TrimSpace(line)))
			}
		}
	}
	if sites < 4 {
		t.Fatalf("census found %d resignRethRGReleasingLL call sites, want the helper-down handler, the plain handler, the posture net and the bootstrap rollback (4)", sites)
	}
	if len(bad) > 0 {
		t.Fatalf("forced resigns that bypass resignRethRGReleasingLL:\n%s", strings.Join(bad, "\n"))
	}
}
