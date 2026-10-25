// #16820: terminateDemotedRGIPsecSAs is a fire-and-forget goroutine that
// never re-checks RG ownership. If the RG fails back while the sweep is
// still running (the live-SA read and each terminate shell out, so the
// window grows with SA count), the sweep force-terminates the SA the
// now-primary node just re-initiated — recreating the #15194 failback
// black hole on the owning node.
//
// The fix captures a per-RG ownership epoch at demotion and re-checks
// !IsLocalPrimary(rg) plus the epoch immediately before each terminate.
//
// SUBJECT cell: failback (re-promotion) lands while the sweep is blocked
// in its live-SA read. The sweep must terminate NOTHING and the final
// event must be the takeover initiate.
// CONTROL cell: the sweep completes before any failback — it must still
// terminate the demoted RG's SA exactly as #15194 requires, and a later
// takeover initiates after it.
// RG0 cell: same race on the RG0 demotion arm of
// applyRG0OwnershipTransition.

package daemon

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// ipsecRaceRecorder16820 records terminate/initiate events in order and
// lets a test block the live-SA read until it releases the gate.
type ipsecRaceRecorder16820 struct {
	mu     sync.Mutex
	events []string
}

func (r *ipsecRaceRecorder16820) record(kind, name string) error {
	r.mu.Lock()
	r.events = append(r.events, kind+":"+name)
	r.mu.Unlock()
	return nil
}

func (r *ipsecRaceRecorder16820) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func (r *ipsecRaceRecorder16820) terminated() []string {
	var out []string
	for _, e := range r.snapshot() {
		if len(e) > 10 && e[:10] == "terminate:" {
			out = append(out, e[10:])
		}
	}
	sort.Strings(out)
	return out
}

// SUBJECT: RG1 demotion launches the sweep; the sweep blocks in
// ipsecActiveNames; RG1 fails back (cluster primary + real promotion
// edge via applyRethServicesForRG, which bumps the epoch and launches
// the real re-initiate leg); the read is then released. Pre-fix the
// sweep terminates vpn-rg1 AFTER the initiate; post-fix it must
// terminate nothing.
func TestDemotionSweepAbortsOnFailback16820(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecRaceRecorder16820{}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1"})

	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	var readOnce sync.Once
	// Count reads: the sweep's read blocks; the takeover belt's read
	// (inside reinitiateIPsecSAsForRG) must not block, or it would
	// deadlock the test — only the FIRST read is gated.
	var readMu sync.Mutex
	readCount := 0

	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			readMu.Lock()
			readCount++
			n := readCount
			readMu.Unlock()
			if n == 1 {
				readOnce.Do(func() { close(readStarted) })
				<-releaseRead
			}
			return []string{"vpn-rg1"}, nil
		},
		ipsecTerminateFn: func(name string) error { return rec.record("terminate", name) },
		ipsecInitiateFn:  func(name string) error { return rec.record("initiate", name) },
	}

	// Node loses RG1: real demotion edge launches the async sweep.
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.clearRethServicesForRG(1)

	// Wait until the sweep is blocked inside its live-SA read.
	select {
	case <-readStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("demotion sweep did not reach its live-SA read")
	}

	// Failback: node becomes RG1 primary again and the real promotion
	// edge runs (bumps epoch + launches re-initiate). Drive the
	// re-initiate leg synchronously for deterministic event order; the
	// belt sees vpn-rg1 live (the gated read returns it for n>1) so it
	// belt-terminates then initiates — that terminate is the belt's,
	// recorded before initiate.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.bumpIPsecRGOwnershipEpoch(1) // what applyRethServicesForRG does first
	d.reinitiateIPsecSAsForRG(1)

	// Now release the sweep's blocked read.
	close(releaseRead)

	// Give the sweep a bounded window to (not) terminate.
	time.Sleep(300 * time.Millisecond)

	events := rec.snapshot()
	// The only terminate allowed is the belt's pre-initiate terminate.
	// After the initiate there must be NO further terminate, and the
	// last event must be the initiate.
	if len(events) == 0 {
		t.Fatal("#16820: no events recorded; takeover initiate never ran")
	}
	if last := events[len(events)-1]; last != "initiate:vpn-rg1" {
		t.Fatalf("#16820: failback-during-sweep must end with initiate:vpn-rg1, got events=%v "+
			"(the demotion sweep terminated the SA the now-primary node just re-initiated)", events)
	}
	// Exactly one terminate (the belt's) before the initiate.
	termCount := 0
	for _, e := range events {
		if e == "terminate:vpn-rg1" {
			termCount++
		}
	}
	if termCount != 1 {
		t.Fatalf("#16820: expected exactly 1 terminate (takeover belt only), got %d in events=%v "+
			"(a second terminate is the stale demotion sweep)", termCount, events)
	}
}

// CONTROL: sweep completes before any failback — unchanged #15194
// behaviour, then a later takeover initiates.
func TestDemotionSweepCompletesBeforeFailback16820(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecRaceRecorder16820{}
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			return []string{"vpn-rg1", "vpn-rg2"}, nil
		},
		ipsecTerminateFn: func(name string) error { return rec.record("terminate", name) },
		ipsecInitiateFn:  func(name string) error { return rec.record("initiate", name) },
	}
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.clearRethServicesForRG(1)

	waitFor15194(t, "control sweep terminate", func() bool {
		return len(rec.terminated()) > 0
	})
	// Small settle window so an erroneous second terminate would land.
	time.Sleep(100 * time.Millisecond)
	if got := rec.terminated(); len(got) != 1 || got[0] != "vpn-rg1" {
		t.Fatalf("#16820 control: sweep without failback must terminate exactly [vpn-rg1], got %v", got)
	}
}

// RG0 SUBJECT: RG0 demotion sweep blocked in its read, RG0 promotion
// intervenes, sweep must abort.
func TestRG0DemotionSweepAbortsOnPromotion16820(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecRaceRecorder16820{}

	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	var readOnce sync.Once
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			readOnce.Do(func() { close(readStarted) })
			<-releaseRead
			return []string{"vpn-rg0"}, nil
		},
		ipsecTerminateFn: func(name string) error { return rec.record("terminate", name) },
	}
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	d.rg0WasPrimary.Store(true)
	d.applyRG0OwnershipTransition(cluster.StateSecondary, true)

	select {
	case <-readStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("RG0 demotion sweep did not reach its live-SA read")
	}

	// RG0 promotion intervenes (real edge bumps the epoch).
	d.applyRG0OwnershipTransition(cluster.StatePrimary, false)
	close(releaseRead)
	time.Sleep(300 * time.Millisecond)

	if got := rec.terminated(); len(got) != 0 {
		t.Fatalf("#16820: RG0 sweep resumed after re-promotion must terminate nothing, got %v", got)
	}
}

// Per-RG isolation: a failback of RG2 must not abort an RG1 sweep.
func TestDemotionSweepUnaffectedByOtherRGFailback16820(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecRaceRecorder16820{}

	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	var readOnce sync.Once
	var readMu sync.Mutex
	readCount := 0
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			readMu.Lock()
			readCount++
			n := readCount
			readMu.Unlock()
			if n == 1 {
				readOnce.Do(func() { close(readStarted) })
				<-releaseRead
			}
			return []string{"vpn-rg1"}, nil
		},
		ipsecTerminateFn: func(name string) error { return rec.record("terminate", name) },
	}
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.clearRethServicesForRG(1)
	select {
	case <-readStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("sweep did not reach its live-SA read")
	}
	// Unrelated RG2 promotion only.
	d.bumpIPsecRGOwnershipEpoch(2)
	close(releaseRead)

	waitFor15194(t, "RG1 sweep terminate after unrelated RG2 promotion", func() bool {
		return len(rec.terminated()) > 0
	})
	if got := rec.terminated(); len(got) != 1 || got[0] != "vpn-rg1" {
		t.Fatalf("#16820: unrelated RG2 failback must not abort RG1 sweep; terminated=%v want [vpn-rg1]", got)
	}
}
