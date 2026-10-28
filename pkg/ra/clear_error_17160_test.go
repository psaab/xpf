package ra

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestClearSurfacesRacingGoodbyeFailure17160 is the #17160 defect cell for
// Manager.Clear's constant-nil error (the #6777 shape left behind in Clear).
//
// Deterministic race, driven through the real Manager.Clear: the sender's
// conn Close is gated, so once Clear hard-stops the sender the owner parks
// in finishShutdown's Close — AFTER it read modeHard, so it can no longer
// emit a goodbye itself, but BEFORE <-stopped closes, so Clear's join is
// still blocked and its tombstone is held. A graceful Withdraw then flips
// goodbyeWanted on Clear's tombstone. The gate is released, Clear joins,
// and its releaseDrain must emit the standalone goodbye — with every
// lifetime-0 write failing, that emit fails. Pre-fix clearLocked logged
// the failure and returned a constant nil, so Clear reported success.
//
// RED on revert: restore clearLocked's `return nil` and Clear returns nil
// while attempts prove a goodbye was tried and failed.
func TestClearSurfacesRacingGoodbyeFailure17160(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	m.mu.Lock()
	s := m.senders["lo"]
	m.mu.Unlock()
	if s == nil {
		t.Fatal("no lo sender")
	}
	if !s.waitConnReady(2 * time.Second) {
		t.Fatal("sender conn never came up")
	}

	g.setFailing(true)

	fc, ok := s.conn.(*fakeConn)
	if !ok {
		t.Fatalf("sender conn is %T, want *fakeConn (probe seam)", s.conn)
	}
	releaseClose := make(chan struct{})
	closing := make(chan struct{})
	var once sync.Once
	fc.setBeforeClose(func() {
		once.Do(func() { close(closing) })
		<-releaseClose
	})

	clearDone := make(chan error, 1)
	go func() { clearDone <- m.Clear() }()

	select {
	case <-closing:
	case <-time.After(2 * time.Second):
		t.Fatal("owner never reached conn Close")
	}

	withdrawDone := make(chan error, 1)
	go func() { withdrawDone <- m.Withdraw() }()
	select {
	case <-withdrawDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Withdraw did not return")
	}

	close(releaseClose)

	var clearErr error
	select {
	case clearErr = <-clearDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Clear did not complete")
	}

	if g.attemptsFor("lo") == 0 {
		t.Fatal("no lifetime-0 write was attempted; the racing goodbye path " +
			"was not exercised, so the Clear assertion proves nothing")
	}
	if clearErr == nil {
		t.Fatal("Clear() returned nil although the goodbye claimed by a " +
			"racing Withdraw failed on every write — the #6777 constant-nil " +
			"shape in Clear (#17160)")
	}
	if m.owedCountForTest() == 0 {
		t.Fatal("no goodbye retry debt retained after Clear surfaced the " +
			"racing-goodbye failure; a later Apply has nothing to retry")
	}
}

// TestClearPureHardStopStaysNil17160 is the positive control: a pure Clear
// with no racing graceful Withdraw owes no goodbye, attempts none, and
// stays nil — the aggregation must not invent errors.
func TestClearPureHardStopStaysNil17160(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, true)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("pure Clear must stay nil, got %v", err)
	}
	if n := g.attemptsFor("lo"); n != 0 {
		t.Fatalf("pure Clear attempted %d lifetime-0 writes; it is the "+
			"no-goodbye primitive", n)
	}
}
