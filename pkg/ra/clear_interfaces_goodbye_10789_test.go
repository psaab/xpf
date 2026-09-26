package ra

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestClearInterfacesWithoutGoodbyeStopsOnlyNamed10789(t *testing.T) {
	requireLo(t)
	fl := newFakeListen(t)
	m := New()
	cfg := testCfg("lo")
	if err := m.Apply([]*config.RAInterfaceConfig{cfg}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Cleanup(func() { _ = m.Clear() })
	waitFor(t, "lo sender", func() bool { return fl.getConn("lo") != nil })

	if err := m.ClearInterfacesWithoutGoodbye([]string{"unrelated"}); err != nil {
		t.Fatalf("ClearInterfacesWithoutGoodbye(unrelated): %v", err)
	}
	if got := len(m.Status()); got != 1 {
		t.Fatalf("clearing an unrelated interface stopped the live sender; status count=%d", got)
	}

	m.mu.Lock()
	m.recordGoodbyeDebtLocked("lo", cfg, errors.New("temporary goodbye failure"))
	m.mu.Unlock()
	if got := m.owedCountForTest(); got != 1 {
		t.Fatalf("test precondition: wanted one goodbye debt, got %d", got)
	}

	if err := m.ClearInterfacesWithoutGoodbye([]string{"lo", "lo"}); err != nil {
		t.Fatalf("ClearInterfacesWithoutGoodbye(lo): %v", err)
	}
	if got := len(m.Status()); got != 0 {
		t.Fatalf("ClearInterfacesWithoutGoodbye(lo) left %d sender statuses, want none", got)
	}
	if got := m.owedCountForTest(); got != 0 {
		t.Fatalf("silent stop retained goodbye retry debt: %d", got)
	}
	if writes, conns := fl.goodbyeStats("lo"); writes != 0 || conns != 0 {
		t.Fatalf("silent stop emitted goodbye writes=%d conns=%d", writes, conns)
	}

	// A concurrent graceful drain may finish after the silent stop. Its late
	// failure must not recreate retry debt that could withdraw the peer.
	m.mu.Lock()
	m.recordGoodbyeDebtLocked("lo", cfg, errors.New("late goodbye failure"))
	m.mu.Unlock()
	if got := m.owedCountForTest(); got != 0 {
		t.Fatalf("a late goodbye failure recreated suppressed debt: %d", got)
	}
	// Also prove a retry already selected by an earlier pass is dropped when
	// the silent-stop marker wins before retryOwedGoodbyes runs.
	m.mu.Lock()
	m.goodbyeOwed["lo"] = &goodbyeDebt{cfg: cfg, recordedEpoch: m.epoch}
	m.mu.Unlock()
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil) after silent stop: %v", err)
	}
	if got := m.owedCountForTest(); got != 0 {
		t.Fatalf("silent stop did not clear retry debt: %d", got)
	}
	if writes, conns := fl.goodbyeStats("lo"); writes != 0 || conns != 0 {
		t.Fatalf("retry after silent stop emitted goodbye writes=%d conns=%d", writes, conns)
	}
}

func TestClearInterfacesWithoutGoodbyeCancelsPendingRestart10789(t *testing.T) {
	requireLo(t)
	fl := newFakeListen(t)
	m := New()
	old, cfg, startEpoch := installRestartEntry(t, fl, m)
	defer func() {
		old.signalStop(modeHard)
		_ = m.Clear()
	}()

	if err := m.ClearInterfacesWithoutGoodbye([]string{"lo"}); err != nil {
		t.Fatalf("ClearInterfacesWithoutGoodbye(lo): %v", err)
	}
	started := false
	onProvenClose := func() error {
		started = true
		return m.startLocked(cfg)
	}
	if err := m.releaseDrain("lo", old, startEpoch, onProvenClose); err != nil {
		t.Fatalf("releaseDrain: %v", err)
	}
	if started {
		t.Fatal("ClearInterfacesWithoutGoodbye(lo) did not supersede the in-flight replacement")
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	_, draining := m.draining["lo"]
	m.mu.Unlock()
	if live || draining {
		t.Fatalf("silent clear left interface state live=%v draining=%v", live, draining)
	}
}
