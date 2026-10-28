package vrrp

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type forceRGMasterLogBarrier17827 struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *forceRGMasterLogBarrier17827) Enabled(context.Context, slog.Level) bool { return true }
func (h *forceRGMasterLogBarrier17827) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "vrrp: forcing MASTER (cluster authoritative)" {
		h.once.Do(func() { close(h.entered) })
		<-h.release
	}
	return nil
}
func (h *forceRGMasterLogBarrier17827) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *forceRGMasterLogBarrier17827) WithGroup(string) slog.Handler      { return h }

// TestForceRGMasterStaleAcrossResignation17827 drives the real manager path.
// A Force sampled as BACKUP must not leave a one-shot flag/token that can be
// consumed in the fresh BACKUP tenure after MASTER entry and forced resignation.
func TestForceRGMasterStaleAcrossResignation17827(t *testing.T) {
	vi, eventCh := newStaleTokenInstance16766(t)
	adverts := capturePriorities16766(t)
	vi.setState(StateBackup)

	m := NewManager()
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{{iface: "eth0", groupID: 101}: vi}
	m.mu.Unlock()

	barrier := &forceRGMasterLogBarrier17827{entered: make(chan struct{}), release: make(chan struct{})}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(barrier))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	t.Cleanup(func() {
		select {
		case <-barrier.release:
		default:
			close(barrier.release)
		}
	})

	forceDone := make(chan struct{})
	go func() {
		m.ForceRGMaster(1) // RG 1 -> VRID 101
		close(forceDone)
	}()
	select {
	case <-barrier.entered:
	case <-time.After(time.Second):
		t.Fatal("ForceRGMaster did not reach the force log barrier")
	}

	// On the old three-operation path this barrier is after getState(BACKUP)
	// and before the flag write/enqueue. Cross all MASTER-entry/resignation
	// drains before allowing that stale force to continue.
	masterDown, advert, preemptHold := longTimers(t)
	if !vi.becomeMaster() {
		t.Fatal("becomeMaster returned false")
	}
	vi.beginResign()
	vi.triggerResign()
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on forced resignation")
	}
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after forced resignation = %s, want BACKUP", got)
	}

	close(barrier.release)
	select {
	case <-forceDone:
	case <-time.After(time.Second):
		t.Fatal("ForceRGMaster did not finish after log barrier release")
	}
	_ = drainAdverts16766(adverts)
	_ = drainEvents16766(eventCh)

	runStepBackup16766(t, vi, masterDown, advert, preemptHold)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("stale pre-resignation ForceRGMaster re-promoted instance: state=%s priority=%d adverts=%v events=%v", got, vi.getPriority(), drainAdverts16766(adverts), drainEvents16766(eventCh))
	}
	if extra := drainAdverts16766(adverts); len(extra) != 0 {
		t.Fatalf("stale force emitted adverts after resignation: %v", extra)
	}
	for _, state := range drainEvents16766(eventCh) {
		if state == StateMaster {
			t.Fatal("stale ForceRGMaster emitted a MASTER event after resignation")
		}
	}
}
