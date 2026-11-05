package configstore

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #18606: SyncApplyGated's gate sees the compiled peer config BEFORE anything
// is promoted, and a refusing gate leaves the store exactly as it was — the
// property the daemon's synced-path control-address refusal depends on (a
// refused text that still became active would be applied by every background
// applier). FAIL-ON-REVERT: run the gate after promotion and the active-text
// and history assertions red.
func TestSyncApplyGatedRefusalPromotesNothing18606(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name before; }\n", nil); err != nil {
		t.Fatalf("seed SyncApply: %v", err)
	}
	beforeText := s.ActiveTree().Format()
	beforeHistory := len(s.history.entries)
	refused := errors.New("refused by the gate")
	var seen *config.Config
	_, err := s.SyncApplyGated(context.Background(), "system { host-name after; }\n", nil,
		func(_ context.Context, c *config.Config) error {
			seen = c
			return refused
		})
	if !errors.Is(err, refused) {
		t.Fatalf("SyncApplyGated = %v, want the gate's error unchanged", err)
	}
	if seen == nil || seen.System.HostName != "after" {
		t.Fatalf("the gate did not see the compiled peer config (got %+v)", seen)
	}
	if got := s.ActiveTree().Format(); got != beforeText {
		t.Fatalf("a refusing gate changed the active config:\n%s", got)
	}
	if got := len(s.history.entries); got != beforeHistory {
		t.Fatalf("a refusing gate pushed rollback history: %d -> %d entries", beforeHistory, got)
	}
	// A passing gate behaves exactly like SyncApply.
	if _, err := s.SyncApplyGated(context.Background(), "system { host-name after; }\n", nil,
		func(_ context.Context, _ *config.Config) error { return nil }); err != nil {
		t.Fatalf("SyncApplyGated with a passing gate: %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "after" {
		t.Fatalf("a passing gate did not promote: host-name %q", got)
	}
}

// #16016: preparation must not clear a local-unshared mark or push rollback
// history before the final authority gate. The matching-content case exercises
// the deferred clear; the changed-content case exercises deferred history.
func TestSyncApplyGatedRefusalKeepsUnsharedState16016(t *testing.T) {
	s := newTestStore(t)
	enter9530(t, s)
	s.SetPeerReachableFn(func() bool { return true })
	markedText := commit9530(t, s, "local-unshared-16016")
	if s.unshared == nil {
		t.Fatal("test precondition: local commit did not create an unshared mark")
	}
	beforeActive := s.active.Format()
	beforeHistory := s.ListHistory()
	beforeCandidate := s.candidate.Format()
	beforeCandidateGen := s.candidateGen
	beforeActiveGen := s.activeGen.Load()
	beforeUnshared := *s.unshared
	beforeDiskMark, err := s.db.ReadUnshared()
	if err != nil || beforeDiskMark == nil {
		t.Fatalf("read persisted unshared mark: record=%+v err=%v", beforeDiskMark, err)
	}
	refused := errors.New("authority expired during final recheck")
	refuse := func(_ context.Context, _ *config.Config) error { return refused }

	if _, err := s.SyncApplyGated(context.Background(), markedText, nil, refuse); !errors.Is(err, refused) {
		t.Fatalf("matching-content SyncApplyGated = %v, want refusal", err)
	}
	if _, err := s.SyncApplyGated(context.Background(), "system { host-name peer-replacement-16016; }\n", nil, refuse); !errors.Is(err, refused) {
		t.Fatalf("changed-content SyncApplyGated = %v, want refusal", err)
	}
	if got := s.active.Format(); got != beforeActive {
		t.Fatalf("refused promotion changed active config:\n%s", got)
	}
	if !reflect.DeepEqual(s.ListHistory(), beforeHistory) {
		t.Fatalf("refused promotion changed rollback history: before=%+v after=%+v", beforeHistory, s.ListHistory())
	}
	if got := s.candidate.Format(); got != beforeCandidate || s.candidateGen != beforeCandidateGen {
		t.Fatalf("refused promotion changed candidate snapshot: text=%q gen=%d; want %q gen=%d",
			got, s.candidateGen, beforeCandidate, beforeCandidateGen)
	}
	if got := s.activeGen.Load(); got != beforeActiveGen {
		t.Fatalf("refused promotion published active generation %d; want unchanged %d", got, beforeActiveGen)
	}
	if s.unshared == nil || *s.unshared != beforeUnshared {
		t.Fatalf("refused promotion changed in-memory unshared mark: before=%+v after=%+v", beforeUnshared, s.unshared)
	}
	afterDiskMark, err := s.db.ReadUnshared()
	if err != nil || afterDiskMark == nil || !reflect.DeepEqual(afterDiskMark, beforeDiskMark) {
		t.Fatalf("refused promotion changed persisted unshared mark: before=%+v after=%+v err=%v", beforeDiskMark, afterDiskMark, err)
	}
	active := s.ActiveConfig()
	if active == nil || active.Chassis.Cluster != nil {
		t.Fatalf("refused promotion changed active cluster/PSK state: %+v", active)
	}
}

func TestSyncApplyClearsUnsharedAfterActivePromotion16016(t *testing.T) {
	restoreRollbackSeams(t)
	s := newTestStore(t)
	s.SetPeerReachableFn(func() bool { return true })
	enter9530(t, s)
	markedText := commit9530(t, s, "local-unshared-16016")
	if s.unshared == nil {
		t.Fatal("test setup did not create an unshared mark")
	}
	beforeGen, beforeCfg := s.ActiveSnapshot()
	if beforeCfg == nil || beforeCfg.System.HostName != "local-unshared-16016" {
		t.Fatalf("test setup active snapshot = (%d,%+v)", beforeGen, beforeCfg)
	}

	markPath := s.db.unsharedPath()
	removeEntered := make(chan struct{})
	releaseRemove := make(chan struct{})
	var releaseOnce sync.Once
	unblockRemove := func() {
		releaseOnce.Do(func() { close(releaseRemove) })
	}
	originalRemove := rbRemove
	rbRemove = func(path string) error {
		if path == markPath {
			close(removeEntered)
			<-releaseRemove
		}
		return originalRemove(path)
	}

	done := make(chan struct{})
	var applyErr error
	go func() {
		_, applyErr = s.SyncApplyGated(context.Background(), markedText, nil,
			func(context.Context, *config.Config) error { return nil })
		close(done)
	}()
	t.Cleanup(func() {
		unblockRemove()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SyncApplyGated did not finish after unshared deletion was released")
		}
	})

	select {
	case <-removeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("SyncApplyGated did not reach durable unshared deletion")
	}
	promotedGen, promotedCfg := s.ActiveSnapshot()
	if promotedGen != beforeGen+1 || promotedCfg == nil || promotedCfg.System.HostName != "local-unshared-16016" {
		t.Fatalf("active snapshot did not promote before unshared deletion: got (%d,%+v), want generation %d",
			promotedGen, promotedCfg, beforeGen+1)
	}

	unblockRemove()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SyncApplyGated did not finish after unshared deletion was released")
	}
	if applyErr != nil {
		t.Fatalf("SyncApplyGated: %v", applyErr)
	}
	if s.unshared != nil {
		t.Fatalf("promoted peer config retained in-memory unshared mark: %+v", s.unshared)
	}
	if record, err := s.db.ReadUnshared(); err != nil || record != nil {
		t.Fatalf("promoted peer config retained persisted unshared mark: record=%+v err=%v", record, err)
	}
}
