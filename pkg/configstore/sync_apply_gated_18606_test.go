package configstore

import (
	"bytes"
	"context"
	"errors"
	"os"
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

// #16016: expiry at the last promotion gate rejects both branches of
// classification without changing any observable or persisted store state.
// FAIL-ON-REVERT: the prepared-state seam must run before the gate; moving
// authority recheck ahead of classification/history preparation makes this
// cell fail even though the refusal still leaves the Store untouched.
func TestSyncApplyGatedCutoffPreservesPreparedState16016(t *testing.T) {
	for _, tc := range []struct {
		name              string
		incoming           func(string) string
		wantClear          bool
		wantDivergence     bool
		wantHistory        bool
	}{
		{name: "matching-content", incoming: func(marked string) string { return marked }, wantClear: true},
		{name: "changed-content", incoming: func(string) string {
			return "system { host-name peer-replacement-16016; }\n"
		}, wantDivergence: true, wantHistory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			enter9530(t, s)
			s.SetPeerReachableFn(func() bool { return true })
			markedText := commit9530(t, s, "local-unshared-cutoff-16016")
			if s.unshared == nil {
				t.Fatal("test precondition: local commit did not create an unshared mark")
			}

			type historyState struct {
				format    string
				timestamp time.Time
			}
			historyStateOf := func() []historyState {
				entries := s.ListHistory()
				got := make([]historyState, len(entries))
				for i, entry := range entries {
					if entry != nil && entry.Config != nil {
						got[i].format = entry.Config.Format()
						got[i].timestamp = entry.Timestamp
					}
				}
				return got
			}
			markPath := s.db.unsharedPath()
			beforeUnsharedBytes, err := os.ReadFile(markPath)
			if err != nil {
				t.Fatalf("read persisted unshared mark: %v", err)
			}
			beforeActive := s.ShowActive()
			beforeHistory := historyStateOf()
			beforeCandidate := s.ShowCandidate()
			beforeCandidateGen := s.CandidateGeneration()
			beforeActiveGen := s.activeGen.Load()
			beforeUnshared := *s.unshared
			prepared := false
			classificationAndHistoryPrepared := false
			s.syncApplyPreparedForTesting = func(classification syncClassification, historyEntry *HistoryEntry) {
				prepared = true
				classificationAndHistoryPrepared =
					classification.clearUnshared == tc.wantClear &&
						(classification.divergence != nil) == tc.wantDivergence &&
						(historyEntry != nil) == tc.wantHistory
				if tc.wantHistory {
					classificationAndHistoryPrepared = classificationAndHistoryPrepared &&
						historyEntry.Config != nil && historyEntry.Config.Format() == beforeActive
				}
			}
			refused := errors.New("authority expired at final gate")
			expired := false
			gateSawPrepared := false
			gate := func(_ context.Context, _ *config.Config) error {
				gateSawPrepared = prepared && classificationAndHistoryPrepared
				expired = true
				return refused
			}
			_, err = s.SyncApplyGated(context.Background(), tc.incoming(markedText), nil, gate)
			if !expired {
				t.Fatal("promotion gate did not simulate authority expiry")
			}
			if !prepared || !gateSawPrepared {
				t.Fatalf("final gate did not observe prepared classification/history (observed=%t prepared=%t divergence=%t history=%t)",
					prepared, classificationAndHistoryPrepared, tc.wantDivergence, tc.wantHistory)
			}
			if !errors.Is(err, refused) {
				t.Fatalf("SyncApplyGated = %v, want final-gate refusal", err)
			}
			if got := s.ShowActive(); got != beforeActive {
				t.Fatalf("refusal changed active text: before=%q after=%q", beforeActive, got)
			}
			if got := historyStateOf(); !reflect.DeepEqual(got, beforeHistory) {
				t.Fatalf("refusal changed rollback history: before=%+v after=%+v", beforeHistory, got)
			}
			if got, gen := s.ShowCandidate(), s.CandidateGeneration(); got != beforeCandidate || gen != beforeCandidateGen {
				t.Fatalf("refusal changed candidate: before=(%q,%d) after=(%q,%d)",
					beforeCandidate, beforeCandidateGen, got, gen)
			}
			if got := s.activeGen.Load(); got != beforeActiveGen {
				t.Fatalf("refusal changed active generation: before=%d after=%d", beforeActiveGen, got)
			}
			if s.unshared == nil || !reflect.DeepEqual(*s.unshared, beforeUnshared) {
				t.Fatalf("refusal changed in-memory unshared mark: before=%+v after=%+v", beforeUnshared, s.unshared)
			}
			afterUnsharedBytes, err := os.ReadFile(markPath)
			if err != nil {
				t.Fatalf("read persisted unshared mark after refusal: %v", err)
			}
			if !bytes.Equal(afterUnsharedBytes, beforeUnsharedBytes) {
				t.Fatalf("refusal changed raw unshared.json bytes: before=%q after=%q", beforeUnsharedBytes, afterUnsharedBytes)
			}
		})
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
