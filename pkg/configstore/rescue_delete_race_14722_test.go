package configstore

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Scenario A: a save already past rescueWriteBarrier must not recreate
// rescue.conf after DeleteRescueConfig has succeeded. The delete is
// issued while the save is deterministically held at the barrier; the
// test asserts the delete completes (does not deadlock on the held
// save) and that releasing the save leaves no file behind.
func TestDeleteRescueConfigDoesNotResurrectInFlightSave_14722(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name rescue-race-14722; }", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	// Materialize a rescue.conf so delete has something to unlink even
	// before the in-flight save lands.
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("initial SaveRescueConfig: %v", err)
	}
	rescuePath := s.rescuePath()
	if _, err := os.Stat(rescuePath); err != nil {
		t.Fatalf("rescue.conf must exist after initial save: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWriter := func() { releaseOnce.Do(func() { close(release) }) }
	var startedOnce sync.Once
	oldBarrier := rescueWriteBarrier
	rescueWriteBarrier = func() {
		startedOnce.Do(func() { close(started) })
		<-release
	}
	defer func() {
		rescueWriteBarrier = oldBarrier
		releaseWriter()
	}()

	saveDone := make(chan error, 1)
	go func() { saveDone <- s.SaveRescueConfig() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight save did not reach rescueWriteBarrier")
	}

	// Delete must succeed while the save is held at the barrier. On
	// unfixed code it returns nil immediately and the later save
	// rename resurrects the file; a fix that simply blocks delete
	// behind rescueMu until the save finishes would deadlock here,
	// so run it with a timeout.
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- s.DeleteRescueConfig() }()
	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("DeleteRescueConfig during in-flight save: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseWriter()
		t.Fatal("DeleteRescueConfig blocked behind in-flight save (deadlock with held barrier)")
	}
	if _, err := os.Stat(rescuePath); !os.IsNotExist(err) {
		t.Fatalf("rescue.conf still present immediately after delete: stat err=%v", err)
	}

	releaseWriter()
	select {
	case err := <-saveDone:
		if !errors.Is(err, ErrRescueSaveSuperseded) {
			t.Fatalf("in-flight save after delete = %v, want ErrRescueSaveSuperseded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight save did not finish after release")
	}
	if _, err := os.Stat(rescuePath); !os.IsNotExist(err) {
		t.Fatalf("rescue.conf was resurrected by in-flight save after DeleteRescueConfig succeeded (stat err=%v)", err)
	}

	// Control: a save STARTED after the delete must legitimately
	// recreate rescue.conf — only in-flight-at-delete saves are
	// superseded.
	rescueWriteBarrier = oldBarrier
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig after delete: %v", err)
	}
	if _, err := os.Stat(rescuePath); err != nil {
		t.Fatalf("save started after delete must recreate rescue.conf: %v", err)
	}
}

// TestSaveRescueConfigNewestWins_14722 pins D18-05 Scenario B: when an
// older save is held at the barrier and a newer save completes first,
// releasing the older save must not overwrite the newer content.
func TestSaveRescueConfigNewestWins_14722(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name old-14722; }", nil); err != nil {
		t.Fatalf("SyncApply old: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWriter := func() { releaseOnce.Do(func() { close(release) }) }
	var startedOnce sync.Once
	oldBarrier := rescueWriteBarrier
	rescueWriteBarrier = func() {
		startedOnce.Do(func() { close(started) })
		<-release
	}
	defer func() {
		rescueWriteBarrier = oldBarrier
		releaseWriter()
	}()

	oldDone := make(chan error, 1)
	go func() { oldDone <- s.SaveRescueConfig() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("old save did not reach rescueWriteBarrier")
	}

	// Rotate the active config and save again; this newer save must win.
	if _, err := s.SyncApply("system { host-name new-14722; }", nil); err != nil {
		t.Fatalf("SyncApply new: %v", err)
	}
	// The newer save must not block behind the held older save's
	// barrier: temporarily install a pass-through barrier.
	rescueWriteBarrier = func() {}
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("newer SaveRescueConfig: %v", err)
	}
	rescuePath := s.rescuePath()
	data, err := os.ReadFile(rescuePath)
	if err != nil {
		t.Fatalf("read rescue.conf after newer save: %v", err)
	}
	if got := string(data); !strings.Contains(got, "new-14722") {
		t.Fatalf("newer save content missing before releasing old save: %q", got)
	}

	releaseWriter()
	select {
	case err := <-oldDone:
		if !errors.Is(err, ErrRescueSaveSuperseded) {
			t.Fatalf("older save after newer save = %v, want ErrRescueSaveSuperseded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("older save did not finish after release")
	}
	data, err = os.ReadFile(rescuePath)
	if err != nil {
		t.Fatalf("read rescue.conf after older save released: %v", err)
	}
	if got := string(data); !strings.Contains(got, "new-14722") || strings.Contains(got, "old-14722") {
		t.Fatalf("stale older save overwrote newer rescue.conf: %q", got)
	}
}
