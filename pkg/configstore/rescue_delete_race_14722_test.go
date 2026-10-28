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

// TestDeleteRescueConfigDoesNotUnlinkLaterSave_16783 pins the reverse
// ordering of #14722: a save that STARTS after a delete claims a later
// generation and must not be unlinked by that delete. The delete is
// deterministically paused inside its rbRemove seam — after it has
// claimed its generation and bumped the applied generation, before
// the unlink lands — while a later save runs. Before the fix the
// delete released rescueMu before unlinking, so the later save took
// rescueMu, wrote durably, reported success, and was then unlinked
// by the paused delete, leaving no rescue.conf. With the fix, a later
// save either applies after the delete's critical section, or applies
// first and causes the delete to skip its unlink (#17825). In both
// orders, a save that reports success leaves its file.
func TestDeleteRescueConfigDoesNotUnlinkLaterSave_16783(t *testing.T) {
	restoreRollbackSeams(t)
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name before-delete-16783; }", nil); err != nil {
		t.Fatalf("SyncApply before-delete: %v", err)
	}
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("initial SaveRescueConfig: %v", err)
	}
	rescuePath := s.rescuePath()
	if _, err := os.Stat(rescuePath); err != nil {
		t.Fatalf("rescue.conf must exist after initial save: %v", err)
	}
	if _, err := s.SyncApply("system { host-name later-save-16783; }", nil); err != nil {
		t.Fatalf("SyncApply later-save: %v", err)
	}

	// Pause the delete inside rbRemove: its generation is already
	// claimed/applied, but the unlink has not landed.
	removeEntered := make(chan struct{})
	releaseRemove := make(chan struct{})
	var removeOnce, releaseOnce sync.Once
	releaseRemoveFn := func() { releaseOnce.Do(func() { close(releaseRemove) }) }
	defer releaseRemoveFn()
	origRemove := rbRemove
	rbRemove = func(path string) error {
		removeOnce.Do(func() { close(removeEntered) })
		<-releaseRemove
		return origRemove(path)
	}

	deleteDone := make(chan error, 1)
	go func() { deleteDone <- s.DeleteRescueConfig() }()
	select {
	case <-removeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not reach rbRemove")
	}

	saveDone := make(chan error, 1)
	go func() { saveDone <- s.SaveRescueConfig() }()

	// Give a broken implementation the chance to complete the later
	// save inside the delete's paused window. On fixed code the save
	// blocks on rescueMu; the short wait only schedules it, the
	// assertions below do not depend on it having blocked.
	select {
	case err := <-saveDone:
		// The save completed while the delete was paused between
		// its generation bump and its unlink (the pre-fix window).
		// Release the delete; its unlink must not remove the file
		// this successful save just wrote.
		if err != nil {
			releaseRemoveFn()
			<-deleteDone
			t.Fatalf("later save during paused delete = %v, want success", err)
		}
		releaseRemoveFn()
		if err := <-deleteDone; err != nil {
			t.Fatalf("DeleteRescueConfig: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		// Fixed shape: the later save is still blocked behind the
		// delete's rescueMu. Release the delete, then the save.
		releaseRemoveFn()
		if err := <-deleteDone; err != nil {
			t.Fatalf("DeleteRescueConfig: %v", err)
		}
		select {
		case err := <-saveDone:
			if err != nil {
				t.Fatalf("later SaveRescueConfig after delete: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("later save did not finish after delete released rescueMu")
		}
	}

	data, err := os.ReadFile(rescuePath)
	if err != nil {
		t.Fatalf("rescue.conf missing after later save reported success: %v", err)
	}
	if got := string(data); !strings.Contains(got, "later-save-16783") {
		t.Fatalf("rescue.conf = %q, want the later save's content", got)
	}
}

// TestDeleteRescueConfigSkipsNewerSave_17825 covers the claim-to-lock
// interleaving missed by #16783: the delete claims generation N, a save
// claims and applies N+1 while the delete is paused before rescueMu, then
// the delete must not unlink the newer rescue.conf.
func TestDeleteRescueConfigSkipsNewerSave_17825(t *testing.T) {
	restoreRollbackSeams(t)
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name before-delete-17825; }", nil); err != nil {
		t.Fatalf("SyncApply before-delete: %v", err)
	}
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("initial SaveRescueConfig: %v", err)
	}
	rescuePath := s.rescuePath()
	if _, err := os.Stat(rescuePath); err != nil {
		t.Fatalf("rescue.conf must exist after initial save: %v", err)
	}

	claimEntered := make(chan struct{})
	releaseClaim := make(chan struct{})
	var claimOnce, releaseOnce sync.Once
	releaseDelete := func() { releaseOnce.Do(func() { close(releaseClaim) }) }
	oldBarrier := rescueDeleteClaimBarrier
	t.Cleanup(func() { rescueDeleteClaimBarrier = oldBarrier })
	rescueDeleteClaimBarrier = func() {
		claimOnce.Do(func() { close(claimEntered) })
		<-releaseClaim
	}
	defer releaseDelete()

	deleteDone := make(chan error, 1)
	go func() { deleteDone <- s.DeleteRescueConfig() }()
	select {
	case <-claimEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not pause after claiming its generation")
	}

	if _, err := s.SyncApply("system { host-name newer-save-17825; }", nil); err != nil {
		t.Fatalf("SyncApply newer save: %v", err)
	}
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("newer SaveRescueConfig: %v", err)
	}
	data, err := os.ReadFile(rescuePath)
	if err != nil {
		t.Fatalf("read rescue.conf after newer save: %v", err)
	}
	if got := string(data); !strings.Contains(got, "newer-save-17825") {
		t.Fatalf("newer save content missing before delete resumes: %q", got)
	}

	releaseDelete()
	var deleteErr error
	select {
	case deleteErr = <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("DeleteRescueConfig did not finish after releasing claim barrier")
	}
	data, err = os.ReadFile(rescuePath)
	if err != nil {
		t.Fatalf("rescue.conf missing after stale delete resumed: %v", err)
	}
	if got := string(data); !strings.Contains(got, "newer-save-17825") {
		t.Fatalf("stale delete replaced newer rescue.conf: %q", got)
	}
	if !errors.Is(deleteErr, ErrRescueDeleteSuperseded) {
		t.Fatalf("DeleteRescueConfig error = %v, want ErrRescueDeleteSuperseded", deleteErr)
	}
}

var errInjectedRescueUnlink = errors.New("injected rescue unlink failure")

// TestFailedNewerRescueDeleteDoesNotSupersedeOlderDelete_18358 pins the
// Rev18358Task-2 finding on PR #18358: DeleteRescueConfig must advance
// rescueAppliedGen only after its unlink and dir sync succeed. An older
// delete claims generation N and pauses before rescueMu; a newer delete
// claims N+1 and fails its unlink (injected). The failed attempt must not
// advance rescueAppliedGen, so the older delete proceeds rather than
// reporting ErrRescueDeleteSuperseded.
func TestFailedNewerRescueDeleteDoesNotSupersedeOlderDelete_18358(t *testing.T) {
	restoreRollbackSeams(t)
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name before-delete-18358; }", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("initial SaveRescueConfig: %v", err)
	}
	rescuePath := s.rescuePath()

	failUnlink := true
	origRemove := rbRemove
	rbRemove = func(path string) error {
		if failUnlink && path == rescuePath {
			return errInjectedRescueUnlink
		}
		return origRemove(path)
	}
	t.Cleanup(func() { rbRemove = origRemove })

	appliedBefore := rescueAppliedGenForTest(s)
	olderClaimed := make(chan struct{})
	releaseOlder := make(chan struct{})
	releaseOnce := sync.Once{}
	releaseOlderFn := func() { releaseOnce.Do(func() { close(releaseOlder) }) }
	var claimCount int
	var claimMu sync.Mutex
	oldBarrier := rescueDeleteClaimBarrier
	t.Cleanup(func() { rescueDeleteClaimBarrier = oldBarrier })
	rescueDeleteClaimBarrier = func() {
		claimMu.Lock()
		claimCount++
		first := claimCount == 1
		claimMu.Unlock()
		if first {
			close(olderClaimed)
			<-releaseOlder
		}
	}
	defer releaseOlderFn()

	olderDone := make(chan error, 1)
	go func() { olderDone <- s.DeleteRescueConfig() }()
	select {
	case <-olderClaimed:
	case <-time.After(2 * time.Second):
		t.Fatal("older delete did not claim its generation")
	}

	// The newer delete claims the next generation and runs while the older
	// delete is held before rescueMu.
	newerDone := make(chan error, 1)
	go func() { newerDone <- s.DeleteRescueConfig() }()
	select {
	case err := <-newerDone:
		if !errors.Is(err, errInjectedRescueUnlink) {
			t.Fatalf("newer DeleteRescueConfig error = %v, want injected unlink failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("newer delete did not finish")
	}
	if _, err := os.Stat(rescuePath); err != nil {
		t.Fatalf("rescue.conf must survive a failed delete: %v", err)
	}
	loaded, err := s.LoadRescueConfig()
	if err != nil || !strings.Contains(loaded, "before-delete-18358") {
		t.Fatalf("rescue.conf must remain loadable after failed delete: loaded=%q err=%v", loaded, err)
	}
	if got := rescueAppliedGenForTest(s); got != appliedBefore {
		t.Errorf("rescueAppliedGen after failed newer delete = %d, want unchanged %d", got, appliedBefore)
	}

	// Disable the injected failure; the older delete must now apply
	// successfully instead of being superseded by the failed try.
	failUnlink = false
	releaseOlderFn()
	select {
	case err := <-olderDone:
		if errors.Is(err, ErrRescueDeleteSuperseded) {
			t.Fatalf("older delete superseded by FAILED newer delete")
		}
		if err != nil {
			t.Fatalf("older DeleteRescueConfig: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("older delete did not finish")
	}
	if _, err := os.Stat(rescuePath); !os.IsNotExist(err) {
		t.Fatalf("rescue.conf must be removed by the older delete: stat err=%v", err)
	}
}

func rescueAppliedGenForTest(s *Store) uint64 {
	s.rescueMu.Lock()
	defer s.rescueMu.Unlock()
	return s.rescueAppliedGen
}
