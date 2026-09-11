package configstore

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #9625: the #9014 arm-write retry ran exactly once. persistRetryLoop's top
// check includes confirmArmDegraded but its bottom exit did not, so a retry that
// failed a SECOND time, with no other debt owed, returned with the debt still
// standing. Health then stayed degraded for the rest of the window, and nothing
// was left to write the record. TestArmWriteDebtSelfHeals9014 fails the write
// only once, so the first retry succeeds and that exit is never reached with arm
// debt outstanding, which is why the suite was green.
func TestArmWriteRetryOutlivesASecondFailure9625(t *testing.T) {
	s := newTestStore(t)
	var fail atomic.Bool
	failConfirmArm(t, &fail)
	var attempts atomic.Int32
	inner := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(path) == "confirm.json" {
			attempts.Add(1)
		}
		return inner(path, data, perm, opts...)
	}
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)

	fail.Store(true)
	if err := s.SetFromInput("system host-name armtwice"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	base := attempts.Load()
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	// The arm plus at least three retries while the fault persists. Before the
	// fix the count stopped at 2 (the arm and one retry) and never moved again.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && attempts.Load()-base < 4 {
		time.Sleep(5 * time.Millisecond)
	}
	if n := attempts.Load() - base; n < 4 {
		t.Fatalf("only %d confirm.json write attempts while the fault persisted: the retry "+
			"loop exited with the arm-write debt still owed (#9625)", n)
	}

	fail.Store(false) // the fault outlasted two retries, and now clears
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("the arm-write debt did not heal after the fault cleared (#9625)")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("health cleared but the confirm record was not written: rec=%v err=%v", rec, err)
	}
	// With nothing owed, the loop must end rather than spin.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		active := s.persistRetryActive
		s.mu.Unlock()
		if !active {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	active, armDebt := s.persistRetryActive, s.confirmArmDegraded
	s.mu.Unlock()
	if active || armDebt {
		t.Errorf("after the heal: persistRetryActive=%v confirmArmDegraded=%v, want both false", active, armDebt)
	}
}
