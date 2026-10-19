package configstore

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15142: the #9530 divergence alarm was process-memory only and the
// unshared mark was durably deleted before the replacement config was
// durable. Both probe cells: (1) restart after a successful heal lost
// the alarm; (2) a failed writeActive + restart lost mark and alarm.

// Cell 1: heal succeeds, then a restart must still surface the alarm.
func TestDivergenceSurvivesRestartAfterHeal_15142(t *testing.T) {
	c0 := winnerConfig9530(t)
	path := filepath.Join(t.TempDir(), "config")
	reachable := true
	node1 := nodeOne9530(t, path, c0, &reachable)
	reachable = false
	tightened := commit9530(t, node1, "tightened")

	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	if _, _, ok := node1.ConfigSyncDivergence(); !ok {
		t.Fatalf("setup: no divergence recorded after heal")
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	div, _, ok := restarted.ConfigSyncDivergence()
	if !ok {
		t.Fatalf("#15142: a restart after the heal lost the divergence alarm; " +
			"the discarded partition commit is silent again")
	}
	if div.DiscardedDigest != configTextDigest(tightened) || div.AdoptedDigest != configTextDigest(c0) {
		t.Errorf("restored divergence digests discarded=%s adopted=%s, want %s/%s",
			div.DiscardedDigest, div.AdoptedDigest, configTextDigest(tightened), configTextDigest(c0))
	}
	if restarted.ConfigSyncDivergenceAlarm() == "" {
		t.Errorf("restored divergence produced no alarm line")
	}
}

// Cell 2: writeActive fails during the heal sync (degrade-not-fail), then
// a restart before the retry heals must not lose the mark or the alarm.
func TestDivergenceWriteFailureKeepsMarkAndAlarmAfterRestart_15142(t *testing.T) {
	c0 := winnerConfig9530(t)
	path := filepath.Join(t.TempDir(), "config")
	reachable := true
	node1 := nodeOne9530(t, path, c0, &reachable)
	node1.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	reachable = false
	tightened := commit9530(t, node1, "tightened")

	node1.SetClusterReadOnly(true)
	node1.SetWriteActiveForTesting(failingWriteActive)
	sync9530(t, node1, c0) // degrade-not-fail: returns nil despite disk failure
	if _, _, ok := node1.ConfigSyncDivergence(); !ok {
		t.Fatalf("setup: no divergence recorded after failed-persist heal")
	}
	// The mark must NOT be durably deleted yet: replacement is not durable.
	if rec, err := node1.db.ReadUnshared(); err != nil || rec == nil {
		t.Fatalf("#15142: unshared mark deleted before replacement was durable (rec=%v err=%v)", rec, err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	div, _, ok := restarted.ConfigSyncDivergence()
	if !ok {
		t.Fatalf("#15142: restart after a failed-persist heal lost the divergence alarm")
	}
	if div.DiscardedDigest != configTextDigest(tightened) {
		t.Errorf("restored divergence discarded=%s, want %s", div.DiscardedDigest, configTextDigest(tightened))
	}
	// Mark also survives the restart, so a re-sync can re-raise if needed.
	if rec, err := restarted.db.ReadUnshared(); err != nil || rec == nil {
		t.Errorf("#15142: unshared mark lost across restart before heal (rec=%v err=%v)", rec, err)
	}
}

// Retry-heal cell (see below).
// Retry-heal: once the persist retry lands the replacement durably,
// the record is reduced to its bare form (Digest == adopted), the
// persisted alarm remains, and it survives a restart.
func TestDivergenceMarkDeletedAfterRetryHeal_15142(t *testing.T) {
	c0 := winnerConfig9530(t)
	path := filepath.Join(t.TempDir(), "config")
	reachable := true
	node1 := nodeOne9530(t, path, c0, &reachable)
	node1.SetPersistRetryBackoffForTesting(5*time.Millisecond, 5*time.Millisecond)
	reachable = false
	commit9530(t, node1, "tightened")

	var fail atomic.Bool
	fail.Store(true)
	node1.SetWriteActiveForTesting(func(tree *config.ConfigTree) error {
		if fail.Load() {
			return errDiskFull
		}
		return node1.db.WriteActive(tree)
	})
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	if rec, err := node1.db.ReadUnshared(); err != nil || rec == nil || rec.Discarded == nil {
		t.Fatalf("#15142: mark deleted before durable replacement (rec=%v err=%v)", rec, err)
	}
	fail.Store(false)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec, _ := node1.db.ReadUnshared(); rec != nil && rec.Digest == rec.Discarded.AdoptedDigest {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec, _ := node1.db.ReadUnshared()
	if rec == nil || rec.Discarded == nil || rec.Digest != rec.Discarded.AdoptedDigest {
		t.Fatalf("#15142: record not reduced to bare alarm form after retry heal: %+v", rec)
	}
	if _, _, ok := node1.ConfigSyncDivergence(); !ok {
		t.Errorf("divergence alarm lost after retry heal")
	}
	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, _, ok := restarted.ConfigSyncDivergence(); !ok {
		t.Errorf("#15142: divergence alarm lost on restart after retry heal")
	}
}

// Control: a divergence cleared by a later different config must not be
// resurrected by a restart (persisted clear, not just in-memory).
func TestDivergenceClearSurvivesRestart_15142(t *testing.T) {
	c0 := winnerConfig9530(t)
	path := filepath.Join(t.TempDir(), "config")
	reachable := true
	node1 := nodeOne9530(t, path, c0, &reachable)
	reachable = false
	commit9530(t, node1, "tightened")
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	if _, _, ok := node1.ConfigSyncDivergence(); !ok {
		t.Fatalf("setup: no divergence")
	}
	node0 := newTestStore(t)
	enter9530(t, node0)
	commit9530(t, node0, "c0")
	c1 := commit9530(t, node0, "c1-recommitted")
	sync9530(t, node1, c1)
	if _, _, ok := node1.ConfigSyncDivergence(); ok {
		t.Fatalf("setup: divergence not cleared by different config")
	}
	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, _, ok := restarted.ConfigSyncDivergence(); ok {
		t.Errorf("#15142: cleared divergence was resurrected by a restart")
	}
}
