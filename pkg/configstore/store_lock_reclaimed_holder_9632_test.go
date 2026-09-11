package configstore

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #9632: after an internal actor reclaims a stale lease, the previous holder's
// edits and commit used to pass the holder gate. The lock had no recorded
// holder, and #5059 lets a user session edit that state.

func reclaimedStore9632(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnterConfigureSession("remote-a"); err != nil {
		t.Fatalf("EnterConfigureSession(remote-a): %v", err)
	}
	if err := store.SetAs("remote-a", []string{"system", "host-name", "before-reclaim"}); err != nil {
		t.Fatalf("SetAs(remote-a) while holding: %v", err)
	}
	backdateConfigLock(t, store, configLockLeaseTTL+time.Minute)
	// The internal actor (event engine, daemon apply-commit, local CLI).
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("internal EnterConfigure should reclaim the stale lease: %v", err)
	}
	if holder, locked := store.ConfigHolder(); !locked || holder != "" {
		t.Fatalf("after the reclaim ConfigHolder() = (%q, %v), want the internal empty holder", holder, locked)
	}
	return store
}

func TestReclaimedSessionIsRefusedOnTheInternalCandidate9632(t *testing.T) {
	store := reclaimedStore9632(t)
	mutators := []struct {
		name string
		fn   func() error
	}{
		{"SetAs", func() error { return store.SetAs("remote-a", []string{"system", "host-name", "stale-edit"}) }},
		{"SetFromInputAs", func() error { return store.SetFromInputAs("remote-a", "system host-name stale-edit") }},
		{"DeleteAs", func() error { return store.DeleteAs("remote-a", []string{"system", "host-name"}) }},
		{"LoadMergeAs", func() error { return store.LoadMergeAs("remote-a", "set system host-name stale-edit") }},
		{"RollbackAs", func() error { return store.RollbackAs("remote-a", 0) }},
		{"AuthorizeCommit", func() error { _, e := store.AuthorizeCommit("remote-a"); return e }},
	}
	for _, m := range mutators {
		err := m.fn()
		if !errors.Is(err, ErrConfigLockedByOther) {
			t.Errorf("%s(reclaimed session) = %v, want ErrConfigLockedByOther", m.name, err)
			continue
		}
		if !strings.Contains(err.Error(), "reclaimed") {
			t.Errorf("%s: the refusal does not say the lock was reclaimed: %v", m.name, err)
		}
	}
	if cand := store.ShowCandidateSet(); strings.Contains(cand, "stale-edit") || strings.Contains(cand, "before-reclaim") {
		t.Fatalf("the reclaimed session's edits reached the internal candidate:\n%s", cand)
	}

	// Controls: the internal caller, and a session that never held the lock
	// (#5059: a user session may edit a local-CLI candidate), are still allowed.
	if err := store.SetAs("", []string{"system", "host-name", "internal"}); err != nil {
		t.Errorf("SetAs(internal) = %v, want nil", err)
	}
	if err := store.SetAs("remote-b", []string{"system", "host-name", "remote-b"}); err != nil {
		t.Errorf("SetAs(never-reclaimed session) = %v, want nil (#5059)", err)
	}
}

func TestReclaimedSessionIsAllowedAfterReEntering9632(t *testing.T) {
	for _, exclusive := range []bool{false, true} {
		t.Run(fmt.Sprintf("exclusive=%v", exclusive), func(t *testing.T) {
			store := reclaimedStore9632(t)
			store.ExitConfigure()
			var err error
			if exclusive {
				err = store.EnterConfigureExclusive("remote-a")
			} else {
				err = store.EnterConfigureSession("remote-a")
			}
			if err != nil {
				t.Fatalf("re-entering configure: %v", err)
			}
			if err := store.SetAs("remote-a", []string{"system", "host-name", "after-reentry"}); err != nil {
				t.Fatalf("SetAs after re-entering = %v, want nil", err)
			}
			if _, err := store.AuthorizeCommit("remote-a"); err != nil {
				t.Fatalf("AuthorizeCommit after re-entering = %v, want nil", err)
			}
			store.ExitConfigureSession("remote-a")
			// Once released and taken by the internal actor again, the session is
			// an ordinary never-reclaimed session (#5059), not a reclaimed one.
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.SetAs("remote-a", []string{"system", "host-name", "5059"}); err != nil {
				t.Fatalf("re-entered session editing a later internal candidate = %v, want nil", err)
			}
		})
	}
}

func TestReclaimedHoldersAreBounded9632(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for i := 0; i < 3*reclaimedHoldersCap; i++ {
		store.markReclaimedHolderLocked(fmt.Sprintf("s%d", i))
	}
	if n := len(store.reclaimedHolders); n > reclaimedHoldersCap {
		t.Fatalf("reclaimedHolders grew to %d, cap %d", n, reclaimedHoldersCap)
	}
	store.markReclaimedHolderLocked("")
	if _, ok := store.reclaimedHolders[""]; ok {
		t.Fatal("the internal empty holder must never be marked reclaimed")
	}
}
