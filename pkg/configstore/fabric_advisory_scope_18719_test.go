package configstore

import (
	"strings"
	"testing"
)

// #18719: the #10105 fabric zone-stamp reminder is change-scoped on the
// operator commit path. It prints on the commit that adds or changes the
// fabric, not on later unrelated commits, and `commit check` reports it
// whenever its condition holds.

const fabricZoneStampMarker18719 = "fabric zone stamp (#10105)"

func hasWarning18719(warnings []string, marker string) bool {
	for _, w := range warnings {
		if strings.Contains(w, marker) {
			return true
		}
	}
	return false
}

func set18719(t *testing.T, s *Store, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
}

func commitWarnings18719(t *testing.T, s *Store) []string {
	t.Helper()
	compiled, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return compiled.Warnings
}

func TestCommitScopesFabricZoneStampReminder18719(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	set18719(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	)
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("the commit that adds the fabric must print the reminder; warnings=%v", w)
	}

	set18719(t, s, "system host-name unrelated-change")
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("an unrelated commit must not repeat the reminder; warnings=%v", w)
	}

	// commit check is not scoped: it reports the reminder while the fabric
	// is unattested, even though nothing about the fabric is staged.
	set18719(t, s, "system host-name another-unrelated-change")
	checked, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	if !hasWarning18719(checked.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("commit check must report the reminder; warnings=%v", checked.Warnings)
	}
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("the commit after the check is still unrelated; warnings=%v", w)
	}

	set18719(t, s, "chassis cluster fabric-peer-address 10.99.1.2")
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("a commit that changes the fabric must print the reminder; warnings=%v", w)
	}

	set18719(t, s, "chassis cluster fabric-interface-authenticated")
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("an attested fabric must not print the reminder; warnings=%v", w)
	}
	checked, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	if hasWarning18719(checked.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("commit check must not report an attested fabric; warnings=%v", checked.Warnings)
	}
}

// The commit-confirmed path compiles at its own site; it is scoped too.
func TestCommitConfirmedScopesFabricZoneStampReminder18719(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	set18719(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	)
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("precondition: the adding commit prints the reminder; warnings=%v", w)
	}
	set18719(t, s, "system host-name unrelated-change")
	compiled, err := s.CommitConfirmed(5)
	if err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	t.Cleanup(func() { _ = s.ConfirmCommit() })
	if hasWarning18719(compiled.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("an unrelated commit confirmed must not repeat the reminder; warnings=%v", compiled.Warnings)
	}
}

// #18751 review MINOR 1: a baseline the operator never saw does not scope.
// A node that booted from disk, took its config by config sync, or was
// auto-rolled back shows the reminder once on its first operator commit.

func committedFabricStore18719(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	enterCfg(t, s)
	set18719(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	)
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("precondition: the adding commit prints the reminder; warnings=%v", w)
	}
	return s
}

// unrelatedCommitsShowOnce18719 makes two unrelated operator commits: the
// first must print the reminder (unseen baseline), the second must not.
func unrelatedCommitsShowOnce18719(t *testing.T, s *Store, why string) {
	t.Helper()
	set18719(t, s, "system host-name after-"+why)
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("after %s the first operator commit must show the reminder once; warnings=%v", why, w)
	}
	set18719(t, s, "system host-name later-"+why)
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("after %s the reminder must show only once; warnings=%v", why, w)
	}
}

func TestBootLoadedBaselineShowsTheReminderOnce18719(t *testing.T) {
	s := committedFabricStore18719(t)
	restarted := newTestStoreAt(t, s.filePath)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	enterCfg(t, restarted)
	unrelatedCommitsShowOnce18719(t, restarted, "boot-load")
}

func TestSyncedBaselineShowsTheReminderOnce18719(t *testing.T) {
	s := committedFabricStore18719(t)
	content := s.active.Format()
	if _, err := s.SyncApply(content, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	unrelatedCommitsShowOnce18719(t, s, "config-sync")
}

func TestRolledBackBaselineShowsTheReminderOnce18719(t *testing.T) {
	s := committedFabricStore18719(t)
	set18719(t, s, "system host-name confirmed-change")
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if _, ok := s.PromoteRollback(s.ConfirmGenForTesting()); !ok {
		t.Fatal("premise: PromoteRollback must succeed")
	}
	unrelatedCommitsShowOnce18719(t, s, "auto-rollback")
}

// A DNS refresh republishes the compiled config without changing the
// operator's tree; it must not reset the baseline, or configs with DNS
// address books would see the reminder on every commit again.
func TestDNSRefreshKeepsTheBaseline18719(t *testing.T) {
	s := committedFabricStore18719(t)
	base := s.ActiveConfig()
	refreshed := *base
	if !s.PublishRefreshedDNS(base, &refreshed) {
		t.Fatal("premise: PublishRefreshedDNS must swap the compiled config")
	}
	set18719(t, s, "system host-name after-dns")
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("a DNS refresh must not make an unrelated commit repeat the reminder; warnings=%v", w)
	}
}

// The commit-confirmed site records the baseline too: after an unrelated
// commit confirmed and its confirmation, the next unrelated commit stays
// quiet. (The pass-3 mutation matrix showed no cell could see a missing
// record at the confirmed site.)
func TestCommitConfirmedRecordsTheBaseline18719(t *testing.T) {
	s := committedFabricStore18719(t)
	set18719(t, s, "system host-name confirmed-change")
	compiled, err := s.CommitConfirmed(5)
	if err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if hasWarning18719(compiled.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("precondition: the unrelated commit confirmed is quiet; warnings=%v", compiled.Warnings)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	set18719(t, s, "system host-name after-confirm")
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("after a confirmed commit the next unrelated commit must stay quiet; warnings=%v", w)
	}
}
