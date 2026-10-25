package configstore

import (
	"strings"
	"testing"
)

// #16721: `show system commit history` numbered rows oldest-first from
// 0, so row label k was the reverse of `rollback k`; confirmations
// wrote no journal row; and no <rollback pending> marker existed.
//
// RED on revert: restoring the oldest-first loop-index rendering (or
// dropping ListCommitHistoryRows' slot assignment / the commit_confirm
// journal writes) makes the label, confirm-row, and pending assertions
// below fail.

// commitHost16721 stages and commits a host-name change with a
// description, the probe's per-generation marker.
func commitHost16721(t *testing.T, s *Store, host, desc string) {
	t.Helper()
	if err := s.SetFromInput("system host-name " + host); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescription(desc); err != nil {
		t.Fatal(err)
	}
}

// slotOf16721 returns the rendered rollback slot for the row whose
// Detail == desc, or -2 when absent.
func slotOf16721(rows []CommitHistoryRow, desc string) int {
	for _, r := range rows {
		if r.Entry.Detail == desc {
			return r.RollbackSlot
		}
	}
	return -2
}

func TestCommitHistoryRollbackSlotLabels16721(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Four generations: set-one..set-four (probe shape from the issue).
	commitHost16721(t, s, "one", "set-one")
	commitHost16721(t, s, "two", "set-two")
	commitHost16721(t, s, "three", "set-three")
	commitHost16721(t, s, "four", "set-four")

	rows, err := s.ListCommitHistoryRows(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	// Labels name the config generation `rollback k` restores: the
	// live commit (set-four, tree "four") is 0 = active; rollback 1
	// restores "three", the tree set-three produced, so set-three is
	// labelled 1; rollback 2 restores "two" (set-two, label 2);
	// rollback 3 restores "one" (set-one, label 3).
	wantSlots := map[string]int{"set-one": 3, "set-two": 2, "set-three": 1, "set-four": 0}
	for desc, want := range wantSlots {
		if got := slotOf16721(rows, desc); got != want {
			t.Errorf("slot(%q) = %d, want %d", desc, got, want)
		}
	}

	// Acceptance: row label k names the commit that `rollback k`
	// restores. rollback k stages that commit's own promoted tree:
	// label 1 = set-three, so rollback 1 stages host "three".
	byLabel := map[int]string{0: "set-four", 1: "set-three", 2: "set-two", 3: "set-one"}
	treeOf := map[string]string{"set-one": "one", "set-two": "two", "set-three": "three", "set-four": "four"}
	for k := 1; k <= 3; k++ {
		if err := s.Rollback(k); err != nil {
			t.Fatalf("rollback %d: %v", k, err)
		}
		staged := s.ShowCandidate()
		labelled := byLabel[k]
		if want := "host-name " + treeOf[labelled]; !strings.Contains(staged, want) {
			t.Errorf("rollback %d staged %q; commit labelled %d is %q, want its tree %q restored", k, staged, k, labelled, want)
		}
		if err := s.Rollback(0); err != nil {
			t.Fatal(err)
		}
	}

	// Rendered form: most-recent-first, label 0 on the newest row.
	out := RenderCommitHistory(rows, false)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("rendered lines = %d, want 4: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "set-four") || !strings.HasPrefix(lines[0], "   0  ") {
		t.Errorf("first rendered row must be slot 0 / set-four, got %q", lines[0])
	}
	if !strings.Contains(lines[3], "set-one") || !strings.HasPrefix(lines[3], "   3  ") {
		t.Errorf("last rendered row must be slot 3 / set-one, got %q", lines[3])
	}
}

func TestCommitConfirmJournaledWithPrincipal16721(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost16721(t, s, "base", "base-commit")
	if err := s.SetFromInput("system host-name confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	defer s.CancelConfirmTimerForTesting()
	if !s.IsConfirmPending() {
		t.Fatal("premise: window must be pending")
	}

	// While pending, the renderer shows <rollback pending> and the
	// commit_confirmed row carries NO rollback slot of its own beyond
	// the positional one (it did push history, so it is the live slot 0).
	rows, err := s.ListCommitHistoryRows(50)
	if err != nil {
		t.Fatal(err)
	}
	if out := RenderCommitHistory(rows, s.IsConfirmPending()); !strings.Contains(out, "<rollback pending>") {
		t.Errorf("pending render missing <rollback pending>: %q", out)
	}

	const principal = "source=peer-uid;uid=1001;user=ops;class=super-user;session=abcd"
	if err := s.ConfirmCommitPrincipalAs("", principal); err != nil {
		t.Fatalf("ConfirmCommitPrincipalAs: %v", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("confirm must clear the window")
	}

	rows, err = s.ListCommitHistoryRows(50)
	if err != nil {
		t.Fatal(err)
	}
	var confirm *JournalEntry
	for _, r := range rows {
		if r.Entry.Action == "commit_confirm" {
			confirm = r.Entry
			if r.RollbackSlot != -1 {
				t.Errorf("commit_confirm row got rollback slot %d, want none (-1)", r.RollbackSlot)
			}
		}
	}
	if confirm == nil {
		t.Fatalf("no commit_confirm journal row in %+v", rows)
	}
	if confirm.Principal != principal {
		t.Errorf("commit_confirm principal = %q, want %q", confirm.Principal, principal)
	}
	if confirm.ConfigHash == "" {
		t.Error("commit_confirm row must carry the active config hash")
	}
	// After confirmation the pending marker is gone.
	if out := RenderCommitHistory(rows, s.IsConfirmPending()); strings.Contains(out, "<rollback pending>") {
		t.Errorf("confirmed render still shows <rollback pending>: %q", out)
	}
	// commit_confirm appears in ListCommitHistory too.
	entries, err := s.ListCommitHistory(50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "commit_confirm" {
			found = true
		}
	}
	if !found {
		t.Error("ListCommitHistory must include commit_confirm rows")
	}
}

// Plain commit and demotion are confirmation paths too (#16721: "every
// confirmation path").
func TestCommitConfirmJournaledOnPlainCommitAndDemotion16721(t *testing.T) {
	confirmPrincipals := func(t *testing.T, s *Store) []string {
		t.Helper()
		rows, err := s.ListCommitHistoryRows(50)
		if err != nil {
			t.Fatal(err)
		}
		var ps []string
		for _, r := range rows {
			if r.Entry.Action == "commit_confirm" {
				ps = append(ps, r.Entry.Principal)
			}
		}
		return ps
	}

	// Plain commit during a pending window.
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost16721(t, s, "base", "base")
	if err := s.SetFromInput("system host-name conf"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	defer s.CancelConfirmTimerForTesting()
	if err := s.SetFromInput("system host-name next"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescriptionAs("user:plain", "next"); err != nil {
		t.Fatal(err)
	}
	if ps := confirmPrincipals(t, s); len(ps) != 1 || ps[0] != "user:plain" {
		t.Errorf("plain-commit confirm principals = %v, want [user:plain]", ps)
	}

	// Demotion.
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost16721(t, s2, "base", "base")
	if err := s2.SetFromInput("system host-name conf"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	defer s2.CancelConfirmTimerForTesting()
	if !s2.ConfirmPendingOnDemotion() {
		t.Fatal("demotion must confirm the window")
	}
	if ps := confirmPrincipals(t, s2); len(ps) != 1 || ps[0] != "system:rg-demotion" {
		t.Errorf("demotion confirm principals = %v, want [system:rg-demotion]", ps)
	}

	// No pending window: no spurious confirm row.
	s3 := newTestStore(t)
	if err := s3.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost16721(t, s3, "only", "only")
	if ps := confirmPrincipals(t, s3); len(ps) != 0 {
		t.Errorf("no-window confirm principals = %v, want none", ps)
	}
}

// Interleaved non-slot rows (auto_rollback) must not shift slot labels.
func TestCommitHistorySlotSkipsAutoRollback16721(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost16721(t, s, "one", "set-one")
	if err := s.SetFromInput("system host-name two"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfirmGenForTesting()
	s.performAutoRollback(gen) // journals auto_rollback, reverts to "one"
	if got := s.ActiveConfig().System.HostName; got != "one" {
		t.Fatalf("premise: auto-rollback must revert to one, got %q", got)
	}
	commitHost16721(t, s, "three", "set-three")

	rows, err := s.ListCommitHistoryRows(50)
	if err != nil {
		t.Fatal(err)
	}
	// Labels name the restored generation: set-three is live (0).
	// rollback 1 restores "one" — the tree set-one produced (the
	// confirmed commit's tree was reverted away), so set-one is
	// labelled 1; the rolled-back commit_confirmed row itself gets
	// no label (its tree exists in no slot).
	if got := slotOf16721(rows, "set-three"); got != 0 {
		t.Errorf("slot(set-three) = %d, want 0", got)
	}
	if got := slotOf16721(rows, "set-one"); got != 1 {
		t.Errorf("slot(set-one) = %d, want 1", got)
	}
	for _, r := range rows {
		if r.Entry.Action == "auto_rollback" && r.RollbackSlot != -1 {
			t.Errorf("auto_rollback row got slot %d, want -1", r.RollbackSlot)
		}
		if r.Entry.Action == "commit_confirmed" && r.RollbackSlot != -1 {
			t.Errorf("rolled-back commit_confirmed row got label %d, want -1", r.RollbackSlot)
		}
	}
	out := RenderCommitHistory(rows, false)
	// auto_rollback row renders with a blank label.
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.Contains(line, "auto_rollback") && !strings.HasPrefix(line, "     ") {
			t.Errorf("auto_rollback row must have blank label, got %q", line)
		}
	}
}
