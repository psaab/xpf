package refactoraudit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// acceptedEntryLOC is deliberately the byte-0x0a count used by
// scripts/refactoring-audit-lib.sh:audit_loc. In particular, a final line
// without a newline is not counted, and CRLF contributes one line.
func acceptedEntryLOC(content []byte) int {
	return bytes.Count(content, []byte{'\n'})
}

// acceptedEntryViolations is the tree-global half of the accepted-entry
// contract. It must fail closed for a missing path: audit_is_audited_path is
// intentionally pattern-only, and the touched-file probe's [ -f ] skip is
// correct for its changed-set question but would silently revive a stale
// acknowledgement here. This assumes a full checkout; sparse or partial
// checkouts intentionally fail closed when an accepted path is absent.
func acceptedEntryViolations(root string, accepted []acceptedCrossing) []string {
	var violations []string
	for _, a := range accepted {
		floor, ok := map[string]int{
			tierWatch:    auditFloor,
			tierRefactor: refactorFloor,
		}[a.tier]
		if !ok {
			violations = append(violations, fmt.Sprintf("%s %s: unknown tier", a.tier, a.path))
			continue
		}

		path := filepath.Join(root, a.path)
		content, err := os.ReadFile(path)
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s %s: cannot read %s: %v", a.tier, a.path, path, err))
			continue
		}
		loc := acceptedEntryLOC(content)
		if loc >= floor {
			continue
		}

		repair := "prune the entry"
		if a.tier == tierRefactor && loc >= auditFloor {
			repair = "demote it to [WATCH] or prune the entry"
		}
		violations = append(violations, fmt.Sprintf(
			"%s %s: %d LOC is below its %d LOC floor; %s",
			a.tier, a.path, loc, floor, repair))
	}
	return violations
}

func TestAcceptedEntriesAreLive(t *testing.T) {
	root := repoRoot(t)
	accepted := readAccepted(t, root)
	if violations := acceptedEntryViolations(root, accepted); len(violations) != 0 {
		t.Fatalf("accepted entries below their live floors:\n  %s", strings.Join(violations, "\n  "))
	}
}

func TestAcceptedEntryFloorBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		tier       string
		loc        int
		wantLive   bool
		wantText   string
		forbidText string
	}{
		{name: "watch just below", tier: tierWatch, loc: 1499, wantText: "prune the entry", forbidText: "demote"},
		{name: "watch at floor", tier: tierWatch, loc: 1500, wantLive: true},
		{name: "watch just above", tier: tierWatch, loc: 1501, wantLive: true},
		{name: "watch above refactor floor", tier: tierWatch, loc: 2001, wantLive: true},
		{name: "refactor below watch floor", tier: tierRefactor, loc: 1499, wantText: "prune the entry", forbidText: "demote"},
		{name: "refactor at watch floor", tier: tierRefactor, loc: 1500, wantText: "demote it to [WATCH] or prune the entry"},
		{name: "refactor just above watch floor", tier: tierRefactor, loc: 1501, wantText: "demote it to [WATCH] or prune the entry"},
		{name: "refactor just below", tier: tierRefactor, loc: 1999, wantText: "demote it to [WATCH] or prune the entry"},
		{name: "refactor at floor", tier: tierRefactor, loc: 2000, wantLive: true},
		{name: "refactor just above", tier: tierRefactor, loc: 2001, wantLive: true},
		{name: "unknown tier", tier: "[UNKNOWN]", loc: 1, wantText: "unknown tier"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "pkg", "fixture.go")
			writeAcceptedFixture(t, path, tt.loc)
			accepted := []acceptedCrossing{{tier: tt.tier, path: "pkg/fixture.go", reason: "boundary fixture"}}
			violations := acceptedEntryViolations(root, accepted)
			if tt.wantLive {
				if len(violations) != 0 {
					t.Fatalf("at-floor entry unexpectedly failed: %v", violations)
				}
				return
			}
			if len(violations) != 1 {
				t.Fatalf("boundary entry got violations %v, want one", violations)
			}
			if tt.wantText != "" && !strings.Contains(violations[0], tt.wantText) {
				t.Fatalf("boundary violation %q lacks required text %q", violations[0], tt.wantText)
			}
			if tt.forbidText != "" && strings.Contains(violations[0], tt.forbidText) {
				t.Fatalf("boundary violation %q contains forbidden text %q", violations[0], tt.forbidText)
			}
		})
	}
}

func TestAcceptedEntryReaddFails(t *testing.T) {
	root := t.TempDir()
	writeAcceptedFixture(t, filepath.Join(root, "pkg", "api", "metrics_userspace.go"), 529)
	writeAcceptedFixture(t, filepath.Join(root, "pkg", "vrrp", "instance.go"), 825)

	accepted := parseAccepted(t, "re-add fixture", strings.Join([]string{
		"[REFACTOR] pkg/api/metrics_userspace.go old crossing decision",
		"[WATCH] pkg/vrrp/instance.go old crossing decision",
	}, "\n"))
	violations := acceptedEntryViolations(root, accepted)
	if len(violations) != 2 {
		t.Fatalf("re-adding the two pruned entries produced %d violations, want 2: %v", len(violations), violations)
	}
	wantViolations := []string{
		"[REFACTOR] pkg/api/metrics_userspace.go: 529 LOC is below its 2000 LOC floor; prune the entry",
		"[WATCH] pkg/vrrp/instance.go: 825 LOC is below its 1500 LOC floor; prune the entry",
	}
	for _, want := range wantViolations {
		found := false
		for _, violation := range violations {
			if violation == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("re-added entry did not produce exact tier/LOC violation %q: %v", want, violations)
		}
	}

	if violations := acceptedEntryViolations(root, nil); len(violations) != 0 {
		t.Fatalf("removing both re-added entries remained red: %v", violations)
	}
}

func TestAcceptedDeletedPathFailsClosed(t *testing.T) {
	const path = "pkg/deleted_10487.go"
	root := t.TempDir()
	accepted := []acceptedCrossing{{tier: tierWatch, path: path, reason: "deleted fixture"}}

	classifierRoot := repoRoot(t)
	out := runScript(t, classifierRoot, "scripts/refactoring-audit-classify.sh", "audited", path)
	if got := strings.TrimSpace(out); got != "AUDITED "+path {
		t.Fatalf("classifier changed the expected pattern-only result: got %q", got)
	}
	violations := acceptedEntryViolations(root, accepted)
	if len(violations) != 1 || !strings.Contains(violations[0], "cannot read") {
		t.Fatalf("missing accepted path got violations %v, want one cannot-read failure", violations)
	}

	oldPath := "pkg/renamed_10487.go"
	oldFile := filepath.Join(root, oldPath)
	writeAcceptedFixture(t, oldFile, 1500)
	if err := os.Rename(oldFile, filepath.Join(root, "pkg", "renamed_10487_new.go")); err != nil {
		t.Fatalf("rename fixture: %v", err)
	}
	violations = acceptedEntryViolations(root, []acceptedCrossing{{tier: tierWatch, path: oldPath, reason: "renamed fixture"}})
	if len(violations) != 1 || !strings.Contains(violations[0], "cannot read") {
		t.Fatalf("renamed accepted path got violations %v, want one cannot-read failure", violations)
	}
}

func TestGoLocMatchesAuditLoc(t *testing.T) {
	root := repoRoot(t)
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "newline terminated", body: "a\nb\n", want: 2},
		{name: "unterminated final line", body: "a\nb", want: 1},
		{name: "crlf", body: "a\r\nb\r\n", want: 2},
		{name: "empty", body: "", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "loc_fixture.go")
			content := []byte(tt.body)
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			gotGo := acceptedEntryLOC(content)
			if gotGo != tt.want {
				t.Fatalf("Go count got %d, want %d", gotGo, tt.want)
			}
			out := runScript(t, root, "scripts/refactoring-audit-classify.sh", "loc", path)
			gotShell := strings.TrimSpace(out)
			if gotShell != fmt.Sprint(gotGo) {
				t.Fatalf("Go count %d disagrees with classify.sh loc %q", gotGo, gotShell)
			}
		})
	}
}

func writeAcceptedFixture(t *testing.T, path string, loc int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x\n", loc)), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
