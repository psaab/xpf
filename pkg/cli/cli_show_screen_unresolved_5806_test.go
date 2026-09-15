package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// danglingScreenRefStore reaches the #5806 state through the genuine TOLERANT
// LOAD path: strict commit REJECTS a zone whose screen profile is undefined, so
// a valid config is committed, the persisted active.json is externally modified
// so the profile DEFINITION no longer parses (the `ids-option` path token occurs
// exactly once and is renamed) while the zone's REFERENCE survives, and a fresh
// store re-Loads it. Mirrors the pkg/api fixture; see that file for the full
// rationale.
func danglingScreenRefStore(t *testing.T) *configstore.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	store, err := configstore.New(path)
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } } }
security {
    screen { ids-option alpha { icmp { ping-death; } } }
    zones { security-zone trust { screen alpha; interfaces { ge-0/0/0.0; } } }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	dbPath := filepath.Join(dir, ".configdb", "active.json")
	rawBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read persisted db: %v", err)
	}
	raw := string(rawBytes)
	if n := strings.Count(raw, "ids-option"); n != 1 {
		t.Fatalf("fixture assumption broken: %q occurs %d times, want 1", "ids-option", n)
	}
	mutated := strings.Replace(raw, "ids-option", "ids-optionz", 1)
	// #9898 F-035: the mutation is deliberate test surgery on a
	// digest-stamped envelope; strip the tamper-evidence field so the
	// reload exercises the legacy-accept path (see the twin fixture in
	// pkg/api/metrics_screen_unresolved_5806_test.go).
	if i := strings.Index(mutated, " body-sha256="); i >= 0 {
		nl := strings.IndexByte(mutated[i:], '\n')
		if nl < 0 {
			t.Fatalf("fixture broken: stamped header has no newline")
		}
		mutated = mutated[:i] + mutated[i+nl:]
	}
	if err := os.WriteFile(dbPath, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write mutated db: %v", err)
	}
	reloaded, err := configstore.New(path)
	if err != nil {
		t.Fatalf("configstore.New (reload): %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("tolerant Load: %v", err)
	}
	if reloaded.ActiveConfig() == nil {
		t.Fatal("tolerant Load produced a nil active config")
	}
	return reloaded
}

// TestShowScreenLocalCLIReportsUnresolvedReference is the #5806 fail-on-revert
// guard for the LOCAL-CLI renderer.
//
// The unresolved-reference block was added to both `show security screen`
// renderers, but only the gRPC one had a test — deleting the local-CLI emit
// passed the entire suite. This binds it, through the real tolerant-load path
// rather than a hand-built config, so it also exercises `c.store.ActiveConfig()`.
//
// RED on revert, measured at the same three placements as the gRPC peer rather
// than asserted (#6839 round 3 — the round-2 claim that deleting the loop makes
// "every assertion here fails" is not what happens: no assertion runs at all,
// because the package stops compiling):
//
//   - DELETE the loop from cli_show_security_screen.go → rc=1, but from the
//     COMPILER, not from here: `dpuserspace` becomes an unused import, and the
//     run reports 0 `--- FAIL`. Worth naming, because a build failure is not
//     this guard firing, and if any other reference to that package is ever
//     added to that file the deletion becomes invisible to it.
//   - MOVE it AFTER the empty-inventory early return (so the empty-Screen case
//     skips it) → rc=1 here, on the heading assertion. This is the placement
//     the original claim described.
//   - MOVE it INSIDE the early-return branch, AFTER the "No screen profiles
//     configured" line → rc=0 on ./pkg/cli/ AND rc=0 across all four packages
//     before round 3. Every assertion below was structural-within-the-block or
//     `strings.Contains`, and neither can see position relative to a line this
//     test never mentioned, so the operator read "nothing was configured" first
//     and the correction after it. The shared ordering check at the end closes
//     that third placement.
func TestShowScreenLocalCLIReportsUnresolvedReference(t *testing.T) {
	c := &CLI{store: danglingScreenRefStore(t)}
	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})

	// Assert STRUCTURE, not token containment. Checking that "trust" and "alpha"
	// merely appear anywhere would pass on a renderer that printed them in an
	// unrelated section, or that emitted the heading with no rows under it.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	const heading = "Unresolved screen profile references:"
	hIdx := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == heading {
			hIdx = i
			break
		}
	}
	if hIdx < 0 {
		t.Fatalf("local CLI must emit the %q heading; got:\n%s", heading, out)
	}
	// Exactly one row, and it must be the line immediately under the heading, so
	// the zone/profile are ASSOCIATED with it rather than floating elsewhere.
	var rows []string
	for _, l := range lines[hIdx+1:] {
		if strings.HasPrefix(l, "  Zone ") {
			rows = append(rows, l)
			continue
		}
		if strings.HasPrefix(l, "  Disposition: ") {
			break
		}
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one unresolved row under the heading, got %d: %v", len(rows), rows)
	}
	if !strings.Contains(rows[0], "trust") || !strings.Contains(rows[0], "alpha") {
		t.Fatalf("the row must name the zone AND the profile it references; got %q", rows[0])
	}
	// The disposition is ONE trailing line, after the rows.
	dispCount := 0
	for _, l := range lines[hIdx+1:] {
		if strings.HasPrefix(l, "  Disposition: ") {
			dispCount++
		}
	}
	if dispCount != 1 {
		t.Fatalf("disposition must appear exactly once after the rows, got %d", dispCount)
	}
	// The shared disposition string, so the CLI, the gRPC block and the metric
	// HELP cannot drift into describing the behaviour differently.
	if !strings.Contains(out, dpuserspace.ScreenUnresolvedDisposition) {
		t.Fatalf("local CLI must carry the shared disposition string; got:\n%s", out)
	}
	if !strings.Contains(out, "policy evaluation is unaffected") {
		t.Errorf("disposition must not read as a permit; got:\n%s", out)
	}
	// ORDER (#6839 round 3). Everything above asserts structure INSIDE the block
	// or containment, and neither can see where the block sits relative to
	// "No screen profiles configured" — the line this renderer prints two
	// statements later, and the one whose "nothing was asked for" reading the
	// block exists to correct. The check is SHARED with the gRPC guard, not
	// re-typed: both renderers ship one contract, so a divergence between two
	// copies of its assertion is always a bug rather than a legitimate
	// difference.
	if err := dpuserspace.CheckScreenUnresolvedRenderOrder(out); err != nil {
		t.Errorf("local CLI showScreen: %v", err)
	}
}

// TestShowScreenLocalCLISilentWhenResolved is the negative control: the block
// must not render for a healthy config, so the guard above cannot pass by the
// renderer emitting it unconditionally.
func TestShowScreenLocalCLISilentWhenResolved(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } } }
security {
    screen { ids-option alpha { icmp { ping-death; } } }
    zones { security-zone trust { screen alpha; interfaces { ge-0/0/0.0; } } }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})
	if strings.Contains(out, "Unresolved screen profile references") {
		t.Fatalf("a resolved reference must not render the unresolved block; got:\n%s", out)
	}
	// Absence alone is the failure default — an aborted or empty render also
	// contains no heading. Require the healthy inventory to actually be there, so
	// this test cannot pass on a renderer that emitted nothing at all.
	if !strings.Contains(out, "Screen profile: alpha") {
		t.Fatalf("the resolved profile inventory must still render (absence of the "+
			"unresolved heading is only meaningful if something WAS rendered); got:\n%s", out)
	}
	if !strings.Contains(out, "trust") {
		t.Errorf("the zone using the resolved profile must still be listed; got:\n%s", out)
	}
}
