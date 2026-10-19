package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15272 B24-03/B24-04: path-scoped compare printed the global diff
// (local) / was rejected (remote), and reference-value completion read
// the active config, offering candidate-deleted names and hiding
// candidate-created ones. RED on master: scoped compare leaked the
// system host-name hunk and completion offered oldzone only.

// TestScopedCompareAndCandidateCompletion15272 drives the real
// handleConfigShow and completion entry points.
func TestScopedCompareAndCandidateCompletion15272(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer store.ExitConfigure()
	for _, cmd := range []string{
		"security zones security-zone oldzone",
		"system host-name before15272",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	// Candidate: rename zone oldzone->newzone (delete+set) and change hostname.
	if err := store.DeleteFromInput("security zones security-zone oldzone"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("security zones security-zone newzone"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name after15272"); err != nil {
		t.Fatal(err)
	}

	c := &CLI{store: store}
	// Scoped compare: only security hunk.
	out := captureStdout(t, func() { _ = c.handleConfigShow([]string{"security", "|", "compare"}) })
	if !strings.Contains(out, "newzone") {
		t.Errorf("scoped compare missing newzone:\n%s", out)
	}
	if strings.Contains(out, "after15272") || strings.Contains(out, "host-name") {
		t.Errorf("scoped compare leaked global hunk:\n%s", out)
	}
	// Edit-path scoped compare.
	store.SetEditPath([]string{"security"})
	out2 := captureStdout(t, func() { _ = c.handleConfigShow([]string{"|", "compare"}) })
	if !strings.Contains(out2, "newzone") || strings.Contains(out2, "after15272") {
		t.Errorf("editpath scoped compare wrong:\n%s", out2)
	}
	store.SetEditPath(nil)
	// Global compare control: both hunks.
	out3 := captureStdout(t, func() { _ = c.handleConfigShow([]string{"|", "compare"}) })
	if !strings.Contains(out3, "newzone") || !strings.Contains(out3, "after15272") {
		t.Errorf("global compare missing hunks:\n%s", out3)
	}
	// Scoped rollback compare: rollback 1 is the first commit (oldzone,
	// before15272); scoped to security it must not leak the host-name hunk.
	out4 := captureStdout(t, func() { _ = c.handleConfigShow([]string{"security", "|", "compare", "rollback", "1"}) })
	if !strings.Contains(out4, "newzone") || strings.Contains(out4, "after15272") || strings.Contains(out4, "host-name") {
		t.Errorf("scoped rollback compare wrong:\n%s", out4)
	}
	// Unchanged scoped subtree renders [no changes].
	out5 := captureStdout(t, func() { _ = c.handleConfigShow([]string{"interfaces", "|", "compare"}) })
	if out5 != "[no changes]\n" {
		t.Errorf("unchanged scoped compare = %q, want [no changes]", out5)
	}
	// B24-04: candidate completion offers newzone not oldzone.
	cands := c.completeConfigWithDesc([]string{"set", "security", "policies", "from-zone"}, "")
	names := map[string]bool{}
	for _, cand := range cands {
		names[cand.name] = true
	}
	if !names["newzone"] {
		t.Errorf("candidate completion missing newzone: %v", names)
	}
	if names["oldzone"] {
		t.Errorf("candidate completion still offers deleted oldzone: %v", names)
	}
	// Direct valueProvider check.
	vp := c.valueProvider(config.ValueHintZoneName, []string{"security", "zones", "security-zone"})
	vnames := map[string]bool{}
	for _, v := range vp {
		vnames[v.Name] = true
	}
	if !vnames["newzone"] || vnames["oldzone"] {
		t.Errorf("valueProvider zones = %v, want newzone only", vnames)
	}
}
