package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestShowPolicyOptionsDisplaysBothConflictingActions11780(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(`policy-options { policy-statement p1 { term t1 { then { accept; next policy; } } } }`, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	c := &CLI{store: store}
	var showErr error
	out := captureStdout(t, func() {
		showErr = c.handleShow([]string{"policy-options"})
	})
	if showErr != nil {
		t.Fatalf("show policy-options: %v", showErr)
	}
	for _, want := range []string{"then next policy", "then accept"} {
		if !strings.Contains(out, want) {
			t.Errorf("show policy-options output missing %q:\n%s", want, out)
		}
	}
}
