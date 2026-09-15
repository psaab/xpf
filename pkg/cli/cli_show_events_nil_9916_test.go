package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #9916 F-135 (display half, parent-review follow-up): the local CLI show path
// must skip a nil within clause, not panic. The compiler never produces nil, so
// the corruption is injected into the committed active config in-memory
// (test-only); failing closed in evaluate while crashing display on the same
// config would be incoherent defense-in-depth.
//
// NOTE (recorded asymmetry, out of F-135 scope): a nil POLICY entry itself still
// panics this loop at ep.Name, while evaluateEvent nil-guards pol. See the gRPC
// twin cell for the same note.
func TestShowEventOptionsSkipsNilClause9916(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
event-options {
    policy p9916 {
        events ping_test_failed;
        within 60 {
            trigger on 2;
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.EventOptions) != 1 {
		t.Fatalf("fixture did not commit exactly one event-options policy")
	}
	pol := cfg.EventOptions[0]
	if len(pol.WithinClauses) != 1 {
		t.Fatalf("precondition: want 1 compiled within clause, got %d", len(pol.WithinClauses))
	}
	pol.WithinClauses = append(pol.WithinClauses, nil)

	c := &CLI{store: store}
	out := captureStdout(t, func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("showEventOptions panicked on nil clause: %v (#9916 F-135)", r)
			}
		}()
		if err := c.showEventOptions(); err != nil {
			t.Fatalf("showEventOptions() error = %v", err)
		}
	})
	if !strings.Contains(out, "Policy: p9916") {
		t.Fatalf("policy header missing from show output %q", out)
	}
	if !strings.Contains(out, "Within: 60 seconds") {
		t.Fatalf("valid sibling clause missing from show output %q (over-suppression)", out)
	}
}
