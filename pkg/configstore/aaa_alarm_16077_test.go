package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16077 (MGMT-16): a leniently-loaded AAA tree (legacy persisted or
// peer-synced, #1960 no-brick) must carry its unsupported-AAA marker on
// the active compiled config so alarm surfaces keep listing it across
// daemon restarts until the stanza is removed — and must drop it once
// a clean tree replaces it. Pre-fix the marker did not exist and the
// warning died with the boot-time log loop.

const aaaTree16077 = `system {
    host-name fw-aaa;
    radius-server 192.0.2.10 {
        secret aaa-secret-16077;
    }
    tacplus-server 192.0.2.20 {
        secret aaa-secret-16077;
    }
}`

func assertAAAAlarm16077(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg == nil {
		t.Fatal("no active config")
	}
	alarms := config.UnimplementedAAAWarnings(cfg)
	if len(alarms) != 2 {
		t.Fatalf("active AAA alarms = %v, want radius-server+tacplus-server", alarms)
	}
	joined := strings.Join(alarms, "\n")
	for _, want := range []string{"radius-server", "tacplus-server", "local-only authentication"} {
		if !strings.Contains(joined, want) {
			t.Errorf("AAA alarms missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "aaa-secret-16077") {
		t.Fatalf("AAA alarm leaked the secret:\n%s", joined)
	}
}

func TestAAAAlarmSurvivesRestart16077(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if _, err := store.SyncApply(aaaTree16077, nil); err != nil {
		t.Fatalf("tolerant SyncApply must not brick on AAA tree (#1960): %v", err)
	}
	assertAAAAlarm16077(t, store.ActiveConfig())

	// Restart: a fresh Store over the same persisted config recompiles
	// leniently at Load, so the marker (and the alarm) is rebuilt.
	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	assertAAAAlarm16077(t, restarted.ActiveConfig())

	// Removing the stanza clears the alarm: the new compile has no marker.
	if _, err := restarted.SyncApply("system { host-name fw-aaa; }", nil); err != nil {
		t.Fatalf("clean SyncApply: %v", err)
	}
	if got := config.UnimplementedAAAWarnings(restarted.ActiveConfig()); len(got) != 0 {
		t.Fatalf("clean config still alarmed: %v", got)
	}

	// Restart again on the clean tree: still no alarm.
	restarted2 := newTestStoreAt(t, path)
	if err := restarted2.Load(); err != nil {
		t.Fatalf("clean restart Load: %v", err)
	}
	if got := config.UnimplementedAAAWarnings(restarted2.ActiveConfig()); len(got) != 0 {
		t.Fatalf("clean restarted config still alarmed: %v", got)
	}
}
