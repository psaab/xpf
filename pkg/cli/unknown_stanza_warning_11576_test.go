package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestUnknownTopLevelStanzaWarningReachesAlarmSurfaces11576(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "unknown-stanza.conf"))
	const typo = `securty { zones { security-zone z1; } }`
	if _, err := store.SyncApply(typo, nil); err != nil {
		t.Fatalf("tolerant SyncApply must not brick on unknown top-level stanza: %v", err)
	}
	cfg := store.ActiveConfig()
	warnings := config.ToleratedUnknownTopLevelStanzaWarnings(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "securty") {
		t.Fatalf("active unknown-stanza warnings = %v, want one warning naming securty", warnings)
	}

	c := &CLI{store: store}
	system := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms: %v", err)
		}
	})
	if !strings.Contains(system, warnings[0]) {
		t.Fatalf("show system alarms omitted unknown-stanza warning %q:\n%s", warnings[0], system)
	}

	security := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail: %v", err)
		}
	})
	if !strings.Contains(security, warnings[0]) {
		t.Fatalf("show security alarms detail omitted unknown-stanza warning %q:\n%s", warnings[0], security)
	}
}
