package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14413 (DR13-H7) CLI twin: `show event-options` must not print an embedded
// live credential verbatim, while non-secret commands render in full and the
// stored ThenCommands stay raw for the event engine.
func TestShowEventOptionsRedactsEmbeddedPSK14413CLI(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands "set security ike policy p1 pre-shared-key ascii-text PSK-DISTINCTIVE-7Q";
                commands "set system host-name foo";
                commands "set system login user bob class operator";
            }
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

	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showEventOptions(); err != nil {
			t.Fatalf("showEventOptions() error = %v", err)
		}
	})
	if strings.Contains(out, "PSK-DISTINCTIVE-7Q") {
		t.Errorf("CLI show event-options leaked embedded PSK verbatim:\n%s", out)
	}
	if !strings.Contains(out, config.SecretDataPlaceholder) {
		t.Errorf("CLI show event-options did not render %s placeholder:\n%s", config.SecretDataPlaceholder, out)
	}
	for _, control := range []string{"set system host-name foo", "set system login user bob class operator"} {
		if !strings.Contains(out, control) {
			t.Errorf("CLI show event-options dropped non-secret control %q:\n%s", control, out)
		}
	}
	if !strings.Contains(strings.Join(cfg.EventOptions[0].ThenCommands, "\n"), "PSK-DISTINCTIVE-7Q") {
		t.Errorf("stored ThenCommands were mutated by display: %q", cfg.EventOptions[0].ThenCommands)
	}
}
