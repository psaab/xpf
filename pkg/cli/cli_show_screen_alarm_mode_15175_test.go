package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15175 (B18-04): a profile whose every check is log-only
// (alarm-without-drop) rendered identically to a drop-enforcing one on
// `show security screen`, `ids-option <p>` and `ids-option <p> detail`.
// The two arms below differ only in that leaf, so any output difference
// is the mode surface; the control arm pins that legit drop profiles are
// unchanged (no mode line, plain `enabled`).
//
// RED on base: no renderer emits "alarm-without-drop" or "alarm-only".

func alarmScreenCLI(t *testing.T, audit bool) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	leaf := ""
	if audit {
		leaf = "            alarm-without-drop;\n"
	}
	body := `
security {
    zones { security-zone untrust { screen p; } }
    screen { ids-option p {
` + leaf + `            tcp { land; }
    } }
}
`
	if err := store.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Security.Screen["p"] == nil || cfg.Security.Screen["p"].AlarmWithoutDrop != audit {
		t.Fatalf("fixture AlarmWithoutDrop=%v not compiled (cfg=%+v)", audit, cfg)
	}
	return &CLI{store: store}
}

func TestCLIScreenAlarmWithoutDrop15175(t *testing.T) {
	views := map[string]func(c *CLI) error{
		"show security screen":                   func(c *CLI) error { return c.showScreen() },
		"show security screen ids-option":        func(c *CLI) error { return c.showScreenIdsOption("p") },
		"show security screen ids-option detail": func(c *CLI) error { return c.showScreenIdsOptionDetail("p") },
	}
	for name, run := range views {
		auditOut := captureStdout(t, func() {
			if err := run(alarmScreenCLI(t, true)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		dropOut := captureStdout(t, func() {
			if err := run(alarmScreenCLI(t, false)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		if !strings.Contains(auditOut, "Mode: alarm-without-drop") || !strings.Contains(auditOut, "nothing is dropped") {
			t.Errorf("%s: audit arm missing mode line:\n%s", name, auditOut)
		}
		if strings.Contains(dropOut, "alarm-without-drop") || strings.Contains(dropOut, "alarm-only") {
			t.Errorf("%s: drop arm must not claim audit mode:\n%s", name, dropOut)
		}
		if name != "show security screen" {
			if !strings.Contains(auditOut, "alarm-only") {
				t.Errorf("%s: audit arm Value must be alarm-only:\n%s", name, auditOut)
			}
			if !strings.Contains(dropOut, "enabled") || strings.Contains(dropOut, "alarm-only") {
				t.Errorf("%s: drop arm Value must stay enabled:\n%s", name, dropOut)
			}
		}
	}
}
