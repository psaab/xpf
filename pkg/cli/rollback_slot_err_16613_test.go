package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #16613: the console read gate discarded CaptureRollback /
// CaptureRollbackSlot's Err and stashed nil arms, so for a classed
// user a missing rollback slot rendered as an empty compare, a
// "[no changes]" compare, or "configuration path not found" instead
// of the slot error the unclassed console, gRPC and REST report.
// The gate now stashes the slotErr with the priced snapshots and each
// handler returns it before rendering. Slot 1 is the positive control:
// it must render/change nothing for either class.
//
// The fixture commits twice, so history holds exactly one slot
// (rollback 1 = the first commit); rollback 40 does not exist. The
// "limited" class has no configuration restriction, matching the
// issue probe: whole-tree rollback reads stay authorized, so only
// the slot error can fail them.

const cli16613Config = `
system {
    host-name cli-16613;
    login {
        class limited {
            permissions [ view configure ];
        }
        user limiteduser { class limited; }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func cli16613Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	commit := func(text string) {
		t.Helper()
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(text); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
	}
	commit(cli16613Config)
	commit(strings.Replace(cli16613Config, "cli-16613", "cli-16613-b", 1))
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return store
}

func TestCLIRollbackMissingSlotClassed16613(t *testing.T) {
	store := cli16613Store(t)

	// Config-mode: show <path> | compare rollback 40.
	// dispatchConfig is the real gated entry (checkConfigShowRegex
	// runs before handleConfigShow); dispatch() would route on the
	// global config-mode flag, so enter configure first.
	t.Run("config-compare", func(t *testing.T) {
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		defer store.ExitConfigure()
		c := &CLI{store: store, userClass: "limited"}
		var err error
		out := captureStdout(t, func() {
			err = c.dispatchConfig("show interfaces | compare rollback 40")
		})
		if err == nil {
			t.Errorf("classed config-mode `show interfaces | compare rollback 40` returned nil error, out=%q (#16613)", out)
		} else if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("classed config-mode missing-slot error = %v, want history out-of-range", err)
		}
		if strings.Contains(out, "[no changes]") {
			t.Errorf("classed config-mode missing slot printed [no changes]: %q", out)
		}
		// Positive control: slot 1 exists and must not error.
		out = captureStdout(t, func() {
			err = c.dispatchConfig("show interfaces | compare rollback 1")
		})
		if err != nil {
			t.Errorf("classed config-mode `show interfaces | compare rollback 1` (existing slot) errored: %v (out=%q)", err, out)
		}
	})

	// Unclassed control: the same missing slot already errors via the
	// live store path — pin it so the classed fix matches it.
	t.Run("config-compare-unclassed-control", func(t *testing.T) {
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		defer store.ExitConfigure()
		c := &CLI{store: store}
		var err error
		captureStdout(t, func() {
			err = c.dispatchConfig("show interfaces | compare rollback 40")
		})
		if err == nil {
			t.Error("unclassed config-mode missing slot returned nil error (control broken)")
		}
	})

	operational := []struct {
		name string
		line string
	}{
		{"op-compare-form", "show system rollback compare 40"},
		{"op-piped-compare-path", "show system rollback 40 interfaces | compare"},
		{"op-bare-compare", "show system rollback 40 compare"},
		{"op-bare-path", "show system rollback 40 interfaces"},
		{"op-bare-whole", "show system rollback 40"},
		{"op-display-set-path", "show system rollback 40 interfaces | display set"},
		{"op-display-set-whole", "show system rollback 40 | display set"},
	}
	for _, tc := range operational {
		t.Run(tc.name, func(t *testing.T) {
			c := &CLI{store: store, userClass: "limited"}
			var err error
			out := captureStdout(t, func() {
				err = c.dispatchOperational(tc.line)
			})
			if err == nil {
				t.Errorf("classed operational %q returned nil error, out=%q (#16613)", tc.line, out)
			} else if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("classed operational %q error = %v, want history out-of-range", tc.line, err)
			}
			if strings.Contains(out, "[no changes]") || strings.Contains(out, "No differences found") {
				t.Errorf("classed operational %q printed a no-changes verdict for a missing slot: %q", tc.line, out)
			}
			if strings.Contains(out, "configuration path not found") {
				t.Errorf("classed operational %q printed path-not-found for a missing slot: %q", tc.line, out)
			}
		})
	}

	// Positive controls: slot 1 renders for the classed user on the
	// same operational shapes (no error, real content / diff).
	t.Run("op-slot1-controls", func(t *testing.T) {
		c := &CLI{store: store, userClass: "limited"}
		var err error
		out := captureStdout(t, func() {
			err = c.dispatchOperational("show system rollback 1 interfaces")
		})
		if err != nil {
			t.Errorf("classed `show system rollback 1 interfaces` errored: %v", err)
		}
		if !strings.Contains(out, "ge-0/0/0") {
			t.Errorf("classed slot-1 render lost interfaces content:\n%s", out)
		}
		out = captureStdout(t, func() {
			err = c.dispatchOperational("show system rollback 1 interfaces | compare")
		})
		if err != nil {
			t.Errorf("classed `show system rollback 1 interfaces | compare` errored: %v", err)
		}
		if out == "" {
			t.Error("classed slot-1 piped compare rendered nothing (want a diff or [no changes])")
		}
		out = captureStdout(t, func() {
			err = c.dispatchOperational("show system rollback compare 1")
		})
		if err != nil {
			t.Errorf("classed `show system rollback compare 1` errored: %v", err)
		}
		if out == "" {
			t.Error("classed slot-1 compare rendered nothing")
		}
	})
}
