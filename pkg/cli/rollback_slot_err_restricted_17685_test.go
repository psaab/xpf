package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #17685 (residual of #16613 / PR #17421): scoped rollback read gates
// stash the slotErr via setRenderSnapshots16613 but must return it
// before scoped authorization. Otherwise a configuration-restricted
// class gets permission-denied rather than the history out-of-range
// error for a missing slot. This affects operational display-pipe,
// piped-compare, bare-path reads and config-mode rollback compares:
// their handlers check renderSlotErr only after authorization has
// already returned. Whole-tree display/compare/rollback gates already
// return slotErr first.

// Fixture mirrors config_read_14987_test.go: limited-view denies
// configuration under "^security", and allow-interfaces only allows
// "^interfaces". Two commits make rollback 1 the only existing slot;
// rollback 40 is missing. Slot 1 remains the positive control: an
// allowed path must render, while a denied path must still be refused.

const cli17685Config = `
system {
    host-name cli-17685;
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class allow-interfaces {
            permissions [ view configure ];
            allow-configuration "^interfaces";
        }
        user limiteduser { class limited-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-17685";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
`

func cli17685Store(t *testing.T) *configstore.Store {
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
	commit(cli17685Config)
	commit(strings.Replace(cli17685Config, "cli-17685", "cli-17685-b", 1))
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return store
}

func TestCLIRollbackMissingSlotRestrictedScopedReads17685(t *testing.T) {
	store := cli17685Store(t)

	// RED cells: each missing-slot scoped read below reaches a gate
	// that stashes slotErr and then authorizes the requested path. The
	// configuration restrictions make the pre-fix authorization error
	// observable; each must instead return the history out-of-range
	// error before authorization.
	red := []struct {
		name      string
		userClass string
		line      string
		config    bool
	}{
		{"denied-path-display-set", "limited-view", "show system rollback 40 security zones | display set", false},
		{"denied-path-display-inheritance", "limited-view", "show system rollback 40 security zones | display inheritance", false},
		{"outside-allowlist-display-set", "allow-interfaces", "show system rollback 40 security zones | display set", false},
		{"outside-allowlist-display-json", "allow-interfaces", "show system rollback 40 system | display json", false},
		{"denied-path-piped-compare", "limited-view", "show system rollback 40 security zones | compare", false},
		{"denied-path-bare-path", "limited-view", "show system rollback 40 security zones", false},
		{"config-mode-denied-path-compare", "limited-view", "show security zones | compare rollback 40", true},
	}
	for _, tc := range red {
		t.Run(tc.name, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.userClass}
			var err error
			out := captureStdout(t, func() {
				if tc.config {
					if enterErr := store.EnterConfigure(); enterErr != nil {
						t.Fatalf("EnterConfigure: %v", enterErr)
					}
					defer store.ExitConfigure()
					err = c.dispatchConfig(tc.line)
				} else {
					err = c.dispatchOperational(tc.line)
				}
			})
			if err == nil {
				t.Fatalf("restricted %q (class %s) returned nil error, out=%q (#17685)", tc.line, tc.userClass, out)
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("restricted %q (class %s) error = %v, want history out-of-range slot error, not the authorization verdict (#17685)", tc.line, tc.userClass, err)
			}
			if strings.Contains(out, "SECRET-TRUST-17685") {
				t.Errorf("restricted %q disclosed the denied security subtree: %q (#17685)", tc.line, out)
			}
			if strings.TrimSpace(out) != "" {
				t.Errorf("restricted missing-slot read %q rendered output before returning its slot error: %q (#17685)", tc.line, out)
			}
		})
	}

	// Whole-tree display already returns slotErr before authorization;
	// it is a control for the shared missing-slot behavior.
	t.Run("control-whole-display-arm", func(t *testing.T) {
		c := &CLI{store: store, userClass: "limited-view"}
		var err error
		out := captureStdout(t, func() { err = c.dispatchOperational("show system rollback 40 | display set") })
		if err == nil {
			t.Fatalf("whole-display control returned nil error, out=%q", out)
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("whole-display control error = %v, want history out-of-range", err)
		}
	})

	// Positive controls: slot 1 exists. An allowed path must render
	// for the restricted class, and a denied path must still get the
	// authorization verdict (not the slot error, which is nil) — the
	// fix must not turn existing-slot authorization into a bypass or
	// a spurious slot error.
	t.Run("slot1-allowed-path-still-renders", func(t *testing.T) {
		c := &CLI{store: store, userClass: "limited-view"}
		var err error
		out := captureStdout(t, func() { err = c.dispatchOperational("show system rollback 1 interfaces | display set") })
		if err != nil {
			t.Errorf("slot-1 allowed-path display set errored for restricted class: %v", err)
		}
		if !strings.Contains(out, "ge-0/0/0") {
			t.Errorf("slot-1 allowed-path display set lost interfaces content:\n%s", out)
		}
	})
	t.Run("slot1-denied-path-still-denied", func(t *testing.T) {
		c := &CLI{store: store, userClass: "limited-view"}
		var err error
		out := captureStdout(t, func() { err = c.dispatchOperational("show system rollback 1 security zones | display set") })
		if err == nil {
			t.Errorf("slot-1 denied-path display set was ALLOWED for deny-configuration ^security, out=%q", out)
		} else if strings.Contains(err.Error(), "out of range") {
			t.Errorf("slot-1 denied-path error = %v, want the authorization verdict, not a slot error", err)
		}
		if strings.Contains(out, "SECRET-TRUST-17685") {
			t.Errorf("slot-1 denied-path disclosed the denied security subtree: %q", out)
		}
	})
	// Unclassed control: the missing-slot display-pipe read already
	// errors via the live store path — pin it so the classed fix
	// matches it.
	t.Run("unclassed-missing-slot-control", func(t *testing.T) {
		c := &CLI{store: store}
		var err error
		captureStdout(t, func() { err = c.dispatchOperational("show system rollback 40 security zones | display set") })
		if err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Errorf("unclassed missing-slot display set error = %v, want history out-of-range (control broken)", err)
		}
	})
}
