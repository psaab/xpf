package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14987 (residual of #14707 / D37-02): the on-box CLI still rendered
// configuration through `show system …` spellings and the config-mode
// `show | compare` pipe with only part of the regex model applied.
//
// Measured on base 5b3b02a61f (probe, since removed):
//   - `show system rollback 1` served the whole denied tree to a
//     deny-configuration "^security" class (checkCommandRegex charged
//     only the literal "show system rollback" spelling, which that
//     deny does not match, and no *-configuration arm existed).
//   - `show | compare` / `show | display set` in config mode: the
//     compare pipe was adjudicated as a path render, so a
//     deny-commands "display set" class read the candidate diff and a
//     `show security zones | display set` read the denied subtree in
//     set form (the format was stripped before the operational pair
//     saw a string it could match — note AuthorizeConfigShowPath does
//     receive the suffix; the RED cell is the compare/format shape as
//     measured below).
//   - `show system login` rendered the system login subtree with no
//     *-configuration adjudication.
//
// These cells drive the real dispatchers (dispatchOperational /
// dispatchConfig / `run`), so a gate that is computed but not obeyed,
// or wired to only one entry point, fails here.

const cli14987Config = `
system {
    host-name cli-14987;
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class deny-setfmt {
            permissions [ view configure ];
            deny-commands "display set";
        }
        class deny-showcfg {
            permissions [ view configure ];
            deny-commands "^show configuration$";
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
            description "SECRET-TRUST-14987";
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

// cli14987Store commits the fixture twice so rollback slot 1 holds a
// full earlier tree (including the denied security subtree).
func cli14987Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(cli14987Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := store.LoadSet("set system domain-name example.net"); err != nil {
		t.Fatalf("LoadSet(v2): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(v2): %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return store
}

func TestCLIShowSystemRollbackDenied14987(t *testing.T) {
	store := cli14987Store(t)
	c := &CLI{store: store, userClass: "limited-view"}
	for _, line := range []string{
		"show system rollback 1",
		"show system rollback 1 | display set",
	} {
		var err error
		out := captureStdout(t, func() { err = c.dispatchOperational(line) })
		if err == nil {
			t.Errorf("%q was ALLOWED for deny-configuration ^security (#14987)", line)
		}
		if strings.Contains(out, "SECRET-TRUST-14987") {
			t.Errorf("%q disclosed the denied security subtree (#14987)", line)
		}
	}
	// `run` from config mode funnels through the same gate.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	var err error
	out := captureStdout(t, func() { err = c.dispatchConfig("run show system rollback 1") })
	if err == nil || strings.Contains(out, "SECRET-TRUST-14987") {
		t.Errorf("run show system rollback 1: err=%v disclosed=%v (#14987)", err, strings.Contains(out, "SECRET-TRUST-14987"))
	}
}

func TestCLIShowSystemAnchoredShowDeny14987(t *testing.T) {
	store := cli14987Store(t)
	c := &CLI{store: store, userClass: "deny-showcfg"}
	// Anchored `^show configuration$`: the bare-form alternate must
	// cover the rollback render exactly as it covers sub-paths of
	// `show configuration` (AuthorizeConfigShow* semantics).
	var err error
	out := captureStdout(t, func() { err = c.dispatchOperational("show system rollback 1") })
	if err == nil {
		t.Error("show system rollback 1 was ALLOWED for deny-commands ^show configuration$ (#14987)")
	}
	if strings.Contains(out, "SECRET-TRUST-14987") {
		t.Error("show system rollback 1 disclosed the security subtree (#14987)")
	}
	// Control: an allowed subtree through the ordinary spelling stays up.
	// (deny-showcfg has no *-configuration rules, so only the anchored
	// operational deny is in play; `show system uptime` is untouched.)
	if err := c.dispatchOperational("show system uptime"); err != nil {
		t.Errorf("show system uptime must stay admitted: %v", err)
	}
}

func TestCLIShowSystemLoginSubtreeDenied14987(t *testing.T) {
	store := cli14987Store(t)
	// deny-configuration on the login subtree itself.
	c := &CLI{store: store, userClass: "allow-interfaces"}
	var err error
	out := captureStdout(t, func() { err = c.dispatchOperational("show system login") })
	if err == nil {
		t.Error("show system login was ALLOWED for allow-configuration ^interfaces (system login outside allowlist) (#14987)")
	}
	if strings.Contains(out, "limited-view") {
		t.Error("show system login disclosed the login subtree (#14987)")
	}
	// Control: the allowed subtree still renders via show configuration.
	c2 := &CLI{store: store, userClass: "allow-interfaces"}
	if err := c2.dispatchOperational("show configuration interfaces"); err != nil {
		t.Errorf("show configuration interfaces must stay admitted for allow-interfaces: %v", err)
	}
	// Control: limited-view (deny ^security) may still read system login —
	// the gate is per-path, not a blanket system denial.
	c3 := &CLI{store: store, userClass: "limited-view"}
	if err := c3.dispatchOperational("show system login"); err != nil {
		t.Errorf("show system login must stay admitted for limited-view: %v", err)
	}
}

func TestCLIShowSystemRescueDenied14987(t *testing.T) {
	store := cli14987Store(t)
	if err := store.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig: %v", err)
	}
	c := &CLI{store: store, userClass: "limited-view"}
	var err error
	out := captureStdout(t, func() { err = c.dispatchOperational("show system configuration rescue") })
	if err == nil {
		t.Error("show system configuration rescue was ALLOWED for deny-configuration ^security (#14987)")
	}
	if strings.Contains(out, "SECRET-TRUST-14987") {
		t.Error("show system configuration rescue disclosed the denied subtree (#14987)")
	}
}

func TestCLIConfigShowCompareFormatDenied14987(t *testing.T) {
	store := cli14987Store(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	if _, err := store.LoadSet("set system host-name staged-14987"); err != nil {
		t.Fatalf("LoadSet(staged): %v", err)
	}
	// deny-commands "display set": the config-mode display pipe must be
	// charged on the operational pair (AuthorizeConfigShowPath already
	// receives the suffix; this pins the wiring end to end).
	c := &CLI{store: store, userClass: "deny-setfmt"}
	if err := c.dispatchConfig("show system host-name | display set"); err == nil {
		t.Error("config-mode `show … | display set` was ALLOWED for deny-commands display set (#14987)")
	}
	if err := c.dispatchConfig("show | compare"); err != nil {
		// compare renders hierarchically (no display suffix); the
		// deny-setfmt class has no *-configuration rules, so it stays up.
		t.Errorf("config-mode `show | compare` must stay admitted for deny-setfmt: %v", err)
	}
	// deny-configuration class: candidate diff is a whole-tree render.
	c2 := &CLI{store: store, userClass: "limited-view"}
	if err := c2.dispatchConfig("show | compare"); err == nil {
		t.Error("config-mode `show | compare` was ALLOWED for deny-configuration ^security (#14987)")
	}
	if err := c2.dispatchConfig("show | compare rollback 1"); err == nil {
		t.Error("config-mode `show | compare rollback 1` was ALLOWED for deny-configuration ^security (#14987)")
	}
	// Control: an allowed subtree in config mode stays up.
	if err := c2.dispatchConfig("show system host-name"); err != nil {
		t.Errorf("config-mode `show system host-name` must stay admitted: %v", err)
	}
}

func TestCLIShowSystemRollbackUnrestrictedUnaffected14987(t *testing.T) {
	store := cli14987Store(t)
	// No regexes at all: every render stays up (narrowness control).
	c := &CLI{store: store, userClass: "super-user"}
	var err error
	out := captureStdout(t, func() { err = c.dispatchOperational("show system rollback 1") })
	if err != nil {
		t.Fatalf("super-user show system rollback 1 denied: %v", err)
	}
	if !strings.Contains(out, "SECRET-TRUST-14987") {
		t.Errorf("super-user rollback render lost the security subtree (gate over-denied):\n%s", out)
	}
	// Timestamp list carries no config content and stays up even for
	// the restricted class.
	c2 := &CLI{store: store, userClass: "limited-view"}
	if err := c2.dispatchOperational("show system rollback"); err != nil {
		t.Errorf("show system rollback (list) must stay admitted: %v", err)
	}
}
