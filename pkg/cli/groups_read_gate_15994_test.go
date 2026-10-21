package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15994 fold (CLI arm): the denied content lives ONLY as an applied
// group body. Covers: operational `show configuration groups …`
// (config arm AND op arm — fold 1), config-mode `show`, and
// `show system rollback` incl. the scoped `| compare` arm pricing
// BOTH actual diff trees (fold 5).

const groups15994CLIConfig = `
system {
    host-name groups-15994;
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class op-view {
            permissions [ view configure ];
            deny-commands "^show configuration security";
        }
        user limiteduser { class limited-view; }
        user opuser { class op-view; }
    }
}
groups {
    G {
        security {
            zones {
                security-zone trust {
                    description "GROUP-SEC-CLI-15994";
                    interfaces [ ge-0/0/0.0 ];
                }
            }
        }
        system { host-name group-h-15994; }
    }
}
apply-groups G;
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func groups15994Store(t *testing.T) *configstore.Store {
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
	commit(groups15994CLIConfig)
	commit(strings.Replace(groups15994CLIConfig, "groups-15994", "groups-15994-b", 1))
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return store
}

func TestCLIGroupsReadDenied15994(t *testing.T) {
	store := groups15994Store(t)
	c := &CLI{store: store, userClass: "limited-view"}
	// Premise: directed read refused.
	if err := c.dispatchOperational("show configuration security"); err == nil {
		t.Fatal("premise: directed show configuration security admitted")
	}
	for _, line := range []string{
		"show configuration groups G security",
		"show configuration groups",
		"show configuration groups G",
		"show configuration groups G security | display set",
		"show system rollback 1 groups G",
		"show system rollback 1 groups G security | display set",
		"show system rollback 1 groups G | compare",
		"show system rollback 1",
		"show configuration",
	} {
		var err error
		out := captureStdout(t, func() { err = c.dispatchOperational(line) })
		if err == nil {
			t.Errorf("%q was ALLOWED for deny-configuration ^security (#15994)", line)
		}
		if strings.Contains(out, "GROUP-SEC-CLI-15994") {
			t.Errorf("%q disclosed the group-authored subtree (#15994)", line)
		}
	}
	// Controls stay admitted.
	for _, line := range []string{
		"show configuration groups G system",
		"show configuration system host-name",
		"show system rollback 1 system",
		"show system rollback 1 groups G system",
	} {
		if err := c.dispatchOperational(line); err != nil {
			t.Errorf("%q control was refused (#15994): %v", line, err)
		}
	}
}

func TestCLIGroupsReadOpDenied15994(t *testing.T) {
	store := groups15994Store(t)
	c := &CLI{store: store, userClass: "op-view"}
	// Fold 1: the operational helper must charge the unwrapped
	// effective command, not only the literal line.
	for _, line := range []string{
		"show configuration groups G security",
		"show configuration groups G security | display set",
		"show configuration groups",
		"show configuration groups G",
	} {
		var err error
		out := captureStdout(t, func() { err = c.dispatchOperational(line) })
		if err == nil {
			t.Errorf("%q was ALLOWED for deny-commands ^show configuration security (#15994 fold 1)", line)
		}
		if strings.Contains(out, "GROUP-SEC-CLI-15994") {
			t.Errorf("%q disclosed the group-authored subtree (#15994)", line)
		}
	}
	if err := c.dispatchOperational("show configuration groups G system"); err != nil {
		t.Errorf("op control refused: %v", err)
	}
}

func TestCLIConfigModeGroupsReadDenied15994(t *testing.T) {
	store := groups15994Store(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	c := &CLI{store: store, userClass: "limited-view"}
	if err := c.checkConfigShowRegex([]string{"groups", "G", "security"}); err == nil {
		t.Error("config-mode groups G security ALLOWED (#15994)")
	}
	if err := c.checkConfigShowRegex([]string{"groups", "G", "system"}); err != nil {
		t.Errorf("config-mode groups G system refused: %v", err)
	}
	if err := c.checkShowConfigurationRead([]string{"groups", "G", "security"}); err == nil {
		t.Error("operational groups G security ALLOWED (#15994)")
	}
	if err := c.checkShowConfigurationRead([]string{"groups", "G", "system"}); err != nil {
		t.Errorf("operational groups G system refused: %v", err)
	}
}
