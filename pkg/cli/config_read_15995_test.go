package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15995 (A8-01, CLI arm): deny-configuration "^security ipsec" was
// evaluated only on the requested path, so `show configuration security`
// (operational), config-mode `show security`, scoped compares and scoped
// rollback renders all disclosed the denied ipsec descendant. The gates
// now price every rendered descendant of the active/candidate/slot trees.

const cli15995Config = `
system {
    host-name cli-15995;
    login {
        class ancestor-view {
            permissions [ view configure ];
            deny-configuration "^security ipsec";
        }
        user ancuser { class ancestor-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "ZONE-DESC-15995";
            interfaces [ ge-0/0/0.0 ];
        }
    }
    ipsec {
        vpn vpn1 { bind-interface st0.0; pre-shared-key ascii-text dummy15995; }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

func cli15995Store(t *testing.T) *configstore.Store {
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
	commit(cli15995Config)
	commit(strings.Replace(cli15995Config, "cli-15995", "cli-15995-b", 1))
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return store
}

func TestCLIShowAncestorDeniedDescendant15995(t *testing.T) {
	store := cli15995Store(t)
	c := &CLI{store: store, userClass: "ancestor-view"}

	// Operational show configuration: ancestor refused, siblings admitted.
	if err := c.dispatchOperational("show configuration security"); err == nil {
		t.Error("operational `show configuration security` was ALLOWED though it renders denied ipsec (#15995)")
	}
	if err := c.dispatchOperational("show configuration security ipsec"); err == nil {
		t.Error("operational `show configuration security ipsec` was ALLOWED (control)")
	}
	for _, line := range []string{
		"show configuration security zones",
		"show configuration interfaces",
	} {
		out := captureStdout(t, func() {
			if err := c.dispatchOperational(line); err != nil {
				t.Errorf("operational %q must stay admitted: %v", line, err)
			}
		})
		if strings.Contains(out, "ipsec") {
			t.Errorf("operational %q disclosed ipsec:\n%s", line, out)
		}
	}

	// Scoped rollback renders/compares: ancestor refused, sibling admitted.
	if err := c.dispatchOperational("show system rollback 1 security"); err == nil {
		t.Error("`show system rollback 1 security` was ALLOWED though it renders denied ipsec (#15995)")
	}
	if err := c.dispatchOperational("show system rollback 1 security | compare"); err == nil {
		t.Error("`show system rollback 1 security | compare` was ALLOWED though it diffs denied ipsec (#15995)")
	}
	if err := c.dispatchOperational("show system rollback 1 security | display set"); err == nil {
		t.Error("`show system rollback 1 security | display set` was ALLOWED though it renders denied ipsec (#15995)")
	}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 security zones"); err != nil {
			t.Errorf("scoped rollback [security zones] must stay admitted: %v", err)
		}
	})
	if !strings.Contains(out, "ZONE-DESC-15995") {
		t.Errorf("scoped rollback zones lost content:\n%s", out)
	}
}

func TestCLIConfigModeShowAncestorDeniedDescendant15995(t *testing.T) {
	store := cli15995Store(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	c := &CLI{store: store, userClass: "ancestor-view"}

	if err := c.dispatchConfig("show security"); err == nil {
		t.Error("config-mode `show security` was ALLOWED though it renders denied ipsec (#15995)")
	}
	if err := c.dispatchConfig("show security | compare"); err == nil {
		t.Error("config-mode `show security | compare` was ALLOWED though it diffs denied ipsec (#15995)")
	}
	if err := c.dispatchConfig("show security zones"); err != nil {
		t.Errorf("config-mode `show security zones` must stay admitted: %v", err)
	}
	// Edit-path form: [edit security] show renders the same subtree.
	store.SetEditPath([]string{"security"})
	if err := c.dispatchConfig("show"); err == nil {
		t.Error("config-mode [edit security] `show` was ALLOWED though it renders denied ipsec (#15995)")
	}
	store.SetEditPath(nil)
}
