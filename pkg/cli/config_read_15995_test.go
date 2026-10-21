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

// Fold C2: abbreviated operational commands resolve in the handler;
// the gate must resolve them the same way or `show conf` slips past.
func TestCLIAbbreviatedShowConfiguration15995(t *testing.T) {
	store := cli15995Store(t)
	c := &CLI{store: store, userClass: "ancestor-view"}
	for _, line := range []string{
		"show conf security",
		"show configur security",
		"show conf",
	} {
		if err := c.dispatchOperational(line); err == nil {
			t.Errorf("operational %q was ALLOWED (#15995 C2 abbreviation bypass)", line)
		}
	}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show conf security zones"); err != nil {
			t.Errorf("abbreviated allowed sibling refused: %v", err)
		}
	})
	if !strings.Contains(out, "ZONE-DESC-15995") || strings.Contains(out, "ipsec") {
		t.Errorf("abbreviated zones render wrong:\n%s", out)
	}
}

// Fold C5: `show system login` / `show system root-authentication`
// render whole subtrees; a denied strict descendant refuses them.
func TestCLIShowSystemSubtreeDescendant15995(t *testing.T) {
	text := `
system {
    host-name cli-15995-sys;
    root-authentication { encrypted-password "$6$CLILEAK00$ROOTPWHASH0000000000000000000000000000000000000000000000000000000000000000000000000000"; }
    login {
        class login-view {
            permissions [ view configure ];
            deny-configuration "^system login user alice$";
        }
        class root-view {
            permissions [ view configure ];
            deny-configuration "^system root-authentication encrypted-password";
        }
        user alice { class login-view; }
        user bob { class login-view; }
    }
}
`
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()

	c := &CLI{store: store, userClass: "login-view"}
	if err := c.dispatchOperational("show system login"); err == nil {
		t.Error("`show system login` ALLOWED though it renders denied user alice (#15995 C5)")
	}
	// Allowed control: bob's subtree via show configuration is not the
	// denied alice node — the [system login user bob] path renders bob.
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show configuration system login user bob"); err != nil {
			t.Errorf("allowed user bob read refused: %v", err)
		}
	})
	if !strings.Contains(out, "bob") || strings.Contains(out, "alice") {
		t.Errorf("user bob render wrong:\n%s", out)
	}
	c2 := &CLI{store: store, userClass: "root-view"}
	if err := c2.dispatchOperational("show system root-authentication"); err == nil {
		t.Error("`show system root-authentication` ALLOWED though it renders denied encrypted-password (#15995 C5)")
	}
}

// Fold C3 (CLI): group-supplied denied descendant under
// `display inheritance` must refuse; ordinary render is the control.
func TestCLIInheritanceGroupDescendant15995(t *testing.T) {
	text := `
system {
    host-name cli-15995-inh;
    login {
        class ancestor-view {
            permissions [ view configure ];
            deny-configuration "^security ipsec";
        }
        user ancuser { class ancestor-view; }
    }
}
groups {
    G {
        security {
            ipsec { vpn vpn1 { bind-interface st0.0; pre-shared-key ascii-text dummy15995; } }
        }
    }
}
apply-groups G;
security {
    zones { security-zone trust { description "ZONE-DESC-15995"; } }
}
`
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()
	c := &CLI{store: store, userClass: "ancestor-view"}
	if err := c.dispatchOperational("show configuration security | display inheritance"); err == nil {
		t.Error("inheritance [security] ALLOWED though expanded render carries ipsec (#15995 C3)")
	}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show configuration security zones | display inheritance"); err != nil {
			t.Errorf("expanded zones refused: %v", err)
		}
	})
	if !strings.Contains(out, "ZONE-DESC-15995") {
		t.Errorf("expanded zones render lost content:\n%s", out)
	}
}

// Fold 2 twin: config-mode `show … | display inheritance` renders the
// candidate's apply-groups expansion (cli_config.go), so the gate must
// price the EXPANDED candidate, exactly as the operational helper does.
// Pre-fold this arm priced the raw candidate unconditionally.
func TestCLIConfigModeInheritanceGroupDescendant15995(t *testing.T) {
	text := `
system {
    host-name cli-15995-inh-cm;
    login {
        class ancestor-view {
            permissions [ view configure ];
            deny-configuration "^security ipsec";
        }
        user ancuser { class ancestor-view; }
    }
}
groups {
    G {
        security {
            ipsec { vpn vpn1 { bind-interface st0.0; pre-shared-key ascii-text dummy15995; } }
        }
    }
}
apply-groups G;
security {
    zones { security-zone trust { description "ZONE-DESC-15995"; } }
}
`
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()
	// Re-enter config mode: config-mode show renders the candidate
	// (initially the just-committed tree).
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer store.ExitConfigure()
	c := &CLI{store: store, userClass: "ancestor-view"}

	// Ordinary config-mode render is the control: raw candidate has
	// no security ipsec child, so it renders (zones only).
	out := captureStdout(t, func() {
		if err := c.dispatchConfig("show security"); err != nil {
			t.Errorf("config-mode raw [security] refused: %v", err)
		}
	})
	if strings.Contains(out, "ipsec") {
		t.Fatalf("premise broken: raw config-mode render carries ipsec:\n%s", out)
	}
	// The inheritance arm expands the group into security: refused.
	if err := c.dispatchConfig("show security | display inheritance"); err == nil {
		t.Error("config-mode inheritance [security] ALLOWED though expanded candidate carries ipsec (#15995 Fold2)")
	}
	// Allowed sibling still renders expanded.
	out = captureStdout(t, func() {
		if err := c.dispatchConfig("show security zones | display inheritance"); err != nil {
			t.Errorf("config-mode expanded zones refused: %v", err)
		}
	})
	if !strings.Contains(out, "ZONE-DESC-15995") || strings.Contains(out, "ipsec") {
		t.Errorf("config-mode expanded zones render wrong:\n%s", out)
	}
}
