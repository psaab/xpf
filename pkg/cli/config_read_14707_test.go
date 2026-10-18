package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14707 (on-box CLI): config-mode `show` rendered the candidate with
// neither regex pair consulted, and operational `show configuration`
// never saw the *-configuration pair.

const cli14707Config = `
system {
    host-name cli-14707;
    login {
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class deny-setfmt {
            permissions [ view configure ];
            deny-commands "display set";
        }
        user limiteduser { class limited-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC-14707";
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

func cli14707Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(cli14707Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return store
}

func TestCLIConfigModeShowDenied14707(t *testing.T) {
	store := cli14707Store(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	c := &CLI{store: store, userClass: "limited-view"}
	if err := c.dispatchConfig("show security zones"); err == nil {
		t.Error("config-mode `show security zones` was ALLOWED for deny-configuration ^security (#14707)")
	}
	if err := c.dispatchConfig("show"); err == nil {
		t.Error("config-mode bare `show` (whole candidate) was ALLOWED for deny-configuration ^security (#14707)")
	}
	if err := c.dispatchConfig("show system host-name"); err != nil {
		t.Errorf("config-mode `show system host-name` must stay admitted: %v", err)
	}
}

func TestCLIOperationalShowConfigurationDenied14707(t *testing.T) {
	store := cli14707Store(t)
	c := &CLI{store: store, userClass: "limited-view"}
	if err := c.dispatchOperational("show configuration"); err == nil {
		t.Error("operational `show configuration` whole-tree was ALLOWED for deny-configuration ^security (#14707)")
	}
	if err := c.dispatchOperational("show configuration security"); err == nil {
		t.Error("operational `show configuration security` was ALLOWED for deny-configuration ^security (#14707)")
	}
	if err := c.dispatchOperational("show configuration system"); err != nil {
		t.Errorf("operational `show configuration system` must stay admitted: %v", err)
	}
	c2 := &CLI{store: store, userClass: "deny-setfmt"}
	if err := c2.dispatchOperational("show configuration | display set"); err == nil {
		t.Error("operational `show configuration | display set` was ALLOWED for deny-commands display set (#14707)")
	}
	if err := c2.dispatchOperational("show configuration"); err != nil {
		t.Errorf("operational hierarchical `show configuration` must stay admitted for deny-setfmt: %v", err)
	}
}
