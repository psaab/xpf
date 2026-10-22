package cli

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #16160 (schema R1): CLI and gRPC completion share
// config.ProvideValues + config.HintRoots. The parity contract is
// anchored on the shared function: each frontend's valueProvider must
// return exactly ProvideValues(completionConfig()) for the same store.
// This test pins the CLI side over a committed store with
// present-but-nil slots injected (#3494 shape) plus the never-committed
// candidate (catalogueSuppressed=true); pkg/grpcapi pins the gRPC side
// the same way, and its Complete RPC test proves the RPC surface (not
// just the provider) serves those values to an admitted principal.
// Slices are canonicalized (sorted by Name, then Desc) because the
// provider iterates maps. No production test helper is introduced.

const parityBody16160 = `
security {
    zones {
        security-zone trust { description "Trust zone"; }
        security-zone untrust;
    }
    address-book {
        global {
            address host-a 10.0.0.1/32;
            address-set set-a { address host-a; }
        }
    }
    nat {
        source { pool pool-src { address { 10.1.0.0/24; } } }
        destination { pool pool-dst { address 10.2.0.1/32; } }
    }
    screen { ids-option scr { tcp { land; } } }
    log { stream stream1 { host 192.0.2.1; } }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web { description "Web"; match { source-address host-a; destination-address any; application custom-app; } then { permit; } }
            policy deny-all { match { source-address any; destination-address any; application any; } then { deny; } }
        }
        global { policy global-pol { match { source-address any; destination-address any; application any; } then { permit; } } }
    }
}
interfaces {
    ge-0/0/0 {
        description "Uplink";
        vlan-tagging;
        unit 0 { description "Primary"; family inet { address 192.0.2.2/24; } }
        unit 1 { vlan-id 10; family inet { address 192.0.2.6/24; } }
    }
}
applications {
    application custom-app { protocol tcp; destination-port 8080; description "Custom"; }
    application-set custom-set { application custom-app; }
}
`

func parityStore16160(t *testing.T, committed bool) (*CLI, *configstore.Store) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(parityBody16160); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if committed {
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
	}
	return &CLI{store: store}, store
}

func canonicalParity16160(in []config.SchemaCompletion) []config.SchemaCompletion {
	out := append([]config.SchemaCompletion(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Desc < out[j].Desc
	})
	return out
}

func parityCells16160() []struct {
	name string
	hint config.ValueHint
	path []string
} {
	return []struct {
		name string
		hint config.ValueHint
		path []string
	}{
		{"zone", config.ValueHintZoneName, nil},
		{"address", config.ValueHintAddressName, nil},
		{"app", config.ValueHintAppName, nil},
		{"appset", config.ValueHintAppSetName, nil},
		{"pool", config.ValueHintPoolName, nil},
		{"screen", config.ValueHintScreenProfile, nil},
		{"stream", config.ValueHintStreamName, nil},
		{"interface", config.ValueHintInterfaceName, nil},
		{"policy-address", config.ValueHintPolicyAddress, nil},
		{"policy-app", config.ValueHintPolicyApp, nil},
		{"policy-name-zonepair", config.ValueHintPolicyName, []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"}},
		{"policy-name-global", config.ValueHintPolicyName, []string{"security", "policies", "global", "policy"}},
		{"unit", config.ValueHintUnitNumber, []string{"interfaces", "ge-0/0/0", "unit"}},
		{"none", config.ValueHintNone, nil},
		{"unknown", config.ValueHint(999), nil},
	}
}

func assertCLIParity16160(t *testing.T, c *CLI, suppressed bool) {
	t.Helper()
	cfg, gotSuppressed := c.completionConfig()
	if gotSuppressed != suppressed {
		t.Fatalf("completionConfig suppressed = %v, want %v", gotSuppressed, suppressed)
	}
	if cfg == nil {
		t.Fatal("completionConfig returned nil config")
	}
	for _, cell := range parityCells16160() {
		want := canonicalParity16160(config.ProvideValues(cfg, cell.hint, cell.path, suppressed))
		got := canonicalParity16160(c.valueProvider(cell.hint, cell.path))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("[suppressed=%v] %s: CLI valueProvider %v != ProvideValues %v", suppressed, cell.name, got, want)
		}
	}
}

func hasName16160(in []config.SchemaCompletion, name string) bool {
	for _, c := range in {
		if c.Name == name {
			return true
		}
	}
	return false
}

func namesOf16160(in []config.SchemaCompletion) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, c.Name)
	}
	return out
}

func TestCompletionProvideValuesParity16160(t *testing.T) {
	// Committed (catalogueSuppressed=false): full catalogue.
	c, store := parityStore16160(t, true)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("committed fixture returned nil config")
	}
	// Present-but-nil fixture (#3494): injected into the committed
	// config the frontend completes from (the store's active pointer,
	// the same object completionConfig returns).
	cfg.Security.Zones["nilzone"] = nil
	cfg.Interfaces.Interfaces["ge-0/0/9"] = nil
	if iface := cfg.Interfaces.Interfaces["ge-0/0/0"]; iface != nil {
		iface.Units[9] = nil
	}
	cfg.Security.Policies = append([]*config.ZonePairPolicies{nil}, cfg.Security.Policies...)
	for _, zpp := range cfg.Security.Policies {
		if zpp != nil {
			zpp.Policies = append([]*config.Policy{nil}, zpp.Policies...)
		}
	}
	assertCLIParity16160(t, c, false)
	// Non-vacuous controls.
	if got := c.valueProvider(config.ValueHintZoneName, nil); !hasName16160(got, "trust") || hasName16160(got, "nilzone") {
		t.Errorf("committed zones = %v, want trust present and nilzone skipped", namesOf16160(got))
	}
	if got := c.valueProvider(config.ValueHintAppName, nil); !hasName16160(got, "junos-ssh") {
		t.Errorf("committed apps missing predefined catalogue")
	}

	// Never committed (catalogueSuppressed=true): the suppression cell —
	// authz-adjacent, since the predefined catalogue is gated on the
	// first commit (#5763). The frontend must suppress identically to
	// the shared function called with suppressed=true.
	c2, _ := parityStore16160(t, false)
	assertCLIParity16160(t, c2, true)
	if got := c2.valueProvider(config.ValueHintAppName, nil); hasName16160(got, "junos-ssh") || !hasName16160(got, "custom-app") {
		t.Errorf("suppressed apps = %v, want custom-app only (no predefined)", namesOf16160(got))
	}
	if got := c2.valueProvider(config.ValueHintPolicyApp, nil); hasName16160(got, "any") {
		t.Errorf("suppressed policy-apps must omit \"any\"")
	}
}
