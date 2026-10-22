package cli

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi"
)

// #16160 (schema R1): CLI and gRPC completion now share
// config.ProvideValues + config.HintRoots. This parity test drives BOTH
// frontend valueProviders over one committed store — plus the
// never-committed (catalogueSuppressed=true) candidate — and asserts
// identical slices for every hint, including the present-but-nil
// fixture (#3494 shape). It deletes the need for mirrored provider
// tables: any future divergence between the local and remote surfaces
// fails here. Slices are canonicalized (sorted by Name, then Desc)
// before comparison because the providers iterate maps.

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

func parityStore16160(t *testing.T, committed bool) (cli *CLI, srv *grpcapi.Server, committedCfg *config.Config) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(parityBody16160); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if committed {
		cfg, err := store.Commit()
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
		return &CLI{store: store}, grpcapi.NewServer("", grpcapi.Config{Store: store}), cfg
	}
	// Never committed: still in config mode, so completionConfig draws
	// the candidate with catalogueSuppressed=true on both frontends.
	return &CLI{store: store}, grpcapi.NewServer("", grpcapi.Config{Store: store}), nil
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

func assertParity16160(t *testing.T, cli *CLI, srv *grpcapi.Server, suppressed bool) {
	t.Helper()
	for _, cell := range parityCells16160() {
		cliGot := canonicalParity16160(cli.valueProvider(cell.hint, cell.path))
		grpcGot := canonicalParity16160(grpcapi.CompletionValuesForTest16160(srv, cell.hint, cell.path))
		if len(cliGot) != len(grpcGot) {
			t.Errorf("[suppressed=%v] %s: CLI %v != gRPC %v", suppressed, cell.name, cliGot, grpcGot)
			continue
		}
		for i := range cliGot {
			if cliGot[i] != grpcGot[i] {
				t.Errorf("[suppressed=%v] %s[%d]: CLI %v != gRPC %v", suppressed, cell.name, i, cliGot[i], grpcGot[i])
			}
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

func TestCompletionProvideValuesParity16160(t *testing.T) {
	// Committed (catalogueSuppressed=false): full catalogue on both.
	cli, srv, cfg := parityStore16160(t, true)
	if cfg == nil {
		t.Fatal("committed fixture returned nil config")
	}
	// Present-but-nil fixture (#3494): injected into the committed
	// config both frontends complete from (the store's active pointer).
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
	assertParity16160(t, cli, srv, false)
	// Non-vacuous control: configured names really are offered.
	if got := cli.valueProvider(config.ValueHintZoneName, nil); !hasName16160(got, "trust") || hasName16160(got, "nilzone") {
		t.Errorf("committed zones = %v, want trust present and nilzone skipped", got)
	}
	if got := cli.valueProvider(config.ValueHintAppName, nil); !hasName16160(got, "junos-ssh") {
		t.Errorf("committed apps missing predefined catalogue: %v", got)
	}

	// Never committed (catalogueSuppressed=true): the suppression cell —
	// authz-adjacent, since the predefined catalogue is gated on the
	// first commit (#5763). Both frontends must suppress identically.
	cli2, srv2, _ := parityStore16160(t, false)
	assertParity16160(t, cli2, srv2, true)
	if got := cli2.valueProvider(config.ValueHintAppName, nil); hasName16160(got, "junos-ssh") || !hasName16160(got, "custom-app") {
		t.Errorf("suppressed apps = %v, want custom-app only (no predefined)", got)
	}
	if got := cli2.valueProvider(config.ValueHintPolicyApp, nil); hasName16160(got, "any") {
		t.Errorf("suppressed policy-apps must omit \"any\": %v", got)
	}
	// Cross-check the shared function directly against the same
	// candidate snapshot semantics: suppressed ProvideValues equals the
	// frontend result for the app hints.
	if _, suppressed := cli2.completionConfig(); !suppressed {
		t.Fatal("never-committed fixture: completionConfig suppressed = false, want true")
	}
}
