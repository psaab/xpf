package grpcapi_test

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16160: the gRPC side of the ProvideValues parity contract. The real
// Complete RPC (driven as an admitted superuser principal, the identity
// completionAuthFor resolves to unrestricted) must serve the shared
// config.ProvideValues values — committed (catalogueSuppressed=false)
// and never-committed (catalogueSuppressed=true) — at every hint
// position. This is the user-visible surface parity: it catches a
// frontend that stops delegating, mis-wires suppression, or drops a
// hint arm, without any production test helper (the principal is
// stamped via the test-only export in export_test.go, visible only to
// this package's test binary).

const parityRPCBody16160 = `
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

type rpcCell16160 struct {
	name string
	line string // trailing space: cursor at the value slot
	hint config.ValueHint
	path []string
}

func rpcCells16160() []rpcCell16160 {
	return []rpcCell16160{
		{"zone", "set security zones security-zone ", config.ValueHintZoneName, nil},
		{"address", "set security address-book global address-set ", config.ValueHintAddressName, nil},
		{"app", "set applications application ", config.ValueHintAppName, nil},
		{"appset", "set applications application-set ", config.ValueHintAppSetName, nil},
		{"pool", "set security nat source pool ", config.ValueHintPoolName, nil},
		{"screen", "set security screen ids-option ", config.ValueHintScreenProfile, nil},
		{"stream", "set security log stream ", config.ValueHintStreamName, nil},
		{"interface", "set interfaces ", config.ValueHintInterfaceName, nil},
		{"policy-address", "set security policies from-zone trust to-zone untrust policy p1 match source-address ", config.ValueHintPolicyAddress, nil},
		{"policy-app", "set security policies from-zone trust to-zone untrust policy p1 match application ", config.ValueHintPolicyApp, nil},
		{"policy-name-zonepair", "set security policies from-zone trust to-zone untrust policy ", config.ValueHintPolicyName, []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"}},
		{"policy-name-global", "set security policies global policy ", config.ValueHintPolicyName, []string{"security", "policies", "global", "policy"}},
		{"unit", "set interfaces ge-0/0/0 unit ", config.ValueHintUnitNumber, []string{"interfaces", "ge-0/0/0", "unit"}},
	}
}

func canonicalRPC16160(in []config.SchemaCompletion) []config.SchemaCompletion {
	out := append([]config.SchemaCompletion(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Desc < out[j].Desc
	})
	return out
}

func liveFromRPC16160(resp *pb.CompleteResponse) []config.SchemaCompletion {
	var out []config.SchemaCompletion
	for i, name := range resp.Candidates {
		if len(name) > 1 && strings.HasPrefix(name, "<") && strings.HasSuffix(name, ">") {
			continue
		}
		desc := ""
		if i < len(resp.Descriptions) {
			desc = resp.Descriptions[i]
		}
		out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
	}
	return canonicalRPC16160(out)
}

func rpcParityCtx16160() context.Context {
	return grpcapi.ContextWithAuthorizedPrincipalForTest(context.Background(), authz.Principal{
		Source: authz.SourcePeerUID, UID: 0, Username: "root", Superuser: true,
	})
}

func TestCompleteRPCParity16160(t *testing.T) {
	for _, committed := range []bool{true, false} {
		store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		if err := store.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := store.LoadOverride(parityRPCBody16160); err != nil {
			t.Fatal(err)
		}
		suppressed := true
		var cfg *config.Config
		if committed {
			cfg, err = store.Commit()
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			store.ExitConfigure()
			suppressed = false
		} else {
			cfg = store.ActiveConfig()
			if cfg == nil {
				// Candidate snapshot: completion draws it in config mode.
				cand, ok := store.CandidateConfigForCompletion()
				if !ok {
					t.Fatal("no candidate config for never-committed parity")
				}
				cfg = cand
			}
		}
		srv := grpcapi.NewServer("", grpcapi.Config{Store: store})
		ctx := rpcParityCtx16160()
		for _, cell := range rpcCells16160() {
			resp, err := srv.Complete(ctx, &pb.CompleteRequest{Line: cell.line, Pos: int32(len(cell.line)), ConfigMode: true})
			if err != nil {
				t.Fatalf("[committed=%v] %s: Complete: %v", committed, cell.name, err)
			}
			got := liveFromRPC16160(resp)
			want := canonicalRPC16160(config.ProvideValues(cfg, cell.hint, cell.path, suppressed))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("[committed=%v] %s: RPC live %v != ProvideValues(suppressed=%v) %v (all RPC %v)", committed, cell.name, got, suppressed, want, resp.Candidates)
			}
			if len(got) == 0 {
				t.Errorf("[committed=%v] %s: no live values via RPC (parity would be vacuous)", committed, cell.name)
			}
		}
		// Suppression witnesses.
		appResp, err := srv.Complete(ctx, &pb.CompleteRequest{Line: "set applications application ", Pos: int32(len("set applications application ")), ConfigMode: true})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(appResp.Candidates, " ")
		if suppressed && strings.Contains(joined, "junos-ssh") {
			t.Errorf("suppressed RPC offered predefined apps: %v", appResp.Candidates)
		}
		if !suppressed && !strings.Contains(joined, "junos-ssh") {
			t.Errorf("committed RPC missing predefined apps: %v", appResp.Candidates)
		}
	}

	// Present-but-nil cell (#3494/#5886 shape), committed only: inject
	// nil zone / interface / unit / zone-pair / policy slots into the
	// ACTIVE config AFTER Commit + ExitConfigure. ExitConfigure is
	// load-bearing: in config mode completionConfig() would draw the
	// CANDIDATE compile (a fresh object without the injections — the
	// 5886 config-mode bypass), so the RPC would complete from a
	// different snapshot than the one mutated and ProvideValues over
	// the active config would disagree for the wrong reason. Out of
	// config mode, completionConfig returns (ActiveConfig, false):
	// the exact object mutated here, catalogueSuppressed=false, so
	// RPC-live must equal ProvideValues(active, hint, path, false)
	// with every nil slot skipped — no panic, no nil name offered.
	// The internal gRPC nil tests only assert no-panic and discard
	// outputs; this cell asserts the outputs.
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New (nil cell): %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(parityRPCBody16160); err != nil {
		t.Fatal(err)
	}
	active, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit (nil cell): %v", err)
	}
	store.ExitConfigure()
	if store.InConfigMode() {
		t.Fatal("nil cell: still in config mode after ExitConfigure (candidate bypass not excluded)")
	}
	if active == nil || store.ActiveConfig() != active {
		t.Fatal("nil cell: ActiveConfig is not the committed object")
	}
	active.Security.Zones["nilzone"] = nil
	active.Interfaces.Interfaces["ge-0/0/9"] = nil
	if iface := active.Interfaces.Interfaces["ge-0/0/0"]; iface != nil {
		iface.Units[9] = nil
	} else {
		t.Fatal("nil cell: fixture missing ge-0/0/0")
	}
	active.Security.Policies = append([]*config.ZonePairPolicies{nil}, active.Security.Policies...)
	for _, zpp := range active.Security.Policies {
		if zpp != nil {
			zpp.Policies = append([]*config.Policy{nil}, zpp.Policies...)
		}
	}
	srv := grpcapi.NewServer("", grpcapi.Config{Store: store})
	ctx := rpcParityCtx16160()
	for _, cell := range rpcCells16160() {
		resp, err := srv.Complete(ctx, &pb.CompleteRequest{Line: cell.line, Pos: int32(len(cell.line)), ConfigMode: true})
		if err != nil {
			t.Fatalf("nil cell %s: Complete: %v", cell.name, err)
		}
		got := liveFromRPC16160(resp)
		want := canonicalRPC16160(config.ProvideValues(active, cell.hint, cell.path, false))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("nil cell %s: RPC live %v != ProvideValues(active) %v (all RPC %v)", cell.name, got, want, resp.Candidates)
		}
		if len(got) == 0 {
			t.Errorf("nil cell %s: no live values via RPC (parity would be vacuous)", cell.name)
		}
		for _, cand := range resp.Candidates {
			if cand == "nilzone" || cand == "ge-0/0/9" {
				t.Errorf("nil cell %s: RPC offered nil slot %q: %v", cell.name, cand, resp.Candidates)
			}
			if cell.name == "unit" && cand == "9" {
				t.Errorf("nil cell unit: RPC offered nil unit 9: %v", resp.Candidates)
			}
		}
	}
}
