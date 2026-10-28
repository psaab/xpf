package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// testPolicyStore builds an active config from a raw Junos override and
// returns a configstore.Store with it committed, for driving the gRPC
// ShowText "test-policy:" handler.
func testPolicyStore(t *testing.T, override string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(override); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func showTestPolicyOutput(t *testing.T, store *configstore.Store, topic string) string {
	t.Helper()
	s := &Server{store: store}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
	if err != nil {
		t.Fatalf("ShowText(%q) error = %v", topic, err)
	}
	return resp.GetOutput()
}

// TestShowTestPolicyAgreesWithRuntimeOnFixedCases is the #3103 fail-on-revert
// guard. Before #3103 the gRPC ShowText "test-policy:" handler used a bespoke
// shadow matcher (matchShowPolicyAddr / matchShowPolicyApp) that diverged from
// the runtime evaluator. Each sub-case below is one the OLD matcher got wrong:
//
//   - predefined-app permit: the old matcher read only
//     cfg.Applications.Applications, so a predefined Junos application
//     (junos-http) never matched and the case fell through to "Default deny";
//   - global-policy fallback: the old matcher looped only the zone-pair sets,
//     never cfg.Security.GlobalPolicies, so a global policy was reported as
//     "Default deny";
//   - default-policy permit-all: the old matcher hard-coded "Default deny" on
//     a miss even when `default-policy permit-all` was configured.
//
// Routing through pkg/policymatch (the same simulator the REST/gRPC
// MatchPolicies and CLI surfaces use since #3042) makes ShowText agree with
// the runtime. We assert the rendered ShowText output AND cross-check it
// against policymatch.Match directly so reverting showTestPolicy to the
// bespoke matcher turns this RED.
func TestShowTestPolicyAgreesWithRuntimeOnFixedCases(t *testing.T) {
	cases := []struct {
		name       string
		override   string
		topic      string
		wantSubstr []string // all must be present in the ShowText output
		notSubstr  []string // none may be present
		// policymatch cross-check inputs (the runtime ground truth):
		query      policymatch.Query
		wantAction config.PolicyAction
	}{
		{
			name: "predefined-app permit",
			override: `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-http {
                match { source-address any; destination-address any; application junos-http; }
                then { permit; }
            }
        }
    }
}
`,
			// junos-http is a PREDEFINED application (tcp/80). The old matcher
			// only knew about user applications, so it missed this entirely.
			topic:      "test-policy:from=trust,to=untrust,src=10.0.1.1,dst=10.0.2.1,port=80,proto=tcp",
			wantSubstr: []string{"Policy match:", "Policy:    allow-http", "Action:    permit"},
			notSubstr:  []string{"Default", "global"},
			query: policymatch.Query{
				FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: policymatch.PortPtr(80),
			},
			wantAction: config.PolicyPermit,
		},
		{
			name: "global-policy fallback",
			override: `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        global {
            policy global-allow {
                match { source-address any; destination-address any; application junos-http; }
                then { permit; }
            }
        }
    }
}
`,
			// Only a global policy exists, and it matches on a PREDEFINED app
			// (junos-http). The old matcher's global loop used the user-apps-only
			// matchShowPolicyApp, so junos-http never matched and it reported
			// "Default deny". The new path resolves predefined apps and matches
			// the global rule.
			topic:      "test-policy:from=trust,to=untrust,src=10.0.1.1,dst=10.0.2.1,port=80,proto=tcp",
			wantSubstr: []string{"Policy match (global):", "Policy:    global-allow", "Action:    permit"},
			notSubstr:  []string{"Default"},
			query: policymatch.Query{
				FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: policymatch.PortPtr(80),
			},
			wantAction: config.PolicyPermit,
		},
		{
			name: "default-policy permit-all",
			override: `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy permit-all;
    }
}
`,
			// No matching policy: the runtime applies the configured
			// default-policy (permit-all). The old matcher hard-coded
			// "Default deny" here — the opposite verdict.
			topic:      "test-policy:from=trust,to=untrust,src=10.0.1.1,dst=10.0.2.1,port=80,proto=tcp",
			wantSubstr: []string{"Default permit"},
			notSubstr:  []string{"Default deny", "Policy match"},
			query: policymatch.Query{
				FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: policymatch.PortPtr(80),
			},
			wantAction: config.PolicyPermit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := testPolicyStore(t, tc.override)
			out := showTestPolicyOutput(t, store, tc.topic)
			for _, want := range tc.wantSubstr {
				if !strings.Contains(out, want) {
					t.Errorf("ShowText output missing %q\n--- got ---\n%s", want, out)
				}
			}
			for _, bad := range tc.notSubstr {
				if strings.Contains(out, bad) {
					t.Errorf("ShowText output unexpectedly contains %q\n--- got ---\n%s", bad, out)
				}
			}

			// Cross-check against the shared simulator (the runtime ground
			// truth). The ShowText handler MUST agree with it.
			cfg := store.ActiveConfig()
			res := policymatch.Match(cfg, tc.query)
			if res.Action != tc.wantAction {
				t.Errorf("policymatch action = %v, want %v", res.Action, tc.wantAction)
			}
			if got := policymatch.ActionString(res.Action); !strings.Contains(out, got) {
				t.Errorf("ShowText output %q does not contain runtime action %q", out, got)
			}
		})
	}
}
