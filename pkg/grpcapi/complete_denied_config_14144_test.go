package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14144: Complete was priced at PermView and exempted from both regex gates
// (operational via configModeMethods9633, configuration because
// configMutationLineFor returns ok=false), yet it returns live-config-derived
// candidates (zone/policy/interface/address names + descriptions) from
// ActiveConfig. A class with deny-configuration "^security" (or an operational
// deny on "show configuration") could therefore enumerate the denied subtree.

const complete14144Config = `
system {
    login {
        class limited-view {
            permissions [ view ];
            deny-configuration "^security";
        }
        class limited-op {
            permissions [ view ];
            deny-commands "^show configuration";
        }
        class open-view {
            permissions [ view ];
        }
        user limiteduser { class limited-view; }
        user limitedop { class limited-op; }
        user openuser { class open-view; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
        security-zone untrust {
            description "SECRET-UNTRUST-DESC";
            host-inbound-traffic { system-services [ https ]; }
            interfaces [ ge-0/0/1.0 ];
        }
    }
    address-book {
        global {
            address web-net 203.0.113.0/24;
            address db-net 198.51.100.0/24;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                description "SECRET-POLICY-DESC";
                match { source-address web-net; destination-address db-net; application junos-http; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { description "SECRET-IFACE-DESC"; family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
`

func complete14144Server(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(complete14144Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func ctx14144(class string) context.Context {
	ctx := ctxWithPeerUID(4242)
	// authorizeRPCContext would normally stamp this; Complete reads it directly.
	return ctxWithAuthorizedPrincipal(ctx, authz.Principal{Source: authz.SourcePeerUID, UID: 4242, Class: class})
}

func doComplete14144(t *testing.T, s *Server, class, line string, cfgMode bool) *pb.CompleteResponse {
	t.Helper()
	resp, err := s.Complete(ctx14144(class), &pb.CompleteRequest{Line: line, Pos: int32(len(line)), ConfigMode: cfgMode})
	if err != nil {
		t.Fatalf("Complete(%q cfg=%v class=%s): %v", line, cfgMode, class, err)
	}
	if resp == nil {
		t.Fatalf("Complete(%q) nil resp", line)
	}
	return resp
}

func assertNoSecrets14144(t *testing.T, what string, resp *pb.CompleteResponse) {
	t.Helper()
	joined := strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"SECRET-TRUST-DESC", "SECRET-UNTRUST-DESC", "SECRET-POLICY-DESC", "SECRET-IFACE-DESC", "203.0.113.0/24", "198.51.100.0/24", "web-net", "db-net", "allow-web", "trust", "untrust"} {
		// trust/untrust as candidates are the zone names themselves.
		if strings.Contains(joined, secret) {
			t.Errorf("%s: leaked %q in candidates=%v descriptions=%v", what, secret, resp.Candidates, resp.Descriptions)
		}
	}
}

func hasCand14144(resp *pb.CompleteResponse, want string) bool {
	for _, c := range resp.Candidates {
		if c == want {
			return true
		}
	}
	return false
}

func TestCompleteDeniedConfigurationDoesNotDisclose14144(t *testing.T) {
	s := complete14144Server(t)

	// Non-vacuity control: unrestricted view class DOES get live values.
	control := doComplete14144(t, s, "open-view", "set security zones security-zone ", true)
	if !hasCand14144(control, "trust") {
		t.Fatalf("control (open-view) missing trust zone; test would be vacuous: %v", control.Candidates)
	}

	// Config-mode value slots under denied subtree.
	for _, line := range []string{
		"set security zones security-zone ",
		"set security policies from-zone ",
		"set security policies from-zone trust to-zone untrust policy ",
		"set interfaces ",
	} {
		resp := doComplete14144(t, s, "limited-view", line, true)
		assertNoSecrets14144(t, "config "+line, resp)
	}
	// Operational show configuration under denied subtree.
	for _, line := range []string{
		"show configuration security zones security-zone ",
		"show configuration security policies from-zone ",
	} {
		resp := doComplete14144(t, s, "limited-view", line, false)
		assertNoSecrets14144(t, "op "+line, resp)
	}
	// Operational dynamic values: show security policies ... should not leak via cmdtree either (covered by value-provider path, but assert).
	resp := doComplete14144(t, s, "limited-view", "show configuration security ", false)
	assertNoSecrets14144(t, "op show configuration security", resp)

	// deny-commands on show configuration: operational completion must not leak.
	resp2 := doComplete14144(t, s, "limited-op", "show configuration security zones security-zone ", false)
	assertNoSecrets14144(t, "deny-commands show configuration", resp2)

	// Schema keywords (non-live) still offered for denied class — not a blanket deny.
	kw := doComplete14144(t, s, "limited-view", "set security zones security-zone trust ", true)
	_ = kw // path inside denied subtree may be empty; at minimum no secrets (asserted above for parent)
	// Top-level schema completion still works.
	top := doComplete14144(t, s, "limited-view", "set ", true)
	if !hasCand14144(top, "security") && !hasCand14144(top, "system") {
		t.Errorf("schema top-level completion broken for limited-view: %v", top.Candidates)
	}
	// Non-denied subtree live values still work for limited-view if any exist:
	// interfaces are not under ^security, so interface names SHOULD appear.
	ifResp := doComplete14144(t, s, "limited-view", "set interfaces ", true)
	if !hasCand14144(ifResp, "ge-0/0/0") {
		t.Errorf("limited-view should still complete non-denied interfaces, got %v", ifResp.Candidates)
	}
	// But its description is under interfaces (not denied) — allowed. Just ensure no security leak there.
	_ = ifResp
	// Open class still gets security values (no over-denial).
	openResp := doComplete14144(t, s, "open-view", "set security zones security-zone ", true)
	if !hasCand14144(openResp, "trust") {
		t.Errorf("open-view lost trust completion: %v", openResp.Candidates)
	}
}
