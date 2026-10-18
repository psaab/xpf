package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14707: ShowConfig, ShowCompare and ShowRollback bypass
// allow-configuration / deny-configuration subtree restrictions and
// path/format-scoped deny-commands rules.
//
// The handlers discard ctx and render the full (secret-redacted) tree;
// authorizeRPCCommand flattens them to the bare "show configuration" and
// authorizeRPCConfigMutation returns nil for them. A class with
// deny-configuration "^security", deny-commands "^show configuration
// security", deny-commands "display set", or an allow-configuration
// allowlist that excludes security still received the security subtree.

const showRead14707Config = `
system {
    host-name show-read-14707;
    login {
        user opsuser {
            class read-only;
        }
        user limiteduser {
            class limited-view;
        }
        user allowlistuser {
            class allowlist-view;
        }
        user dencmduser {
            class deny-cmd;
        }
        user setfmtuser {
            class deny-setfmt;
        }
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class allowlist-view {
            permissions [ view configure ];
            allow-configuration "system";
        }
        class deny-cmd {
            permissions [ view configure ];
            deny-commands "^show configuration security";
        }
        class deny-setfmt {
            permissions [ view configure ];
            deny-commands "display set";
        }
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
    address-book {
        global {
            address web-net 203.0.113.0/24;
        }
    }
    policies {
        from-zone trust to-zone trust {
            policy allow-web {
                description "SECRET-POLICY-DESC-14707";
                match { source-address web-net; destination-address web-net; application junos-http; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

const showRead14707Passwd = `root:x:0:0:root:/root:/bin/bash
opsuser:x:4242:4242::/home/opsuser:/bin/bash
limiteduser:x:4246:4246::/home/limiteduser:/bin/bash
allowlistuser:x:4247:4247::/home/allowlistuser:/bin/bash
dencmduser:x:4248:4248::/home/dencmduser:/bin/bash
setfmtuser:x:4249:4249::/home/setfmtuser:/bin/bash
`

const (
	uidLimited14707   = 4246
	uidAllowlist14707 = 4247
	uidDenyCmd14707   = 4248
	uidDenySet14707   = 4249
)

// showRead14707Server commits showRead14707Config, seeds one rollback slot
// by committing a host-name change, then stages a candidate that adds a
// security marker so ShowCompare has denied content to disclose.
func writePasswd14707(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(showRead14707Passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

func showRead14707Server(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	writePasswd14707(t, path)

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
	commit(showRead14707Config)
	// Second commit so rollback slot 1 holds the first config.
	commit(strings.Replace(showRead14707Config, "show-read-14707", "show-read-14707-b", 1))

	// Stage a candidate carrying a denied-subtree marker.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure candidate: %v", err)
	}
	if err := store.SetFromInput("security zones security-zone trust description CANDIDATE-MARKER-14707"); err != nil {
		t.Fatalf("stage candidate marker: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func show14707Method(m string) string {
	return "/" + serviceName + "/" + m
}

func wantDenied14707(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s was ALLOWED, want PermissionDenied (#14707)", what)
		return
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("%s denial code = %s, want PermissionDenied (err=%v)", what, status.Code(err), err)
	}
}

func TestShowConfigDenyConfigurationConcealsSubtree14707(t *testing.T) {
	s := showRead14707Server(t)
	ctx := ctxWithPeerUID(uidLimited14707)

	// Path-scoped read of the denied subtree.
	wantDenied14707(t, "ShowConfig ACTIVE security (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))
	// Whole-tree read would render the denied subtree too.
	wantDenied14707(t, "ShowConfig ACTIVE whole-tree (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}))
	// Candidate arm as well.
	wantDenied14707(t, "ShowConfig CANDIDATE whole-tree (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE}))
	wantDenied14707(t, "ShowConfig CANDIDATE security (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE, Path: []string{"security"}}))
	// ShowCompare diffs candidate (with denied marker) against active/rollback.
	wantDenied14707(t, "ShowCompare candidate-vs-active (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"), &pb.ShowCompareRequest{RollbackN: 0}))
	wantDenied14707(t, "ShowCompare rollback-vs-candidate (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"), &pb.ShowCompareRequest{RollbackN: 1}))
	// ShowRollback renders a whole historical tree containing security.
	wantDenied14707(t, "ShowRollback 1 (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"), &pb.ShowRollbackRequest{N: 1}))
	wantDenied14707(t, "ShowRollback 1 display set (deny-configuration ^security)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"), &pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_SET}))

	// Controls: allowed subtree and unrelated commands stay admitted.
	if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"system"}}); err != nil {
		t.Errorf("ShowConfig ACTIVE system must stay admitted for limited-view: %v", err)
	}
	if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"interfaces"}}); err != nil {
		t.Errorf("ShowConfig ACTIVE interfaces must stay admitted for limited-view: %v", err)
	}
}

func TestShowConfigAllowConfigurationAllowlistConceals14707(t *testing.T) {
	s := showRead14707Server(t)
	ctx := ctxWithPeerUID(uidAllowlist14707)
	// allow-configuration "system" is an allowlist: security is not permitted.
	wantDenied14707(t, "ShowConfig ACTIVE security (allow-configuration system)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowConfig ACTIVE whole-tree (allow-configuration system)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}))
	wantDenied14707(t, "ShowRollback 1 (allow-configuration system)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"), &pb.ShowRollbackRequest{N: 1}))
	if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"system"}}); err != nil {
		t.Errorf("ShowConfig ACTIVE system must stay admitted under allow-configuration system: %v", err)
	}
}

func TestShowConfigPathScopedDenyCommandsConceals14707(t *testing.T) {
	s := showRead14707Server(t)
	ctx := ctxWithPeerUID(uidDenyCmd14707)
	wantDenied14707(t, "ShowConfig ACTIVE security (deny-commands ^show configuration security)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowConfig ACTIVE security zones (deny-commands ^show configuration security)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "zones"}}))
	// Whole-tree and other subtrees are not named by that deny.
	if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"system"}}); err != nil {
		t.Errorf("ShowConfig ACTIVE system must stay admitted under path-scoped deny-commands: %v", err)
	}
	if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}); err != nil {
		t.Errorf("ShowConfig ACTIVE whole-tree must stay admitted under ^show configuration security: %v", err)
	}
}

func TestShowConfigFormatScopedDenyCommandsConceals14707(t *testing.T) {
	s := showRead14707Server(t)
	ctx := ctxWithPeerUID(uidDenySet14707)
	wantDenied14707(t, "ShowConfig ACTIVE display set (deny-commands display set)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Format: pb.ConfigFormat_SET}))
	wantDenied14707(t, "ShowRollback display set (deny-commands display set)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_SET}))
	// Hierarchical form is not named by the deny.
	if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Format: pb.ConfigFormat_HIERARCHICAL}); err != nil {
		t.Errorf("ShowConfig hierarchical must stay admitted under deny display set: %v", err)
	}
	if err := s.authorizeRPC(ctx, show14707Method("ShowRollback"),
		&pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_HIERARCHICAL}); err != nil {
		t.Errorf("ShowRollback hierarchical must stay admitted under deny display set: %v", err)
	}
}

func TestShowConfigUnrestrictedAndSuperuserUnaffected14707(t *testing.T) {
	s := showRead14707Server(t)
	// read-only class carries no regexes.
	ctx := ctxWithPeerUID(authzUIDReadOnly)
	for _, tc := range []struct {
		what string
		m    string
		req  any
	}{
		{"ShowConfig ACTIVE security", "ShowConfig", &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}},
		{"ShowConfig ACTIVE whole", "ShowConfig", &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}},
		{"ShowRollback", "ShowRollback", &pb.ShowRollbackRequest{N: 1}},
	} {
		if err := s.authorizeRPC(ctx, show14707Method(tc.m), tc.req); err != nil {
			t.Errorf("%s must stay admitted for unrestricted read-only: %v", tc.what, err)
		}
	}
	// Superuser is exempt from regex gates.
	if err := s.authorizeRPC(ctxWithPeerUID(0), show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}); err != nil {
		t.Errorf("superuser ShowConfig must stay admitted: %v", err)
	}
}

// End-to-end: the handler must not render denied content when reached
// through the interceptor-stamped context. This drives authorizeRPCContext
// (the production unary path) and then the handler with its output.
func TestShowConfigHandlerDoesNotRenderDeniedSubtree14707(t *testing.T) {
	s := showRead14707Server(t)
	ctx, err := s.authorizeRPCContext(ctxWithPeerUID(uidLimited14707), show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE})
	if err == nil {
		resp, herr := s.ShowConfig(ctx, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE})
		if herr != nil {
			t.Fatalf("ShowConfig handler: %v", herr)
		}
		if strings.Contains(resp.Output, "SECRET-TRUST-DESC-14707") ||
			strings.Contains(resp.Output, "security-zone trust") ||
			strings.Contains(resp.Output, "203.0.113.0/24") {
			t.Errorf("whole-tree ShowConfig rendered denied security subtree:\n%s", resp.Output)
		}
	} // gate denial also satisfies the assertion
}
