package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15995 (A8-01, gRPC arm): deny-configuration "^security ipsec" was
// evaluated only on the joined requested path, so ShowConfig{["security"]}
// was admitted and the handler rendered the whole security subtree —
// ipsec included. Same for scoped ShowCompare / ShowRollback. The gate
// now prices every rendered descendant of the target/slot trees.
//
// Fixture: ancestor-view class (deny ^security ipsec, view+configure),
// config with security{zones,ipsec,policies} + interfaces. Rollback slot 1
// and a staged candidate carry the same shape so compare/rollback arms
// have denied descendants to disclose.

const ancestor15995Config = `
system {
    host-name ancestor-15995;
    login {
        user ancuser { class ancestor-view; }
        user openuser { class open-view; }
        class ancestor-view {
            permissions [ view configure ];
            deny-configuration "^security ipsec";
        }
        class open-view {
            permissions [ view configure ];
        }
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
    policies {
        from-zone trust to-zone trust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

const ancestor15995Passwd = `root:x:0:0:root:/root:/bin/bash
ancuser:x:4260:4260::/home/ancuser:/bin/bash
openuser:x:4261:4261::/home/openuser:/bin/bash
`

const (
	uidAncestor15995 = 4260
	uidOpen15995     = 4261
)

func ancestor15995Server(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(ancestor15995Passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

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
	commit(ancestor15995Config)
	// Slot 1 = first config (with the denied ipsec descendant).
	commit(strings.Replace(ancestor15995Config, "ancestor-15995", "ancestor-15995-b", 1))
	// Stage a candidate so scoped compares have both arms.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure candidate: %v", err)
	}
	if err := store.SetFromInput("security zones security-zone trust description CANDIDATE-15995"); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func TestShowConfigAncestorDeniedDescendant15995(t *testing.T) {
	s := ancestor15995Server(t)
	ctx := ctxWithPeerUID(uidAncestor15995)

	// The leak: ancestor admitted pre-fix, renders denied ipsec.
	wantDenied14707(t, "ShowConfig ACTIVE [security] (deny ^security ipsec; renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowConfig CANDIDATE [security] (deny ^security ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowConfig ACTIVE [security] display set (deny ^security ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}, Format: pb.ConfigFormat_SET}))
	// Direct denied path: control (already denied pre-fix).
	wantDenied14707(t, "ShowConfig ACTIVE [security ipsec] (control)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "ipsec"}}))

	// Allowed siblings / unrelated subtrees stay admitted.
	for _, path := range [][]string{
		{"security", "zones"},
		{"security", "policies"},
		{"interfaces"},
		{"system"},
	} {
		if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: path}); err != nil {
			t.Errorf("ShowConfig ACTIVE %v must stay admitted: %v", path, err)
		}
	}

	// End-to-end: handler output through the admitted context must not
	// carry the denied descendant for the allowed sibling, and the
	// ancestor request must never reach the handler admitted.
	ctx2, err := s.authorizeRPCContext(ctxWithPeerUID(uidAncestor15995), show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "zones"}})
	if err != nil {
		t.Fatalf("authorize zones context: %v", err)
	}
	resp, herr := s.ShowConfig(ctx2, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "zones"}})
	if herr != nil {
		t.Fatalf("ShowConfig zones handler: %v", herr)
	}
	if !strings.Contains(resp.Output, "ZONE-DESC-15995") {
		t.Errorf("zones render lost its content:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "ipsec") {
		t.Errorf("zones render disclosed ipsec:\n%s", resp.Output)
	}
}

func TestShowCompareRollbackAncestorDeniedDescendant15995(t *testing.T) {
	s := ancestor15995Server(t)
	ctx := ctxWithPeerUID(uidAncestor15995)

	wantDenied14707(t, "ShowCompare [security] candidate-vs-active (renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"),
			&pb.ShowCompareRequest{Path: []string{"security"}}))
	wantDenied14707(t, "ShowCompare [security] rollback-vs-candidate",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"),
			&pb.ShowCompareRequest{RollbackN: 1, Path: []string{"security"}}))
	wantDenied14707(t, "ShowCompare [security] active-baseline",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"),
			&pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true, Path: []string{"security"}}))
	wantDenied14707(t, "ShowRollback 1 [security] (renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Path: []string{"security"}}))
	wantDenied14707(t, "ShowRollback 0 [security] (active renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 0, Path: []string{"security"}}))

	for _, tc := range []struct {
		what string
		m    string
		req  any
	}{
		{"ShowCompare [security zones]", "ShowCompare", &pb.ShowCompareRequest{Path: []string{"security", "zones"}}},
		{"ShowRollback 1 [security zones]", "ShowRollback", &pb.ShowRollbackRequest{N: 1, Path: []string{"security", "zones"}}},
		{"ShowRollback 1 [interfaces]", "ShowRollback", &pb.ShowRollbackRequest{N: 1, Path: []string{"interfaces"}}},
	} {
		if err := s.authorizeRPC(ctx, show14707Method(tc.m), tc.req); err != nil {
			t.Errorf("%s must stay admitted: %v", tc.what, err)
		}
	}

	// Unrestricted control: the ancestor read is admitted.
	ctxOpen := ctxWithPeerUID(uidOpen15995)
	if err := s.authorizeRPC(ctxOpen, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}); err != nil {
		t.Errorf("open-view ShowConfig [security] must stay admitted: %v", err)
	}
}
