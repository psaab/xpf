package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15994 fold (gRPC arm): the denied content lives ONLY as an applied
// group body, so the literal `groups G …` spelling was the leak. The
// directed read is refused (premise inside the test); every alias
// spelling on every verb must refuse too, and price+render share the
// priced snapshot (#16096 transport preserved).

const groups15994GrpcConfig = `
system {
    host-name groups-15994;
    login {
        user limiteduser { class limited-view; }
        user opuser { class op-view; }
        class limited-view {
            permissions [ view configure ];
            deny-configuration "^security";
        }
        class op-view {
            permissions [ view configure ];
            deny-commands "^show configuration security";
        }
    }
}
groups {
    G {
        security {
            zones {
                security-zone trust {
                    description "GROUP-SEC-MARKER-15994";
                    interfaces [ ge-0/0/0.0 ];
                }
            }
        }
        system { host-name group-h-15994; }
    }
}
apply-groups G;
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

const groups15994Passwd = `root:x:0:0:root:/root:/bin/bash
limiteduser:x:4270:4270::/home/limiteduser:/bin/bash
opuser:x:4271:4271::/home/opuser:/bin/bash
`

const (
	uidLimited15994 = 4270
	uidOp15994      = 4271
)

func groups15994Server(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(groups15994Passwd), 0o600); err != nil {
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
	commit(groups15994GrpcConfig)
	commit(strings.Replace(groups15994GrpcConfig, "groups-15994", "groups-15994-b", 1))
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func TestGroupsReadGate15994(t *testing.T) {
	s := groups15994Server(t)
	ctx := ctxWithPeerUID(uidLimited15994)

	// Premise: the directed read is refused.
	wantDenied14707(t, "ShowConfig [security] (directed baseline)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))

	// Alias spellings refuse on every verb.
	for _, path := range [][]string{
		{"groups", "G", "security"},
		{"groups"},
		{"groups", "G"},
	} {
		wantDenied14707(t, "ShowConfig "+strings.Join(path, " "),
			s.authorizeRPC(ctx, show14707Method("ShowConfig"),
				&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: path}))
		wantDenied14707(t, "ShowCompare "+strings.Join(path, " "),
			s.authorizeRPC(ctx, show14707Method("ShowCompare"),
				&pb.ShowCompareRequest{Path: path}))
	}
	wantDenied14707(t, "ShowCompare unscoped (denied in both arms)",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"), &pb.ShowCompareRequest{}))
	wantDenied14707(t, "ShowRollback 1 [groups G]",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Path: []string{"groups", "G"}}))
	wantDenied14707(t, "ShowRollback 1 unscoped",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1}))
	wantDenied14707(t, "ShowRollback 1 [groups G security] display set",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Path: []string{"groups", "G", "security"}, Format: pb.ConfigFormat_SET}))
	// Whole-tree export of the denied subtree's tree (whole ShowConfig,
	// no path) is refused for the config-restricted class.
	wantDenied14707(t, "ShowConfig whole-tree",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}))

	// Controls stay admitted.
	for _, tc := range []struct {
		method string
		req    any
	}{
		{"ShowConfig", &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"groups", "G", "system"}}},
		{"ShowConfig", &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"system"}}},
		{"ShowCompare", &pb.ShowCompareRequest{Path: []string{"groups", "G", "system"}}},
		{"ShowRollback", &pb.ShowRollbackRequest{N: 1, Path: []string{"system"}}},
		{"ShowRollback", &pb.ShowRollbackRequest{N: 1, Path: []string{"groups", "G", "system"}}},
	} {
		if err := s.authorizeRPC(ctx, show14707Method(tc.method), tc.req); err != nil {
			t.Errorf("%s control was refused (#15994): %v", tc.method, err)
		}
	}

	// Op-only class: the alias must not outrun the effective command.
	ctxOp := ctxWithPeerUID(uidOp15994)
	for _, path := range [][]string{
		{"groups", "G", "security"},
		{"groups"},
		{"groups", "G"},
	} {
		wantDenied14707(t, "op ShowConfig "+strings.Join(path, " "),
			s.authorizeRPC(ctxOp, show14707Method("ShowConfig"),
				&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: path}))
	}
	if err := s.authorizeRPC(ctxOp, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"groups", "G", "system"}}); err != nil {
		t.Errorf("op control refused: %v", err)
	}

	// Snapshot identity: handler output for an admitted sibling comes
	// from the priced snapshot (no group marker leaks).
	ctx2, err := s.authorizeRPCContext(ctx, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"groups", "G", "system"}})
	if err != nil {
		t.Fatalf("authorize groups G system: %v", err)
	}
	resp, herr := s.ShowConfig(ctx2, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"groups", "G", "system"}})
	if herr != nil {
		t.Fatalf("ShowConfig handler: %v", herr)
	}
	if strings.Contains(resp.Output, "GROUP-SEC-MARKER-15994") {
		t.Errorf("snapshot render leaked the denied group body:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, "group-h-15994") {
		t.Errorf("snapshot render lost the allowed body:\n%s", resp.Output)
	}
}
