package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16080 fold (1): the gRPC fast path bypassed the credential surcharge
// for a no-regex configure class. authorizeRPCConfigMutation calls the
// shared AuthorizeConfigMutation (which enforces the fence) for
// Set/Delete, but authorizeRPCLoadAndRollback returned nil at
// `if !restricted { return nil }` before AuthorizeConfigLoad/Rollback
// were ever called — so Load/Rollback carried credential writes for
// exactly the limited class the issue names. It now routes surcharged
// classes through the shared decision as well. The Set/Delete ancestor
// leg (fold 2) is pinned here too: `Delete system` names no fence
// prefix yet deletes the credential subtree beneath it.
//
// RED-on-revert: dropping the CredentialSurchargeCheck16080 arm from
// authorizeRPCLoadAndRollback makes the Load/Rollback cells return nil;
// dropping the ancestor arm in pkg/config makes the Delete cells pass.

func cfg16080grpc(t *testing.T) *config.Config {
	t.Helper()
	lc := &config.LoginClass{
		Name:              "limited",
		Permissions:       []string{"configure", "view"},
		MappedPermissions: []config.LoginClassPermission{config.PermConfig, config.PermView},
	}
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	return cfg
}

func TestGRPCCredentialSurchargeNoRegexClass16080(t *testing.T) {
	cfg := cfg16080grpc(t)
	s := &Server{}

	// Load / rollback legs (the fast-path bypass).
	for _, tc := range []struct {
		name, label string
		req         any
	}{
		{"load merge credential", "Load", &pb.LoadRequest{Mode: "merge", Content: "set system root-authentication plain-text-password hunter2-16080"}},
		{"load merge login", "Load", &pb.LoadRequest{Mode: "merge", Content: "set system login user eve class super-user"}},
		{"load override", "Load", &pb.LoadRequest{Mode: "override", Content: "set system host-name ok-16080"}},
		{"load rescue", "Load", &pb.LoadRequest{Mode: "rescue"}},
		{"rollback 1", "Rollback", &pb.RollbackRequest{N: 1}},
	} {
		if err := s.authorizeRPCConfigMutation(cfg, "limited", method9633(tc.label), tc.req); err == nil {
			t.Errorf("%s ALLOWED for no-regex configure class over gRPC; credential surcharge bypassed (#16080 fold 1)", tc.name)
		}
	}
	// Controls through the same entry points.
	for _, tc := range []struct {
		name, label string
		req         any
	}{
		{"load merge host-name", "Load", &pb.LoadRequest{Mode: "merge", Content: "set system host-name ok-16080"}},
		{"rollback 0", "Rollback", &pb.RollbackRequest{N: 0}},
		{"set host-name", "Set", &pb.SetRequest{Input: "set system host-name ok-16080"}},
	} {
		if err := s.authorizeRPCConfigMutation(cfg, "limited", method9633(tc.label), tc.req); err != nil {
			t.Errorf("%s refused for limited class, want allowed: %v", tc.name, err)
		}
	}
	// Set/Delete credential + ancestor legs (shared decision, fold 2).
	for _, tc := range []struct {
		name, label string
		req         any
	}{
		{"set root-auth", "Set", &pb.SetRequest{Input: "set system root-authentication plain-text-password hunter2-16080"}},
		{"set api-auth", "Set", &pb.SetRequest{Input: "set system services web-management api-auth user admin password correct-horse-16080"}},
		{"delete system (ancestor)", "Delete", &pb.DeleteRequest{Input: "system"}},
		{"delete system login (ancestor)", "Delete", &pb.DeleteRequest{Input: "system login"}},
		{"delete web-management via Set verb", "Set", &pb.SetRequest{Input: "delete system services web-management"}},
	} {
		err := s.authorizeRPCConfigMutation(cfg, "limited", method9633(tc.label), tc.req)
		if err == nil {
			t.Errorf("%s ALLOWED for no-regex configure class over gRPC (#16080)", tc.name)
		} else if strings.Contains(err.Error(), "hunter2-16080") {
			t.Errorf("%s denial leaked the secret: %v", tc.name, err)
		}
	}
}
