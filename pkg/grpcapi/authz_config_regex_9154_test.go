package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #9154: this listener performed config mutations with NO `*-configuration`
// regex check. The shipped `cli` binary speaks it, which made the DOCUMENTED
// way to administer the box the way around a restriction the operator had
// deliberately configured.

func cfgCfg9154(t *testing.T, denyConfiguration, denyCommands string) *config.Config {
	t.Helper()
	lc := &config.LoginClass{Name: "ops"}
	if denyConfiguration != "" {
		lc.DenyConfiguration = denyConfiguration
		lc.DenyLeavesPresent = append(lc.DenyLeavesPresent, "deny-configuration")
	}
	if denyCommands != "" {
		lc.DenyCommands = denyCommands
		lc.DenyLeavesPresent = append(lc.DenyLeavesPresent, "deny-commands")
	}
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	return cfg
}

func decideConfig9154(t *testing.T, cfg *config.Config, method string, req any) error {
	t.Helper()
	s := &Server{}
	return s.authorizeRPCConfigMutation(cfg, "ops", "/"+serviceName+"/"+method, req)
}

// TestConfigurationDenyIsEnforcedOverRPC9154 is the defect.
//
// The issue's own measurement is reproduced as the CONTROL PAIR: a
// deny-commands-only class was already denied here, which proves the gate
// machinery is live and was simply never asked the configuration question. A
// cell showing only the deny-configuration row could not tell "now enforced"
// from "everything is denied".
func TestConfigurationDenyIsEnforcedOverRPC9154(t *testing.T) {
	const line = "set system root-authentication plain-text-password hunter2"

	t.Run("deny-configuration is enforced", func(t *testing.T) {
		cfg := cfgCfg9154(t, "system root-authentication", "")
		err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: line})
		if err == nil {
			t.Fatal("a Set RPC matching deny-configuration was ALLOWED — the shipped remote " +
				"cli walks the restriction (#9154)")
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the denial leaked the operator's secret: %v", err)
		}
	})

	t.Run("a narrow deny stays narrow", func(t *testing.T) {
		cfg := cfgCfg9154(t, "system root-authentication", "")
		if err := decideConfig9154(t, cfg, "Set",
			&pb.SetRequest{Input: "set system host-name fw1"}); err != nil {
			t.Errorf("an unrelated mutation was denied: %v", err)
		}
	})

	t.Run("a class with no configuration regexes is untouched", func(t *testing.T) {
		cfg := cfgCfg9154(t, "", "")
		if err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: line}); err != nil {
			t.Errorf("a class with no regexes was denied: %v", err)
		}
	})

	t.Run("every mutating verb the Set RPC carries", func(t *testing.T) {
		cfg := cfgCfg9154(t, "system root-authentication", "")
		for _, in := range []string{
			"set system root-authentication plain-text-password x",
			"delete system root-authentication",
			"deactivate system root-authentication",
			"activate system root-authentication",
		} {
			if err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: in}); err == nil {
				t.Errorf("%q was ALLOWED — the Set RPC prefix-routes every mutating verb, so "+
					"each has to be gated", in)
			}
		}
	})

	t.Run("the Delete RPC carries a bare path", func(t *testing.T) {
		cfg := cfgCfg9154(t, "system root-authentication", "")
		// Its Input is the PATH, not a verb-led line, so the gate supplies the
		// verb. Without that the regex sees `system root-authentication` with
		// no verb and configMutationPath declines to gate it at all.
		if err := decideConfig9154(t, cfg, "Delete",
			&pb.DeleteRequest{Input: "system root-authentication"}); err == nil {
			t.Error("a Delete RPC matching deny-configuration was ALLOWED")
		}
	})

	t.Run("a non-mutating RPC is not gated", func(t *testing.T) {
		cfg := cfgCfg9154(t, "system", "")
		if err := decideConfig9154(t, cfg, "GetStatus", &pb.GetStatusRequest{}); err != nil {
			t.Errorf("GetStatus was gated by a CONFIGURATION regex: %v", err)
		}
	})
}

// TestConfigMutationGateIsWiredIntoTheInterceptor9154 binds the WIRING, not the
// function.
//
// The cells above drive authorizeRPCConfigMutation directly, and a mutation
// removing its CALL SITE in the interceptor left every one of them green — the
// gate was correct and unreachable, which is the state the whole issue is about.
// A gate nothing calls is exactly what #9154 found on this surface.
//
// This reads the interceptor's source and requires the call to be present,
// which is the cheapest check that survives the function being renamed or the
// call being deleted. It is deliberately not a behavioural test: standing up a
// full authorized gRPC connection to assert one middleware line would take a
// fixture larger than the thing under test, and the failure mode being guarded
// is "someone deleted the line", not "the line behaves subtly differently".
func TestConfigMutationGateIsWiredIntoTheInterceptor9154(t *testing.T) {
	src, err := os.ReadFile("authz.go")
	if err != nil {
		t.Fatalf("read authz.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "authorizeRPCConfigMutation(") {
		t.Fatal("the interceptor does not call authorizeRPCConfigMutation — the " +
			"`*-configuration` regexes are unreachable on this surface again, which is " +
			"exactly the #9154 defect")
	}
	// It must sit beside the operational gate, so a reader cannot conclude one
	// is the whole authorization story.
	if !strings.Contains(body, "authorizeRPCCommand(") {
		t.Fatal("the operational gate call vanished; this cell's premise no longer holds")
	}
}

// #13628: admission and Server.Set must recognize the same whitespace-delimited
// annotate verb. Otherwise a tab bypasses the deny path while the handler still
// applies the annotation to the denied node.
func TestAnnotateAdmissionMatchesHandlerWhitespace13628(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, `system {
    login {
        class ops {
            permissions [ configure view ];
            deny-configuration "^system host-name$";
        }
        user opuser { class ops; }
    }
    host-name before;
    name-server { 9.9.9.9; }
}`)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	s := &Server{store: store}
	for _, sep := range []string{" ", "\t"} {
		t.Run(map[string]string{" ": "space", "\t": "tab"}[sep], func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				path   string
				denied bool
			}{
				{name: "denied subtree", path: "system host-name", denied: true},
				{name: "allowed subtree", path: "system name-server 9.9.9.9"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req := &pb.SetRequest{Input: "annotate" + sep + tc.path + ` "note"`}
					called := false
					_, err := s.principalUnaryInterceptor(
						ctxWithPeerUID(authzUIDOperator), req,
						&grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_Set_FullMethodName},
						func(ctx context.Context, request any) (any, error) {
							called = true
							return s.Set(ctx, request.(*pb.SetRequest))
						},
					)
					if tc.denied {
						if status.Code(err) != codes.PermissionDenied || called {
							t.Fatalf("denied annotate err=%v handlerCalled=%v, want PermissionDenied and no handler",
								err, called)
						}
						return
					}
					if err != nil || !called {
						t.Fatalf("allowed annotate err=%v handlerCalled=%v", err, called)
					}
				})
			}
		})
	}
	for _, sep := range []string{" ", "\t"} {
		t.Run(map[string]string{" ": "space", "\t": "tab"}[sep]+" embedded quotes", func(t *testing.T) {
			req := &pb.SetRequest{
				Input: "annotate" + sep + `system host-name "say "hi" team"`,
			}
			called := false
			_, err := s.principalUnaryInterceptor(
				ctxWithPeerUID(authzUIDOperator), req,
				&grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_Set_FullMethodName},
				func(ctx context.Context, request any) (any, error) {
					called = true
					return s.Set(ctx, request.(*pb.SetRequest))
				},
			)
			if status.Code(err) != codes.PermissionDenied || called {
				t.Fatalf("embedded-quote annotate err=%v handlerCalled=%v, want PermissionDenied and no handler",
					err, called)
			}
		})
	}
}
