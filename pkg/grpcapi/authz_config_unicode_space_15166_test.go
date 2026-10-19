package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #15166 (B23-01): a Unicode space after deactivate/activate defeated the
// *-configuration gate on gRPC but not the executor.
//
// The gate lexes with the config lexer, which accepts only ASCII
// ' ' '\t' '\n' '\r' as whitespace and rejects bytes >= 0x80 as identifier
// characters. For "deactivate\u00a0system login" the lexer therefore
// returns only [deactivate] and stops on a TokenError, so
// authorizeConfigMutationDepth9939 saw a verb with no lexed path and
// returned "not gated".
//
// Server.Set, however, routes with strings.Fields, which is Unicode-aware:
// it splits the same input into [deactivate system login] and called
// DeactivateFromInputAsPlantClass, whose store lexer re-parses
// "deactivate system login" (joined with ASCII spaces by applyEditLine) and
// deactivated the real path. A path-restricted class could thus deactivate
// its own deny/allow regex leaf and then commit unrestricted configuration.
//
// Acceptance: NBSP/EM/IDEOGRAPHIC/NNBSP cells for deactivate and activate
// return PermissionDenied with handler=false; the end-to-end cell cannot
// commit a deactivated regex leaf; ASCII and TAB controls are unchanged.

var unicodeSpaces15166 = []struct {
	name string
	sep  string
}{
	{"NBSP", "\u00a0"},
	{"EM SPACE", "\u2003"},
	{"IDEOGRAPHIC SPACE", "\u3000"},
	{"NNBSP", "\u202f"},
}

// cfgUnicode15166 builds a class restricted by allow-configuration to
// ^system services (an allowlist). Deactivating "system login" — which
// carries the class definition itself — is outside the allow, exactly the
// self-deactivation leg in the report.
func cfgUnicode15166(t *testing.T) *config.Config {
	t.Helper()
	// Reuse the 9154 helper shape but with an allow list, built directly so
	// this file does not depend on deny-only helper semantics.
	lc := &config.LoginClass{Name: "ops"}
	lc.AllowConfiguration = "^system services"
	lc.AllowLeavesPresent = append(lc.AllowLeavesPresent, "allow-configuration")
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	return cfg
}

func TestUnicodeSpaceDeactivateActivateDeniedAtGate15166(t *testing.T) {
	cfg := cfgUnicode15166(t)
	// Also cover a deny-configuration class: deny on the exact path.
	denyCfg := cfgCfg9154(t, "^system login$", "")

	for _, verb := range []string{"deactivate", "activate"} {
		for _, sp := range unicodeSpaces15166 {
			input := verb + sp.sep + "system login"
			t.Run(verb+"/"+sp.name+"/allow", func(t *testing.T) {
				if err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: input}); err == nil {
					t.Fatalf("%q was ALLOWED under allow-configuration %q; the gate lexed only the verb while strings.Fields in the handler splits on the Unicode space (#15166)", input, "^system services")
				}
			})
			t.Run(verb+"/"+sp.name+"/deny", func(t *testing.T) {
				if err := decideConfig9154(t, denyCfg, "Set", &pb.SetRequest{Input: input}); err == nil {
					t.Fatalf("%q was ALLOWED under deny-configuration %q (#15166)", input, "^system login$")
				}
			})
		}
		// Direct gate spelling (config surface) must also fail closed.
		for _, sp := range unicodeSpaces15166 {
			line := verb + sp.sep + "system login"
			t.Run(verb+"/"+sp.name+"/direct", func(t *testing.T) {
				if err := config.AuthorizeConfigMutation(cfg, "ops", nil, line); err == nil {
					t.Fatalf("AuthorizeConfigMutation(%q) was ALLOWED; a verb whose lexer stopped on an error token with no lexed path must be denied for a regex-restricted class (#15166)", line)
				}
			})
		}
	}
}

func TestUnicodeSpaceControlsUnchanged15166(t *testing.T) {
	cfg := cfgUnicode15166(t)
	denyCfg := cfgCfg9154(t, "^system login$", "")
	// ASCII and TAB controls: denied paths stay denied, allowed paths pass.
	for _, sep := range []string{" ", "\t"} {
		name := "space"
		if sep == "\t" {
			name = "tab"
		}
		for _, verb := range []string{"deactivate", "activate"} {
			denied := verb + sep + "system login"
			if err := decideConfig9154(t, denyCfg, "Set", &pb.SetRequest{Input: denied}); err == nil {
				t.Errorf("%s control %q was ALLOWED under deny (#15166)", name, denied)
			}
			allowed := verb + sep + "system services ssh"
			if err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: allowed}); err != nil {
				t.Errorf("%s control %q was DENIED though inside allow: %v (#15166)", name, allowed, err)
			}
			if err := decideConfig9154(t, denyCfg, "Set", &pb.SetRequest{Input: allowed}); err != nil {
				t.Errorf("%s control %q was DENIED under unrelated deny: %v (#15166)", name, allowed, err)
			}
		}
	}
	// Unrestricted class: a malformed/Unicode line must keep its ordinary
	// (non-permission) behaviour — the fail-closed arm applies only to a
	// regex-restricted class.
	open := cfgCfg9154(t, "", "")
	for _, verb := range []string{"deactivate", "activate"} {
		input := verb + "\u00a0" + "system login"
		if err := decideConfig9154(t, open, "Set", &pb.SetRequest{Input: input}); err != nil {
			t.Errorf("unrestricted class %q was denied: %v (#15166)", input, err)
		}
	}
	// Verb with no path at all stays ungated (handler usage error) even for
	// a restricted class — preserving neighbouring legitimate behaviour.
	for _, verb := range []string{"deactivate", "activate"} {
		if err := decideConfig9154(t, denyCfg, "Set", &pb.SetRequest{Input: verb}); err != nil {
			t.Errorf("bare %q was gated: %v (#15166)", verb, err)
		}
	}
}

const unicodeCfg15166 = `system {
    host-name unicode-15166;
    login {
        class limited {
            permissions [ configure view ];
            allow-configuration "^system services";
        }
        user opuser { class limited; }
    }
    services {
        ssh;
    }
}
`

// End-to-end: through the real interceptor + handler, a Unicode-space
// deactivate of the login subtree must be PermissionDenied, the handler
// must not run, and the candidate must carry no deactivated login leaf —
// so there is nothing for a later commit to promote.
func TestUnicodeSpaceDeactivateCannotCommitRegexLeaf15166(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, unicodeCfg15166)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	s := &Server{store: store}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_Set_FullMethodName}

	for _, verb := range []string{"deactivate", "activate"} {
		for _, sp := range unicodeSpaces15166 {
			input := verb + sp.sep + "system login"
			t.Run(verb+"/"+sp.name, func(t *testing.T) {
				called := false
				_, err := s.principalUnaryInterceptor(
					ctxWithPeerUID(authzUIDOperator), &pb.SetRequest{Input: input}, info,
					func(ctx context.Context, request any) (any, error) {
						called = true
						return s.Set(ctx, request.(*pb.SetRequest))
					},
				)
				if status.Code(err) != codes.PermissionDenied || called {
					t.Fatalf("%q: err=%v handlerCalled=%v, want PermissionDenied and no handler (#15166)", input, err, called)
				}
			})
		}
	}

	// The candidate must be untouched: no inactive login node was staged,
	// so a commit by anyone cannot ship a deactivated regex leaf.
	if out := store.ShowCandidateSet(); strings.Contains(out, "deactivate system login") {
		t.Fatalf("candidate carries a deactivated regex leaf after denied Unicode-space Set:\n%s", out)
	}
	tree := store.CandidateTree()
	if tree == nil {
		t.Fatal("candidate tree is nil in configure mode")
	}
	if sys := tree.FindChild("system"); sys != nil {
		for _, ch := range sys.Children {
			if len(ch.Keys) > 0 && ch.Keys[0] == "login" && ch.Inactive {
				t.Fatal("system login is inactive in the candidate after denied Unicode-space deactivate (#15166)")
			}
		}
	}

	// Control through the same interceptor: an allowed ASCII deactivate
	// reaches the handler and lands.
	called := false
	_, err := s.principalUnaryInterceptor(
		ctxWithPeerUID(authzUIDOperator), &pb.SetRequest{Input: "deactivate system services ssh"}, info,
		func(ctx context.Context, request any) (any, error) {
			called = true
			return s.Set(ctx, request.(*pb.SetRequest))
		},
	)
	if err != nil || !called {
		t.Fatalf("allowed ASCII deactivate err=%v handlerCalled=%v, want success (#15166)", err, called)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "deactivate system services ssh") {
		t.Fatalf("allowed ASCII deactivate did not land:\n%s", out)
	}
}
