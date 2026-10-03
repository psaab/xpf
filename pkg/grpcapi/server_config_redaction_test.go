package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// grpcSecretSet stages a custom `permissions all` class alongside the secrets
// named by #4051, proving remote ShowConfig remains redacted independently of
// CLI login-class privileges.
var grpcSecretSet = []string{
	"set system login class noc-admin permissions all",
	"set security ike policy pol1 pre-shared-key ascii-text GRPC-LEAK-IKE-PSK",
	"set snmp community GRPC-LEAK-SNMP-COMMUNITY authorization read-only",
	"set routing-options autonomous-system 65000",
	"set protocols bgp group ext authentication-key GRPC-LEAK-BGP-AUTHPW",
	"set interfaces wg0 tunnel wireguard private-key GRPC-LEAK-WG-PRIVKEY",
}

var grpcSecretSentinels = []string{
	"GRPC-LEAK-IKE-PSK", "GRPC-LEAK-SNMP-COMMUNITY",
	"GRPC-LEAK-BGP-AUTHPW", "GRPC-LEAK-WG-PRIVKEY",
}

func newSecretServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join(grpcSecretSet, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &Server{store: store}
}

// TestShowConfigRedactsRawAST is the #4051 RED-on-revert net for the gRPC
// ShowConfig RPC: it renders the active config across every format and asserts
// no cleartext secret survives while the redaction placeholder does. It goes
// RED (cleartext IKE PSK / SNMP community / keys) against pre-fix code that
// called the cleartext Show* methods.
func TestShowConfigRedactsRawAST(t *testing.T) {
	s := newSecretServer(t)
	formats := []pb.ConfigFormat{
		pb.ConfigFormat_HIERARCHICAL,
		pb.ConfigFormat_SET,
		pb.ConfigFormat_JSON,
		pb.ConfigFormat_XML,
		pb.ConfigFormat_INHERITANCE,
	}
	for _, f := range formats {
		resp, err := s.ShowConfig(context.Background(), &pb.ShowConfigRequest{
			Target: pb.ConfigTarget_ACTIVE,
			Format: f,
		})
		if err != nil {
			t.Fatalf("ShowConfig(format=%v): %v", f, err)
		}
		out := resp.Output
		for _, leak := range grpcSecretSentinels {
			if strings.Contains(out, leak) {
				t.Errorf("ShowConfig(format=%v) leaked cleartext secret %q:\n%s", f, leak, out)
			}
		}
		if !strings.Contains(out, config.SecretDataPlaceholder) {
			t.Errorf("ShowConfig(format=%v) missing redaction placeholder %q:\n%s",
				f, config.SecretDataPlaceholder, out)
		}
	}
}

// TestShowConfigActivePathRedacts confirms a path-scoped ShowConfig (subtree
// render) also redacts.
func TestShowConfigActivePathRedacts(t *testing.T) {
	s := newSecretServer(t)
	resp, err := s.ShowConfig(context.Background(), &pb.ShowConfigRequest{
		Target: pb.ConfigTarget_ACTIVE,
		Format: pb.ConfigFormat_SET,
		Path:   []string{"security"},
	})
	if err != nil {
		t.Fatalf("ShowConfig(path=security): %v", err)
	}
	if strings.Contains(resp.Output, "GRPC-LEAK-IKE-PSK") {
		t.Errorf("path-scoped ShowConfig leaked IKE PSK:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, config.SecretDataPlaceholder) {
		t.Errorf("path-scoped ShowConfig missing placeholder:\n%s", resp.Output)
	}
}
