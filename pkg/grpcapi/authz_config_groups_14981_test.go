package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14981: groups/apply-groups expansion bypassed deny-configuration over
// gRPC in Set, Load, and Commit. The store-backed cells seed a candidate
// through the store's own (plant-class) mutation entries — the same state
// a peer-synced or earlier-session candidate can be in — and then drive
// the interceptor gate, which must refuse the denied inheritance.

func store14981(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	return s
}

func seed14981(t *testing.T, s *configstore.Store, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if err := s.SetFromInputAsPlantClass("", "", strings.TrimPrefix(line, "set ")); err != nil {
			t.Fatalf("seed %q: %v", line, err)
		}
	}
}

// Commit gate: a candidate whose group body carries the denied leaf must
// not be committable by the restricted class, even though no single Set
// line the gate saw was denied.
func TestCommitGroupInheritedDeniedRefused14981(t *testing.T) {
	cfg := loginCfg9633(&config.LoginClass{
		Name: "ops", Permissions: []string{"all"},
		DenyConfiguration: "system root-authentication", DenyLeavesPresent: []string{"deny-configuration"},
	})
	store := store14981(t)
	seed14981(t, store,
		"set groups G system root-authentication plain-text-password hunter2",
		"set apply-groups G",
	)
	srv := &Server{store: store}
	if err := srv.authorizeRPCConfigMutation(cfg, "ops", method9633("Commit"), &pb.CommitRequest{}); err == nil {
		t.Fatal("Commit of a candidate with group-inherited denied path was ALLOWED (#14981)")
	}
	if err := srv.authorizeRPCConfigMutation(cfg, "ops", method9633("CommitConfirmed"), &pb.CommitConfirmedRequest{}); err == nil {
		t.Fatal("CommitConfirmed of a candidate with group-inherited denied path was ALLOWED (#14981)")
	}
	// Control: an allowed group inheritance commits.
	store2 := store14981(t)
	seed14981(t, store2,
		"set groups G system host-name ok14981",
		"set apply-groups G",
	)
	srv2 := &Server{store: store2}
	if err := srv2.authorizeRPCConfigMutation(cfg, "ops", method9633("Commit"), &pb.CommitRequest{}); err != nil {
		t.Fatalf("Commit of allowed group inheritance refused: %v", err)
	}
}

// Set gate: applying a group whose already-staged body is denied must be
// refused at Set time, not only at commit.
func TestSetApplyGroupsDeniedRefused14981(t *testing.T) {
	cfg := loginCfg9633(&config.LoginClass{
		Name: "ops", Permissions: []string{"all"},
		DenyConfiguration: "system root-authentication", DenyLeavesPresent: []string{"deny-configuration"},
	})
	store := store14981(t)
	seed14981(t, store, "set groups G system root-authentication plain-text-password hunter2")
	srv := &Server{store: store}
	if err := srv.authorizeRPCConfigMutation(cfg, "ops", method9633("Set"), &pb.SetRequest{Input: "apply-groups G"}); err == nil {
		t.Fatal("Set apply-groups with a denied group body was ALLOWED (#14981)")
	}
	// Control: applying an allowed group is permitted.
	store2 := store14981(t)
	seed14981(t, store2, "set groups G system host-name ok14981")
	srv2 := &Server{store: store2}
	if err := srv2.authorizeRPCConfigMutation(cfg, "ops", method9633("Set"), &pb.SetRequest{Input: "apply-groups G"}); err != nil {
		t.Fatalf("Set apply-groups with an allowed group body refused: %v", err)
	}
}

// Load gate over gRPC: the shared evaluator must refuse group-carried
// denied paths (flat and hierarchical), including the <*> spelling.
func TestLoadGroupInheritedDeniedRefused14981(t *testing.T) {
	cfg := loginCfg9633(&config.LoginClass{
		Name: "ops", Permissions: []string{"all"},
		DenyConfiguration: "system root-authentication", DenyLeavesPresent: []string{"deny-configuration"},
	})
	s := &Server{}
	for name, body := range map[string]string{
		"flat":         "set groups G system root-authentication plain-text-password hunter2\nset apply-groups G",
		"hierarchical": "groups { G { system { root-authentication { plain-text-password hunter2; } } } }\napply-groups G;",
	} {
		if err := s.authorizeRPCConfigMutation(cfg, "ops", method9633("Load"), &pb.LoadRequest{Mode: "merge", Content: body}); err == nil {
			t.Errorf("Load %s carrying a group-inherited denied path was ALLOWED (#14981)", name)
		}
	}
	if err := s.authorizeRPCConfigMutation(cfg, "ops", method9633("Load"), &pb.LoadRequest{Mode: "merge", Content: "set groups G system host-name ok14981\nset apply-groups G"}); err != nil {
		t.Fatalf("Load of an allowed group refused: %v", err)
	}
}
