package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15942 H2-04 (gRPC arm): ShowRollback honoured Path in the handler
// but authorizeRPCConfigRead priced only the whole tree, ignoring
// r.GetPath(). A path-scoped operational deny therefore failed open
// (the scoped render was waved through by a gate that judged the bare
// command), and a subtree-only allow failed closed. The gate now
// prices the requested path.
func TestShowRollbackScopedPathGate15942(t *testing.T) {
	s := showRead14707Server(t)

	// deny-cmd class: deny-commands "^show configuration security",
	// no *-configuration rules. ShowConfig{security} is denied by the
	// same gate (control); the scoped rollback must be denied too.
	ctxDenyCmd := ctxWithPeerUID(uidDenyCmd14707)
	wantDenied14707(t, "control ShowConfig security (deny-commands ^show configuration security)",
		s.authorizeRPC(ctxDenyCmd, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowRollback 1 [security] (deny-commands ^show configuration security)",
		s.authorizeRPC(ctxDenyCmd, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Path: []string{"security"}}))
	// A subtree the deny does not name stays admitted.
	if err := s.authorizeRPC(ctxDenyCmd, show14707Method("ShowRollback"),
		&pb.ShowRollbackRequest{N: 1, Path: []string{"interfaces"}}); err != nil {
		t.Errorf("ShowRollback 1 [interfaces] must stay admitted under ^show configuration security: %v", err)
	}
	// Whole-tree rollback is not named by the path-scoped deny either.
	if err := s.authorizeRPC(ctxDenyCmd, show14707Method("ShowRollback"),
		&pb.ShowRollbackRequest{N: 1}); err != nil {
		t.Errorf("whole-tree ShowRollback must stay admitted under ^show configuration security: %v", err)
	}

	// allowlist class (allow-configuration "system"): a rollback scoped
	// to the allowed subtree is admitted (pre-fix the whole-tree gate
	// refused it), a scope outside the allowlist is refused.
	ctxAllow := ctxWithPeerUID(uidAllowlist14707)
	if err := s.authorizeRPC(ctxAllow, show14707Method("ShowRollback"),
		&pb.ShowRollbackRequest{N: 1, Path: []string{"system"}}); err != nil {
		t.Errorf("ShowRollback 1 [system] must be admitted under allow-configuration system: %v", err)
	}
	wantDenied14707(t, "ShowRollback 1 [security] (allow-configuration system)",
		s.authorizeRPC(ctxAllow, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Path: []string{"security"}}))
}
