package grpcapi

import (
	"errors"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #8597 K47: two `request` verbs the SSOT command tree advertises and the local
// console implements were rejected by the remote `cli` dispatcher —
// `request security policies check` and
// `request system configuration rescue save|delete`.
//
// The remote binary is the surface most operators use, and tab-completion is
// served by the SAME cmdtree, so completion offered a command the dispatcher
// then refused with "unknown request security target: policies". Fail-closed,
// hence Low, but for `policies check` it withheld the shadowed-policy lint from
// remote incident response.
//
// WHY THESE TWO ARE SERVED BY DIFFERENT RPCs. `policies check` is a pure config
// lint that produces TEXT and mutates nothing, which is exactly what ShowText
// is; rescue save/delete are store mutations with a one-line result, which is
// exactly what SystemAction is. Inventing a third RPC for a `request` verb
// would have added a method the #5278 authz map, the #7172 command table and
// every completeness guard would each need a new case for, to express something
// two existing methods already express.
//
// Both are priced at PermControl, which is what pkg/cli charges: neither verb
// is in requestSubcommandIsMaintenance's destructive set, so the `request`
// family's default tier applies. Leaving `rescue-save`/`rescue-delete` out of
// systemActionPermissions would have defaulted them to PermMaint and made the
// remote surface STRICTER than the console — a parity defect of the same family
// as the one this row is about, in the other direction.

// showPoliciesCheck serves the `policies-check` ShowText topic.
//
// It renders through policymatch.RenderPolicyCheck, the same call the local CLI
// makes, so the two surfaces cannot answer differently. A nil active config —
// a box with nothing committed — is the "no active configuration" answer rather
// than an error, matching the console.
//
// It takes cfg rather than reading s.store, like every other topic handler:
// showText already resolved the active config, and a second read could see a
// different one after a concurrent commit. A nil-STORE guard would be dead code
// — showText dereferences s.store at its first statement, so this handler is
// unreachable without one.
func (s *Server) showPoliciesCheck(cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	buf.WriteString(policymatch.RenderPolicyCheck(cfg))
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// rescueAction serves the `rescue-save` / `rescue-delete` SystemAction verbs.
//
// The messages are byte-identical to the console's, because an operator reading
// a runbook must see the same confirmation on either surface.
func (s *Server) rescueAction(action string) (*pb.SystemActionResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "no configuration store")
	}
	switch action {
	case "rescue-save":
		if err := s.store.SaveRescueConfig(); err != nil {
			// #10769 d05-F8: a save refused by the reset fence reports the
			// state, not a server failure — FailedPrecondition, like the
			// "no configuration store" guard above.
			if errors.Is(err, configstore.ErrRescueSaveFenced) {
				return nil, status.Errorf(codes.FailedPrecondition, "save rescue configuration: %v", err)
			}
			return nil, status.Errorf(codes.Internal, "save rescue configuration: %v", err)
		}
		return &pb.SystemActionResponse{Message: "Rescue configuration saved"}, nil
	case "rescue-delete":
		if err := s.store.DeleteRescueConfig(); err != nil {
			return nil, status.Errorf(codes.Internal, "delete rescue configuration: %v", err)
		}
		return &pb.SystemActionResponse{Message: "Rescue configuration deleted"}, nil
	}
	return nil, status.Errorf(codes.Internal, "unhandled rescue action %q", action)
}
