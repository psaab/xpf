package grpcapi

import (
	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9324: reading the CANDIDATE configuration costs PermConfig, not PermView.
//
// THE DEFECT. ConfigTarget's proto3 zero value is CANDIDATE, and ShowConfig is
// priced PermView (authz_methods.go). A read-only principal that omitted the
// target therefore received another session's UNCOMMITTED configuration —
// topology, zones, policies and address books (secrets are separately redacted,
// so this is not #4099). On an idle box the same call returned an empty string,
// so a config-backup client written without a target archived either nothing or
// somebody's draft and could not tell which.
//
// WHY THIS IS NOT FIXED BY CHANGING THE DEFAULT, on this surface. proto3 cannot
// distinguish an omitted enum from an explicit zero, so "unset means ACTIVE"
// would also rewrite an EXPLICIT CANDIDATE request into an ACTIVE one — and
// cmd/cli/show.go:420 sends exactly that for the config-mode view. Renumbering
// the enum so zero becomes an UNSPECIFIED sentinel is a wire redefinition, which
// this repo treats as the rolling-upgrade hazard it is (add a field, never
// redefine one). So the gRPC surface is fixed by PRICE rather than by default:
// the target keeps its meaning and reading a candidate now requires the
// permission that lets you be in configuration mode at all.
//
// That is also the Junos-faithful reading. Operational `show configuration`
// renders the ACTIVE configuration; seeing a candidate is a configure-mode
// activity, and a class without `configure` cannot get there.
//
// The REST twin CAN distinguish absent from explicit — `?target` is a string —
// so it additionally defaults to ACTIVE (configShowHandler). Both surfaces agree
// on the price.
//
// It runs at the INTERCEPTOR, beside authorizeRPCConfigMutation, rather than in
// the handler: the initial permission check happens there, and a check that
// lives somewhere else can be added to a new target-taking RPC by an author who
// never sees it.
//
// #9889 is this gate's second member: ShowCompare diffs against the CANDIDATE
// on BOTH arms (rollback_n == 0 renders active-vs-candidate, rollback_n > 0
// renders the rollback slot against the candidate), so pricing it at the
// table's PermView let a view-only caller read another session's uncommitted
// configuration. Unlike ShowConfig there is no ACTIVE arm — no selector makes
// the answer right for a viewer — so the price is unconditional, mirroring the
// REST twin (candidateConfigReadPermission prices GET /api/v1/config/compare
// at PermConfig on both branches).

// configTargetReadPermission returns the permission an RPC's CANDIDATE read
// requires, and ok=false when the RPC does not read uncommitted configuration.
//
// Keyed on the REQUEST, like configMutationLineFor, because the thing being
// gated is what the handler will actually render: ShowConfig's ConfigTarget,
// or ShowCompare's both-arms candidate diff, which has no target selector.
func configTargetReadPermission(fullMethod string, req any) (config.LoginClassPermission, bool) {
	service, method, okM := splitFullMethod(fullMethod)
	if !okM || service != serviceName {
		return 0, false
	}
	switch method {
	case "ShowConfig":
		r, okReq := req.(*pb.ShowConfigRequest)
		if !okReq {
			// A ShowConfig whose request could not be read is refused at the
			// stricter price rather than admitted at the looser one.
			return config.PermConfig, true
		}
		if r.GetTarget() == pb.ConfigTarget_ACTIVE {
			return 0, false
		}
		// CANDIDATE, explicitly or by proto3 default.
		return config.PermConfig, true
	case "ShowCompare":
		// #9889: both arms render s.candidate (ShowCompareRedacted and
		// ShowCompareRollbackRedacted), so work-in-progress is the only
		// thing this RPC can produce. Priced, not defaulted: the request
		// carries no target that could make the answer right for a viewer,
		// so it is not even decoded here.
		return config.PermConfig, true
	}
	return 0, false
}

// authorizeRPCConfigTargetRead refuses a candidate-configuration read by a
// principal that does not hold PermConfig.
func (s *Server) authorizeRPCConfigTargetRead(cfg *config.Config, p authz.Principal, fullMethod string, req any) error {
	required, ok := configTargetReadPermission(fullMethod, req)
	if !ok {
		return nil
	}
	return authz.Authorize(cfg, p, required)
}
