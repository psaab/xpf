package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #10019: GetConfigModeStatus and REST GET /api/v1/config/status return the
// identical three store facts (InConfigMode/Dirty/ConfirmPending) but demanded
// different permission tiers — PermConfig over gRPC, PermView over REST. One
// tier was wrong by construction.
//
// PermView is the correct tier, from the survey the issue demanded:
//
//   - This file's own command table maps the RPC to `show version`
//     (methodCanonicalCommand), and config-mode mutations are explicitly
//     exempted from that table in methodsWithoutCanonicalCommand —
//     GetConfigModeStatus is not among them. The codebase's own taxonomy
//     calls it an operational show-equivalent.
//   - pkg/cli prices `show` at PermView, and authz_methods.go's header
//     invariant says every entry mirrors the CLI price of the command
//     reaching the RPC. PermConfig violated the file's own invariant.
//   - The shipped CLI polls this RPC pre-prompt in config-mode sessions
//     ONLY (cmd/cli/main.go:217 gates confirmPending on c.configMode,
//     which requires PermConfig to enter) — so the poll characterizes
//     the RPC as a status read, but proves nothing about view-tier
//     consumption. The tier evidence is the survey below, not this poll.
//   - Every neighboring status/show method's coarse entry on this surface
//     is PermView (GetStatus, GetSystemInfo, config-render RPCs) —
//     excluding the multiplexed ShowText FLOOR (PermControl, the highest
//     tier any of its ~127 topics needs; decoded show topics price at
//     PermView via showTextTopicPermission). Every REST read is PermView
//     by deliberate tested contract (TestReadRoutesAreAllViewTier_6660).
//     Config-render requests that read a candidate are additionally
//     charged PermConfig by the dedicated candidate-read gate; that
//     separate protection does not apply to these three status facts.
//     GetConfigModeStatus was the lone status read at PermConfig on
//     either surface.
//   - Loosening discloses nothing new: the identical facts already serve
//     at PermView over REST, and this RPC does not read candidate content.
//     Candidate-reading config renders retain their separate PermConfig
//     gate, while dirty flags are explicitly out of the candidate-content
//     disclosure property (the #9889 census). Tightening REST instead would
//     break view-only consumers and the tested all-reads-PermView contract.
//   - The PermConfig entry was lumped into the lifecycle block in a single
//     commit (03134d9a60) with no per-method deliberation.
//
// The fix moves the entry to the operational show block at PermView. The
// REST twin is pinned in pkg/api/config_status_authz_10019_test.go. The
// production diff (one entry) is the proof no other tier changed:
// TestEveryServiceMethodHasAPermission_5278 guards key-set coverage in
// both directions, never tier values, while TestReadRoutesAreAllViewTier_6660
// pins every REST read at PermView.

// TestGetConfigModeStatusCostsView_10019 pins the gate price through the
// LOOKUP rather than the map, so a table entry unreachable through
// methodPermission still fails.
//
// RED-on-revert: PermConfig in the table returns PermConfig here.
func TestGetConfigModeStatusCostsView_10019(t *testing.T) {
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/GetConfigModeStatus"
	perm, mapped := methodPermission(full, &pb.GetConfigModeStatusRequest{})
	if !mapped {
		t.Fatal("GetConfigModeStatus is not in methodPermissions — it falls to " +
			"the super-user-only default (#10019)")
	}
	if perm != config.PermView {
		t.Fatalf("GetConfigModeStatus costs %s, want %s (#10019: the identical "+
			"facts serve at PermView over REST GET /api/v1/config/status)",
			permName(perm), permName(config.PermView))
	}
}

// TestViewTierServedConfigModeStatus_10019 is the end-to-end served cell:
// read-only and operator principals — neither holds PermConfig — reach the
// RPC through the production listener and interceptor chain. The store is
// put in config mode by a super-user session first, so the response must
// report InConfigMode=true: proving the admitted call reached the handler
// and returned live facts, not merely avoided a denial.
//
// RED-on-revert: both subtests are denied with PermissionDenied.
func TestViewTierServedConfigModeStatus_10019(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, authzConfig5278)

	// Stage config mode through a super-user client on the same store, the
	// way an operator session would hold it in production.
	superClient := runPrimaryListener(t, Config{
		Store:        store,
		PeerLookupFn: fixedPeerUID5278(authzUIDSuperuser),
	})
	if _, err := superClient.EnterConfigure(callCtx(t), &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("precondition: super-user EnterConfigure: %v", err)
	}

	for _, tc := range []struct {
		name string
		uid  uint32
	}{
		{"read-only", authzUIDReadOnly},
		{"operator", authzUIDOperator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := runPrimaryListener(t, Config{
				Store:        store,
				PeerLookupFn: fixedPeerUID5278(tc.uid),
			})
			resp, err := client.GetConfigModeStatus(callCtx(t), &pb.GetConfigModeStatusRequest{})
			assertNotDenied(t, "GetConfigModeStatus", err)
			if err != nil {
				t.Fatalf("GetConfigModeStatus: %v", err)
			}
			if resp == nil {
				t.Fatal("GetConfigModeStatus returned a nil response")
			}
			if !resp.GetInConfigMode() {
				t.Error("GetConfigModeStatus reports InConfigMode=false while a " +
					"super-user session holds config mode — the served call did " +
					"not return live facts")
			}
		})
	}
}
