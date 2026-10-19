package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15690: GetVRRPStatus sat in methodsWithoutCanonicalCommand with the stale
// rationale "no `show vrrp` node exists", while `show security vrrp` has
// always been in the operational tree and the remote CLI dispatches it to
// this RPC. authorizeRPCCommand therefore failed closed ("no canonical
// command to evaluate") for every login class carrying allow/deny regexes,
// even an unrelated deny. The method must be priced as `show vrrp` (the
// top-level node added with this fix): a class that allows `show vrrp` /
// `show security vrrp` is admitted, and a class denying `show vrrp` is
// refused — the charge must not be so broad that either spelling escapes.
func TestGetVRRPStatusCanonicalCommand15690(t *testing.T) {
	if cmd, ok := methodCanonicalCommand["GetVRRPStatus"]; !ok || cmd != "show vrrp" {
		t.Fatalf("GetVRRPStatus must map to \"show vrrp\" in methodCanonicalCommand, got %q (mapped=%v)", cmd, ok)
	}
	if reason, excused := methodsWithoutCanonicalCommand["GetVRRPStatus"]; excused {
		t.Fatalf("GetVRRPStatus must not remain excused in methodsWithoutCanonicalCommand: %q", reason)
	}

	// A class whose only restriction is an unrelated deny must be admitted.
	unrelated := gateCfg7172(t, "^request ", true)
	if err := gateDecide7172(t, unrelated, "GetVRRPStatus", &pb.GetVRRPStatusRequest{}); err != nil {
		t.Errorf("GetVRRPStatus refused under an unrelated deny: %v", err)
	}

	// A class allowing show commands must be admitted via the charge.
	allow := allowCfg15076(t, "^show ")
	if err := gateDecide7172(t, allow, "GetVRRPStatus", &pb.GetVRRPStatusRequest{}); err != nil {
		t.Errorf("GetVRRPStatus refused under allow-commands \"^show \": %v", err)
	}

	// A deny on the charged command must refuse the RPC.
	deny := gateCfg7172(t, "^show vrrp$", true)
	if err := gateDecide7172(t, deny, "GetVRRPStatus", &pb.GetVRRPStatusRequest{}); err == nil {
		t.Error("GetVRRPStatus bypassed deny-commands \"^show vrrp$\"")
	}
}
