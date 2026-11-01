package daemon

import (
	"testing"
	"time"
)

// ipsecReconcileOverlayReadbacksPerHold18721 is how many host-input overlay
// readbacks reconcileIpsecHostInputFence, the short applySem holder, can make
// in one hold. Each path is the overlay apply plus, on its error path, the
// restore apply:
//   - OPEN: host_input_fence_conntrack_9506.go:309 and :311;
//   - CLOSING: ipsec_host_fence_reconcile_9506.go:408 and :417.
//
// The commit-time hold, holdIpsecHostInputFenceForDivertTransition (via
// applyConfigLocked, daemon_apply.go, and shutdown), can stack 3 to 5
// readbacks. Commit holds already run for seconds, though, so they are outside
// this invariant.
const ipsecReconcileOverlayReadbacksPerHold18721 = 2

// overlayReadbackPassAllowance18721 is the wall time of one readback pass.
// AD measured the MAXIMUM pass on the canonical HA config (137 input rules,
// 178 sets) at 168 ms, under loadavg ~40. Since fold 8 a readback is exactly
// one pass, with no retries, so this is the whole cost of one readback.
const overlayReadbackPassAllowance18721 = 168 * time.Millisecond

// overlayReadbackPreactivateHeadroom18721 is the margin the worst case must
// leave below transferPreActivateLockWait.
const overlayReadbackPreactivateHeadroom18721 = 100 * time.Millisecond

// #18721 folds 5-8. The overlay readback runs UNDER applySem. HA transfer
// pre-activation (daemon_ha_transfer_preactivate.go) waits
// transferPreActivateLockWait for applySem and then SKIPS pre-activation,
// running the transfer break-before-make.
//
// Since fold 8 one readback is exactly one pass between two GETGEN reads, and
// it fails closed on any generation change. pkg/nftables pins that with
// TestVerifyHostInboundOverlayIsGenerationBracketed18721, which counts 2
// GETGENs. The reconcile hold's worst case is therefore
// readbacks-per-hold x one measured-maximum pass, and it must leave the
// headroom below the wait. The wait is read from its real definition, so
// lowering it fails this test. The pass time is AD's measured maximum, cited
// above.
func TestOverlayReadbackFitsTransferPreActivateWait18721(t *testing.T) {
	worst := time.Duration(ipsecReconcileOverlayReadbacksPerHold18721) * overlayReadbackPassAllowance18721
	if worst+overlayReadbackPreactivateHeadroom18721 >= transferPreActivateLockWait {
		t.Fatalf("worst-case overlay readback hold under applySem = %d readbacks x %v pass = %v; "+
			"with %v headroom that reaches transferPreActivateLockWait (%v), so an HA transfer queued "+
			"behind a reconcileIpsecHostInputFence hold would skip pre-activation and run break-before-make",
			ipsecReconcileOverlayReadbacksPerHold18721, overlayReadbackPassAllowance18721, worst,
			overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
	}
	t.Logf("worst-case reconcile readback hold %v + %v headroom < %v", worst, overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
}
