package daemon

import (
	"testing"
	"time"

	xnft "github.com/psaab/xpf/pkg/nftables"
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

// overlayReadbackPassAllowance18721 is the ASSUMED wall time of one readback
// pass. AD measured p95 passes of 100 to 125 ms at loadavg ~40 on the
// canonical HA config (137 input rules, 178 sets). The first pass always runs,
// and the last retry admitted inside the deadline overruns it by at most one
// pass, so one readback costs at most deadline + one pass.
const overlayReadbackPassAllowance18721 = 100 * time.Millisecond

// overlayReadbackPreactivateHeadroom18721 is the margin the worst case must
// leave below transferPreActivateLockWait.
const overlayReadbackPreactivateHeadroom18721 = 100 * time.Millisecond

// #18721 folds 5-7. The overlay readback runs UNDER applySem. HA transfer
// pre-activation (daemon_ha_transfer_preactivate.go) waits
// transferPreActivateLockWait for applySem and then SKIPS pre-activation,
// running the transfer break-before-make.
//
// The deadline (nftables.HostOverlayReadbackDeadline) bounds the retries of
// one readback. A retry starts only if elapsed + its pause + the slowest pass
// so far fits, so one readback costs at most deadline + one pass. The
// reconcile hold's worst case is therefore
// readbacks-per-hold x (deadline + pass allowance), and it must leave the
// headroom below the wait. The deadline and the wait are read from their real
// definitions, so raising the deadline or lowering the wait fails this test.
// The pass allowance is the stated assumption above.
func TestOverlayReadbackFitsTransferPreActivateWait18721(t *testing.T) {
	deadline := xnft.HostOverlayReadbackDeadline()
	worst := time.Duration(ipsecReconcileOverlayReadbacksPerHold18721) * (deadline + overlayReadbackPassAllowance18721)
	if worst+overlayReadbackPreactivateHeadroom18721 >= transferPreActivateLockWait {
		t.Fatalf("worst-case overlay readback hold under applySem = %d readbacks x (%v deadline + %v pass) = %v; "+
			"with %v headroom that reaches transferPreActivateLockWait (%v), so an HA transfer queued "+
			"behind a reconcileIpsecHostInputFence hold would skip pre-activation and run break-before-make",
			ipsecReconcileOverlayReadbacksPerHold18721, deadline, overlayReadbackPassAllowance18721, worst,
			overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
	}
	t.Logf("worst-case reconcile readback hold %v + %v headroom < %v", worst, overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
}
