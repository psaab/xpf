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

// overlayReadbackPreactivateHeadroom18721 is the margin the worst case must
// leave below transferPreActivateLockWait.
const overlayReadbackPreactivateHeadroom18721 = 100 * time.Millisecond

// #18721 folds 5 and 6. The overlay readback runs UNDER applySem. HA transfer
// pre-activation (daemon_ha_transfer_preactivate.go) waits
// transferPreActivateLockWait for applySem and then SKIPS pre-activation,
// running the transfer break-before-make.
//
// One readback is bounded at run time by its wall-clock deadline
// (nftables.HostOverlayReadbackDeadline). That covers passes, pauses and all,
// so the bound holds whatever the table size or host load. An assumed per-pass
// cost did not hold: on the canonical HA config one pass measured 45-60 ms on
// average, against about 1 ms on a test table.
//
// So the reconcile hold's worst case is readbacks-per-hold x deadline, and it
// must leave the headroom below the wait. Both durations are read from the real
// definitions, not copied, so raising the deadline or lowering the wait fails
// this test.
func TestOverlayReadbackFitsTransferPreActivateWait18721(t *testing.T) {
	deadline := xnft.HostOverlayReadbackDeadline()
	worst := time.Duration(ipsecReconcileOverlayReadbacksPerHold18721) * deadline
	if worst+overlayReadbackPreactivateHeadroom18721 >= transferPreActivateLockWait {
		t.Fatalf("worst-case overlay readback hold under applySem = %d readbacks x %v deadline = %v; "+
			"with %v headroom that reaches transferPreActivateLockWait (%v), so an HA transfer queued "+
			"behind a reconcileIpsecHostInputFence hold would skip pre-activation and run break-before-make",
			ipsecReconcileOverlayReadbacksPerHold18721, deadline, worst,
			overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
	}
	t.Logf("worst-case reconcile readback hold %v + %v headroom < %v", worst, overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
}
