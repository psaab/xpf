package daemon

import (
	"testing"
	"time"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// overlayReadbackPassAllowance18721 is the stated wall-time allowance for one
// overlay readback pass: two GETGEN reads plus the marker, set, rule and
// expression-name reads. Measured in a netns at loadavg ~30, a pass on a small
// fenced table took 1.2 ms on average and 7.6 ms at worst over 200 passes.
// Production host-inbound tables are larger, so the allowance is 10 ms.
const overlayReadbackPassAllowance18721 = 10 * time.Millisecond

// overlayReadbackPreactivateHeadroom18721 is the margin the worst case must
// leave below transferPreActivateLockWait.
const overlayReadbackPreactivateHeadroom18721 = 100 * time.Millisecond

// #18721 fold 5: the overlay readback's backoff runs UNDER applySem, on the
// commit path and on the IPsec reconcile path. HA transfer pre-activation
// (daemon_ha_transfer_preactivate.go) waits transferPreActivateLockWait for
// applySem and then SKIPS pre-activation, running the transfer
// break-before-make. The IPsec hold path can do two readbacks (verify, then
// reinstall and verify again), so its worst-case hold from the readback alone
// is 2 x (pause + attempts x allowance). That must leave the stated headroom
// below the wait, or a failover queued behind it loses make-before-break.
// Both constants are read from the real definitions, not copied, so raising
// the backoff or lowering the wait fails here.
func TestOverlayReadbackFitsTransferPreActivateWait18721(t *testing.T) {
	pause, attempts := xnft.HostOverlayReadbackBudget()
	worst := 2 * (pause + time.Duration(attempts)*overlayReadbackPassAllowance18721)
	if worst+overlayReadbackPreactivateHeadroom18721 >= transferPreActivateLockWait {
		t.Fatalf("worst-case overlay readback hold under applySem = 2 x (%v pause + %d x %v reads) = %v; "+
			"with %v headroom that reaches transferPreActivateLockWait (%v), so an HA transfer queued "+
			"behind an IPsec-hold readback would skip pre-activation and run break-before-make",
			pause, attempts, overlayReadbackPassAllowance18721, worst,
			overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
	}
	t.Logf("worst-case readback hold %v + %v headroom < %v", worst, overlayReadbackPreactivateHeadroom18721, transferPreActivateLockWait)
}
