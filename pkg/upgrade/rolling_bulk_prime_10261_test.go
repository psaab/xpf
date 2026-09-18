package upgrade

import (
	"strings"
	"testing"
	"time"
)

func TestRejoinAndConfirmWaitsForInboundBulkPrime10261(t *testing.T) {
	f := &fakeCluster{
		peerAlive:     true,
		synced:        true,
		bulkPrimedSet: true,
		bulkPrimed:    false,
	}

	err := RejoinAndConfirm(f, 20*time.Millisecond)
	if err == nil {
		t.Fatal("rejoin must not confirm while inbound bulk session state is unprimed (#10261)")
	}
	if !strings.Contains(err.Error(), "bulk-primed=false") {
		t.Fatalf("rejoin timeout must identify the unprimed bulk gate, got %v", err)
	}
	if f.resetCalled {
		t.Fatal("rejoin must keep ForceSecondary held until inbound bulk prime completes")
	}
	if f.rejoinChecks != 0 {
		t.Fatal("per-RG rejoin polling must begin only after the reset phase")
	}
}
