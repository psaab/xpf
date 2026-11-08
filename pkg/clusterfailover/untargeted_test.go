package clusterfailover_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover"
)

// #18559: only the untargeted form of a DATA RG, run on its owner with a live
// peer that does not itself claim the RG, becomes the targeted transfer to
// the other chassis node.
func TestUntargetedPeerTransfer18559(t *testing.T) {
	for _, tc := range []struct {
		name         string
		op           clusterfailover.Op
		local        int
		primary      bool
		peerAlive    bool
		peerPrimary  bool
		want         clusterfailover.Op
		wantTransfer bool
	}{
		{"owner node0 RG1", clusterfailover.RGFailover(1), 0, true, true, false, clusterfailover.TargetedRGFailover(1, 1), true},
		{"owner node1 RG2", clusterfailover.RGFailover(2), 1, true, true, false, clusterfailover.TargetedRGFailover(2, 0), true},
		{"RG0 keeps the resign", clusterfailover.RGFailover(0), 0, true, true, false, clusterfailover.Op{}, false},
		{"non-owner keeps the resign", clusterfailover.RGFailover(1), 0, false, true, false, clusterfailover.Op{}, false},
		{"dead peer keeps the resign", clusterfailover.RGFailover(1), 0, true, false, false, clusterfailover.Op{}, false},
		{"dual-active keeps the resign", clusterfailover.RGFailover(1), 0, true, true, true, clusterfailover.Op{}, false},
		{"unsupported local node", clusterfailover.RGFailover(1), 2, true, true, false, clusterfailover.Op{}, false},
		{"targeted form untouched", clusterfailover.TargetedRGFailover(1, 1), 0, true, true, false, clusterfailover.Op{}, false},
		{"data form untouched", clusterfailover.DataFailover(1), 0, true, true, false, clusterfailover.Op{}, false},
		{"reset untouched", clusterfailover.ResetFailover(1), 0, true, true, false, clusterfailover.Op{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := clusterfailover.UntargetedPeerTransfer(tc.op, tc.local, tc.primary, tc.peerAlive, tc.peerPrimary)
			if ok != tc.wantTransfer || got != tc.want {
				t.Fatalf("UntargetedPeerTransfer = (%+v, %v), want (%+v, %v)", got, ok, tc.want, tc.wantTransfer)
			}
		})
	}
}

// The local-resign reply is the pre-#18559 text without a note and carries the
// note otherwise, so the fallback and the dual-active resign are visible.
func TestLocalResignMessage18559(t *testing.T) {
	if got := clusterfailover.LocalResignMessage(2, ""); got != "Manual failover triggered for redundancy group 2" {
		t.Fatalf("plain text changed: %q", got)
	}
	if got := clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable); got !=
		"Manual failover triggered for redundancy group 1 (peer unreachable; resigned locally, break-before-make)" {
		t.Fatalf("fallback text = %q", got)
	}
}

// The refusal names the peer's group as the peer's, keeps the peer's reasons,
// and ends with a next step and the forced-evacuation path.
func TestUntargetedTransferRefusal18559(t *testing.T) {
	got := clusterfailover.UntargetedTransferRefusal(1, 1,
		"local redundancy group 1 not ready for explicit failover ready=false reasons=[sync]")
	for _, want := range []string{"the peer's redundancy group 1 not ready", "reasons=[sync]", "node 1",
		"no local resign", "Next: on node 1", "request system software in-service-upgrade"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "local redundancy group") {
		t.Errorf("refusal still says \"local redundancy group\": %q", got)
	}
}
