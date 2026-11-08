package clusterfailover_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover"
)

// #18559: only the untargeted form of a DATA RG, run on its owner with a live
// peer, becomes the targeted transfer to the other chassis node.
func TestUntargetedPeerTransfer18559(t *testing.T) {
	for _, tc := range []struct {
		name         string
		op           clusterfailover.Op
		local        int
		primary      bool
		peerAlive    bool
		want         clusterfailover.Op
		wantTransfer bool
	}{
		{"owner node0 RG1", clusterfailover.RGFailover(1), 0, true, true, clusterfailover.TargetedRGFailover(1, 1), true},
		{"owner node1 RG2", clusterfailover.RGFailover(2), 1, true, true, clusterfailover.TargetedRGFailover(2, 0), true},
		{"RG0 keeps the resign", clusterfailover.RGFailover(0), 0, true, true, clusterfailover.Op{}, false},
		{"non-owner keeps the resign", clusterfailover.RGFailover(1), 0, false, true, clusterfailover.Op{}, false},
		{"dead peer keeps the resign", clusterfailover.RGFailover(1), 0, true, false, clusterfailover.Op{}, false},
		{"unsupported local node", clusterfailover.RGFailover(1), 2, true, true, clusterfailover.Op{}, false},
		{"targeted form untouched", clusterfailover.TargetedRGFailover(1, 1), 0, true, true, clusterfailover.Op{}, false},
		{"data form untouched", clusterfailover.DataFailover(1), 0, true, true, clusterfailover.Op{}, false},
		{"reset untouched", clusterfailover.ResetFailover(1), 0, true, true, clusterfailover.Op{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := clusterfailover.UntargetedPeerTransfer(tc.op, tc.local, tc.primary, tc.peerAlive)
			if ok != tc.wantTransfer || got != tc.want {
				t.Fatalf("UntargetedPeerTransfer = (%+v, %v), want (%+v, %v)", got, ok, tc.want, tc.wantTransfer)
			}
		})
	}
}
