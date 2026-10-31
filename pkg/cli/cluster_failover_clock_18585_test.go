package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #18585: the local CLI's cross-node failover forms refuse before the fabric
// RPC when the heartbeat-measured peer clock is past the guaranteed-break
// bound, and proxy as before below it.
func TestCLICrossNodeFailoverFailsFastOnPeerClockSkew18585(t *testing.T) {
	for _, args := range [][]string{
		{"redundancy-group", "2", "node", "1"},
		{"data", "node", "1"},
	} {
		c := failoverCLI15081(t)
		calls := 0
		c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
			calls++
			return "Manual failover completed", nil
		}
		c.cluster.NotePeerWallClockForTesting(-72 * time.Second)
		var err error
		captureStdout(t, func() { err = c.handleRequestChassisClusterFailover(args) })
		if err == nil || !strings.Contains(err.Error(), "run this command on node1") || calls != 0 {
			t.Fatalf("%v with the peer 72 s behind: err=%v calls=%d, want a refusal and no RPC", args, err, calls)
		}
		c.cluster.NotePeerWallClockForTesting(-1 * time.Second)
		captureStdout(t, func() { err = c.handleRequestChassisClusterFailover(args) })
		if err != nil || calls != 1 {
			t.Fatalf("%v with clocks 1 s apart: err=%v calls=%d, want one proxied RPC", args, err, calls)
		}
	}
}

// #18585 review seat AE: the workaround the refusal names — the local-target
// form — proceeds on the same skew (it pulls over session sync, no fabric).
func TestCLILocalTargetFailoverProceedsOnPeerClockSkew18585(t *testing.T) {
	for _, args := range [][]string{
		{"redundancy-group", "2", "node", "0"},
		{"data", "node", "0"},
	} {
		c := failoverCLI15081(t)
		c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
			t.Fatalf("%v: a local-target move must not proxy to the peer", args)
			return "", nil
		}
		c.cluster.NotePeerWallClockForTesting(-72 * time.Second)
		var err error
		captureStdout(t, func() { err = c.handleRequestChassisClusterFailover(args) })
		if err != nil && strings.Contains(err.Error(), "cross-node request not sent") {
			t.Fatalf("%v: the local pull was refused on the peer's clock: %v", args, err)
		}
	}
}
