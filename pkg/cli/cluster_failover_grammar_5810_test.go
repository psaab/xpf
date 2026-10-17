// #5810: the in-process CLI shares ONE strict cluster-failover grammar with the
// remote CLI and the gRPC handler (pkg/clusterfailover). It parses BEFORE the
// nil-cluster / routing decision, so a malformed selector or out-of-range node
// is rejected without any cluster call or peer dial.
//
// These tests drive a CLI with a NIL cluster. That makes "cluster not
// configured" a sentinel: it is returned ONLY when a form PASSED the grammar
// (reaching the nil-cluster guard) but before any cluster method runs. So:
//
//   - an accepted form returns exactly "cluster not configured" (passed parse,
//     no side effect reached), and
//   - a rejected form returns some OTHER error (rejected at parse, so the switch
//     — and therefore ManualFailover / RequestPeerFailover / the peer proxy —
//     is unreachable).
//
// This proves parse parity with the shared table AND that no cluster side
// effect is reachable for a rejected form, without needing a running cluster.
// A separate spy test pins the peer-proxy dial as untouched for rejects.

package cli

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover/grammarvectors"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

const nilClusterMsg = "cluster not configured"

func TestInProcFailoverGrammarRejects_5810(t *testing.T) {
	for _, tc := range grammarvectors.CommandRejects {
		t.Run(tc.Name, func(t *testing.T) {
			c := &CLI{} // nil cluster
			err := c.handleRequestChassisClusterFailover(tc.Args)
			if err == nil {
				t.Fatalf("handleRequestChassisClusterFailover(%v) = nil; want rejection", tc.Args)
			}
			if err.Error() == nilClusterMsg {
				t.Fatalf("handleRequestChassisClusterFailover(%v) reached the nil-cluster guard "+
					"=> the grammar ACCEPTED a malformed form (a cluster side effect would be reachable)", tc.Args)
			}
		})
	}
}

func TestInProcFailoverGrammarAccepts_5810(t *testing.T) {
	for _, tc := range grammarvectors.CommandAccepts {
		t.Run(tc.Name, func(t *testing.T) {
			c := &CLI{} // nil cluster
			err := c.handleRequestChassisClusterFailover(tc.Args)
			if err == nil || err.Error() != nilClusterMsg {
				t.Fatalf("handleRequestChassisClusterFailover(%v) = %v; want it to PASS parse and "+
					"stop at the nil-cluster guard (%q)", tc.Args, err, nilClusterMsg)
			}
		})
	}
}

// TestInProcFailoverRejectsNeverProxy_5810 pins with a real (un-started)
// manager and a peer-proxy spy that no rejected form dials the peer.
func TestInProcFailoverRejectsNeverProxy_5810(t *testing.T) {
	for _, tc := range grammarvectors.CommandRejects {
		t.Run(tc.Name, func(t *testing.T) {
			c := &CLI{cluster: cluster.NewManager(0, 1)}
			c.peerSystemActionFn = func(context.Context, *pb.SystemActionRequest) (string, error) {
				t.Fatalf("rejected form %v proxied to peer", tc.Args)
				return "", nil
			}
			if err := c.handleRequestChassisClusterFailover(tc.Args); err == nil {
				t.Fatalf("handleRequestChassisClusterFailover(%v) = nil; want rejection", tc.Args)
			}
		})
	}
}
