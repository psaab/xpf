package cli

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #16154 fold (Opus): byte-golden output must be pinned from the CLI
// FRONTEND, not only via peerclient.Reconcile unit calls. These cells
// drive the real CLI path in both of its modes:
//
//   - actual context site: no peerSystemActionFn, so
//     requestPeerSystemAction -> dialPeer() -> real loopback gRPC ->
//     context.WithTimeout(ctx, peerclient.TimeoutFor(action)) at
//     pkg/cli/peer.go -> fake peer's SystemAction handler captures
//     the server-observed deadline AND returns DeadlineExceeded, and
//     the reconciled message comes back through
//     requestPeerSystemAction -> handleRequestChassisClusterFailover
//     -> fmt.Println. The stdout capture is byte-compared (Println's
//     trailing newline included), and the server-observed deadline is
//     asserted in the ~46s cluster-budget window (not the old 5s).
//     Reverting the deadline site to 5s, or breaking the dial path,
//     fails these cells even if peerclient.TimeoutFor stays correct.
//   - seam path (peerSystemActionFn) for the full wording matrix,
//     including the peer-down cells the loopback server cannot
//     produce while it is itself answering (a dead peer in the
//     manager's heartbeat view: PeerAlive()==false).
//
// The fake peer is unkeyed (no fabricAuthKeyFn / cluster key), so the
// CLI's fabric-auth creds dial tokenless and the plain grpc.Server
// admits it — the same dual-accept posture as the #5324 cells.

type failoverDeadlinePeer16154 struct {
	pb.UnimplementedBpfrxServiceServer
	captured chan time.Duration
	hasDL    chan bool
	action   chan string
}

func (p *failoverDeadlinePeer16154) SystemAction(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	dl, ok := ctx.Deadline()
	p.hasDL <- ok
	if ok {
		p.captured <- time.Until(dl)
	} else {
		p.captured <- 0
	}
	p.action <- req.Action
	return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
}

func startFailoverDeadlinePeer16154(t *testing.T) (*failoverDeadlinePeer16154, int) {
	t.Helper()
	peer := &failoverDeadlinePeer16154{
		captured: make(chan time.Duration, 1),
		hasDL:    make(chan bool, 1),
		action:   make(chan string, 1),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, peer)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return peer, lis.Addr().(*net.TCPAddr).Port
}

// The exact byte-golden the CLI prints (fmt.Println adds "\n") for the
// reconciled deadline outcomes, captured from the pre-refactor CLI
// twin. Any wording drift fails byte-exactly here, through the CLI.
const (
	goldenCLIRGCommitted16154   = "Manual failover completed for redundancy group 1 (transfer committed on node 1; proxy response timed out after the peer committed)\n"
	goldenCLIRGNotMoved16154    = "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out; redundancy group 1 is not primary on node 1 — verify ownership before retrying\n"
	goldenCLIRGPeerDown16154    = "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out and the peer is unreachable; verify redundancy group 1 ownership before retrying\n"
	goldenCLIDataCommitted16154 = "Manual failover completed for data redundancy groups [1 2] (transfer committed on node 1; proxy response timed out after the peer committed)\n"
	goldenCLIDataPartial16154   = "Data failover outcome unknown: forwarded request to node 1 timed out; data redundancy groups now primary on node 1: [1] — verify ownership before retrying\n"
	goldenCLIDataNoneMoved16154 = "Data failover outcome unknown: forwarded request to node 1 timed out; data redundancy groups now primary on node 1: [] — verify ownership before retrying\n"
	goldenCLIDataPeerDown16154  = "Data failover outcome unknown: forwarded request to node 1 timed out and the peer is unreachable; verify redundancy group ownership before retrying\n"
)

// dialPathCLI16154 builds a CLI wired to the real loopback peer (no
// peerSystemActionFn seam): requests flow through dialPeer + the
// production context.WithTimeout site.
func dialPathCLI16154(t *testing.T, port int, setPeer func(mgr *cluster.Manager)) *CLI {
	t.Helper()
	c := failoverCLI15081(t)
	if setPeer != nil {
		setPeer(c.cluster)
	}
	c.fabricPeerAddrFn = func() []string { return []string{"127.0.0.1"} }
	c.fabricPeerPort = port
	return c
}

func TestCLIFrontendGoldenThroughDialPath16154(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		setPeer    func(mgr *cluster.Manager)
		wantStdout string
		wantAction string
		wantError  bool // #16432: unknown cells error with codes.Unknown, no stdout
	}{
		{
			name: "rg committed after timeout",
			args: []string{"redundancy-group", "1", "node", "1"},
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
			},
			wantStdout: goldenCLIRGCommitted16154,
			wantAction: "cluster-failover:1:node1",
		},
		{
			name: "rg peer reachable not moved",
			args: []string{"redundancy-group", "1", "node", "1"},
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
			},
			wantStdout: goldenCLIRGNotMoved16154,
			wantError:  true,
			wantAction: "cluster-failover:1:node1",
		},
		{
			name: "data committed after timeout",
			args: []string{"data", "node", "1"},
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
				mgr.SetPeerGroupStateForTesting(2, cluster.StatePrimary)
			},
			wantStdout: goldenCLIDataCommitted16154,
			wantAction: "cluster-failover-data:node1",
		},
		{
			name: "data partially completed",
			args: []string{"data", "node", "1"},
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
				mgr.SetPeerGroupStateForTesting(2, cluster.StateSecondary)
			},
			wantStdout: goldenCLIDataPartial16154,
			wantError:  true,
			wantAction: "cluster-failover-data:node1",
		},
		{
			name: "data peer reachable none moved",
			args: []string{"data", "node", "1"},
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
				mgr.SetPeerGroupStateForTesting(2, cluster.StateSecondary)
			},
			wantStdout: goldenCLIDataNoneMoved16154,
			wantError:  true,
			wantAction: "cluster-failover-data:node1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer, port := startFailoverDeadlinePeer16154(t)
			c := dialPathCLI16154(t, port, tc.setPeer)
			var callErr error
			out := captureStdout(t, func() {
				callErr = c.handleRequestChassisClusterFailover(tc.args)
			})
			if tc.wantError {
				// #16432: unknown is codes.Unknown (byte-golden message
				// without Println newline), never a stdout success.
				if status.Code(callErr) != codes.Unknown {
					t.Fatalf("handleRequestChassisClusterFailover() error = %v (code %s), want codes.Unknown", callErr, status.Code(callErr))
				}
				st, _ := status.FromError(callErr)
				wantMsg := strings.TrimSuffix(tc.wantStdout, "\n")
				if st.Message() != wantMsg {
					t.Fatalf("CLI unknown byte-drift:\n got: %q\nwant: %q", st.Message(), wantMsg)
				}
				if out != "" {
					t.Fatalf("CLI stdout = %q, want no success stdout for unknown outcome", out)
				}
			} else {
				if callErr != nil {
					t.Fatalf("handleRequestChassisClusterFailover() error = %v, want reconciled (byte-golden) message", callErr)
				}
				if out != tc.wantStdout {
					t.Fatalf("CLI stdout byte-drift:\n got: %q\nwant: %q", out, tc.wantStdout)
				}
			}
			// The forwarded RPC the real server received must carry
			// the cluster-budget deadline applied at the CLI's actual
			// context site — ~46s, inside [40s,50s], never the old 5s.
			select {
			case gotAction := <-peer.action:
				if gotAction != tc.wantAction {
					t.Fatalf("server saw action %q, want %q", gotAction, tc.wantAction)
				}
			default:
				t.Fatal("fake peer never received SystemAction (dial path not driven)")
			}
			if !<-peer.hasDL {
				t.Fatal("forwarded SystemAction carried no context deadline at the CLI context site")
			}
			if captured := <-peer.captured; captured < 40*time.Second || captured > 50*time.Second {
				t.Fatalf("server-observed deadline = %v, want ~46s cluster budget applied at CLI context site (5s on revert)", captured)
			}
		})
	}
}

// Timeout-site control: an ordinary (non-failover) action through the
// same real dial path must keep the historical 5s deadline at the
// server. Drives requestPeerSystemAction directly (the failover
// command grammar never forwards ordinary actions, but
// requestPeerSystemAction is the production entry the persistent-NAT
// clear and system-action forwards use).
func TestCLIFrontendOrdinaryActionKeepsShortDeadline16154(t *testing.T) {
	peer, port := startFailoverDeadlinePeer16154(t)
	c := dialPathCLI16154(t, port, nil)
	// The fake peer answers DeadlineExceeded; an ordinary action is
	// not a targeted failover, so the error must relay verbatim and
	// the message path must not reconcile it.
	_, err := c.requestPeerSystemAction(context.Background(), "reboot")
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("ordinary action error = %v, want verbatim DeadlineExceeded relay (no reconciliation)", err)
	}
	if gotAction := <-peer.action; gotAction != "reboot" {
		t.Fatalf("server saw action %q, want reboot", gotAction)
	}
	if !<-peer.hasDL {
		t.Fatal("forwarded ordinary action carried no context deadline")
	}
	if captured := <-peer.captured; captured < 3*time.Second || captured > 6*time.Second {
		t.Fatalf("server-observed ordinary-action deadline = %v, want ~5s historical budget", captured)
	}
}

// Peer-down cells: the peer is dead in the heartbeat view, so no
// loopback server can answer; driven through the CLI seam (which is
// still the CLI frontend: handleRequestChassisClusterFailover ->
// requestPeerSystemAction -> reconciliation) and byte-compared.
func TestCLIFrontendGoldenPeerDown16154(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantStdout string
	}{
		{name: "rg peer down", args: []string{"redundancy-group", "1", "node", "1"}, wantStdout: goldenCLIRGPeerDown16154},
		{name: "data peer down", args: []string{"data", "node", "1"}, wantStdout: goldenCLIDataPeerDown16154},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := failoverCLI15081(t) // no peer states set: PeerAlive()==false
			c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
				return "", status.Error(codes.DeadlineExceeded, "context deadline exceeded")
			}
			var callErr error
			out := captureStdout(t, func() {
				callErr = c.handleRequestChassisClusterFailover(tc.args)
			})
			// #16432: peer-down unknown is codes.Unknown, not stdout.
			if status.Code(callErr) != codes.Unknown {
				t.Fatalf("handleRequestChassisClusterFailover() error = %v (code %s), want codes.Unknown peer-down", callErr, status.Code(callErr))
			}
			st, _ := status.FromError(callErr)
			wantMsg := strings.TrimSuffix(tc.wantStdout, "\n")
			if st.Message() != wantMsg {
				t.Fatalf("CLI peer-down unknown byte-drift:\n got: %q\nwant: %q", st.Message(), wantMsg)
			}
			if out != "" {
				t.Fatalf("CLI stdout = %q, want no success stdout for unknown outcome", out)
			}
		})
	}
}
