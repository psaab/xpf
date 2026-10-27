package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
	"github.com/psaab/xpf/pkg/fwdstatus"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

// showChassisForwarding renders the `show chassis forwarding` Junos-
// style one-screen view.  Uses the shared pkg/fwdstatus package so
// the gRPC handler and this local TTY path produce identical output.
//
// #877: local-node MVP.
// #879: cluster mode renders both node0:/node1: blocks via peer dial.
func (c *CLI) showChassisForwarding() error {
	localBuf, err := c.buildLocalForwarding()
	if err != nil {
		return err
	}

	if c.cluster == nil {
		fmt.Print(localBuf)
		return nil
	}

	// Cluster mode — compose two blocks with node0:/node1: headers.
	localNodeID := c.cluster.NodeID()
	fmt.Printf("node%d:\n%s\n%s",
		localNodeID, chassisForwardingSeparator, localBuf)

	peerResp, peerErr := c.dialAndShowForwarding()
	peerAlive := c.cluster.PeerAlive()
	expectedPeerNodeID := 0
	if peerAlive {
		expectedPeerNodeID = c.cluster.PeerNodeID()
	}
	var responderNodeID *int32
	if peerResp != nil {
		responderNodeID = peerResp.ResponderNodeId
	}
	peerLabel := chassisForwardingPeerLabel(responderNodeID, peerAlive, expectedPeerNodeID)
	fmt.Printf("\n%s:\n%s\n", peerLabel, chassisForwardingSeparator)
	if peerErr != nil {
		fmt.Printf("FWDD status:\n  (peer unreachable: %s)\n", peerErr)
	} else if peerResp != nil {
		fmt.Print(peerResp.Output)
	}
	return nil
}

func chassisForwardingPeerLabel(responderNodeID *int32, peerAlive bool, expectedPeerNodeID int) string {
	if responderNodeID == nil {
		return "node?"
	}
	label := fmt.Sprintf("node%d", *responderNodeID)
	if peerAlive && int(*responderNodeID) != expectedPeerNodeID {
		return fmt.Sprintf("%s (identity mismatch: expected node%d)", label, expectedPeerNodeID)
	}
	return label
}

const chassisForwardingSeparator = "--------------------------------------------------------------------------"

// buildLocalForwarding renders a single-node FWDD-status block for
// the local node.
func (c *CLI) buildLocalForwarding() (string, error) {
	var snap fwdstatus.SamplerSnapshot
	if c.fwdSampler != nil {
		snap = c.fwdSampler.Snapshot()
	}
	fs, err := fwdstatus.Build(
		c.forwardingStatusDataplane(),
		fwdstatus.OSProcReader{},
		c.startTime,
		snap,
	)
	if err != nil {
		return "", fmt.Errorf("build forwarding status: %w", err)
	}
	return fwdstatus.Format(fs), nil
}

// cliMapStatsSource adapts the CLI's stored provider to the
// package-local MapStats shape fwdstatus.NewAccessor needs (#17128).
// IsLoaded/GetMapStats forward to c.dp (the live indirection forwards
// both to the published backend).
type cliMapStatsSource struct{ cli *CLI }

func (s cliMapStatsSource) IsLoaded() bool {
	return s.cli != nil && s.cli.dp != nil && s.cli.dp.IsLoaded()
}

func (s cliMapStatsSource) GetMapStats() []fwdstatus.MapStats {
	if s.cli == nil || s.cli.dp == nil {
		return nil
	}
	stats := s.cli.dp.GetMapStats()
	out := make([]fwdstatus.MapStats, 0, len(stats))
	for _, ms := range stats {
		out = append(out, fwdstatus.MapStats{
			Type:       ms.Type,
			MaxEntries: ms.MaxEntries,
			UsedCount:  ms.UsedCount,
		})
	}
	return out
}

func (c *CLI) forwardingStatusDataplane() fwdstatus.DataPlaneAccessor {
	if c == nil {
		return nil
	}
	// #2114/#6743 r2-B7: same single-resolution publication check as the
	// gRPC peer in pkg/grpcapi/server_show_forwarding.go, and for the same
	// reason: `c.dp == nil` is permanently false under the daemon's live
	// indirection, so an emptied cell returned the non-userspace `base`
	// wrapper and fwdstatus.Build reported "Buffer utilization 0 percent"
	// with BufferKnown=TRUE — a zero that every downstream consumer is
	// told to trust — where the nil-dp control says "unknown (see #878)".
	// #17128: the shared fwdstatus.NewAccessor owns the adapter; this
	// surface supplies its three inputs (map source, resolved backend,
	// status func) and NewAccessor returns nil on an empty cell.
	backend := mgmtview.Probe(c.dp)
	return fwdstatus.NewAccessor(cliMapStatsSource{cli: c}, backend, c.userspaceDataplaneStatus)
}

// dialAndShowForwarding queries the cluster peer for its single-node
// FWDD-status block.  Injects xpf-no-peer:1 to prevent recursion.
func (c *CLI) dialAndShowForwarding() (*pb.ShowTextResponse, error) {
	conn := c.dialPeer()
	if conn == nil {
		return nil, fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
