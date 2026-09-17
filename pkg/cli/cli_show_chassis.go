package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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

	peerBuf, peerErr := c.dialAndShowForwarding()
	peerLabel := "node?"
	if c.cluster.PeerAlive() {
		peerLabel = fmt.Sprintf("node%d", c.cluster.PeerNodeID())
	}
	fmt.Printf("\n%s:\n%s\n", peerLabel, chassisForwardingSeparator)
	if peerErr != nil {
		fmt.Printf("FWDD status:\n  (peer unreachable: %s)\n", peerErr)
	} else {
		fmt.Print(peerBuf)
	}
	return nil
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

type forwardingStatusCLIDataPlane struct {
	cli *CLI
}

func (a forwardingStatusCLIDataPlane) IsLoaded() bool {
	return a.cli != nil && a.cli.dp != nil && a.cli.dp.IsLoaded()
}

func (a forwardingStatusCLIDataPlane) GetMapStats() []fwdstatus.MapStats {
	if a.cli == nil || a.cli.dp == nil {
		return nil
	}
	stats := a.cli.dp.GetMapStats()
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

type forwardingStatusCLIUserspaceDataPlane struct {
	forwardingStatusCLIDataPlane
}

func (a forwardingStatusCLIUserspaceDataPlane) Status() (dpuserspace.ProcessStatus, error) {
	return a.cli.userspaceDataplaneStatus()
}

// HelperCrashState feeds fwdstatus's #7250 crash block.
//
// It resolves the backend directly rather than going through
// `userspaceDataplaneStatus()`, because that helper returns a ProcessStatus and
// the crash record is Manager-owned state that is NOT part of it — a crash
// clears the cached status, so routing this through the status path would make
// the block blank in the one case it exists for.
func (a forwardingStatusCLIUserspaceDataPlane) HelperCrashState() (dpuserspace.HelperCrashRecord, bool) {
	provider, ok := a.cli.dpProbe().(cliUserspaceCrashProvider)
	if !ok {
		return dpuserspace.HelperCrashRecord{}, false
	}
	return provider.HelperCrashState()
}

// HelperCrashHistory feeds fwdstatus's #8397 recovered-episode summary.
// Resolve the backend directly: unlike the current crash record, history is
// deliberately still present after a successful restart has wiped the live
// episode state.
func (a forwardingStatusCLIUserspaceDataPlane) HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int) {
	provider, ok := a.cli.dpProbe().(cliUserspaceCrashHistoryProvider)
	if !ok {
		return nil, 0
	}
	return provider.HelperCrashHistory()
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
	backend := dataplane.Unwrap(c.dp)
	if backend == nil {
		return nil
	}
	base := forwardingStatusCLIDataPlane{cli: c}
	if _, ok := backend.(cliUserspaceStatusProvider); ok {
		return forwardingStatusCLIUserspaceDataPlane{forwardingStatusCLIDataPlane: base}
	}
	return base
}

// dialAndShowForwarding queries the cluster peer for its single-node
// FWDD-status block.  Injects xpf-no-peer:1 to prevent recursion.
func (c *CLI) dialAndShowForwarding() (string, error) {
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		return "", err
	}
	return resp.Output, nil
}
