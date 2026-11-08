package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	"github.com/psaab/xpf/pkg/osident"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (c *CLI) handleRequestChassis(args []string) error {
	if len(args) == 0 || args[0] != "cluster" {
		fmt.Println("request chassis:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children))
		return nil
	}
	args = args[1:] // consume "cluster"
	if len(args) == 0 {
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
	switch args[0] {
	case "failover":
		return c.handleRequestChassisClusterFailover(args[1:])
	case "unkeyed-grace":
		return c.handleRequestChassisClusterUnkeyedGrace(args[1:])
	case "data-plane":
		return c.handleRequestChassisClusterDataPlane(args[1:])
	default:
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
}

func (c *CLI) handleRequestChassisClusterUnkeyedGrace(args []string) error {
	if len(args) == 0 {
		fmt.Println("request chassis cluster unkeyed-grace:")
		writeCompletionHelp(os.Stdout,
			treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["unkeyed-grace"].Children))
		return nil
	}
	if len(args) != 1 || args[0] != "restart" {
		return fmt.Errorf("usage: request chassis cluster unkeyed-grace restart")
	}
	if c.cluster == nil {
		return fmt.Errorf("cluster not configured")
	}

	operator := osident.Current().String()
	cutoff, err := c.cluster.RestartUnkeyedAuthorityGrace(operator)
	if err != nil {
		return err
	}
	fmt.Printf("Unkeyed authority grace restarted by operator %s on node %d; cutoff %s\n",
		operator, c.cluster.NodeID(), cutoff.Format(time.RFC3339Nano))
	return nil
}

func (c *CLI) handleRequestChassisClusterFailover(args []string) error {
	// One strict grammar, shared with the remote CLI and the gRPC handler
	// (pkg/clusterfailover). Parse BEFORE the nil-cluster / routing decision so
	// a malformed selector or out-of-range node is rejected without any cluster
	// call or peer dial — the old per-form gates degraded a misspelled/missing
	// `node` selector into an untargeted ManualFailover (#5810).
	op, err := clusterfailover.ParseCommand(args)
	if err != nil {
		return err
	}
	if c.cluster == nil {
		return fmt.Errorf("cluster not configured")
	}

	switch op.Kind {
	case clusterfailover.KindForcePrimary:
		return c.cluster.ForcePrimaryRecovery(op.RG, osident.Current().String())

	case clusterfailover.KindReset:
		if err := c.cluster.ResetFailover(op.RG); err != nil {
			return err
		}
		fmt.Printf("Failover reset for redundancy group %d\n", op.RG)
		return nil

	case clusterfailover.KindDataFailover:
		targetNode := op.Node
		if targetNode != c.cluster.NodeID() {
			if err := c.cluster.CrossNodeFabricClockError(targetNode); err != nil { // #18585
				return err
			}
			message, err := c.requestPeerSystemAction(context.Background(), op.Action())
			if err != nil {
				return err
			}
			fmt.Println(message)
			return nil
		}
		dataRGs := c.cluster.DataGroupIDs()
		if len(dataRGs) == 0 {
			return fmt.Errorf("no data redundancy groups configured")
		}
		moveRGs := make([]int, 0, len(dataRGs))
		for _, rgID := range dataRGs {
			if !c.cluster.IsLocalPrimary(rgID) {
				moveRGs = append(moveRGs, rgID)
			}
		}
		if len(moveRGs) == 0 {
			fmt.Printf("All data redundancy groups are already primary on node %d\n", targetNode)
			return nil
		}
		if len(moveRGs) == 1 {
			if err := c.cluster.RequestPeerFailover(moveRGs[0]); err != nil {
				return err
			}
		} else {
			if err := c.cluster.RequestPeerFailoverBatch(moveRGs); err != nil {
				return err
			}
		}
		fmt.Printf("Manual failover completed for data redundancy groups %v (transfer committed)\n", moveRGs)
		return nil

	case clusterfailover.KindRGFailoverNode:
		if op.Node == c.cluster.NodeID() {
			if c.cluster.IsLocalPrimary(op.RG) {
				fmt.Printf("Redundancy group %d is already primary on node %d\n", op.RG, op.Node)
				return nil
			}
			if err := c.cluster.RequestPeerFailover(op.RG); err != nil {
				return err
			}
			fmt.Printf("Manual failover completed for redundancy group %d (transfer committed)\n", op.RG)
			return nil
		}
		if err := c.cluster.CrossNodeFabricClockError(op.Node); err != nil { // #18585
			return err
		}
		message, err := c.requestPeerSystemAction(context.Background(), op.Action())
		if err != nil {
			return err
		}
		fmt.Println(message)
		return nil

	case clusterfailover.KindRGFailover:
		// #18559: on the owner of a data RG with a live peer, run the
		// make-before-break transfer to the peer instead of the local
		// resign. Same rule as the gRPC handler (untargetedPeerTransfer).
		if message, err, done := c.untargetedPeerTransfer(op); done {
			if err != nil {
				return err
			}
			fmt.Println(message)
			return nil
		}
		outcome, err := c.cluster.ManualFailover(op.RG)
		if err != nil {
			return err
		}
		// #8000: see the gRPC twin — a supersede must not read as "triggered".
		if outcome == cluster.FailoverSuperseded {
			fmt.Printf("Manual failover for redundancy group %d was superseded by a concurrent reset; no failover performed\n", op.RG)
			return nil
		}
		fmt.Printf("Manual failover triggered for redundancy group %d\n", op.RG)
		return nil
	}

	// ParseCommand only returns the five kinds above; this is unreachable.
	return fmt.Errorf("%s", clusterfailover.CommandUsage)
}

// untargetedPeerTransfer is the in-process CLI twin of the gRPC handler's
// (#18559): an untargeted RG failover on the RG's owner runs as the
// node-targeted transfer to the peer. done=false means "run the local
// resign": the form did not qualify, or the request provably never reached
// the peer (the #18585 clock refusal, or no fabric address answered the
// dial). Every failure that reached the peer is returned; nothing resigns on
// top of it. The rule is documented with clusterfailover.UntargetedPeerTransfer.
func (c *CLI) untargetedPeerTransfer(op clusterfailover.Op) (message string, err error, done bool) {
	target, ok := clusterfailover.UntargetedPeerTransfer(op, c.cluster.NodeID(),
		c.cluster.IsLocalPrimary(op.RG), c.cluster.PeerAlive())
	if !ok {
		return "", nil, false
	}
	slog.Info("cluster failover: running the untargeted failover on the owner as a make-before-break transfer to the peer",
		"rg", op.RG, "target_node", target.Node)
	sent := false
	if err = c.cluster.CrossNodeFabricClockError(target.Node); err == nil { // #18585
		message, err, sent = c.requestPeerSystemActionSent(context.Background(), target.Action(), "", 0)
		if err == nil {
			return message, nil, true
		}
	}
	if !sent {
		slog.Info("cluster failover: the transfer request never reached the peer; falling back to the local resign (the peer claims the group on its next heartbeat)",
			"rg", op.RG, "target_node", target.Node, "reason", err)
		return "", nil, false
	}
	slog.Warn("cluster failover: the transfer to the peer did not complete; not resigning locally",
		"rg", op.RG, "target_node", target.Node, "err", err)
	return "", untargetedTransferError18559(op.RG, target.Node, err), true
}

// untargetedTransferError18559 names the transfer in a failure the peer
// returned and keeps its gRPC code; see the gRPC handler's twin.
func untargetedTransferError18559(rg, targetNode int, err error) error {
	st := status.Convert(err)
	if st.Code() == codes.Unknown {
		return st.Err()
	}
	return status.Errorf(st.Code(),
		"untargeted failover of redundancy group %d ran as a make-before-break transfer to node %d, which returned: %s; no local resign was run",
		rg, targetNode, st.Message())
}

func (c *CLI) handleRequestChassisClusterDataPlane(args []string) error {
	if len(args) == 0 || args[0] != "userspace" {
		fmt.Println("request chassis cluster data-plane:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["data-plane"].Children))
		return nil
	}
	provider, err := c.userspaceDataplaneControl()
	if err != nil {
		return err
	}
	args = args[1:]

	var status dpuserspace.ProcessStatus
	switch {
	case len(args) > 0 && args[0] == "inject-packet":
		slot, mode, extra, err := dpuserspace.ParseInjectPacketCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.Status()
		if err != nil {
			return err
		}
		req, err := dpuserspace.BuildInjectPacketRequest(slot, mode, extra, status)
		if err != nil {
			return err
		}
		status, err = provider.InjectPacket(req)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "forwarding":
		armed, err := dpuserspace.ParseForwardingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetForwardingArmed(armed)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "queue":
		queueID, registered, armed, err := dpuserspace.ParseQueueCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetQueueState(queueID, registered, armed)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "binding":
		slot, registered, armed, err := dpuserspace.ParseBindingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetBindingState(slot, registered, armed)
		if err != nil {
			return err
		}
	default:
		fmt.Println("request chassis cluster data-plane userspace:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["data-plane"].Children["userspace"].Children))
		return nil
	}
	fmt.Print(dpformat.FormatStatusSummary(status))
	fmt.Println()
	fmt.Print(dpformat.FormatBindings(status))
	return nil
}
