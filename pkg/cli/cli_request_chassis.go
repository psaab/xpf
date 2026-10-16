package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
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
	case "data-plane":
		return c.handleRequestChassisClusterDataPlane(args[1:])
	default:
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
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
	case clusterfailover.KindReset:
		if err := c.cluster.ResetFailover(op.RG); err != nil {
			return err
		}
		fmt.Printf("Failover reset for redundancy group %d\n", op.RG)
		return nil

	case clusterfailover.KindDataFailover:
		targetNode := op.Node
		if targetNode != c.cluster.NodeID() {
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
		message, err := c.requestPeerSystemAction(context.Background(), op.Action())
		if err != nil {
			return err
		}
		fmt.Println(message)
		return nil

	case clusterfailover.KindRGFailover:
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

	// ParseCommand only returns the four kinds above; this is unreachable.
	return fmt.Errorf("%s", clusterfailover.CommandUsage)
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
