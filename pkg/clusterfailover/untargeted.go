package clusterfailover

import (
	"fmt"
	"strings"
)

// The untargeted form run on the owner (#18559).
//
// `request chassis cluster failover redundancy-group <rg>` names no target.
// It used to be Manager.ManualFailover everywhere. On the RG's OWNER that is a
// break-before-make resign: the owner demoted at once and the peer promoted on
// its next periodic heartbeat. On the loss cluster the owner's helper demoted,
// the peer elected 170-270 ms later and activated about 100 ms after that, and
// every flow the owner fabric-redirected in between died on the peer's
// fabric-ingress HA-inactive gate (71-336 ms gaps, 5-19 consecutive 10 ms
// pings, every iperf stream stalled; docs/log/18559.md). H1's planned moves
// are exactly this form.
//
// The node-targeted transfer to the peer (`... node <peer>`) moves the same RG
// make-before-break: the peer pre-activates its forwarding before it asks the
// owner to demote. So on the owner of a data RG with a live peer that does not
// itself claim the RG, the untargeted form now runs that transfer. Both
// frontends (pkg/cli, pkg/grpcapi) apply the same rules to its outcome:
//
//   - The request never reached the peer: the #18585 cross-node clock refusal
//     stopped it before any fabric RPC, or NO fabric address accepted a TCP
//     connection (peerclient.ProbeFabricTCP, the one transport-absence test
//     both dialers use). Nothing happened anywhere, so the frontend runs the
//     pre-#18559 local resign, replies LocalResignMessage(rg,
//     ResignNoteUnreachable) and logs the reason; the peer claims the RG on
//     its next heartbeat, as it always did.
//   - The caller's context ended before the outcome was known: its context
//     error is returned and nothing resigns.
//   - The peer answered (anything, at any stage: an Unauthenticated or slow
//     probe after the connection was accepted, a not-takeover-ready refusal,
//     an RPC error, an unknown proxied outcome, a failure after this node's
//     applied-ACK): the error is returned and nothing resigns on top of it.
//     Resigning to a peer that will not promote strands the RG (the #18731
//     class); an unknown outcome may still commit (#15081/#16432); a
//     post-ACK failure is restored by its abort or the #5079 lease.
//   - The peer replied success but this node is STILL primary: the peer
//     answered "already primary", i.e. both nodes claim the RG. The frontend
//     then runs the local resign so the operator can still end a dual-active
//     RG from the CLI (LocalResignMessage(rg, ResignNoteDualActive)).

// Reply notes appended to the local-resign text when the untargeted form on
// an owner did not run the transfer, so the operator, H1 and the soak can tell
// it from both the transfer ("... (transfer committed)") and the plain
// pre-#18559 / non-owner reply ("Manual failover triggered for redundancy
// group N").
const (
	// ResignNoteUnreachable: no fabric address accepted a connection, or
	// the #18585 clock refusal; the break-before-make resign ran.
	ResignNoteUnreachable = "peer unreachable; resigned locally, break-before-make"
	// ResignNoteDualActive: the peer also claims the RG; resigning here
	// ends the dual-active state.
	ResignNoteDualActive = "the peer is also primary; resigned locally"
)

// LocalResignMessage is the reply for a local resign of rg. With an empty
// note it is the pre-#18559 text, unchanged.
func LocalResignMessage(rg int, note string) string {
	if note == "" {
		return fmt.Sprintf("Manual failover triggered for redundancy group %d", rg)
	}
	return fmt.Sprintf("Manual failover triggered for redundancy group %d (%s)", rg, note)
}

// UntargetedPeerTransfer reports whether an untargeted redundancy-group
// failover issued on localNode must run as the node-targeted transfer to the
// peer, and returns that targeted op. It does when all of these hold:
//
//   - op is the untargeted form (KindRGFailover);
//   - the RG is a data RG (ID > 0). RG0 is config authority and owns no
//     forwarding, so there is nothing to make before the break; the
//     untargeted RG0 form stays the local resign it always was;
//   - this node is the RG's primary (localPrimary). On a node that does not
//     own the RG the form is the local resign hold and stays one;
//   - the peer is alive. Without one there is nobody to transfer to;
//   - the peer does not itself claim the RG (peerPrimary false). When both
//     nodes are primary the transfer would be answered "already primary" and
//     move nothing; the local resign is what ends the dual-active state.
//
// The peer is the other supported chassis node: the grammar only admits nodes
// 0 and 1 (SupportedNode).
func UntargetedPeerTransfer(op Op, localNode int, localPrimary, peerAlive, peerPrimary bool) (Op, bool) {
	if op.Kind != KindRGFailover || op.RG <= 0 || !localPrimary || !peerAlive || peerPrimary {
		return Op{}, false
	}
	if !SupportedNode(localNode) {
		return Op{}, false
	}
	return TargetedRGFailover(op.RG, 1-localNode), true
}

// UntargetedTransferRefusal is the operator text for a transfer the peer
// answered but did not complete (#18559): a not-takeover-ready or
// not-transfer-ready refusal, a config-stale peer, an RPC error, a failure
// after this node's applied-ACK. The peer words its refusals about its OWN
// group ("local redundancy group N ..."); that is rewritten to "the peer's
// redundancy group" so the reader does not take it for this node's. The text
// ends with the next step and the forced-evacuation path.
func UntargetedTransferRefusal(rg, targetNode int, peerMessage string) string {
	msg := strings.ReplaceAll(peerMessage, "local redundancy group", "the peer's redundancy group")
	return fmt.Sprintf("untargeted failover of redundancy group %d ran as a make-before-break transfer to node %d, "+
		"which answered: %s; this command ran no local resign. Next: on node %d, check `show chassis cluster status` "+
		"(Takeover ready / Transfer ready for redundancy group %d) and retry once it is ready; "+
		"to evacuate this node regardless, drain it with `request system software in-service-upgrade`",
		rg, targetNode, msg, targetNode, rg)
}
