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
// owner to demote. So on the owner of a data RG with a live peer the
// untargeted form now always attempts that transfer. Before sending, the
// frontend records the RG's ownership epoch (Manager.LocalMastershipSnapshot:
// primary + mastership generation). Both frontends (pkg/cli, pkg/grpcapi)
// then apply the same rules to the outcome:
//
//   - The transfer committed: this node has been demoted by the transfer's
//     own #5640 fence; the peer's reply is returned.
//   - The peer replied success but this node is STILL primary at the SAME
//     epoch: the peer answered "already primary", i.e. both nodes claim the
//     RG. The frontend runs the local resign fenced to that epoch
//     (Manager.ManualFailoverIfMastership) and replies
//     LocalResignMessage(rg, ResignNoteDualActive), so a dual-active RG can
//     still be ended from the CLI. The decision rests on the peer's own
//     answer, never on the cached heartbeat view of the peer's role, which
//     can be stale and would resign the sole owner.
//   - The peer replied success and this node is primary at a DIFFERENT
//     epoch: a newer ownership move completed before the reply arrived. No
//     resign; the command reports the supersession (codes.Aborted).
//   - The request never reached the peer: the #18585 cross-node clock refusal
//     stopped it before any fabric RPC, or NO fabric address accepted a TCP
//     connection (peerclient.ProbeFabricTCP, the one transport-absence test
//     both dialers use). Nothing happened anywhere, so the frontend runs the
//     epoch-fenced local resign, replies LocalResignMessage(rg,
//     ResignNoteUnreachable) and logs the reason; the peer claims the RG on
//     its next heartbeat, as it always did.
//   - The caller's context ended before a local resign would run: its context
//     error is returned and nothing resigns. (This covers every local resign
//     the transfer path derives; RG0, a non-owner and a dead peer keep the
//     context-free resign master always ran.)
//   - The peer answered anything else, at any stage (an Unauthenticated or
//     slow probe after the connection was accepted, a not-takeover-ready
//     refusal, an RPC error, an unknown proxied outcome, a failure after this
//     node's applied-ACK): the error is returned and nothing resigns on top
//     of it. Resigning to a peer that will not promote strands the RG (the
//     #18731 class); an unknown outcome may still commit (#15081/#16432); a
//     post-ACK failure is restored by its abort or the #5079 lease.

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
//   - the peer is alive. Without one there is nobody to transfer to.
//
// The peer's cached role is deliberately NOT an input: a stale "peer is
// primary" heartbeat view would resign the sole owner. A peer that really is
// primary answers the transfer "already primary", and the frontend's
// epoch-fenced post-check ends the dual-active state.
//
// The peer is the other supported chassis node: the grammar only admits nodes
// 0 and 1 (SupportedNode).
func UntargetedPeerTransfer(op Op, localNode int, localPrimary, peerAlive bool) (Op, bool) {
	if op.Kind != KindRGFailover || op.RG <= 0 || !localPrimary || !peerAlive {
		return Op{}, false
	}
	if !SupportedNode(localNode) {
		return Op{}, false
	}
	return TargetedRGFailover(op.RG, 1-localNode), true
}

// UntargetedSupersededMessage is the text returned (codes.Aborted) when this
// node is primary for rg again, at a newer ownership epoch, by the time the
// untargeted command would act on the transfer's reply or resign locally: a
// newer move completed in between, so nothing more is done.
func UntargetedSupersededMessage(rg, targetNode int, peerReply string) string {
	m := fmt.Sprintf("redundancy group %d is primary on this node again at a newer ownership epoch "+
		"(a newer move completed while the untargeted failover ran)", rg)
	if peerReply != "" {
		m += fmt.Sprintf("; node %d had replied: %s", targetNode, peerReply)
	}
	return m + "; no local resign was run. Check `show chassis cluster status` before retrying"
}

// RefusalClass selects the next step UntargetedTransferRefusal offers.
type RefusalClass int

const (
	// RefusalTransport: the fabric RPC failed or the outcome is otherwise
	// unexplained; check the fabric path.
	RefusalTransport RefusalClass = iota
	// RefusalAuth: the peer rejected the fabric token (gRPC Unauthenticated
	// or PermissionDenied); almost always clock skew (#18585) or a key
	// mismatch.
	RefusalAuth
	// RefusalReadiness: the peer is not takeover- or transfer-ready.
	RefusalReadiness
)

// UntargetedTransferRefusal is the operator text for a transfer the peer
// answered but did not complete (#18559). The peer words its refusals about
// its OWN group ("local redundancy group N ..."); that is rewritten to "the
// peer's redundancy group" so the reader does not take it for this node's.
// The text ends with the next step for the failure's class.
func UntargetedTransferRefusal(rg, targetNode int, class RefusalClass, peerMessage string) string {
	msg := strings.ReplaceAll(peerMessage, "local redundancy group", "the peer's redundancy group")
	head := fmt.Sprintf("untargeted failover of redundancy group %d ran as a make-before-break transfer to node %d, "+
		"which answered: %s; this command ran no local resign. Next: ", rg, targetNode, msg)
	switch class {
	case RefusalAuth:
		return head + fmt.Sprintf("node %d rejected this node's fabric credentials, almost always clock skew "+
			"(#18585) or a control-link key mismatch: check `chronyc tracking` and the NTP "+
			"`server ... routing-instance mgmt` stanza on both nodes, then retry", targetNode)
	case RefusalReadiness:
		return head + fmt.Sprintf("on node %d, check `show chassis cluster status` (Takeover ready / Transfer "+
			"ready for redundancy group %d) and retry once it is ready. `request system software "+
			"in-service-upgrade` drains this whole node instead: it demotes EVERY redundancy group here, RG0 "+
			"included, and is safe only once node %d shows Takeover ready: yes; with a peer that is not ready "+
			"it leaves the groups owned by neither node", targetNode, rg, targetNode)
	default:
		return head + fmt.Sprintf("check the fabric path to node %d (`show chassis cluster status` monitor "+
			"failures, fab0 reachability) and retry", targetNode)
	}
}

// ClassifyRefusal picks the RefusalClass for a failure with gRPC code name
// codeName (codes.Code.String()) and text msg. Kept on strings so this
// grammar package does not depend on gRPC.
func ClassifyRefusal(codeName, msg string) RefusalClass {
	switch {
	case codeName == "Unauthenticated" || codeName == "PermissionDenied" ||
		strings.Contains(msg, "authentication failed"):
		return RefusalAuth
	case strings.Contains(msg, "not ready for explicit failover") || strings.Contains(msg, "not transfer-ready") ||
		strings.Contains(msg, "peer config stale") || strings.Contains(msg, "standby config stale"):
		return RefusalReadiness
	default:
		return RefusalTransport
	}
}
