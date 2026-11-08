package clusterfailover

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
// untargeted form now runs that transfer. The frontends (pkg/cli,
// pkg/grpcapi) apply one rule to its failure:
//
//   - The request provably never reached the peer: the peer could not be
//     dialed, or the #18585 cross-node clock refusal stopped it before the
//     fabric RPC. Nothing happened anywhere, so the frontend falls back to
//     the pre-#18559 local resign (ManualFailover) and logs the fallback;
//     the peer claims the RG on its next heartbeat, as it always did.
//   - Anything else reached the peer and is reported, never resigned on top
//     of. That includes a peer that refused because it is not takeover-ready
//     (demoting to a peer that will not promote strands the RG, the #18731
//     class), an unknown proxied outcome (#15081/#16432: it may still
//     commit), and a transfer that failed after this node's applied-ACK had
//     already demoted it (its abort or the #5079 lease restores the node).

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
