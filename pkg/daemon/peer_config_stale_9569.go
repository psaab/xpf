package daemon

// peerConfigStale reports whether the peer sent a config-apply nack for the
// newest config generation this node pushed (#9569). With no session sync there
// is no push to have failed, so it is not stale: the handover proceeds as
// before, and the other failover preconditions still apply.
func (d *Daemon) peerConfigStale() (bool, string) {
	ss := d.getSessionSync()
	if ss == nil {
		return false, ""
	}
	stale, reason := ss.PeerConfigStale()
	if stale {
		// #18521: a refusal is the moment someone is waiting on this ACK.
		// If it is overdue, re-push now (rate-limited inside) so the
		// operator's next attempt can pass instead of waiting for the next
		// reconcile tick. Async: this predicate runs on the failover
		// admission path and must not do I/O.
		go d.repushIfConfigAckOverdue("failover refused by the stale-config gate")
	}
	return stale, reason
}
