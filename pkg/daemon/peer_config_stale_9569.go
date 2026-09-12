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
	return ss.PeerConfigStale()
}
