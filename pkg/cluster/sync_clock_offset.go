package cluster

import "net"

// maxPeerMonoSeconds bounds a peer's ClockSync reading (#9653). The reading is
// CLOCK_MONOTONIC seconds since the peer booted, so a century is past any real
// uptime and still far inside the int64 range the offset arithmetic needs.
const maxPeerMonoSeconds = 100 * 365 * 24 * 3600

// plausiblePeerMonoSeconds reports whether a ClockSync reading could come from
// a running peer. Its daemon cannot be running in the first second of its boot,
// and no machine has been up for a century.
func plausiblePeerMonoSeconds(peerMono uint64) bool {
	return peerMono >= 1 && peerMono <= maxPeerMonoSeconds
}

// clockOffsetFor returns the offset that rebases the timestamps of a session
// carried by conn (#9653): the offset that connection's own ClockSync
// established. A connection that has not synced yet uses the last accepted
// offset, which is what every session used before the offset was per
// connection.
func (s *SessionSync) clockOffsetFor(conn net.Conn) int64 {
	if ac, ok := conn.(*authConn); ok && ac.clockSynced.Load() {
		return ac.clockOffset.Load()
	}
	return s.peerClockOffset.Load()
}

// clockSyncLocalMono returns the local monotonic-seconds reading the ClockSync
// handler rebases against: the test override when set, else the live clock.
func (s *SessionSync) clockSyncLocalMono() uint64 {
	if s != nil && s.testClockNow != nil {
		return s.testClockNow()
	}
	return monotonicSeconds()
}

// publishClockSyncIfCurrent stores a ClockSync offset iff conn is still
// installed in its slot and belongs to the incarnation in force. Check and
// store run under s.mu, so publication serializes against retirement
// (disconnect, supersession and incarnation advance all clear under s.mu): a
// frame already read off a conn that retires first is dropped instead of
// republishing the dead incarnation's offset. Reports whether it stored.
func (s *SessionSync) publishClockSyncIfCurrent(conn net.Conn, offset int64) bool {
	if s == nil {
		return false
	}
	if conn == nil {
		// Test drivers bypass the registry; there is nothing to retire
		// against, so publish to the global fallback directly.
		s.peerClockOffset.Store(offset)
		s.clockSynced.Store(true)
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !((conn == s.conn0 && s.conn0Gen == s.peerIncarnation) ||
		(conn == s.conn1 && s.conn1Gen == s.peerIncarnation)) {
		return false
	}
	if s.testClockPublishBeforeStore != nil {
		s.testClockPublishBeforeStore()
	}
	if ac, ok := conn.(*authConn); ok {
		ac.clockOffset.Store(offset)
		ac.clockSynced.Store(true)
	}
	s.peerClockOffset.Store(offset)
	s.clockSynced.Store(true)
	if s.testClockPublishAfterStore != nil {
		s.testClockPublishAfterStore()
	}
	return true
}

// clearConnClockState resets per-connection clock state on conns that no
// longer belong to the live incarnation. Atomics make it safe under or beside
// s.mu; incarnation-switch and disconnect callers hold s.mu so the clear
// serializes against publication (see publishClockSyncIfCurrent).
func clearConnClockState(conns ...net.Conn) {
	for _, c := range conns {
		if ac, ok := c.(*authConn); ok {
			ac.clockOffset.Store(0)
			ac.clockSynced.Store(false)
		}
	}
}
