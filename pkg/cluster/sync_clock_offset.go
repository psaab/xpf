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
