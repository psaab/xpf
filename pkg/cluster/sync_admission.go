package cluster

// Pre-auth connection admission for the session-sync accept path (#5303).
//
// #4370 made the accept loop spawn a per-connection setup goroutine so a slow
// handshake on ONE connection can no longer stall accepting the NEXT. That fix
// is preserved. Its residual, closed here, is that there was NO aggregate cap
// on how many connections could be in pre-auth setup at once: a host reachable
// on the sync/control network could open connections at rate R and stall each
// before authentication. Each stalled connection held a tracked goroutine, a
// 256 KiB read+write buffered socket (configureSessionSyncConn ran BEFORE the
// handshake), and an FD until its handshake deadline — steady-state ~3*R
// in-flight until FDs/goroutines/socket-memory exhausted and a LEGITIMATE peer
// could no longer reconnect (and Stop waited on every stalled setup goroutine).
// The HMAC handshake (sync_auth.go) stops a flooder from becoming the active
// peer, but it runs AFTER the buffers are sized, so it does not bound the
// resource cost of the flood.
//
// The gate has three parts, all cheap and all preserving the #4107 handshake
// and the #4370 parallel accept:
//
//  1. A small admission cap on inbound pre-auth setups (preAuthSetupCap), with
//     a reserved tail (preAuthPeerReserve) that only the configured peer's
//     address may consume — so a flood from any other source can never deny the
//     peer a reconnect slot (the DoS-denies-reconnect property). Excess
//     connections are closed immediately and bump a rate-limited counter.
//  2. Deferral of the large socket-buffer sizing until AFTER the handshake
//     succeeds (handleNewConnection), so pre-auth sockets stay cheap.
//  3. Tracking of every in-flight setup connection so Stop() can close them and
//     unblock a stalled handshake instead of hanging on the shutdown budget.

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	// preAuthSetupCap bounds the total inbound sync connections in pre-auth
	// setup at once. The cluster has at most one real peer opening at most two
	// fabric connections, so this is generous headroom for legitimate traffic
	// while capping a flood far below FD/goroutine/socket-memory exhaustion.
	preAuthSetupCap = 8
	// preAuthPeerReserve is the tail of preAuthSetupCap reserved for connections
	// arriving from the configured peer address. A flood from any OTHER source
	// can consume at most preAuthSetupCap-preAuthPeerReserve slots, so the
	// legitimate peer always retains capacity to reconnect. Sized for the peer's
	// two fabric connections.
	preAuthPeerReserve = 2
)

// configureSyncConn applies the #5303 buffer deferral: the large (256 KiB)
// session-sync socket buffers must not be sized until AFTER the auth handshake
// succeeds.
//
// It is a METHOD, not a package-level function variable, and that is the whole
// of #8182 — see SessionSync.configureConn for why a shared global made the
// guard built on it unable to tell a real revert from a parallel neighbour.
// A test binds its OWN sync's hook; another SessionSync running concurrently
// cannot satisfy it.
func (s *SessionSync) configureSyncConn(conn net.Conn) {
	if s != nil && s.configureConn != nil {
		s.configureConn(conn)
		return
	}
	configureSessionSyncConn(conn)
}

// beginSetup admits a connection into its pre-auth setup window and registers
// it for shutdown cleanup. For an inbound connection it enforces the #5303
// admission cap — reserving preAuthPeerReserve slots for the configured peer —
// and returns false when the applicable limit is reached, so the caller closes
// the excess connection immediately (before any large buffer is allocated). An
// outbound connection (our own dial, bounded to one per fabric) is never capped;
// it is only registered so Stop() can close it if it stalls in the handshake.
// finishSetup releases the slot/registration once the handshake resolves.
func (s *SessionSync) beginSetup(conn net.Conn, inbound bool) bool {
	s.preAuthMu.Lock()
	defer s.preAuthMu.Unlock()
	if inbound {
		limit := preAuthSetupCap
		if !s.isPeerRemote(conn) {
			limit = preAuthSetupCap - preAuthPeerReserve
		}
		if s.preAuthInFlight >= limit {
			return false
		}
		s.preAuthInFlight++
	}
	if s.setupConns == nil {
		s.setupConns = make(map[net.Conn]bool)
	}
	s.setupConns[conn] = inbound // value == holds-a-counted-inbound-slot
	return true
}

// finishSetup ends a connection's pre-auth setup window: it unregisters the
// connection and, if it held a counted inbound admission slot, frees it. It is
// called exactly once per connection right after the handshake returns (success
// or failure), so an admitted slot is held only for the brief pre-auth window,
// never through the subsequent (potentially slow) bulk sync. Idempotent: a
// second call (e.g. after closeSetupConns already dropped the entry) is a no-op.
func (s *SessionSync) finishSetup(conn net.Conn) {
	s.preAuthMu.Lock()
	defer s.preAuthMu.Unlock()
	counted, ok := s.setupConns[conn]
	if !ok {
		return
	}
	delete(s.setupConns, conn)
	if counted && s.preAuthInFlight > 0 {
		s.preAuthInFlight--
	}
}

// closeSetupConns closes every connection currently in its pre-auth setup
// window so a stalled handshake read unblocks and its setup goroutine exits.
// Called from Stop() before waiting on the goroutine group so shutdown never
// hangs on a pre-auth connection a flooder opened and abandoned (#5303). It does
// not mutate preAuthInFlight/setupConns — each goroutine's own finishSetup does
// that as it unwinds — so the close is idempotent with a racing finishSetup.
func (s *SessionSync) closeSetupConns() {
	s.preAuthMu.Lock()
	conns := make([]net.Conn, 0, len(s.setupConns))
	for c := range s.setupConns {
		conns = append(conns, c)
	}
	s.preAuthMu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// notePreAuthRejected records a #5303 pre-auth admission rejection and logs at
// most ~1/sec so a sustained flood cannot itself become a log flood. The
// rate-independent observable is the PreAuthRejected counter (surfaced in sync
// stats), not this log line.
func (s *SessionSync) notePreAuthRejected(conn net.Conn) {
	s.stats.PreAuthRejected.Add(1)
	now := MonotonicNanos()
	last := s.preAuthLogMono.Load()
	if now-last >= int64(time.Second) && s.preAuthLogMono.CompareAndSwap(last, now) {
		slog.Warn("cluster sync: pre-auth admission cap reached, dropping connection",
			"remote", connRemoteAddrString(conn), "cap", preAuthSetupCap,
			"reserve", preAuthPeerReserve, "rejected_total", s.stats.PreAuthRejected.Load())
	}
}

// lookupPeerHostIPs resolves a configured peer hostname to all its IPs.
// It is a package var only so tests can stub DNS deterministically; production
// uses the default resolver with a bounded context so a wedged resolver
// cannot hang SessionSync construction (comms start). Never called per
// connection or under preAuthMu.
var lookupPeerHostIPs = func(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveConfiguredPeerIPs builds the cached peer-IP set for the configured
// peer addresses (#14371). IP literals keep the exact prior semantics via
// parseAddrIP (ip:port / bare IP / v4-in-v6, unmapped). A hostname is resolved
// once here and ALL answers (v4+v6) are stored, mirroring the heartbeat's
// resolve-at-startup shape (heartbeat_manager.go ResolveUDPAddr) and the sync
// dial (DialContext), which both already resolve hostnames — only the
// admission reserve compared literally and silently voided itself.
//
// An unresolvable/empty hostname yields no entry for that address (the peer
// is then treated as a non-peer, exactly as before) but warns loudly naming
// the address, so the misconfiguration is visible instead of silent.
// Resolution failure never panics and never blocks beyond the lookup timeout.
//
// Known limitation: cached answers go stale if the peer's IP changes; the
// reserve recovers on comms restart, which reconstructs SessionSync (same
// posture as the heartbeat's startup resolution). DNS rebinding is out of
// scope: an attacker who can rebind the peer hostname to their own IP still
// cannot pass the HMAC handshake, and the general-pool cap still bounds the
// total resource cost.
func resolveConfiguredPeerIPs(addrs ...string) map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{})
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		if ip := peerIPOf(addr); ip.IsValid() {
			out[ip] = struct{}{}
			continue
		}
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if host == "" {
			continue
		}
		ips, err := lookupPeerHostIPs(host)
		if err != nil || len(ips) == 0 {
			slog.Warn("cluster sync: configured peer address does not resolve to any IP, "+
				"pre-auth peer reserve unavailable for it",
				"peer_address", addr, "err", err)
			continue
		}
		for _, ip := range ips {
			if ip.IsValid() {
				out[ip.Unmap()] = struct{}{}
			}
		}
	}
	return out
}

// refreshPeerIPs (re)resolves the configured peer addresses into the cached
// peerIPs set. Called once at SessionSync construction; comms restart
// reconstructs the SessionSync, which is the refresh point. Never called on
// the per-connection admission path.
func (s *SessionSync) refreshPeerIPs() {
	s.peerIPs = resolveConfiguredPeerIPs(s.peerAddr, s.peerAddr1)
}

// isPeerRemote reports whether conn's remote IP matches a configured peer fabric
// address. The reservation matches on IP only — the peer dials from an ephemeral
// source port — so a flood from any other host cannot consume the peer's
// reserved admission slots. An attacker who can source-spoof the exact peer IP
// could reach the reserved tail, but that is a strictly harder attack and still
// cannot pass the HMAC handshake; the general-pool cap already bounds the total
// resource cost. Reads the construction-time resolved cache (peerIPs, #14371);
// the caller holds preAuthMu for lock-discipline uniformity, not because the
// read needs it. A zero-value SessionSync that never went through a
// constructor falls back to the literal comparison.
func (s *SessionSync) isPeerRemote(conn net.Conn) bool {
	ip := remoteIPOf(conn)
	if !ip.IsValid() {
		return false
	}
	if s.peerIPs != nil {
		_, ok := s.peerIPs[ip]
		return ok
	}
	if peer := peerIPOf(s.peerAddr); peer.IsValid() && peer == ip {
		return true
	}
	if s.peerAddr1 != "" {
		if peer := peerIPOf(s.peerAddr1); peer.IsValid() && peer == ip {
			return true
		}
	}
	return false
}

// remoteIPOf extracts the remote IP from a connection, tolerating a nil conn/
// addr and non-"ip:port" address string forms. Returns the zero Addr on failure.
func remoteIPOf(conn net.Conn) netip.Addr {
	if conn == nil {
		return netip.Addr{}
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return netip.Addr{}
	}
	return parseAddrIP(addr.String())
}

// peerIPOf extracts the IP from a configured "host:port" peer address string.
func peerIPOf(addr string) netip.Addr {
	if addr == "" {
		return netip.Addr{}
	}
	return parseAddrIP(addr)
}

// parseAddrIP parses an IP from an "ip:port" or bare "ip" string, returning the
// unmapped IP (so a v4-in-v6 form compares equal to the plain v4 config).
func parseAddrIP(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap()
	}
	return netip.Addr{}
}
