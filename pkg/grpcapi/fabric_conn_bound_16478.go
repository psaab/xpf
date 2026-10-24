package grpcapi

// fabric_conn_bound_16478.go — #16478: bound pre-auth connections on the
// network-exposed fabric gRPC listener.
//
// The fabric listener's PSK auth (#4107) and allowlist (#4122) are per-RPC:
// the first interceptor runs only when an RPC arrives. A host without the
// PSK that completes the HTTP/2 handshake (preface + SETTINGS) and then
// sends no RPC therefore committed ~73 KiB heap, 3 goroutines and an FD per
// connection with NO bound at all — the gRPC sibling of the session-sync
// flood #5303 closed. At that cost 100k held connections is ~7 GB plus FD
// exhaustion, which OOM-kills or starves xpfd and removes the peer-proxy
// surface (cross-node show/clear, MonitorInterface, forwarded failover)
// exactly when an operator needs to fail over to this node.
//
// The bound has three layers, mirroring #5303's contract ("small
// global/per-fabric pre-auth semaphore with immediate close for excess
// connections, reserving capacity for peer recovery") and complementing
// it with the lifetime bounds the issue's fix direction names:
//
//  1. Admission gate (this file): a Server-wide counting gate consulted at
//     Accept time, BEFORE grpc.Server spawns its per-connection goroutines
//     or allocates HTTP/2 buffers. Non-peer sources may hold at most
//     fabricMaxConnsTotal-fabricPeerReserve connections; the reserved tail
//     is consumable only by a connection whose remote IP is a configured
//     peer fabric address (fabricPeerAddrFn, resolved per Accept so a
//     comms rebind is honoured). Excess connections are closed immediately
//     and counted (FabricConnRefusals), with the refusal log rate-limited
//     to ~1/sec so the flood cannot become a log flood. The slot is held
//     for the connection's whole life — a pre-auth-only distinction at the
//     listener layer cannot tell a held-idle attacker connection from an
//     authenticated peer connection with a long MonitorInterface stream,
//     and both hold the same FD/goroutine/buffer cost the bound protects.
//     Release is exactly-once on first Close (grpc.Server closes every
//     accepted conn on every exit path, including GOAWAY drain).
//  2. KeepaliveParams on buildFabricServer: MaxConnectionIdle (5m) reaps
//     connections with no outstanding RPC — the preface-only flood shape —
//     long before grpc-go's 2h default ping cycle, and MaxConnectionAge
//     (1h, +30s grace) caps even a ping-ACKing holder. Neither touches a
//     connection with an active stream, so a long MonitorInterface stream
//     is never severed by them.
//  3. ConnectionTimeout (30s, down from grpc-go's 120s default) bounds how
//     long a connection may stall mid-handshake before its slot frees.
//
// The gate is shared across both fabric listeners (fab0+fab1) of one
// Server: the protected resource (process FDs/goroutines) is per-process,
// so a per-listener cap would multiply the ceiling by the fabric count —
// the same reasoning as the REST gate (#16081). Limits are vars so tests
// can shrink them; production never assigns them
// (TestFabricConnBoundDefaults16478 pins the shipped values).

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// fabricMaxConnsTotal bounds concurrent connections across ALL fabric
// listeners of one Server. Each admitted connection costs ~73 KiB heap,
// 3 goroutines and 1 FD (measured, #16478), so 32 caps the fabric surface
// at ~2.3 MiB — far below FD/memory exhaustion — while staying generous
// for the legitimate surface: one peer, dual-fabric, each dial creating a
// fresh short-lived ClientConn per proxied RPC plus single-digit
// long-lived MonitorInterface streams.
var fabricMaxConnsTotal = 32

// fabricPeerReserve is the tail of fabricMaxConnsTotal only a connection
// from the configured peer's fabric IP may consume, so a flood from any
// other source can never deny the peer a (re)connect slot — the
// DoS-denies-reconnect property #5303 established for session sync. Sized
// for the peer's dual-fabric dials plus monitor headroom.
var fabricPeerReserve = 4

// fabricMaxConnectionIdle reaps fabric connections with no outstanding
// RPC. A var ONLY so tests can shrink it; production never assigns it.
var fabricMaxConnectionIdle = 5 * time.Minute

// fabricMaxConnectionAge caps the life of any fabric connection, even one
// ACKing keepalive pings, after which grpc-go sends GOAWAY and drains.
// In-flight streams (MonitorInterface) finish within
// fabricMaxConnectionAgeGrace or are force-closed at its end; the peer's
// proxy re-dials per operation, so rotation is transparent to callers.
// A var ONLY so tests can shrink it; production never assigns it.
var fabricMaxConnectionAge = time.Hour

// fabricMaxConnectionAgeGrace is the additive drain window after
// fabricMaxConnectionAge before the connection is forcibly closed.
const fabricMaxConnectionAgeGrace = 30 * time.Second

// fabricConnectionTimeout bounds HTTP/2 handshake establishment on the
// fabric listener (grpc-go's default is 120s).
const fabricConnectionTimeout = 30 * time.Second

// fabricConnGate is the Server-wide fabric connection admission gate.
// The zero value is NOT usable; construct with newFabricConnGate. It lives
// on Server behind an atomic pointer so bare &Server{} fixtures (handler
// tests that never serve) observe a nil gate and skip wrapping, while every
// NewServer-built server gets one.
type fabricConnGate struct {
	limit    int
	reserve  int
	active   atomic.Int64
	peerHeld atomic.Int64 // admitted connections currently holding reserve-eligible (peer) slots
	refusals atomic.Uint64
	// lastRefusalLog rate-limits the refusal log line (~1/sec); the counter
	// above is the rate-independent observable.
	lastRefusalLog atomic.Int64 // unix nanos
	// isPeer classifies a remote address as the configured peer. It is the
	// Server's fabricPeerAddrFn-backed check in production; a gate built
	// without one treats every source as non-peer (fail-closed: the general
	// pool still applies, only the reserve is unreachable).
	isPeer func(net.Addr) bool
}

func newFabricConnGate(limit, reserve int, isPeer func(net.Addr) bool) *fabricConnGate {
	return &fabricConnGate{limit: limit, reserve: reserve, isPeer: isPeer}
}

// tryAcquire claims one slot for a connection from remote. It never
// blocks: a full applicable pool refuses. Non-peer sources are capped at
// limit-reserve; peer sources may use the full limit. The peerHeld count
// is advisory accounting for FabricConnActive's breakdown — the binding
// check is the single active count against the source's limit.
func (g *fabricConnGate) tryAcquire(remote net.Addr) bool {
	peer := g.isPeer != nil && g.isPeer(remote)
	limit := int64(g.limit)
	if !peer {
		limit -= int64(g.reserve)
	}
	for {
		cur := g.active.Load()
		if cur >= limit {
			return false
		}
		if g.active.CompareAndSwap(cur, cur+1) {
			if peer {
				g.peerHeld.Add(1)
			}
			return true
		}
	}
}

func (g *fabricConnGate) release(peer bool) {
	g.active.Add(-1)
	if peer {
		g.peerHeld.Add(-1)
	}
}

// refusalsCount is the cumulative refused-connection count.
func (g *fabricConnGate) refusalsCount() uint64 { return g.refusals.Load() }

// activeCount is the number of admitted, not-yet-closed connections.
func (g *fabricConnGate) activeCount() int64 { return g.active.Load() }

func (g *fabricConnGate) noteRefusal(addr net.Addr) {
	g.refusals.Add(1)
	now := time.Now().UnixNano()
	last := g.lastRefusalLog.Load()
	if now-last < int64(time.Second) || !g.lastRefusalLog.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("grpcapi: fabric connection refused at pre-auth connection bound (#16478)",
		"remote", addrString(addr), "limit", g.limit, "reserve", g.reserve,
		"refusals_total", g.refusals.Load())
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// FabricConnRefusals returns the cumulative fabric connections refused at
// the #16478 pre-auth connection bound. Nil-safe: a server without a gate
// has refused nothing. The metrics collector exports this as
// xpf_fabric_conn_refusals_total (via the api.Server hook the daemon wires).
func (s *Server) FabricConnRefusals() uint64 {
	g := s.fabricGateFor()
	if g == nil {
		return 0
	}
	return g.refusalsCount()
}

// FabricConnActive returns the currently admitted fabric connection count.
func (s *Server) FabricConnActive() int64 {
	g := s.fabricGateFor()
	if g == nil {
		return 0
	}
	return g.activeCount()
}

// FabricConnStats returns (refusals, active) for the metrics hook the
// daemon wires into the REST collector. Nil-safe like the accessors above.
func (s *Server) FabricConnStats() (uint64, int64) {
	return s.FabricConnRefusals(), s.FabricConnActive()
}

// fabricGateFor returns the server's fabric connection gate, or nil when
// the server was built as a bare &Server{} (no NewServer): those servers
// serve only in tests that drive serveUntilDone directly, and a nil gate
// leaves their listeners unwrapped rather than inventing a bound no
// constructor chose (the #16081 discipline).
func (s *Server) fabricGateFor() *fabricConnGate {
	if s == nil {
		return nil
	}
	return s.fabricConnGate.Load()
}

// fabricBoundListener wraps ln so every accepted fabric connection must
// claim a gate slot first. Nil gate or nil listener passes through
// unwrapped.
func (s *Server) fabricBoundListener(ln net.Listener) net.Listener {
	g := s.fabricGateFor()
	if g == nil || ln == nil {
		return ln
	}
	return &fabricBoundedListener{Listener: ln, gate: g}
}

// isFabricPeerRemote reports whether remote is a configured peer fabric
// address. The reservation matches on IP only — the peer dials from an
// ephemeral source port — so a flood from any other host cannot consume
// the peer's reserved slots. Matching mirrors the session-sync reserve
// (#5303/#14371): configured addresses are IP literals (or bare IPs) in
// production; an unparseable entry simply never matches, leaving that
// source in the general pool (fail-closed, never fail-open). The peer set
// is read fresh per call from fabricPeerAddrFn so a comms rebind that
// changes the peer address is honoured without rebuilding the gate.
// An attacker who can source-spoof the exact peer IP could reach the
// reserved tail, but that is strictly harder and still cannot pass the
// #4107 PSK auth; the total cap still bounds the resource cost.
func (s *Server) isFabricPeerRemote(remote net.Addr) bool {
	if remote == nil || s.fabricPeerAddrFn == nil {
		return false
	}
	ip := fabricRemoteIP(remote)
	if !ip.IsValid() {
		return false
	}
	for _, addr := range s.fabricPeerAddrFn() {
		if peer := fabricPeerIP(addr); peer.IsValid() && peer == ip {
			return true
		}
	}
	return false
}

// fabricRemoteIP extracts the remote IP, tolerating non-"ip:port" forms.
func fabricRemoteIP(remote net.Addr) netip.Addr {
	if remote == nil {
		return netip.Addr{}
	}
	return fabricPeerIP(remote.String())
}

// fabricPeerIP parses an IP from an "ip:port" or bare "ip" string,
// returning the unmapped IP so a v4-in-v6 form compares equal to the
// plain v4 config (the pkg/cluster parseAddrIP contract).
func fabricPeerIP(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
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

// A fabricBoundedListener refuses (closes + counts) accepted connections
// past the gate limit. Accepted-but-refused connections never reach
// grpc.Server, so they cost no goroutine and no HTTP/2 buffer — only the
// accept itself.
type fabricBoundedListener struct {
	net.Listener
	gate *fabricConnGate
}

func (l *fabricBoundedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		// Listener errors (including close during shutdown) carry no
		// connection and claim no slot.
		return nil, err
	}
	if !l.gate.tryAcquire(c.RemoteAddr()) {
		l.gate.noteRefusal(c.RemoteAddr())
		_ = c.Close()
		// Refusal must not surface as an Accept error: grpc.Server treats
		// a non-temporary Accept error as fatal and would exit the serve
		// loop, turning the DoS bound into a self-DoS. A temporary error
		// makes it back off and retry — the next Accept then blocks on
		// the real listener until another connection arrives.
		return nil, fabricTemporaryAcceptError{err: errors.New("grpcapi: fabric connection-count bound reached (#16478)")}
	}
	peer := l.gate.isPeer != nil && l.gate.isPeer(c.RemoteAddr())
	return &fabricGatedConn{Conn: c, gate: l.gate, peer: peer}, nil
}

// fabricTemporaryAcceptError implements net.Error with Temporary() == true
// so grpc.Server's accept loop backs off and retries instead of exiting
// (grpc-go checks Temporary() via its internal isTemporary helper).
type fabricTemporaryAcceptError struct{ err error }

func (e fabricTemporaryAcceptError) Error() string   { return e.err.Error() }
func (e fabricTemporaryAcceptError) Timeout() bool   { return false }
func (e fabricTemporaryAcceptError) Temporary() bool { return true }
func (e fabricTemporaryAcceptError) Unwrap() error   { return e.err }

// fabricGatedConn releases its gate slot exactly once, on first Close.
// The peer flag is the classification made at Accept time, so release
// accounting cannot drift if the configured peer address changes while
// the connection is open.
type fabricGatedConn struct {
	net.Conn
	gate     *fabricConnGate
	peer     bool
	released atomic.Bool
}

func (c *fabricGatedConn) Close() error {
	err := c.Conn.Close()
	if c.released.CompareAndSwap(false, true) {
		c.gate.release(c.peer)
	}
	return err
}
