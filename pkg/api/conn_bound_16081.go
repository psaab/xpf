package api

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// conn_bound_16081.go — #16081 (DOS-6): bound the NUMBER of concurrent
// connections on every REST listener.
//
// The per-connection axes were already bounded (#4150: ReadHeaderTimeout,
// ReadTimeout, IdleTimeout, MaxHeaderBytes), but the count axis was open:
// http.Server accepts without limit, so an attacker opening many idle or
// slow connections could hold one fd, one goroutine and one socket buffer
// apiece until fd exhaustion denied legitimate management clients. The
// per-connection timeouts only cap how LONG each such connection lives;
// they do not cap how many can be live at once.
//
// Design:
//
//   - One gate per Server (apiConnGate), shared by every leg on both
//     planes. A per-leg limit alone would let dual-stack HTTP+HTTPS
//     multiply the ceiling by the leg count (a dual-stack box would admit
//     4x the intended total). The resource being protected — process fds
//     and goroutines — is per-process, so the count is too.
//   - The gate is consulted at Accept time, before http.Server spawns a
//     goroutine or reads a byte. Excess connections are closed immediately
//     (the peer sees a clean close, not a hang), counted on the gate, and
//     logged at most ~once per second so a sustained flood cannot become a
//     log flood. The count is exported as xpf_rest_conn_refusals_total.
//   - Release is exactly-once per admitted connection, driven by the
//     wrapped conn's Close (guarded by sync.Once semantics via an atomic
//     flag): http.Server closes the accepted conn on every exit path —
//     handler return, timeout, Shutdown, Close — and TLS conns are counted
//     at the raw TCP layer underneath, so a stalled TLS handshake still
//     occupies (and releases) exactly one slot.
//   - The slot is held for the connection's whole life, including
//     keep-alive idle time. That is deliberate: an idle keep-alive
//     connection holds the same fd the bound protects. IdleTimeout (120s)
//     already reaps those; the count bound complements it.
//   - Hijacked connections: http.Server removes them from its tracking and
//     never closes them itself, but drainLeg closes them via the #7011
//     hijack tracker (which received the same wrapped conn), so the slot
//     is still released at drain. A handler that hijacks and never closes
//     holds its slot — the same standard the hijack tracker already sets.
// #16622: the global count alone let ONE unauthenticated source hold all
// 256 slots and lock every operator out of every leg. The gate therefore
// also enforces a per-source sub-limit (apiMaxConnsPerSource, 32): one
// source IP (IPv6: one /64, mirroring normalizeAuthThrottleSource) can
// hold at most 32 of the 256 slots, so at least eight distinct sources
// must cooperate to exhaust the global pool. Sources behind one NAT share
// their 32 — generous for a management plane (browsers hold a handful of
// keep-alive connections each) while a single host can no longer deny
// every other source. Per-source entries are deleted when their count
// reaches zero, so the tracking map holds at most one entry per source
// with a live connection (bounded by the global limit itself).
//
// Limit: apiMaxConnsTotal (256) is a var so tests can shrink it; production
// never assigns it (TestRESTConnBoundDefault16081 pins the shipped value,
// mirroring legDrainTimeout / TestLegDrainTimeoutDefault_6827). 256 is
// generous for a management plane (a handful of operator browsers, CLI
// polls and scrapers, each holding a few keep-alive connections) while
// sitting far below a typical 1024+ fd limit, leaving headroom for the
// daemon's other listeners and files.

// apiMaxConnsTotal bounds concurrent connections across ALL REST legs of
// one Server (HTTP + HTTPS, every bind family). See the file doc above.
var apiMaxConnsTotal = 256

// apiMaxConnsPerSource bounds concurrent connections from ONE source
// (IPv4 address, or IPv6 /64) across all REST legs of one Server (#16622).
var apiMaxConnsPerSource = 32

// apiConnGate is the Server-wide admission gate for accepted connections.
// The zero value is NOT usable; construct with newAPIConnGate. It lives on
// Server behind an atomic pointer so bare &Server{} fixtures (handler
// tests that never serve) observe a nil gate and skip wrapping, while every
// NewServer-built server gets one.
type apiConnGate struct {
	limit     int
	perSource int
	active    atomic.Int64
	refusals  atomic.Uint64
	// lastRefusalLog rate-limits the refusal log line (~1/sec); the counter
	// above is the rate-independent observable.
	lastRefusalLog atomic.Int64 // unix nanos
	// mu guards sources. Accept is not a hot path (management plane), so a
	// plain mutex keeps the global+per-source check atomic without CAS
	// loops spanning two counters.
	mu      sync.Mutex
	sources map[string]int
}

// newAPIConnGate requires a positive per-source limit. Accepting zero here
// would silently disable the #16622 partition (#17687).
func newAPIConnGate(limit, perSource int) *apiConnGate {
	if perSource <= 0 {
		panic("api: REST connection gate per-source limit must be positive")
	}
	return &apiConnGate{limit: limit, perSource: perSource, sources: make(map[string]int)}
}

// connGateSourceKey partitions a remote address into its gate source:
// an IPv4 address, an IPv6 /64, or the raw address string when it is not
// an IP address at all (real TCP peers always are).
func connGateSourceKey(remote net.Addr) string {
	if remote == nil {
		return ""
	}
	return normalizeAuthThrottleSource(remote.String())
}

// tryAcquire claims one slot for remote's source. It never blocks: a
// full gate — globally, or for this source — refuses.
func (g *apiConnGate) tryAcquire(remote net.Addr) bool {
	if g.perSource <= 0 {
		return false
	}
	key := connGateSourceKey(remote)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active.Load() >= int64(g.limit) {
		return false
	}
	if g.sources[key] >= g.perSource {
		return false
	}
	g.sources[key]++
	g.active.Add(1)
	return true
}

func (g *apiConnGate) release(remote net.Addr) {
	key := connGateSourceKey(remote)
	g.mu.Lock()
	if n := g.sources[key]; n <= 1 {
		delete(g.sources, key)
	} else {
		g.sources[key] = n - 1
	}
	g.mu.Unlock()
	g.active.Add(-1)
}

// refusalsCount is the cumulative refused-connection count.
func (g *apiConnGate) refusalsCount() uint64 { return g.refusals.Load() }

// activeCount is the number of admitted, not-yet-closed connections.
func (g *apiConnGate) activeCount() int64 { return g.active.Load() }

func (g *apiConnGate) noteRefusal(addr net.Addr) {
	g.refusals.Add(1)
	now := time.Now().UnixNano()
	last := g.lastRefusalLog.Load()
	if now-last < int64(time.Second) || !g.lastRefusalLog.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("api: REST connection refused at connection-count bound (#16081)",
		"remote", addr.String(), "limit", g.limit, "per_source_limit", g.perSource, "refusals_total", g.refusals.Load())
}

// RestConnRefusals returns the cumulative REST connections refused at the
// connection-count bound (#16081). Nil-safe: a server without a gate has
// refused nothing. The metrics collector exports this as
// xpf_rest_conn_refusals_total.
func (s *Server) RestConnRefusals() uint64 {
	g := s.gateFor()
	if g == nil {
		return 0
	}
	return g.refusalsCount()
}

// RestConnActive returns the currently admitted REST connection count.
// Nil-safe like RestConnRefusals.
func (s *Server) RestConnActive() int64 {
	g := s.gateFor()
	if g == nil {
		return 0
	}
	return g.activeCount()
}

// gateFor returns the server's connection gate, or nil when the server was
// built as a bare &Server{} (no NewServer): those servers never serve, and
// a nil gate leaves their listeners unwrapped rather than inventing a bound
// no constructor chose.
func (s *Server) gateFor() *apiConnGate {
	if s == nil {
		return nil
	}
	return s.connGate.Load()
}

// boundListener wraps ln so every accepted connection must claim a gate
// slot first. nil gate or nil listener passes through unwrapped.
func (s *Server) boundListener(ln net.Listener) net.Listener {
	g := s.gateFor()
	if g == nil || ln == nil {
		return ln
	}
	return &boundedListener{Listener: ln, gate: g}
}

// A boundedListener refuses (closes + counts) accepted connections past the
// gate limit. Accepted-but-refused connections never reach http.Server, so
// they cost no goroutine and no read buffer — only the accept itself.
type boundedListener struct {
	net.Listener
	gate *apiConnGate
}

func (l *boundedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		// Listener errors (including close during drain) carry no
		// connection and claim no slot.
		return nil, err
	}
	if !l.gate.tryAcquire(c.RemoteAddr()) {
		l.gate.noteRefusal(c.RemoteAddr())
		_ = c.Close()
		// Refusal must not surface as an Accept error: http.Server treats a
		// non-temporary Accept error as fatal and would exit the serve loop,
		// turning the DoS bound into a self-DoS. A temporary error makes it
		// back off and retry — the next Accept then blocks on the real
		// listener until another connection arrives.
		return nil, temporaryAcceptError{err: errors.New("api: REST connection-count bound reached")}
	}
	return &gatedConn{Conn: c, gate: l.gate, source: c.RemoteAddr()}, nil
}

// temporaryAcceptError implements net.Error with Temporary() == true so
// http.Server's accept loop backs off and retries instead of exiting.
// (http.Server checks the deprecated Temporary() via its internal
// isTemporary helper for errors returned from Accept.)
type temporaryAcceptError struct{ err error }

func (e temporaryAcceptError) Error() string   { return e.err.Error() }
func (e temporaryAcceptError) Timeout() bool   { return false }
func (e temporaryAcceptError) Temporary() bool { return true }
func (e temporaryAcceptError) Unwrap() error   { return e.err }

// gatedConn releases its gate slot exactly once, on first Close.
type gatedConn struct {
	net.Conn
	gate     *apiConnGate
	source   net.Addr
	released atomic.Bool
}

func (c *gatedConn) Close() error {
	err := c.Conn.Close()
	if c.released.CompareAndSwap(false, true) {
		c.gate.release(c.source)
	}
	return err
}
