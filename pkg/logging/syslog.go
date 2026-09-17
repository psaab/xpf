package logging

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/termsafe"
)

// Resilience defaults for ALL transports. These bound the time the dataplane
// event hot-path can spend inside a single Send and rate-limit reconnect
// attempts so a down server cannot drive a fresh 5s-timeout dial on every
// event.
//
// #9025: this used to end "UDP is connectionless and never blocks on Write, so
// these do not apply to it." THAT IS FALSE, and it was the proximate cause of
// the omission — a false rationale re-justifies itself every time someone
// checks it. This tree already refutes it verbatim, in
// pkg/flowexport/transport.go (#4423 H07):
//
//	A connected-UDP Write is normally instantaneous, but it CAN BLOCK
//	INDEFINITELY on a full socket send buffer (ENOBUFS / a congested or down
//	egress path parks the goroutine in the netpoller until the buffer drains).
//
// Two modules in one tree held opposite beliefs about the same syscall; one
// armed a deadline and one did not. UDP is also the DEFAULT protocol here, so
// the unbounded path was the common one.
//
// What blocks is the local socket send buffer, not the network, and the
// goroutine it parks is the EventStream reader — which also carries HA session
// sync (EventTypeSessionOpen/Update/Close), the ISSU drain signal
// (EventTypeDrainComplete) and EventTypeFullResync. Stalling syslog stalls
// those.
const (
	// defaultWriteTimeout caps how long a single conn.Write may block before
	// it is treated as a write failure (message dropped, reconnect armed).
	// Generous enough that a healthy server is never affected; short enough
	// that a hung server cannot stall the event reader.
	defaultWriteTimeout = 4 * time.Second
	// defaultReconnectCooldown is the minimum interval between dial attempts
	// after a dial failure. Within the window, a stream Send that needs a
	// reconnect fails fast (drops) instead of dialing — preventing a
	// thundering herd of 5s dials against a down server.
	defaultReconnectCooldown = 1 * time.Second
	// closeJoinTimeout bounds how long Close waits for an in-flight Send to
	// release s.mu after the active socket has been closed. A real net.Conn
	// unblocks promptly; this bound also protects a reconfigure commit from a
	// custom connection that ignores Close.
	closeJoinTimeout = 100 * time.Millisecond
)

// Syslog wire severity levels (RFC 5424 / RFC 3164 numeric PRI severity).
// LOWER number = MORE severe. These are the on-the-wire severity codes AND
// the values a record's severity is compared against in ShouldSend.
const (
	SyslogEmergency = 0
	SyslogAlert     = 1
	SyslogCritical  = 2
	SyslogError     = 3
	SyslogWarning   = 4
	SyslogNotice    = 5
	SyslogInfo      = 6
	SyslogDebug     = 7
)

// SyslogClient.MinSeverity filter sentinels (#5314). MinSeverity encodes the
// Junos `host <facility> <severity>` threshold ("send this severity AND every
// more-severe one"). It is NOT a wire severity code — it reuses the raw RFC
// values above for alert(1)..debug(7), but the two extremes need dedicated
// sentinels:
//
//   - 0 = "no severity filter" — forward every record. This is the ZERO VALUE,
//     so an unconfigured client forwards everything, and it is also what Junos
//     `any` (and an unknown/typo'd severity, tolerantly) maps to.
//   - SeverityEmergency = -1 — forward ONLY emergency records. The most severe
//     level cannot reuse SyslogEmergency(0) because 0 already means send-all;
//     collapsing emergency into the send-all sentinel is exactly the #5314
//     over-forward bug, so emergency gets its own code.
//   - SeverityNone = -2 — forward NOTHING (Junos `none`).
const (
	SeverityNone      = -2
	SeverityEmergency = -1
)

// Syslog facility codes (RFC 3164).
const (
	FacilityKern   = 0
	FacilityUser   = 1
	FacilityDaemon = 3
	FacilityAuth   = 4
	FacilitySyslog = 5
	FacilityLocal0 = 16
	FacilityLocal1 = 17
	FacilityLocal2 = 18
	FacilityLocal3 = 19
	FacilityLocal4 = 20
	FacilityLocal5 = 21
	FacilityLocal6 = 22
	FacilityLocal7 = 23
	// #6830: RFC 5424 §6.2.1 facility codes for the two Junos facility names
	// whose documented remote-destination facility is themselves and which had
	// no constant here. Declared with the table below; NOT yet emitted — see
	// JunosRemoteFacility for why the wire is unchanged.
	FacilityFTP = 11
	FacilityNTP = 12
)

// SyslogClient sends syslog messages over UDP, TCP, or TLS.
// Supports RFC 3164 (BSD) and RFC 5424 (structured-data syslog) formats.
// TCP/TLS use RFC 6587 octet-counting framing.
type SyslogClient struct {
	mu          sync.Mutex
	connMu      sync.RWMutex // protects conn while Close races an in-flight Write
	conn        net.Conn
	hostname    string
	remoteAddr  string
	sourceAddr  string
	protocol    string // "udp", "tcp", "tls"
	tlsConfig   *tls.Config
	Facility    int    // syslog facility code (default: FacilityLocal0)
	MinSeverity int    // severity threshold; 0 = no filter, SeverityEmergency(-1)/SeverityNone(-2) sentinels, else raw RFC level (see ShouldSend)
	Format      string // "sd-syslog" for RFC 5424, "structured" for Junos RT_FLOW, "" for RFC 3164
	Categories  uint8  // bitmask of allowed event categories (0 = all)

	// Stream-transport resilience (TCP/TLS). All guarded by mu except the
	// atomic counters, which are observability only.
	writeTimeout      time.Duration // per-Write deadline; 0 disables (UDP)
	reconnectCooldown time.Duration // min interval between reconnect attempts
	// lastReconnectFailure is when the last reconnect CYCLE failed: either the
	// dial errored, OR the dial succeeded but the retry-write that followed it
	// failed (accept-then-reset). Armed by both modes so an accept-then-reset
	// target cannot bypass the cooldown (#2302); cleared only on a fully
	// successful reconnect (dial + retry-write). mu-guarded.
	lastReconnectFailure time.Time
	lastDropLog          time.Time // rate-limit for the drop warning (mu-guarded)

	// droppedWrites counts messages dropped because the write itself failed:
	// a write timeout (SetWriteDeadline expiry) or a write error
	// (ECONNRESET/EPIPE) on the stream conn. It does NOT count reconnect dial
	// failures — those are droppedDials (#2287).
	droppedWrites atomic.Uint64
	// droppedDials counts messages dropped because the post-write-failure
	// reconnect dial itself failed (the message could not be re-sent because
	// the new connection could not be established).
	droppedDials atomic.Uint64
	// droppedCooldown counts messages dropped because a needed reconnect was
	// suppressed by the cooldown window (fail-fast, no dial attempted).
	droppedCooldown atomic.Uint64

	// Seams for deterministic testing. nil → real implementations.
	nowFn  func() time.Time         // clock source (default time.Now)
	dialFn func() (net.Conn, error) // dial override (default s.dial)

	// closed is set atomically by Close() before it closes the active socket.
	// Send/SendBinary/Connect/reconnect check it both before and after any
	// operation that can race Close. The separate connMu lets Close detach and
	// close a socket without waiting for s.mu, which an in-flight Write holds.
	closed atomic.Bool
}

// now returns the client's clock (overridable in tests).
func (s *SyslogClient) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// loadConn returns the current connection. A Send copies the interface under
// connMu, then deliberately writes through the local copy so Close can close
// the same socket concurrently without racing the s.conn field.
func (s *SyslogClient) loadConn() net.Conn {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return s.conn
}

// storeConn publishes a newly connected socket unless Close won the race.
// The closed check and publication share connMu with Close's detach, so a
// connection can never be installed after Close has detached the prior one.
func (s *SyslogClient) storeConn(conn net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.conn = conn
	return true
}

// detachConn removes and returns the active socket. It is intentionally
// independent of s.mu: Close uses it to interrupt a Write that holds s.mu.
func (s *SyslogClient) detachConn() net.Conn {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	conn := s.conn
	s.conn = nil
	return conn
}

// closeSyslogConn closes a syslog socket without allowing TLS close_notify to
// block a caller. tls.Conn.Close writes close_notify before closing its raw
// socket; close the raw socket first so that notification fails immediately,
// then finish the TLS wrapper close and ignore the expected notification error.
func closeSyslogConn(conn net.Conn) error {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if raw := tlsConn.NetConn(); raw != nil {
			_ = raw.Close()
		}
		_ = tlsConn.Close()
		return nil
	}
	return conn.Close()
}

// joinSendBounded gives an in-flight Send a short chance to observe the
// socket close and release s.mu. It never waits on a custom Conn indefinitely.
func (s *SyslogClient) joinSendBounded() {
	if s.mu.TryLock() {
		s.mu.Unlock()
		return
	}
	deadline := time.Now().Add(closeJoinTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		if s.mu.TryLock() {
			s.mu.Unlock()
			return
		}
	}
}

// dialConn dials a new connection via the test seam if set, else the real
// protocol dialer.
func (s *SyslogClient) dialConn() (net.Conn, error) {
	if s.dialFn != nil {
		return s.dialFn()
	}
	return s.dial()
}

// Category bitmask constants for event filtering.
const (
	CategorySession  uint8 = 1 << 0 // SESSION_OPEN, SESSION_CLOSE
	CategoryPolicy   uint8 = 1 << 1 // POLICY_DENY
	CategoryScreen   uint8 = 1 << 2 // SCREEN_DROP
	CategoryFirewall uint8 = 1 << 3 // FILTER_LOG
	CategoryAll      uint8 = CategorySession | CategoryPolicy | CategoryScreen | CategoryFirewall
)

// NewSyslogClient creates a new UDP syslog client connected to host:port.
func NewSyslogClient(host string, port int) (*SyslogClient, error) {
	return NewSyslogClientWithSource(host, port, "")
}

// NewSyslogClientWithSource creates a new UDP syslog client with an optional
// source address for the local UDP socket binding.
func NewSyslogClientWithSource(host string, port int, sourceAddr string) (*SyslogClient, error) {
	return NewSyslogClientTransport(host, port, sourceAddr, "udp", nil)
}

// ErrUnsupportedTransport is returned when a syslog client is asked to use a
// transport token the dialer cannot honor. It exists so the runtime refuses to
// silently downgrade an unknown/typo'd transport to plaintext UDP. The strict
// commit schema (`security log stream <s> transport protocol`, enum
// udp|tcp|tls, #2008) rejects bad tokens at a normal commit, but the tolerant
// persisted / HA-synced load path does not — so a typo or a newer transport
// value could reach NewSyslogClientTransport with a token that dial()'s old
// default arm mapped to UDP, sending security/audit records in plaintext while
// config and status still name a non-UDP transport (#5581). Callers use
// errors.Is to distinguish this fail-closed configuration error from a
// transient dial failure.
var ErrUnsupportedTransport = errors.New("syslog: unsupported transport protocol")

// supportedTransport reports whether protocol is a transport the dialer can
// actually establish. Empty is NOT accepted here: NewSyslogClientTransport
// normalizes "" to "udp" (the documented default) BEFORE validation, so an
// empty token never reaches this check; a caller building a client another way
// must pass an explicit token.
func supportedTransport(protocol string) bool {
	switch protocol {
	case "udp", "tcp", "tls":
		return true
	default:
		return false
	}
}

// NewSyslogClientTransport creates a syslog client with the specified transport
// protocol ("udp", "tcp", or "tls"). For TLS, a *tls.Config is used; if nil,
// system CA roots are used.
//
// An unknown/unsupported transport token is REJECTED here (returns
// (nil, ErrUnsupportedTransport)) instead of silently falling back to UDP.
// Empty is the documented UDP default and is normalized to "udp" before this
// check. This is the runtime fail-closed guard for the tolerant persisted /
// HA-synced load path that bypasses the strict commit enum (#5581).
//
// A TCP/TLS receiver that is unreachable at construction (down at config-apply
// or boot) does NOT fail the stream (#3351). The returned client is usable but
// unconnected: the first Send sees conn==nil, treats it as a (non-timeout)
// write failure, and the existing cooldown-gated reconnect path dials when the
// receiver returns. The dial error is returned ALONGSIDE the non-nil client so
// the caller can log the "unreachable at apply" condition; a caller that wants
// the stream to recover MUST install the client even when err != nil (only a
// nil client means the stream cannot be built — see UDP below). UDP has no live
// peer to "connect" to, so a UDP dial failure is a genuine construction error
// (unresolvable host / bad source bind) and still returns (nil, err).
func NewSyslogClientTransport(host string, port int, sourceAddr, protocol string, tlsCfg *tls.Config) (*SyslogClient, error) {
	if protocol == "" {
		protocol = "udp"
	}
	// Fail closed on an unknown transport instead of dial()'s old default-to-UDP
	// path: a security-log stream configured (or persisted / HA-synced) with a
	// typo'd or unsupported transport must NOT silently ship audit records in
	// plaintext UDP while config/status still name a non-UDP transport (#5581).
	if !supportedTransport(protocol) {
		return nil, fmt.Errorf("%w %q", ErrUnsupportedTransport, protocol)
	}
	remoteAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	c := &SyslogClient{
		hostname:          hostname,
		remoteAddr:        remoteAddr,
		sourceAddr:        sourceAddr,
		protocol:          protocol,
		tlsConfig:         tlsCfg,
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}

	conn, err := c.dial()
	if err != nil {
		// UDP "dial" does not require a live peer; a failure here is an
		// unrecoverable construction error (unresolvable host / bad source
		// bind), so drop the stream as before.
		if protocol == "udp" {
			return nil, err
		}
		// #3351: a TCP/TLS receiver down at apply/boot must NOT permanently
		// disable the stream. Hand back a usable, unconnected client so the
		// cooldown-gated reconnect path (Send → writeMsg(conn==nil) →
		// reconnect) brings it up when the receiver returns. Arm the cooldown
		// clock so the first reconnect waits one cooldown window rather than
		// dialing under s.mu on the very next event — exactly as reconnect()
		// arms on a failed dial. Return the error too so the caller logs it.
		c.lastReconnectFailure = c.now()
		return c, err
	}
	c.conn = conn
	return c, nil
}

// Protocol returns the transport this client was constructed with ("udp",
// "tcp", or "tls"). Exported so callers/tests can verify the configured
// transport was honored — e.g. that an in-process CLI commit preserves a
// TCP/TLS stream instead of downgrading it to plaintext UDP (#5712).
// NewSyslogClientDeferred builds a client WITHOUT dialing, for callers on a
// latency-sensitive path (#9326: the config-commit path).
//
// TCP/TLS ONLY, and the restriction is a correctness bound rather than caution.
// A stream client reconnects lazily: Send -> writeMsg fails "syslog connection
// closed" on a nil conn -> the stream branch performs one cooldown-gated
// reconnect and retries. UDP has NO such branch — writeMsg returns the error
// and the caller deliberately does not reconnect — so a deferred UDP client
// would never connect at all, silently, for the life of the config. UDP
// therefore keeps dialing at construction, which is cheap because a UDP "dial"
// binds rather than handshakes; its only blocking term is the name lookup, now
// bounded by dialUDP's own 5s dialer.
//
// Returns an error for a UDP or unsupported protocol so the restriction cannot
// be violated silently by a future caller.
func NewSyslogClientDeferred(host string, port int, sourceAddr, protocol string, tlsCfg *tls.Config) (*SyslogClient, error) {
	if !supportedTransport(protocol) {
		return nil, fmt.Errorf("%w %q", ErrUnsupportedTransport, protocol)
	}
	if protocol == "udp" {
		return nil, fmt.Errorf("%w: udp cannot be deferred — it never reconnects lazily",
			ErrUnsupportedTransport)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	return &SyslogClient{
		hostname:          hostname,
		remoteAddr:        net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		sourceAddr:        sourceAddr,
		protocol:          protocol,
		tlsConfig:         tlsCfg,
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}, nil
}

// Connect establishes the connection if it is not already up.
//
// #9326: this is what lets the commit path DEFER the dial without losing the
// #3351 operator signal ("receiver unreachable at apply"). The caller runs it
// off the commit path; a failure is reported there rather than charged to the
// operator's commit latency. Safe on a closed client (fails fast, #4806) and
// safe to call concurrently with Close.
func (s *SyslogClient) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errSyslogClientClosed
	}
	if s.loadConn() != nil {
		return nil
	}
	conn, err := s.dialConn()
	if err != nil {
		if s.closed.Load() {
			return errSyslogClientClosed
		}
		s.lastReconnectFailure = s.now()
		return err
	}
	if !s.storeConn(conn) {
		_ = closeSyslogConn(conn)
		return errSyslogClientClosed
	}
	return nil
}

// Connected reports whether this client currently holds a connection.
//
// #9326: it is what makes "the commit path did not dial" observable. A cell
// that only checks the apply was FAST proves nothing (a fast machine, or a
// target that refuses rather than blackholes, passes it with the dial still
// there), and a cell against an unreachable host cannot tell a deferred client
// from a failed dial — both end unconnected. Against a REACHABLE listener the
// two are distinguishable, and that is the shape the daemon cell uses.
func (s *SyslogClient) Connected() bool {
	return s.loadConn() != nil
}

// RemoteAddr is the "host:port" this client targets. Read-only after
// construction, so no lock is required (#9326: the warm path needs it for the
// operator warning).
func (s *SyslogClient) RemoteAddr() string { return s.remoteAddr }

func (s *SyslogClient) Protocol() string { return s.protocol }

// SourceAddr returns the source IP this client was constructed to bind its
// outbound connection to (empty when the kernel chooses the source). Exported
// so callers/tests can verify the source binding was honored -- e.g. that an
// in-process CLI commit applies the global `security log source-interface`
// fallback for a stream with no per-stream source-address, matching the daemon
// reconcile (#5738).
func (s *SyslogClient) SourceAddr() string { return s.sourceAddr }

// NewSyslogClientWithConn wraps an already-established net.Conn in a syslog
// client. No dial is performed: the connection is treated as already up, and
// protocol governs any later reconnect. It exists so callers — primarily
// tests in other packages such as pkg/daemon — can supply a custom net.Conn
// (an in-memory pipe or a Close-recording fake) and observe connection
// teardown, since the conn field is unexported. Production code builds
// clients through NewSyslogClientTransport.
func NewSyslogClientWithConn(conn net.Conn, protocol string) *SyslogClient {
	if protocol == "" {
		protocol = "udp"
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	return &SyslogClient{
		hostname:          hostname,
		protocol:          protocol,
		conn:              conn,
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}
}

// dial establishes a connection based on the configured protocol.
//
// An unknown protocol fails closed here (returns ErrUnsupportedTransport)
// rather than falling back to UDP. NewSyslogClientTransport already rejects
// bad tokens, so in production s.protocol is always udp/tcp/tls; this is
// defense-in-depth for any client built another way (and for the reconnect
// path) so an unrecognized transport can never silently downgrade a
// stream/secure syslog to plaintext UDP (#5581). "" is treated as UDP for
// parity with the constructors, which default an empty token to UDP.
func (s *SyslogClient) dial() (net.Conn, error) {
	switch s.protocol {
	case "tcp":
		return s.dialTCP()
	case "tls":
		return s.dialTLS()
	case "udp", "":
		return s.dialUDP()
	default:
		return nil, fmt.Errorf("%w %q", ErrUnsupportedTransport, s.protocol)
	}
}

func (s *SyslogClient) dialUDP() (net.Conn, error) {
	if s.sourceAddr != "" {
		laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.sourceAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve source %s: %w", s.sourceAddr, err)
		}
		raddr, err := net.ResolveUDPAddr("udp", s.remoteAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve remote %s: %w", s.remoteAddr, err)
		}
		return net.DialUDP("udp", laddr, raddr)
	}
	// #9326: the same 5s bound its TCP/TLS siblings carry. `net.Dial` on a
	// HOSTNAME performs a resolver lookup, and with no Dialer there was no
	// deadline and no context on it — an unbounded blocking call on the commit
	// path. The connectionless nature of UDP is why the SEND needs no timeout;
	// it says nothing about the NAME LOOKUP that precedes it, and conflating
	// the two is how this one stayed asymmetric with its siblings.
	//
	// `security log stream <s> host` is also a typed leaf as of #9326, so a
	// non-hostname is now refused at commit rather than handed to the resolver.
	// This bound is the belt for the tolerant load / HA-sync ingress, which
	// only warns.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.Dial("udp", s.remoteAddr)
}

func (s *SyslogClient) dialTCP() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if s.sourceAddr != "" {
		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.sourceAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve source %s: %w", s.sourceAddr, err)
		}
		dialer.LocalAddr = laddr
	}
	return dialer.Dial("tcp", s.remoteAddr)
}

func (s *SyslogClient) dialTLS() (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    s.tlsConfig,
	}
	if s.sourceAddr != "" {
		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.sourceAddr, "0"))
		if err != nil {
			return nil, fmt.Errorf("resolve source %s: %w", s.sourceAddr, err)
		}
		dialer.NetDialer.LocalAddr = laddr
	}
	return dialer.DialContext(context.Background(), "tcp", s.remoteAddr)
}

// reconnect attempts to re-establish the connection, subject to a cooldown so
// a down server cannot drive a fresh dial on every event. Called with mu held.
//
// Returns errReconnectCooldown without dialing if the previous reconnect cycle
// failed within reconnectCooldown; the caller drops the message and continues.
// The event hot-path therefore never spends more than one dial's worth of time
// per cooldown window on a dead target.
//
// The cooldown clock (lastReconnectFailure) is armed by THREE failure modes:
//   - a failed dial (set here),
//   - a write timeout (set by Send/SendBinary), and
//   - a dial that SUCCEEDS but whose subsequent retry-write fails (set by the
//     caller via armReconnectCooldown).
//
// Arming on dial-success-then-write-failure closes #2302: an accept-then-reset
// target (overloaded collector, half-open server, TLS app-layer drop) lets the
// dial succeed every time, so gating only on a failed dial left the cooldown
// permanently disengaged and every log message drove a fresh TCP connect +
// teardown — a dial storm. The clock is cleared only on a FULLY successful
// reconnect (dial AND the retry-write that follows it land), so the legitimate
// recovery path (a single broken-pipe error that the reconnect repairs) is
// unaffected.
func (s *SyslogClient) reconnect() error {
	if s.closed.Load() {
		return errSyslogClientClosed
	}
	if s.reconnectCooldownActive() {
		return errReconnectCooldown
	}
	if conn := s.detachConn(); conn != nil {
		_ = closeSyslogConn(conn)
	}
	if s.closed.Load() {
		return errSyslogClientClosed
	}
	conn, err := s.dialConn()
	if err != nil {
		if s.closed.Load() {
			return errSyslogClientClosed
		}
		s.lastReconnectFailure = s.now()
		return err
	}
	// Dial succeeded. Do NOT clear the cooldown clock yet — the retry-write may
	// still fail (accept-then-reset). The caller clears it on a successful
	// retry-write and arms it (armReconnectCooldown) if the retry-write fails.
	if !s.storeConn(conn) {
		_ = closeSyslogConn(conn)
		return errSyslogClientClosed
	}
	return nil
}

// reconnectCooldownActive reports whether a reconnect-cycle failure is still
// suppressing writes. Called with s.mu held.
func (s *SyslogClient) reconnectCooldownActive() bool {
	return s.reconnectCooldown > 0 &&
		!s.lastReconnectFailure.IsZero() &&
		s.now().Sub(s.lastReconnectFailure) < s.reconnectCooldown
}

// armReconnectCooldown records a failure on the cooldown clock so the NEXT
// write or reconnect within the window fails fast. Called with mu held from
// both the write-timeout path and the post-reconnect retry-write-failure path:
// without this, a hung or accept-then-reset target bypasses the cooldown
// because the initial write or dial never reaches the reconnect gate (#2302,
// #9911).
func (s *SyslogClient) armReconnectCooldown() {
	s.lastReconnectFailure = s.now()
}

// clearReconnectCooldown marks the reconnect cycle as fully recovered (dial AND
// the retry-write both succeeded), re-enabling immediate reconnect on the next
// failure. Called with mu held.
func (s *SyslogClient) clearReconnectCooldown() {
	s.lastReconnectFailure = time.Time{}
}

// errReconnectCooldown signals that a reconnect was suppressed by the cooldown
// window; the message is dropped (fail-fast) rather than blocking on a dial.
var errReconnectCooldown = fmt.Errorf("syslog reconnect in cooldown")

// errSyslogClientClosed signals that Close() already ran on this client
// (#4806); Send/SendBinary return it immediately without touching s.conn or
// attempting a reconnect.
var errSyslogClientClosed = fmt.Errorf("syslog client closed")

// dropReason classifies why a message was dropped, for the counter and the
// rate-limited warning.
type dropReason int

const (
	dropWrite    dropReason = iota // write timeout or write error
	dropDial                       // post-write-failure reconnect dial failed
	dropCooldown                   // reconnect suppressed by the cooldown window
)

// pendingDropWarn carries the fields for a rate-limited drop warning that MUST
// be emitted AFTER s.mu is released. Emitting slog.Warn while holding s.mu is a
// re-entrancy hazard: slog.Default() is the SyslogSlogHandler, whose Handle
// calls back into SyslogClient.Send for this same client, which re-locks s.mu
// (sync.Mutex is non-reentrant) → self-deadlock on the dataplane event reader
// goroutine (#2287). Capturing the snapshot under the lock and emitting after
// the deferred Unlock keeps the ≤1/s rate-limit intact while removing the hazard.
type pendingDropWarn struct {
	reason          dropReason
	err             error
	droppedWrites   uint64
	droppedDials    uint64
	droppedCooldown uint64
}

// pendingDebug is a slog.Debug record captured under s.mu and emitted after
// the deferred Unlock, for exactly the reason pendingDropWarn exists (#2287).
//
// #8597: the #2287 fix moved the drop WARNING out from under the lock but left
// two `slog.Debug("... reconnecting")` emits on the same failure path under it.
// Under `xpfd --debug` those records are enabled, so slog.Default() — a
// SyslogSlogHandler in the daemon — synchronously forwards them to this same
// client's Send, which re-locks the already-held s.mu on the same goroutine and
// wedges the caller (the dataplane event reader) forever. The #2287 cells could
// not see it because their base handler sits at Info, where slog.Debug
// short-circuits before reaching the handler.
type pendingDebug struct {
	msg string
	err error
}

// emit emits the captured debug record. It MUST be called with s.mu NOT held
// (via a defer ordered to run after the Unlock). A nil receiver is a no-op.
func (d *pendingDebug) emit(remoteAddr string) {
	if d == nil {
		return
	}
	slog.Debug(d.msg, "addr", remoteAddr, "err", d.err)
}

// noteDrop bumps the appropriate drop counter and, subject to the ≤1/s gate,
// returns a snapshot describing a warning the CALLER must emit after releasing
// s.mu (see pendingDropWarn). It returns nil when the rate-limit gate swallows
// the warning. Called with mu held; emits NO slog itself.
func (s *SyslogClient) noteDrop(reason dropReason, err error) *pendingDropWarn {
	switch reason {
	case dropCooldown:
		s.droppedCooldown.Add(1)
	case dropDial:
		s.droppedDials.Add(1)
	default:
		s.droppedWrites.Add(1)
	}
	now := s.now()
	if !s.lastDropLog.IsZero() && now.Sub(s.lastDropLog) < time.Second {
		return nil
	}
	s.lastDropLog = now
	return &pendingDropWarn{
		reason:          reason,
		err:             err,
		droppedWrites:   s.droppedWrites.Load(),
		droppedDials:    s.droppedDials.Load(),
		droppedCooldown: s.droppedCooldown.Load(),
	}
}

// emit emits the rate-limited drop warning. It MUST be called with s.mu NOT
// held (typically via a defer ordered to run after the Unlock) so the slog.Warn
// cannot re-enter SyslogClient.Send under the lock (#2287). A nil receiver
// (rate-limited) is a no-op.
func (w *pendingDropWarn) emit(remoteAddr string) {
	if w == nil {
		return
	}
	slog.Warn("syslog message dropped",
		"addr", remoteAddr,
		"reason", w.reason.String(),
		"dropped_writes", w.droppedWrites,
		"dropped_dials", w.droppedDials,
		"dropped_cooldown", w.droppedCooldown,
		"err", w.err)
}

// String renders the drop reason for the warning attribute.
func (r dropReason) String() string {
	switch r {
	case dropDial:
		return "dial"
	case dropCooldown:
		return "cooldown"
	default:
		return "write"
	}
}

// DroppedWrites reports the count of messages dropped because the write itself
// failed — a write timeout (SetWriteDeadline expiry) or a write error
// (ECONNRESET/EPIPE). Reconnect dial failures are counted separately by
// DroppedDials, not here (#2287). Observability only.
func (s *SyslogClient) DroppedWrites() uint64 { return s.droppedWrites.Load() }

// DroppedDials reports the count of messages dropped because the
// post-write-failure reconnect dial failed (observability).
func (s *SyslogClient) DroppedDials() uint64 { return s.droppedDials.Load() }

// DroppedCooldown reports the count of messages dropped because a reconnect was
// suppressed by the cooldown window (observability).
func (s *SyslogClient) DroppedCooldown() uint64 { return s.droppedCooldown.Load() }

// Send sends a syslog message with the given severity.
// For TCP/TLS, uses RFC 6587 octet-counting framing.
// On write failure for TCP/TLS, attempts one reconnect.
func (s *SyslogClient) Send(severity int, msg string) error {
	// #6585: neutralize control bytes before the message becomes a syslog
	// frame. This is the LAST boundary before the wire and every caller passes
	// through it, so a producer cannot be added that bypasses it — which is the
	// point: the producers are open-ended (any slog attribute anywhere in the
	// daemon) and a per-producer fix rots on the next one.
	//
	// Go's own slog text handler quotes non-printing attribute values
	// (log/slog/text_handler.go), which is why the local stderr/journald copy
	// was never exposed. SyslogSlogHandler deliberately bypasses that path to
	// build the syslog framing itself, and reintroduced the raw value.
	//
	// Two distinct consequences, both worse here than on a terminal because
	// syslog is aggregated and long-retained:
	//
	//  1. LOG INJECTION. A bare LF is a record delimiter in RFC 3164, so an
	//     embedded newline forges a frame boundary and lets the payload
	//     synthesize an entire additional syslog line — arbitrary
	//     facility/severity/timestamp/host as far as the collector is
	//     concerned.
	//  2. DEFERRED TERMINAL INJECTION. ESC/CSI stored verbatim in the
	//     collector fires whenever an operator later cats or tails the
	//     archive.
	//
	// SanitizeForDisplay (single-line) rather than SanitizeBlockForDisplay:
	// the block variant deliberately PRESERVES LF, which is right for a
	// multi-line table and exactly wrong for a single syslog frame. It has an
	// allocation-free fast path for the already-clean case, which is every
	// ordinary record.
	msg = termsafe.SanitizeForDisplay(msg)

	priority := s.Facility*8 + severity
	var line string
	if s.Format == "sd-syslog" {
		// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
		ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
		line = fmt.Sprintf("<%d>1 %s %s xpf - - - %s", priority, ts, s.hostname, msg)
	} else {
		// RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
		ts := time.Now().Format(time.Stamp) // "Jan _2 15:04:05"
		line = fmt.Sprintf("<%d>%s %s xpf: %s", priority, ts, s.hostname, msg)
	}

	// pendingWarn is captured under s.mu by noteDrop and emitted AFTER the
	// deferred Unlock — emitting slog.Warn under s.mu re-enters this same
	// client's Send and self-deadlocks (#2287). Defers run LIFO, so this
	// emit-defer (registered first) runs after the Unlock-defer.
	var pendingWarn *pendingDropWarn
	var pendingDbg *pendingDebug
	defer func() {
		pendingDbg.emit(s.remoteAddr)
		pendingWarn.emit(s.remoteAddr)
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed.Load() {
		// Close() already ran: fail fast, never reconnect (#4806).
		return errSyslogClientClosed
	}
	if s.protocol != "udp" && s.reconnectCooldownActive() {
		pendingWarn = s.noteDrop(dropCooldown, errReconnectCooldown)
		return errReconnectCooldown
	}

	if err := s.writeMsg(line); err != nil {
		if s.closed.Load() {
			// Close may have interrupted the write. Count the dropped record
			// before returning the terminal closed-client error.
			pendingWarn = s.noteDrop(dropWrite, err)
			return errSyslogClientClosed
		}
		// For stream protocols, attempt one cooldown-gated reconnect. UDP has
		// no connection to re-establish, so it returns the error — but it is
		// now a BOUNDED error: #9025 armed the same write deadline on the
		// datagram path, so "UDP never blocks" is not asserted here either.
		// Nor is it a SILENT error: #9165 counts every UDP write failure below.
		if s.protocol != "udp" {
			// A write-deadline TIMEOUT was already bounded by the deadline;
			// do NOT reconnect+retry (that would re-arm another writeTimeout,
			// doubling the worst-case stall on the event reader, #2287). Drop
			// and return. Only a genuine connection error reconnects.
			if isTimeout(err) {
				s.armReconnectCooldown()
				pendingWarn = s.noteDrop(dropWrite, err)
				return err
			}
			// Captured, not emitted: this runs under s.mu (#8597).
			pendingDbg = &pendingDebug{msg: "syslog send failed, reconnecting", err: err}
			if rerr := s.reconnect(); rerr != nil {
				if rerr == errSyslogClientClosed {
					pendingWarn = s.noteDrop(dropWrite, err)
					return rerr
				}
				// Cooldown or dial failure: drop and continue. The event
				// reader must make forward progress regardless.
				if rerr == errReconnectCooldown {
					pendingWarn = s.noteDrop(dropCooldown, err)
				} else {
					pendingWarn = s.noteDrop(dropDial, rerr)
				}
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			if s.closed.Load() {
				pendingWarn = s.noteDrop(dropWrite, err)
				return errSyslogClientClosed
			}
			if werr := s.writeMsg(line); werr != nil {
				if s.closed.Load() {
					pendingWarn = s.noteDrop(dropWrite, werr)
					return errSyslogClientClosed
				}
				// Dial succeeded but the retry-write failed (accept-then-reset).
				// Arm the cooldown so the NEXT message's reconnect is throttled
				// instead of dialing afresh every time (#2302).
				s.armReconnectCooldown()
				pendingWarn = s.noteDrop(dropWrite, werr)
				return werr
			}
			// Full recovery: dial AND retry-write both succeeded. Clear the
			// cooldown clock so a future failure can reconnect immediately.
			s.clearReconnectCooldown()
			return nil
		}
		// #9025 counted the UDP DEADLINE EXPIRY it had just introduced. #9165:
		// count every UDP write failure, not only that one.
		//
		// UDP is the DEFAULT transport, and the socket is CONNECTED
		// (dialUDP), so Linux delivers the ICMP port-unreachable from a dead
		// collector back as ECONNREFUSED on the next write. That is a real,
		// observable failure and it is exactly the incident an operator needs
		// to see. Under the old gate it was neither counted nor warned: on the
		// default transport `droppedWrites` stayed 0 while every message went
		// nowhere, so all three instruments — the counter, the rate-limited
		// warning, and a `show` rendering the collector as configured — read
		// healthy at once.
		//
		// There is no reconnect arm to add here: a datagram socket has no
		// connection to re-establish, so the message is still dropped and the
		// error still returned. Only the ACCOUNTING changes.
		pendingWarn = s.noteDrop(dropWrite, err)
		return err
	}
	return nil
}

// isTimeout reports whether err is a network timeout (e.g. a SetWriteDeadline
// expiry surfaces as os.ErrDeadlineExceeded, which satisfies net.Error with
// Timeout()==true). A timeout is already bounded by the deadline, so the stream
// Send path drops it rather than reconnect+retrying (#2287).
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// datagramWrite writes one UDP datagram under the same bounded write deadline
// the stream path uses (#9025).
//
// A SEPARATE function from streamWrite, not a shared one, because the two
// differ in exactly the way that matters: PARTIAL WRITES. A stream write can
// return 0 < n < len(b), leaving a truncated octet-counted frame that
// permanently desyncs the collector's length parser — hence streamWrite's conn
// teardown (#3874). A datagram is atomic: the kernel queues all of it or none,
// so there is no partial frame to recover from and tearing the conn down would
// lose the socket for no benefit. Sharing one function would have carried the
// stream's teardown into a path that cannot need it — how a correct-looking
// generalisation acquires a wrong branch.
//
// A deadline expiry surfaces as os.ErrDeadlineExceeded, and the Send path
// counts it as a drop rather than letting it vanish. That is the point: volume
// backpressure already existed (#3478); LATENCY backpressure did not, and a
// hung write never returned to be counted. Since #9165 the Send path counts
// EVERY datagram write error, so this no longer depends on isTimeout — the
// ECONNREFUSED a connected UDP socket gets back from a dead collector is
// counted on the same footing.
func (s *SyslogClient) datagramWrite(conn net.Conn, b []byte) error {
	if s.writeTimeout > 0 {
		// Best-effort, as in streamWrite: a conn that does not support
		// deadlines still gets its Write, just unbounded.
		_ = conn.SetWriteDeadline(s.now().Add(s.writeTimeout))
	}
	_, err := conn.Write(b)
	return err
}

// writeMsg writes the framed message to the connection. Called with mu held.
func (s *SyslogClient) writeMsg(line string) error {
	conn := s.loadConn()
	if conn == nil {
		return fmt.Errorf("syslog connection closed")
	}
	if s.protocol == "udp" {
		return s.datagramWrite(conn, []byte(line))
	}
	// TCP/TLS: RFC 6587 octet-counting: "<length> <message>"
	framed := fmt.Sprintf("%d %s", len(line), line)
	return s.streamWrite(conn, []byte(framed))
}

// streamWrite writes to a TCP/TLS conn with a bounded write deadline so a
// hung/congested server cannot block the dataplane event reader indefinitely.
// A deadline expiry surfaces as a timeout error (os.ErrDeadlineExceeded);
// callers treat it as a write failure and drop the message. Called with mu
// held; conn is non-nil.
//
// Partial-frame teardown (#3874). A stream write can return 0 < n < len(b) —
// some but not all of the framed record reached the wire — when the deadline
// expires (or the peer resets) mid-write. Both stream framings are corrupted
// by a truncated write: the RFC 6587 octet-count prefix ("<len> <msg>") and
// the self-framing binary record (length at offset [3:5]) both tell the
// collector to expect `len` bytes, so a truncated frame leaves the collector's
// length parser mid-record — a permanent desync of the audit/forensics
// channel, exactly under incident load (slow writes). A half-written
// octet-counted frame is unrecoverable in-stream; the only correct recovery is
// close+reconnect so a later frame starts a fresh, correctly-counted stream.
// So on a partial write we tear the conn down (conn=nil). A partial
// non-timeout write reconnects in the same Send; a partial timeout arms the
// reconnect cooldown, which makes immediate later Sends fail fast before
// attempting another write or dial. Once the window expires, a later Send
// reconnects to a fresh stream. A clean 0-byte TCP timeout wrote nothing and
// stays drop-without-close per #2287. A TLS timeout also tears down the conn:
// crypto/tls documents its state as corrupt after a timed-out Write, so the
// next post-cooldown Send must reconnect rather than reuse it.
//
// closeSyslogConn closes the raw socket before asking *tls.Conn to send its
// close_notify. This keeps TLS shutdown bounded against a blackholed collector;
// the expected close_notify error is ignored after the raw socket is closed.
// Closing the raw conn here does NOT reintroduce the #2285 re-entrant deadlock:
// it never routes back through slog/SyslogSlogHandler.Handle/SyslogClient.Send.
func (s *SyslogClient) streamWrite(conn net.Conn, b []byte) error {
	if s.writeTimeout > 0 {
		// Best-effort: if SetWriteDeadline is unsupported by the conn it
		// returns an error we ignore (the Write still proceeds, just
		// without the bound). Real TCP/TLS conns always support it.
		_ = conn.SetWriteDeadline(s.now().Add(s.writeTimeout))
	}
	n, err := conn.Write(b)
	_, isTLS := conn.(*tls.Conn)
	if (n > 0 && n < len(b)) || (isTLS && isTimeout(err)) {
		// corrupt state after a timed-out Write. In either case, discard the
		// connection so a later Send cannot reuse an unrecoverable stream.
		_ = closeSyslogConn(conn)
		s.connMu.Lock()
		s.conn = nil
		s.connMu.Unlock()
	}
	return err
}

// SendBinary sends a raw binary log record. The record is self-framing
// (contains its own length at offset [3:5]), so no additional framing is added.
// On write failure for TCP/TLS, attempts one reconnect.
func (s *SyslogClient) SendBinary(data []byte) error {
	// See Send: the drop warning is emitted after the deferred Unlock to avoid
	// the slog re-entrancy self-deadlock (#2287).
	var pendingWarn *pendingDropWarn
	var pendingDbg *pendingDebug
	defer func() {
		pendingDbg.emit(s.remoteAddr)
		pendingWarn.emit(s.remoteAddr)
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed.Load() {
		// Close() already ran: fail fast, never reconnect (#4806).
		return errSyslogClientClosed
	}
	if s.protocol != "udp" && s.reconnectCooldownActive() {
		pendingWarn = s.noteDrop(dropCooldown, errReconnectCooldown)
		return errReconnectCooldown
	}

	if err := s.writeBinaryMsg(data); err != nil {
		if s.closed.Load() {
			// Close may have interrupted the write. Count the dropped record
			// before returning the terminal closed-client error.
			pendingWarn = s.noteDrop(dropWrite, err)
			return errSyslogClientClosed
		}
		if s.protocol != "udp" {
			// Write-deadline timeout: already bounded — drop, don't retry (#2287).
			if isTimeout(err) {
				s.armReconnectCooldown()
				pendingWarn = s.noteDrop(dropWrite, err)
				return err
			}
			// Captured, not emitted: this runs under s.mu (#8597).
			pendingDbg = &pendingDebug{msg: "syslog binary send failed, reconnecting", err: err}
			if rerr := s.reconnect(); rerr != nil {
				if rerr == errSyslogClientClosed {
					pendingWarn = s.noteDrop(dropWrite, err)
					return rerr
				}
				if rerr == errReconnectCooldown {
					pendingWarn = s.noteDrop(dropCooldown, err)
				} else {
					pendingWarn = s.noteDrop(dropDial, rerr)
				}
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			if s.closed.Load() {
				pendingWarn = s.noteDrop(dropWrite, err)
				return errSyslogClientClosed
			}
			if werr := s.writeBinaryMsg(data); werr != nil {
				if s.closed.Load() {
					pendingWarn = s.noteDrop(dropWrite, werr)
					return errSyslogClientClosed
				}
				// Dial succeeded but the retry-write failed (accept-then-reset):
				// arm the cooldown so the next reconnect is throttled (#2302).
				s.armReconnectCooldown()
				pendingWarn = s.noteDrop(dropWrite, werr)
				return werr
			}
			// Full recovery: clear the cooldown clock.
			s.clearReconnectCooldown()
			return nil
		}
		// #9165: count every UDP write failure, not only the #9025 deadline
		// expiry. See Send for the full reasoning — UDP is the default, the
		// socket is connected so a dead collector surfaces ECONNREFUSED, and
		// leaving it uncounted made the default transport silent on all three
		// instruments at once. There is no reconnect arm on a datagram socket;
		// only the accounting changes.
		pendingWarn = s.noteDrop(dropWrite, err)
		return err
	}
	return nil
}

// writeBinaryMsg writes the raw binary data to the connection. Called with mu held.
func (s *SyslogClient) writeBinaryMsg(data []byte) error {
	conn := s.loadConn()
	if conn == nil {
		return fmt.Errorf("syslog connection closed")
	}
	if s.protocol == "udp" {
		return s.datagramWrite(conn, data)
	}
	return s.streamWrite(conn, data)
}

// ShouldSend returns true if the event severity passes this client's filter.
// Lower severity number = higher priority (emergency=0 < error=3 < info=6). A
// record is sent iff it is at least as severe as MinSeverity — the Junos
// "<severity> AND more severe" threshold. The two sentinels are handled
// explicitly so the most-severe level (emergency) does not collide with the
// send-all zero value (#5314):
//
//   - MinSeverity == 0 (no filter / Junos any / unset) → send everything.
//   - MinSeverity == SeverityNone (Junos none) → send nothing.
//   - MinSeverity == SeverityEmergency (Junos emergency) → send only emergency
//     (SyslogEmergency==0), i.e. severity <= 0.
//   - otherwise MinSeverity is a raw RFC level alert(1)..debug(7); send iff the
//     record's severity is <= MinSeverity (equal or more severe).
func (s *SyslogClient) ShouldSend(severity int) bool {
	switch s.MinSeverity {
	case 0:
		return true
	case SeverityNone:
		return false
	case SeverityEmergency:
		return severity <= SyslogEmergency
	default:
		return severity <= s.MinSeverity
	}
}

// minSeverityRestrictRank ranks a MinSeverity threshold code by how much it
// restricts forwarding: HIGHER rank = MORE restrictive (forwards fewer
// records). Ordering, most→least restrictive: none, emergency, alert,
// critical, error, warning, notice, info, debug, any(0). Used to merge the
// per-facility severities of one syslog host into a single most-restrictive
// client filter (the client holds one MinSeverity, not a per-facility map).
func minSeverityRestrictRank(min int) int {
	switch min {
	case SeverityNone: // send nothing — most restrictive
		return 100
	case SeverityEmergency: // send only emergency
		return 99
	case 0: // no filter / any — least restrictive
		return -1
	default: // raw RFC level: alert(1)..debug(7); lower value = more restrictive
		return 8 - min
	}
}

// MoreRestrictiveMinSeverity returns whichever of two MinSeverity threshold
// codes forwards the FEWER records. When a syslog host lists several
// `<facility> <severity>` pairs the client — which carries a single
// MinSeverity — adopts the most restrictive of them (#5314).
func MoreRestrictiveMinSeverity(a, b int) int {
	if minSeverityRestrictRank(b) > minSeverityRestrictRank(a) {
		return b
	}
	return a
}

// ShouldSendEvent returns true if both severity and category filters pass.
func (s *SyslogClient) ShouldSendEvent(severity int, categoryBit uint8) bool {
	if !s.ShouldSend(severity) {
		return false
	}
	return s.Categories == 0 || s.Categories&categoryBit != 0
}

// ParseCategory converts a Junos category name to a bitmask.
// "all" or "" returns 0 (no filter = send everything).
func ParseCategory(name string) uint8 {
	switch name {
	case "all", "":
		return 0
	case "session":
		return CategorySession
	case "policy":
		return CategoryPolicy
	case "screen":
		return CategoryScreen
	case "firewall":
		return CategoryFirewall
	default:
		return 0
	}
}

// ParseCategoryStrict is the fail-closed variant of ParseCategory (#3383).
// "all" or "" returns (0, nil) — the explicit "no filter" sentinel — while an
// unrecognized name returns a non-nil error instead of silently collapsing to
// 0 (which the lenient ParseCategory does). Surfaces that must NOT fail open on
// a typo (the SSE log/event stream, where a misspelled query would widen a live
// feed to everything) use this instead of treating an unknown token as "all".
func ParseCategoryStrict(name string) (uint8, error) {
	switch name {
	case "all", "":
		return 0, nil
	case "session":
		return CategorySession, nil
	case "policy":
		return CategoryPolicy, nil
	case "screen":
		return CategoryScreen, nil
	case "firewall":
		return CategoryFirewall, nil
	default:
		return 0, fmt.Errorf("unknown log category %q (want session, policy, screen, firewall, or all)", name)
	}
}

// ParseSeverityStrict is the fail-closed variant of ParseSeverity (#3383).
// An empty string returns (0, nil) — "no filter". An unrecognized name returns
// a non-nil error rather than 0, so a typo'd severity cannot silently disable
// filtering on the SSE log stream.
func ParseSeverityStrict(name string) (int, error) {
	switch name {
	case "":
		return 0, nil
	case "error":
		return SyslogError, nil
	case "warning":
		return SyslogWarning, nil
	case "notice":
		return SyslogNotice, nil
	case "info":
		return SyslogInfo, nil
	default:
		return 0, fmt.Errorf("unknown severity %q (want error, warning, notice, info)", name)
	}
}

// ParseSeverity converts a Junos syslog severity name to the MinSeverity
// threshold code used by ShouldSend. It maps ALL ten severities the config
// schema accepts (junosSyslogSeverities in pkg/config/schema_system.go), plus
// the two extremes as sentinels (#5314):
//
//	any                        -> 0                 (no filter, send all)
//	none                       -> SeverityNone (-2) (send nothing)
//	emergency                  -> SeverityEmergency (-1) (send only emergency)
//	alert/critical/error/
//	warning/notice/info/debug  -> raw RFC level 1..7
//
// The mapping is case-insensitive. Before #5314 only error/warning/info were
// mapped and everything else fell through to 0 = send-all, so a legitimate
// `host H <facility> critical` collapsed to no-filter and over-forwarded
// info/warning/error records the operator never authorized.
//
// Tolerant contract (preserved): an unrecognized name returns 0 (no filter),
// matching the historical behavior. The strict commit-time schema
// (ValidateEnum(junosSyslogSeverities)) rejects unknown severities before they
// reach here; ParseSeverityStrict is the fail-closed variant used by the SSE
// surface.
func ParseSeverity(name string) int {
	switch strings.ToLower(name) {
	case "any":
		return 0
	case "none":
		return SeverityNone
	case "emergency":
		return SeverityEmergency
	case "alert":
		return SyslogAlert
	case "critical":
		return SyslogCritical
	case "error":
		return SyslogError
	case "warning":
		return SyslogWarning
	case "notice":
		return SyslogNotice
	case "info":
		return SyslogInfo
	case "debug":
		return SyslogDebug
	default:
		return 0
	}
}

// ParseFacilityChecked converts a facility name to its numeric code and
// reports whether the name was RECOGNIZED (#5797).
//
// ParseFacility below collapses "unrecognized" and "local0" into the same
// return value, so a caller cannot tell an authored `local0` from a typo that
// silently became local0 — records then leave under a facility the operator
// never wrote, and the remote collector's facility-based routing/filtering
// silently misfiles them. Callers that can surface the difference (the daemon's
// syslog client wiring) MUST use this form; ParseFacility is retained for
// callers that genuinely only want the code.
//
// The recognized set is exactly ParseFacility's mapped names — no more, no
// less. It is NOT derived from a config-side gate, because there is no gate to
// derive it from: `system syslog <dest> <facility> <severity>` models the
// facility as the schema's wildcard KEY (pkg/config syslogFacilitySeverityLeaf)
// and attaches a validator only to the severity VALUE, so any facility spelling
// whatsoever commits clean and arrives at the daemon verbatim. (pkg/config's
// `syslogFacilities` enum does gate a facility name, but on the unrelated
// `security log ... facility` leaf — do not mistake it for this surface.)
// TestParseFacilityCheckedKnownSetIsExactlyParseFacility_5797 pins the
// two-function agreement over the whole mapping table.
//
// `any` is deliberately NOT recognized: it is a selector wildcard meaningful to
// the rsyslog-backed file/user destinations, not a numeric facility a host
// client can stamp on a record.
func ParseFacilityChecked(name string) (int, bool) {
	switch name {
	case "kern", "user", "daemon", "auth", "syslog",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
		"change-log":
		return ParseFacility(name), true
	default:
		// #6830: every documented Junos facility is now MAPPED, so it is
		// `known` here too. Without this the emit path would file the record
		// correctly while the caller still warned that it had substituted
		// local0 — a warning that is false the moment the mapping lands, and
		// the fastest way to train an operator to ignore the one warning that
		// still means something.
		if _, ok := junosRemoteFacility[name]; ok {
			return ParseFacility(name), true
		}
		return FacilityLocal0, false
	}
}

// junosRemoteFacility is the DOCUMENTED Junos facility→wire mapping for
// messages directed to a remote destination (#6830).
//
// This is a LOOKUP, not a judgement. Junos publishes it, and the two rules
// together cover the whole `[edit system syslog]` vocabulary:
//
//  1. "Table 3: Default Facilities for Messages Directed to a Remote
//     Destination" lists the six Junos-SPECIFIC facilities whose names a
//     standard syslogd cannot interpret, each with a localX stand-in:
//     change-log→local6, conflict-log→local5, dfc→local1, firewall→local3,
//     interactive-commands→local7, pfe→local4.
//  2. "For facilities that are not listed, the default alternative name is
//     the same as the local facility name" — so authorization, daemon, ftp,
//     kernel, ntp and user go out as themselves.
//
// The repository already implemented ONE row of this table, `change-log` →
// local6 in ParseFacility, which is exactly Table 3's value. The table was
// consulted once and never finished; the remaining names fall through
// ParseFacility's `default:` to local0.
//
// NOTE THE SPELLINGS. Junos writes `authorization` and `kernel`; ParseFacility
// recognizes the BSD spellings `auth` and `kern`. An operator configuring this
// box as the Junos clone it is therefore gets local0 for the two most obvious
// facilities in the vocabulary.
//
// THIS TABLE IS NOW THE WIRE. ParseFacility consults it first, so a documented
// Junos facility leaves the box under the code Junos would use (#6830).
//
// It shipped one round earlier as data only, feeding a diagnostic that told an
// operator what Junos WOULD send while the contract decision stayed open. That
// ordering was deliberate and is the migration path: anyone whose collector
// buckets an affected name on local0 was warned, by name, before the records
// moved.
var junosRemoteFacility = map[string]int{
	// Table 3 — Junos-specific names with a localX stand-in.
	"change-log":           FacilityLocal6,
	"conflict-log":         FacilityLocal5,
	"dfc":                  FacilityLocal1,
	"firewall":             FacilityLocal3,
	"interactive-commands": FacilityLocal7,
	"pfe":                  FacilityLocal4,
	// Not listed in Table 3 — "the default alternative name is the same as the
	// local facility name".
	"authorization": FacilityAuth,
	"daemon":        FacilityDaemon,
	"ftp":           FacilityFTP,
	"kernel":        FacilityKern,
	"user":          FacilityUser,
	// `ntp` is deliberately ABSENT (#6830 round 2). It looked like a row: a
	// prose summary of the Junos facility vocabulary lists it, and RFC 5424
	// assigns 12 to the NTP subsystem, so FacilityNTP below is a real code.
	// But Table 2 ("Facility Codes Reported in Priority Information") carries
	// the NTP code with NO Junos facility name against it, and the documented
	// rule is that a code whose second column is empty "cannot be included in
	// a statement at the [edit system syslog] hierarchy level". So `ntp` is not
	// configurable Junos, and a row here would be xpf INVENTING a mapping for
	// a name Junos itself rejects — the "picked by implementation convenience"
	// this issue exists to avoid. It falls through to local0 and the unmapped
	// diagnostic, which is the correct handling for a name with no documented
	// wire facility.
	//
	// The two sources conflict on this one name and only this one. That is
	// precisely why it is out: a mapping we cannot substantiate must not move a
	// record.
}

// JunosRemoteFacility reports the facility Junos would put on the wire for a
// `[edit system syslog]` facility name directed to a remote destination, and
// whether name is in that vocabulary at all (#6830).
//
// It distinguishes the two cases the current diagnostic cannot tell apart:
//
//   - a real Junos facility this box does not yet map (junos=true) — the
//     operator wrote valid Junos and the records are misfiled;
//   - a name in neither vocabulary (junos=false) — a typo, where local0 is a
//     substitution for something that means nothing.
//
// `any` is deliberately absent: it names no facility (see FacilityIsWildcard).
func JunosRemoteFacility(name string) (int, bool) {
	code, ok := junosRemoteFacility[name]
	return code, ok
}

// FacilityMisfiled reports that name is a valid Junos syslog facility whose
// records this box currently forwards under a DIFFERENT facility than Junos
// would (#6830), and returns the two codes.
//
// It is the predicate the operator diagnostic keys on, so a name xpf already
// maps correctly (change-log, daemon, user) never warns, and a typo is
// reported as a typo rather than as a mapping gap.
func FacilityMisfiled(name string) (emitted, junos int, misfiled bool) {
	want, isJunos := JunosRemoteFacility(name)
	if !isJunos {
		return ParseFacility(name), 0, false
	}
	got := ParseFacility(name)
	return got, want, got != want
}

// FacilityIsWildcard reports whether name is the Junos "all facilities"
// wildcard rather than a facility name to be mapped.
//
// #6829 A3: `set system syslog host <ip> any <sev>` is the CANONICAL Junos
// form — it is the repo's own fixture in parser_system_test.go — and `any`
// deliberately names no facility. ParseFacilityChecked correctly reports it
// unmapped (it has no case, so it takes the local0 default like any other
// unrecognized name), but a CALLER must not turn that into a substitution
// warning: the #5797 warning says "records will carry a facility the
// configuration does not name", which for `any` is literally false — the
// configuration names none on purpose. Warning on the canonical form is exactly
// the train-operators-to-ignore-it failure the warning exists to avoid.
//
// This is a caller-side suppression, not a mapping change: ParseFacility and
// ParseFacilityChecked both still return FacilityLocal0 for `any`, unchanged.
func FacilityIsWildcard(name string) bool { return name == "any" }

// ParseFacility converts a facility name to its numeric code.
// Returns FacilityLocal0 for unrecognized names.
//
// #5797: prefer ParseFacilityChecked at any call site that can report the
// substitution — this form cannot distinguish an unmapped name from an
// authored local0.
func ParseFacility(name string) int {
	// #6830: the documented Junos table is consulted FIRST.
	//
	// Before this, nine of the thirteen Junos facility names fell through to
	// local0 — including `authorization` and `kernel`, the two buckets a
	// security collector is most likely watching. An operator who writes
	// `authorization` has told the box, in Junos, to file authentication
	// records under `auth`; emitting local0 was not a conservative default, it
	// was the box failing to mean what its own configuration language says.
	// `change-log -> local6` was already implemented below, so the intended
	// contract was half-expressed in the tree: an unfinished table, not a
	// considered choice.
	//
	// This MOVES records for a collector already bucketing an affected name on
	// local0. That is upgrade-visible, and it is why the misfiled diagnostic
	// (#6830, FacilityMisfiled) shipped first: it fires before the flip for
	// anyone affected, names the facility, and says what will change.
	if code, ok := junosRemoteFacility[name]; ok {
		return code
	}
	switch name {
	case "kern":
		return FacilityKern
	case "user":
		return FacilityUser
	case "daemon":
		return FacilityDaemon
	case "auth":
		return FacilityAuth
	case "syslog":
		return FacilitySyslog
	case "local0":
		return FacilityLocal0
	case "local1":
		return FacilityLocal1
	case "local2":
		return FacilityLocal2
	case "local3":
		return FacilityLocal3
	case "local4":
		return FacilityLocal4
	case "local5":
		return FacilityLocal5
	case "local6":
		return FacilityLocal6
	case "local7":
		return FacilityLocal7
	case "change-log":
		return FacilityLocal6
	default:
		return FacilityLocal0
	}
}

// Close closes the underlying connection and marks the client closed (#4806).
// It marks closed and detaches the socket without taking s.mu, so a concurrent
// Send blocked in conn.Write cannot serialize a reconfigure commit behind it.
// Once Close returns, Send/SendBinary always fail fast and never dial a fresh
// connection.
func (s *SyslogClient) Close() error {
	// Mark the client closed before detaching the socket. This path must not
	// take s.mu: an in-flight Send holds it across conn.Write, and Close must
	// be able to interrupt that Write for a reconfigure commit.
	s.closed.Store(true)
	conn := s.detachConn()
	var err error
	if conn != nil {
		err = closeSyslogConn(conn)
	}
	// Real sockets unblock the in-flight Write promptly. Keep the join bounded
	// for custom connections whose Close does not interrupt Write.
	s.joinSendBounded()
	return err
}
