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
)

// Resilience defaults for the stream (TCP/TLS) transports. These bound the
// time the dataplane event hot-path can spend inside a single Send and rate-
// limit reconnect attempts so a down server cannot drive a fresh 5s-timeout
// dial on every event. UDP is connectionless and never blocks on Write, so
// these do not apply to it.
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
)

// SyslogClient sends syslog messages over UDP, TCP, or TLS.
// Supports RFC 3164 (BSD) and RFC 5424 (structured-data syslog) formats.
// TCP/TLS use RFC 6587 octet-counting framing.
type SyslogClient struct {
	mu          sync.Mutex
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

	// closed is set true by Close() (mu-guarded) and checked at the top of
	// Send/SendBinary. Without it, a Send racing a Close (both serialize on
	// mu, so this is a happens-after ordering, not a data race) can run
	// AFTER Close() returns, see the pre-#4806 code's now-stale
	// s.conn != nil, hit a "use of closed network connection" write error,
	// and — since that is treated as a generic write failure — fall into
	// reconnect(), silently re-establishing a brand-new socket to a target
	// the caller believed was torn down (#4806). Checking closed instead of
	// conn != nil makes Close() terminal: no Send after Close() may dial.
	closed bool
}

// now returns the client's clock (overridable in tests).
func (s *SyslogClient) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
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
	return net.Dial("udp", s.remoteAddr)
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
// The cooldown clock (lastReconnectFailure) is armed by BOTH failure modes:
//   - a failed dial (set here), and
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
	if s.reconnectCooldown > 0 && !s.lastReconnectFailure.IsZero() {
		if s.now().Sub(s.lastReconnectFailure) < s.reconnectCooldown {
			return errReconnectCooldown
		}
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	conn, err := s.dialConn()
	if err != nil {
		s.lastReconnectFailure = s.now()
		return err
	}
	// Dial succeeded. Do NOT clear the cooldown clock yet — the retry-write may
	// still fail (accept-then-reset). The caller clears it on a successful
	// retry-write and arms it (armReconnectCooldown) if the retry-write fails.
	s.conn = conn
	return nil
}

// armReconnectCooldown records a reconnect-cycle failure on the cooldown clock
// so the NEXT reconnect within the window fails fast. Called with mu held from
// the post-reconnect retry-write-failure path (dial succeeded, write failed):
// without this, an accept-then-reset target bypasses the cooldown forever
// because the dial never errors (#2302).
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
	defer func() { pendingWarn.emit(s.remoteAddr) }()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		// Close() already ran: fail fast, never reconnect (#4806).
		return errSyslogClientClosed
	}

	if err := s.writeMsg(line); err != nil {
		// For stream protocols, attempt one cooldown-gated reconnect. UDP
		// never blocks or needs reconnect, so it just returns the error.
		if s.protocol != "udp" {
			// A write-deadline TIMEOUT was already bounded by the deadline;
			// do NOT reconnect+retry (that would re-arm another writeTimeout,
			// doubling the worst-case stall on the event reader, #2287). Drop
			// and return. Only a genuine connection error reconnects.
			if isTimeout(err) {
				pendingWarn = s.noteDrop(dropWrite, err)
				return err
			}
			slog.Debug("syslog send failed, reconnecting", "addr", s.remoteAddr, "err", err)
			if rerr := s.reconnect(); rerr != nil {
				// Cooldown or dial failure: drop and continue. The event
				// reader must make forward progress regardless.
				if rerr == errReconnectCooldown {
					pendingWarn = s.noteDrop(dropCooldown, err)
				} else {
					pendingWarn = s.noteDrop(dropDial, rerr)
				}
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			if werr := s.writeMsg(line); werr != nil {
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

// writeMsg writes the framed message to the connection. Called with mu held.
func (s *SyslogClient) writeMsg(line string) error {
	if s.conn == nil {
		return fmt.Errorf("syslog connection closed")
	}
	if s.protocol == "udp" {
		_, err := s.conn.Write([]byte(line))
		return err
	}
	// TCP/TLS: RFC 6587 octet-counting: "<length> <message>"
	framed := fmt.Sprintf("%d %s", len(line), line)
	return s.streamWrite([]byte(framed))
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
// length parser mid-record. If the connection stayed up, the NEXT frame's
// bytes would concatenate onto the truncated one and the parser would
// mis-frame every subsequent message — a permanent desync of the
// audit/forensics channel, exactly under incident load (slow writes). A
// half-written octet-counted frame is unrecoverable in-stream; the only
// correct recovery is close+reconnect so the next frame starts a fresh,
// correctly-counted stream. So on a partial write we tear the conn down here
// (conn=nil); the next Send sees conn==nil, treats it as a non-timeout write
// failure, and the existing cooldown-gated reconnect path dials a fresh
// stream. A clean 0-byte timeout (n==0) wrote nothing, cannot desync the
// collector, and stays drop-without-close per #2287.
//
// Closing the raw conn here does NOT reintroduce the #2285 re-entrant
// deadlock: net.Conn.Close() (and *tls.Conn.Close) is a pure syscall that
// never routes back through slog/SyslogSlogHandler.Handle/SyslogClient.Send,
// so it cannot re-lock s.mu on this goroutine. It is also NOT the #2287 stall
// hazard: we only close (cheap) — we do NOT dial or re-arm a second
// writeTimeout in this branch; the reconnect happens on the next Send via the
// conn==nil path, so the worst-case in-Send stall stays one writeTimeout.
func (s *SyslogClient) streamWrite(b []byte) error {
	if s.writeTimeout > 0 {
		// Best-effort: if SetWriteDeadline is unsupported by the conn it
		// returns an error we ignore (the Write still proceeds, just
		// without the bound). Real TCP/TLS conns always support it.
		_ = s.conn.SetWriteDeadline(s.now().Add(s.writeTimeout))
	}
	n, err := s.conn.Write(b)
	if n > 0 && n < len(b) {
		// A truncated frame is on the wire and the stream is now unrecoverable
		// (see the doc comment). Discard the corrupt conn so the next Send
		// reconnects and resyncs; leaving it up would concatenate the next
		// frame onto the truncated one and permanently desync the collector.
		s.conn.Close()
		s.conn = nil
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
	defer func() { pendingWarn.emit(s.remoteAddr) }()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		// Close() already ran: fail fast, never reconnect (#4806).
		return errSyslogClientClosed
	}

	if err := s.writeBinaryMsg(data); err != nil {
		if s.protocol != "udp" {
			// Write-deadline timeout: already bounded — drop, don't retry (#2287).
			if isTimeout(err) {
				pendingWarn = s.noteDrop(dropWrite, err)
				return err
			}
			slog.Debug("syslog binary send failed, reconnecting", "addr", s.remoteAddr, "err", err)
			if rerr := s.reconnect(); rerr != nil {
				if rerr == errReconnectCooldown {
					pendingWarn = s.noteDrop(dropCooldown, err)
				} else {
					pendingWarn = s.noteDrop(dropDial, rerr)
				}
				return fmt.Errorf("syslog reconnect %s: %w", s.remoteAddr, rerr)
			}
			if werr := s.writeBinaryMsg(data); werr != nil {
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
		return err
	}
	return nil
}

// writeBinaryMsg writes the raw binary data to the connection. Called with mu held.
func (s *SyslogClient) writeBinaryMsg(data []byte) error {
	if s.conn == nil {
		return fmt.Errorf("syslog connection closed")
	}
	if s.protocol == "udp" {
		_, err := s.conn.Write(data)
		return err
	}
	return s.streamWrite(data)
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
		return FacilityLocal0, false
	}
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
// Once Close returns, Send/SendBinary always fail fast — they never dial a
// fresh connection, even if a caller races a Send against this Close (the
// shared mu serializes the two: whichever acquires it first runs to
// completion before the other observes the closed state).
func (s *SyslogClient) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
