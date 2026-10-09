package routing

import (
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ProbeResult is the typed outcome of a single tunnel keepalive probe
// (#1918, Axis B1). It carries the "could not probe" signal the old
// bool return destroyed: a route-existence check is NOT a liveness
// check, and the loop must distinguish "confirmed dead" from "unable to
// probe" so it can hold-on-unknown instead of defaulting to up.
type ProbeResult int

const (
	// ProbeAlive: an ICMP echo reply matching THIS probe (Seq + nonce)
	// was received within the deadline.
	ProbeAlive ProbeResult = iota
	// ProbeDead: the echo was sent but no matching reply arrived before
	// the deadline. This is a real liveness signal and counts toward
	// MaxRetries.
	ProbeDead
	// ProbeUnsupported: the probe could not be performed at all (socket
	// could not be opened/bound, marshal failure, etc.). The loop applies
	// hold-on-unknown (§6 Axis C, C1) — it never tears the link down
	// purely because the daemon cannot probe.
	ProbeUnsupported
)

// UnsupportedKind sub-classifies a ProbeUnsupported result (#1918 Axis
// C). Structural = a configuration/capability problem (missing
// ping_group_range, bound source not local) that holds indefinitely
// with a one-shot warning. Transient = a local resource problem
// (FD/memory exhaustion) that holds but escalates to a loud status +
// slog.Error after a sustained window so a real peer death is never
// silently masked by a local resource storm.
type UnsupportedKind int

const (
	// UnsupportedNone is the zero value used when the result is not
	// ProbeUnsupported.
	UnsupportedNone UnsupportedKind = iota
	// UnsupportedStructural: config/capability error — hold indefinitely,
	// one-shot Warn.
	UnsupportedStructural
	// UnsupportedTransient: local resource error — hold but escalate after
	// a sustained-unknown window.
	UnsupportedTransient
)

// tunnelProber performs one ICMP echo round-trip to a tunnel's underlay
// peer. The production implementation is icmpProber; tests inject a
// deterministic fake on tunnelManager.prober.
//
// source is the tunnel's local endpoint IP (TunnelConfig.Source) bound
// as the ICMP listen address (§5c) so the echo egresses from the tunnel
// endpoint; "" → wildcard bind. dst is the underlay Destination, routed
// in the FIB used by the tunnel's outer traffic. On the userspace-anchor
// path, transportInstance selects that FIB; the legacy kernel GRE/IPIP
// path passes "" because its outer lookup uses the main FIB when no
// lower link is configured, even if tc.RoutingInstance VRF-binds the
// tunnel interface. A non-empty transport instance binds the socket to
// its VRF device (`vrf-<instance>`).
// seq + nonce uniquely key the reply to THIS probe (§5a — NOT the ICMP ID,
// which datagram sockets rewrite to the socket source port).
// The reason return is a short human-readable detail for a
// ProbeUnsupported result (the actual syscall errno / config failure),
// surfaced in KeepaliveInfo and the escalation log so the operator sees
// WHY the probe could not run — not just a generic label (Copilot PR
// #1947). Empty for Alive/Dead.
type tunnelProber interface {
	Probe(transportInstance, source, dst string, seq int, nonce []byte, deadline time.Duration) (result ProbeResult, kind UnsupportedKind, reason string)
}

// icmpProber is the production tunnelProber. It uses unprivileged
// datagram ICMP ("udp4"/"udp6" via x/net/icmp), the same mechanism as
// the tested pkg/cluster/monitor.go precedent, with the precedent's two
// gaps fixed: reply matching on Seq + Data-nonce (§5a) and binding to
// the tunnel source IP (§5c). Transport-instance probes bind to the
// corresponding `vrf-<instance>` device.
type icmpProber struct{}

// probeConn is the narrow ICMP socket surface icmpProber needs, so tests
// can substitute a fake without real network I/O. Mirrors
// pkg/cluster/monitor.go's icmpConn.
type probeConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// listenICMP opens a datagram ICMP socket bound to source (or wildcard
// when source==""). A non-empty bindDevice is applied before the source
// bind so a source local only in a VRF is valid. Indirection point for tests.
var listenICMP = func(network, source, bindDevice string) (probeConn, error) {
	if bindDevice == "" {
		c, err := icmp.ListenPacket(network, source)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return listenBoundICMP(network, source, bindDevice)
}

// keepaliveVRFDeviceName mirrors pkg/rpm.vrfDeviceName: routing-instance
// names map to Linux VRF master devices named vrf-<instance>.
func keepaliveVRFDeviceName(transportInstance string) string {
	if transportInstance == "" {
		return ""
	}
	return "vrf-" + transportInstance
}

// listenBoundICMP is the SO_BINDTODEVICE equivalent of icmp.ListenPacket.
// x/net/icmp.ListenPacket creates and binds the socket internally without
// exposing a socket-control hook, so create its datagram ICMP socket here
// when transport scoping is required.
func listenBoundICMP(network, source, bindDevice string) (probeConn, error) {
	family, protocol := 0, 0
	switch network {
	case "udp4":
		family, protocol = unix.AF_INET, unix.IPPROTO_ICMP
	case "udp6":
		family, protocol = unix.AF_INET6, unix.IPPROTO_ICMPV6
	default:
		return nil, net.InvalidAddrError("unsupported ICMP network: " + network)
	}

	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, bindDevice); err != nil {
		return nil, os.NewSyscallError("setsockopt SO_BINDTODEVICE", err)
	}
	addr, err := keepaliveSockaddr(network, source)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, addr); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}

	file := os.NewFile(uintptr(fd), "vrf-bound datagram ICMP")
	conn, err := net.FilePacketConn(file)
	closeErr := file.Close()
	fd = -1
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, closeErr
	}
	return conn, nil
}

func keepaliveSockaddr(network, source string) (unix.Sockaddr, error) {
	if network == "udp4" {
		addr := &unix.SockaddrInet4{}
		if source == "" || source == "0.0.0.0" {
			return addr, nil
		}
		ip := net.ParseIP(source)
		if ip == nil || ip.To4() == nil {
			return nil, net.InvalidAddrError("non-ipv4 address")
		}
		copy(addr.Addr[:], ip.To4())
		return addr, nil
	}

	addr := &unix.SockaddrInet6{}
	if source == "" || source == "::" {
		return addr, nil
	}
	host, zone, _ := strings.Cut(source, "%")
	ip := net.ParseIP(host)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil, net.InvalidAddrError("non-ipv6 address")
	}
	copy(addr.Addr[:], ip.To16())
	if zone != "" {
		iface, err := net.InterfaceByName(zone)
		if err != nil {
			return nil, err
		}
		addr.ZoneId = uint32(iface.Index)
	}
	return addr, nil
}

// Probe sends one ICMP echo to dst and reports the typed result.
func (icmpProber) Probe(transportInstance, source, dst string, seq int, nonce []byte, deadline time.Duration) (ProbeResult, UnsupportedKind, string) {

	ip := net.ParseIP(dst)
	if ip == nil {
		// A non-parseable destination is a configuration error, not a
		// transient resource problem: hold-on-unknown structural.
		return ProbeUnsupported, UnsupportedStructural, "destination not an IP: " + dst
	}

	isIPv6 := ip.To4() == nil
	var (
		network   string
		echoType  icmp.Type
		replyType icmp.Type
		proto     int
		listen    string
	)
	if isIPv6 {
		network, echoType, replyType, proto = "udp6", ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58
		listen = "::"
	} else {
		network, echoType, replyType, proto = "udp4", ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, 1
		listen = "0.0.0.0"
	}
	// §5c: bind to the tunnel source IP so the echo egresses from the
	// tunnel endpoint and the reply routes back to it. Empty source →
	// wildcard (auto-selected tunnels). A family-mismatched source (e.g.
	// a v4 Source against a v6 dst) would EAFNOSUPPORT/EADDRNOTAVAIL on
	// ListenPacket → classified structural below; that is correct (a
	// misconfigured source pair cannot probe).
	if source != "" {
		listen = source
	}

	conn, err := listenICMP(network, listen, keepaliveVRFDeviceName(transportInstance))
	if err != nil {
		return ProbeUnsupported, classifyListenErr(err), "listen " + network + " " + listen + ": " + err.Error()
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			// ID is advisory only: datagram sockets overwrite it with the
			// socket source port (§5a). The authoritative match is Seq +
			// Data-nonce.
			ID:   0,
			Seq:  seq,
			Data: nonce,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		// Marshal of a fixed-shape echo should never fail; treat a failure
		// as a structural (non-flapping) unknown.
		return ProbeUnsupported, UnsupportedStructural, "echo marshal: " + err.Error()
	}

	abs := time.Now().Add(deadline)
	if err := conn.SetReadDeadline(abs); err != nil {
		return ProbeUnsupported, classifyListenErr(err), "set deadline: " + err.Error()
	}
	if _, err := conn.WriteTo(b, &net.UDPAddr{IP: ip}); err != nil {
		// Classify a write error (Codex PR #1947 r1 HIGH). A path/route
		// problem (ENETUNREACH/EHOSTUNREACH/ENETDOWN — no route to the
		// underlay peer) IS a real liveness signal → Dead. A LOCAL RESOURCE
		// fault (ENOBUFS/ENOMEM/EAGAIN — transmit buffer pressure) is NOT
		// peer death; bucketing it Dead would let a local resource storm
		// self-inflict a tunnel down. Route it through hold-on-unknown
		// (transient) instead, mirroring the ListenPacket classifier.
		if kind := classifyWriteErr(err); kind != UnsupportedNone {
			return ProbeUnsupported, kind, "write echo: " + err.Error()
		}
		return ProbeDead, UnsupportedNone, ""
	}

	reply := make([]byte, 1500)
	for {
		// R4: re-check the absolute deadline each iteration so a datagram
		// flood cannot extend a probe past its budget.
		if remaining := time.Until(abs); remaining <= 0 {
			return ProbeDead, UnsupportedNone, ""
		}
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			// Deadline exceeded or read error → no matching reply → Dead.
			return ProbeDead, UnsupportedNone, ""
		}
		parsed, perr := icmp.ParseMessage(proto, reply[:n])
		if perr != nil || parsed.Type != replyType {
			continue // not an echo reply we recognize; keep reading
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// §5a authoritative match: Seq AND Data-nonce. ID is ignored
		// (kernel-substituted on datagram sockets).
		if echo.Seq == seq && bytesEqual(echo.Data, nonce) {
			return ProbeAlive, UnsupportedNone, ""
		}
		// A stale/foreign reply (different probe) — keep reading until the
		// deadline.
	}
}

// bytesEqual is a small constant-shape comparison (the nonce is ~8
// bytes); avoids importing bytes for one call.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// classifyListenErr buckets a ListenPacket/socket errno into structural
// (config/capability — hold indefinitely, one-shot Warn) vs transient
// (local resource — hold but escalate after the sustained-unknown
// window). The default for any UNRECOGNIZED errno is TRANSIENT (§6 Axis
// C, Codex r2 NF4): a resource storm must never be silently mis-bucketed
// as a held structural.
func classifyListenErr(err error) UnsupportedKind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		// Non-errno error (e.g. a parse/address-format error from the
		// library before the syscall) → treat as a config problem.
		return UnsupportedStructural
	}
	switch errno {
	case syscall.EPERM, syscall.EACCES,
		syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT,
		syscall.EPROTOTYPE, syscall.EADDRNOTAVAIL:
		// Capability / configuration: no ping_group_range or cap, wrong
		// family, or the bound tc.Source is not a local address.
		return UnsupportedStructural
	case syscall.EMFILE, syscall.ENFILE,
		syscall.ENOBUFS, syscall.ENOMEM, syscall.EINTR:
		return UnsupportedTransient
	default:
		// Total default — UNRECOGNIZED → TRANSIENT (escalate).
		return UnsupportedTransient
	}
}

// classifyWriteErr buckets a WriteTo error. A LOCAL RESOURCE fault
// (transmit-buffer pressure) returns UnsupportedTransient so the loop
// holds-on-unknown rather than self-inflicting a down. Anything else
// (path/route unreachable — ENETUNREACH/EHOSTUNREACH/ENETDOWN — or an
// unclassifiable error) returns UnsupportedNone, telling the caller to
// treat it as a real Dead liveness signal. NOTE the asymmetry with
// classifyListenErr's "unrecognized → transient" default: a ListenPacket
// failure means we could not probe at all (hold), but a WriteTo failure
// to a specific destination is most plausibly that destination being
// unreachable (Dead), so an unrecognized write error counts toward the
// real-death path.
func classifyWriteErr(err error) UnsupportedKind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return UnsupportedNone // not an errno → treat as Dead
	}
	switch errno {
	case syscall.ENOBUFS, syscall.ENOMEM, syscall.EAGAIN, syscall.EINTR, syscall.EMFILE, syscall.ENFILE:
		return UnsupportedTransient
	default:
		// ENETUNREACH, EHOSTUNREACH, ENETDOWN, EADDRNOTAVAIL, etc. — a real
		// path/liveness signal.
		return UnsupportedNone
	}
}

// makeNonce returns a fresh per-probe random nonce (§5a). 8 bytes is
// small enough that responders echo it faithfully (R3) yet wide enough
// to make a cross-probe collision negligible.
func makeNonce() []byte {
	b := make([]byte, 8)
	// No error branch, and deliberately no fallback value (#7171). The
	// nonce is the anti-spoof discriminator: a reply is matched on Seq +
	// nonce precisely so an off-path forgery cannot pass as a reply to
	// THIS probe. The previous code fell back to a FIXED marker
	// ("xpf-ka00") if rand.Read failed, which would have dissolved that
	// property silently -- every probe carrying a nonce an attacker can
	// predict, so a spoofed echo reply holds a dead tunnel UP.
	//
	// That fallback was also unreachable: since Go 1.24 crypto/rand.Read
	// never returns an error. A failure of the system entropy source is
	// fatal (the runtime crashes the process, see go.dev/issue/66821), so
	// there is no observable error for a caller to handle. Keeping the
	// branch bought nothing and left a predictable-nonce path in the
	// source for a future reader to "restore". Having no fallback at all
	// makes the weak nonce unrepresentable rather than merely improbable.
	rand.Read(b)
	return b
}
