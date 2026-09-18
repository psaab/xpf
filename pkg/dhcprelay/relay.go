// Package dhcprelay implements a DHCP relay agent (RFC 3046) that forwards
// DHCPv4 packets between clients on local interfaces and remote DHCP servers.
// It inserts Option 82 (Relay Agent Information) with the circuit-id sub-option
// set to the receiving interface name, allowing servers to identify the origin.
package dhcprelay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/psaab/xpf/pkg/config"
)

// relayPort is the standard DHCP server/relay port.
const relayPort = 67

// clientPort is the standard DHCP client port.
const clientPort = 68

// defaultMaxHopCount is the RFC 1542 §4.1.1 relay hop limit applied when a
// group does not configure `overrides maximum-hop-count`. A client request
// whose hops field has reached this value is dropped for loop protection.
// This preserves the historical hardcoded limit (#4309).
const defaultMaxHopCount uint8 = 16

// resolveMaxHopCount maps a configured hop limit to the value the relay
// enforces: 0 (unset) or out-of-range falls back to defaultMaxHopCount. The
// schema bounds the leaf to 1..16 (`ValidateInteger(1, 16)`), so the clamp
// only backstops a config that predates the bound (e.g. a loaded active.json).
func resolveMaxHopCount(n int) uint8 {
	if n <= 0 || n > int(defaultMaxHopCount) {
		return defaultMaxHopCount
	}
	return uint8(n)
}

// defaultMaxPacketRate is the per-interface DHCP relay ingress rate limit (in
// packets per second) applied when a group does not configure `overrides
// maximum-packet-rate` (#5670). DHCP relay traffic is inherently low-rate (a
// client sends a handful of packets per lease then renews on the order of
// hours), so a 100 pps sustained bound with a short burst allowance is
// generous for legitimate use yet caps an untrusted client segment that would
// otherwise flood the relay — each admitted packet costs a variable-length
// dhcpv4.FromBytes TLV parse, an Option 82 allocation, and a fan-out send to
// EVERY configured server (a 1→N amplification into the upstream DHCP servers).
const defaultMaxPacketRate = 100

// resolveMaxPacketRate maps a configured per-interface packet-rate limit to the
// value the relay enforces: 0 (unset) or a nonsensical negative falls back to
// defaultMaxPacketRate. The schema bounds the leaf to 1..1000000, so this only
// backstops a config that predates the bound (e.g. a loaded active.json).
func resolveMaxPacketRate(n int) int {
	if n <= 0 {
		return defaultMaxPacketRate
	}
	return n
}

// tokenBucket is a simple token-bucket rate limiter for the per-interface relay
// ingress path (#5670). It is accessed only from the single per-interface main
// read-loop goroutine, so it carries no internal lock. `now` is an injectable
// clock (time.Now in production; a fake in tests) so the refill behavior is
// deterministically testable without sleeping.
type tokenBucket struct {
	rate   float64          // tokens added per second (sustained pps)
	burst  float64          // bucket capacity (max tokens)
	tokens float64          // current tokens
	last   time.Time        // last refill timestamp
	now    func() time.Time // clock seam
}

// newTokenBucket builds a token bucket admitting `rate` packets/second with a
// `burst` capacity. It starts FULL so a cold relay tolerates an initial
// simultaneous-boot burst up to `burst` before throttling to the sustained
// rate. A nil clock defaults to time.Now.
func newTokenBucket(rate, burst int, now func() time.Time) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	return &tokenBucket{
		rate:   float64(rate),
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now(),
		now:    now,
	}
}

// allow refills the bucket for the elapsed wall-clock time (capped at burst)
// and consumes one token. It returns true if a token was available (the packet
// is admitted) or false if the bucket is empty (the packet must be dropped).
func (b *tokenBucket) allow() bool {
	now := b.now()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// relayBurstFor sizes the token-bucket burst capacity from the sustained rate:
// two seconds' worth of packets, so a brief simultaneous-boot spike is admitted
// instantly while the sustained rate still bounds a persistent flood.
func relayBurstFor(rate int) int {
	return rate * 2
}

// readBufSize is the size of the per-loop read buffer for both the
// client-facing and server-facing UDP sockets.
//
// net.PacketConn.ReadFrom (UDP) copies only the first len(buf) bytes of a
// datagram and silently discards the remainder (MSG_TRUNC). A truncated DHCP
// datagram corrupts the trailing option block, so dhcpv4.FromBytes fails and
// the packet is dropped. DHCP itself imposes no 1500-byte limit — the Maximum
// DHCP Message Size option is a uint16, and a UDP datagram can carry up to
// 65535 bytes. A datagram can therefore legitimately exceed 1500 bytes (large
// option sets — classless static routes, many search domains, Option 82,
// vendor/PXE options — or jumbo-MTU links). Size the buffer to the UDP/IP
// maximum so the buffer is never the truncation point (#3012).
const readBufSize = 65535

// messageTypeForceRenew is the DHCPFORCERENEW message type. RFC 3203 §4
// (Message layout) defines it — "DHCP option 53 (DHCP message type) is extended
// with a new value: DHCPFORCERENEW (9)" — and §5 (IANA Considerations) records
// the assignment. (An earlier comment here cited "§3.1"; §3 is the extended
// DHCP state diagram and has no §3.1.) The insomniacslk/dhcp library only
// enumerates message types 1-8, so the type-9 value is defined locally.
//
// A server sends FORCERENEW to a client that already holds a lease to force it
// back into the RENEWING state. This relay recognizes the type in order to
// REFUSE it (#6562) — see the reply switch in handleServerResponses for the
// RFC 3203 §6 / RFC 3118 rationale.
const messageTypeForceRenew = dhcpv4.MessageType(9)

// startupRetryInterval is how long runRelay waits between attempts to resolve
// the interface and its IPv4 address (giaddr) at startup. Apply runs once at
// daemon boot, so an interface that is not yet ready (carrier wait, late link
// bring-up, DHCP-learned address not yet bound, or a not-yet-created dynamic
// VLAN/tunnel) must be retried rather than failing the relay permanently. The
// retry loop is ctx-cancelable so Stop() unwinds it promptly.
const startupRetryInterval = 5 * time.Second

// ifindexCheckInterval is how often a running relay re-resolves its interface
// name to the live kernel ifindex and compares it against the ifindex its
// client listener was SO_BINDTODEVICE-bound to at socket creation (#2347). The
// listener socket pins to the interface's ifindex at bind(2); if the interface
// is deleted+recreated or renamed under unchanged config it gets a NEW ifindex
// and the kernel stops delivering DHCP client requests to the stale-bound
// listener (the relay goes deaf on that segment). On drift the relay tears down
// the current session and rebinds to the new ifindex. This mirrors the #2294
// VRRP reconcile probe. 5s matches the VRRP/daemon reconcile cadence closely
// enough to bound the deaf window without a tight netlink loop; the resolve is
// a cheap name->ifindex lookup and idempotent (unchanged ifindex => no action).
const ifindexCheckInterval = 5 * time.Second

// sessionOutcome is how a single relay session ended, telling the supervisor
// (runRelay) whether to stop, rebind immediately, or retry after a delay.
type sessionOutcome int

const (
	// sessionStop is a terminal exit: the manager context was cancelled
	// (Stop()) or a session goroutine exited one-sidedly. The supervisor ends
	// the per-interface goroutine.
	sessionStop sessionOutcome = iota
	// sessionDrift means the interface's live kernel ifindex moved away from
	// the bound ifindex (#2347); the supervisor rebuilds immediately to rebind.
	sessionDrift
	// sessionReaddr means the interface's PRIMARY IPv4 address changed while its
	// ifindex stayed the same (#3960) — e.g. a DHCP-learned lease renewing to a
	// different IP, a static readdress, or an HA VIP move on the same netdev. The
	// session's giaddr (the source the DHCP server unicasts its reply back to) was
	// resolved once at session start and is now STALE: the relay would keep
	// stamping the old giaddr AND the server conn would stay bound to the old
	// giaddr:67, so replies to the new address are blackholed and relayed clients
	// stop getting leases. Like sessionDrift the supervisor rebuilds immediately,
	// which re-resolves the giaddr, rebinds the server conn to the new address,
	// and makes the new main loop stamp the current giaddr.
	sessionReaddr
	// sessionRetry means a TRANSIENT socket bind/listen failure occurred
	// before the session could start (#2787). The supervisor waits the
	// bounded, ctx-cancelable retry interval and rebuilds, so the relay
	// recovers when the interface comes up — it must NOT kill the supervisor.
	sessionRetry
)

// option82 is the DHCP Relay Agent Information option (RFC 3046).
const option82 = dhcpv4.OptionRelayAgentInformation

// suboption1CircuitID is the circuit-id sub-option within Option 82.
const suboption1CircuitID byte = 1

// RelayStats holds per-interface relay statistics.
type RelayStats struct {
	// Family is empty for the historical DHCPv4 rows and "inet6" for
	// DHCPv6 rows. It lets callers distinguish identical interface names
	// across the two independently configured relay families.
	Family string
	// Interface is the AUTHORED config reference ("ge-0/0/0.0", "reth0.0").
	Interface string
	// KernelInterface is the Linux device the relay actually bound (#9406).
	// It is reported separately rather than replacing Interface because the
	// two differ under the canonical Junos spelling, and an operator staring
	// at an all-zero counter row needs to see WHICH device this relay is on —
	// that row is otherwise indistinguishable from an idle segment.
	KernelInterface  string
	RequestsRelayed  uint64
	RepliesForwarded uint64

	// RequestsDroppedBackup counts client requests dropped because this node is
	// BACKUP for the interface's redundancy group (#2456 HA relay gate).
	RequestsDroppedBackup uint64

	// RequestsDroppedMaxHops counts client requests dropped because their hops
	// field reached the group's `overrides maximum-hop-count` limit (default
	// 16) — the RFC 1542 §4.1.1 loop-protection drop (#4309).
	RequestsDroppedMaxHops uint64

	// RequestsUntrustedGiaddrReset counts client requests that arrived on an
	// UNTRUSTED client-facing interface with a nonzero (client-forged) giaddr
	// that the relay reset to its own address + re-stamped Option 82 on (#5414,
	// RFC 3046 §2.1 anti-spoofing). Nonzero means a host on the client segment
	// tried to spoof a downstream relay's giaddr / Option 82; it is trusted and
	// preserved only when the group sets `overrides trust-option-82`.
	RequestsUntrustedGiaddrReset uint64

	// RequestsDroppedRateLimit counts client-facing datagrams dropped by the
	// per-interface ingress rate limiter (#5670) BEFORE the DHCP parse. A
	// sustained nonzero value means this segment is exceeding its configured
	// (or default 100) pps bound — either a misbehaving/looping client
	// population or an active flood/amplification attempt. It is the
	// observability signal for the DoS-hardening token bucket; raise the
	// group's `overrides maximum-packet-rate` if a legitimate segment trips it.
	RequestsDroppedRateLimit uint64

	// RepliesDroppedUnknownServer counts server replies dropped because their
	// source IP is NOT one of the configured DHCP servers (#4163). The
	// server-facing socket is bound (not connected), so it accepts datagrams
	// from any host that can route to giaddr:67; RFC 3046 relay practice
	// forwards replies only from the configured server set. A non-zero value
	// means a non-configured source tried to inject a reply (rogue-DHCP /
	// lease-hijack attempt) or a legitimately multi-homed server unicast from
	// an unlisted source IP — either way it MUST be visible, not silent.
	RepliesDroppedUnknownServer uint64

	// RepliesDroppedNoRequest counts server replies dropped because they do not
	// bind to an outstanding relayed request (#6562). The #4163 source-IP
	// allow-list is spoofable, so a reply must additionally match a request the
	// relay actually forwarded (xid + chaddr, see pending.go). A nonzero value
	// means either an injection attempt that guessed/spoofed its way past the
	// source check, or a LEGITIMATE reply that arrived outside the binding
	// window — the second is a client-visible DHCP failure, so this counter
	// MUST be watched, not assumed hostile.
	RepliesDroppedNoRequest uint64

	// RepliesDroppedForceRenew counts DHCPFORCERENEW messages refused by the
	// relay (#6562). RFC 3203 §6 makes RFC 3118 authentication of FORCERENEW a
	// MUST, and a relay holds no RFC 3118 key material, so it cannot discharge
	// that MUST — it refuses rather than forwarding an unverifiable
	// reconfigure command at its clients. A nonzero value means a server (or a
	// spoofer) is sending FORCERENEW to relayed clients; leases still renew
	// normally at T1/T2, and RFC 3203 §2.2 defines the server's retransmission
	// behavior when a FORCERENEW is not answered.
	RepliesDroppedForceRenew uint64

	// PendingEvicted counts outstanding-request entries dropped by CAP PRESSURE
	// on the #6562 pending table (not by ordinary expiry). Capacity is derived
	// from the interface's maximum-packet-rate, so under a correctly-sized
	// relay this stays 0; a nonzero value means the table filled anyway (the
	// rate limiter's burst allowance, or a rate high enough that the memory
	// ceiling clamped capacity) and legitimate replies may now be dropped for
	// want of a binding.
	//
	// NOTE it is a COINCIDENT signal, not a leading one: an eviction is what
	// CAUSES the subsequent drop, so the lead time is one server RTT. Use
	// PendingSize/PendingCapacity for advance warning.
	PendingEvicted uint64

	// PendingSize is the CURRENT occupancy of the #6562 outstanding-request
	// table, and PendingCapacity its ceiling. This pair is the genuine LEADING
	// indicator (#6603 review F3): occupancy climbing toward capacity means the
	// relay is about to start evicting bindings and dropping legitimate
	// replies, and it is observable BEFORE any reply is lost. Alert on the
	// ratio; PendingEvicted only rises once the damage has begun.
	//
	// These are gauges (instantaneous), not monotonic counters.
	PendingSize     uint64
	PendingCapacity uint64

	// Reply-delivery breakdown (#2076). These distinguish WHY a reply was
	// broadcast vs L2-unicast so an L2/CAP_NET_RAW/driver/MTU regression is
	// observable in operations. RepliesBroadcastL2Fallback is the one to
	// alert on: it means the raw-L2 path failed and the relay had to
	// degrade to broadcast.
	RepliesL2Unicast           uint64 // flag-clear reply delivered via raw L2
	RepliesUnicastCiaddr       uint64 // flag-clear reply UDP-unicast to ciaddr
	RepliesBroadcastFlag1      uint64 // client set the broadcast flag
	RepliesBroadcastForced     uint64 // overrides always-broadcast
	RepliesBroadcastNoTarget   uint64 // no routable target (yiaddr==0,ciaddr==0)
	RepliesBroadcastL2Fallback uint64 // raw-L2 path failed → degraded
	RepliesBroadcastNak        uint64 // DHCPNAK force-broadcast (RFC 2131 §4.3.2)
	// DHCPv6-specific per-reason counters (#9553). These are populated only
	// on Family=="inet6" rows; the common rate-limit/unknown-server counters
	// above remain shared field names for both families.
	RequestsDroppedNested uint64
	RequestsDroppedParse  uint64
	RequestsDroppedPort   uint64
	RequestsDroppedPeer   uint64
	RequestsDroppedBuild  uint64
	RepliesDroppedIID     uint64
	RepliesDroppedParse   uint64
	RepliesDroppedInvalid uint64
	RepliesDroppedNested  uint64
	// Shared DHCPv6 dispatcher pre-dispatch drops are aggregate across active
	// IPv6 relays and appear once on the synthetic inet6 dispatcher row whose
	// Interface is "<dhcpv6-reply-dispatcher>".
	RepliesDroppedDispatcherParse      uint64
	RepliesDroppedDispatcherEmptyIID   uint64
	RepliesDroppedDispatcherUnknownIID uint64
	RepliesDroppedDispatcherAmbiguous  uint64
}

// l2Replier is the raw-L2 unicast seam. *l2Sender implements it in production;
// tests inject a fake to exercise the dst-decision matrix and fallback without
// CAP_NET_RAW or real NICs.
type l2Replier interface {
	sendReply(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) error
	Close() error
}

// relaySpec is the immutable per-interface configuration that determines a
// relay session's behavior. Apply (#2348) keys the desired set by interface
// name and compares the running relay's spec against the desired spec to
// decide start (added), stop (removed), or restart (changed). Two specs are
// equal iff their server set (order-significant: the relay forwards to servers
// in config order) and alwaysBroadcast flag match — a change in either is a
// behavior change that requires a fresh session.
type relaySpec struct {
	servers         []string // server IPs in config order
	alwaysBroadcast bool
	// kernelName is the LINUX DEVICE this relay binds, resolved from the
	// authored config reference through Config.ResolveKernelIfName (#9406).
	// It is part of the SPEC, not just a cached lookup: an edit that changes
	// the resolved device without changing any other field — retagging a unit's
	// `vlan-id`, or repointing a RETH at a different local member — must tear
	// the old socket down and bind the new device, and equal() is the only
	// thing that decides that.
	kernelName string
	// maxHopCount is the RFC 1542 §4.1.1 loop-protection hop limit (#4309):
	// a client request whose hops field has reached this value is dropped.
	// 0 = unset = the default (defaultMaxHopCount, 16). A change requires a
	// fresh session, so it participates in equal().
	maxHopCount int
	// trustOption82 marks this interface as a TRUSTED relay uplink (#5414,
	// Junos `overrides trust-option-82`). When false (the default) the
	// interface is an UNTRUSTED client-facing segment and a nonzero inbound
	// giaddr is treated as client-forged (overwritten, not preserved). A
	// change flips the anti-spoofing behavior, so it participates in equal().
	trustOption82 bool
	// maxPacketRate is the per-interface DHCP relay ingress rate limit in
	// packets per second (#5670). 0 = unset = the default (defaultMaxPacketRate,
	// 100). A change resizes the token bucket, so it requires a fresh session
	// and participates in equal().
	maxPacketRate int
}

// equal reports whether two specs would produce an identical relay session.
func (s relaySpec) equal(o relaySpec) bool {
	if s.alwaysBroadcast != o.alwaysBroadcast {
		return false
	}
	if s.kernelName != o.kernelName {
		return false
	}
	if s.maxHopCount != o.maxHopCount {
		return false
	}
	if s.trustOption82 != o.trustOption82 {
		return false
	}
	if s.maxPacketRate != o.maxPacketRate {
		return false
	}
	if len(s.servers) != len(o.servers) {
		return false
	}
	for i := range s.servers {
		if s.servers[i] != o.servers[i] {
			return false
		}
	}
	return true
}

// interfaceRelay represents a relay goroutine bound to one interface.
type interfaceRelay struct {
	// ifaceName is the AUTHORED config reference ("ge-0/0/0.0", "reth0.0").
	// It is this relay's IDENTITY: the Apply diff key, the Stats row, the
	// #2456 HA master gate and the #2456 RG lookup all speak it, and
	// relayInterfaceRG (pkg/daemon) parses it as a Junos unit ref. Do not
	// replace it with the kernel name — that would silently open the HA gate
	// on every RETH-owned segment, because a kernel name is not a key in
	// cfg.Interfaces.Interfaces.
	ifaceName string
	// kernelName is the LINUX DEVICE this relay binds (#9406): the ifaceName
	// resolved through Config.ResolveKernelIfName. Every kernel-facing call —
	// SO_BINDTODEVICE, the giaddr address lookup, the #2347 ifindex drift
	// check, the #2076 raw-L2 sender — takes THIS, because none of them can
	// find a device whose name contains '/' or a Junos unit suffix.
	kernelName       string
	cancel           context.CancelFunc
	done             chan struct{}
	requestsRelayed  atomic.Uint64
	repliesForwarded atomic.Uint64

	// requestsDroppedBackup counts client requests dropped because this node is
	// BACKUP (not MASTER) for the interface's redundancy group (#2456). It is
	// the observability signal that the HA relay gate is suppressing duplicate
	// upstream relays on the standby node.
	requestsDroppedBackup atomic.Uint64

	// repliesDroppedUnknownServer counts server replies dropped by the reply
	// path because their source IP is not one of the configured DHCP servers
	// (#4163). It is the observability signal for a rogue-reply injection
	// attempt (or a multi-homed server unicasting from an unlisted source IP).
	repliesDroppedUnknownServer atomic.Uint64

	// pending is the bounded outstanding-request table (#6562): the
	// client-facing loop records every request it forwards upstream, and the
	// server-facing loop forwards a reply only if it binds to one. It lives
	// here rather than on the session so a session rebuild (#2347 ifindex
	// drift / #3960 re-address) does NOT wipe in-flight bindings and strand a
	// client mid-transaction. Always non-nil in production (set where this
	// struct is built); a nil table fails CLOSED — see pendingTable.matches.
	// Its capacity is derived from maxPacketRate (pendingCapacityFor).
	pending *pendingTable

	// pendingClamped records that pendingCapacityFor hit the memory ceiling,
	// so the effective reply-binding window is shorter than pendingTTL. Set
	// once at start; read-only thereafter. Drives the startup Warn in Apply.
	pendingClamped bool

	// repliesDroppedNoRequest counts server replies dropped because they bind
	// to no outstanding request (#6562). Observability for a spoofed-source
	// injection that got past #4163 — and, just as importantly, for an
	// over-strict binding dropping legitimate replies.
	repliesDroppedNoRequest atomic.Uint64

	// repliesDroppedForceRenew counts DHCPFORCERENEW messages refused (#6562).
	// A relay cannot perform the RFC 3118 validation RFC 3203 §6 requires, so
	// it does not forward an unverifiable reconfigure command at its clients.
	repliesDroppedForceRenew atomic.Uint64

	// spec is the desired-config snapshot this relay was started with. Apply
	// (#2348) compares it against the new desired spec to detect a changed
	// group (servers / always-broadcast) that requires a restart. Set once at
	// start; read-only thereafter (Apply holds m.mu while reading it).
	spec relaySpec

	// alwaysBroadcast forces every reply to broadcast (overrides
	// always-broadcast). Set once at start; read-only thereafter.
	alwaysBroadcast bool

	// maxHopCount is the resolved RFC 1542 §4.1.1 hop limit (#4309) — a
	// client request whose hops field has reached it is dropped. Resolved
	// from the group's overrides maximum-hop-count (default 16). Set once
	// at start; read-only thereafter.
	maxHopCount uint8

	// requestsDroppedMaxHops counts client requests dropped because their
	// hops field reached maxHopCount (#4309). Observability for a relay loop
	// or a misconfigured downstream relay chain.
	requestsDroppedMaxHops atomic.Uint64

	// trustOption82 marks this interface as a TRUSTED relay uplink (#5414).
	// When false (the default) the interface is UNTRUSTED client-facing and a
	// nonzero inbound giaddr is treated as client-forged. Resolved from the
	// group's `overrides trust-option-82`. Set once at start; read-only
	// thereafter.
	trustOption82 bool

	// requestsUntrustedGiaddrReset counts client requests that arrived on this
	// UNTRUSTED interface carrying a nonzero (client-forged) giaddr, which the
	// relay reset to its own address and re-stamped Option 82 on (#5414, RFC
	// 3046 §2.1 anti-spoofing). A nonzero value means a host on the client
	// segment attempted to spoof a downstream relay's identity / Option 82.
	requestsUntrustedGiaddrReset atomic.Uint64

	// maxPacketRate is the resolved per-interface DHCP relay ingress rate limit
	// in packets per second (#5670) — the token bucket admits at most this many
	// client-facing datagrams per second. Resolved from the group's `overrides
	// maximum-packet-rate` (default 100). Set once at start; read-only
	// thereafter.
	maxPacketRate int

	// requestsDroppedRateLimit counts client-facing datagrams dropped by the
	// per-interface ingress rate limiter (#5670). Observability for a flood /
	// amplification attempt or a segment exceeding its configured pps bound.
	requestsDroppedRateLimit atomic.Uint64

	// Reply-delivery counters (#2076).
	repliesL2Unicast           atomic.Uint64
	repliesUnicastCiaddr       atomic.Uint64
	repliesBroadcastFlag1      atomic.Uint64
	repliesBroadcastForced     atomic.Uint64
	repliesBroadcastNoTarget   atomic.Uint64
	repliesBroadcastL2Fallback atomic.Uint64
	repliesBroadcastNak        atomic.Uint64
}

// packetConnFactory creates a UDP packet connection with the relay's required
// socket options applied before bind(2). It is a seam so lifecycle tests can
// inject fake connections (no root, no real NICs).
//
//   - ifaceName: when non-empty, SO_BINDTODEVICE binds the socket to that
//     interface (required on the client conn so REUSEPORT fanout is filtered
//     per-interface). Empty for the server conn, which binds a specific
//     giaddr:67 (#2888) and is steered by the unicast destination address, not
//     by a device binding.
//   - reusePort: when true, SO_REUSEADDR+SO_REUSEPORT are set so multiple
//     client listeners coexist on 0.0.0.0:67, and so the server conn's
//     giaddr:67 bind (#2888) coexists with the client listener's 0.0.0.0:67.
//   - broadcast: when true, SO_BROADCAST is set so the socket can send to
//     255.255.255.255 (the client conn's broadcast reply path).
//   - bindAddr: the local address to bind.
type packetConnFactory func(ctx context.Context, ifaceName string,
	reusePort, broadcast bool, bindAddr *net.UDPAddr) (net.PacketConn, error)

// ifaceResolver resolves the giaddr for an interface by name. It wraps both
// the interface lookup and the IPv4-address selection so the startup-retry
// loop (Axis C1) can cover a not-yet-created dynamic interface as well as a
// not-yet-addressed one. It is a seam so the retry behavior is testable.
type ifaceResolver func(ifaceName string) (net.IP, error)

// ifindexResolver resolves an interface name to its current kernel ifindex
// (#2347). It is a separate seam from ifaceResolver so the drift detector can
// observe ifindex churn independently of giaddr addressing, and so lifecycle
// tests can drive an ifindex change without root/netlink. A non-nil error means
// "unresolvable right now" — the caller MUST treat that as "no drift" and keep
// the existing listener (a transient netlink hiccup or a mid-rename window must
// NOT tear down a working relay), mirroring the tolerant #2294 VRRP probe.
type ifindexResolver func(ifaceName string) (int, error)

// Manager manages per-interface DHCP relay goroutines.
type Manager struct {
	mu     sync.Mutex
	relays map[string]*interfaceRelay // keyed by interface name

	// Injectable seams (defaulted in NewManager; overridden by tests).
	newConn       packetConnFactory
	resolveGIAddr ifaceResolver
	retryInterval time.Duration

	// resolveIfindex resolves the interface name to its live kernel ifindex for
	// the #2347 drift detector; ifindexCheck is how often runRelay re-checks.
	// Both are seams so lifecycle tests drive a deterministic ifindex change.
	resolveIfindex ifindexResolver
	ifindexCheck   time.Duration

	// now is the clock seam for the #5670 per-interface ingress rate limiter's
	// token bucket. Defaulted to time.Now in NewManager; tests inject a fake so
	// the rate-limit refill behavior is deterministic without sleeping.
	now func() time.Time
	// newL2 opens the raw-L2 unicast sender for an interface (#2076). It is
	// a seam so tests can inject a fake or force open failure. The default
	// returns (nil, err) → fail-soft to the broadcast path; the production
	// implementation is defaultL2SenderFactory.
	newL2 l2SenderFactory

	// ifNameResolver maps an authored interface reference to the Linux device
	// to bind (#9406). Set by the daemon to Config.ResolveKernelIfName for the
	// config being applied; nil means IDENTITY, the pre-#9406 behaviour.
	// Guarded by mu because Apply reads it while a commit may be setting it.
	ifNameResolverFn func(string) string

	// relayGate, when non-nil, gates the upstream relay-forward on this node's
	// VRRP/cluster MASTER state for the relay interface's redundancy group
	// (#2456). It is read PER PACKET (under mu) so a backup→master failover is
	// followed without a relay restart. nil (the NewManager default) = always
	// relay (standalone fail-open). SetMasterGate installs the daemon's live
	// RG-master query.
	relayGate masterGate
	// v6 owns separate client/server IPv6 sockets and multicast membership,
	// while sharing this Manager's interface-name and HA-gate wiring (#9553).
	v6 *dhcpV6Manager
}

// SetMasterGate installs the per-interface VRRP/cluster master-state gate
// (#2456). The daemon calls this once after constructing the Manager, passing a
// closure that resolves the relay interface's redundancy group and reports
// whether this node is currently MASTER for it (true) or BACKUP (false). The
// gate is read per packet by the relay loops, so it MUST be cheap and lock-safe
// to call concurrently. A nil gate restores the standalone fail-open behavior.
func (m *Manager) SetMasterGate(g masterGate) {
	m.mu.Lock()
	m.relayGate = g
	m.mu.Unlock()
}

// SetIfNameResolver installs the authored-reference -> Linux-device resolver
// the desired-set builder uses to decide what each relay BINDS (#9406).
//
// The daemon calls this on every commit with Config.ResolveKernelIfName for the
// config being applied, immediately before Apply, so the resolution always
// matches the config that produced the group list. It is a Manager seam rather
// than an Apply parameter because Apply's signature is reached from ~50 call
// sites; the production wire is asserted at the daemon instead, where severing
// it is what actually breaks the box.
//
// A nil resolver is IDENTITY — the pre-#9406 behaviour, under which a canonical
// Junos reference like `ge-0/0/0.0` was handed straight to net.InterfaceByName
// and never resolved to a device.
func (m *Manager) SetIfNameResolver(fn func(string) string) {
	m.mu.Lock()
	m.ifNameResolverFn = fn
	m.mu.Unlock()
}

// ifNameResolver returns the installed resolver under mu. Must NOT be called
// with mu already held (Apply calls it before taking the lock).
func (m *Manager) ifNameResolver() func(string) string {
	m.mu.Lock()
	fn := m.ifNameResolverFn
	m.mu.Unlock()
	return fn
}

// shouldRelay reports whether a client request received on ifaceName may be
// forwarded upstream now (#2456). It reads the installed master gate under mu
// so a concurrent SetMasterGate is race-free. nil gate = fail-open (standalone
// always relays).
func (m *Manager) shouldRelay(ifaceName string) bool {
	m.mu.Lock()
	g := m.relayGate
	m.mu.Unlock()
	if g == nil {
		return true
	}
	return g(ifaceName)
}

// l2SenderFactory opens a raw-L2 reply sender bound to ifaceName. On error the
// caller records a nil sender and every flag-clear reply takes the broadcast
// fallback — the relay stays up (fail-soft).
type l2SenderFactory func(ifaceName string) (l2Replier, error)

// masterGate reports whether THIS node should relay client requests received
// on ifaceName right now (#2456). On a shared client segment both the cluster
// MASTER and the BACKUP node receive the client broadcast; only the MASTER for
// the relay interface's redundancy group may forward it upstream, otherwise the
// server sees duplicate relayed requests (and duplicate relay state with
// different per-node giaddrs). It is queried PER PACKET so a backup that becomes
// master (VRRP failover) starts relaying immediately with no cached-at-startup
// staleness — the daemon's implementation reads live RG master state. A nil
// gate (the NewManager default, or any non-cluster build) is fail-open: every
// request is relayed, which is the correct standalone behavior.
type masterGate func(ifaceName string) bool

// NewManager creates a new DHCP relay Manager.
func NewManager() *Manager {
	return &Manager{
		relays:         make(map[string]*interfaceRelay),
		newConn:        defaultPacketConnFactory,
		resolveGIAddr:  defaultIfaceResolver,
		retryInterval:  startupRetryInterval,
		resolveIfindex: defaultIfindexResolver,
		ifindexCheck:   ifindexCheckInterval,
		newL2:          defaultL2SenderFactory,
		now:            time.Now,
		v6:             newDHCPV6Manager(),
	}
}

// defaultL2SenderFactory opens a real AF_PACKET sender. Returning a typed-nil
// *l2Sender through the l2Replier interface would defeat the `== nil` guard, so
// on error it returns a nil interface value explicitly.
func defaultL2SenderFactory(ifaceName string) (l2Replier, error) {
	s, err := newL2Sender(ifaceName)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// defaultPacketConnFactory builds a real UDP packet connection, setting
// SO_REUSEADDR/SO_REUSEPORT, SO_BINDTODEVICE, and SO_BROADCAST inside the
// ListenConfig.Control hook (i.e. BEFORE bind(2)). This mirrors the in-repo
// vrfListenConfig precedent (pkg/cluster/heartbeat_manager.go). It returns the
// net.PacketConn as-is — no *net.UDPConn type assertion — so the runtime
// programs to the interface and stays mockable.
func defaultPacketConnFactory(ctx context.Context, ifaceName string,
	reusePort, broadcast bool, bindAddr *net.UDPAddr) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				if reusePort {
					if ctrlErr = setReusePort(fd); ctrlErr != nil {
						return
					}
				}
				if ifaceName != "" {
					if ctrlErr = setBindToDevice(fd, ifaceName); ctrlErr != nil {
						return
					}
				}
				if broadcast {
					if ctrlErr = setBroadcast(fd); ctrlErr != nil {
						return
					}
				}
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}
	return lc.ListenPacket(ctx, "udp4", bindAddr.String())
}

// defaultIfaceResolver resolves the giaddr for an interface by selecting its
// PRIMARY non-loopback IPv4 address. It delegates address enumeration to the
// primaryIPv4Lister seam (netlink-backed on Linux so the kernel's
// IFA_F_SECONDARY flag is observable; a portable net.Interface.Addrs() fallback
// otherwise) and primary selection to selectPrimaryIPv4.
//
// #2849: the previous implementation returned the FIRST IPv4 from
// net.Interface.Addrs(). On Linux an interface with a primary address plus
// secondary subnet aliases returns them in netlink maintenance order, NOT
// guaranteed primary-first; returning a secondary alias as giaddr makes the
// upstream server lease from the wrong subnet pool.
func defaultIfaceResolver(ifaceName string) (net.IP, error) {
	cands, err := primaryIPv4Lister(ifaceName)
	if err != nil {
		return nil, err
	}
	return selectPrimaryIPv4(ifaceName, cands)
}

// ipv4Candidate is one IPv4 address on an interface together with whether the
// kernel marked it secondary (an alias of an earlier address in the same
// subnet). selectPrimaryIPv4 prefers a non-secondary address.
type ipv4Candidate struct {
	ip        net.IP // 4-byte form
	secondary bool
}

// primaryIPv4Lister enumerates the non-loopback IPv4 addresses on ifaceName,
// preserving kernel ordering and the secondary flag. It is a package-level seam:
// relay_giaddr_linux.go's init() replaces this portable fallback (which cannot
// see IFA_F_SECONDARY and therefore reports every address as primary) with a
// netlink-backed enumerator that does.
var primaryIPv4Lister = portableIPv4Lister

// portableIPv4Lister enumerates IPv4 addresses via the standard library. It
// cannot distinguish primary from secondary (net.Interface.Addrs() drops the
// flag), so every candidate is reported as primary — preserving the historical
// first-address behavior on platforms without the netlink override.
func portableIPv4Lister(ifaceName string) ([]ipv4Candidate, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	var cands []ipv4Candidate
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		cands = append(cands, ipv4Candidate{ip: ip4})
	}
	return cands, nil
}

// selectPrimaryIPv4 returns the primary giaddr from the candidate list. It
// prefers the first non-secondary IPv4; only if every candidate is secondary
// (which the kernel does not normally produce, but a future netlink quirk
// might) does it fall back to the first secondary so the relay still has an
// address rather than failing closed. An empty list is an error.
func selectPrimaryIPv4(ifaceName string, cands []ipv4Candidate) (net.IP, error) {
	var firstSecondary net.IP
	for _, c := range cands {
		if !c.secondary {
			return c.ip, nil
		}
		if firstSecondary == nil {
			firstSecondary = c.ip
		}
	}
	if firstSecondary != nil {
		return firstSecondary, nil
	}
	return nil, fmt.Errorf("no IPv4 address on %s", ifaceName)
}

// defaultIfindexResolver resolves an interface name to its live kernel ifindex
// (#2347). It deliberately does NOT require an address (unlike
// defaultIfaceResolver): ifindex drift must be observable even during a window
// where the recreated interface has not yet been re-addressed.
func defaultIfindexResolver(ifaceName string) (int, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, fmt.Errorf("interface lookup: %w", err)
	}
	return iface.Index, nil
}

// desiredRelay is one entry in the desired relay set computed from config: the
// interface to bind, the originating group (for logging), and the per-interface
// spec (servers + always-broadcast). Server addresses are resolved at the
// desired-set build so a relay started from this entry never re-parses config.
type desiredRelay struct {
	ifaceName string
	// kernelName is the resolved Linux device for ifaceName (#9406).
	kernelName string
	groupName  string
	spec       relaySpec
	servers    []*net.UDPAddr
}

// computeDesired builds the desired per-interface relay set from config. It
// mirrors the validation the previous Apply did inline (skip unknown/empty
// server groups, skip invalid server IPs, skip an interface that already has a
// desired entry — first group wins, matching the pre-#2348 dedup) but produces
// data instead of starting goroutines, so Apply can diff it against the running
// set. The returned map is keyed by interface name.
//
// resolveIfName maps an authored interface reference to the Linux device the
// relay must bind (#9406). A nil resolver is IDENTITY, which is the pre-#9406
// behaviour: the direct callers in this package's tests keep working unchanged,
// and the production wire is asserted separately at the daemon.
func computeDesired(cfg *config.DHCPRelayConfig, resolveIfName func(string) string) map[string]desiredRelay {
	if resolveIfName == nil {
		resolveIfName = func(s string) string { return s }
	}
	desired := make(map[string]desiredRelay)
	if cfg == nil {
		return desired
	}
	// Iterate groups in a DETERMINISTIC (sorted-by-name) order. cfg.Groups is a
	// map, and the "interface already mapped, skipping" dedup below is
	// first-group-wins — so a random map-iteration order would make an
	// interface that appears in multiple groups resolve to a nondeterministic
	// group across Apply calls. That both picks a nondeterministic server set
	// AND defeats the day-2 idempotency diff (a re-Apply of the SAME config
	// could compute a different relaySpec and spuriously restart the relay).
	// Sorting the group names makes first-wins stable and the diff idempotent.
	groupNames := make([]string, 0, len(cfg.Groups))
	for name := range cfg.Groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for _, gname := range groupNames {
		group := cfg.Groups[gname]
		sgName := group.ActiveServerGroup
		sg, ok := cfg.ServerGroups[sgName]
		if !ok {
			slog.Warn("dhcp-relay: server group not found",
				"group", group.Name, "server_group", sgName)
			continue
		}
		if len(sg.Servers) == 0 {
			slog.Warn("dhcp-relay: server group has no servers",
				"group", group.Name, "server_group", sgName)
			continue
		}

		// Resolve server addresses once. Keep the validated string list in
		// lockstep with serverAddrs so the spec's equality compares exactly the
		// servers the relay will use (a server dropped for being invalid must
		// not count as "changed" forever).
		serverIPs := make([]string, 0, len(sg.Servers))
		serverAddrs := make([]*net.UDPAddr, 0, len(sg.Servers))
		for _, s := range sg.Servers {
			ip := net.ParseIP(s)
			if ip == nil {
				slog.Warn("dhcp-relay: invalid server IP",
					"group", group.Name, "server", s)
				continue
			}
			// The relay listener binds udp4 (ListenPacket "udp4" above), so
			// a helper server address MUST be IPv4. net.ParseIP happily
			// accepts an IPv6 literal, which would then be handed to a
			// udp4 socket and fail silently per-packet at forward time.
			// Reject it here — consistent with the invalid-IP path — so a
			// misconfigured IPv6 server is dropped loudly at build time
			// rather than blackholing relayed DISCOVERs (#5557).
			if ip.To4() == nil {
				slog.Warn("dhcp-relay: ignoring non-IPv4 server (DHCPv4 relay binds udp4)",
					"group", group.Name, "server", s)
				continue
			}
			serverIPs = append(serverIPs, s)
			serverAddrs = append(serverAddrs, &net.UDPAddr{IP: ip, Port: relayPort})
		}
		if len(serverAddrs) == 0 {
			continue
		}

		for _, ifaceName := range group.Interfaces {
			if _, exists := desired[ifaceName]; exists {
				slog.Warn("dhcp-relay: interface already mapped, skipping",
					"interface", ifaceName, "group", group.Name)
				continue
			}
			// The DESIRED-SET key stays the authored reference: it is the
			// relay's identity everywhere (Apply diff, Stats, the #2456 HA
			// gate). Only the bind target is resolved.
			kernelName := resolveIfName(ifaceName)
			desired[ifaceName] = desiredRelay{
				ifaceName:  ifaceName,
				kernelName: kernelName,
				groupName:  group.Name,
				spec: relaySpec{
					servers:         serverIPs,
					alwaysBroadcast: group.AlwaysBroadcast,
					kernelName:      kernelName,
					maxHopCount:     group.MaximumHopCount,
					trustOption82:   group.TrustOption82,
					maxPacketRate:   group.MaximumPacketRate,
				},
				servers: serverAddrs,
			}
		}
	}
	return desired
}

// Apply reconciles the running per-interface relays to match the provided
// configuration (#2348). It is called at boot AND on every day-2 commit
// (pkg/daemon/daemon_apply.go), so it must diff desired-vs-running rather than
// tearing everything down:
//
//   - interface in desired but not running  -> start a new relay
//   - interface running but not desired      -> stop it (bounded teardown)
//   - interface in both, spec changed         -> stop then start (restart)
//   - interface in both, spec unchanged       -> leave running (no churn)
//
// A nil cfg stops all relays (relay configuration removed). Stop-then-start of
// a changed/removed interface reuses the same ir.cancel()+<-ir.done teardown as
// Stop(): the per-interface supervisor (#2347 runRelay) and socket lifecycle
// (#1915 close-on-cancel + WaitGroup join) fully close the old listener before
// the replacement binds, so a restart never races EADDRINUSE and never hangs.
func (m *Manager) Apply(ctx context.Context, cfg *config.DHCPRelayConfig) {
	var v6cfg *config.DHCPRelayV6Config
	if cfg != nil {
		v6cfg = cfg.V6
	}
	resolveIfName := m.ifNameResolver()
	if m.v6 != nil {
		m.v6.apply(ctx, v6cfg, resolveIfName, m.shouldRelay)
	}
	desired := computeDesired(cfg, resolveIfName)
	// Phase 1 (under lock): decide which running relays to stop and which
	// desired relays to start, mutating m.relays to the post-reconcile set.
	// We collect the relays to stop and start them OUTSIDE the lock so the
	// bounded <-ir.done join does not hold m.mu (Stats()/concurrent Apply
	// would otherwise block on a teardown).
	m.mu.Lock()

	var toStop []*interfaceRelay // removed or changed: tear down
	// replaced maps an interface name to the relay being torn down BECAUSE ITS
	// SPEC CHANGED (not one being removed). Its outstanding-request bindings
	// are migrated into the replacement once it has fully stopped (#6562) —
	// see the phase-2.5 loop below.
	replaced := make(map[string]*interfaceRelay)
	// Remove relays that are no longer desired, or whose spec changed. A
	// changed relay is removed here and re-added in the start loop below.
	for name, ir := range m.relays {
		d, want := desired[name]
		if !want {
			toStop = append(toStop, ir)
			delete(m.relays, name)
			slog.Info("dhcp-relay: stopping (interface removed from config)",
				"interface", name)
			continue
		}
		if !ir.spec.equal(d.spec) {
			toStop = append(toStop, ir)
			delete(m.relays, name)
			replaced[name] = ir
			slog.Info("dhcp-relay: restarting (config changed)",
				"interface", name,
				"old_servers", ir.spec.servers, "new_servers", d.spec.servers,
				"old_always_broadcast", ir.spec.alwaysBroadcast,
				"new_always_broadcast", d.spec.alwaysBroadcast)
		}
	}

	// Start relays that are desired but not currently running (newly added,
	// plus the ones just removed for a spec change). Record each ir in
	// m.relays before releasing the lock so a concurrent Apply observes the
	// new set; the goroutine is launched after the lock is dropped is fine —
	// the supervisor only reads its own ir + the manager seams.
	var toStart []struct {
		ir      *interfaceRelay
		rctx    context.Context
		servers []*net.UDPAddr
		group   string
	}
	for name, d := range desired {
		if _, running := m.relays[name]; running {
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		// #6562: size the outstanding-request table from THIS interface's
		// ingress packet-rate limit. A fixed capacity would be cap-bound (and
		// the reply-binding window would silently collapse) on any segment
		// whose `overrides maximum-packet-rate` is raised — which the relay's
		// own docs recommend for a busy segment. pendingCapacityFor reports
		// when the memory ceiling clamps it; that case is logged below.
		rate := resolveMaxPacketRate(d.spec.maxPacketRate)
		pendingCapacity, pendingClamped := pendingCapacityFor(rate)
		ir := &interfaceRelay{
			ifaceName:       d.ifaceName,
			kernelName:      d.kernelName,
			cancel:          cancel,
			done:            make(chan struct{}),
			spec:            d.spec,
			alwaysBroadcast: d.spec.alwaysBroadcast,
			maxHopCount:     resolveMaxHopCount(d.spec.maxHopCount),
			trustOption82:   d.spec.trustOption82,
			maxPacketRate:   rate,
			// The table is built here, with the relay, so it survives session
			// rebuilds; it shares the manager clock seam with the #5670 token
			// bucket so tests drive expiry deterministically.
			pending:        newPendingTable(pendingCapacity, pendingTTL, m.now),
			pendingClamped: pendingClamped,
		}
		m.relays[name] = ir
		toStart = append(toStart, struct {
			ir      *interfaceRelay
			rctx    context.Context
			servers []*net.UDPAddr
			group   string
		}{ir, rctx, d.servers, d.groupName})
	}
	m.mu.Unlock()

	// Phase 2 (outside lock): tear down removed/changed relays. For a changed
	// interface this completes BEFORE the replacement's listener binds below,
	// so the old SO_BINDTODEVICE socket is fully closed (no EADDRINUSE).
	for _, ir := range toStop {
		ir.cancel()
		<-ir.done
	}

	// Phase 2.5 (outside lock, AFTER the join): migrate outstanding-request
	// bindings from each replaced relay into its replacement (#6562).
	//
	// Ordering is load-bearing. The old relay's goroutines are fully joined
	// above, so its table is quiescent and the snapshot is complete; and the
	// replacement has not been launched yet, so nothing is concurrently
	// inserting into the destination. Snapshotting in phase 1 instead would
	// miss every request relayed between the decision and the actual stop.
	//
	// Without this, ANY day-2 change to a relay group (servers,
	// always-broadcast, hop count, trust-option-82, packet rate) destroys every
	// in-flight binding, and because the replacement rebinds the SAME
	// giaddr:67, replies for pre-reload requests still arrive and are then
	// dropped — an availability regression against pre-#6562 behavior. It bites
	// hardest for maximum-packet-rate, whose documented remedy is to raise it
	// on a busy segment: doing that mid-boot-storm would flush every binding.
	for _, s := range toStart {
		old, ok := replaced[s.ir.ifaceName]
		if !ok {
			continue
		}
		carried := old.pending.snapshot()
		s.ir.pending.adopt(carried)
		if len(carried) > 0 {
			slog.Info("dhcp-relay: carried outstanding request bindings across restart",
				"interface", s.ir.ifaceName,
				"bindings", len(carried),
				"new_capacity", s.ir.pending.capacity())
		}
	}

	// Phase 3 (outside lock): launch the new/restarted relays.
	for _, s := range toStart {
		go func(relay *interfaceRelay, rctx context.Context, servers []*net.UDPAddr) {
			defer close(relay.done)
			m.runRelay(rctx, relay.cancel, relay, servers)
		}(s.ir, s.rctx, s.servers)

		slog.Info("dhcp-relay: started",
			"interface", s.ir.ifaceName,
			"group", s.group,
			"servers", s.ir.spec.servers)

		// #6562: the reply-binding window is nominally pendingTTL, but at a
		// high `overrides maximum-packet-rate` the memory ceiling on the
		// outstanding-request table binds first and the real window is
		// capacity/rate. Say so at startup with the actual number — an
		// operator who raised the rate must not have to infer a shortened
		// binding window from a rising PendingEvicted later.
		if s.ir.pendingClamped {
			slog.Warn("dhcp-relay: reply-binding window reduced by the pending-table "+
				"memory ceiling at this packet rate",
				"interface", s.ir.ifaceName,
				"max_packet_rate", s.ir.maxPacketRate,
				"pending_capacity", s.ir.pending.capacity(),
				"nominal_window", pendingTTL,
				"effective_window", pendingWindow(s.ir.pending.capacity(), s.ir.maxPacketRate))
		}
	}
}

// Stats returns per-interface relay statistics.
func (m *Manager) Stats() []RelayStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := make([]RelayStats, 0, len(m.relays))
	for _, ir := range m.relays {
		stats = append(stats, RelayStats{
			Interface:                    ir.ifaceName,
			KernelInterface:              ir.kernelName,
			RequestsRelayed:              ir.requestsRelayed.Load(),
			RepliesForwarded:             ir.repliesForwarded.Load(),
			RequestsDroppedBackup:        ir.requestsDroppedBackup.Load(),
			RequestsDroppedMaxHops:       ir.requestsDroppedMaxHops.Load(),
			RequestsUntrustedGiaddrReset: ir.requestsUntrustedGiaddrReset.Load(),
			RequestsDroppedRateLimit:     ir.requestsDroppedRateLimit.Load(),
			RepliesDroppedUnknownServer:  ir.repliesDroppedUnknownServer.Load(),
			RepliesDroppedNoRequest:      ir.repliesDroppedNoRequest.Load(),
			RepliesDroppedForceRenew:     ir.repliesDroppedForceRenew.Load(),
			PendingEvicted:               ir.pending.evictions(),
			PendingSize:                  uint64(ir.pending.occupancy()),
			PendingCapacity:              uint64(ir.pending.capacity()),
			RepliesL2Unicast:             ir.repliesL2Unicast.Load(),
			RepliesUnicastCiaddr:         ir.repliesUnicastCiaddr.Load(),
			RepliesBroadcastFlag1:        ir.repliesBroadcastFlag1.Load(),
			RepliesBroadcastForced:       ir.repliesBroadcastForced.Load(),
			RepliesBroadcastNoTarget:     ir.repliesBroadcastNoTarget.Load(),
			RepliesBroadcastL2Fallback:   ir.repliesBroadcastL2Fallback.Load(),
			RepliesBroadcastNak:          ir.repliesBroadcastNak.Load(),
		})
	}
	if m.v6 != nil {
		m.v6.mu.Lock()
		dispatcherStats := m.v6.replyDispatcher.stats()
		for _, relay := range m.v6.relays {
			stats = append(stats, RelayStats{
				Family:                      "inet6",
				Interface:                   relay.ifaceName,
				KernelInterface:             relay.kernelName,
				RequestsRelayed:             relay.requestsRelayed.Load(),
				RepliesForwarded:            relay.repliesForwarded.Load(),
				RequestsDroppedBackup:       relay.requestsDroppedBackup.Load(),
				RequestsDroppedRateLimit:    relay.requestsDroppedRateLimit.Load(),
				RequestsDroppedNested:       relay.requestsDroppedNested.Load(),
				RequestsDroppedParse:        relay.requestsDroppedParse.Load(),
				RequestsDroppedPort:         relay.requestsDroppedPort.Load(),
				RequestsDroppedPeer:         relay.requestsDroppedPeer.Load(),
				RequestsDroppedBuild:        relay.requestsDroppedBuild.Load(),
				RepliesDroppedUnknownServer: relay.repliesDroppedUnknownSrv.Load(),
				RepliesDroppedIID:           relay.repliesDroppedIID.Load(),
				RepliesDroppedParse:         relay.repliesDroppedParse.Load(),
				RepliesDroppedInvalid:       relay.repliesDroppedInvalid.Load(),
				RepliesDroppedNested:        relay.repliesDroppedNested.Load(),
			})
		}
		if dispatcherStats.parse != 0 || dispatcherStats.emptyIID != 0 ||
			dispatcherStats.unknown != 0 || dispatcherStats.ambiguous != 0 {
			stats = append(stats, RelayStats{
				Family:                             "inet6",
				Interface:                          "<dhcpv6-reply-dispatcher>",
				RepliesDroppedDispatcherParse:      dispatcherStats.parse,
				RepliesDroppedDispatcherEmptyIID:   dispatcherStats.emptyIID,
				RepliesDroppedDispatcherUnknownIID: dispatcherStats.unknown,
				RepliesDroppedDispatcherAmbiguous:  dispatcherStats.ambiguous,
			})
		}
		m.v6.mu.Unlock()
	}
	return stats
}

// Stop stops all running relay goroutines and waits for them to finish.
func (m *Manager) Stop() {
	m.mu.Lock()
	relays := make(map[string]*interfaceRelay, len(m.relays))
	for k, v := range m.relays {
		relays[k] = v
	}
	m.relays = make(map[string]*interfaceRelay)
	m.mu.Unlock()

	// v6.stop() performs its own lock-and-join cycle after m.mu is released;
	// the HA callback can therefore safely read Manager's gate state.
	if m.v6 != nil {
		m.v6.stop()
	}
	for _, ir := range relays {
		ir.cancel()
		<-ir.done
	}
}

// runRelay is the per-interface supervisor. It runs one relay SESSION (resolve
// giaddr, open listener + server conn + raw-L2 sender, relay packets) under a
// child context, and rebuilds the session when it exits because the interface's
// kernel ifindex drifted away from the ifindex the client listener was bound to
// (#2347). It returns only when the manager context is cancelled (Stop()), at
// which point ir.done closes and Stop()'s join completes.
//
// Why a supervisor loop: the client listener binds SO_BINDTODEVICE once at
// bind(2), pinning it to the interface's then-current ifindex. If the interface
// is deleted+recreated/renamed under unchanged config the kernel stops
// delivering to the stale-bound socket and the relay goes permanently deaf
// until daemon restart. Detecting drift and rebinding restores delivery without
// dropping relays on other interfaces (each interface has its own supervisor).
// This mirrors the #2294 VRRP instance-restart-on-ifindex-drift fix.
func (m *Manager) runRelay(ctx context.Context, cancel context.CancelFunc,
	ir *interfaceRelay, servers []*net.UDPAddr) {
	// cancel is the manager-level cancel for this interface (invoked by Stop()).
	// We do not need it here beyond observing ctx.Done(); keep the signature
	// stable for Apply's call site.
	_ = cancel
	for {
		if ctx.Err() != nil {
			return
		}
		switch m.runRelaySession(ctx, ir, servers) {
		case sessionStop:
			// Stop() / one-sided exit / unrecoverable: end the per-interface
			// goroutine.
			return
		case sessionDrift:
			// The live ifindex moved (#2347): rebuild immediately (rebind to
			// the new ifindex), no delay.
			if ctx.Err() != nil {
				return
			}
			slog.Info("dhcp-relay: interface ifindex changed, rebinding listener",
				"interface", ir.ifaceName)
		case sessionReaddr:
			// The interface's primary IPv4 changed under a stable ifindex
			// (#3960): rebuild immediately so the giaddr is re-resolved, the
			// server conn rebinds to the new giaddr:67, and the new main loop
			// stamps the current address. No delay — the reply path is broken
			// until the rebuild completes.
			if ctx.Err() != nil {
				return
			}
			slog.Info("dhcp-relay: interface address changed, re-resolving giaddr",
				"interface", ir.ifaceName)
		case sessionRetry:
			// A transient socket bind/listen failure (interface not yet up,
			// IP not yet bound, EADDRINUSE on a quick reload). Do NOT kill the
			// supervisor (#2787) — wait the bounded, ctx-cancelable retry
			// interval and rebuild, so the relay recovers when the condition
			// clears. Stop() unblocks the wait promptly via ctx.Done().
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(m.retryInterval):
			}
		}
	}
}

// runRelaySession runs a single relay session and returns how it ended:
//   - sessionDrift: it tore down because the interface's live ifindex differs
//     from the ifindex the client listener was bound to (#2347) — rebind now.
//   - sessionRetry: a TRANSIENT socket bind/listen failure occurred before the
//     session could start (interface not yet up, IP not yet bound, EADDRINUSE
//     on a quick reload, #2787) — the supervisor waits and rebuilds rather than
//     dying, so the relay recovers when the interface comes up.
//   - sessionStop: any other exit (Stop, one-sided socket close) — the
//     supervisor ends the per-interface goroutine.
//
// Lifecycle invariants (see docs/research/1915-relay-socket-lifecycle/plan.md),
// preserved intact under a per-session child context:
//   - Both conns are net.PacketConn (ReadFrom/WriteTo) — no *net.UDPConn
//     assertion — which keeps the factory mockable.
//   - A close-on-cancel watcher is started LAST (after both conns exist) and
//     closes BOTH conns so a blocked ReadFrom returns net.ErrClosed.
//   - Both loops cancel the shared ctx on exit BEFORE the runner joins, so a
//     one-sided exit cannot hang wg.Wait(). The main loop runs in an inner
//     func whose `defer cancel()` fires before the outer wg.Wait().
//   - The #2347 drift watcher cancels this SAME session ctx, so a drift teardown
//     reuses the existing close-on-cancel + WaitGroup join — no new teardown
//     path, no EADDRINUSE (the old socket is fully closed before rebind), no
//     Stop()-hang risk.
func (m *Manager) runRelaySession(ctx context.Context,
	ir *interfaceRelay, servers []*net.UDPAddr) sessionOutcome {
	// ifaceName is the relay's IDENTITY (the authored config reference); it is
	// what the #2456 HA master gate and every log line speak. bindName is the
	// LINUX DEVICE (#9406) and is what every kernel call below must take —
	// net.InterfaceByName and SO_BINDTODEVICE cannot find `ge-0/0/0.0`. Empty
	// kernelName falls back to ifaceName so a Manager driven without a
	// resolver behaves exactly as it did before #9406.
	ifaceName := ir.ifaceName
	bindName := ir.kernelName
	if bindName == "" {
		bindName = ifaceName
	}

	// Per-session context. Either the manager ctx (Stop), a loop's exit
	// (cross-cancel), or the drift watcher cancels it.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// driftDetected (ifindex, #2347) and readdrDetected (primary-IPv4 change,
	// #3960) are set by the watcher under no lock other than its own
	// happens-before with wg.Wait(): the watcher writes them then the session
	// returns after wg.Wait() joins the watcher, so the reads below are safe.
	var driftDetected atomic.Bool
	var readdrDetected atomic.Bool

	// Axis C1: resolve giaddr with bounded, ctx-cancelable retry. Re-resolve
	// the interface every attempt so a dynamic interface recreated under the
	// same name (new Index) is picked up, and so a not-yet-created interface
	// does not permanently kill the relay.
	giaddr, ok := m.resolveGIAddrWithRetry(sctx, bindName)
	if !ok {
		return sessionStop // ctx cancelled during retry; nothing created yet.
	}

	// #2347: capture the interface's live ifindex at the moment we open the
	// client listener. SO_BINDTODEVICE inside the factory binds the socket to
	// this ifindex; the drift watcher compares against this baseline. A resolve
	// failure here is non-fatal — we proceed with boundIfindex=0 (an impossible
	// real ifindex) so the FIRST successful watcher resolve that returns a real
	// index is NOT mistaken for drift; the watcher only fires when it can read a
	// real index that differs from a real captured baseline.
	// Guard the resolver the same way the drift watcher does (`m.resolveIfindex
	// != nil`): a Manager constructed without a resolver disables drift
	// detection entirely, so the baseline capture must not call a nil resolver
	// (it would panic at session startup). nil resolver → degraded baseline 0.
	var boundIfindex int
	if m.resolveIfindex != nil {
		idx, ierr := m.resolveIfindex(bindName)
		if ierr != nil {
			slog.Warn("dhcp-relay: could not capture bound ifindex (drift detection degraded)",
				"interface", ifaceName, "err", ierr)
		} else {
			boundIfindex = idx
		}
	}

	// Client-facing listener: 0.0.0.0:67, REUSEPORT (coexist with other
	// interfaces), SO_BINDTODEVICE (per-interface isolation under REUSEPORT),
	// SO_BROADCAST (deliver broadcast OFFER/ACK to 255.255.255.255:68).
	conn, err := m.newConn(sctx, bindName, true, true,
		&net.UDPAddr{IP: net.IPv4zero, Port: relayPort})
	if err != nil {
		// #2787: a bind/listen failure is TRANSIENT, not terminal — the
		// interface may not be up yet, its IP not yet bound, or port 67 may be
		// momentarily busy on a quick reload. Tell the supervisor to retry
		// (after retryInterval) rather than killing it, so the relay recovers
		// when the condition clears. Only a cancelled session ctx is terminal.
		if sctx.Err() != nil {
			return sessionStop
		}
		slog.Warn("dhcp-relay: listen failed, will retry",
			"interface", ifaceName, "err", err,
			"interval", m.retryInterval)
		return sessionRetry
	}
	defer conn.Close()

	// Server conn: bound to giaddr:67 (BOOTPS), NOT an ephemeral port (#2888).
	// RFC 2131 §4.1 specifies a server unicasts its reply back to the relay
	// agent at the giaddr it saw in the relayed request, destination port 67
	// (BOOTPS) — NOT the relay's source port. A strict-RFC server therefore
	// sends OFFER/ACK to giaddr:67; if the relay's server-facing socket sits on
	// an ephemeral port nothing is listening on giaddr:67 and the reply is
	// dropped, so a relayed lease never completes with a strict server. Bind the
	// server conn to :67 so the giaddr-side reply is received.
	//
	// SO_REUSEADDR/SO_REUSEPORT (reusePort=true) is REQUIRED: the client-facing
	// listener already holds 0.0.0.0:67 (REUSEPORT). A second bind on port 67 —
	// even to the distinct, specific giaddr — would otherwise fail EADDRINUSE.
	// The two sockets do not steal each other's traffic: the client listener is
	// SO_BINDTODEVICE-pinned to the LAN interface (and receives client
	// broadcasts/limited-broadcast there), while the server conn binds the
	// SPECIFIC unicast giaddr — the kernel delivers a unicast datagram destined
	// to giaddr:67 to the address-specific socket in preference to the wildcard
	// listener. No BINDTODEVICE (the reply arrives via the routed WAN path, not
	// necessarily the client interface) and no broadcast (server replies to the
	// relay are unicast).
	serverConn, err := m.newConn(sctx, "", true, false,
		&net.UDPAddr{IP: giaddr, Port: relayPort})
	if err != nil {
		// #2787: likewise transient — the giaddr may have just been removed
		// (interface flap) or the ephemeral bind momentarily failed. Retry
		// instead of dying. Only a cancelled session ctx is terminal.
		if sctx.Err() != nil {
			return sessionStop
		}
		slog.Warn("dhcp-relay: server conn failed, will retry",
			"interface", ifaceName, "err", err,
			"interval", m.retryInterval)
		return sessionRetry
	}
	defer serverConn.Close()

	// Open the raw-L2 unicast sender (#2076), fail-soft: a nil sender means
	// every flag-clear reply takes the broadcast fallback and the relay stays
	// up (e.g. no CAP_NET_RAW). It is opened AFTER both UDP conns succeed and
	// BEFORE the cancel watcher. It is TX-only — it is deliberately NOT closed
	// by the watcher (it never blocks a read); it is closed by the idempotent
	// l2.Close() in a defer that runs only after wg.Wait() below, so every
	// sendReply caller has joined first (preserves the #1915 invariants).
	var l2 l2Replier
	if ir.alwaysBroadcast {
		slog.Info("dhcp-relay: overrides always-broadcast set, raw-L2 disabled",
			"interface", ifaceName)
	} else {
		l2, err = m.newL2(bindName)
		if err != nil {
			slog.Warn("dhcp-relay: raw-L2 sender unavailable, "+
				"flag-clear replies will broadcast",
				"interface", ifaceName, "err", err)
			l2 = nil
		}
	}
	defer func() {
		if l2 != nil {
			_ = l2.Close()
		}
	}()

	slog.Info("dhcp-relay: listening",
		"interface", ifaceName, "giaddr", giaddr, "ifindex", boundIfindex,
		"always_broadcast", ir.alwaysBroadcast, "raw_l2", l2 != nil,
		"trust_option_82", ir.trustOption82, "max_packet_rate_pps", ir.maxPacketRate)

	// Both the cancel watcher and the server-response goroutine are tracked by
	// the WaitGroup so the runner's wg.Wait() is a true join of every spawned
	// goroutine — runRelaySession does not return until the watcher's two
	// Close() calls have completed.
	var wg sync.WaitGroup

	// Cancel watcher — started LAST, after BOTH conns exist. Closing both is
	// REQUIRED for the wg.Wait() liveness chain: it unblocks both ReadFrom
	// calls. Double-close (here + the defers) is an idempotent no-op.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sctx.Done()
		_ = conn.Close()
		_ = serverConn.Close()
	}()

	// #2347 ifindex-drift + #3960 primary-IPv4 (giaddr) re-resolution watcher.
	// Periodically re-resolve the interface. On a real, differing live ifindex it
	// records drift (#2347); on a real, differing primary IPv4 it records a
	// readdress (#3960). Either cancels THIS session ctx, which trips the
	// close-on-cancel watcher above (clean teardown) and makes runRelay rebuild —
	// rebinding to the new ifindex (#2347) and/or re-resolving the giaddr + the
	// server conn's giaddr:67 bind (#3960). A resolve FAILURE (either lookup) is
	// treated as "no change" (tolerant) so a transient netlink hiccup, a
	// mid-rename window, or a momentarily unaddressed interface never tears down a
	// working listener — and never stamps a bogus giaddr, since the session keeps
	// its last-known-good giaddr until a real new address appears. Disabled when
	// ifindexCheck<=0 or no ifindex resolver; a degraded ifindex baseline
	// (boundIfindex==0) treats a later real index as drift only if the baseline
	// was real (see the guard below).
	if m.ifindexCheck > 0 && m.resolveIfindex != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(m.ifindexCheck)
			defer ticker.Stop()
			for {
				select {
				case <-sctx.Done():
					return
				case <-ticker.C:
					// #2347: ifindex drift.
					if live, lerr := m.resolveIfindex(bindName); lerr != nil {
						// Tolerant: keep the listener; this is not drift.
						slog.Debug("dhcp-relay: ifindex re-resolve failed, keeping listener",
							"interface", ifaceName, "err", lerr)
					} else if boundIfindex == 0 {
						// Degraded capture: adopt the first real reading as the
						// baseline rather than treating it as drift.
						boundIfindex = live
					} else if live != boundIfindex {
						slog.Info("dhcp-relay: detected ifindex drift",
							"interface", ifaceName,
							"old_ifindex", boundIfindex, "new_ifindex", live)
						driftDetected.Store(true)
						cancel()
						return
					}

					// #3960: primary-IPv4 (giaddr) change under a stable ifindex.
					// Re-resolve the current primary address and compare against
					// the giaddr this session bound at start. A differing address
					// means the DHCP server would unicast its OFFER/ACK to the old
					// (now-invalid) giaddr:67 and the reply is blackholed — rebuild
					// so the giaddr is re-resolved, the server conn rebinds to the
					// new giaddr:67, and the new main loop stamps the current
					// address. Runs every tick regardless of the ifindex result
					// (an address can change while the ifindex is stable).
					if m.resolveGIAddr != nil {
						if cur, gerr := m.resolveGIAddr(bindName); gerr != nil {
							// Tolerant: a momentary unaddressed window keeps the
							// last-known-good giaddr rather than tearing down (and
							// so never stamps a bogus giaddr).
							slog.Debug("dhcp-relay: giaddr re-resolve failed, keeping listener",
								"interface", ifaceName, "err", gerr)
						} else if !cur.Equal(giaddr) {
							slog.Info("dhcp-relay: detected giaddr address change",
								"interface", ifaceName,
								"old_giaddr", giaddr, "new_giaddr", cur)
							readdrDetected.Store(true)
							cancel()
							return
						}
					}
				}
			}
		}()
	}

	// Track the server-response goroutine so the runner joins it. Its exit
	// cancels the shared ctx (cross-cancellation) so the watcher closes both
	// conns and the main loop unblocks too.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		handleServerResponses(sctx, serverConn, conn, ir, l2, giaddr, servers)
	}()

	// Main read loop in its OWN func scope so its `defer cancel()` fires on
	// THIS func's return — BEFORE the outer wg.Wait() below. A function-scope
	// defer cancel() would run only after wg.Wait() and hang (Codex r3 BLOCKER).
	func() {
		defer cancel()
		buf := make([]byte, readBufSize)
		// #5670: per-interface ingress rate limiter. The token bucket admits at
		// most ir.maxPacketRate client-facing datagrams per second (with a short
		// burst allowance) so an untrusted client segment cannot flood the relay.
		// It is owned solely by this single-goroutine read loop, so it needs no
		// lock; the drop COUNTER on ir is atomic (Stats reads it). warnedRateLimit
		// throttles the log to warn-once-per-session then Debug (never per packet,
		// per the project logging rules).
		rateBucket := newTokenBucket(ir.maxPacketRate,
			relayBurstFor(ir.maxPacketRate), m.now)
		warnedRateLimit := false
		for {
			n, srcAddr, err := conn.ReadFrom(buf)
			if err != nil {
				// Exit ONLY on cancel or socket-close; a transient read error
				// is logged and the loop continues (a single bad datagram must
				// not kill the relay). Returning on ErrClosed too prevents a
				// hot-spin if the socket is closed while sctx.Err() is still nil.
				if sctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				slog.Warn("dhcp-relay: read error",
					"interface", ifaceName, "err", err)
				continue
			}

			// #5670: bound the per-interface admit rate BEFORE the (variable-
			// length TLV) dhcpv4.FromBytes parse and the Option-82 fan-out to
			// EVERY configured server. Each admitted packet is a CPU cost and a
			// 1→N amplification into the upstream DHCP servers, so an untrusted
			// client segment flooding :67 must be throttled at the cheapest point.
			// Excess is dropped and counted; the log is throttled (warn-once then
			// Debug) so a sustained flood cannot spam the journal.
			if !rateBucket.allow() {
				ir.requestsDroppedRateLimit.Add(1)
				if !warnedRateLimit {
					slog.Warn("dhcp-relay: client request rate limit exceeded, dropping excess",
						"interface", ifaceName, "rate_pps", ir.maxPacketRate, "src", srcAddr)
					warnedRateLimit = true
				} else {
					slog.Debug("dhcp-relay: client request rate limit exceeded, dropping",
						"interface", ifaceName, "src", srcAddr)
				}
				continue
			}

			pkt, err := dhcpv4.FromBytes(buf[:n])
			if err != nil {
				slog.Debug("dhcp-relay: invalid DHCP packet",
					"interface", ifaceName, "src", srcAddr, "err", err)
				continue
			}

			// Only relay client -> server messages (BOOTREQUEST).
			if pkt.OpCode != dhcpv4.OpcodeBootRequest {
				continue
			}

			msgType := pkt.MessageType()
			if !clientRequestRelayable(msgType) {
				continue
			}

			slog.Debug("dhcp-relay: received client request",
				"interface", ifaceName,
				"type", msgType,
				"client_mac", pkt.ClientHWAddr,
				"src", srcAddr)

			// #2456: HA master-state gate. On a shared client segment both the
			// cluster MASTER and the BACKUP node receive the client broadcast;
			// only the MASTER for this interface's redundancy group may forward
			// it upstream, otherwise the server sees duplicate relayed requests
			// (and duplicate relay state with different per-node giaddrs). The
			// gate is read per packet, so a backup→master failover starts
			// relaying immediately (the daemon's gate reads live RG state).
			// Standalone (nil gate) always relays.
			if !m.shouldRelay(ifaceName) {
				ir.requestsDroppedBackup.Add(1)
				slog.Debug("dhcp-relay: not master for interface, dropping client request",
					"interface", ifaceName,
					"type", msgType,
					"client_mac", pkt.ClientHWAddr)
				continue
			}

			// RFC 1542 §4.1.1 / RFC 3046 relay chaining: a nonzero inbound
			// giaddr means a DOWNSTREAM relay is the FIRST relay on the
			// client's segment and already stamped both the giaddr and the
			// relay-agent Option 82. That first relay OWNS them: the server
			// selects the client's address pool from the giaddr it sees and
			// unicasts its OFFER/ACK back to giaddr:67, and the original
			// circuit-id must survive so the operator's per-port policy still
			// applies. An intermediate relay MUST preserve both and only
			// touch the BOOTP hops field (#5071). Overwriting the giaddr makes
			// the server lease from the wrong pool and reply to the wrong
			// relay; overwriting Option 82 destroys the downstream circuit-id.
			//
			// #5414 (RFC 3046 §2.1 anti-spoofing): a nonzero giaddr is only a
			// TRUSTWORTHY downstream-relay stamp when it arrives on a TRUSTED
			// relay uplink (`overrides trust-option-82`). On the DEFAULT
			// untrusted client-facing interface a host on the client segment
			// can forge a nonzero giaddr + a crafted Option 82 to impersonate a
			// downstream relay and steer server-side pool/policy selection.
			// There the relay MUST NOT trust it: giaddrIsSet is gated on
			// trustOption82 so an untrusted forged giaddr falls through to the
			// first-hop branch below, which overwrites giaddr with our own
			// address (RFC 951/1542) and re-stamps Option 82 (addOption82 Dels
			// the forged option first). Capture BOTH conditions BEFORE any
			// mutation; forgedGiaddrValue snapshots the forged address for the
			// reset log because the first-hop branch overwrites giaddr. The
			// counter/log fire in that branch (below), AFTER the hop-limit drop,
			// so a request dropped for looping is not miscounted as a reset.
			chained := ir.trustOption82 && giaddrIsSet(pkt.GatewayIPAddr)
			forgedGiaddr := !ir.trustOption82 && giaddrIsSet(pkt.GatewayIPAddr)
			forgedGiaddrValue := pkt.GatewayIPAddr

			// Enforce the RFC 1542 §4.1.1 hop limit BEFORE incrementing.
			// HopCount is uint8: checking after a ++ lets an incoming value
			// of 255 wrap to 0 and slip past a post-increment ">= limit"
			// test, defeating loop protection. A request that already carries
			// the limit has reached it and must be dropped. The limit is the
			// group's `overrides maximum-hop-count` (default 16) — #4309. This
			// loop guard applies to first-hop AND chained requests; it is most
			// load-bearing on a chained ring, where a misconfigured downstream
			// relay loop would otherwise circulate the request forever.
			if pkt.HopCount >= ir.maxHopCount {
				ir.requestsDroppedMaxHops.Add(1)
				slog.Warn("dhcp-relay: hop count exceeded, dropping",
					"interface", ifaceName, "hops", pkt.HopCount, "limit", ir.maxHopCount)
				continue
			}
			pkt.HopCount++

			if chained {
				// Chained downstream relay: preserve giaddr AND the existing
				// relay-agent Option 82 untouched (do NOT stamp our giaddr and
				// do NOT Del/overwrite Option 82). Only the hops field above
				// was modified.
				slog.Debug("dhcp-relay: preserving downstream giaddr and Option 82 (relay chain)",
					"interface", ifaceName,
					"giaddr", pkt.GatewayIPAddr, "hops", pkt.HopCount)
			} else {
				// First hop, OR an untrusted interface with a client-forged
				// giaddr (#5414): stamp our interface IP so the server knows
				// where to reply, and insert Option 82 (Relay Agent
				// Information) with the circuit-id sub-option. addOption82 Dels
				// any existing (forged) Option 82 first, so a spoofed
				// circuit-id/remote-id is replaced, not preserved.
				if forgedGiaddr {
					ir.requestsUntrustedGiaddrReset.Add(1)
					slog.Debug("dhcp-relay: untrusted client-forged giaddr reset "+
						"(RFC 3046 anti-spoofing)",
						"interface", ifaceName,
						"client_mac", pkt.ClientHWAddr,
						"forged_giaddr", forgedGiaddrValue, "src", srcAddr)
				}
				pkt.GatewayIPAddr = giaddr
				addOption82(pkt, ifaceName)
			}

			// #6562: record this transaction as outstanding BEFORE writing it
			// upstream. handleServerResponses runs in a DIFFERENT goroutine on
			// the same session, so a server on a fast local segment can deliver
			// its OFFER before a post-send insert had run — which would drop
			// the legitimate first reply of every exchange. Recording first
			// costs nothing and closes that race.
			//
			// The key is taken from the fully-stamped packet, but the relay's
			// mutations (hops, giaddr, Option 82) do not touch xid or chaddr,
			// so it is identical either side of the stamping.
			//
			// Only requests that are actually forwarded are recorded: this sits
			// AFTER the rate limiter, the #2456 HA master gate and the #4309
			// hop-limit drop, so a request the relay refused upstream never
			// arms a binding for a reply it should not receive.
			ir.pending.insert(pendingKeyFor(pkt))

			// Unicast the modified packet to each server in the active group.
			relayData := pkt.ToBytes()
			for _, srv := range servers {
				if _, err := serverConn.WriteTo(relayData, srv); err != nil {
					slog.Warn("dhcp-relay: send to server failed",
						"interface", ifaceName,
						"server", srv, "err", err)
				}
			}
			ir.requestsRelayed.Add(1)
		}
	}()

	// Safe now: the inner func's defer cancel() has fired, so the watcher has
	// closed both conns and the response goroutine's ReadFrom is unblocked.
	wg.Wait()

	// The watcher (joined above) is the only writer of driftDetected /
	// readdrDetected; its store happens-before these reads through wg.Wait().
	// Both outcomes rebuild immediately in runRelay (a giaddr change breaks the
	// reply path just as an ifindex drift breaks the request path).
	if driftDetected.Load() {
		return sessionDrift
	}
	if readdrDetected.Load() {
		return sessionReaddr
	}
	return sessionStop
}

// resolveGIAddrWithRetry resolves the interface giaddr, retrying on a bounded
// ctx-cancelable interval until it succeeds. Returns (giaddr, true) on success
// or (nil, false) if ctx was cancelled first. The resolver re-looks-up the
// interface every attempt (no stale cached Index).
func (m *Manager) resolveGIAddrWithRetry(ctx context.Context, ifaceName string) (net.IP, bool) {
	warned := false
	for {
		giaddr, err := m.resolveGIAddr(ifaceName)
		if err == nil {
			return giaddr, true
		}
		if !warned {
			slog.Warn("dhcp-relay: interface not ready, retrying",
				"interface", ifaceName, "err", err,
				"interval", m.retryInterval)
			warned = true
		} else {
			slog.Debug("dhcp-relay: interface still not ready",
				"interface", ifaceName, "err", err)
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(m.retryInterval):
		}
	}
}

// handleServerResponses reads DHCP replies from servers on the serverConn
// and forwards them back to clients on the client-facing conn.
//
// Reply delivery honors the RFC 2131 §4.1 broadcast flag (#2076):
//
//	overrides always-broadcast        -> broadcast (operator override wins)
//	broadcast flag set                -> broadcast (existing path)
//	flag clear, yiaddr real           -> raw-L2 unicast to chaddr+yiaddr
//	flag clear, yiaddr 0, ciaddr real -> UDP-unicast to ciaddr (client has IP)
//	flag clear, yiaddr 0, ciaddr 0    -> broadcast (nothing routable)
//	raw-L2 path fails                 -> broadcast fallback (+ counter)
//
// srcIP is the saved interface giaddr (the IPv4 source the server saw in the
// relayed request); it MUST come from the caller, not from pkt.GatewayIPAddr,
// which is zeroed below before sending.
//
// Source validation (#4163): the server-facing socket is bound (not
// connect()-ed) to giaddr:67, so it accepts datagrams from ANY host that can
// route there. Before parsing or forwarding, each reply's source IP is checked
// against the configured server set (RFC 3046 relay practice — a relay forwards
// replies only from its explicit server list); a reply from an unlisted source
// is DROPPED and counted (repliesDroppedUnknownServer) so an off-path
// rogue-DHCP / lease-hijack injection cannot reach the client. The check is by
// IP with net.IP.Equal (the source port is not load-bearing); an empty server
// set admits nothing (fail-closed — a session is only started with a non-empty
// set, so this cannot black-hole a legitimately-configured relay).
//
// Outstanding-request binding (#6562): a source IP is spoofable, so passing the
// #4163 check is necessary but NOT sufficient. Each OFFER/ACK/NAK must also
// bind to a request this relay forwarded (xid + chaddr, ir.pending — see
// pending.go). DHCPFORCERENEW is refused outright: RFC 3203 §6 makes RFC 3118
// authentication a MUST, and a relay holds none of the key material RFC 3118
// §5.2/§5.3 puts between the client and the server, so it cannot verify one.
func handleServerResponses(ctx context.Context, serverConn, clientConn net.PacketConn,
	ir *interfaceRelay, l2 l2Replier, srcIP net.IP, servers []*net.UDPAddr) {
	ifaceName := ir.ifaceName
	// Build the server-IP allow-set ONCE, outside the read loop. Keep the raw
	// net.IP (compared with net.IP.Equal) rather than a string key so a 4-in-6
	// vs 4-byte form never causes a false miss.
	allow := make([]net.IP, 0, len(servers))
	for _, s := range servers {
		if s != nil && s.IP != nil {
			allow = append(allow, s.IP)
		}
	}
	// warnedUnknownSrc: log the FIRST rogue-source drop of this session at Warn
	// (loud, so an operator sees the injection attempt / multi-homed
	// misconfiguration) and subsequent ones at Debug — the counter is the
	// durable signal, so a flood of forged replies cannot spam the log. Mirrors
	// the resolveGIAddrWithRetry warn-once pattern.
	warnedUnknownSrc := false
	// #6562: the same warn-once-then-Debug discipline for the two new drop
	// paths. Both are reachable in a flood (a spoofing attacker, or a
	// FORCERENEW-emitting server), so neither may log per packet.
	warnedNoRequest := false
	warnedForceRenew := false
	buf := make([]byte, readBufSize)
	for {
		n, srcAddr, err := serverConn.ReadFrom(buf)
		if err != nil {
			// Exit ONLY on cancel or socket-close (see runRelay main loop).
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("dhcp-relay: server read error",
				"interface", ifaceName, "err", err)
			continue
		}

		// #4163: drop any reply whose source IP is not a configured server,
		// BEFORE parsing or forwarding. This closes the rogue-reply injection
		// hole (a forged OFFER/ACK steering the client to a hostile
		// gateway/DNS, or a forged NAK forcing a client restart).
		if !replySourceAllowed(srcAddr, allow) {
			ir.repliesDroppedUnknownServer.Add(1)
			if !warnedUnknownSrc {
				slog.Warn("dhcp-relay: dropping server reply from unconfigured source",
					"interface", ifaceName, "src", srcAddr)
				warnedUnknownSrc = true
			} else {
				slog.Debug("dhcp-relay: dropping server reply from unconfigured source",
					"interface", ifaceName, "src", srcAddr)
			}
			continue
		}

		pkt, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			slog.Debug("dhcp-relay: invalid server DHCP packet",
				"interface", ifaceName, "src", srcAddr, "err", err)
			continue
		}

		// Only process server -> client messages (BOOTREPLY).
		if pkt.OpCode != dhcpv4.OpcodeBootReply {
			continue
		}

		msgType := pkt.MessageType()
		switch msgType {
		case dhcpv4.MessageTypeOffer, dhcpv4.MessageTypeAck, dhcpv4.MessageTypeNak:
			// Forward to the client, subject to the #6562 binding below. NAK
			// rejects the client's request (RFC 2131 §4.3.2); dropping it makes
			// the client hang until its retransmission timeout instead of
			// restarting with a fresh DISCOVER.

		case messageTypeForceRenew:
			// #6562: REFUSE. This reverses #2645, which forwarded FORCERENEW on
			// the reasoning that RFC 3118 authentication is end-to-end
			// client<->server and therefore "out of scope for the relay".
			//
			// RFC 3203 §6 (Security Considerations — NOT §5, which is IANA
			// Considerations) is a MUST, and it is a MUST precisely because of
			// this attack: "As in some network environments FORCERENEW can be
			// used to snoop and spoof traffic, the FORCERENEW message MUST be
			// authenticated using the procedures as described in [DHCP-AUTH].
			// FORCERENEW messages failing the authentication should be silently
			// discarded by the client."
			//
			// A relay structurally CANNOT discharge that MUST. RFC 3118 §5.2
			// defines the key as "K - a secret value shared between the source
			// and destination of the message" and notes that "Delayed
			// authentication requires a shared secret key for each client on
			// each DHCP server"; RFC 3118 §3 casts the relay agent purely as a
			// transparent mutator whose giaddr/hops/Option-82 changes are
			// EXCLUDED from the hash, and §5.3 assigns validation to the
			// receiver ("If the MAC computed by the receiver does not match the
			// MAC contained in the authentication option, the receiver MUST
			// discard the DHCP message"). The relay is neither source,
			// destination, nor receiver, and holds no secret or secret-ID
			// mapping. It cannot verify the MAC.
			//
			// Checking merely that option 90 is PRESENT would be theater: the
			// off-path attacker in this threat model already forges the
			// server's source IP, so they can equally attach a well-formed
			// option 90 with a bogus MAC. Since the relay cannot check the MAC,
			// a presence test admits exactly the attacker it is meant to stop —
			// while most real clients do not implement RFC 3118 at all and
			// would never catch it downstream.
			//
			// Refusing costs a CONFORMANT deployment nothing, because a
			// conformant FORCERENEW never reaches this socket. RFC 3203 §2.2
			// opens: "The DHCP server sends a unicast FORCERENEW message to
			// the client." A unicast to the client's own leased address routes
			// as ordinary traffic and is never delivered to the relay's
			// giaddr:67 server socket at all. The only FORCERENEW that can
			// arrive HERE is one deliberately addressed to giaddr:67 — a
			// non-conformant server, or the attacker §6 is about. Normal
			// leasing is untouched either way: clients still renew at T1/T2.
			//
			// (Do NOT justify this by §2.2's retransmission sentence. That
			// describes recovery from TRANSIENT loss; the loss here is
			// PERMANENT — every retransmission hits this same arm — and §2.2
			// itself bounds the attempts: "The amount of retransmissions should
			// be limited." The backoff never converges, so it cannot carry the
			// argument.)
			//
			// This arm is also belt-and-braces: FORCERENEW is server-initiated,
			// so its xid matches no outstanding request and the #6562 binding
			// below would drop it regardless. The dedicated arm exists to give
			// the refusal its OWN counter and log, so an operator can tell it
			// apart from an ordinary unbound reply.
			ir.repliesDroppedForceRenew.Add(1)
			if !warnedForceRenew {
				slog.Warn("dhcp-relay: refusing to forward DHCPFORCERENEW "+
					"(RFC 3203 §6 requires RFC 3118 authentication a relay cannot verify)",
					"interface", ifaceName, "src", srcAddr,
					"client_mac", pkt.ClientHWAddr)
				warnedForceRenew = true
			} else {
				slog.Debug("dhcp-relay: refusing to forward DHCPFORCERENEW",
					"interface", ifaceName, "src", srcAddr)
			}
			continue

		default:
			continue
		}

		// #6562: bind the reply to an outstanding request. The #4163 source-IP
		// check above is spoofable — an off-path attacker who forges a
		// configured server's address passes it — so a reply must ALSO answer a
		// request this relay actually forwarded. The key is xid + chaddr, both
		// of which RFC 2131 §4.3.1 Table 3 requires the server to copy from the
		// client's message into OFFER/ACK/NAK (see pending.go for why option 61
		// is deliberately excluded).
		//
		// FAIL DIRECTION: this gate can silently break DHCP for real clients if
		// it is too strict, which is a worse outage than the injection it
		// prevents. Every drop is therefore counted (repliesDroppedNoRequest,
		// surfaced in `show services dhcp relay`) and logged warn-once-then-
		// Debug, so an operator sees a mis-binding immediately instead of
		// debugging an invisible black hole.
		if !ir.pending.matches(pendingKeyFor(pkt)) {
			ir.repliesDroppedNoRequest.Add(1)
			if !warnedNoRequest {
				slog.Warn("dhcp-relay: dropping server reply with no outstanding request",
					"interface", ifaceName, "src", srcAddr, "type", msgType,
					"xid", pkt.TransactionID, "client_mac", pkt.ClientHWAddr)
				warnedNoRequest = true
			} else {
				slog.Debug("dhcp-relay: dropping server reply with no outstanding request",
					"interface", ifaceName, "src", srcAddr, "type", msgType,
					"xid", pkt.TransactionID, "client_mac", pkt.ClientHWAddr)
			}
			continue
		}

		slog.Debug("dhcp-relay: received server reply",
			"interface", ifaceName,
			"type", msgType,
			"server", srcAddr,
			"client_mac", pkt.ClientHWAddr,
			"yiaddr", pkt.YourIPAddr)

		// Strip Option 82 before forwarding to the client.
		stripOption82(pkt)

		// Clear giaddr since we are the last relay hop. The L2 source IP
		// comes from the saved giaddr (srcIP), NOT this field.
		pkt.GatewayIPAddr = net.IPv4zero

		replyData := pkt.ToBytes()
		if deliverReply(ir, clientConn, l2, srcIP, pkt, replyData) {
			ir.repliesForwarded.Add(1)
		}
	}
}

// replySourceAllowed reports whether a server reply's source address is one of
// the configured DHCP servers (#4163). Comparison is by IP with net.IP.Equal so
// a 4-in-6 vs 4-byte form never yields a false miss; the source port is NOT
// checked (a strict-RFC server unicasts its reply from BOOTPS/67, but the port
// is not load-bearing for the trust decision). An empty allow-set admits
// nothing — a relay session is only started with a non-empty resolved server
// set, so this fail-closed default never black-holes a legitimately-configured
// relay.
func replySourceAllowed(srcAddr net.Addr, allow []net.IP) bool {
	src := udpAddrIP(srcAddr)
	if src == nil {
		return false
	}
	for _, ip := range allow {
		if ip.Equal(src) {
			return true
		}
	}
	return false
}

// udpAddrIP extracts the source IP from a ReadFrom address. It handles the
// *net.UDPAddr a UDP PacketConn returns (and *net.IPAddr for completeness), and
// falls back to parsing the string form for any other net.Addr implementation.
// Returns nil when no IP can be extracted (a nil addr or an unparseable form),
// which replySourceAllowed treats as "not a configured server" (drop).
func udpAddrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case nil:
		return nil
	case *net.UDPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		return net.ParseIP(host)
	}
}

// deliverReply applies the #2076 reply-destination matrix and sends the reply.
// It returns true if the reply was delivered (any path that issued a successful
// send), false on a hard send failure. It increments the per-reason counters.
func deliverReply(ir *interfaceRelay, clientConn net.PacketConn, l2 l2Replier,
	srcIP net.IP, pkt *dhcpv4.DHCPv4, replyData []byte) bool {
	yiaddr := pkt.YourIPAddr.To4()
	yiaddrReal := yiaddr != nil && !yiaddr.Equal(net.IPv4zero)
	ciaddr := pkt.ClientIPAddr.To4()
	ciaddrReal := ciaddr != nil && !ciaddr.Equal(net.IPv4zero)

	switch {
	case pkt.MessageType() == dhcpv4.MessageTypeNak:
		// A DHCPNAK rejects the client's request: it carries no binding,
		// so yiaddr (and ciaddr) are zero and the client has no usable
		// address. RFC 2131 §4.3.2 requires the relay to broadcast the
		// NAK on the client's subnet regardless of the broadcast flag.
		// Force broadcast here so a server that erroneously echoes a
		// stale ciaddr cannot trick the matrix into a unicast to an
		// address the client does not own.
		ir.repliesBroadcastNak.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case ir.alwaysBroadcast:
		ir.repliesBroadcastForced.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case pkt.IsBroadcast():
		ir.repliesBroadcastFlag1.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case yiaddrReal:
		// Flag clear with a real offered address: RFC-correct raw-L2
		// unicast to chaddr+yiaddr. Fall back to broadcast on any L2
		// failure or when no raw-L2 sender is available.
		if l2 != nil && l2Eligible(pkt) {
			err := l2.sendReply(pkt.ClientHWAddr, srcIP, yiaddr, replyData)
			if err == nil {
				ir.repliesL2Unicast.Add(1)
				return true
			}
			slog.Warn("dhcp-relay: raw-L2 unicast failed, broadcasting",
				"interface", ir.ifaceName,
				"client_mac", pkt.ClientHWAddr,
				"yiaddr", yiaddr, "err", err)
		}
		ir.repliesBroadcastL2Fallback.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case ciaddrReal:
		// Flag clear, no yiaddr, but the client already owns ciaddr
		// (DHCPINFORM / REBINDING ACK) — it answers ARP, so a normal UDP
		// unicast is deliverable.
		dst := &net.UDPAddr{IP: ciaddr, Port: clientPort}
		if _, err := clientConn.WriteTo(replyData, dst); err != nil {
			slog.Warn("dhcp-relay: unicast to ciaddr failed",
				"interface", ir.ifaceName, "dst", dst, "err", err)
			return false
		}
		ir.repliesUnicastCiaddr.Add(1)
		return true

	default:
		// Flag clear, no yiaddr, no ciaddr: nothing routable. Broadcast.
		ir.repliesBroadcastNoTarget.Add(1)
		return broadcastReply(ir, clientConn, replyData)
	}
}

// broadcastReply sends the reply to 255.255.255.255:68 on the client conn.
func broadcastReply(ir *interfaceRelay, clientConn net.PacketConn, replyData []byte) bool {
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort}
	if _, err := clientConn.WriteTo(replyData, dst); err != nil {
		slog.Warn("dhcp-relay: broadcast to client failed",
			"interface", ir.ifaceName, "dst", dst, "err", err)
		return false
	}
	return true
}

// clientRequestRelayable reports whether a client-originated BOOTREQUEST of the
// given DHCP message type must be relayed to the configured servers.
//
// Per RFC 2131 §3.4 a relay agent forwards all client-originated requests that
// carry server-bound options, not just lease acquisition (DISCOVER) and
// lease (re)negotiation (REQUEST):
//
//   - DISCOVER / REQUEST — lease acquisition and renewal/rebinding.
//   - INFORM — a client that already holds an address (statically configured,
//     or post-lease) asking only for supplemental parameters (DNS servers,
//     domain search, NTP, etc.). Dropping it leaves such clients without
//     central configuration; the server answers an INFORM with an ACK, which
//     the reply path already forwards (see deliverReply: the flag-clear,
//     yiaddr==0, real-ciaddr case unicasts to the client's ciaddr).
//   - DECLINE — a client that, after an ARP probe, detected the offered
//     address already in use broadcasts a DHCPDECLINE (RFC 2131 §3.1 step 4,
//     §4.4.1). The relay MUST forward it so the originating server marks that
//     address unavailable; otherwise the server keeps re-offering the
//     conflicting address and the segment suffers a persistent duplicate-IP
//     condition (#2789). DECLINE carries no server reply, so no reply-path
//     handling is needed.
//
// RELEASE is intentionally not relayed here. Unlike DISCOVER/REQUEST/INFORM/
// DECLINE — which a client broadcasts when it has no usable server unicast
// path on the local segment — a RELEASE is unicast by the client directly to
// the server it is bound to (RFC 2131 §4.4.4), so the datagram routes to the
// server without relay assistance and is never seen on the relay's
// client-facing broadcast socket in the first place.
func clientRequestRelayable(msgType dhcpv4.MessageType) bool {
	switch msgType {
	case dhcpv4.MessageTypeDiscover,
		dhcpv4.MessageTypeRequest,
		dhcpv4.MessageTypeInform,
		dhcpv4.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// l2Eligible reports whether a reply can be sent via the raw-L2 path: the
// client must use a 6-byte Ethernet hardware address. Non-Ethernet htype or a
// non-6-byte chaddr falls back to broadcast (the L2 frame would be malformed).
func l2Eligible(pkt *dhcpv4.DHCPv4) bool {
	return pkt.HWType == iana.HWTypeEthernet && len(pkt.ClientHWAddr) == 6
}

// giaddrIsSet reports whether a BOOTP giaddr (GatewayIPAddr) field carries a
// real relay address — i.e. a DOWNSTREAM relay already stamped it and this node
// is an intermediate hop in a relay chain (RFC 1542 §4.1.1 / RFC 3046). A zero
// or unset giaddr (0.0.0.0 or nil) means this relay is the first hop on the
// client segment. Comparison is form-agnostic (net.IP.Equal handles the 4-byte
// vs 4-in-16 form), so a zero in either representation reads as unset.
func giaddrIsSet(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && !v4.Equal(net.IPv4zero)
}

// addOption82 inserts or replaces the Relay Agent Information option (82)
// with sub-option 1 (circuit-id) set to the interface name.
func addOption82(pkt *dhcpv4.DHCPv4, ifaceName string) {
	// Build the sub-option TLV: type(1) + length + value.
	circuitID := []byte(ifaceName)
	subopt := make([]byte, 0, 2+len(circuitID))
	subopt = append(subopt, suboption1CircuitID)
	subopt = append(subopt, byte(len(circuitID)))
	subopt = append(subopt, circuitID...)

	// Remove any existing Option 82 first.
	pkt.Options.Del(option82)

	// Add the new Option 82.
	pkt.Options.Update(dhcpv4.OptGeneric(option82, subopt))
}

// stripOption82 removes the Relay Agent Information option (82) from the packet.
func stripOption82(pkt *dhcpv4.DHCPv4) {
	pkt.Options.Del(option82)
}

// interfaceIPv4 returns the primary non-loopback IPv4 address on the interface
// using the standard-library address list. It is retained for callers/tests
// that already hold a *net.Interface; the giaddr resolution path uses
// defaultIfaceResolver (which prefers a netlink-backed primary selection that
// honors IFA_F_SECONDARY — see #2849).
func interfaceIPv4(iface *net.Interface) (net.IP, error) {
	cands, err := portableIPv4Lister(iface.Name)
	if err != nil {
		return nil, err
	}
	return selectPrimaryIPv4(iface.Name, cands)
}
