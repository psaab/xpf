package ddns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// backend_bind.go: source / interface / VRF binding for the RFC 2136 UPDATE
// transport (#2691 P1b / #2665, plan §5.7). In a multi-WAN or VRF deployment a
// DNS UPDATE must egress from a specific source IP, a specific interface,
// and/or a specific routing-instance (VRF) — otherwise it leaves via the
// default table / kernel-chosen source and is dropped by source-IP-keyed ACLs
// (authoritative servers commonly ACL on source IP in addition to TSIG) or
// sent to the wrong upstream.
//
// The binding is built into the *dns.Client's transport via a custom
// net.Dialer:
//   - source-address       → Dialer.LocalAddr (bind the socket's source IP).
//   - destination-interface → Dialer.Control → SO_BINDTODEVICE (pin egress).
//   - routing-instance     → Dialer.Control → SO_BINDTODEVICE on the VRF
//     master device (Linux binds a socket into a VRF by binding to the vrf
//     device, which shares the routing-instance name — pkg/routing). When both
//     a destination-interface and a routing-instance are set, the
//     destination-interface wins for SO_BINDTODEVICE (the more specific pin);
//     a VRF-only config binds to the VRF device.
//
// FAIL-OPEN at runtime: a malformed source-address is rejected at construction
// (the manager falls back to a no-op for that family and counts it, never a
// crash); a SO_BINDTODEVICE failure surfaces as a dial error on the exchange,
// which the reconciler logs + retries next cycle (it never wedges DHCP). This
// matches the existing update-server / TSIG fail-open posture.

// bindConfig is the resolved source/interface/VRF binding for one family's
// backend (#2665). The zero value (all empty) means "no binding — default
// table / kernel source selection", today's behaviour byte-for-byte.
type bindConfig struct {
	sourceAddr  netip.Addr // bound source IP; zero ⇒ none
	bindDevice  string     // SO_BINDTODEVICE target (dest-interface or VRF dev)
	routingInst string     // routing-instance name (informational / VRF dev)
}

// An interface-name resolver maps a Junos interface reference (as an operator
// types it in a destination-interface leaf, e.g. "reth0.50" or "ge-0/0/2") to
// the ACTUAL kernel device name on the LOCAL node. Production threads the
// committed config's SSOT resolver, config.(*Config).ResolveKernelIfName, which
// correctly handles reth→physical-member, unit-0 collapse, unit≠vlan-id, and
// tunnel/irb/st0 refs (config/types.go). A nil resolver falls back to the leaf
// slash-substitution (config.LinuxIfName) — used only by callers with no
// committed config in hand (never the daemon path). See #5070. The type is the
// bare `func(string) string` throughout so the exported daemon-facing seams
// (ReconcileOptions.InterfaceResolver, SurfaceAManager.Reconcile) take
// cfg.ResolveKernelIfName without a named-type conversion.

// firstResolver extracts the single OPTIONAL interface-name resolver from a
// variadic trailing slot. The bind path threads the resolver as an optional arg
// so the many existing no-resolver call sites (tests, direct callers) stay
// valid while the daemon threads cfg.ResolveKernelIfName. A missing or nil
// entry yields nil (leaf fallback).
func firstResolver(resolveIf []func(string) string) func(string) string {
	if len(resolveIf) > 0 {
		return resolveIf[0]
	}
	return nil
}

// resolveIfKernelName maps a destination-interface Junos ref to its kernel
// device name via the SSOT resolver, falling back to the leaf
// slash-substitution when no resolver was threaded in.
func resolveIfKernelName(resolve func(string) string, ref string) string {
	if resolve != nil {
		return resolve(ref)
	}
	return config.LinuxIfName(ref)
}

// resolveBindConfig builds a bindConfig from a DDNS policy's source-binding
// leaves (#2665). An empty config yields the zero bindConfig (no binding). A
// non-empty source-address that does not parse is a hard error so the manager
// falls back to no-op for that family (and counts it) rather than emitting
// UPDATEs from the wrong source.
//
// resolve is the committed config's Junos→kernel interface-name resolver
// (cfg.ResolveKernelIfName); nil ⇒ the leaf slash-substitution fallback.
func resolveBindConfig(c *config.DHCPDynamicDNSConfig, resolve func(string) string) (bindConfig, error) {
	if c == nil {
		return bindConfig{}, nil
	}
	var b bindConfig
	if c.SourceAddress != "" {
		a, err := netip.ParseAddr(c.SourceAddress)
		if err != nil {
			return bindConfig{}, fmt.Errorf("ddns: invalid source-address %q: %w", c.SourceAddress, err)
		}
		b.sourceAddr = a.Unmap()
	}
	// destination-interface is the more specific SO_BINDTODEVICE pin; a VRF
	// (routing-instance) binds to its VRF master device. Prefer the explicit
	// destination-interface.
	//
	// SO_BINDTODEVICE needs the REAL kernel device name — NOT the Junos config
	// token (#5070). A destination-interface is a Junos interface reference
	// (e.g. "reth0.50", "ge-0/0/2.50"); the daemon renames/creates the kernel
	// device via config.(*Config).ResolveKernelIfName, which resolves
	// reth→physical member, unit-0 collapse ("ge-0/0/2.0" → "ge-0-0-2"), and
	// unit≠vlan-id (unit 50 / vlan-id 80 → "ge-0-0-2.80"). Resolve through that
	// SSOT (threaded in as `resolve`), NOT the leaf slash-substitution — the
	// latter yields fictitious devices ("reth0.100", "ge-0-0-2.50") for exactly
	// the reth / VLAN cases the HA-cluster WAN binding targets. A
	// routing-instance is realized as a kernel VRF master device named
	// "vrf-<name>", so resolve it through routing.VRFDeviceName — the
	// single source of truth for that prefix, applied unconditionally
	// (#16664; an instance named "vrf-red" binds "vrf-vrf-red", never
	// sibling "red"). Without this mapping SO_BINDTODEVICE targets a
	// nonexistent device and every RFC 2136 / HTTP-provider / check-IP
	// exchange hard-fails at dial.
	//
	// routingInst keeps the RAW routing-instance name (informational only; it
	// is never used for the socket op — only bindDevice is).
	b.routingInst = c.RoutingInstance
	switch {
	case c.DestinationInterface != "":
		b.bindDevice = resolveIfKernelName(resolve, c.DestinationInterface)
	case c.RoutingInstance != "":
		b.bindDevice = routing.VRFDeviceName(c.RoutingInstance)
	}
	return b, nil
}

// bindDeviceLinkByName is the netlink lookup used to validate that a resolved
// SO_BINDTODEVICE target exists as a kernel device at backend construction
// (#5070). It is a package var so tests can inject a fake without touching real
// netlink; production uses the real netlink.LinkByName.
var bindDeviceLinkByName = func(name string) error {
	_, err := netlink.LinkByName(name)
	return err
}

// validateDevice checks that the resolved bindDevice exists as a kernel device,
// surfacing a CLEAR construction-time error instead of a cryptic
// SO_BINDTODEVICE dial failure later (#5070). A bindConfig with no device
// (source-address-only, or no binding at all) validates trivially. The netlink
// lookup goes through the bindDeviceLinkByName seam so a transiently-absent
// device (e.g. the WAN link not yet up at boot) simply fails this construction
// pass and is retried by the reconciler's resolve-per-Reconcile loop.
func (b bindConfig) validateDevice() error {
	if b.bindDevice == "" {
		return nil
	}
	if err := bindDeviceLinkByName(b.bindDevice); err != nil {
		return fmt.Errorf("ddns: bind device %q does not exist: %w", b.bindDevice, err)
	}
	return nil
}

// isSet reports whether the bindConfig requests any binding.
func (b bindConfig) isSet() bool {
	return b.sourceAddr.IsValid() || b.bindDevice != ""
}

// dialer builds the net.Dialer the *dns.Client uses for both the UDP-first and
// the TCP-retry exchange, applying the source-address bind AND the
// interface/VRF SO_BINDTODEVICE in a SINGLE Dialer.Control hook.
//
// Both binds are done in Control (not via Dialer.LocalAddr) deliberately: the
// SAME dialer is reused for a "udp" dial (the primary path) and a "tcp" dial
// (the truncation retry, see exchange()), and net.Dialer.LocalAddr is
// network-typed (a *net.UDPAddr LocalAddr makes a "tcp" dial fail with an
// address-type mismatch). Binding the source IP with unix.Bind inside Control —
// where the socket fd is already open but not yet connected — works for BOTH
// networks with no type coupling. Port 0 lets the kernel pick the source port.
//
// Returns nil when no binding is requested (the *dns.Client then uses its
// default dialer — today's behaviour byte-for-byte).
//
// Dual-stack family gate (#2901, refined by #5327): the source-bind is applied
// only when the source-address family MATCHES the dial socket's address family.
// The dialer is shared by the RFC 2136 backend AND, via newHTTPClientBound
// (#2846), every HTTP DDNS backend + the checkip probe — dialing endpoints that
// may resolve to both A and AAAA records. Calling unix.Bind with a SockaddrInet4
// on an AF_INET6 socket (or the reverse) fails EAFNOSUPPORT/EINVAL and would
// abort the whole connection, so this hook keys off the Dialer.Control "network"
// argument ("tcp4"/"tcp6"/"udp4"/"udp6") and only binds on a family match.
//
// The gate is now a SECONDARY guard: whenever a source-address is configured,
// the callers PIN the dial network to the source family upstream
// (constrainDialNetwork — cl.Net for RFC 2136, the Transport.DialContext wrapper
// for HTTP), so Happy-Eyeballs can no longer pick the other family. That closes
// the #5327 hole where a cross-family dial SILENTLY SKIPPED the bind and egressed
// from a kernel-chosen source on the WRONG WAN (bypassing a source ACL /
// publishing the wrong address with no error). With the pin in place the network
// here always carries the matching family suffix, so the gate always evaluates
// true for a source-configured dial; if the endpoint has no address in the source
// family the pinned dial FAILS CLOSED before this hook runs. The gate still
// guards the device-only bind (no source-address → no family pin → SO_BINDTODEVICE
// only, family-agnostic) and remains defense-in-depth against an unsuffixed
// network. SO_BINDTODEVICE is family-agnostic and is always applied.
func (b bindConfig) dialer(timeout time.Duration) *net.Dialer {
	if !b.isSet() {
		return nil
	}
	src := b.sourceAddr
	dev := b.bindDevice
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				if dev != "" {
					// SO_BINDTODEVICE pins egress to the named device; for a VRF
					// the device is the VRF master (Linux's VRF socket-binding
					// model), matching pkg/grpcapi's VRF-bind pattern. It is
					// family-agnostic, so it applies on every dial.
					if e := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); e != nil {
						serr = e
						return
					}
				}
				if src.IsValid() && sourceMatchesDialFamily(src, network) {
					// Bind the source IP (ephemeral port). unix.Bind on the raw fd
					// before connect sets the socket's local address for both UDP
					// and TCP. Only reached when the source family matches the dial
					// socket's family, so the Sockaddr type can never mismatch the
					// socket (no EAFNOSUPPORT on a dual-stack lookup, #2901).
					var sa unix.Sockaddr
					if src.Is4() {
						sa = &unix.SockaddrInet4{Addr: src.As4()}
					} else {
						sa = &unix.SockaddrInet6{Addr: src.As16()}
					}
					if e := unix.Bind(int(fd), sa); e != nil {
						serr = e
						return
					}
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}
}

// sourceMatchesDialFamily reports whether the source-address family is
// compatible with the dial socket's address family, as named by the
// Dialer.Control "network" argument ("tcp4"/"tcp6"/"udp4"/"udp6"). A "4" suffix
// is an AF_INET socket; a "6" suffix is an AF_INET6 socket. When the network
// carries no family suffix (e.g. a bare "tcp"/"udp" — the dial family is then
// chosen by the resolved address and not surfaced here) we cannot prove a
// mismatch, so we permit the bind and rely on the source family selecting the
// correct Sockaddr type (pre-#2901 behaviour for the no-hint case).
func sourceMatchesDialFamily(src netip.Addr, network string) bool {
	switch {
	case strings.HasSuffix(network, "4"):
		return src.Is4()
	case strings.HasSuffix(network, "6"):
		return src.Is6()
	default:
		return true
	}
}

// sourceDialFamily returns the address-family suffix ("4" or "6") that a
// configured source-address pins the dial to, and whether a pin applies (#5327).
// A pin applies ONLY when a source-address is configured: it is the operator's
// multi-WAN / security egress control and MUST always be honored. A device-only
// bind (SO_BINDTODEVICE) is family-agnostic and imposes no family pin, and a
// no-binding config never reaches the constrained path.
func (b bindConfig) sourceDialFamily() (suffix string, ok bool) {
	if !b.sourceAddr.IsValid() {
		return "", false
	}
	if b.sourceAddr.Is4() {
		return "4", true
	}
	return "6", true
}

// constrainDialNetwork pins a base dial network ("tcp"/"udp") to the configured
// source-address family (#5327). A source-address is a multi-WAN / security
// egress pin: left dual-stack, Go's Happy-Eyeballs can pick the family the source
// does NOT cover, the family gate in dialer() then SILENTLY SKIPS the bind, and
// the exchange egresses from a kernel-chosen source on the wrong WAN — bypassing
// a source ACL and/or publishing the wrong external address with no error (the
// #2901 documented-intentional silent-skip, overridden here as a reviewed
// decision because a configured source-address must never be silently abandoned).
// Forcing the network to the source family guarantees the bind always applies; if
// the endpoint has NO address in that family the pinned dial FAILS CLOSED (a clear
// "no suitable address" dial error surfaced to the reconciler) instead of
// egressing unbound. A network already carrying a family suffix, or a config with
// no source-address (device-only / unbound), is returned unchanged.
func (b bindConfig) constrainDialNetwork(base string) string {
	suffix, ok := b.sourceDialFamily()
	if !ok {
		return base
	}
	if strings.HasSuffix(base, "4") || strings.HasSuffix(base, "6") {
		return base
	}
	return base + suffix
}

// boundDialContext wraps a *net.Dialer's DialContext so the dial network is
// pinned to the configured source-address family (#5327) before delegating. The
// HTTP transport calls Transport.DialContext with a bare "tcp"; the rewrite forces
// "tcp4"/"tcp6" so Happy-Eyeballs cannot pick the other family and skip the source
// bind. With no source-address (device-only) the network is passed through
// unchanged, so behaviour is byte-for-byte the pre-#5327 dial.
func (b bindConfig) boundDialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, b.constrainDialNetwork(network), address)
	}
}

// networkFamilySuffix returns the "4"/"6" family suffix carried by a dial network
// string, or "" for a bare "tcp"/"udp". Used to carry the #5327 source-family pin
// from the UDP dial onto the RFC 2136 TCP truncation retry.
func networkFamilySuffix(network string) string {
	switch {
	case strings.HasSuffix(network, "4"):
		return "4"
	case strings.HasSuffix(network, "6"):
		return "6"
	default:
		return ""
	}
}
