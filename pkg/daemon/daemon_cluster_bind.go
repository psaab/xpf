// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

func isInteractive() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// interfaceAddrsByName resolves a LINUX-kernel interface name to its addresses.
// It is a package var so the web-management bind resolution
// (resolveInterfaceAddrs) is unit-testable without a real kernel interface.
var interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(kernelName)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}

// resolveInterfaceAddrs returns one bind host per address family present on
// the interface identified by the AUTHORED Junos ref (e.g. "ge-0/0/0.0"): the
// first usable IPv4 address and the first usable IPv6 address, IPv4 first.
// It is the #14583 (Y07-02) successor of resolveInterfaceAddr, which returned
// a SINGLE IPv4-first address — a dual-stack web-management interface silently
// had no IPv6 management listener at all, though host-inbound admits
// http/https for both families and IPv6 is first-class.
//
// #5714: the ref is first mapped to its Linux kernel ifname via
// config.ResolveKernelIfName (the same Junos->Linux mapping networkd/linksetup
// use) BEFORE the kernel lookup — net.InterfaceByName expects the kernel name
// (e.g. "ge-0-0-0"), not the Junos name (e.g. "ge-0/0/0"), so passing the
// authored name verbatim never matched and the bind SILENTLY fell back to
// loopback, leaving web-management unreachable on the configured interface while
// the operator believed it was bound there. On any resolution/lookup failure
// this logs LOUDLY at ERROR (the bind did NOT land on the configured
// interface) and returns []string{fallback}, so the mgmt API still serves on
// loopback rather than not at all — a hard error here would strand a mgmt
// interface that is merely not up yet at daemon start.
//
// IPv6 selection (#14583): a global address is preferred; a link-local
// address is used only when no global address exists, and then WITH its zone
// (the kernel interface name) attached — a bare link-local bind
// ("[fe80::…]:443") fails EINVAL because the kernel cannot pick an interface,
// while the zoned form binds. An address that already carries a zone keeps
// that zone.
func resolveInterfaceAddr(cfg *config.Config, ifname, fallback string) string {
	addr, _ := resolveInterfaceAddrDegraded(cfg, ifname, fallback)
	return addr
}

// resolveInterfaceAddrDegraded is resolveInterfaceAddr for callers that must
// distinguish "the interface's current address" from "no usable address yet,
// so the loopback fallback was used" (#14582). degraded=true means fallback
// was returned because the kernel lookup failed or found no usable address;
// the desired bind has NOT landed on the configured interface. A leg that
// resolves degraded must not be recorded as converged on the configured
// interface and must not report Listening there: the socket (if any) is on
// loopback while the operator asked for a routable interface address.
func resolveInterfaceAddrDegraded(cfg *config.Config, ifname, fallback string) (addr string, degraded bool) {
	addrs, degraded := resolveInterfaceAddrsDegraded(cfg, ifname, fallback)
	if len(addrs) == 0 {
		return fallback, true
	}
	return addrs[0], degraded
}

func resolveInterfaceAddrs(cfg *config.Config, ifname, fallback string) []string {
	addrs, _ := resolveInterfaceAddrsDegraded(cfg, ifname, fallback)
	return addrs
}

// resolveInterfaceAddrsDegraded is the #14583 multi-address resolver with the
// #14582 degraded signal: degraded=true exactly when the returned set is the
// loopback fallback because resolution/lookup failed or no usable address
// exists.
func resolveInterfaceAddrsDegraded(cfg *config.Config, ifname, fallback string) (addrs []string, degraded bool) {
	kernelName := ifname
	if cfg != nil {
		kernelName = cfg.ResolveKernelIfName(ifname)
	}
	ifaceAddrs, err := interfaceAddrsByName(kernelName)
	if err != nil {
		slog.Error("web-management interface not found; NOT bound to configured interface, using loopback fallback",
			"interface", ifname, "kernel", kernelName, "fallback", fallback, "err", err)
		return []string{fallback}, true
	}
	hosts := selectInterfaceBindHosts(ifaceAddrs, kernelName)
	if len(hosts) == 0 {
		slog.Error("web-management interface has no usable addresses; NOT bound to configured interface, using loopback fallback",
			"interface", ifname, "kernel", kernelName, "fallback", fallback)
		return []string{fallback}, true
	}
	return hosts, false
}

// selectInterfaceBindHosts picks the bind hosts for one interface's address
// list: first usable IPv4, plus first global IPv6 — or, when the interface
// has no global IPv6, its first link-local IPv6 WITH zone attached (the
// kernel name, unless the address already carries a zone). Unspecified
// addresses are skipped (they are not interface addresses to bind by name).
// Returns nil when nothing is usable.
func selectInterfaceBindHosts(addrs []net.Addr, zone string) []string {
	var v4, v6Global, v6LinkLocal string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsUnspecified() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			if v4 == "" {
				v4 = ip4.String()
			}
			continue
		}
		// net.IPNet carries no Zone field; a zoned address renders it in
		// String() ("fe80::1%eth0"). ipNet.IP.String() strips it, so take the
		// rendered form and drop any "/mask" suffix.
		host := ipNet.String()
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		if !strings.Contains(host, "%") && ipNet.IP.IsLinkLocalUnicast() && zone != "" {
			host += "%" + zone
		}
		if ipNet.IP.IsLinkLocalUnicast() {
			if v6LinkLocal == "" {
				v6LinkLocal = host
			}
			continue
		}
		if v6Global == "" {
			v6Global = host
		}
	}
	v6 := v6Global
	if v6 == "" {
		v6 = v6LinkLocal
	}
	var out []string
	if v4 != "" {
		out = append(out, v4)
	}
	if v6 != "" {
		out = append(out, v6)
	}
	return out
}

// joinBindAddrs renders one "host:port" bind per host (net.JoinHostPort, so
// an IPv6 host — zoned or not — is bracketed).
func joinBindAddrs(hosts []string, port string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, net.JoinHostPort(h, port))
	}
	return out
}

// clampBindsToLoopback applies clampBindToLoopback to every bind in the set
// (#14583: a dual-stack leg set clamps per family — the IPv4 entry to
// 127.0.0.1, the IPv6 entry to ::1). The effective set is multi when present,
// else the single mirror. Each clamped entry warns once.
func clampBindsToLoopback(multi []string, single string, hasAuth bool, kind string) []string {
	addrs := multi
	if len(addrs) == 0 && single != "" {
		addrs = []string{single}
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if clamped, ok := clampBindToLoopback(a, hasAuth); ok {
			slog.Warn(kind+" API bind is non-loopback without api-auth; clamping to loopback (add `set system services web-management api-auth` to bind off-loopback) — #4047/#5127",
				"requested", a, "clamped", clamped)
			out = append(out, clamped)
			continue
		}
		out = append(out, a)
	}
	return out
}

// hostIsLoopback reports whether a bind host string is a loopback address.
// Used by the #4047 part-B runtime clamp (daemon_run.go) to decide whether a
// no-auth web-management bind is network-reachable and must be pulled back to
// loopback.
//
// An EMPTY host is the Go wildcard bind spelling — `net.SplitHostPort(":8080")`
// yields host "" and listens on ALL interfaces (0.0.0.0 / ::). It is emphatically
// NOT loopback. Treating it as loopback (the pre-#4903 behaviour) let an
// unauthenticated `--api-addr :8080` escape the clamp and expose the mutating
// REST surface network-wide (#4903), exactly the exposure this clamp exists to
// prevent. An unparseable, non-loopback host is likewise treated as NON-loopback
// so the no-auth clamp errs toward pulling the bind back to loopback (fail safe)
// rather than leaving a possibly network-reachable bind exposed. The lone
// exception is the literal hostname "localhost": it is not a parseable IP but is
// a legitimate loopback bind spelling that conventionally resolves to loopback,
// so it stays classified as loopback and is not clamped.
func hostIsLoopback(host string) bool {
	if host == "" {
		// Wildcard bind (all interfaces) — never loopback.
		return false
	}
	if host == "localhost" {
		// Not a parseable IP, but a legitimate loopback bind spelling.
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Unparseable and not "localhost": fail safe, treat as non-loopback so
		// a no-auth bind gets clamped rather than left exposed.
		return false
	}
	return ip.IsLoopback()
}

// clampBindToLoopback is the pure decision for the #4047 part-B runtime
// fail-safe clamp. Given a resolved REST bind ("host:port", IPv6 host bracketed)
// and whether api-auth is configured, it returns the effective bind address and
// whether it was clamped. A bind is clamped ONLY when it is BOTH off-loopback
// AND unauthenticated — that is the exact case where the unauthenticated
// mutating config endpoints would otherwise be reachable from the network. The
// clamp targets a loopback of the SAME address family (::1 for an IPv6 bind,
// 127.0.0.1 for IPv4) and preserves the port. An authenticated bind or a
// genuine loopback bind (127.0.0.0/8, ::1, or the literal "localhost") is
// returned unchanged. A bind whose host part fails to parse as an address
// (`net.SplitHostPort` errors, e.g. a bare no-port string) is also returned
// unchanged, since there is no port to clamp; but a parsed wildcard/empty or
// unparseable-but-split host is now classified NON-loopback by hostIsLoopback
// and clamped when no-auth (fail safe, #4903).
func clampBindToLoopback(addr string, hasAuth bool) (string, bool) {
	if hasAuth {
		return addr, false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || hostIsLoopback(host) {
		return addr, false
	}
	loopback := "127.0.0.1"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// An IPv6 (non-v4-mapped) address clamps to the IPv6 loopback so the
		// bind stays same-family (a v6 daemon is reachable on ::1, not 127.0.0.1).
		loopback = "::1"
	}
	return net.JoinHostPort(loopback, port), true
}

func parseLiteralIP(addr string) net.IP {
	if addr == "" {
		return nil
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func selectClusterBindAddr(addrs []net.Addr, peerAddr, fallback string) string {
	var ipv4Candidates []string
	var globalIPv6Candidates []string
	peerIP := parseLiteralIP(peerAddr)
	peerWantsIPv4 := peerIP != nil && peerIP.To4() != nil
	peerWantsIPv6 := peerIP != nil && peerIP.To4() == nil

	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			ipv4Candidates = append(ipv4Candidates, ip4.String())
			continue
		}
		// Cluster control/fabric transports do not support binding to bare
		// link-local IPv6 addresses because the resulting listen address lacks
		// an interface zone. Treat them as unusable so startup waits for the
		// configured control/fabric address family instead of racing on fe80::.
		if ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		globalIPv6Candidates = append(globalIPv6Candidates, ipNet.IP.String())
	}

	switch {
	case peerWantsIPv4:
		if len(ipv4Candidates) > 0 {
			return ipv4Candidates[0]
		}
	case peerWantsIPv6:
		if len(globalIPv6Candidates) > 0 {
			return globalIPv6Candidates[0]
		}
	default:
		if len(ipv4Candidates) > 0 {
			return ipv4Candidates[0]
		}
		if len(globalIPv6Candidates) > 0 {
			return globalIPv6Candidates[0]
		}
	}

	return fallback
}

// resolveClusterInterfaceAddr returns a usable control/fabric bind address for
// the named interface. It prefers the same address family as the configured
// peer and skips unscoped link-local IPv6 addresses.
func resolveClusterInterfaceAddr(ifname, peerAddr, fallback string) string {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		slog.Warn("cluster interface not found, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		slog.Warn("cluster interface has no addresses, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addr := selectClusterBindAddr(addrs, peerAddr, fallback)
	if addr == "" {
		slog.Info("cluster interface has no usable bind address yet", "interface", ifname, "peer", peerAddr)
	}
	return addr
}
