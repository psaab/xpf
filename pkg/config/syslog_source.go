package config

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
)

// ResolveSyslogSourceAddr returns the source IP to bind syslog forwarding to,
// resolved from a `security log source-interface` value (an interface name with
// an optional `.<unit>` suffix). It prefers the unit's configured
// PrimaryAddress (stripped to a bare IP); failing that it falls back to the
// first IPv4 address on the live kernel interface, and returns "" when neither
// is available.
//
// It lives in pkg/config, not pkg/daemon, so BOTH the daemon reconcile
// (applySyslogConfig) and the CLI in-process commit path (reloadSyslog /
// buildSyslogClients) resolve the global source-interface fallback identically
// — a stream configured with source-interface but no per-stream source-address
// must bind the same source IP whether the config is applied by daemon reconcile
// or a local-console commit (#5738). The split rule (first '.') mirrors
// ValidateSyslogSourceInterface exactly.
func ResolveSyslogSourceAddr(cfg *Config, srcIface string) string {
	return resolveSyslogSource(cfg, srcIface, "")
}

// ResolveSyslogSourceAddrForCollector is ResolveSyslogSourceAddr with the
// collector's address family taken into account (#15078, A47-01).
//
// The family-blind resolver returned the unit's `primary` address — inet
// wins at compile time (compiler_interfaces.go) — or else the first IPv4
// on the kernel interface. A stream to an IPv6 collector on a dual-stack
// source-interface therefore bound an IPv4 source and failed to dial for
// the life of the config (#14597's retry re-derived the same wrong-family
// address, so it could not recover).
//
// collectorHost is the stream's `host` value. When it is an IP literal,
// only addresses of that literal's family are eligible: within the
// configured addresses the family's primary/preferred wins, otherwise
// the first configured address of the family; within the kernel fallback
// the first kernel address of the family. When no address of the family
// exists the result is "" — the caller leaves the bind unbound and warns,
// rather than pinning a wrong-family source that fails the dial. When
// collectorHost is a hostname or empty it carries no family and the
// legacy family-blind behaviour is kept.
func ResolveSyslogSourceAddrForCollector(cfg *Config, srcIface, collectorHost string) string {
	family := ""
	if ip := net.ParseIP(strings.TrimSpace(collectorHost)); ip != nil {
		if ip.To4() != nil {
			family = "ipv4"
		} else {
			family = "ipv6"
		}
	}
	return resolveSyslogSource(cfg, srcIface, family)
}

// resolveSyslogSource is the shared resolver behind
// ResolveSyslogSourceAddr (family == "") and
// ResolveSyslogSourceAddrForCollector (family "ipv4"/"ipv6"). See those
// for the contract; the family only narrows which addresses are eligible.
func resolveSyslogSource(cfg *Config, srcIface, family string) string {
	// #6942: normalise exactly as ValidateSyslogSourceInterface does. The
	// validator trims before it parses, so on the strict path a value with
	// surrounding whitespace is judged in its trimmed form and then handed here
	// untrimmed — the two disagreed about the same string. The callers only
	// guard `!= ""`, which a whitespace-only value passes.
	srcIface = strings.TrimSpace(srcIface)

	// Parse "iface.unit" — e.g. "reth1.100" → base="reth1", unit=100
	base, unitStr, hasUnit := strings.Cut(srcIface, ".")
	unitNum := 0
	unitOK := true
	if hasUnit {
		// #6942: the error was checked and then IGNORED — unitNum stayed 0, so
		// "reth1.abc" resolved to reth1 unit 0 and syslog bound the wrong
		// logical unit, silently and plausibly. ValidateSyslogSourceInterface
		// rejects this and its message names this exact behaviour ("a
		// non-numeric unit silently binds the syslog source to unit 0"), so the
		// strict path masked it; the lenient path (Load / SyncApply) did not.
		//
		// A BARE name legitimately means unit 0 — that is why the skip is
		// conditioned on hasUnit && parse-failed rather than on unitNum == 0.
		n, err := strconv.Atoi(unitStr)
		if err != nil {
			unitOK = false
		} else {
			unitNum = n
		}
	}
	if cfg != nil {
		if ifc, ok := cfg.Interfaces.Interfaces[base]; ok && ifc != nil && unitOK {
			if unit, ok := ifc.Units[unitNum]; ok && unit != nil {
				if addr := syslogUnitSourceAddr(unit, family); addr != "" {
					return addr
				}
			}
		}
	}
	// Fallback: first address of the collector's family from kernel
	// (first IPv4 when no family is known — the legacy behaviour).
	if iface, err := net.InterfaceByName(srcIface); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && syslogIPMatchesFamily(ipn.IP, family) {
					return ipn.IP.String()
				}
			}
		}
	}
	if family != "" {
		slog.Warn("security log: no source address of the collector's family on the source-interface; "+
			"leaving the syslog source unbound (#15078)",
			"source_interface", srcIface, "family", family)
	}
	return ""
}

// syslogUnitSourceAddr picks the source address for one interface unit.
// With a family (#15078) it honours that family's primary, then preferred,
// then the first configured address of the family — PrimaryAddress /
// PreferredAddress are single slots that inet fills first at compile time,
// so for an IPv6 collector they usually hold an IPv4 address and must be
// skipped when their family does not match. Without a family it is the
// legacy rule: PrimaryAddress only.
func syslogUnitSourceAddr(unit *InterfaceUnit, family string) string {
	parse := func(cidr string) (net.IP, string) {
		if cidr == "" {
			return nil, ""
		}
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, ""
		}
		return ip, ip.String()
	}
	if family == "" {
		if _, s := parse(unit.PrimaryAddress); s != "" {
			return s
		}
		return ""
	}
	for _, cand := range []string{unit.PrimaryAddress, unit.PreferredAddress} {
		if ip, s := parse(cand); s != "" && syslogIPMatchesFamily(ip, family) {
			return s
		}
	}
	for _, cidr := range unit.Addresses {
		if ip, s := parse(cidr); s != "" && syslogIPMatchesFamily(ip, family) {
			return s
		}
	}
	return ""
}

// syslogIPMatchesFamily reports whether ip belongs to family
// ("ipv4"/"ipv6"); "" matches any family (the legacy behaviour).
func syslogIPMatchesFamily(ip net.IP, family string) bool {
	switch family {
	case "ipv4":
		return ip.To4() != nil
	case "ipv6":
		return ip.To4() == nil
	default:
		// Legacy: first IPv4 (see the kernel fallback's original rule).
		return ip.To4() != nil
	}
}
