package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// IP / CIDR validators (#1319 PR 3, interfaces subsystem). They reuse the
// net package parsers the runtime consumers use (net.ParseIP /
// net.ParseCIDR), so schema acceptance mirrors runtime parse acceptance
// exactly — including the family classification rule ip.To4() != nil that
// pkg/dataplane/userspace/interfaces.go buildConfiguredAddressSnapshots
// applies to configured addresses.

// ValidateIPAddress accepts any IPv4 or IPv6 address WITHOUT a prefix
// length. Used for leaves the runtime feeds to net.ParseIP (e.g. GRE
// tunnel source/destination, pkg/routing/tunnel.go:194), where garbage
// silently disables the feature today.
func ValidateIPAddress(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an IP address, e.g. 10.0.1.10 or 2001:db8::1)")
	}
	if net.ParseIP(trimmed) == nil {
		if _, _, err := net.ParseCIDR(trimmed); err == nil {
			return fmt.Errorf("prefix length not allowed here (got %q; use a bare IP address)", raw)
		}
		return fmt.Errorf("not a valid IP address (got %q)", raw)
	}
	return nil
}

// ValidateBGPClusterID accepts a BGP route-reflector cluster-id in exactly the
// two forms FRR/vtysh's `bgp cluster-id <A.B.C.D | (1-4294967295)>` grammar
// accepts: an IPv4 dotted-quad, or a 32-bit unsigned integer in 1..4294967295.
//
// `protocols bgp cluster-id` is parsed as a raw string and rendered verbatim
// (compiler_protocols.go copies child.Keys[1]; pkg/frr/policy_render.go emits
// `bgp cluster-id <v>`). Unlike the adjacent router-id (guarded by
// validateRouterIDStrict + the validRouterID render belt), cluster-id had NO
// value validator and NO render-side sanitize belt. A bad token (`not.an.ip`,
// an IPv6 literal, `0`, or an out-of-range integer) is rejected by FRR at
// frr-reload, which exits non-zero on any CMD_WARNING_CONFIG_FAILED and stalls
// the WHOLE xpf-managed section — so a mistyped cluster-id poisons the reload
// for any co-committed routing change (#4919). Accepting exactly what FRR
// accepts keeps the commit gate from over-rejecting a valid config while
// closing the reload-poison surface.
//
// Strict at commit-check (SchemaValidate); the tolerant load / peer-sync path
// keeps booting (#1960) and the render belt (validClusterID + sanitizeFRRValue,
// pkg/frr) keeps a leniently-loaded bad value out of frr.conf.
func ValidateBGPClusterID(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a BGP cluster-id: an IPv4 dotted-quad like 10.0.0.1, or an integer 1..4294967295)")
	}
	// IPv4 dotted-quad form. net.ParseIP rejects a bare integer, so the
	// integer spelling falls through to the ParseUint arm below.
	if ip := net.ParseIP(trimmed); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("invalid cluster-id %q (an IPv6 address is not a valid BGP cluster-id; use an IPv4 dotted-quad or a 32-bit integer)", raw)
		}
		return nil
	}
	// 32-bit unsigned integer form. ParseUint with bitSize 32 rejects a value
	// above 4294967295 (out-of-FRR-range) as a parse error.
	if v, err := strconv.ParseUint(trimmed, 10, 32); err == nil {
		if v < 1 {
			return fmt.Errorf("invalid cluster-id %q (the integer form must be in 1..4294967295)", raw)
		}
		return nil
	}
	return fmt.Errorf("invalid cluster-id %q (expected an IPv4 dotted-quad like 10.0.0.1, or a 32-bit integer 1..4294967295)", raw)
}

// ValidateIPv6Address accepts an IPv6 literal WITHOUT a prefix length and
// rejects IPv4. Used for the RDNSS dns-server-address leaf (#2497): the RA
// sender (pkg/ra/sender.go buildRA) feeds each address to netip.ParseAddr
// and appends it to an RFC 8106 RecursiveDNSServer option, which is an
// IPv6-only NDP option. The runtime skips an unparseable string but does
// NOT family-gate, so a bare IPv4 literal (8.8.8.8) parses and is
// advertised on the wire inside an IPv6 RDNSS option — a malformed RA.
// The family rule mirrors the runtime's ip.To4()==nil classification.
func ValidateIPv6Address(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an IPv6 address, e.g. 2001:db8::1)")
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		if _, _, err := net.ParseCIDR(trimmed); err == nil {
			return fmt.Errorf("prefix length not allowed here (got %q; use a bare IPv6 address)", raw)
		}
		return fmt.Errorf("not a valid IP address (got %q)", raw)
	}
	if ip.To4() != nil {
		return fmt.Errorf("not an IPv6 address (got %q; the RDNSS option is IPv6-only per RFC 8106)", raw)
	}
	return nil
}

// pref64PrefixLengths are the prefix lengths RFC 8781 §4 permits for a
// PREF64 (NAT64 prefix) option: only these encode in the 3-bit PLC field.
// A prefix of any other length cannot be advertised at all.
var pref64PrefixLengths = map[int]struct{}{
	32: {}, 40: {}, 48: {}, 56: {}, 64: {}, 96: {},
}

// ValidatePREF64CIDR accepts an IPv6 prefix usable in a PREF64 option:
// a valid IPv6 CIDR (reusing ValidateIPv6CIDR's family + prefix rules)
// whose prefix length is one of the RFC 8781 §4 set {32,40,48,56,64,96}.
// Used for the router-advertisement nat-prefix/nat64prefix leaves (#2497):
// the RA sender wraps the prefix in an ndp.PREF64 option whose wire PLC
// field can only encode those six lengths. An out-of-set length committed
// today reaches netip.ParsePrefix cleanly, so the runtime accepts it and
// then either omits the option or mis-encodes the length.
func ValidatePREF64CIDR(raw string, cfg *Config) error {
	if err := ValidateIPv6CIDR(raw, cfg); err != nil {
		return err
	}
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		// Unreachable: ValidateIPv6CIDR already parsed it.
		return fmt.Errorf("not a valid address/prefix-length (got %q): %v", raw, err)
	}
	ones, _ := ipnet.Mask.Size()
	if _, ok := pref64PrefixLengths[ones]; !ok {
		return fmt.Errorf("invalid PREF64 prefix length /%d (got %q; RFC 8781 permits only /32, /40, /48, /56, /64, /96)", ones, raw)
	}
	return nil
}

// ValidateIPv4CIDR accepts an IPv4 address with an explicit prefix
// length (e.g. 10.0.1.10/24). The prefix is REQUIRED: every runtime
// consumer of configured interface addresses net.ParseCIDRs the string
// and silently skips it on error (dataplane snapshot:
// pkg/dataplane/userspace/interfaces.go:391; RETH link-local checks:
// pkg/daemon/daemon_reth.go:308), so a bare IP would commit and then
// silently not exist. The v4/v6 family split mirrors the runtime
// classification ip.To4() != nil.
func ValidateIPv4CIDR(raw string, _ *Config) error {
	ip, err := parseCIDRStrict(raw, "10.0.1.10/24")
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return fmt.Errorf("not an IPv4 address (got %q; IPv6 addresses belong under family inet6)", raw)
	}
	return nil
}

// ValidateIPv6CIDR accepts an IPv6 address with an explicit prefix
// length (e.g. 2001:db8::1/64). See ValidateIPv4CIDR for why the prefix
// is required; the family rule mirrors the runtime's ip.To4() == nil
// classification, so 4-in-6 forms like ::ffff:10.0.1.1/96 — which the
// runtime classifies as inet — are rejected under family inet6.
func ValidateIPv6CIDR(raw string, _ *Config) error {
	ip, err := parseCIDRStrict(raw, "2001:db8::1/64")
	if err != nil {
		return err
	}
	if ip.To4() != nil {
		return fmt.Errorf("not an IPv6 address (got %q; IPv4 addresses belong under family inet)", raw)
	}
	return nil
}

// parseCIDRStrict is the shared require-a-prefix CIDR parse for the two
// family validators. It upgrades the two common operator mistakes to
// targeted messages: a bare IP (missing /prefix-length) and outright
// garbage.
func parseCIDRStrict(raw, example string) (net.IP, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("missing value (expected address/prefix-length, e.g. %s)", example)
	}
	ip, _, err := net.ParseCIDR(trimmed)
	if err != nil {
		if net.ParseIP(trimmed) != nil {
			return nil, fmt.Errorf("missing /prefix-length (got %q; the runtime silently skips addresses without one — write e.g. %s)", raw, example)
		}
		return nil, fmt.Errorf("not a valid address/prefix-length (expected e.g. %s): %v", example, err)
	}
	return ip, nil
}

// ValidateOSPFArea accepts an OSPF/OSPFv3 area identifier in either Junos
// spelling: an IPv4 dotted-quad (0.0.0.0, 10.1.2.3) or a 32-bit unsigned
// integer (0, 1, 4294967295). Both are legitimate and FRR renders either.
//
// #6564: the `area` key carried NO validator, while its siblings `route`
// (ValidateRouteDestination) and `next-hop` (ValidateStaticNextHop) both do.
// compileProtocols takes the area name verbatim from Keys[1] via
// namedInstances and pkg/frr writes it straight into frr.conf (` area %s %s`,
// ` ip ospf area %s`), so a malformed id reached the routing daemon's config
// file unexamined. Unlike a BGP cluster-id, area 0 is the BACKBONE and must be
// accepted — the integer arm therefore has no >= 1 floor.
func ValidateOSPFArea(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an OSPF area id: an IPv4 dotted-quad like 0.0.0.0, or an integer 0..4294967295)")
	}
	// #9820: validate what is emitted. The renderer interpolates the RAW
	// key; padding that TrimSpace hides would pass here while the RAW key
	// renders. Padding IS authorable through ordinary ingress (the lexer
	// preserves quoted-string contents verbatim and the parser accepts
	// them as path values), so `area " 0.0.0.0 "` commits clean today and
	// functions (spaces are harmless FRR token separators) — refusing it
	// is therefore an INTENTIONAL compatibility tightening (option 1):
	// area IDs must be bare tokens, where bare = unpadded DECODED value
	// (quotes themselves are fine). Migration: remove quotes/padding.
	// Newlines need no story here: the #1798 prewalk already rejects
	// control characters in every key on the strict path and scrubs them
	// to spaces on the lenient path, so no `\n`-padding ever rendered
	// split lines; this arm additionally refuses it first, with the
	// area-specific message. Tolerant path omits-with-warning.
	if trimmed != raw {
		return fmt.Errorf("invalid area id %q (leading or trailing whitespace is not allowed; use a bare IPv4 dotted-quad or integer)", raw)
	}
	// Dotted-quad form. net.ParseIP rejects a bare integer, so the integer
	// spelling falls through to the ParseUint arm below.
	if ip := net.ParseIP(trimmed); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("invalid area id %q (an IPv6 address is not a valid OSPF area id; use an IPv4 dotted-quad or a 32-bit integer)", raw)
		}
		if addr, err := netip.ParseAddr(trimmed); err == nil && addr.Is4In6() {
			return fmt.Errorf("invalid area id %q (an IPv4-mapped IPv6 literal is not a valid OSPF area id; FRR takes only an IPv4 dotted-quad or a 32-bit integer)", raw)
		}
		return nil
	}
	// 32-bit unsigned integer form. ParseUint with bitSize 32 rejects a value
	// above 4294967295. Area 0 is the backbone, so there is no lower bound.
	if _, err := strconv.ParseUint(trimmed, 10, 32); err == nil {
		return nil
	}
	return fmt.Errorf("invalid area id %q (expected an IPv4 dotted-quad like 0.0.0.0, or a 32-bit integer 0..4294967295)", raw)
}
