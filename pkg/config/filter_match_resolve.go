package config

import (
	"fmt"
	"strconv"
	"strings"
)

// filter_match_resolve.go is the single source of truth for resolving SYMBOLIC
// firewall-filter match values (icmp-type / icmp-code names and named/service
// ports) to their numeric values at compile time (#3205, agy-070 findings
// 070-07 and 070-08).
//
// Why this matters — the fail-open / silent-drop the resolution closes:
//
//   - icmp-type/icmp-code: the compiler used to parse these with strconv.Atoi
//     and IGNORE the error, so a Junos symbolic name (echo-request, ...) was
//     silently dropped, leaving the type/code set empty. An empty set means
//     "match ANY ICMP", so a term meant to narrow to one icmp-type silently
//     matched every ICMP type — an `accept` term then permitted redirect,
//     unreachable, router-solicitation, ... (a policy bypass).
//
//   - named ports: the Rust dataplane's port table only recognized a tiny set
//     and silently dropped any other name (e.g. `domain`, the Junos canonical
//     name for 53). An unresolved-but-non-empty port left the port set
//     constrained-yet-empty, and a `*-port-except` term then matched ALL ports
//     (fail open — it accepted the very port it was meant to exclude).
//
// The fix is two-part: resolve every recognized symbolic value to its number
// HERE (shared by the compile path so the dataplane only ever sees numerics),
// and FAIL CLOSED on an unrecognized value — the compile path records it and a
// strict commit gate (validateFilterMatchValuesStrict) rejects the commit with
// a clear error rather than silently widening or breaking the term.

// icmpTypeNames maps Junos ICMPv4 (`family inet`) icmp-type names to their
// numeric type values. This is the canonical Junos firewall-filter icmp-type
// name set (Junos `set firewall family inet filter ... from icmp-type ?`), not
// a partial convenience list. Both the long Junos name and the common short
// alias are accepted where Junos accepts both.
var icmpTypeNames = map[string]int{
	"echo-reply":              0,
	"unreachable":             3,
	"destination-unreachable": 3,
	"source-quench":           4,
	"redirect":                5,
	"echo-request":            8,
	"echo":                    8,
	"router-advertisement":    9,
	"router-solicit":          10,
	"time-exceeded":           11,
	"parameter-problem":       12,
	"timestamp":               13,
	"timestamp-reply":         14,
	"info-request":            15,
	"info-reply":              16,
	"mask-request":            17,
	"mask-reply":              18,
}

// icmp6TypeNames maps Junos ICMPv6 (`family inet6`) icmp-type names to their
// numeric type values. Canonical Junos firewall-filter icmp6 type-name set.
var icmp6TypeNames = map[string]int{
	"destination-unreachable":                  1,
	"packet-too-big":                           2,
	"time-exceeded":                            3,
	"parameter-problem":                        4,
	"echo-request":                             128,
	"echo-reply":                               129,
	"membership-query":                         130,
	"membership-report":                        131,
	"membership-termination":                   132,
	"router-solicit":                           133,
	"router-advertisement":                     134,
	"neighbor-solicit":                         135,
	"neighbor-advertisement":                   136,
	"redirect":                                 137,
	"router-renumbering":                       138,
	"node-information-request":                 139,
	"node-information-reply":                   140,
	"inverse-neighbor-discovery-solicitation":  141,
	"inverse-neighbor-discovery-advertisement": 142,
}

// junosServicePorts maps Junos firewall-filter port/service names to their
// numeric port value. This is the canonical Junos `port` value name set used in
// `from {source,destination}-port[-except] <name>`, NOT a partial list. Where a
// port is known by more than one Junos name (dns/domain, login/who, exec/biff)
// every accepted spelling is present.
var junosServicePorts = map[string]uint16{
	"tcpmux":         1,
	"echo":           7,
	"discard":        9,
	"systat":         11,
	"daytime":        13,
	"netstat":        15,
	"chargen":        19,
	"ftp-data":       20,
	"ftp":            21,
	"ssh":            22,
	"telnet":         23,
	"smtp":           25,
	"time":           37,
	"whois":          43,
	"nameserver":     42,
	"tacacs":         49,
	"tacacs-ds":      65,
	"domain":         53,
	"dns":            53,
	"bootps":         67,
	"dhcp":           67,
	"bootpc":         68,
	"tftp":           69,
	"gopher":         70,
	"finger":         79,
	"http":           80,
	"www":            80,
	"kerberos-sec":   88,
	"pop2":           109,
	"pop3":           110,
	"sunrpc":         111,
	"ident":          113,
	"auth":           113,
	"nntp":           119,
	"ntp":            123,
	"netbios-ns":     137,
	"netbios-dgm":    138,
	"netbios-ssn":    139,
	"imap":           143,
	"snmp":           161,
	"snmptrap":       162,
	"xdmcp":          177,
	"bgp":            179,
	"irc":            194,
	"ldap":           389,
	"https":          443,
	"snpp":           444,
	"mobileip-agent": 434,
	"mobilip-mn":     435,
	"smtps":          465,
	"ldp":            646,
	"msdp":           639,
	"ike":            500,
	"isakmp":         500,
	"exec":           512,
	"biff":           512,
	"login":          513,
	"who":            513,
	"cmd":            514,
	"rsh":            514,
	"syslog":         514,
	"printer":        515,
	"talk":           517,
	"ntalk":          518,
	"router":         520,
	"rip":            520,
	"timed":          525,
	"klogin":         543,
	"kshell":         544,
	"afs":            1483,
	"radius":         1812,
	"radacct":        1813,
	"krbupdate":      760,
	"kpasswd":        761,
	"krb-prop":       754,
	"socks":          1080,
	"pptp":           1723,
	"nfsd":           2049,
	"cvspserver":     2401,
	"eklogin":        2105,
	"ekshell":        2106,
	"rkinit":         2108,
	"zephyr-srv":     2102,
	"zephyr-clt":     2103,
	"zephyr-hm":      2104,
}

// resolveICMPTypeToken resolves a single `from icmp-type` token to its numeric
// type value. A numeric token in 0..255 passes through; a symbolic name is
// looked up in the family-appropriate Junos name table (ICMPv6 for `inet6`,
// ICMPv4 otherwise). Returns ok=false for anything unrecognized so the caller
// can FAIL CLOSED rather than silently drop the constraint.
func resolveICMPTypeToken(tok, family string) (int, bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(tok); err == nil {
		if n >= 0 && n <= 255 {
			return n, true
		}
		return 0, false
	}
	key := strings.ToLower(tok)
	if family == "inet6" {
		if n, ok := icmp6TypeNames[key]; ok {
			return n, true
		}
		return 0, false
	}
	if n, ok := icmpTypeNames[key]; ok {
		return n, true
	}
	return 0, false
}

// resolveICMPCodeToken resolves a single `from icmp-code` token. ICMP code
// names in Junos are TYPE-dependent and rarely used; rather than hardcode a
// partial / ambiguous code-name table we accept a numeric 0..255 and FAIL
// CLOSED (ok=false) on any symbolic code, so the strict gate rejects it with a
// clear "use a numeric code" error instead of silently dropping the constraint.
func resolveICMPCodeToken(tok string) (int, bool) {
	tok = strings.TrimSpace(tok)
	if n, err := strconv.Atoi(tok); err == nil && n >= 0 && n <= 255 {
		return n, true
	}
	return 0, false
}

// resolveSinglePort resolves one port token (a number 1..65535 or a Junos
// service name) to its numeric value. Port 0 is rejected (Junos filter ports
// are 1..65535 and the dataplane port parser rejects 0).
func resolveSinglePort(s string) (uint16, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	// parseCanonicalPort (not strconv.Atoi) so a non-canonical signed token
	// ("+80") is treated as unresolved rather than silently coerced to 80 and
	// shipped as a numeric port the operator never wrote (#3606).
	if n, err := parseCanonicalPort(s); err == nil {
		if n >= 1 && n <= 65535 {
			return uint16(n), true
		}
		return 0, false
	}
	if p, ok := junosServicePorts[strings.ToLower(s)]; ok {
		return p, true
	}
	return 0, false
}

// resolveFilterPort resolves a single `from {source,destination}-port[-except]`
// spec — a number, a Junos service name, or a `lo-hi` range of either — to a
// canonical NUMERIC string ("53" or "1024-65535"). Returns ok=false for an
// unrecognized name or a malformed range so the caller can FAIL CLOSED.
func resolveFilterPort(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	// Whole-spec service name first — covers hyphenated catalog names
	// (ftp-data, kerberos-sec, tacacs-ds) that a range-split on '-' would
	// otherwise mangle into a malformed low-high range and reject. Mirrors
	// resolveAppPort (compiler_applications.go, #3340). A two-token range
	// such as http-https is not a catalog name, so it falls through to the
	// range path below and still resolves.
	if p, ok := junosServicePorts[strings.ToLower(spec)]; ok {
		return strconv.Itoa(int(p)), true
	}
	if i := strings.IndexByte(spec, '-'); i > 0 && i < len(spec)-1 {
		lo, ok1 := resolveSinglePort(spec[:i])
		hi, ok2 := resolveSinglePort(spec[i+1:])
		if !ok1 || !ok2 || lo > hi {
			return "", false
		}
		return fmt.Sprintf("%d-%d", lo, hi), true
	}
	p, ok := resolveSinglePort(spec)
	if !ok {
		return "", false
	}
	return strconv.Itoa(int(p)), true
}

// ResolveFilterPortRange resolves a single `from {source,destination}-port`
// spec — a number, a Junos service name, or a `lo-hi` range of either — to a
// numeric [lo,hi] port range for the kernel filter-based-forwarding ip-rule
// mirror (pkg/routing, #3730). It reuses resolveFilterPort (the SSOT that the
// compile path uses) so the kernel FBF mirror and the userspace filter path
// resolve named/ranged ports identically. A single port yields lo==hi.
//
// ok=false for an unrecognized name or a malformed range so the caller FAILS
// CLOSED (drops the steering rule + degrades) rather than widening the match.
func ResolveFilterPortRange(spec string) (lo, hi uint16, ok bool) {
	canon, ok := resolveFilterPort(spec)
	if !ok {
		return 0, 0, false
	}
	if i := strings.IndexByte(canon, '-'); i > 0 {
		l, e1 := strconv.Atoi(canon[:i])
		h, e2 := strconv.Atoi(canon[i+1:])
		if e1 != nil || e2 != nil || l < 0 || h > 65535 || l > h {
			return 0, 0, false
		}
		return uint16(l), uint16(h), true
	}
	n, err := strconv.Atoi(canon)
	if err != nil || n < 0 || n > 65535 {
		return 0, 0, false
	}
	return uint16(n), uint16(n), true
}

// resolveFilterPortTokens resolves every port token in a `from` port list to a
// canonical numeric spec. A recognized token is rewritten to its numeric form
// so the dataplane only ever sees numerics. An UNrecognized token is kept
// verbatim (so the dataplane's constrained-but-unparseable guard fails CLOSED
// rather than fail-open) AND recorded on term.UnknownPorts so the strict commit
// gate can reject it with a clear error. Empty placeholder tokens are skipped.
func resolveFilterPortTokens(in []string, term *FirewallFilterTerm) []string {
	out := make([]string, 0, len(in))
	for _, tok := range in {
		if strings.TrimSpace(tok) == "" {
			continue
		}
		if num, ok := resolveFilterPort(tok); ok {
			out = append(out, num)
		} else {
			out = append(out, tok)
			term.UnknownPorts = append(term.UnknownPorts, tok)
		}
	}
	return out
}

// recordFilterAddrTokens records every literal firewall-filter address token
// that the shared classifier cannot represent on term.UnknownAddresses (#6463)
// — malformed IP/CIDR text and zone-scoped literals (`%zone`) are both
// unrepresentable by the Rust dataplane. This is the deferred-reject channel
// mirroring term.UnknownPorts (#3205). The token is kept VERBATIM in the
// term's address list (the caller appends the values unconditionally), so the
// compiled term is unchanged from the pre-#6463 shape; the record exists so
// the snapshot builder can set the AddressUnrepresentable wire marker on the
// tolerant load / peer-sync path — the Rust parse_address drops such a token
// per-token, and a PARTIALLY-malformed list would otherwise silently narrow a
// discard/reject term to only the surviving prefixes (fail-open via fall-through
// to the implicit accept). `any` and the empty string are NO-CONSTRAINT
// placeholders (the matcher's addr_is_real / parse_address drop them); they are
// NOT malformed and are not recorded — exactly the skip the strict gate
// (validateFilterAddressLiteralsStrict) applies before classifying. The
// classifier (classifyFilterAddrFamily) is the single source of truth shared
// with that gate, so "recorded here" and "rejected at strict commit" can never
// drift apart.
func recordFilterAddrTokens(term *FirewallFilterTerm, values []string) {
	for _, v := range values {
		if v == "" || v == "any" {
			continue
		}
		if _, ok := classifyFilterAddrFamily(v); !ok {
			term.UnknownAddresses = append(term.UnknownAddresses, v)
		}
	}
}
