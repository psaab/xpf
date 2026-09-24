package config

import (
	"fmt"
	"net"
)

// SNMP community `clients` source-IP restriction (#4289).
//
// Junos `snmp community <c> clients { <prefix> [restrict]; ... }` scopes a
// community so it is answered only from the listed source prefixes. xpf parsed
// only `authorization` and served every source, so a community scoped to a
// management subnet was queryable from anywhere — the restriction was silently
// ignored (a security fail-open). The compiler now captures the allowlist
// (parseSNMPClients) and the SNMP agent enforces it before serving a v2c
// request (AllowsSource).
//
// #4711: the `clients` prefixes are parsed ONCE at config-compile time into
// clientNets (a []compiledSNMPClient) rather than re-parsed on every incoming
// v2c packet. AllowsSource then does an allocation-free longest-prefix match
// over the precomputed *net.IPNet set. compileClientNets runs during compilation
// (compiler_system.go), before the config is published to the SNMP agent, so the
// cache is set with no concurrent readers; AllowsSource never mutates it.

// compiledSNMPClient is a `clients` allowlist entry with its prefix already
// parsed into a *net.IPNet (#4711). ones is the prefix length (net.IPMask
// Size), cached so the longest-prefix comparison in AllowsSource needs no
// per-packet Mask.Size() call. restrict mirrors SNMPClient.Restrict.
type compiledSNMPClient struct {
	net      *net.IPNet
	ones     int
	restrict bool
}

// compileClientNets pre-parses a `clients` allowlist into the allocation-free
// match set consumed by AllowsSource (#4711). An unparseable prefix is skipped
// (inert), exactly as the former per-call parse skipped it — never a silent
// allow-all. Returns nil for an empty allowlist; a non-empty allowlist whose
// entries are all unparseable yields a non-nil empty slice, so a populated but
// fully-inert list still default-denies (and is distinguishable from "not yet
// compiled").
func compileClientNets(clients []SNMPClient) []compiledSNMPClient {
	if len(clients) == 0 {
		return nil
	}
	out := make([]compiledSNMPClient, 0, len(clients))
	for _, cl := range clients {
		_, ipnet, err := parseClientPrefix(cl.Prefix)
		if err != nil || ipnet == nil {
			continue // an unparseable prefix is inert, never a silent allow-all
		}
		ones, _ := ipnet.Mask.Size()
		out = append(out, compiledSNMPClient{net: ipnet, ones: ones, restrict: cl.Restrict})
	}
	return out
}

// AllowsSource reports whether a v2c query from srcIP may be served under this
// community. Semantics (Junos):
//
//   - No `clients` configured (empty allowlist): allow all (the default).
//   - Otherwise longest-prefix match wins: the most-specific entry containing
//     srcIP decides — `restrict` denies, a plain entry allows. IPv4 and IPv6
//     are distinct families: a 4-byte IPv4 source matches only IPv4 prefixes;
//     a 16-byte IPv6 source matches only IPv6 prefixes, including mapped IPv6.
//     Callers must represent IPv4 sources in 4-byte form; a 16-byte mapped
//     source is IPv6 here (the UDP serving path normalizes kernel-mapped IPv4).
//   - `clients` configured but srcIP matches no entry: deny (an allowlist that
//     lists some sources implicitly excludes the rest).

// A nil srcIP (e.g. a non-IP transport / test path with no address) is allowed
// so enforcement never blocks a request whose source cannot be determined; the
// real serving path always supplies the UDP source address.
//
// #4711: the match runs against clientNets, the prefixes parsed once at compile
// time. A community built directly (e.g. a unit test) that never went through
// the compiler has a nil clientNets; AllowsSource then parses on the fly for the
// same decision — this reads only local state, so it stays race-free under
// concurrent serving, and the real serving path always has clientNets populated.
func (c *SNMPCommunity) AllowsSource(srcIP net.IP) bool {
	if c == nil {
		return false
	}
	// #9416: "no restriction was authored" is `Clients` empty AND `clientNets`
	// nil — not `Clients` empty alone.
	//
	// The two came apart when a community could be QUARANTINED with an empty
	// `Clients`. #5833's quarantine overrides only `clientNets` (deliberately:
	// the operator's config text stays intact for display and hashing), and it
	// worked because a malformed INLINE token still leaves that token in
	// `Clients`, so the length check below never fired. An unresolvable
	// `client-list-name` has no such residue: the reference resolves to nothing,
	// `Clients` stays empty, and the community was returning ALLOW-ALL through
	// this line while carrying an explicit deny-all match set two fields over.
	// The quarantine was armed and unreachable.
	//
	// `clientNets` is the exact predicate for "a restriction was authored":
	// compileClientNets returns nil ONLY for an empty allowlist, and returns a
	// non-nil (possibly empty) slice for a populated one — a distinction its own
	// doc comment already calls out, so that a populated-but-fully-inert list
	// default-denies rather than opening. A directly-constructed community that
	// never went through the compiler has clientNets nil and is unaffected.
	if len(c.Clients) == 0 && c.clientNets == nil {
		return true // no restriction — allow-all (Junos default)
	}
	if srcIP == nil {
		return true
	}
	nets := c.clientNets
	if nets == nil {
		// Not compiled (directly-constructed community) — parse on the fly.
		// Same decision, just not the precomputed fast path.
		nets = compileClientNets(c.Clients)
	}
	bestBits := -1
	bestAllow := false
	for _, cn := range nets {
		if !clientPrefixContains(cn.net, srcIP) {
			continue
		}
		switch {
		case cn.ones > bestBits:
			bestBits = cn.ones
			bestAllow = !cn.restrict
		case cn.ones == bestBits && cn.restrict:
			// Equal-length tie: deny wins (C179-049). A `restrict` entry at
			// the same prefix length overrides an allow regardless of the
			// insertion order the two self-contradictory prefixes appeared in
			// — otherwise `10.0.0.0/24` before `10.0.0.0/24 restrict` would
			// leak the allow, while the reverse order denied.
			bestAllow = false
		}
	}
	if bestBits < 0 {
		return false // clients configured, no match: default-deny
	}
	return bestAllow
}

// clientPrefixContains applies the allowlist's address-family boundary before
// comparing bytes. net.IPNet.Contains calls To4 on every source, which folds a
// 16-byte IPv4-mapped IPv6 address into IPv4 and can make it match an IPv4
// prefix. Preserve the representation's family instead: only 4-byte sources
// can match IPv4 prefixes, and only 16-byte sources can match IPv6 prefixes.
//
// IPv6 matching uses the mask bytes directly because net.IPNet.Contains would
// fold mapped IPv6 sources to IPv4 even when the configured prefix is IPv6.
func clientPrefixContains(prefix *net.IPNet, srcIP net.IP) bool {
	if prefix == nil {
		return false
	}
	switch len(prefix.Mask) {
	case net.IPv4len:
		return len(srcIP) == net.IPv4len && prefix.Contains(srcIP)
	case net.IPv6len:
		if len(srcIP) != net.IPv6len || len(prefix.IP) != net.IPv6len {
			return false
		}
		for i, mask := range prefix.Mask {
			if srcIP[i]&mask != prefix.IP[i]&mask {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// parseClientPrefix parses a `clients` entry as either a CIDR prefix
// (10.0.0.0/24, 2001:db8::/32) or a bare address (192.168.1.5, ::1), the bare
// form treated as a host route (/32 or /128).
func parseClientPrefix(s string) (net.IP, *net.IPNet, error) {
	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		return ip, ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, nil, &net.ParseError{Type: "SNMP client prefix", Text: s}
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// parseSNMPClients extracts the `clients` allowlist from a community's `clients`
// node, across both parser AST shapes (the #2419 dual-shape class). Each entry
// is a `<prefix> [restrict]` group: a token equal to "restrict" attaches to the
// prefix immediately preceding it (modeled on firewallPrefixListRefs's
// `<name> [except]` handling).
//
//   - hierarchical block   `clients { 10.0.0.0/24; 0.0.0.0/0 restrict; }`
//     → one child node per entry (child.Keys=["10.0.0.0/24"] / ["0.0.0.0/0","restrict"])
//   - flat set / bracket   `clients 10.0.0.0/24` / `clients [ a b ]`
//     → tokens on node.Keys[1:]
func parseSNMPClients(node *Node) []SNMPClient {
	var out []SNMPClient
	appendTokens := func(tokens []string) {
		for _, t := range tokens {
			if t == "" {
				continue
			}
			if t == "restrict" && len(out) > 0 {
				out[len(out)-1].Restrict = true
				continue
			}
			// #5898: a leading/orphan `restrict` (t == "restrict" with no
			// preceding prefix to modify — an invalid-Junos-ordering typo like
			// `clients restrict 0.0.0.0/0`) previously fell into the branch above
			// and was SILENTLY DROPPED, leaving the following prefix a plain
			// ALLOW — an SNMP community answerable from every source, with nothing
			// recorded so #5833's quarantine never engaged. Do NOT drop it: record
			// it AS a client entry. "restrict" is not a valid IP/CIDR, so
			// validateSNMPClients flags it MALFORMED — strict commit hard-rejects
			// it (naming the token) and the lenient / peer-sync path QUARANTINES
			// the community to deny-all (snmpQuarantineClientNets) — fail-closed,
			// on both paths (the bug was identical on both). A well-formed
			// `<prefix> restrict` (len(out) > 0) still attaches above, unchanged.
			out = append(out, SNMPClient{Prefix: t})
		}
	}
	appendTokens(node.Keys[1:])
	for _, ch := range node.Children {
		appendTokens(ch.Keys)
	}
	return out
}

// validateSNMPClients (#4834) rejects a `clients` allowlist entry whose
// Prefix does not parse as a CIDR/IP prefix (parseClientPrefix).
//
// A mistyped *prefix* is already fail-closed on its own: compileClientNets
// silently drops the unparseable entry, which only ever shrinks the
// allowlist. But parseSNMPClients treats ANY token that is not the exact
// literal "restrict" as a new prefix entry — so a mistyped "restrict"
// keyword (e.g. "restric") does not attach to the prefix immediately
// before it and instead becomes its OWN unparseable entry. That silently
// detaches "restrict" from a broad prefix: `0.0.0.0/0 restrict` (a Junos
// deny-all-except idiom) degrades to a plain `0.0.0.0/0` allow, and the
// community becomes answerable from any source with no commit warning —
// the exact fail-open class #4289/#4711 set out to prevent, just reached
// via a different typo.
//
// Rejecting every unparseable Prefix at commit time closes this: the typo
// is caught before it can produce a silent allow-all, and a genuine
// prefix typo now also gets a clear error instead of a silently-shrunk
// allowlist. Strict (commit / commit-check): hard-reject, naming the bad
// token. Lenient (load / peer-sync): warn so an already-persisted config
// an older binary accepted still boots (#1960 fail-closed-on-load class).
//
// #5833: on the LENIENT path the caller must NOT keep the surviving broad
// allow live. Dropping the malformed token and compiling the rest of the
// allowlist normally is FAIL-OPEN: `0.0.0.0/0 restric` degrades to a plain
// `0.0.0.0/0` allow, so on restart/upgrade/peer-sync the community becomes
// answerable from every source — a warning does not make that safe. The
// second return value reports whether ANY entry was malformed so the caller
// (compileSNMP) can QUARANTINE the affected community to deny-all
// (snmpQuarantineClientNets) instead. The warning is preserved either way.
//
// The message never includes the community NAME (a secret, per the
// snmpInertKnobWarnings convention) — only the offending token, which is
// an IP/CIDR literal or a keyword typo, not a credential.
func validateSNMPClients(clients []SNMPClient, lenient bool) (warnings []string, malformed bool, err error) {
	for _, cl := range clients {
		if _, _, perr := parseClientPrefix(cl.Prefix); perr == nil {
			continue
		}
		malformed = true
		msg := fmt.Sprintf(
			"snmp community clients entry %q is not a valid IP/CIDR prefix "+
				"(if this was meant to be the \"restrict\" keyword, check for a "+
				"typo — a malformed token here can silently detach \"restrict\" "+
				"from the preceding prefix, turning a deny-except entry into an "+
				"unrestricted allow)",
			cl.Prefix)
		if lenient {
			warnings = append(warnings, msg+" (the affected community is quarantined to deny-all until the typo is fixed)")
			continue
		}
		return nil, true, fmt.Errorf("%s", msg)
	}
	return warnings, malformed, nil
}

// snmpQuarantineClientNets returns a fail-CLOSED SNMP client match set: an
// explicit `restrict` on all IPv4 (0.0.0.0/0) and all IPv6 (::/0) sources, so
// SNMPCommunity.AllowsSource denies every query regardless of source family.
//
// It is installed on a community whose `clients` allowlist carried a MALFORMED
// token on the tolerant load / peer-sync path (#5833). The strict commit path
// rejects such a config outright; the lenient path must still boot (#1960), but
// silently dropping the bad token and keeping the surviving broad allow is
// fail-OPEN (the `restrict` typo turns `0.0.0.0/0 restrict` into an
// unrestricted allow answerable from every source). Quarantining to deny-all
// makes the lenient path fail CLOSED for the affected community while the rest
// of the config loads, until the operator fixes the typo.
//
// This overrides only clientNets (the derived enforcement cache), not
// comm.Clients (the config surface marshaled to the API / hashed by the SNMP
// reconcile): the operator's config text is preserved for display and
// change-detection; only runtime enforcement is forced closed.
func snmpQuarantineClientNets() []compiledSNMPClient {
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("::/0")
	return []compiledSNMPClient{
		{net: v4, ones: 0, restrict: true},
		{net: v6, ones: 0, restrict: true},
	}
}
