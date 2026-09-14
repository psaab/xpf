// render_validate.go holds the render-side value-sanitization and
// validation belt: it keeps a leniently-loaded / peer-synced / rolled-back
// malformed value (router-id, cluster-id, BGP origin, or a free-text
// field carrying an embedded newline) out of the generated frr.conf so a
// single bad token can neither inject commands nor fail the whole managed
// frr-reload. Commit-time validation stays strict in pkg/config; this is
// defense-in-depth for the tolerant load / no-brick paths.
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - sanitizeFRRValue
//   - validRouterID, validClusterID, validBGPOrigin
package frr

import (
	"net"
	"net/netip"
	"strconv"
)

// sanitizeFRRValue strips ASCII control characters — the C0 set
// (0x00-0x1F, including newline) and DEL (0x7F), each replaced by a
// space — from a free-text config value (description, auth key,
// password, BGP community member, AS-path regex) before it is
// interpolated into a generated frr.conf line. Render-side belt for
// #1798 / #4097: a BGP neighbor description, auth key, community-list
// member, or as-path-access-list regex containing an embedded newline
// must not be able to inject extra frr.conf commands even if the
// commit-time validation layer were bypassed (a leniently-loaded /
// peer-synced / rolled-back stored value re-parses through the same
// lexer, which materializes a `\n` escape into a real newline byte).
// Collapsing the newline to a space keeps the whole value on the single
// rendered line, so no injected `router bgp` / `neighbor` command
// reaches the managed section. A single SPACE (0x20) is preserved: an
// FRR `bgp as-path access-list ... permit LINE` and an expanded
// `bgp community-list expanded ... permit LINE` take the regex as a
// rest-of-line token, so a space inside the regex is legitimate (unlike
// a whitespace-split auth secret, which frrTokenUnsafeIndex also rejects
// at commit).
func sanitizeFRRValue(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// validRouterID reports whether a router-id is a valid 32-bit IPv4
// dotted-quad. FRR/vtysh requires an IPv4 router-id for ALL routing
// protocols (including the IPv6 protocols OSPFv3 and BGP) and rejects
// anything else, failing the whole frr-reload. This is the render-side
// defense-in-depth for #2980: commit-time validation
// (validateRouterIDStrict, pkg/config) hard-rejects a bad router-id, but
// the tolerant load / peer-sync paths only warn (#1960 no-brick), so the
// renderer must keep a leniently-loaded malformed router-id out of frr.conf
// entirely. Empty is intentionally invalid here (the caller already gates
// on != "" and an empty value is omitted so FRR auto-derives the router-id).
func validRouterID(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// validClusterID reports whether a BGP route-reflector cluster-id is one of
// the two forms FRR/vtysh's `bgp cluster-id <A.B.C.D | (1-4294967295)>` grammar
// accepts: an IPv4 dotted-quad or a 32-bit unsigned integer in 1..4294967295.
// Render-side defense-in-depth for #4919: `protocols bgp cluster-id` is stored
// verbatim, so a tolerant-load / peer-synced / rolled-back config may carry a
// malformed value (e.g. `not.an.ip`, an IPv6 literal, or an embedded-newline
// injection). FRR rejects anything else and fails the whole frr-reload, so the
// renderer must keep a leniently-loaded bad cluster-id out of frr.conf
// entirely. Commit / commit-check stay strict (config.ValidateBGPClusterID).
// Mirrors validRouterID; the accept set matches ValidateBGPClusterID exactly.
func validClusterID(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return err == nil && v >= 1
}

// validFRRRoutePrefix reports whether a static / generate-route destination is
// renderable as a single FRR `ip route <prefix>` operand (#6795).
//
// Both a CIDR prefix and a bare address are accepted. FRR's own grammar wants a
// mask, but this tree stores the destination as a RAW STRING from the parser and
// a host route may reach here maskless — rejecting a form that commits today
// would drop a working route, and in routing config a dropped route is an
// outage. The belt exists to keep UNRENDERABLE operands out of frr.conf, not to
// re-litigate the accepted grammar.
//
// netip parsing is the whole check: it rejects any string containing whitespace
// or trailing text, so a value that parses is guaranteed to be one token and to
// be something FRR's parser can consume. A malformed destination that reaches
// frr.conf fails the WHOLE frr-reload (one vtysh add-batch exits non-zero on any
// CMD_WARNING_CONFIG_FAILED), taking every other route on the box with it — the
// same blast radius #2980 documents for a bad router-id.
func validFRRRoutePrefix(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// validFRRNextHopAddress reports whether a next-hop is renderable as a single
// FRR gateway operand (#6795). Bare address only: FRR's `ip route <p> <gw>`
// takes an address, and a prefix there is a grammar error that fails the
// frr-reload.
func validFRRNextHopAddress(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// validFRRInterfaceOperand reports whether an interface name is renderable as a
// single FRR token (#6795).
//
// Kernel interface names cannot contain whitespace or '/', but the value
// reaching the renderer is not always a kernel name: it is assembled from
// config, RETH resolution and a `.vlan` suffix, and on the tolerant load /
// peer-sync path it is whatever the config carried. A name with an embedded
// space would split `ip route <p> <gw> <ifname>` into an extra operand and
// change what FRR installs — or, with a newline, add a statement outright.
//
// Deliberately a token test rather than a name-charset test: over-restricting
// interface names would drop working routes on any naming scheme this tree has
// not seen, and the defect is about token COUNT.
func validFRRInterfaceOperand(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// validBGPNeighborAddress reports whether a BGP neighbor identity occupies
// exactly ONE FRR token.
//
// Render-side fail-closed belt for #6796. `n.Address` is rendered RAW at 24
// sites — unlike every other operand around it (update-source, description and
// password are all sanitized) — so a value carrying whitespace SPANS MULTIPLE
// FRR TOKENS: an identity of `1.1.1.1 remote-as 65000\n neighbor 2.2.2.2`
// renders a valid first statement followed by an attacker-chosen second one,
// which is arbitrary FRR configuration injected through a config value.
//
// The test is single-token-ness, deliberately NOT "is an IP". FRR's grammar is
// `neighbor <A.B.C.D|X:X::X:X|WORD>`, and this tree already commits configs
// whose neighbor is a hostname (a pre-existing parser test peers with
// `peer.example.com`). Requiring an IP literal would reject configs that work
// today — over-rejection in routing config is an outage, and the defect here is
// about token COUNT, not address form.
//
// sanitizeFRRValue is deliberately not the tool, and this is the reason: it
// maps control bytes to a SPACE, and space is exactly the separator FRR
// tokenizes on. Replacing a newline with a space still splits the token, and a
// plain embedded space is not a control byte at all, so it passes through
// untouched. A sanitizer whose replacement character is the sink's delimiter
// cannot make a value safe for that sink.
//
// Commit / commit-check stay strict (validateBGPNeighborAddressStrict); this is
// the #1960 belt for the tolerant load / peer-sync / rollback paths, which only
// warn.
func validBGPNeighborAddress(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		// Space, tab, CR, LF, form feed, vertical tab — every byte FRR's lexer
		// treats as a separator — plus the remaining control bytes and DEL,
		// which have no legitimate place in an identity and would corrupt the
		// rendered line.
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// validBGPOrigin reports whether a route-map `then origin` value is one of the
// three tokens FRR's `set origin <egp|igp|incomplete>` grammar accepts.
// Render-side belt for #4919: `then origin` is stored verbatim and was only
// control-char sanitized (#4498), so a non-control typo (`igpp`) or a
// leniently-loaded / peer-synced bad value reached FRR and failed the route-map
// grammar, stalling the reload. Skipping an invalid origin (fail-closed) keeps
// it out of frr.conf; commit-check stays strict (schema ValidateEnum).
func validBGPOrigin(s string) bool {
	switch s {
	case "igp", "egp", "incomplete":
		return true
	}
	return false
}
