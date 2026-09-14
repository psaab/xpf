package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateBGPHoldTime accepts a BGP hold-time in seconds: 0, or 3..65535.
// FRR (and RFC 4271 §4.2 / §10) require the hold-time to be either 0
// (hold timer disabled) or at least 3 seconds — the keepalive interval is
// hold-time/3, so a hold-time of 1 or 2 yields a sub-second/zero keepalive
// that FRR's `neighbor X timers <keepalive> <hold>` command REJECTS, and a
// rejected line fails the WHOLE frr-reload (a single `vtysh -f` add-batch
// exits non-zero on any CMD_WARNING_CONFIG_FAILED) — one bad leaf takes
// down every routing change on that reload. The renderer treats 0 as "unset"
// via its `> 0` gate (no `timers` line), an accepted documented tradeoff, so
// 0 is permitted here; 1 and 2 are the values that must be rejected at commit
// before they can reach frr-reload. Upper bound is the 16-bit on-wire max.
func ValidateBGPHoldTime(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected integer)")
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %q", raw)
	}
	if v != 0 && (v < 3 || v > 65535) {
		return fmt.Errorf("BGP hold-time must be 0 or 3..65535 seconds (got %d); FRR rejects 1/2 and a rejected timers line fails the whole reload", v)
	}
	return nil
}

// routeFilterMatchTypes are the match-type keywords accepted in the
// SECOND slot of a `from route-filter <prefix> <match-type>` node. The
// schema node is args:2 and uses a POSITION-AWARE key validator
// (ValidateRouteFilterArgPositional, #5576): arg 0 is the prefix slot
// (must be a CIDR) and arg 1 is the match-type slot (must be one of
// these keywords). A match-type keyword is NOT accepted in the prefix
// slot — that was the #5576 silent-false-deny bug.
//
// exact/longer/orlonger/upto/prefix-length-range are the rendered
// match-types (pkg/frr policy_render.go). `through` is ADMITTED as a
// grammar token here but REJECTED at commit by
// validateRouteFilterMatchTypesStrict (#2525): FRR prefix-lists express
// only length ranges (ge/le) and cannot represent the two-prefix
// containment path of Junos `through`. It stays in this set so the
// commit-check reaches the semantic gate (which emits an actionable
// "unsupported match-type" error) rather than failing earlier with a
// generic "not a valid prefix" message. `prefix-length-range` is
// admitted AND rendered (`ge low le high`); its /low-/high bounds are
// semantically validated by validateRouteFilterMatchTypesStrict.
var routeFilterMatchTypes = map[string]bool{
	"exact":               true,
	"longer":              true,
	"orlonger":            true,
	"upto":                true,
	"prefix-length-range": true,
	"through":             true,
}

// ValidateRouteFilterArgPositional is the #2105 + #5576 POSITION-AWARE
// commit-check validator for a `policy-options policy-statement <p> term
// <t> from route-filter <prefix> <match-type>` identity arg token. The
// node is args:2, so the walker (schema_walk.go) calls this once for the
// prefix token (argIdx 0) and once for the match-type token (argIdx 1).
// The `upto /N` length token lands as a CHILD of the route-filter node
// (or a fourth packed key past the args:2 span), never in the validated
// Keys[1:3], so it does not reach here.
//
//   - argIdx 0 (prefix slot): MUST be a syntactically valid CIDR (v4 or
//     v6 — route-filter is family-agnostic). A match-type keyword here is
//     REJECTED: `route-filter longer exact` puts `longer` in the CIDR
//     slot, which the FRR renderer's malformed-prefix belt then swallows
//     into a match-none policy (a silent false-deny). A malformed prefix
//     (no "/", non-numeric mask, out-of-range mask) is likewise rejected
//     so it never reaches the renderer as an FRR-invalid prefix-list line.
//
//   - argIdx 1 (match-type slot): MUST be a supported match-type keyword
//     (routeFilterMatchTypes). A CIDR or any other token here is REJECTED.
//
// The #5576 fix is the per-position split: the prior position-AGNOSTIC
// validator accepted the UNION (a CIDR OR a keyword) in EITHER slot, so a
// swapped or keyword-in-prefix-slot form committed clean and rendered a
// match-none policy.
//
// Strictness is automatic: SchemaValidate is strict on the operator
// commit / commit-check path and lenient (warn, not fail) on Store.Load
// / SyncApply (the #1960 lenient-downgrade-on-load doctrine), so a
// prefix persisted by an older binary never blackouts boot. The renderer
// carries a belt-and-suspenders skip for any malformed prefix that
// reaches it via that lenient path.
func ValidateRouteFilterArgPositional(argIdx int, raw string, _ *Config) error {
	tok := strings.TrimSpace(raw)
	if argIdx == 0 {
		// Prefix slot — a CIDR, never a match-type keyword.
		if tok == "" {
			return fmt.Errorf("missing route-filter prefix (expected CIDR, e.g. 10.0.0.0/24)")
		}
		if routeFilterMatchTypes[tok] {
			return fmt.Errorf("match-type keyword %q in the prefix slot; the FIRST route-filter token must be a CIDR (e.g. 10.0.0.0/24 or 2001:db8::/32) and the match-type must follow it (e.g. `route-filter 10.0.0.0/24 %s`)", tok, tok)
		}
		// Family-agnostic CIDR. parseCIDRStrict requires a /prefix-length
		// and upgrades the common operator mistakes (bare IP, garbage) to
		// targeted messages, matching the ValidateIPv4CIDR/ValidateIPv6CIDR
		// convention; the returned IP is discarded because both families are
		// valid here. Surface parseCIDRStrict's targeted message (e.g.
		// "missing /prefix-length") so the commit-check failure is actionable.
		if _, err := parseCIDRStrict(tok, "10.0.0.0/24"); err != nil {
			return fmt.Errorf("not a valid route-filter prefix (expected a CIDR, e.g. 10.0.0.0/24 or 2001:db8::/32): %v", err)
		}
		return nil
	}
	// Match-type slot (argIdx >= 1) — a supported keyword, never a CIDR.
	// The walker only reaches this when a token is actually present (the
	// args:2 span caps at len(Keys)), so an empty tok cannot occur here.
	if routeFilterMatchTypes[tok] {
		return nil
	}
	return fmt.Errorf("not a valid route-filter match-type %q (expected one of: exact, longer, orlonger, upto, prefix-length-range, through)", tok)
}

// ValidateRouteDestination accepts a static-route destination prefix: a
// family-agnostic CIDR (v4 or v6) with an explicit /prefix-length. Used for
// the `routing-options static route <destination>` identity arg (#2448):
// the destination feeds net.ParseCIDR in the FRR renderer
// (pkg/frr/config_render.go generateStaticRoute) and net/ipnet parse in the
// Rust FIB builder (userspace-dp forwarding_build/fib.rs populate_routes).
// A destination that parses as neither IPv4 nor IPv6 is SILENTLY dropped by
// both consumers today — the route commits cleanly but never installs. The
// default routes 0.0.0.0/0 and ::/0 parse via net.ParseCIDR and are
// accepted; a bare IP without a length, or outright garbage, is rejected
// with a targeted message. route is family-agnostic so both families pass.
func ValidateRouteDestination(raw string, _ *Config) error {
	// #9820: validate what is emitted. The compiler stores the RAW
	// destination and the renderer drops a padded one silently (netip
	// shape belt), while parseCIDRStrict validates the TRIMMED form —
	// so a quoted-padded destination would commit clean and install
	// nothing. Padding IS authorable through ordinary ingress (the lexer
	// preserves quoted-string contents verbatim). Newlines need no arm
	// here: the #1798 prewalk already rejects control characters in any
	// key; the real class is spaces, which previously functioned as
	// harmless separators. Scoped to this validator (not the shared
	// parseCIDRStrict): other CIDR consumers are out of #9820's scope.
	if raw != strings.TrimSpace(raw) {
		return fmt.Errorf("not a valid route destination (leading or trailing whitespace is not allowed; use a bare CIDR, e.g. 10.0.0.0/24 or 2001:db8::/32)")
	}
	// parseCIDRStrict requires a /prefix-length and upgrades the two common
	// operator mistakes (bare IP, garbage) to targeted messages. The returned
	// IP is discarded because both v4 and v6 destinations are valid here.
	if _, err := parseCIDRStrict(raw, "10.0.0.0/24"); err != nil {
		return fmt.Errorf("not a valid route destination (expected a CIDR, e.g. 10.0.0.0/24 or 2001:db8::/32): %v", err)
	}
	return nil
}

// ValidateStaticNextHop accepts a static-route next-hop VALUE: a bare IPv4
// or IPv6 address, the Rust-FIB `ip@interface` / `@interface` spec, or a
// bare interface name. It rejects values that are genuinely malformed —
// neither a usable IP nor a plausible interface name — so an operator typo
// fails loud at commit instead of installing a blackhole (#2448).
//
// Why each accepted form is real:
//   - a bare IP (192.168.1.1, 2001:db8::1) is the common gateway form; the
//     FRR renderer emits it verbatim (config_render.go) and the Rust FIB
//     parses it (parse_route_next_hop[_v6]).
//   - `ip@iface` / `@iface` is the Rust FIB interface-scoped form
//     (forwarding_build/fib.rs split_once('@')); the IP part, when present,
//     must itself parse, else the spec silently degrades to interface-only.
//   - a bare interface name (ge-0-0-0.0, reth0.50, eth1) is a valid Junos
//     next-hop and renders as an interface route in FRR (config_render.go
//     `case ifName != ""`).
//
// The malformed cases rejected: a botched IP literal (1.2.3.999,
// 2001:db8::garbage), an `ip@iface` whose IP part does not parse
// (notanip@eth0 — silently becomes interface-only), and any value that is
// neither a valid IP nor a syntactically plausible interface name. The
// interface-name test requires at least one ASCII letter so a numeric-only
// dotted value (a botched IPv4) cannot masquerade as an interface, and uses
// the [A-Za-z0-9._-] charset interface names actually use — which excludes
// ':' so a botched IPv6 literal is rejected rather than mistaken for a name.
func ValidateStaticNextHop(raw string, _ *Config) error {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return fmt.Errorf("missing next-hop (expected an IP address, e.g. 192.168.1.1 or 2001:db8::1, or an interface name)")
	}
	// #9820: validate what is emitted (see ValidateRouteDestination).
	// The compiler stores the RAW next-hop; the renderer drops a padded
	// one silently and the family gate cannot classify it — so a
	// quoted-padded next-hop would commit clean and install nothing.
	// Control characters are already rejected by the #1798 prewalk; the
	// real class is spaces.
	if tok != raw {
		return fmt.Errorf("not a valid next-hop (leading or trailing whitespace is not allowed; use a bare IP address, ip@interface, or interface name)")
	}
	// Rust-FIB ip@interface / @interface spec.
	if ipPart, ifPart, hasAt := strings.Cut(tok, "@"); hasAt {
		if ifPart == "" {
			return fmt.Errorf("malformed next-hop %q: missing interface name after '@'", raw)
		}
		if ipPart != "" && net.ParseIP(ipPart) == nil {
			return fmt.Errorf("malformed next-hop %q: %q is not a valid IP address before '@interface'", raw, ipPart)
		}
		if !plausibleInterfaceName(ifPart) {
			return fmt.Errorf("malformed next-hop %q: %q is not a valid interface name after '@'", raw, ifPart)
		}
		return nil
	}
	if net.ParseIP(tok) != nil {
		return nil
	}
	if plausibleInterfaceName(tok) {
		return nil
	}
	return fmt.Errorf("not a valid next-hop (got %q; expected an IP address, ip@interface, or an interface name)", raw)
}

// plausibleInterfaceName reports whether s is syntactically usable as a
// next-hop interface name: the [A-Za-z0-9._-] charset that xpf/vSRX and
// kernel interface names use, with at least one ASCII letter so a
// numeric-only dotted token (a botched IPv4 like 1.2.3.999) cannot pass as
// an interface name. ':' is excluded so a malformed IPv6 literal is not
// mistaken for an interface name.
func plausibleInterfaceName(s string) bool {
	if s == "" {
		return false
	}
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			// allowed non-letter
		default:
			return false
		}
	}
	return hasLetter
}
