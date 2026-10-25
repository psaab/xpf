package config

import (
	"fmt"
	"net"
	"strings"
)

// #9493: operands pkg/frr renders straight into the managed frr.conf section
// that carried no commit-time validator. FRR's command lexer splits on
// whitespace and has no quoting, so `local-address "10.0.0.2 POISON"` rendered
// as ` neighbor 10.0.0.1 update-source 10.0.0.2 POISON` on a GREEN commit, and
// the rejected line failed the whole managed reload. Each validator here is
// attached to its leaf in schema_routing.go. SchemaValidate runs on commit and
// commit-check only, so a persisted value still boots (#1960); pkg/frr belts
// the same operands at render for that path.

// #16867: a prefix-list name that lands in an FRR YANG `list-name` leaf
// (the `ip|ipv6 prefix-list` definition and the `match ... prefix-list`
// route-map references) is additionally BOUNDED to FRR's 128-byte limit.
// Past it FRR rejects the leaf with "Unsatisfied length" but leaves a
// half-built match-condition node, and the next `show running-config` —
// the first step of every frr-reload.py run — SIGABRTs five routing
// daemons. Route-map and community-list names were measured NOT
// length-bounded by FRR, so only the prefix-list name is length-gated at
// commit. AS-path DEFINITION names are likewise unbounded, but the
// `match as-path` REFERENCE lands in the YANG `filter:access-list-name`
// leaf (length 1..128), so an overlong as-path name is still unsafe at
// its match sites. The render belt (frrName) therefore aliases EVERY
// name class over the bound, so a persisted or peer-synced long name of
// any class still renders as one bounded token at definition and
// reference sites alike.

// FRRSingleToken reports whether s can be carried as ONE token on an FRR
// config line: non-empty, with no whitespace or control byte. It is the render
// belt's predicate, exported so pkg/frr and the commit gate agree.
func FRRSingleToken(s string) bool {
	return s != "" && frrTokenUnsafeIndex(s) < 0
}

// ValidateFRRObjectName accepts a policy-statement, term, prefix-list or
// community name that FRR can render as a single token. Only whitespace and
// control bytes are refused: FRR's WORD token takes any other character, and
// narrowing it further would refuse names this product already accepts.
func ValidateFRRObjectName(raw string) error {
	if raw == "" {
		return fmt.Errorf("missing name")
	}
	if i := frrTokenUnsafeIndex(raw); i >= 0 {
		return fmt.Errorf("name %q contains whitespace or a control character at byte offset %d; "+
			"it is rendered into frr.conf as a route-map / prefix-list / community-list name, "+
			"where FRR splits it into extra arguments and rejects the line", raw, i)
	}
	if strings.Contains(raw, FRRNameEscapeMarker) {
		return fmt.Errorf("name %q contains the reserved %q marker; xpf owns that marker "+
			"for the hashed aliases it renders for names FRR cannot carry, and an operator "+
			"name in that namespace could be spelled identically to another name's alias — "+
			"FRR merges same-named objects and would silently fuse two distinct policies "+
			"(#16867) — rename the object without the reserved marker", raw, FRRNameEscapeMarker)
	}
	return nil
}

// FRRNameMaxLen is FRR's 128 cap on the YANG `list-name` leaf behind
// `ip|ipv6 prefix-list` (measured on the wire: accepted at 128 bytes,
// rejected at 129 with "Unsatisfied length"). YANG `length` counts
// CHARACTERS, not bytes; this cap is enforced in BYTES, which is the
// conservative direction — a multi-byte name that YANG would admit (128
// runes in more than 128 bytes) is refused/aliased here rather than
// risking the byte-oriented CLI/YANG path that produced the measured
// 129-byte rejection. A rendered FRR object name must never exceed
// it; the commit validator refuses a longer prefix-list name and frrName
// aliases a longer persisted or peer-synced name of any class (#16867).
const FRRNameMaxLen = 128

// FRRNameEscapeMarker is the infix every frrName alias carries
// ("<fragment>-xpfesc-<8 hex>"). The alias namespace is RESERVED: an
// operator name containing it renders unchanged (it is a fine single
// token) and could therefore be spelled identically to the alias of a
// DIFFERENT raw name — e.g. an overlong name L and the literal
// A = frrName(L) would render as one FRR object and silently merge two
// distinct policies. ValidateFRRObjectName rejects any name carrying
// the marker so a literal alias can never be committed (strict reject;
// the tolerant path warns and pkg/frr fails the apply closed), making
// the alias map injective against operator names by construction. The
// renderer (pkg/frr frrName) builds its aliases from this exact string
// so the two cannot drift.
const FRRNameEscapeMarker = "-xpfesc-"

// ValidateFRRPrefixListName is ValidateFRRObjectName plus FRR's 128-byte
// YANG `list-name` bound (#16867), attached only to the `prefix-list`
// definition leaf. Route-map and community names are not length-bounded
// by FRR and keep the unbounded ValidateFRRObjectName; as-path names
// keep it too (definitions unbounded — the 1..128 `access-list-name`
// bound on `match as-path` references is enforced by the render belt,
// which aliases every class over the bound at match sites as well).
func ValidateFRRPrefixListName(raw string) error {
	if err := ValidateFRRObjectName(raw); err != nil {
		return err
	}
	if len(raw) > FRRNameMaxLen {
		return fmt.Errorf("prefix-list name %q is %d bytes, over FRR's %d-byte list-name limit; "+
			"FRR rejects the name with \"Unsatisfied length\" yet leaves a half-built "+
			"match-condition node, and the next `show running-config` (the first step of "+
			"every frr-reload.py run) aborts the routing daemons — shorten the name to "+
			"%d bytes or fewer (#16867)", raw, len(raw), FRRNameMaxLen, FRRNameMaxLen)
	}
	return nil
}

// ValidateOSPFVirtualLinkNeighbor accepts an OSPF virtual-link neighbor router
// ID: an IPv4 dotted-quad, which is the only form FRR's `area A virtual-link
// A.B.C.D` accepts.
func ValidateOSPFVirtualLinkNeighbor(raw string) error {
	if ip := net.ParseIP(raw); ip == nil || ip.To4() == nil {
		return fmt.Errorf("virtual-link neighbor %q is not an IPv4 router ID (a dotted-quad such as 10.0.0.1)", raw)
	}
	return nil
}

// ValidISISNET reports whether s is an IS-IS NET that FRR's `net` command
// accepts: hex digits in dot-separated groups of whole octets, 8 to 20 octets in
// total (lib dotformat2buff and isis_area_net_address's length bounds).
func ValidISISNET(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	digits := 0
	for _, group := range strings.Split(s, ".") {
		if group == "" || len(group)%2 != 0 {
			return false
		}
		for i := 0; i < len(group); i++ {
			c := group[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		digits += len(group)
	}
	octets := digits / 2
	return octets >= 8 && octets <= 20
}

// ValidateISISNET is the commit-time form of ValidISISNET.
func ValidateISISNET(raw string) error {
	if !ValidISISNET(raw) {
		return fmt.Errorf("IS-IS NET %q is not a valid NET (hex octets in dot-separated groups, "+
			"8 to 20 octets, e.g. 49.0001.1921.6800.1001.00)", raw)
	}
	return nil
}

// ValidateASPathNameArg validates `policy-options as-path <name> <regex>` by
// position: the name (arg 0) is rendered as an FRR access-list name and must be
// one token. The regex (arg 1) is a rest-of-line operand FRR accepts with
// spaces, and the Junos translation gate already covers it, so it is not re-checked here.
func ValidateASPathNameArg(argIdx int, raw string) error {
	if argIdx == 0 {
		return ValidateFRRObjectName(raw)
	}
	return nil
}
