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
func ValidateFRRObjectName(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing name")
	}
	if i := frrTokenUnsafeIndex(raw); i >= 0 {
		return fmt.Errorf("name %q contains whitespace or a control character at byte offset %d; "+
			"it is rendered into frr.conf as a route-map / prefix-list / community-list name, "+
			"where FRR splits it into extra arguments and rejects the line", raw, i)
	}
	return nil
}

// ValidateOSPFVirtualLinkNeighbor accepts an OSPF virtual-link neighbor router
// ID: an IPv4 dotted-quad, which is the only form FRR's `area A virtual-link
// A.B.C.D` accepts.
func ValidateOSPFVirtualLinkNeighbor(raw string, _ *Config) error {
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
func ValidateISISNET(raw string, _ *Config) error {
	if !ValidISISNET(raw) {
		return fmt.Errorf("IS-IS NET %q is not a valid NET (hex octets in dot-separated groups, "+
			"8 to 20 octets, e.g. 49.0001.1921.6800.1001.00)", raw)
	}
	return nil
}

// ValidateASPathNameArg validates `policy-options as-path <name> <regex>` by
// position: the name (arg 0) is rendered as an FRR access-list name and must be
// one token. The regex (arg 1) is a rest-of-line operand FRR accepts with
// spaces, and ValidASPathRegex already gates it, so it is not re-checked here.
func ValidateASPathNameArg(argIdx int, raw string, cfg *Config) error {
	if argIdx == 0 {
		return ValidateFRRObjectName(raw, cfg)
	}
	return nil
}
