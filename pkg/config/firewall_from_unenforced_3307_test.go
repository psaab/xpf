package config

import (
	"strings"
	"testing"
)

// #3307: a firewall-filter `from` match leaf the dataplane does NOT enforce
// (ttl, source-mac-address, ip-options, fragment-offset, hop-limit, ...) passes
// the opt-in schema gate and was silently DROPPED by compileFilterFrom (no
// default arm). The term then enforced a BROADER match than authored — an
// accept over-permits (fail open), a discard/reject over-drops.
// validateFilterFromMatchStrict makes the unsupported leaf an operator-visible
// commit error instead, naming the family/filter/term/leaf.
//
// The enforced set verified against the dataplane: the compileFilterFrom switch
// cases are source-address, destination-address, source-prefix-list,
// destination-prefix-list, protocol, next-header, dscp, traffic-class,
// destination-port, source-port, destination-port-except, source-port-except,
// icmp-type, icmp-code, tcp-flags, is-fragment, flexible-match-range — each maps
// to a wire field the snapshot builder emits and the Rust matcher reads.
// next-header is the IPv6 alias for protocol (it compiles to term.Protocols), so
// it is ENFORCED and is NOT one of the rejected leaves. Everything else (ttl,
// source-mac-address, ip-options, fragment-offset, hop-limit, ...) is
// parsed-but-ignored and rejected here.
//
// FAIL-ON-REVERT: remove the compileFilterFrom `default:` arm (the silent drop)
// or the validateFilterFromMatchStrict invocation and these strict-path tests
// go RED — CompileConfig accepts the term with the dropped constraint.

// unenforcedFromLeaves are leaves NOT in the compileFilterFrom switch; each must
// be rejected at commit. The trailing value makes the flat-set token a leaf.
var unenforcedFromLeaves = []struct {
	leaf string
	cmd  string
}{
	{"ttl", "set firewall family inet filter f term t from ttl 1"},
	{"source-mac-address", "set firewall family inet filter f term t from source-mac-address 00:11:22:33:44:55"},
	{"ip-options", "set firewall family inet filter f term t from ip-options router-alert"},
	{"fragment-offset", "set firewall family inet filter f term t from fragment-offset 0"},
}

func TestFilterUnenforcedFromLeafRejected_3307(t *testing.T) {
	for _, tc := range unenforcedFromLeaves {
		t.Run(tc.leaf, func(t *testing.T) {
			tree := buildFilterTree(t,
				tc.cmd,
				"set firewall family inet filter f term t then accept",
			)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("term with unenforced `from %s` must be rejected at "+
					"commit (#3307 — the constraint would be silently dropped)", tc.leaf)
			}
			if !strings.Contains(err.Error(), tc.leaf) ||
				!strings.Contains(err.Error(), "not enforced") {
				t.Fatalf("error %q must name the unenforced leaf %q", err, tc.leaf)
			}
			if !strings.Contains(err.Error(), `filter "f"`) ||
				!strings.Contains(err.Error(), `term "t"`) ||
				!strings.Contains(err.Error(), "inet ") {
				t.Fatalf("error %q must name the offending family/filter/term", err)
			}
			// Tolerant path downgrades to a warning so a persisted/peer-synced
			// config still boots (#1960 no-brick).
			if _, lerr := CompileConfigLenient(tree); lerr != nil {
				t.Fatalf("lenient path must not hard-fail on the unenforced leaf: %v", lerr)
			}
		})
	}
}

// hop-limit under inet6 is the IPv6 analogue — the validator walks both
// families, so an unenforced inet6 `from` leaf is gated identically.
func TestFilterUnenforcedFromLeafRejectedV6_3307(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from hop-limit 1",
		"set firewall family inet6 filter f6 term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 term with unenforced `from hop-limit` must be rejected " +
			"at commit (#3307)")
	}
	if !strings.Contains(err.Error(), "hop-limit") ||
		!strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 hop-limit leaf", err)
	}
}

// A term built only from ENFORCED `from` leaves must still compile cleanly — the
// gate must not over-reject the supported match set. (`is-fragment` is
// exercised in its own term: combined with destination-port it is the
// #15258 never-match and must reject.)
func TestFilterEnforcedFromLeavesAccepted_3307(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ok term t from source-address 10.0.0.0/8",
		"set firewall family inet filter ok term t from destination-address 192.168.0.0/16",
		"set firewall family inet filter ok term t from protocol tcp",
		"set firewall family inet filter ok term t from destination-port 22",
		"set firewall family inet filter ok term t from dscp ef",
		"set firewall family inet filter ok term t then accept",
		"set firewall family inet filter ok term frags from is-fragment",
		"set firewall family inet filter ok term frags then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("term using only enforced `from` leaves must compile: %v", err)
	}
}
