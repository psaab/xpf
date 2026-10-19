package config

import (
	"strings"
	"testing"
)

// #15045 (A05-01): the #3723 icmp-type/code cross-field arm classified a
// protocol token as ICMP-family without regard to the FILTER family. In an
// inet6 filter, `next-header icmp` (1) / `1` with `icmp-type echo-request`
// resolved the type with the IPv6 table (128) but pinned the protocol bitmap
// to proto 1; real ICMPv6 traffic is proto 58, so the term could never match
// and a `then discard`/`reject` silently fell through to the implicit accept
// (fail-OPEN). Mirror: inet + icmpv6/58/icmp6 aliases.
//
// FAIL-ON-REVERT: drop the family argument from the icmp arm in
// validateFilterCrossFieldStrict and every reject case below goes RED —
// strict CompileConfig accepts the never-match discard term.

func TestFilterCrossFamilyICMPRejected_15045(t *testing.T) {
	cases := []struct {
		name  string
		cmds  []string
		proto string
	}{
		{
			name: "inet6_nextheader_icmp_echo",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header icmp",
				"set firewall family inet6 filter f6 term t from icmp-type echo-request",
				"set firewall family inet6 filter f6 term t then discard",
			},
			proto: "icmp",
		},
		{
			name: "inet6_nextheader_1_echo",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header 1",
				"set firewall family inet6 filter f6 term t from icmp-type echo-request",
				"set firewall family inet6 filter f6 term t then discard",
			},
			proto: "1",
		},
		{
			name: "inet6_protocol_1_icmptype",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from protocol 1",
				"set firewall family inet6 filter f6 term t from icmp-type 128",
				"set firewall family inet6 filter f6 term t then reject",
			},
			proto: "1",
		},
		{
			name: "inet6_junos_ping_echo",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header junos-ping",
				"set firewall family inet6 filter f6 term t from icmp-type echo-request",
				"set firewall family inet6 filter f6 term t then discard",
			},
			proto: "junos-ping",
		},
		{
			name: "inet6_mixed_icmp_icmpv6_echo",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header [ icmp icmpv6 ]",
				"set firewall family inet6 filter f6 term t from icmp-type echo-request",
				"set firewall family inet6 filter f6 term t then discard",
			},
			proto: "icmp",
		},
		{
			name: "inet6_icmp_code_too",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header icmp",
				"set firewall family inet6 filter f6 term t from icmp-type echo-request",
				"set firewall family inet6 filter f6 term t from icmp-code 0",
				"set firewall family inet6 filter f6 term t then discard",
			},
			proto: "icmp",
		},
		{
			name: "inet_protocol_icmpv6_type",
			cmds: []string{
				"set firewall family inet filter f term t from protocol icmpv6",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
			proto: "icmpv6",
		},
		{
			name: "inet_protocol_58_type",
			cmds: []string{
				"set firewall family inet filter f term t from protocol 58",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then reject",
			},
			proto: "58",
		},
		{
			name: "inet_icmp6_alias_type",
			cmds: []string{
				"set firewall family inet filter f term t from protocol icmp6",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
			proto: "icmp6",
		},
		{
			name: "inet_junos_pingv6_type",
			cmds: []string{
				"set firewall family inet filter f term t from protocol junos-pingv6",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
			proto: "junos-pingv6",
		},
		{
			name: "inet_mixed_icmp_icmpv6_type",
			cmds: []string{
				"set firewall family inet filter f term t from protocol [ icmp icmpv6 ]",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
			proto: "icmpv6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("cross-family ICMP term (proto %q) must be rejected at strict commit (#15045)", tc.proto)
			}
			if !strings.Contains(err.Error(), tc.proto) || !strings.Contains(err.Error(), "icmp") {
				t.Fatalf("error %q must name the icmp match and offending protocol %q", err, tc.proto)
			}
			// Lenient path warns, does not hard-fail (#1960); the Rust
			// snapshot backstop fails the term's snapshot closed.
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient path must not hard-fail: %v", lerr)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "cross-field") && strings.Contains(w, tc.proto) {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("lenient path must warn naming %q, got %v", tc.proto, cfg.Warnings)
			}
		})
	}
}

// Controls: the family-correct ICMP spellings stay accepted on both
// families, with the family-appropriate echo-request numeric (8 / 128).
func TestFilterFamilyCorrectICMPAccepted_15045(t *testing.T) {
	v6 := buildFilterTree(t,
		"set firewall family inet6 filter ok6 term t from next-header icmpv6",
		"set firewall family inet6 filter ok6 term t from icmp-type echo-request",
		"set firewall family inet6 filter ok6 term t then discard",
	)
	cfg6, err := CompileConfig(v6)
	if err != nil {
		t.Fatalf("inet6 + icmpv6 + echo-request must compile: %v", err)
	}
	f6 := cfg6.Firewall.FiltersInet6["ok6"]
	if f6 == nil || len(f6.Terms) != 1 || len(f6.Terms[0].ICMPTypes) != 1 || f6.Terms[0].ICMPTypes[0] != 128 {
		t.Fatalf("inet6 control term = %+v, want ICMPTypes [128]", f6)
	}
	for _, proto := range []string{"58", "icmp6", "icmp-v6", "junos-icmp6-all", "junos-pingv6"} {
		tree := buildFilterTree(t,
			"set firewall family inet6 filter ok6 term t from next-header "+proto,
			"set firewall family inet6 filter ok6 term t from icmp-type echo-request",
			"set firewall family inet6 filter ok6 term t then discard",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("inet6 + %q + echo-request must compile: %v", proto, err)
		}
	}

	v4 := buildFilterTree(t,
		"set firewall family inet filter ok4 term t from protocol icmp",
		"set firewall family inet filter ok4 term t from icmp-type echo-request",
		"set firewall family inet filter ok4 term t then discard",
	)
	cfg4, err := CompileConfig(v4)
	if err != nil {
		t.Fatalf("inet + icmp + echo-request must compile: %v", err)
	}
	f4 := cfg4.Firewall.FiltersInet["ok4"]
	if f4 == nil || len(f4.Terms) != 1 || len(f4.Terms[0].ICMPTypes) != 1 || f4.Terms[0].ICMPTypes[0] != 8 {
		t.Fatalf("inet control term = %+v, want ICMPTypes [8]", f4)
	}
	for _, proto := range []string{"1", "junos-icmp-all", "junos-ping"} {
		tree := buildFilterTree(t,
			"set firewall family inet filter ok4 term t from protocol "+proto,
			"set firewall family inet filter ok4 term t from icmp-type echo-request",
			"set firewall family inet filter ok4 term t then discard",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("inet + %q + echo-request must compile: %v", proto, err)
		}
	}

	// A wrong-family protocol WITHOUT an icmp predicate is not this gate's
	// concern (protocol alone stays enforceable as authored).
	noICMP := buildFilterTree(t,
		"set firewall family inet6 filter plain term t from next-header icmp",
		"set firewall family inet6 filter plain term t then discard",
	)
	if _, err := CompileConfig(noICMP); err != nil {
		t.Fatalf("inet6 + icmp without icmp-type must stay accepted (out of #15045 scope): %v", err)
	}
}

// Direct helper pin: family split of the ICMP predicate.
func TestProtocolIsICMPForFamily_15045(t *testing.T) {
	if !protocolIsICMPForFamily("icmp", "inet") || !protocolIsICMPForFamily("1", "inet") ||
		!protocolIsICMPForFamily("junos-ping", "inet") || protocolIsICMPForFamily("icmpv6", "inet") ||
		!protocolIsICMPForFamily("icmpv6", "inet6") || !protocolIsICMPForFamily("58", "inet6") ||
		!protocolIsICMPForFamily("junos-pingv6", "inet6") || protocolIsICMPForFamily("icmp", "inet6") ||
		protocolIsICMPForFamily("tcp", "inet") || protocolIsICMPForFamily("tcp", "inet6") {
		t.Fatal("protocolIsICMPForFamily family split is wrong (#15045)")
	}
	if !protocolIsICMPForFamily("icmp", "any") || !protocolIsICMPForFamily("icmpv6", "any") {
		t.Fatal("unknown family must keep the #3723 either-ICMP verdict")
	}
}
