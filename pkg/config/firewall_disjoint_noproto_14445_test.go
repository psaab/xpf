package config

import (
	"strings"
	"testing"
)

// #14445 (DR19-H1): a no-protocol firewall-filter term combining predicates
// from disjoint L4 protocol families is a never-match. The matcher ANDs its
// arms: ports require a port-bearing (TCP/UDP) packet, tcp-flags requires
// TCP, and icmp-type/code requires ICMP/ICMPv6 — no single packet satisfies
// both families. validateFilterCrossFieldStrict must strict-reject the
// combination (and the lenient path must warn, leaving the Rust snapshot
// backstop to fail the snapshot closed); each predicate ALONE with no
// protocol, and ports+tcp-flags together, must still compile.
//
// FAIL-ON-REVERT: remove the #14445 no-protocol disjoint arms from
// validateFilterCrossFieldStrict and every strict case below goes RED —
// CompileConfig accepts a never-match discard term.

func TestFilterNoProtoDisjointRejected_14445(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string // substrings the error must name
	}{
		{
			name: "dport_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"destination-port", "icmp-type"},
		},
		{
			name: "sport_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from source-port 1024",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"source-port", "icmp"},
		},
		{
			name: "dport_except_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port-except 80",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"port", "icmp"},
		},
		{
			name: "sport_except_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from source-port-except 1024",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then reject",
			},
			want: []string{"port", "icmp"},
		},
		{
			name: "dport_icmpcode_with_type",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t from icmp-type 3",
				"set firewall family inet filter f term t from icmp-code 0",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"port", "icmp"},
		},
		{
			name: "tcpflags_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"tcp-flags", "icmp"},
		},
		{
			name: "tcpflags_forbidden_shape_icmptype",
			// `syn & !ack` carries a forbidden half; the Go term still
			// records TCPFlags, so the disjoint gate sees it.
			cmds: []string{
				"set firewall family inet filter f term t from tcp-flags \"syn & !ack\"",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"tcp-flags", "icmp"},
		},
		{
			name: "inet6_dport_icmptype",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from destination-port 80",
				"set firewall family inet6 filter f6 term t from icmp-type 128",
				"set firewall family inet6 filter f6 term t then discard",
			},
			want: []string{"port", "icmp"},
		},
		{
			name: "inet6_tcpflags_icmptype",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from tcp-flags syn",
				"set firewall family inet6 filter f6 term t from icmp-type 128",
				"set firewall family inet6 filter f6 term t then discard",
			},
			want: []string{"tcp-flags", "icmp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("no-protocol disjoint term must be rejected at commit (#14445)")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q must name %q", err, w)
				}
			}
			if !strings.Contains(err.Error(), "no") || !strings.Contains(err.Error(), "protocol is set") {
				t.Fatalf("error %q must explain the no-protocol disjoint pair", err)
			}
			// Lenient path warns and does not hard-fail (#1960 no-brick);
			// the Rust backstop fails the snapshot closed independently.
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient path must not hard-fail on the disjoint term: %v", lerr)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "cross-field") {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("expected a cross-field downgrade warning, got %v", cfg.Warnings)
			}
		})
	}
}

// Positive controls: each predicate ALONE with no protocol still compiles
// (pinned by the issue), ports+tcp-flags together compile (one TCP packet
// satisfies both), and an explicitly satisfiable protocol still compiles.
func TestFilterNoProtoSinglePredicateAccepted_14445(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "dport_alone",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "dport_except_alone",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port-except 80",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "icmptype_alone",
			cmds: []string{
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "tcpflags_alone",
			cmds: []string{
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "ports_and_tcpflags_no_protocol",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "explicit_tcp_port_icmp_still_rejected_by_3723_not_this_gate",
			// Explicit protocol + icmp is the #3723 shape; it must still
			// reject (on the protocol arm), proving the disjoint gate did
			// not widen or shadow the existing check.
			cmds: nil, // handled separately below
		},
	}
	for _, tc := range cases {
		if tc.cmds == nil {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("single/no-protocol-satisfiable term must compile cleanly: %v", err)
			}
		})
	}
	// Explicit tcp + port + icmp-type: rejected by the pre-existing #3723
	// protocol arms (icmp on tcp), not silently accepted.
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from destination-port 80",
		"set firewall family inet filter f term t from icmp-type 8",
		"set firewall family inet filter f term t then discard",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("explicit tcp + port + icmp-type must still be rejected (#3723)")
	}
}

// #15258 (A89-01): `is-fragment` since #14631 matches ONLY trailing
// fragments (offset != 0), which carry no L4 header — so it is disjoint
// from every L4 predicate (ports/except, tcp-flags, icmp-type/code).
// A term combining is-fragment with any of those can never match and
// must strict-reject; is-fragment ALONE and is-fragment+protocol tcp
// (the protocol is not an L4 predicate) must still commit.
func TestFilterIsFragmentDisjointRejected_15258(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string
	}{
		{
			name: "is_fragment_dport",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"is-fragment", "port"},
		},
		{
			name: "is_fragment_dport_except",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t from destination-port-except 80",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"is-fragment", "port"},
		},
		{
			name: "is_fragment_tcpflags",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"is-fragment", "tcp-flags"},
		},
		{
			name: "is_fragment_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t from icmp-type 8",
				"set firewall family inet filter f term t then discard",
			},
			want: []string{"is-fragment", "icmp"},
		},
		{
			name: "is_fragment_icmpcode_with_type",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t from icmp-type 3",
				"set firewall family inet filter f term t from icmp-code 0",
				"set firewall family inet filter f term t then reject",
			},
			want: []string{"is-fragment", "icmp"},
		},
		{
			name: "inet6_is_fragment_dport",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from is-fragment",
				"set firewall family inet6 filter f6 term t from destination-port 80",
				"set firewall family inet6 filter f6 term t then discard",
			},
			want: []string{"is-fragment", "port"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("is-fragment + L4 predicate term must be rejected at commit (#15258)")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q must name %q", err, w)
				}
			}
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient path must not hard-fail: %v", lerr)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "cross-field") {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("expected a cross-field downgrade warning, got %v", cfg.Warnings)
			}
		})
	}
}

func TestFilterIsFragmentAloneAccepted_15258(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{
			name: "is_fragment_alone",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "is_fragment_protocol_tcp",
			cmds: []string{
				"set firewall family inet filter f term t from is-fragment",
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t then discard",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildFilterTree(t, tc.cmds...)); err != nil {
				t.Fatalf("is-fragment control must commit (#15258): %v", err)
			}
		})
	}
}
