package config

import (
	"strings"
	"testing"
)

// #3723: the stateless firewall-filter compile path accepted several cross-field
// combinations the Rust dataplane matcher can never satisfy, so a `then discard`
// / `then reject` term silently became a never-match. Because an xpf filter falls
// through to an implicit ACCEPT on no-match, the drop the operator wrote was dead
// and the traffic was admitted — a fail-OPEN. validateFilterCrossFieldStrict is
// the stateless-filter mirror of the application cross-field gate (#3373/#3348)
// and rejects the offending term at commit.
//
// FAIL-ON-REVERT: remove the validateFilterCrossFieldStrict invocation (or the
// function's reject) and every strict-path case below goes RED — CompileConfig
// accepts a never-match discard term (accepted + never-matches + implicit-accept)
// instead of erroring.

// H01 / M01 / M02: a source-port / destination-port match on a NON-port-bearing
// protocol is a never-match. Cover several protocols, both directions, both
// families, the *-except lists, and a mixed bracket list.
func TestFilterPortOnNonPortProtocolRejected_3723(t *testing.T) {
	cases := []struct {
		name  string
		cmds  []string
		proto string // token that must appear in the error
	}{
		{
			name: "gre_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol gre",
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
			proto: "gre",
		},
		{
			name: "esp_sport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol esp",
				"set firewall family inet filter f term t from source-port 4500",
				"set firewall family inet filter f term t then reject",
			},
			proto: "esp",
		},
		{
			name: "icmp_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol icmp",
				"set firewall family inet filter f term t from destination-port 8",
				"set firewall family inet filter f term t then discard",
			},
			proto: "icmp",
		},
		{
			name: "numeric_gre_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol 47",
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
			proto: "47",
		},
		{
			// M01: a mixed bracket list — tcp is port-bearing, gre is not. A
			// single configured deny that only enforces on tcp and silently
			// never-matches gre must be rejected on gre.
			name: "mixed_list_tcp_gre_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol [ tcp gre ]",
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
			proto: "gre",
		},
		{
			// M02: inet6 next-header is the IPv6 spelling of protocol; it routes
			// into term.Protocols so it inherits the identical hazard.
			name: "inet6_nextheader_esp_dport",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header esp",
				"set firewall family inet6 filter f6 term t from destination-port 80",
				"set firewall family inet6 filter f6 term t then discard",
			},
			proto: "esp",
		},
		{
			// The negated *-port-except list carries the same hazard.
			name: "gre_dport_except",
			cmds: []string{
				"set firewall family inet filter f term t from protocol gre",
				"set firewall family inet filter f term t from destination-port-except 80",
				"set firewall family inet filter f term t then discard",
			},
			proto: "gre",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("term with a port on non-port protocol %q must be rejected at commit (#3723)", tc.proto)
			}
			if !strings.Contains(err.Error(), tc.proto) ||
				!strings.Contains(err.Error(), "port") {
				t.Fatalf("error %q must name the port match and protocol %q", err, tc.proto)
			}
			// Tolerant path downgrades to a warning (#1960 no-brick); the Rust
			// backstop fails the snapshot closed independently.
			if _, lerr := CompileConfigLenient(tree); lerr != nil {
				t.Fatalf("lenient path must not hard-fail on the cross-field term: %v", lerr)
			}
		})
	}
}

// H02: tcp-flags on a NON-TCP protocol is a never-match. UDP is port-bearing but
// still not TCP, so it must be rejected — proving tcp-flags uses the stricter
// protocolIsTCP predicate, not protocolIsPortBearing.
func TestFilterTCPFlagsOnNonTCPProtocolRejected_3723(t *testing.T) {
	cases := []struct {
		name, proto string
	}{
		{"udp", "udp"},
		{"icmp", "icmp"},
		{"gre", "gre"},
		{"numeric_udp", "17"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t,
				"set firewall family inet filter f term t from protocol "+tc.proto,
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t then discard",
			)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("tcp-flags on non-TCP protocol %q must be rejected at commit (#3723)", tc.proto)
			}
			if !strings.Contains(err.Error(), tc.proto) ||
				!strings.Contains(err.Error(), "tcp-flags") {
				t.Fatalf("error %q must name tcp-flags and protocol %q", err, tc.proto)
			}
			if _, lerr := CompileConfigLenient(tree); lerr != nil {
				t.Fatalf("lenient path must not hard-fail on the cross-field term: %v", lerr)
			}
		})
	}
}

// H03: icmp-type / icmp-code on a NON-ICMP protocol is a never-match.
func TestFilterICMPOnNonICMPProtocolRejected_3723(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "tcp_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "udp_icmpcode",
			cmds: []string{
				"set firewall family inet filter f term t from protocol udp",
				"set firewall family inet filter f term t from icmp-type 3",
				"set firewall family inet filter f term t from icmp-code 0",
				"set firewall family inet filter f term t then discard",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("icmp-type/icmp-code on a non-ICMP protocol must be rejected at commit (#3723)")
			}
			if !strings.Contains(err.Error(), "icmp") {
				t.Fatalf("error %q must name the icmp match", err)
			}
			if _, lerr := CompileConfigLenient(tree); lerr != nil {
				t.Fatalf("lenient path must not hard-fail on the cross-field term: %v", lerr)
			}
		})
	}
}

// M03: an icmp-code with NO icmp-type is broader than a Junos config implies
// (icmp-code 0 is common across types). Mirror the #3506 application reject.
func TestFilterICMPCodeWithoutTypeRejected_3723(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol icmp",
		"set firewall family inet filter f term t from icmp-code 0",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("icmp-code without icmp-type must be rejected at commit (#3723 M03)")
	}
	if !strings.Contains(err.Error(), "icmp-code") ||
		!strings.Contains(err.Error(), "icmp-type") {
		t.Fatalf("error %q must explain the icmp-code-without-icmp-type coupling", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the icmp-code-only term: %v", lerr)
	}
}

// Positive controls — a same-protocol (satisfiable) term must STILL compile and
// keep its match fields, proving the gate is scoped to genuinely-unsatisfiable
// cross-field pairs, not to every L4 predicate.
func TestFilterCrossFieldSatisfiableAccepted_3723(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "tcp_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t from destination-port 22",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "udp_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol udp",
				"set firewall family inet filter f term t from destination-port 53",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "tcp_tcpflags",
			cmds: []string{
				"set firewall family inet filter f term t from protocol tcp",
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "icmp_icmptype",
			cmds: []string{
				"set firewall family inet filter f term t from protocol icmp",
				"set firewall family inet filter f term t from icmp-type echo-request",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "icmp_type_and_code",
			cmds: []string{
				"set firewall family inet filter f term t from protocol icmp",
				"set firewall family inet filter f term t from icmp-type 3",
				"set firewall family inet filter f term t from icmp-code 0",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			name: "inet6_nextheader_icmp6_type",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from next-header icmp6",
				"set firewall family inet6 filter f6 term t from icmp-type echo-request",
				"set firewall family inet6 filter f6 term t then discard",
			},
		},
		{
			name: "mixed_list_tcp_udp_dport",
			cmds: []string{
				"set firewall family inet filter f term t from protocol [ tcp udp ]",
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			// A port with NO protocol is legitimate for a FILTER (the matcher
			// matches the port on whatever L4-port-bearing packet arrives). The
			// gate fires only when an incompatible protocol is PRESENT.
			name: "dport_no_protocol",
			cmds: []string{
				"set firewall family inet filter f term t from destination-port 80",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			// tcp-flags with NO protocol is enforceable — the matcher self-gates
			// on the packet protocol being TCP.
			name: "tcpflags_no_protocol",
			cmds: []string{
				"set firewall family inet filter f term t from tcp-flags syn",
				"set firewall family inet filter f term t then discard",
			},
		},
		{
			// A non-port protocol with NO port is fine — the protocol alone is
			// enforceable.
			name: "gre_no_port",
			cmds: []string{
				"set firewall family inet filter f term t from protocol gre",
				"set firewall family inet filter f term t then discard",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildFilterTree(t, tc.cmds...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("satisfiable term must compile cleanly: %v", err)
			}
		})
	}
}

// The lenient path must record a downgrade WARNING (not just avoid failing) so
// an operator syncing a legacy config can see the term is inert.
func TestFilterCrossFieldLenientWarns_3723(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol gre",
		"set firewall family inet filter f term t from destination-port 80",
		"set firewall family inet filter f term t then discard",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", err)
	}
	warned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "cross-field") && strings.Contains(w, "gre") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected a cross-field downgrade warning naming gre, got %v", cfg.Warnings)
	}
}

// L12 cross-package canary: the application cross-field gate (#3373/#3348) and
// the firewall-filter cross-field gate (#3723) MUST reason about protocol/L4
// compatibility with the SAME SSOT helpers (protocolIsPortBearing /
// protocolIsICMPFamily), plus protocolIsTCP for the tcp-flags arm. If a future
// refactor changes one helper's verdict for a protocol, both gates move
// together — this pin fails if the port-bearing / ICMP-family classification
// they share ever diverges from the tcp-flags subset relationship.
func TestApplicationAndFilterCrossFieldGatesUseSharedSSOT_3723(t *testing.T) {
	// Representative protocol tokens spanning port / TCP-only / ICMP / neither.
	tokens := []string{
		"tcp", "udp", "icmp", "icmpv6", "icmp6", "gre", "esp", "ah",
		"ospf", "vrrp", "sctp", "junos-tcp-any", "junos-udp-any",
		"junos-ping", "6", "17", "1", "58", "47", "132",
	}
	for _, tok := range tokens {
		// Invariant 1: every TCP token is port-bearing (tcp-flags implies a
		// port-bearing transport), but not every port-bearing token is TCP (UDP).
		if protocolIsTCP(tok) && !protocolIsPortBearing(tok) {
			t.Fatalf("protocol %q is TCP but not port-bearing — the tcp-flags gate would "+
				"reject a term the port gate accepts, an SSOT split", tok)
		}
		// Invariant 2: TCP and ICMP-family are disjoint (a token cannot be both,
		// else a tcp-flags+icmp-type term would have no consistent verdict).
		if protocolIsTCP(tok) && protocolIsICMPFamily(tok) {
			t.Fatalf("protocol %q classified as BOTH TCP and ICMP-family — cross-field "+
				"verdicts would be inconsistent", tok)
		}
		// Invariant 3: an ICMP-family token is never port-bearing (a port on ICMP
		// is a never-match; both gates must agree it is not port-bearing).
		if protocolIsICMPFamily(tok) && protocolIsPortBearing(tok) {
			t.Fatalf("protocol %q classified as BOTH ICMP-family and port-bearing — the "+
				"port gate and icmp gate would disagree", tok)
		}
	}

	// And prove both gates actually FIRE on the shared classification for the
	// same protocol: an ICMP protocol carrying a port is rejected by BOTH the
	// application gate and the firewall-filter gate.
	appCfg := &Config{}
	appCfg.Services.ApplicationIdentification = true
	appCfg.Applications.Applications = map[string]*Application{
		"BAD": {Name: "BAD", Protocol: "icmp", DestinationPort: "80"},
	}
	if err := validateApplicationSpecsStrict(appCfg); err == nil {
		t.Fatal("application gate must reject a port on icmp (shared #3373 SSOT)")
	}
	filterCfg := &Config{}
	filterCfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"f": {Name: "f", Terms: []*FirewallFilterTerm{
			{Name: "t", Protocols: []string{"icmp"}, DestinationPorts: []string{"80"}, Action: FilterActionDiscard},
		}},
	}
	if err := validateFilterCrossFieldStrict(filterCfg); err == nil {
		t.Fatal("firewall-filter gate must reject a port on icmp (shared #3723 SSOT)")
	}
}
