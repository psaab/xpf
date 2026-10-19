package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHostInboundNftRenderGoldenByteIdentical is the #3627 B1a byte-identity
// proof for the SSOT nft-render refactor. hostInboundServiceMatches /
// hostInboundProtocolMatches now RENDER the structured token->tuple SSOT
// (config.HostInboundServiceMatch / config.HostInboundProtocolMatch) instead of
// carrying their own hand-written nft strings. This golden freezes the EXACT
// pre-#3627 nft fragments (captured from the hand-written switch before the
// refactor) for every known token in both families, so any drift in the SSOT or
// the renderer — a moved port, a lost `{ 9, 10 }` coalesce, a numeric
// echo-request, a wrong `all` expansion order — turns this RED. It is the
// "no behavior change, only a shared SSOT" guarantee the refactor rests on.
//
// The golden values are the authoritative nft match fragments; the parallel
// domain-parity guards (TestHostInboundNftMatchesKnownTokens,
// TestHostInboundSipTftpNarrowPortSet, ...) still assert the token SETS agree
// with the recognized-token SSOT and the Rust classifier.
func TestHostInboundNftRenderGoldenByteIdentical(t *testing.T) {
	svc := map[string][2][]string{
		// #3226: `all` renders the union of the named system-services (the
		// xpf-only `gre` and `r-exec`/`rexec` extensions excluded), in
		// HostInboundAllExpansionServices order. Before #3226 it rendered
		// NOTHING here because it took the hostInboundAllowsAll blanket-accept
		// branch instead. `tcp dport 113` appears via the expanded ident-reset
		// and carries the `reject with tcp reset` VERDICT (verdicts are
		// asserted separately — this golden pins the match FRAGMENTS).
		//
		// FAIL-ON-REVERT, all three directions of the #3226 fold:
		//
		//   ABSENT — `tcp dport 512`: Juniper's schema enumerates rlogin and rsh
		//     but not rexec, so a Junos-correct `all` never opens 512.
		//   PRESENT — the Junos services xpf previously did not recognize that
		//     have a port Juniper FIXES: tcp 2901 (reverse-ssh), tcp 2900
		//     (reverse-telnet) from explicit YANG `default` statements, and udp
		//     8503 (lsselfping) from RFC 7746.
		//   ABSENT — `udp dport 28762` and `tcp/udp dport 7`. An earlier revision
		//     rendered these for r2cp and rpm, from a draft SUGGESTION and a
		//     configurable range FLOOR respectively. Neither is a Junos default,
		//     so both opened a port with no listener on every `all` zone while
		//     still denying whatever port the operator had configured.
		"all": {
			{"udp dport { 67, 68 }", "udp dport { 67, 68 }", "udp dport 53", "tcp dport 53", "tcp dport 79", "tcp dport 21", "tcp dport 80", "tcp dport 443", "tcp dport 113", "udp dport { 500, 4500 }", "udp dport { 500, 4500 }", "udp dport 3503", "udp dport 8503", "tcp dport 830", "tcp dport { 22, 830 }", "udp dport 123", "icmp type echo-request", "tcp dport 513", "tcp dport 514", "tcp dport 2901", "tcp dport 2900", "tcp dport 513", "tcp dport 514", "udp dport 5060", "tcp dport 5060", "udp dport 161", "udp dport 162", "tcp dport 22", "tcp dport { 22, 830 }", "tcp dport 23", "udp dport 69", "udp dport 33434-33523", "tcp dport 80", "tcp dport 443", "tcp dport 3221", "tcp dport 3220"},
			{"udp dport { 546, 547 }", "udp dport 53", "tcp dport 53", "tcp dport 79", "tcp dport 21", "tcp dport 80", "tcp dport 443", "tcp dport 113", "udp dport { 500, 4500 }", "udp dport { 500, 4500 }", "udp dport 3503", "udp dport 8503", "tcp dport 830", "tcp dport { 22, 830 }", "udp dport 123", "icmpv6 type echo-request", "tcp dport 513", "tcp dport 514", "tcp dport 2901", "tcp dport 2900", "tcp dport 513", "tcp dport 514", "udp dport 5060", "tcp dport 5060", "udp dport 161", "udp dport 162", "tcp dport 22", "tcp dport { 22, 830 }", "tcp dport 23", "udp dport 69", "udp dport 33434-33523", "tcp dport 80", "tcp dport 443", "tcp dport 3221", "tcp dport 3220"},
		},
		"any-service": {nil, nil},
		// #3226 fold: Junos services xpf has no authoritative listening port for
		// (config.HostInboundUnportedSystemServices) render NOTHING on either
		// family. They stay recognized and stay in the `all` union above,
		// contributing no fragment. Earlier revisions rendered "udp dport 28762"
		// for r2cp and "tcp/udp dport 7" for rpm from a draft SUGGESTION and a
		// configurable range FLOOR respectively; neither is a Junos default.
		"appqoe":            {nil, nil},
		"high-availability": {nil, nil},
		"r2cp":              {nil, nil},
		"rpm":               {nil, nil},
		"tcp-encap":         {nil, nil},
		"bootp":             {{"udp dport { 67, 68 }"}, nil},
		"dhcp":              {{"udp dport { 67, 68 }"}, nil},
		"dhcpv6":            {nil, {"udp dport { 546, 547 }"}},
		"dns":               {{"udp dport 53", "tcp dport 53"}, {"udp dport 53", "tcp dport 53"}},
		"finger":            {{"tcp dport 79"}, {"tcp dport 79"}},
		"ftp":               {{"tcp dport 21"}, {"tcp dport 21"}},
		"gre":               {{"meta l4proto 47"}, {"meta l4proto 47"}},
		"http":              {{"tcp dport 80"}, {"tcp dport 80"}},
		"https":             {{"tcp dport 443"}, {"tcp dport 443"}},
		"ident-reset":       {{"tcp dport 113"}, {"tcp dport 113"}},
		"ike":               {{"udp dport { 500, 4500 }"}, {"udp dport { 500, 4500 }"}},
		"ipsec":             {{"udp dport { 500, 4500 }"}, {"udp dport { 500, 4500 }"}},
		"lsping":            {{"udp dport 3503"}, {"udp dport 3503"}},
		"lsselfping":        {{"udp dport 8503"}, {"udp dport 8503"}},
		"netconf":           {{"tcp dport 830"}, {"tcp dport 830"}},
		"netconf-ssh":       {{"tcp dport { 22, 830 }"}, {"tcp dport { 22, 830 }"}},
		"ntp":               {{"udp dport 123"}, {"udp dport 123"}},
		"ping":              {{"icmp type echo-request"}, {"icmpv6 type echo-request"}},
		"r-exec":            {{"tcp dport 512"}, {"tcp dport 512"}},
		"r-login":           {{"tcp dport 513"}, {"tcp dport 513"}},
		"r-sh":              {{"tcp dport 514"}, {"tcp dport 514"}},
		"reverse-ssh":       {{"tcp dport 2901"}, {"tcp dport 2901"}},
		"reverse-telnet":    {{"tcp dport 2900"}, {"tcp dport 2900"}},
		"rexec":             {{"tcp dport 512"}, {"tcp dport 512"}},
		"rlogin":            {{"tcp dport 513"}, {"tcp dport 513"}},
		"rsh":               {{"tcp dport 514"}, {"tcp dport 514"}},
		"sip":               {{"udp dport 5060", "tcp dport 5060"}, {"udp dport 5060", "tcp dport 5060"}},
		"snmp":              {{"udp dport 161"}, {"udp dport 161"}},
		"snmp-trap":         {{"udp dport 162"}, {"udp dport 162"}},
		"ssh":               {{"tcp dport 22"}, {"tcp dport 22"}},
		"ssh-netconf":       {{"tcp dport { 22, 830 }"}, {"tcp dport { 22, 830 }"}},
		"telnet":            {{"tcp dport 23"}, {"tcp dport 23"}},
		"tftp":              {{"udp dport 69"}, {"udp dport 69"}},
		"traceroute":        {{"udp dport 33434-33523"}, {"udp dport 33434-33523"}},
		"webapi-clear-text": {{"tcp dport 80"}, {"tcp dport 80"}},
		"webapi-ssl":        {{"tcp dport 443"}, {"tcp dport 443"}},
		"xnm-clear-text":    {{"tcp dport 3221"}, {"tcp dport 3221"}},
		"xnm-ssl":           {{"tcp dport 3220"}, {"tcp dport 3220"}},
	}
	proto := map[string][2][]string{
		"all": {
			{"udp dport { 3784, 3785, 4784 }", "tcp dport 179", "meta l4proto 2", "meta l4proto 2", "tcp dport 646", "udp dport 646", "tcp dport 639", "meta l4proto 54", "meta l4proto 89", "meta l4proto 113", "meta l4proto 103", "udp dport 520", "icmp type { 9, 10 }", "meta l4proto 46", "udp dport 9875", "meta l4proto 112"},
			{"udp dport { 3784, 3785, 4784 }", "tcp dport 179", "tcp dport 646", "udp dport 646", "tcp dport 639", "icmpv6 type { 133, 134, 135, 136 }", "meta l4proto 54", "meta l4proto 89", "meta l4proto 113", "meta l4proto 103", "udp dport 521", "meta l4proto 46", "udp dport 9875", "meta l4proto 112"},
		},
		"bfd":              {{"udp dport { 3784, 3785, 4784 }"}, {"udp dport { 3784, 3785, 4784 }"}},
		"bgp":              {{"tcp dport 179"}, {"tcp dport 179"}},
		"dvmrp":            {{"meta l4proto 2"}, nil},
		"igmp":             {{"meta l4proto 2"}, nil},
		"isis":             {nil, nil},
		"ldp":              {{"tcp dport 646", "udp dport 646"}, {"tcp dport 646", "udp dport 646"}},
		"msdp":             {{"tcp dport 639"}, {"tcp dport 639"}},
		"ndp":              {nil, {"icmpv6 type { 133, 134, 135, 136 }"}},
		"nhrp":             {{"meta l4proto 54"}, {"meta l4proto 54"}},
		"ospf":             {{"meta l4proto 89"}, nil},
		"ospf3":            {nil, {"meta l4proto 89"}},
		"pgm":              {{"meta l4proto 113"}, {"meta l4proto 113"}},
		"pim":              {{"meta l4proto 103"}, {"meta l4proto 103"}},
		"rip":              {{"udp dport 520"}, nil},
		"ripng":            {nil, {"udp dport 521"}},
		"router-discovery": {{"icmp type { 9, 10 }"}, nil},
		"rsvp":             {{"meta l4proto 46"}, {"meta l4proto 46"}},
		"sap":              {{"udp dport 9875"}, {"udp dport 9875"}},
		"vrrp":             {{"meta l4proto 112"}, {"meta l4proto 112"}},
	}

	families := [2]string{"ip", "ip6"}

	// Every golden key must be a recognized token, and every recognized token
	// must have a golden entry — so a token added to the SSOT without a golden
	// (or vice versa) is caught, not silently unverified.
	for tok := range config.KnownHostInboundSystemServices {
		if _, ok := svc[tok]; !ok {
			t.Errorf("service token %q recognized by the SSOT but missing a byte-identity golden entry", tok)
		}
	}
	for tok := range svc {
		if !config.KnownHostInboundSystemServices[tok] {
			t.Errorf("golden lists service token %q that is not in the recognized-token SSOT", tok)
		}
		for fi, fam := range families {
			got := hostInboundServiceMatches(tok, fam)
			if !equalStrings(got, svc[tok][fi]) {
				t.Errorf("service %q (%s): render drift\n got  %#v\n want %#v", tok, fam, got, svc[tok][fi])
			}
		}
	}
	for tok := range config.KnownHostInboundProtocols {
		if _, ok := proto[tok]; !ok {
			t.Errorf("protocol token %q recognized by the SSOT but missing a byte-identity golden entry", tok)
		}
	}
	for tok := range proto {
		if !config.KnownHostInboundProtocols[tok] {
			t.Errorf("golden lists protocol token %q that is not in the recognized-token SSOT", tok)
		}
		for fi, fam := range families {
			got := hostInboundProtocolMatches(tok, fam)
			if !equalStrings(got, proto[tok][fi]) {
				t.Errorf("protocol %q (%s): render drift\n got  %#v\n want %#v", tok, fam, got, proto[tok][fi])
			}
		}
	}
}

// TestHostInboundIdentResetRejectMarkerMatchesNftVerdict ties the #3627 SSOT
// Reject marker to the pre-existing nft verdict SSOT (hostInboundServiceAction):
// a service token whose SSOT tuple carries Reject == true is EXACTLY the token
// the nft chain rejects (ident-reset), and every non-Reject token is a plain
// accept. This guards against the marker and the nft verdict drifting apart —
// e.g. adding a Reject tuple without teaching hostInboundServiceAction, which
// would make the classifier report "not admitted" while the nft chain still
// admits (or vice versa).
func TestHostInboundIdentResetRejectMarkerMatchesNftVerdict(t *testing.T) {
	// #3226: the builder assigns the verdict per EXPANDED token
	// (hostInboundMatchSet walks config.HostInboundServiceTokenExpansion), so
	// the marker/verdict agreement is a property of the CONCRETE tokens. Walking
	// the expansion covers every authored token including `all`, whose expansion
	// contains ident-reset.
	for tok := range config.KnownHostInboundSystemServices {
		for _, sub := range config.HostInboundServiceTokenExpansion(tok) {
			reject := false
			for _, fam := range []string{"ip", "ip6"} {
				for _, m := range config.HostInboundServiceMatch(sub, fam) {
					if m.Reject {
						reject = true
					}
				}
			}
			wantReject := hostInboundServiceAction(sub) == hostInboundReject
			if reject != wantReject {
				t.Errorf("service %q (via authored token %q): SSOT Reject marker = %v but nft verdict reject = %v — the marker and the nft verdict must agree", sub, tok, reject, wantReject)
			}
		}
	}

	// #3226 fail-open guard: `all` MUST expand to a set containing a Reject
	// tuple, and the builder must not flatten it to an accept. If
	// hostInboundMatchSet went back to keying the verdict on the AUTHORED token,
	// `all`'s tcp/113 fragment would render `accept` and ADMIT ident probes the
	// per-token form resets.
	sawReject := false
	for _, sub := range config.HostInboundServiceTokenExpansion("all") {
		for _, m := range config.HostInboundServiceMatch(sub, "ip") {
			if m.Reject {
				sawReject = true
			}
		}
	}
	if !sawReject {
		t.Errorf("`system-services all` expansion must contain the ident-reset Reject tuple (#3226)")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
