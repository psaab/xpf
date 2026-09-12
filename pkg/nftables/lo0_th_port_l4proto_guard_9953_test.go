package nftables

import (
	"strings"
	"testing"
)

// #9953. `th sport` / `th dport` load two bytes at an offset into whatever the
// kernel considers the TRANSPORT HEADER and compare them to a port number. The
// load is unconditional: nothing in the rule says the packet is TCP or UDP.
//
// On the `inet xpf_lo0` INPUT chain that is not a theoretical concern. The chain
// is filled by buildLo0FilterNetlink at nftLo0FilterPriority with policy accept
// and its terms carry no `iif` predicate, so every packet arriving at the kernel
// input hook is evaluated against them — and the host-bound set is not "TCP and
// UDP to the firewall". The shim's local-destination arm passes host-bound
// traffic to the kernel on every AF_XDP-bound interface keyed on the DESTINATION
// being local, not on protocol, so SCTP, GRE and ICMP to a firewall-local
// address take that arm exactly as TCP and UDP do; and the lifelines (fxp0, em0,
// fab*) are never AF_XDP-bound at all and are served on the kernel path
// unconditionally.
//
// So an operator's `destination-port 22` term is evaluated against a GRE or
// ICMP packet, reading two arbitrary bytes of its header as a port. A term that
// ACCEPTS gets a fail-open on a match; a term that DISCARDS drops unrelated
// traffic. Neither is what the configuration says.
//
// The fix is the one this file's own doctrine already demands everywhere else —
// #6405 for ports, #6512 for addresses, #6806 for protocols all refuse to let a
// narrowing predicate go missing. A port match with no protocol predicate gets
// `meta l4proto { tcp, udp }`.

// canon of an l4proto set match: the builder emits a Meta load of L4PROTO into
// register 1 followed by a lookup against an anonymous set. Asserting on the
// canonical text keeps this cell readable and is what the sibling #6405 cell
// does for the port comparison itself.
func hasL4ProtoGuard9953(t *testing.T, rules string) bool {
	t.Helper()
	// meta l4proto -> Meta(key=16) in the canon dump; the tcp/udp values are 6
	// and 17, rendered as single-byte set elements.
	return strings.Contains(rules, "meta(key=16")
}

func buildLo0Term9953(t *testing.T, term Lo0FilterTerm) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{V4Terms: []Lo0FilterTerm{term}})
	if p.err != nil {
		t.Fatalf("build failed: %v", p.err)
	}
	return p
}

// THE REPRODUCTION. A port-constrained term with no protocol predicate must not
// read a port out of a non-transport header.
func TestLo0PortMatchWithoutProtocolIsGuarded_9953(t *testing.T) {
	for _, tc := range []struct {
		name string
		term Lo0FilterTerm
	}{
		{"dport", Lo0FilterTerm{Name: "ssh-in", DestinationPorts: []string{"22"}, Action: "accept"}},
		{"sport", Lo0FilterTerm{Name: "ssh-out", SourcePorts: []string{"22"}, Action: "accept"}},
		{"dport_except", Lo0FilterTerm{Name: "not-ssh", DestPortsExcept: []string{"22"}, Action: "discard"}},
		{"sport_except", Lo0FilterTerm{Name: "not-ssh-s", SourcePortsExcept: []string{"22"}, Action: "discard"}},
		{"dport_set", Lo0FilterTerm{Name: "mgmt", DestinationPorts: []string{"22", "161"}, Action: "accept"}},
		{"dport_range", Lo0FilterTerm{Name: "hi", DestinationPorts: []string{"5000-5010"}, Action: "accept"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := canonRules(buildLo0Term9953(t, tc.term))
			if !hasL4ProtoGuard9953(t, got) {
				t.Errorf("#9953: a `th %s` match was emitted on the lo0 input chain with NO "+
					"l4proto predicate. The two bytes it compares are read from whatever the "+
					"kernel calls the transport header, so this term is evaluated against SCTP, "+
					"GRE and ICMP reaching a firewall-local address — an accept term fails OPEN "+
					"on a chance byte match and a discard term drops unrelated traffic. "+
					"Emit `meta l4proto { tcp, udp }` alongside it.\nrules:\n%s", tc.name, got)
			}
		})
	}
}

// The fallback set must contain BOTH tcp and udp.
//
// Every other cell here asks only whether a guard is present, so a fallback
// narrowed to {tcp} alone would satisfy all of them while silently breaking
// every UDP service an operator admits by port — `destination-port 53 accept`
// would stop matching DNS. That direction is fail-CLOSED, so it does not show up
// as a bypass; it shows up as a lockout, and the lo0 chain is the control plane.
//
// It is also the one property the two render paths cannot check for each other:
// they take the set from one SSOT, so a change there moves both together and a
// parity comparison stays green.
func TestLo0PortFallbackCoversBothTransportProtocols_9953(t *testing.T) {
	nums := Lo0PortFallbackProtocols()
	got := map[uint8]bool{}
	for _, n := range nums {
		got[n] = true
	}
	for _, want := range []struct {
		num  uint8
		name string
	}{{6, "tcp"}, {17, "udp"}} {
		if !got[want.num] {
			t.Errorf("#9953: the port-match fallback does not include %s (%d): %v. A term that "+
				"admits a service by port with no protocol named must keep matching that "+
				"service — narrowing the fallback locks out %s traffic on the control plane",
				want.name, want.num, nums, want.name)
		}
	}
	// And the rendered text must carry both, since that is what nft parses.
	expr := Lo0PortFallbackL4ProtoExpr()
	for _, want := range []string{"6", "17"} {
		if !strings.Contains(expr, want) {
			t.Errorf("#9953: rendered fallback %q omits protocol %s", expr, want)
		}
	}

	// EXACTLY those two, and nothing else.
	//
	// "contains tcp and udp" is not sufficient, and a mutation proved it: adding
	// GRE to the set escaped every other cell in this file. The membership rule
	// is not "protocols we like" — it is "protocols for which the two bytes at
	// the port offsets ARE ports". Admitting one for which they are not puts the
	// #9953 defect straight back, now blessed by a named constant: a
	// `destination-port 22 discard` term would again drop GRE packets whose
	// header bytes happen to read as 22.
	//
	// SCTP is the interesting near-miss and is deliberately excluded. Its first
	// four header bytes genuinely ARE source and destination ports, so the
	// comparison would be meaningful — but adding it would silently WIDEN every
	// existing operator rule to a protocol they never wrote, which is a scope
	// change, not a bug fix. If it is ever wanted it belongs in the config, not
	// in a fallback.
	if len(nums) != 2 {
		t.Errorf("#9953: the fallback set is %v, want exactly [6 17]. Every member must be a "+
			"protocol whose bytes at the port offsets are actually ports; anything else "+
			"re-creates the defect this guard exists to prevent", nums)
	}
}

// POSITIVE CONTROL, same run: a term that DOES carry a protocol predicate must
// keep the operator's protocol, not acquire {tcp, udp}.
//
// Without this cell the fix is indistinguishable from "always emit tcp+udp",
// which would silently WIDEN a `protocol tcp` term to also match UDP — turning a
// narrowing fix into a fail-open of its own, on exactly the terms that were
// already correct.
func TestLo0PortMatchWithProtocolKeepsIt_9953(t *testing.T) {
	p := buildLo0Term9953(t, Lo0FilterTerm{
		Name: "ssh-in", Protocols: []string{"tcp"},
		DestinationPorts: []string{"22"}, Action: "accept",
	})
	got := canonRules(p)
	if !hasL4ProtoGuard9953(t, got) {
		t.Fatalf("premise: a `protocol tcp` term must already carry an l4proto match:\n%s", got)
	}
	// tcp is 6; udp (17 = 0x11) must NOT appear. The guard for a single protocol
	// is a cmp, not a set, so a widened term is visible as the set form.
	if strings.Contains(got, "0011") {
		t.Errorf("#9953: a term that specifies `protocol tcp` acquired UDP. The guard must "+
			"only supply {tcp, udp} where the operator supplied NO protocol; supplying it "+
			"alongside an explicit protocol widens the term.\nrules:\n%s", got)
	}
}

// A term with NO port match at all must not acquire a protocol guard it never
// asked for. `from protocol gre` with a discard action is a legitimate lo0 term
// and must not be narrowed to tcp/udp — that would be the mirror-image
// fail-open, letting GRE through a rule written to stop it.
func TestLo0TermWithoutPortsIsNotNarrowed_9953(t *testing.T) {
	for _, tc := range []struct {
		name string
		term Lo0FilterTerm
	}{
		{"addr_only", Lo0FilterTerm{Name: "from-net", SrcAddrs: []string{"10.0.0.0/8"}, Action: "accept"}},
		{"bare_discard", Lo0FilterTerm{Name: "catch-all", Action: "discard"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := canonRules(buildLo0Term9953(t, tc.term))
			if hasL4ProtoGuard9953(t, got) {
				t.Errorf("#9953: a term with no port match acquired an l4proto guard. The guard "+
					"exists to make a PORT comparison meaningful; adding it to a term that "+
					"compares no port narrows the operator's rule — a `discard` term written "+
					"to stop GRE would stop only tcp/udp.\nrules:\n%s", got)
			}
		})
	}
}
