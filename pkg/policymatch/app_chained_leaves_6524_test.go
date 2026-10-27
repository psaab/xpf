package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6524 — the SECURITY crux, asserted on the POLICY OUTCOME rather than on the
// compiled struct.
//
// In the flat-set grammar `set a b c d` builds a CHAIN of single-key nodes, so
//
//	set applications application myapp protocol tcp destination-port 8080
//
// nests `destination-port` under the VALUE node `tcp` instead of beside
// `protocol`. compileApplications iterated only the application node's direct
// Children, saw just `protocol`, and never assigned DestinationPort — the
// application compiled PROTOCOL-ONLY. An empty DestinationPort is a match-any
// port term (matchSingleApp only constrains the port when app.DestinationPort
// is non-empty), so a policy matching that application permitted ALL TCP.
//
// A test that only checked `app.DestinationPort != ""` would pass on a fix that
// populated the field while leaving matching broken, so these cases drive
// Match() and assert the verdict for an IN-scope port and an OUT-of-scope port.
//
// RED-on-revert: restore the pre-#6524 `for _, prop := range inst.node.Children`
// loop in compileApplications (dropping applicationDirectLeaves) and
// DestinationPort goes back to "" — the "tcp/22 must NOT be permitted" subcases
// then report Matched=true / PolicyPermit and these tests go RED. The
// permit-8080 subcases stay green under the revert (protocol-only matches
// everything), which is exactly why the negative port is the load-bearing
// assertion.

// chainedAppPolicyCfg compiles a trust->untrust permit policy whose only
// application is authored with the CHAINED flat-set spelling under test.
func chainedAppPolicyCfg(t *testing.T, appLine string) *config.Config {
	t.Helper()
	return compileFromSet(t, []string{
		appLine,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application myapp",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})
}

func chainedAppQuery(cfg *config.Config, proto string, dstPort int) Result {
	return Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: proto, SrcPort: PortPtr(40000), DstPort: PortPtr(uint16(dstPort)),
	})
}

// TestChainedAppDestPortPolicyDoesNotPermitAllTCP is the issue's headline case:
// the chained one-line application must permit ONLY tcp/8080, not every TCP
// port.
func TestChainedAppDestPortPolicyDoesNotPermitAllTCP(t *testing.T) {
	cfg := chainedAppPolicyCfg(t,
		"set applications application myapp protocol tcp destination-port 8080")

	// The in-scope port is permitted — the chained destination-port was
	// actually honored, not merely recorded.
	if res := chainedAppQuery(cfg, "tcp", 8080); !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("tcp/8080 = matched:%v action:%v, want a PERMIT (the chained "+
			"destination-port must still admit the port it names)",
			res.Matched, res.Action)
	}
	// The load-bearing assertion: any OTHER TCP port must fall through the
	// application term to the default deny. Pre-#6524 the app was
	// protocol-only, so this permitted.
	for _, port := range []int{22, 80, 443, 65535} {
		res := chainedAppQuery(cfg, "tcp", port)
		if res.Matched && res.Action == config.PolicyPermit {
			t.Fatalf("tcp/%d was PERMITTED by an application declared "+
				"`protocol tcp destination-port 8080` — the chained "+
				"destination-port was dropped and the policy permits ALL TCP (#6524)",
				port)
		}
	}
}

// TestChainedAppSourcePortPolicyConstrainsSourcePort covers the source-port
// axis of the same chain — the third untyped match leaf.
func TestChainedAppSourcePortPolicyConstrainsSourcePort(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application myapp protocol tcp source-port 5000",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application myapp",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})
	q := func(srcPort int) Result {
		return Match(cfg, Query{
			FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
			Protocol: "tcp", SrcPort: PortPtr(uint16(srcPort)), DstPort: PortPtr(80),
		})
	}
	if res := q(5000); !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("source-port 5000 = matched:%v action:%v, want PERMIT", res.Matched, res.Action)
	}
	if res := q(5001); res.Matched && res.Action == config.PolicyPermit {
		t.Fatalf("source-port 5001 was PERMITTED by an application declared " +
			"`protocol tcp source-port 5000` — the chained source-port was " +
			"dropped and the policy permits every source port (#6524)")
	}
}

// TestChainedAppICMPTypePolicyConstrainsType covers `protocol icmp icmp-type 8`
// — the chain drops the type constraint, leaving the application matching EVERY
// ICMP type (the fail-open widening #3348 fixed for the alias/inline-term
// paths).
func TestChainedAppICMPTypePolicyConstrainsType(t *testing.T) {
	cfg := chainedAppPolicyCfg(t,
		"set applications application myapp protocol icmp icmp-type 8")

	icmp := func(typ uint8) Result {
		v := typ
		return Match(cfg, Query{
			FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
			Protocol: "icmp", ICMPType: &v,
		})
	}
	// Echo-request (type 8) is the authored constraint — permitted.
	if res := icmp(8); !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("icmp type 8 = matched:%v action:%v, want PERMIT", res.Matched, res.Action)
	}
	// Every other type must NOT be permitted. Pre-#6524 ICMPType stayed nil, so
	// the term was unconstrained and redirect/timestamp/unreachable all passed.
	for _, typ := range []uint8{0, 3, 5, 13} {
		if res := icmp(typ); res.Matched && res.Action == config.PolicyPermit {
			t.Fatalf("icmp type %d was PERMITTED by an application declared "+
				"`protocol icmp icmp-type 8` — the chained icmp-type was dropped "+
				"and the policy permits EVERY ICMP type (#6524)", typ)
		}
	}
}

// TestChainedAppDenyPolicyCoversNamedPort is the DENY-side mirror. A deny whose
// application dropped its port constraint widens to all-TCP, which is a
// fail-CLOSED blast radius (unrelated TCP is blocked) rather than a fail-open —
// the inverse error, and equally wrong. It pins that the deny covers 8080 and
// leaves other TCP to the later permit.
func TestChainedAppDenyPolicyCoversNamedPort(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application myapp protocol tcp destination-port 8080",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy blk match source-address any",
		"set security policies from-zone trust to-zone untrust policy blk match destination-address any",
		"set security policies from-zone trust to-zone untrust policy blk match application myapp",
		"set security policies from-zone trust to-zone untrust policy blk then deny",
		"set security policies from-zone trust to-zone untrust policy rest match source-address any",
		"set security policies from-zone trust to-zone untrust policy rest match destination-address any",
		"set security policies from-zone trust to-zone untrust policy rest match application any",
		"set security policies from-zone trust to-zone untrust policy rest then permit",
	})
	if res := chainedAppQuery(cfg, "tcp", 8080); !res.Matched || res.Action != config.PolicyDeny {
		t.Fatalf("tcp/8080 = matched:%v action:%v, want the DENY to cover the "+
			"port its application names", res.Matched, res.Action)
	}
	// Pre-#6524 the deny widened to every TCP port and swallowed the later
	// permit.
	if res := chainedAppQuery(cfg, "tcp", 443); !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("tcp/443 = matched:%v action:%v, want the later PERMIT — a deny "+
			"application declared `protocol tcp destination-port 8080` must not "+
			"widen to ALL TCP (#6524)", res.Matched, res.Action)
	}
}

// TestSiblingAppSpellingUnchanged is the over-reach guard at the OUTCOME level:
// the one-leaf-per-line spelling (which always worked) must produce exactly the
// same verdicts as the chained spelling now does.
func TestSiblingAppSpellingUnchanged(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application myapp",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})
	if res := chainedAppQuery(cfg, "tcp", 8080); !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("sibling spelling tcp/8080 = matched:%v action:%v, want PERMIT",
			res.Matched, res.Action)
	}
	if res := chainedAppQuery(cfg, "tcp", 22); res.Matched && res.Action == config.PolicyPermit {
		t.Fatalf("sibling spelling tcp/22 was PERMITTED — the pre-existing " +
			"one-leaf-per-line behavior regressed")
	}
}
