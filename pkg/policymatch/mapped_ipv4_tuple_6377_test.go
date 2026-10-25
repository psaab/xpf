package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMatchMappedIPv6SourceNotGated is the #6377 fail-on-revert artifact. An
// IPv4-mapped IPv6 source (::ffff:192.0.2.1) against a genuine IPv6 destination
// is a same-family V6/V6 tuple to the colon-strict runtime matcher
// (userspace-dp/src/policy.rs), so the #5720 unsupported-tuple gate must NOT
// flag it. The caller derives the family hint from the RAW operator text via
// config.NATAddrFamily (colon-strict) exactly as the four Query builders now do;
// the mapped literal carries a ':' and is classified "v6", so the gate falls
// through to normal evaluation.
//
// RED on revert: restore the folding gate
//
//	q.SrcIP.To4() != nil && q.DstIP.To4() == nil
//
// (ignoring q.SrcFamily/q.DstFamily). net.ParseIP("::ffff:192.0.2.1").To4() is
// NON-nil, so the mapped source folds to v4, the (v4,v6) gate fires, and this
// query is FALSELY reported UnsupportedTupleFamily — the assertion below fails.
func TestMatchMappedIPv6SourceNotGated(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
	}, config.ApplicationsConfig{})

	const srcText = "::ffff:192.0.2.1" // IPv4-mapped IPv6 literal
	const dstText = "2001:db8::1"      // genuine IPv6

	// The colon-strict SSOT classifier must see the mapped literal as v6 — the
	// exact call the four Query builders make on the raw operator string.
	if got := config.NATAddrFamily(srcText); got != "v6" {
		t.Fatalf("config.NATAddrFamily(%q) = %q, want v6 (mapped literal is colon-strict v6)", srcText, got)
	}
	// Precondition: net.ParseIP DOES fold the mapped literal, which is exactly
	// the trap #6377 defends against. If this ever stops holding the fold is
	// gone and the whole gate story changes.
	if net.ParseIP(srcText).To4() == nil {
		t.Fatalf("precondition: net.ParseIP(%q).To4() must be non-nil (the fold #6377 closes)", srcText)
	}

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP(srcText),
		DstIP:     net.ParseIP(dstText),
		SrcFamily: config.NATAddrFamily(srcText),
		DstFamily: config.NATAddrFamily(dstText),
	})
	if res.UnsupportedTupleFamily {
		t.Fatalf("mapped-IPv6 source %q -> %q must NOT be gated unsupported (same-family V6/V6), got res=%+v", srcText, dstText, res)
	}
	// #16803: since #10686 the runtime drops mapped/compat IPv6 at ingress
	// before policy, so this tuple now reports the ingress-drop verdict
	// instead of falling through to normal evaluation (see README).
	if !res.V4MappedCompatIngressDrop {
		t.Fatalf("mapped-IPv6 source %q -> %q must report the #10686 ingress drop (#16803), got res=%+v", srcText, dstText, res)
	}
	if res.Matched || res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("ingress-drop verdict must carry no matched/default verdict, got res=%+v", res)
	}
	if got := res.DisplayAction(); got != V4MappedCompatIngressDropActionString {
		t.Fatalf("DisplayAction() = %q, want V4MappedCompatIngressDropActionString", got)
	}
}

// TestMatchTextFamilyClassifiesGenuineTuples guards that threading the text
// hint does NOT weaken the gate for genuine literals: a real dotted-quad v4
// source with a v6 destination is STILL the unsupported (V4 src, V6 dst) tuple
// NAT46 cannot produce, while both same-family tuples fall through. A
// regression that classified every hinted source as one family (dropping the
// real gate, or over-rejecting a same-family tuple) is caught here.
func TestMatchTextFamilyClassifiesGenuineTuples(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
	}, config.ApplicationsConfig{})

	cases := []struct {
		name      string
		src, dst  string
		wantGated bool
	}{
		{"genuine v4 src / v6 dst is gated", "10.0.0.1", "2001:db8::1", true},
		{"genuine v6 src / v6 dst same family", "2001:db8::9", "2001:db8::1", false},
		{"genuine v4 src / v4 dst same family", "10.0.0.1", "10.0.0.2", false},
		{"genuine v6 src / v4 dst NAT64 arm", "2001:db8::9", "10.0.0.2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{
				FromZone: "trust", ToZone: "untrust",
				SrcIP:     net.ParseIP(tc.src),
				DstIP:     net.ParseIP(tc.dst),
				SrcFamily: config.NATAddrFamily(tc.src),
				DstFamily: config.NATAddrFamily(tc.dst),
			})
			if res.UnsupportedTupleFamily != tc.wantGated {
				t.Fatalf("%s: UnsupportedTupleFamily = %v, want %v (res=%+v)", tc.name, res.UnsupportedTupleFamily, tc.wantGated, res)
			}
			if !tc.wantGated && !res.V4MappedCompatIngressDrop && res.Action != config.PolicyPermit {
				t.Fatalf("%s: expected fall-through to default-permit, got %v", tc.name, res.Action)
			}
		})
	}
}

// TestMatchMappedIPv6SourceNotEvaluatedAsV4 is the #6377 EVALUATION-correctness
// fail-on-revert (Codex): the gate falling through is not enough — the policy
// evaluator (matchAddr) must also classify the mapped source as V6, or it would
// match the source against the V4 address rules and FABRICATE A PERMIT the
// runtime never produces. Config: a `permit` rule whose source-address is a
// V4-only book (192.0.2.0/24), over default-deny, and NO V6 rule. A mapped
// source ::ffff:192.0.2.1 FOLDS (To4()) to 192.0.2.1 which IS inside
// 192.0.2.0/24, so a v4-classified evaluation would permit. The colon-strict
// runtime (userspace-dp/src/policy.rs) sees a V6 source, evaluates it against
// the V6 rules (there are none), and falls to default-deny — the simulator must
// agree.
//
// DstIP is nil (match-any) to isolate the SOURCE family classification and keep
// the (V4 src, V6 dst) up-front gate out of the picture entirely.
//
// RED on revert: restore `isV4 := ip.To4() != nil` in matchAddr. The mapped
// source folds to v4, matches the V4-only permit rule, and the simulator reports
// a fabricated PERMIT — the deny assertions below fail.
func TestMatchMappedIPv6SourceNotEvaluatedAsV4(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"v4src": {Name: "v4src", Value: "192.0.2.0/24"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "permit-v4",
				Match: config.PolicyMatch{
					// source-address is V4-only; dest + app unset = match-any.
					SourceAddresses: []string{"v4src"},
				},
				Action: config.PolicyPermit,
			}),
		},
	}, config.ApplicationsConfig{})

	// Mapped-IPv6 source: MUST be evaluated as V6 → no V6 rule → default-deny.
	// #16803 supersedes the fall-through half of that expectation: since
	// #10686 the runtime drops the mapped tuple at ingress before policy,
	// so Match now reports the ingress-drop verdict. The fail-open half is
	// unchanged — the mapped source must never match permit-v4.
	mappedRes := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("::ffff:192.0.2.1"), // folds (To4) to 192.0.2.1 ∈ v4src
		SrcFamily: config.NATAddrFamily("::ffff:192.0.2.1"),
		// DstIP nil (match-any) — isolate the source-family classification.
	})
	if mappedRes.Matched || mappedRes.Action == config.PolicyPermit {
		t.Fatalf("mapped-IPv6 source must NOT match the V4-only permit rule (fabricated permit); got res=%+v", mappedRes)
	}
	if !mappedRes.V4MappedCompatIngressDrop || mappedRes.Action != config.PolicyDeny {
		t.Fatalf("mapped-IPv6 source should report the #10686 ingress drop (#16803), got res=%+v", mappedRes)
	}

	// Control: a GENUINE dotted-quad V4 source in the same subnet MUST still
	// match the V4 permit rule — the family threading did not break real v4.
	v4Res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("192.0.2.5"),
		SrcFamily: config.NATAddrFamily("192.0.2.5"),
	})
	if !v4Res.Matched || v4Res.Action != config.PolicyPermit || v4Res.PolicyName != "permit-v4" {
		t.Fatalf("genuine v4 source must match permit-v4, got res=%+v", v4Res)
	}
}

// TestQueryTupleFamilyFallbackFolds pins the intentional net.IP-only fallback:
// with NO text hint (SrcFamily/DstFamily == ""), queryTupleFamily uses To4(),
// which FOLDS a mapped literal to v4, so the mapped-source tuple IS gated. This
// preserves pre-#6377 behavior for callers that pass only net.IP (e.g. legacy
// tests). The contrast with TestMatchMappedIPv6SourceNotGated isolates the fix:
// the ONLY difference is whether the colon-strict hint is threaded — same IPs,
// opposite verdict.
func TestQueryTupleFamilyFallbackFolds(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("::ffff:192.0.2.1"), // mapped literal, folded by To4()
		DstIP: net.ParseIP("2001:db8::1"),
		// no SrcFamily/DstFamily hint
	})
	if !res.UnsupportedTupleFamily {
		t.Fatalf("without a text hint the mapped source must fold to v4 and gate (pre-#6377 fallback), got res=%+v", res)
	}
	// #16803: the folded fallback classifies the side as "v4", so the
	// colon-strict ingress-drop gate does not ALSO fire for this caller —
	// the unsupported-tuple verdict above is the preserved pre-#6377
	// fallback answer for net.IP-only callers. Callers that thread the
	// hint (all five live surfaces) get the ingress-drop verdict instead.
	if res.V4MappedCompatIngressDrop {
		t.Fatalf("folded fallback must not double-report the ingress drop, got res=%+v", res)
	}
}
