package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16803 (R3-A55-02): the userspace helper drops IPv4-mapped
// (::ffff:0:0/96) and IPv4-compatible (::/96, excluding :: and ::1) IPv6
// frames at ingress BEFORE any policy evaluation (#10686/#11669,
// userspace-dp/src/afxdp/frame/inspect.rs
// ipv6_addr_is_v4_mapped_or_compat, gated in poll_descriptor/mod.rs for
// transit and host-bound traffic alike). Match must therefore return the
// first-class V4MappedCompatIngressDrop verdict instead of certifying a
// permit/deny/default policy verdict for such a tuple.
//
// RED on revert: drop the queryHasV4MappedOrCompatSide gate in Match and
// every defect row below falls through to the permit-all policy /
// default-permit (Matched/DefaultUsed true, ingress-drop flag false) —
// the assertions fail. The control rows pin that v4, ordinary-v6,
// link-local, :: and ::1 tuples are unchanged.
func TestV4MappedCompatIngressDrop16803(t *testing.T) {
	// Permit-all zone-pair over default-permit: without the gate every
	// defect row would read as a concrete permit, so the lie is maximal.
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-any", config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}})),
			zonePair("trust", "junos-host", permit("permit-host", config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}})),
		},
	}, config.ApplicationsConfig{})

	defect := []struct {
		name string
		q    Query
	}{
		{"mapped src transit", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("::ffff:192.0.2.1"), DstIP: net.ParseIP("2001:db8::7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"mapped dst transit", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::ffff:198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"compat src transit", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("::192.0.2.1"), DstIP: net.ParseIP("2001:db8::7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		// No family hint, IPv4-compatible form: To4() is nil for ::/96
		// (only the mapped ::ffff: form folds), so the bytes alone gate
		// it even for a net.IP-only caller.
		{"compat src no hint single side", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("::192.0.2.1")}},
		{"compat dst transit", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"mapped src host-bound", Query{FromZone: "trust", ToZone: JunosHostZone,
			SrcIP: net.ParseIP("::ffff:192.0.2.1"), DstIP: net.ParseIP("2001:db8::7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"compat dst host-bound", Query{FromZone: "trust", ToZone: JunosHostZone,
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
	}
	for _, tc := range defect {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, tc.q)
			if !res.V4MappedCompatIngressDrop {
				t.Fatalf("V4MappedCompatIngressDrop = false, want true (res=%+v)", res)
			}
			if res.Matched || res.DefaultUsed || res.HostInboundUnmatched {
				t.Fatalf("ingress-drop verdict must carry no policy verdict: %+v", res)
			}
			if res.Action != config.PolicyDeny {
				t.Fatalf("Action = %v, want conservative PolicyDeny", res.Action)
			}
			if got := res.DisplayAction(); got != V4MappedCompatIngressDropActionString {
				t.Fatalf("DisplayAction() = %q, want V4MappedCompatIngressDropActionString", got)
			}
		})
	}

	controls := []struct {
		name string
		q    Query
	}{
		{"genuine v4", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("198.51.100.7"),
			SrcFamily: "v4", DstFamily: "v4"}},
		{"ordinary v6", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("2001:db8::7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"v6 link-local dst", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("fe80::1"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"unspecified v6 src excluded", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("::"), DstIP: net.ParseIP("2001:db8::7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"loopback v6 dst excluded", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::1"),
			SrcFamily: "v6", DstFamily: "v6"}},
	}
	for _, tc := range controls {
		t.Run("control/"+tc.name, func(t *testing.T) {
			res := Match(cfg, tc.q)
			if res.V4MappedCompatIngressDrop {
				t.Fatalf("control wrongly flagged as ingress drop: %+v", res)
			}
			if res.DisplayAction() == V4MappedCompatIngressDropActionString {
				t.Fatalf("control must not render the ingress-drop verdict: %+v", res)
			}
		})
	}

	// The ordinary-v6 and v4 controls still reach the permit verdict —
	// the gate did not swallow same-family evaluation.
	uni := Match(cfg, Query{FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("2001:db8::7"),
		SrcFamily: "v6", DstFamily: "v6"})
	if !uni.Matched || uni.Action != config.PolicyPermit {
		t.Fatalf("ordinary v6 control must still permit, got %+v", uni)
	}
}
