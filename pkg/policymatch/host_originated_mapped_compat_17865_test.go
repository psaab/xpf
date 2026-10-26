package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHostOriginatedV4MappedCompatExempt17865 pins #17865: the #16803
// V4MappedCompatIngressDrop arm in Match must not precede/ignore the
// host-originated exemption. A from-zone junos-host query is
// host-ORIGINATED (locally generated, egresses via the kernel TX path —
// #3611/#4230/#16805) and never traverses the AF_XDP RX policy gate, so
// stamping the RX ingress-drop verdict on it fabricates a forwarding stage
// that never runs. The neighbouring route-drop advisory already excludes
// host-originated queries for exactly this reason (Match, #4373 block).
//
// FAIL-ON-REVERT: remove the FromZone != JunosHostZone guard from the
// queryHasV4MappedOrCompatSide gate and every host-originated row below
// returns V4MappedCompatIngressDrop (HostOriginated false), failing the
// assertions. The transit/host-bound controls pin that the #16803
// ingress drop itself is unchanged for non-host-originated queries.
func TestHostOriginatedV4MappedCompatExempt17865(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-any", config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}})),
		},
	}, config.ApplicationsConfig{})

	hostOriginated := []struct {
		name string
		q    Query
	}{
		// The reviewer's cited shape verbatim (v6 hints on both sides,
		// mapped destination).
		{"mapped dst host-originated", Query{FromZone: JunosHostZone, ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::ffff:198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"mapped src host-originated", Query{FromZone: JunosHostZone, ToZone: "untrust",
			SrcIP: net.ParseIP("::ffff:192.0.2.1"), DstIP: net.ParseIP("2001:db8::7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"compat dst host-originated", Query{FromZone: JunosHostZone, ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		// The from-axis governs (#16805): junos-host -> junos-host with a
		// mapped side is still host-originated, not host-bound/ingress.
		{"mapped host-to-host", Query{FromZone: JunosHostZone, ToZone: JunosHostZone,
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::ffff:198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
	}
	for _, tc := range hostOriginated {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, tc.q)
			if res.V4MappedCompatIngressDrop {
				t.Fatalf("host-originated query must not fabricate the RX ingress drop (#17865): %+v", res)
			}
			if !res.HostOriginated {
				t.Fatalf("HostOriginated = false, want true for from-zone junos-host; res = %+v", res)
			}
			if res.Matched || res.DefaultUsed || res.HostInboundUnmatched || res.UnzonedIngress || res.UnzonedEgress {
				t.Fatalf("host-originated must carry no policy/default/host-gate/unzoned verdict; res = %+v", res)
			}
			if res.Action != config.PolicyDeny {
				t.Fatalf("Action = %v, want conservative PolicyDeny", res.Action)
			}
			if got := res.DisplayAction(); got != HostOriginatedActionString {
				t.Fatalf("DisplayAction() = %q, want HostOriginatedActionString %q", got, HostOriginatedActionString)
			}
		})
	}

	// Controls: the #16803 ingress drop is unchanged when the query is NOT
	// host-originated — transit and host-BOUND (to-zone junos-host) rows
	// still report the ingress drop.
	controls := []struct {
		name string
		q    Query
	}{
		{"mapped dst transit control", Query{FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::ffff:198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
		{"mapped dst host-bound control", Query{FromZone: "trust", ToZone: JunosHostZone,
			SrcIP: net.ParseIP("2001:db8::9"), DstIP: net.ParseIP("::ffff:198.51.100.7"),
			SrcFamily: "v6", DstFamily: "v6"}},
	}
	for _, tc := range controls {
		t.Run("control/"+tc.name, func(t *testing.T) {
			res := Match(cfg, tc.q)
			if !res.V4MappedCompatIngressDrop {
				t.Fatalf("non-host-originated mapped query must keep the ingress drop; res = %+v", res)
			}
			if res.HostOriginated {
				t.Fatalf("non-host-originated query must not be host-originated; res = %+v", res)
			}
			if got := res.DisplayAction(); got != V4MappedCompatIngressDropActionString {
				t.Fatalf("DisplayAction() = %q, want V4MappedCompatIngressDropActionString", got)
			}
		})
	}
}
