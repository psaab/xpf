package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHostOriginatedFromJunosHost16805 pins #16805: a `from-zone junos-host`
// query asks about host-ORIGINATED (locally-generated) traffic, which
// egresses via the kernel TX path and is never evaluated by the
// security-policy RX gate (#3611 Piece A / #4230). Before the fix the query
// fell into UnzonedIngress (junos-host is not in cfg.Security.Zones) and the
// operator was told an unknown-ingress-zone unconditional deny blocks traffic
// no policy ever sees.
//
// FAIL-ON-REVERT: removing the q.FromZone == JunosHostZone arm in Match makes
// the transit and host-to-host cells return UnzonedIngress (and the
// junos-host -> junos-host cell return the host-gate verdict), failing the
// HostOriginated / DisplayAction assertions.
func TestHostOriginatedFromJunosHost16805(t *testing.T) {
	cfg := undefinedZoneCfg()

	tests := []struct {
		name string
		q    Query
	}{
		{"host-originated to transit zone", Query{FromZone: "junos-host", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(53)}},
		{"host-originated to host (from-axis governs)", Query{FromZone: "junos-host", ToZone: "junos-host", Protocol: "tcp", DstPort: PortPtr(53)}},
		{"host-originated to unknown zone", Query{FromZone: "junos-host", ToZone: "nosuch", Protocol: "tcp", DstPort: PortPtr(53)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(cfg, tt.q)
			if !res.HostOriginated {
				t.Fatalf("HostOriginated = false, want true for from-zone junos-host; res = %+v", res)
			}
			if res.UnzonedIngress || res.UnzonedEgress {
				t.Fatalf("host-originated must not be an unzoned deny (#16805); res = %+v", res)
			}
			if res.Matched || res.DefaultUsed || res.HostInboundUnmatched {
				t.Fatalf("host-originated must carry no policy/default/host-gate verdict; res = %+v", res)
			}
			if got := res.DisplayAction(); got != HostOriginatedActionString {
				t.Fatalf("DisplayAction() = %q, want HostOriginatedActionString %q", got, HostOriginatedActionString)
			}
		})
	}
}

// TestHostOriginatedControlsUnchanged16805 pins the acceptance controls: the
// genuinely-unknown from-zone and the host-bound to-zone directions are
// unchanged by the #16805 arm.
func TestHostOriginatedControlsUnchanged16805(t *testing.T) {
	cfg := undefinedZoneCfg()

	// Control 1: `from-zone nosuch` is still the unconditional
	// unknown-ingress-zone deny (#6682/#8318), not host-originated.
	res := Match(cfg, Query{FromZone: "nosuch", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if res.HostOriginated || !res.UnzonedIngress || res.Action != config.PolicyDeny {
		t.Fatalf("from-zone nosuch control changed: want UnzonedIngress deny, got %+v", res)
	}
	if got := res.DisplayAction(); got != UnzonedIngressActionString {
		t.Fatalf("nosuch DisplayAction() = %q, want UnzonedIngressActionString", got)
	}

	// Control 2: `to-zone junos-host` is still host-BOUND (host gate /
	// HostInboundUnmatched), not host-originated.
	res = Match(cfg, Query{FromZone: "trust", ToZone: "junos-host", Protocol: "tcp", DstPort: PortPtr(22)})
	if res.HostOriginated || !res.HostInboundUnmatched {
		t.Fatalf("to-zone junos-host control changed: want HostInboundUnmatched, got %+v", res)
	}
	if got := res.DisplayAction(); got != HostInboundActionString {
		t.Fatalf("host-bound DisplayAction() = %q, want HostInboundActionString", got)
	}

	// Control 3: a defined transit pair still matches normally.
	res = Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if res.HostOriginated || !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("defined transit control changed: want wildcard permit, got %+v", res)
	}
}
