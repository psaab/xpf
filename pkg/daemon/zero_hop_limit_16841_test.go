package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16841: the kernel host-inbound chain must drop hop-limit-0 IPv6 to a
// firewall-local destination by default (Junos), and admit it when
// `no-ipv6-reject-zero-hop-limit` is set. The drop must precede every
// accept (ESP/AH, established, ICMP errors, ND) so no global accept
// resurrects it, and must be scoped to local destinations so transit
// (which draws Time Exceeded from the dataplane) is unaffected.

func TestZeroHopLimitDropText16841(t *testing.T) {
	if got := zeroHopLimitLocalDropText(true); got != "" {
		t.Errorf("admit=true must emit no drop, got %q", got)
	}
	got := zeroHopLimitLocalDropText(false)
	if !strings.Contains(got, "ip6 hoplimit 0") || !strings.Contains(got, "fib daddr type { local, anycast }") || !strings.Contains(got, "drop") {
		t.Errorf("default drop = %q, want hoplimit-0 local fib drop", got)
	}
}

func TestHostInboundPayloadZeroHopFirst16841(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)

	def := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	dropAt := strings.Index(def, "ip6 hoplimit 0 fib daddr type { local, anycast } drop")
	if dropAt < 0 {
		t.Fatalf("default payload lacks the zero-hop local drop:\n%s", def)
	}
	for _, accept := range []string{"meta l4proto { 50, 51 } accept", "ct state established,related", "icmpv6 type"} {
		if at := strings.Index(def, accept); at >= 0 && at < dropAt {
			t.Errorf("accept %q at %d must follow the zero-hop drop at %d", accept, at, dropAt)
		}
	}

	admit := buildHostInboundFilterPayloadWithAdmit(views, nil, nil, nil, nil, true, true)
	if strings.Contains(admit, "ip6 hoplimit 0") {
		t.Errorf("knob-set payload must not drop local hop-limit-0:\n%s", admit)
	}
}

func TestLo0PayloadZeroHopFirst16841(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"f6": {Terms: []*config.FirewallFilterTerm{{Name: "t", Action: config.FilterActionAccept}}},
	}
	def := buildLo0FilterPayload(cfg, "", "f6")
	if !strings.Contains(def, "ip6 hoplimit 0 fib daddr type { local, anycast } drop") {
		t.Errorf("default lo0 payload lacks the zero-hop drop:\n%s", def)
	}
	cfg.System.InternetOptions = &config.InternetOptionsConfig{NoIPv6RejectZeroHopLimit: true}
	admit := buildLo0FilterPayload(cfg, "", "f6")
	if strings.Contains(admit, "ip6 hoplimit 0") {
		t.Errorf("knob-set lo0 payload must not drop local hop-limit-0:\n%s", admit)
	}
	if got := toNftLo0Spec(cfg, "", "f6"); !got.NoIPv6RejectZeroHopLimit {
		t.Error("toNftLo0Spec must carry the knob")
	}
}

func TestFencePayloadsZeroHop16841(t *testing.T) {
	fence := buildHostInboundFencePayload(nil, nil, []string{"2001:db8::1"}, nil, nil, nil, nil, dhcpBackstopLists{})
	if !strings.Contains(fence, "ip6 hoplimit 0 fib daddr type { local, anycast } drop") {
		t.Errorf("cold-boot fence lacks the zero-hop drop:\n%s", fence)
	}
	gap := buildHostInboundGapFencePayload(nil, nil, []string{"2001:db8::1"}, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
	if !strings.Contains(gap, "ip6 hoplimit 0 fib daddr type { local, anycast } drop") {
		t.Errorf("gap fence lacks the zero-hop drop:\n%s", gap)
	}
	// The netlink mirror of the same fences is xnft.EmitZeroHopLimitLocalDrop;
	// its presence in the rendered rules is pinned in pkg/nftables.
	_ = xnft.HostInboundTableName
}
