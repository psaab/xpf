package daemon

import (
	"strings"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundScreenFloodTextMixedIngressAddressFallback12847(t *testing.T) {
	screen := xnft.HostInboundScreenFloodRule{
		Zone: "wan", Family: "ip", Protocol: "udp",
		AggregateThreshold: 160, SourceThreshold: 20,
		IngressNetdevs: []string{"ge-0-0-0"},
		Addresses: []string{"192.0.2.2"},
	}
	var rules []string
	emitHostInboundScreenFloodText(&rules, []xnft.HostInboundScreenFloodRule{screen}, false)
	payload := strings.Join(rules, "\n")
	if !strings.Contains(payload, `iifname "ge-0-0-0" meta nfproto ipv4 meta l4proto 17`) {
		t.Fatalf("direct ingress flood scope missing:\n%s", payload)
	}
	if !strings.Contains(payload, "ip daddr 192.0.2.2 meta l4proto 17") {
		t.Fatalf("address fallback flood scope missing:\n%s", payload)
	}
}
