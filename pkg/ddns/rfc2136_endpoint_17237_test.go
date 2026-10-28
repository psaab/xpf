package ddns

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17237: the Surface A provider and the DHCP per-family config share one
// RFC2136Endpoint, so their unsigned-non-loopback posture and updater
// construction cannot diverge.

func TestEndpointUnsignedNonLoopback17237(t *testing.T) {
	ep := config.RFC2136Endpoint{UpdateServer: "192.0.2.53"}
	if !endpointUnsignedNonLoopback(ep, "") {
		t.Fatal("non-loopback unsigned endpoint must be flagged")
	}
	if !endpointUnsignedNonLoopback(ep, "rfc2136") {
		t.Fatal("explicit rfc2136 non-loopback unsigned must be flagged")
	}
	if endpointUnsignedNonLoopback(ep, "kea-d2") {
		t.Fatal("non-rfc2136 backend must not be flagged")
	}
	keyed := ep
	keyed.TSIGKeyName = "k1"
	if endpointUnsignedNonLoopback(keyed, "") {
		t.Fatal("keyed endpoint must not be flagged")
	}
	// Both shapes delegate to the same predicate.
	d := &config.DHCPDynamicDNSConfig{Backend: "rfc2136", RFC2136Endpoint: ep}
	p := &config.DDNSProvider{Backend: "rfc2136", RFC2136Endpoint: ep}
	if !ddnsConfigUnsignedNonLoopback(d) || !providerUnsignedNonLoopback(p) {
		t.Fatal("both shapes must report unsigned non-loopback via shared endpoint")
	}
}

func TestNewRFC2136UpdaterFromProviderEndpoint17237(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	p := &config.DDNSProvider{
		Backend:         "rfc2136",
		RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: srv.addrUDP, ForwardZone: "example.com", ReverseZone: "8.b.d.0.1.0.0.2.ip6.arpa"},
	}
	du, err := newSurfaceARFC2136(p, "")
	if err != nil {
		t.Fatalf("newSurfaceARFC2136 from provider endpoint: %v", err)
	}
	ru, ok := du.(*rfc2136Updater)
	if !ok || ru == nil || !ru.selfOwned {
		t.Fatalf("surface A updater must be self-owned rfc2136Updater, got %T", du)
	}
	// Direct endpoint construction (no DHCP carrier struct).
	u2, err := newRFC2136Updater(ddnsPolicy{backend: "rfc2136", conflictPolicy: "replace-owned"}, p.RFC2136Endpoint, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater(endpoint): %v", err)
	}
	if !strings.Contains(u2.server, ":") {
		t.Fatalf("updater server not normalized: %q", u2.server)
	}
}
