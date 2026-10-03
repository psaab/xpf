package config

import "testing"

// Test_4455_CatalogSSOTShape guards the protocol->multicast-group catalog SSOT:
// every catalog token is a recognized host-inbound protocol, and none is a
// unicast-only or L2 protocol misfiled as multicast.
func Test_4455_CatalogSSOTShape(t *testing.T) {
	for _, tok := range HostInboundMulticastProtocolTokens() {
		if !KnownHostInboundProtocols[tok] {
			t.Errorf("catalog token %q is not a KnownHostInboundProtocols token", tok)
		}
		if HostInboundL2Protocols[tok] {
			t.Errorf("catalog token %q is an L2 protocol and rides no IP multicast group", tok)
		}
		g, ok := HostInboundMulticastProtocol(tok)
		if !ok {
			t.Errorf("HostInboundMulticastProtocol(%q) must report ok for a catalog token", tok)
		}
		if len(g.V4) == 0 && len(g.V6) == 0 {
			t.Errorf("catalog token %q has no multicast groups", tok)
		}
	}
	// bgp is unicast — must NOT be in the multicast catalog.
	if _, ok := HostInboundMulticastProtocol("bgp"); ok {
		t.Errorf("bgp is unicast and must not be a multicast-catalog protocol")
	}
}
