package config

import "testing"

// #17237: MergeFrom is first-writer-wins per endpoint field and latches RequireTSIG.
func TestRFC2136EndpointMergeFrom17237(t *testing.T) {
	dst := RFC2136Endpoint{UpdateServer: "a", RequireTSIG: false}
	src := RFC2136Endpoint{UpdateServer: "b", ForwardZone: "z.", TSIGSecret: NewSecret("s"), RequireTSIG: true}
	dst.MergeFrom(src)
	if dst.UpdateServer != "a" || dst.ForwardZone != "z." || dst.TSIGSecret.Reveal() != "s" || !dst.RequireTSIG {
		t.Fatalf("MergeFrom = %+v", dst)
	}
	// DHCP merge uses it: dst endpoint wins, src fills gaps.
	d1 := &DHCPDynamicDNSConfig{Domain: "d1", RFC2136Endpoint: RFC2136Endpoint{UpdateServer: "a"}}
	d2 := &DHCPDynamicDNSConfig{RFC2136Endpoint: RFC2136Endpoint{UpdateServer: "b", ForwardZone: "z."}}
	merged := mergeDHCPDynamicDNS(d1, d2)
	if merged.UpdateServer != "a" || merged.ForwardZone != "z." || merged.Domain != "d1" {
		t.Fatalf("mergeDHCPDynamicDNS = %+v", merged)
	}
}
