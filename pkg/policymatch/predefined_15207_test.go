package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15207 A18-02 acceptance: junos-icmp6-packet-too-big admits type 2, denies 134.
func TestPredefinedICMP6PacketTooBig15207(t *testing.T) {
	cfg := predefinedICMPAppCfg11340("junos-icmp6-packet-too-big")
	for _, tc := range []struct {
		typ  uint8
		want config.PolicyAction
	}{
		{2, config.PolicyPermit},
		{134, config.PolicyDeny},
		{128, config.PolicyDeny},
	} {
		ty := tc.typ
		code := uint8(0)
		res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmpv6", ICMPType: &ty, ICMPCode: &code})
		if res.Action != tc.want {
			t.Fatalf("type %d: got %v want %v (matched=%v)", ty, res.Action, tc.want, res.Matched)
		}
	}
	// wrong code denies
	cfg2 := predefinedICMPAppCfg11340("junos-icmp6-packet-too-big")
	ty, code := uint8(2), uint8(1)
	res := Match(cfg2, Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmpv6", ICMPType: &ty, ICMPCode: &code})
	if res.Action != config.PolicyDeny {
		t.Fatalf("type2/code1: got %v want deny", res.Action)
	}
}
