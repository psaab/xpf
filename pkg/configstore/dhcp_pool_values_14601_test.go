package configstore

import (
	"strings"
	"testing"
)

// #14601 through the real operator check pipeline (CheckText is the thin
// composition of the same functions Store.Commit uses): a DHCP pool value
// Kea would refuse must be rejected naming the leaf, and the valid control
// in the same shape must pass, so the refusal is the pool value and not
// the fixture.
func TestCheckTextRefusesBadDHCPPoolValues14601(t *testing.T) {
	pool := func(extra string) string {
		return "system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; " +
			"pool p1 { subnet 10.0.61.0/24; address-range low 10.0.61.100 high 10.0.61.199; " + extra + " } } } } }"
	}
	cases := []struct {
		name string
		text string
		want string
	}{
		{"range outside subnet", "system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; pool p1 { subnet 10.0.61.0/24; address-range low 10.0.99.100 high 10.0.99.199; } } } } }", "address-range low"},
		{"subnet without prefix length", "system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; pool p1 { subnet 10.0.61.0; address-range low 10.0.61.100 high 10.0.61.199; } } } } }", "subnet"},
		{"v6 router in v4 pool", pool("router 2001:db8::1;"), "router"},
		{"v6 dns-server in v4 pool", pool("dns-server 2001:db8::53;"), "dns-server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, 0); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckText accepted a Kea-refused pool value (%s): %v", tc.want, err)
			}
		})
	}
	if _, err := CheckText(pool("router 10.0.61.1; dns-server 10.0.61.53;"), 0); err != nil {
		t.Fatalf("control: a valid DHCP pool was refused: %v", err)
	}
}
