package api

import (
	"strings"
	"testing"
)

func TestAPIShowTextDHCPRelayV6NamesGroupAndServers11694(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set forwarding-options dhcp-relay dhcpv6 server-group sg6 2001:db8::5",
		"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group sg6",
		"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0",
	})
	out := renderShowTextBody(t, s, "dhcp-relay")
	for _, want := range []string{"DHCPv6 server groups:", "sg6", "2001:db8::5", "DHCPv6 relay groups:", "g6", "ge-0/0/0.0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("REST show-text dhcp-relay missing %q; got:\n%s", want, out)
		}
	}
}
