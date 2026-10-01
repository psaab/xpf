package frr

import (
	"strings"
	"testing"
)

func TestIPv6RIODefaultRouteSafety11425(t *testing.T) {
	render := func(route DHCPRoute) string {
		var b strings.Builder
		renderDHCPDefaults(&b, &FullConfig{DHCPRoutes: []DHCPRoute{route}})
		return b.String()
	}

	t.Run("router default remains allowed", func(t *testing.T) {
		t.Setenv(dhcpClasslessTrustOverrideEnv, "")
		got := render(DHCPRoute{Gateway: "fe80::1", Interface: "wan0", IsIPv6: true})
		if !strings.Contains(got, "ipv6 route ::/0 fe80::1 wan0 200\n") {
			t.Fatalf("ordinary RA default-router gateway should remain installable:\n%s", got)
		}
	})

	t.Run("RIO default is refused", func(t *testing.T) {
		t.Setenv(dhcpClasslessTrustOverrideEnv, "")
		got := render(DHCPRoute{
			Destination: "::/0", Gateway: "fe80::1", Interface: "wan0", IsIPv6: true,
		})
		if strings.Contains(got, "ipv6 route ::/0") {
			t.Fatalf("broad IPv6 RIO route must be refused by default:\n%s", got)
		}
	})

	t.Run("explicit trust override allows RIO default", func(t *testing.T) {
		t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
		got := render(DHCPRoute{
			Destination: "::/0", Gateway: "fe80::1", Interface: "wan0", IsIPv6: true,
		})
		if !strings.Contains(got, "ipv6 route ::/0 fe80::1 wan0 200\n") {
			t.Fatalf("explicit trust override should permit the RIO route:\n%s", got)
		}
	})
}
