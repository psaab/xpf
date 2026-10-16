package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestHostInboundRedirectIsNotGlobalAccept13982(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint8
		want bool
	}{
		{name: "router solicitation remains global", typ: 133, want: true},
		{name: "neighbor advertisement remains global", typ: 136, want: true},
		{name: "redirect cannot install firewall route exception", typ: 137, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInboundGlobalAccept(config.HostInboundProtoICMPv6, &tc.typ, "ip6")
			if got != tc.want {
				t.Fatalf("hostInboundGlobalAccept(ICMPv6 type %d) = %t, want %t", tc.typ, got, tc.want)
			}
		})
	}
}
