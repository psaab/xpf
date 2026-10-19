package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13982 (retained): Redirect 137 is never a global accept.
// #15671: ND 133-136 likewise left the unconditional accept — they
// ride the ndp default exemption (hostInboundIsNDP), so this
// predicate must not admit them either.
func TestHostInboundRedirectIsNotGlobalAccept13982(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint8
		want bool
	}{
		{name: "router solicitation not unconditional (ndp default)", typ: 133, want: false},
		{name: "neighbor advertisement not unconditional (ndp default)", typ: 136, want: false},
		{name: "redirect cannot install firewall route exception", typ: 137, want: false},
		{name: "packet too big remains global", typ: 2, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInboundGlobalAccept(config.HostInboundProtoICMPv6, &tc.typ, "ip6")
			if got != tc.want {
				t.Fatalf("hostInboundGlobalAccept(ICMPv6 type %d) = %t, want %t", tc.typ, got, tc.want)
			}
			if tc.typ >= 133 && tc.typ <= 136 && !hostInboundIsNDP(config.HostInboundProtoICMPv6, tc.typ, "ip6") {
				t.Fatalf("hostInboundIsNDP(type %d) = false, want true (#15671 ND predicate)", tc.typ)
			}
		})
	}
}
