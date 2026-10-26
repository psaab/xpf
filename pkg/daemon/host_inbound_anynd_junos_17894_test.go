package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// The daemon text oracle mirrors the production ordering for an any-service
// view whose zone has a fine junos-host terminal drop. Keep the mixed-zone
// behavior (and the no-program / ndp-except controls) aligned with netlink.
func TestHostInboundAnyServiceNDBeforeJunosJumpText17894(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{Zone: "untrust", SystemServices: []string{"any-service"}, V6Addrs: []string{"2001:db8:2::10"}, IngressNetdevs: []string{"ge-0-0-1"}},
		{Zone: "trust", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8:1::10"}, IngressNetdevs: []string{"ge-0-0-0"}},
		{Zone: "except", SystemServices: []string{"ssh"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:3::10"}, IngressNetdevs: []string{"ge-0-0-2"}},
		{Zone: "open", SystemServices: []string{"any-service"}, V6Addrs: []string{"2001:db8:4::10"}, IngressNetdevs: []string{"ge-0-0-3"}},
	}
	programs := []dpuserspace.JunosHostProgram{{
		Zone:           "untrust",
		IngressIfnames: []string{"ge-0-0-1"},
		RulesV6: []config.JunosHostDenyRule{
			{Family: "ip6", SrcAny: true, DstAny: true, Verdict: config.JunosHostDrop},
		},
	}}
	payload := buildHostInboundFilterPayload(views, nil, nil, programs, nil, true)
	jump := `iifname "ge-0-0-1" jump ` + xnft.HostInboundJunosHostChainName(0, "untrust")
	jumpAt := strings.Index(payload, jump)
	if jumpAt < 0 {
		t.Fatalf("untrust junos-host jump missing:\n%s", payload)
	}
	ndCounter := `counter name "` + xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptICMP6ND) + `"`
	anyNDAt := -1
	openNDAt := -1
	for _, line := range ndLines15931(payload) {
		if !strings.Contains(line, ndCounter) {
			continue
		}
		at := strings.Index(payload, line)
		switch {
		case strings.Contains(line, `"ge-0-0-1"`):
			if anyNDAt < 0 {
				anyNDAt = at
			}
		case strings.Contains(line, `"ge-0-0-3"`):
			if openNDAt < 0 {
				openNDAt = at
			}
		case strings.Contains(line, `"ge-0-0-2"`):
			t.Fatalf("ndp-except view got an ND accept: %q", line)
		}
	}
	if anyNDAt < 0 || anyNDAt >= jumpAt {
		t.Fatalf("any-service ND accept must precede the untrust junos-host jump; accept=%d jump=%d:\n%s", anyNDAt, jumpAt, payload)
	}
	if openNDAt >= 0 && openNDAt < jumpAt {
		t.Fatalf("any-service view without a fine program gained an early ND accept; accept=%d jump=%d:\n%s", openNDAt, jumpAt, payload)
	}
}
