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
		case strings.Contains(line, `"ge-0-0-1"`) && strings.Contains(line, "2001:db8:2::10"):
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

func TestHostInboundAnyServiceNDICMPScreenBeforeJunosJumpText17894(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:               "untrust",
			SystemServices:     []string{"any-service"},
			V4Addrs:            []string{"192.0.2.10"},
			V6Addrs:            []string{"2001:db8:2::10"},
			ICMPFloodThreshold: 3,
			IngressNetdevs:     []string{"ge-0-0-1"},
		},
		{
			Zone:           "trust",
			SystemServices: []string{"ssh"},
			V4Addrs:        []string{"192.0.2.1"},
			V6Addrs:        []string{"2001:db8:1::10"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
	}
	programs := []dpuserspace.JunosHostProgram{{
		Zone:           "untrust",
		IngressIfnames: []string{"ge-0-0-1"},
		RulesV4: []config.JunosHostDenyRule{
			{Family: "ip", SrcAny: true, DstAny: true, Verdict: config.JunosHostDrop},
		},
	}}
	payload := buildHostInboundFilterPayload(views, nil, nil, programs, nil, true)
	ndAt, jumpAt := -1, strings.Index(payload, `iifname "ge-0-0-1" jump `+xnft.HostInboundJunosHostChainName(0, "untrust"))
	for _, line := range ndLines15931(payload) {
		if strings.Contains(line, `"ge-0-0-1"`) && strings.Contains(line, "2001:db8:2::10") {
			ndAt = strings.Index(payload, line)
			break
		}
	}
	if jumpAt < 0 || ndAt < 0 || ndAt >= jumpAt {
		t.Fatalf("untrust ND accept must remain before the fine junos-host jump (ND=%d jump=%d):\n%s", ndAt, jumpAt, payload)
	}
	err6At := strings.Index(payload, `counter name "`+xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptICMP6Error)+`"`)
	err4At := strings.Index(payload, `counter name "`+xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptICMP4Error)+`"`)
	if err6At < 0 || err4At < 0 {
		t.Fatalf("mandatory ICMP accepts missing (v6=%d v4=%d):\n%s", err6At, err4At, payload)
	}
	seenV4, seenV6 := false, false
	lines := strings.Split(payload, "\n")
	for _, screen := range xnft.HostInboundScreenFloodRules(toNftViews(views)) {
		if screen.Protocol != "icmp" && screen.Protocol != "icmpv6" {
			continue
		}
		switch screen.Protocol {
		case "icmp":
			seenV4 = true
		case "icmpv6":
			seenV6 = true
		}
		for _, source := range []bool{true, false} {
			name := xnft.HostInboundScreenFloodCounterName(screen, source)
			count, replyCount, originalAt := 0, 0, -1
			for _, line := range lines {
				if !strings.Contains(line, `counter name "`+name+`"`) {
					continue
				}
				count++
				if !strings.HasSuffix(line, " drop") {
					t.Fatalf("%s screen must retain its over-threshold drop action: %s", name, line)
				}
				if strings.Contains(line, "ct state established,related ct direction reply") {
					replyCount++
				} else {
					originalAt = strings.Index(payload, line)
				}
			}
			if count != 2 || replyCount != 1 || originalAt < 0 {
				t.Fatalf("%s meters need exactly one reply and one original-direction rule (count=%d reply=%d original=%d):\n%s",
					name, count, replyCount, originalAt, payload)
			}
			if originalAt >= err6At || originalAt >= err4At || originalAt >= ndAt {
				t.Fatalf("%s original-direction screen must run before every mandatory ICMP/ND accept; screen=%d mandatory-v6=%d mandatory-v4=%d ND=%d",
					name, originalAt, err6At, err4At, ndAt)
			}
		}
	}
	if !seenV4 || !seenV6 {
		t.Fatalf("fixture must exercise both IPv4 and IPv6 ICMP screens (v4=%t v6=%t)", seenV4, seenV6)
	}
}
