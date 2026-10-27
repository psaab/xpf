package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundScreenFloodTextOrder11087(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{{
		Zone:                 "wan",
		IngressNetdevs:       []string{"ge-0-0-0"},
		ICMPFloodThreshold:   5,
		UDPFloodThreshold:    3,
		SYNFloodThreshold:    11,
		SYNFloodSrcThreshold: 2,
	}}
	programs := []dpuserspace.JunosHostProgram{{
		Zone:           "wan",
		IngressIfnames: []string{"ge-0-0-0"},
	}}
	payload := buildHostInboundFilterPayload(views, nil, nil, programs, nil, true)
	if !strings.Contains(payload, "type filter hook input") || strings.Contains(payload, "hook forward") {
		t.Fatalf("host-inbound screens must remain input-only (transit path unchanged):\n%s", payload)
	}

	v4UDP := xnft.HostInboundScreenFloodRule{Zone: "wan", Family: "ip", Protocol: "udp", SourceThreshold: 3}
	replyScreen := "ct state established,related ct direction reply iifname \"ge-0-0-0\" meta nfproto ipv4 meta l4proto 17 update @" +
		xnft.HostInboundScreenFloodSetName(v4UDP) + " { ip saddr limit rate over 3/second burst 3 packets } counter name \"" +
		xnft.HostInboundScreenFloodCounterName(v4UDP, true) + "\" drop"
	if !strings.Contains(payload, "    "+replyScreen) {
		t.Fatalf("reply-direction per-source screen is missing its ingress-family guard:\n%s", payload)
	}
	v6UDP := xnft.HostInboundScreenFloodRule{Zone: "wan", Family: "ip6", Protocol: "udp", SourceThreshold: 3}
	v6ReplyScreen := "ct state established,related ct direction reply iifname \"ge-0-0-0\" meta nfproto ipv6 meta l4proto 17 update @" +
		xnft.HostInboundScreenFloodSetName(v6UDP) + " { ip6 saddr limit rate over 3/second burst 3 packets } counter name \"" +
		xnft.HostInboundScreenFloodCounterName(v6UDP, true) + "\" drop"
	if !strings.Contains(payload, "    "+v6ReplyScreen) {
		t.Fatalf("mixed-family ingress v6 screen is missing its family guard:\n%s", payload)
	}
	replyAggregate := "ct state established,related ct direction reply iifname \"ge-0-0-0\" meta nfproto ipv4 meta l4proto 17 update @" +
		xnft.HostInboundScreenFloodAggregateSetName(v4UDP) + " { 0 limit rate over 24/second burst 24 packets } counter name \"" +
		xnft.HostInboundScreenFloodCounterName(v4UDP, false) + "\" drop"
	if !strings.Contains(payload, "    "+replyAggregate) {
		t.Fatalf("reply-direction 8x zone ceiling is missing:\n%s", payload)
	}
	replyAcceptRule := "    ct state established,related ct direction reply accept"
	replyAccept := strings.Index(payload, replyAcceptRule)
	replyRule := strings.Index(payload, "    "+replyScreen)
	replyAggregateRule := strings.Index(payload, "    "+replyAggregate)
	if replyRule < 0 || replyAggregateRule < 0 || replyAccept < 0 || replyRule >= replyAggregateRule || replyAggregateRule >= replyAccept {
		t.Fatalf("reply per-source then zone-ceiling screens must precede the early reply accept (source=%d aggregate=%d accept=%d):\n%s", replyRule, replyAggregateRule, replyAccept, payload)
	}
	fineJump := strings.Index(payload, "    iifname \"ge-0-0-0\" jump ")
	afterReplyOffset, afterReply := 0, ""
	if replyAccept >= 0 {
		afterReplyOffset = replyAccept + len(replyAcceptRule)
		afterReply = payload[afterReplyOffset:]
	}
	originalRule := strings.Index(afterReply, "    iifname \"ge-0-0-0\" meta nfproto ipv4 meta l4proto 17 update @")
	originalICMPv4 := strings.Index(afterReply, "    iifname \"ge-0-0-0\" meta nfproto ipv4 meta l4proto 1 update @")
	originalICMPv6 := strings.Index(afterReply, "    iifname \"ge-0-0-0\" meta nfproto ipv6 meta l4proto 58 update @")
	if originalRule >= 0 {
		originalRule += afterReplyOffset
	}
	if originalICMPv4 >= 0 {
		originalICMPv4 += afterReplyOffset
	}
	if originalICMPv6 >= 0 {
		originalICMPv6 += afterReplyOffset
	}
	globalICMPv6 := strings.Index(payload, "    icmpv6 type { 1, 2, 3, 4 }")
	globalICMPv4 := strings.Index(payload, "    icmp type { destination-unreachable, time-exceeded, parameter-problem }")
	// #17894: original-direction ICMP screens precede mandatory ICMP accepts,
	// while UDP/SYN screens remain after fine policy without duplicate rules.
	if fineJump < replyAccept || originalRule <= fineJump ||
		originalICMPv6 < 0 || originalICMPv6 >= globalICMPv6 ||
		originalICMPv4 < 0 || originalICMPv4 >= globalICMPv4 ||
		globalICMPv6 < 0 || globalICMPv6 >= fineJump ||
		globalICMPv4 < 0 || globalICMPv4 >= fineJump {
		t.Fatalf("mandatory ICMP accepts must follow ICMP screens and precede the fine jump; UDP/SYN screens follow fine policy (jump=%d UDP=%d ICMPv4Screen=%d ICMPv4Accept=%d ICMPv6Screen=%d ICMPv6Accept=%d):\n%s",
			fineJump, originalRule, originalICMPv4, globalICMPv4, originalICMPv6, globalICMPv6, payload)
	}
	for _, fragment := range []string{
		"meta nfproto ipv4",
		"meta nfproto ipv6",
		"ip saddr limit rate over 2/second burst 2 packets",
		"ip6 saddr limit rate over 2/second burst 2 packets",
		"meta l4proto 1",
		"meta l4proto 58",
		"tcp flags & (syn | ack) == syn",
		"limit rate over 11/second burst 11 packets",
	} {
		if !strings.Contains(payload, fragment) {
			t.Errorf("screen profile rule missing %q:\n%s", fragment, payload)
		}
	}
}

func TestHostInboundScreenFloodAlarmWithoutDrop11087(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{{
		Zone:              "wan",
		IngressNetdevs:    []string{"ge-0-0-0"},
		UDPFloodThreshold: 3,
		AlarmWithoutDrop:  true,
	}}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	count := 0
	for _, line := range strings.Split(payload, "\n") {
		if !strings.Contains(line, "update @") {
			continue
		}
		count++
		if strings.HasSuffix(line, " drop") {
			t.Errorf("alarm-without-drop flood rule terminates with drop: %s", line)
		}
		if !strings.Contains(line, "counter name \"xpf_his_c_") {
			t.Errorf("alarm-without-drop flood rule lacks an over-threshold counter: %s", line)
		}
		if !strings.Contains(line, " log prefix \"xpf screen flood udp/") || !strings.HasSuffix(line, " level warn") {
			t.Errorf("alarm-without-drop flood rule lacks a rate-limited kernel alarm: %s", line)
		}
	}
	if count != 8 {
		t.Fatalf("screen meter rules = %d, want source+aggregate in both directions and families", count)
	}
}
