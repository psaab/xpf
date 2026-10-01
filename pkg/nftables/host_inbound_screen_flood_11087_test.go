package nftables

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestHostInboundScreenFloodRulesCoalesceZoneViews11087(t *testing.T) {
	views := []HostInboundZoneView{
		{
			Zone:                 "trust",
			V4Addrs:              []string{"10.0.0.1"},
			V6Addrs:              []string{"2001:db8::1"},
			IngressNetdevs:       []string{"ge-0-0-0"},
			ICMPFloodThreshold:   30,
			UDPFloodThreshold:    20,
			SYNFloodThreshold:    100,
			SYNFloodSrcThreshold: 5,
			AlarmWithoutDrop:     true,
		},
		{
			Zone:                 "trust",
			V4Addrs:              []string{"10.0.1.1"},
			V6Addrs:              []string{"2001:db8::2"},
			IngressNetdevs:       []string{"ge-0-0-1"},
			ICMPFloodThreshold:   30,
			UDPFloodThreshold:    20,
			SYNFloodThreshold:    100,
			SYNFloodSrcThreshold: 5,
			AlarmWithoutDrop:     true,
		},
	}
	rules := HostInboundScreenFloodRules(views)
	if len(rules) != 6 {
		t.Fatalf("flood rules = %d, want 6 (three protocols per family): %+v", len(rules), rules)
	}
	for _, rule := range rules {
		if rule.Zone != "trust" || !rule.AlarmWithoutDrop {
			t.Errorf("rule lost zone/alarm profile: %+v", rule)
		}
		if len(rule.IngressNetdevs) != 2 || rule.IngressNetdevs[0] != "ge-0-0-0" || rule.IngressNetdevs[1] != "ge-0-0-1" {
			t.Errorf("zone ingress scopes were not coalesced: %+v", rule.IngressNetdevs)
		}
		switch rule.Protocol {
		case "udp":
			if rule.AggregateThreshold != 160 || rule.SourceThreshold != 20 {
				t.Errorf("UDP thresholds = %d/%d, want 160/20 (8x zone ceiling/per-source)", rule.AggregateThreshold, rule.SourceThreshold)
			}
		case "icmp", "icmpv6":
			if rule.AggregateThreshold != 240 || rule.SourceThreshold != 30 {
				t.Errorf("%s thresholds = %d/%d, want 240/30 (8x zone ceiling/per-source)", rule.Protocol, rule.AggregateThreshold, rule.SourceThreshold)
			}
		case "tcp-syn":
			if rule.AggregateThreshold != 100 || rule.SourceThreshold != 5 {
				t.Errorf("SYN thresholds = %d/%d, want 100/5", rule.AggregateThreshold, rule.SourceThreshold)
			}
		default:
			t.Errorf("unexpected protocol %q", rule.Protocol)
		}
	}
}

func TestHostInboundScreenFloodOptionalThresholdsAndSaturation11087(t *testing.T) {
	const maxUint32 = ^uint32(0)
	for _, tc := range []struct {
		name      string
		udp       uint32
		wantUDP   uint32
		syn       uint32
		synSource uint32
	}{
		{name: "udp zone ceiling", udp: 1, wantUDP: 8},
		{name: "udp ceiling saturates", udp: maxUint32, wantUDP: maxUint32},
		{name: "syn source threshold remains optional", syn: 10},
		{name: "syn source threshold is preserved", syn: 10, synSource: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := HostInboundScreenFloodRules([]HostInboundZoneView{{
				Zone:                 "wan",
				IngressNetdevs:       []string{"ge-0-0-9"},
				UDPFloodThreshold:    tc.udp,
				SYNFloodThreshold:    tc.syn,
				SYNFloodSrcThreshold: tc.synSource,
			}})
			for _, rule := range rules {
				switch rule.Protocol {
				case "udp":
					if rule.AggregateThreshold != tc.wantUDP || rule.SourceThreshold != tc.udp {
						t.Errorf("UDP thresholds = %d/%d, want %d/%d", rule.AggregateThreshold, rule.SourceThreshold, tc.wantUDP, tc.udp)
					}
				case "tcp-syn":
					if rule.AggregateThreshold != tc.syn || rule.SourceThreshold != tc.synSource {
						t.Errorf("SYN thresholds = %d/%d, want %d/%d", rule.AggregateThreshold, rule.SourceThreshold, tc.syn, tc.synSource)
					}
				default:
					t.Errorf("unexpected screen protocol %q", rule.Protocol)
				}
			}
			if len(rules) != 2 {
				t.Fatalf("normalized rules = %d, want one per active protocol and family: %+v", len(rules), rules)
			}
		})
	}
}
func TestHostInboundScreenFloodNetlinkShape11087(t *testing.T) {
	views := []HostInboundZoneView{{
		Zone:                 "wan",
		IngressNetdevs:       []string{"ge-0-0-9"},
		UDPFloodThreshold:    2,
		SYNFloodThreshold:    10,
		SYNFloodSrcThreshold: 3,
		AlarmWithoutDrop:     true,
	}}
	spec := HostInboundSpec{Views: views}
	p := newBuildPlan(t, "xpf_11087", hostInboundPriority)
	buildHostInboundNetlink(p, spec)
	if p.err != nil {
		t.Fatalf("build screen flood netlink plan: %v", p.err)
	}
	if p.chain.Hooknum == nil || *p.chain.Hooknum != *gnft.ChainHookInput {
		t.Fatalf("screen backstop hook = %v, want input", p.chain.Hooknum)
	}
	rules := HostInboundScreenFloodRules(views)
	if len(rules) != 4 {
		t.Fatalf("normalized rules = %d, want UDP+SYN for both families: %+v", len(rules), rules)
	}
	if len(p.screenFloodSets) != 8 {
		t.Fatalf("dynamic meter sets = %d, want source+aggregate UDP and SYN meters for both families: %+v", len(p.screenFloodSets), p.screenFloodSets)
	}

	expectedRates := make(map[string]uint32)
	expectedFamilies := make(map[string]byte)
	for _, rule := range rules {
		family := screenFloodFamily(rule).nfproto
		aggregateName := HostInboundScreenFloodAggregateSetName(rule)
		aggregate := p.screenFloodSets[aggregateName]
		if rule.AggregateThreshold > 0 {
			expectedRates[aggregateName] = rule.AggregateThreshold
			expectedFamilies[aggregateName] = family
			if aggregate == nil || !aggregate.Dynamic || !aggregate.HasTimeout || aggregate.Timeout != HostInboundScreenFloodMeterTimeout || aggregate.Size != 1 || aggregate.KeyType != gnft.TypeMark {
				t.Errorf("aggregate meter has wrong bound/key type: %+v", aggregate)
			}
		} else if aggregate != nil {
			t.Errorf("unexpected aggregate meter for per-source screen: %+v", aggregate)
		}
		sourceName := HostInboundScreenFloodSetName(rule)
		source := p.screenFloodSets[sourceName]
		if rule.SourceThreshold > 0 {
			expectedRates[sourceName] = rule.SourceThreshold
			expectedFamilies[sourceName] = family
			wantSourceType := gnft.TypeIPAddr
			if rule.Family == "ip6" {
				wantSourceType = gnft.TypeIP6Addr
			}
			if source == nil || !source.Dynamic || !source.HasTimeout || source.Timeout != HostInboundScreenFloodMeterTimeout || source.Size != HostInboundScreenFloodMeterSize || source.KeyType != wantSourceType {
				t.Errorf("source meter has wrong bound/key type: %+v", source)
			}
		} else if source != nil {
			t.Errorf("unexpected source meter without configured source threshold: %+v", source)
		}
	}

	var dynsets int
	for _, emitted := range p.rules {
		for i, e := range emitted {
			dynset, ok := e.(*expr.Dynset)
			if !ok {
				continue
			}
			dynsets++
			if len(dynset.Exprs) != 1 {
				t.Fatalf("dynset %q nested exprs = %d, want one rate limit", dynset.SetName, len(dynset.Exprs))
			}
			limit, ok := dynset.Exprs[0].(*expr.Limit)
			wantRate := expectedRates[dynset.SetName]
			if !ok || wantRate == 0 || !limit.Over || limit.Rate != uint64(wantRate) || limit.Burst != wantRate || limit.Unit != expr.LimitTimeSecond {
				t.Errorf("dynset %q limit = %#v, want over %d/second burst %d", dynset.SetName, dynset.Exprs[0], wantRate, wantRate)
			}
			wantFamily, known := expectedFamilies[dynset.SetName]
			if !known {
				t.Errorf("dynset %q has no expected IP family", dynset.SetName)
			} else {
				familyGuarded := false
				for j := 0; j+1 < i; j++ {
					meta, ok := emitted[j].(*expr.Meta)
					if !ok || meta.Key != expr.MetaKeyNFPROTO {
						continue
					}
					cmp, ok := emitted[j+1].(*expr.Cmp)
					if ok && cmp.Op == expr.CmpOpEq && cmp.Register == meta.Register && len(cmp.Data) == 1 && cmp.Data[0] == wantFamily {
						familyGuarded = true
						break
					}
				}
				if !familyGuarded {
					t.Errorf("mixed-family ingress dynset %q lacks a preceding nfproto=%d guard", dynset.SetName, wantFamily)
				}
			}
			if strings.HasPrefix(dynset.SetName, "xpf_his_a_") {
				if i == 0 {
					t.Errorf("aggregate meter lacks constant key: %s", dynset.SetName)
					continue
				}
				key, ok := emitted[i-1].(*expr.Immediate)
				if !ok || key.Register != 1 || len(key.Data) != 4 || key.Data[0] != 0 || key.Data[1] != 0 || key.Data[2] != 0 || key.Data[3] != 0 {
					t.Errorf("aggregate meter key = %#v, want constant integer zero", emitted[i-1])
				}
			} else if strings.HasPrefix(dynset.SetName, "xpf_his_s_") {
				if i == 0 {
					t.Errorf("source meter lacks source-address key: %s", dynset.SetName)
					continue
				}
				key, ok := emitted[i-1].(*expr.Payload)
				wantOffset, wantLength := uint32(12), uint32(4)
				if sourceSet := p.screenFloodSets[dynset.SetName]; sourceSet != nil && sourceSet.KeyType == gnft.TypeIP6Addr {
					wantOffset, wantLength = 8, 16
				}
				if !ok || key.DestRegister != 1 || key.Base != expr.PayloadBaseNetworkHeader {
					t.Errorf("source meter key = %#v, want network-header source payload", emitted[i-1])
				} else if key.Offset != wantOffset || key.Len != wantLength {
					t.Errorf("source key offset/length = %d/%d, want %d/%d", key.Offset, key.Len, wantOffset, wantLength)
				}
			}
		}
	}
	if dynsets != 16 {
		t.Fatalf("dynset expressions = %d, want source+aggregate UDP and SYN meters in both rule phases", dynsets)
	}
	var alarmLogs, alarmLimits int
	for _, emitted := range p.rules {
		for _, e := range emitted {
			switch v := e.(type) {
			case *expr.Log:
				alarmLogs++
				wantLogKey := uint32(1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_LEVEL)
				if v.Level != expr.LogLevelWarning || v.Key&wantLogKey != wantLogKey || !strings.Contains(string(v.Data), "xpf screen flood ") {
				}
			case *expr.Limit:
				if !v.Over && v.Rate == 1 && v.Burst == 1 && v.Unit == expr.LimitTimeSecond {
					alarmLimits++
				}
			}
		}
	}
	if alarmLogs != 16 || alarmLimits != 16 {
		t.Fatalf("rate-limited alarm expressions = %d logs/%d limits, want 16/16", alarmLogs, alarmLimits)
	}
}

func TestHostInboundEstablishedUDPFloodDropsAboveThreshold11087(t *testing.T) {
	enterPrivateNetns(t)
	parentNS, err := netns.Get()
	if err != nil {
		t.Fatalf("read parent netns: %v", err)
	}
	defer parentNS.Close()
	clientNS, err := netns.New()
	if err != nil {
		t.Skipf("cannot create client netns: %v", err)
	}
	t.Cleanup(func() { _ = clientNS.Close() })
	if err := netns.Set(parentNS); err != nil {
		t.Fatalf("restore parent netns: %v", err)
	}

	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = "xpf11087fw"
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: linkAttrs, PeerName: "xpf11087cl"}); err != nil {
		t.Skipf("cannot create veth pair: %v", err)
	}
	fw, err := netlink.LinkByName("xpf11087fw")
	if err != nil {
		t.Fatalf("find firewall veth: %v", err)
	}
	client, err := netlink.LinkByName("xpf11087cl")
	if err != nil {
		t.Fatalf("find client veth: %v", err)
	}
	if err := netlink.LinkSetNsFd(client, int(clientNS)); err != nil {
		t.Skipf("cannot move client veth into its namespace: %v", err)
	}
	addr, err := netlink.ParseAddr("192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(fw, addr); err != nil {
		t.Fatalf("assign firewall address: %v", err)
	}
	if err := netlink.LinkSetUp(fw); err != nil {
		t.Fatalf("bring up firewall veth: %v", err)
	}
	withFloodNetns11087(t, clientNS, func() {
		client, err := netlink.LinkByName("xpf11087cl")
		if err != nil {
			t.Fatalf("find client veth in peer namespace: %v", err)
		}
		addr, err := netlink.ParseAddr("192.0.2.2/24")
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(client, addr); err != nil {
			t.Fatalf("assign client address: %v", err)
		}
		if err := netlink.LinkSetUp(client); err != nil {
			t.Fatalf("bring up client veth: %v", err)
		}
	})

	if err := NewNetlinkInstaller().InstallHostInbound(HostInboundSpec{Views: []HostInboundZoneView{{
		Zone:              "wan",
		SystemServices:    []string{"any-service"},
		IngressNetdevs:    []string{"xpf11087fw"},
		UDPFloodThreshold: 3,
	}}}); err != nil {
		t.Fatalf("install flood backstop: %v", err)
	}

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 19087})
	if err != nil {
		t.Fatalf("listen on firewall address: %v", err)
	}
	defer receiver.Close()
	seedReady := make(chan error, 1)
	sendErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		oldNS, err := netns.Get()
		if err != nil {
			seedReady <- fmt.Errorf("read sender netns: %w", err)
			return
		}
		defer oldNS.Close()
		if err := netns.Set(clientNS); err != nil {
			seedReady <- fmt.Errorf("enter client netns: %w", err)
			return
		}
		defer func() { _ = netns.Set(oldNS) }()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.2")})
		if err != nil {
			seedReady <- fmt.Errorf("bind client UDP socket: %w", err)
			return
		}
		defer conn.Close()
		server := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 19087}
		if _, err := conn.WriteToUDP([]byte("seed"), server); err != nil {
			seedReady <- fmt.Errorf("send seed packet: %w", err)
			return
		}
		seedReady <- nil
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			sendErr <- fmt.Errorf("set client reply deadline: %w", err)
			return
		}
		if _, _, err := conn.ReadFromUDP(make([]byte, 16)); err != nil {
			sendErr <- fmt.Errorf("receive seed reply: %w", err)
			return
		}
		for i := range 3 {
			if _, err := conn.WriteToUDP([]byte{byte(i)}, server); err != nil {
				sendErr <- fmt.Errorf("send flood packet %d: %w", i+1, err)
				return
			}
		}
		sendErr <- nil
	}()
	if err := <-seedReady; err != nil {
		t.Fatalf("establish UDP flow: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set seed receive deadline: %v", err)
	}
	if _, peer, err := receiver.ReadFromUDP(make([]byte, 16)); err != nil {
		t.Fatalf("seed packet did not reach the local UDP service: %v", err)
	} else if _, err := receiver.WriteToUDP([]byte("reply"), peer); err != nil {
		t.Fatalf("reply to seed packet: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("send established UDP flow flood: %v", err)
	}
	for i := range 2 {
		if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set receive deadline: %v", err)
		}
		if _, _, err := receiver.ReadFromUDP(make([]byte, 16)); err != nil {
			t.Fatalf("packet %d did not reach the local UDP service before threshold: %v", i+1, err)
		}
	}
	if err := receiver.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set flood-drop deadline: %v", err)
	}
	if _, _, err := receiver.ReadFromUDP(make([]byte, 16)); err == nil {
		t.Fatal("third packet on the established UDP flow reached the local service above threshold")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("waiting for threshold drop: %v", err)
	}

}

func withFloodNetns11087(t *testing.T, ns netns.NsHandle, fn func()) {
	t.Helper()
	oldNS, err := netns.Get()
	if err != nil {
		t.Fatalf("read current netns: %v", err)
	}
	defer oldNS.Close()
	if err := netns.Set(ns); err != nil {
		t.Fatalf("enter requested netns: %v", err)
	}
	defer func() {
		if err := netns.Set(oldNS); err != nil {
			t.Errorf("restore netns: %v", err)
		}
	}()
	fn()
}
