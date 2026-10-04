package daemon

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundBoxOrientedConntrackFlush10752And10764(t *testing.T) {
	// Both zones deny SSH/IKE so no ingress view permits the tuple: the
	// wan box-oriented entries are denied by owner AND every ingress and
	// must flush. hostInboundFlushTestConfig opens lan to any-service, so
	// tighten it here to isolate the owner-denied case.
	cfg := hostInboundFlushTestConfig("snmp")
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"snmp"}}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if filter == nil {
		t.Fatal("expected a filter for the enforcing configuration")
	}
	for _, tc := range []struct {
		name string
		flow *netlink.ConntrackFlow
		want bool
	}{
		{"tcp-ssh-box-originated", boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 22), true},
		{"udp-ike-500-box-originated", boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 500), true},
		{"udp-ike-4500-box-originated", boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 4500), true},
		{"ipv6-udp-ike-box-originated", boxOrientedFlow(config.HostInboundProtoUDP, "2001:db8:50::8", 500), true},
		{"tcp-ephemeral-egress", boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 41000), false},
		{"udp-ntp-client", boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 123), false},
		{"udp-dhcp-client", boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 67), false},
		{"tcp-bgp-client", boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 179), false},
		{"lifeline-source", boxOrientedFlow(config.HostInboundProtoUDP, "10.0.0.1", 500), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := filter.MatchConntrackFlow(tc.flow); got != tc.want {
				t.Fatalf("MatchConntrackFlow(%+v) = %v, want %v", tc.flow.Forward, got, tc.want)
			}
		})
	}

	admittedCfg := hostInboundFlushTestConfig("ssh", "ike", "snmp")
	admittedCfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"snmp"}}
	admittedViews := dpuserspace.BuildZoneHostInboundViews(admittedCfg)
	admittedV4, admittedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(admittedCfg)
	admitted := buildHostInboundConntrackFlushFilter(admittedViews, admittedV4, admittedV6, nil)
	for _, flow := range []*netlink.ConntrackFlow{
		boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 22),
		boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 500),
		boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 4500),
	} {
		if admitted.MatchConntrackFlow(flow) {
			t.Errorf("still-admitted box-oriented tuple %+v was selected for flush", flow.Forward)
		}
	}
	identResetCfg := hostInboundFlushTestConfig("ident-reset")
	identResetCfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"snmp"}}
	identViews := dpuserspace.BuildZoneHostInboundViews(identResetCfg)
	identV4, identV6 := dpuserspace.BuildUnzonedHostInboundAddrs(identResetCfg)
	identFilter := buildHostInboundConntrackFlushFilter(identViews, identV4, identV6, nil)
	if !identFilter.MatchConntrackFlow(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 113)) {
		t.Fatal("ident-reset is a reject, not an admit; box-oriented TCP/113 must remain flushable")
	}
}

func TestHostInboundBoxOrientedFlushRespectsIngressPermits10752(t *testing.T) {
	// Ingress-permits/owner-denies: wan denies SSH/IKE but lan is open, so
	// some ingress zone still permits the tuple to the wan address. The
	// flush must keep the entry (no disruption); the per-ingress nft guard
	// judges each reply packet by its actual arrival zone.
	cfg := hostInboundFlushTestConfig("snmp")
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if filter == nil {
		t.Fatal("expected a filter for the enforcing configuration")
	}
	for _, flow := range []*netlink.ConntrackFlow{
		boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 22),
		boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 500),
		boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 4500),
		boxOrientedFlow(config.HostInboundProtoUDP, "2001:db8:50::8", 500),
	} {
		if filter.MatchConntrackFlow(flow) {
			t.Errorf("ingress-permitted box-oriented tuple %+v must be kept, not flushed", flow.Forward)
		}
	}
	// Admitted-client control: ephemeral and NTP/DHCP client tuples are kept
	// regardless of ingress policy.
	for _, flow := range []*netlink.ConntrackFlow{
		boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 41000),
		boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 123),
	} {
		if filter.MatchConntrackFlow(flow) {
			t.Errorf("client tuple %+v must be kept", flow.Forward)
		}
	}
}
func TestHostInboundNonCatalogTCPStatusQuo10752(t *testing.T) {
	// Sec2 A: custom/non-SSOT TCP (2222 models any any-service-admitted
	// custom port) is neither flushed box-oriented nor guarded — in BOTH
	// generations. Pre-PR the predicate was DstIP-only with no box-oriented
	// branch, so box 2222 (DstIP=peer, never in the admit map) was kept
	// identically; post-PR the catalog miss keeps it. Peer-oriented 2222
	// flushes in both via the unchanged destination branch. This pins the
	// documented HIGH residual (idle-expiry, indefinite sustain under active
	// traffic) against silent drift in either direction; same for the TCP
	// client-role exempt 179 (tuple ambiguity with box-originated BGP).
	cfg := hostInboundFlushTestConfig("snmp")
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"snmp"}}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, nil)
	if filter == nil {
		t.Fatal("expected a filter for the enforcing configuration")
	}
	if !filter.MatchConntrackFlow(ctFlow(config.HostInboundProtoTCP, "172.16.50.8", 2222)) {
		t.Error("peer-oriented custom TCP/2222 to a denying owner must flush (both generations)")
	}
	for _, flow := range []*netlink.ConntrackFlow{
		boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 2222),
		boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 179),
	} {
		if filter.MatchConntrackFlow(flow) {
			t.Errorf("box-oriented %+v must be kept (documented non-catalog/TCP-exempt HIGH residual)", flow.Forward)
		}
	}
	payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
	for _, line := range strings.Split(payload, "\n") {
		if !isGuardDrop(line) {
			continue
		}
		for _, port := range []uint16{2222, 179} {
			if strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, port) {
				t.Errorf("non-catalog/TCP-exempt port %d must never appear in a guard DROP: %s", port, line)
			}
		}
	}
}
func TestHostInboundReplyDropsAreCatalogBounded10752(t *testing.T) {
	// Structural proof for ephemeral/range WARN silence: no host-inbound
	// chain, however tight, can drop a reply-direction non-catalog tuple —
	// every reply-direction DROP's dports are a subset of the catalog, and
	// the broad reply accept admits the rest unconditionally. Ephemeral
	// replies are therefore policy-invariant authorized under every config,
	// so warning on them would fire on ordinary egress. Rendered for both
	// an open-ingress and a fully tightened config.
	for _, lanServices := range [][]string{{"any-service"}, {"snmp"}} {
		cfg := hostInboundFlushTestConfig("snmp")
		cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: lanServices}
		views := dpuserspace.BuildZoneHostInboundViews(cfg)
		unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
		payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
		if !strings.Contains(payload, "ct state established,related ct direction reply accept") {
			t.Fatalf("lan=%v: broad reply accept missing:\n%s", lanServices, payload)
		}
		guards := 0
		for _, line := range strings.Split(payload, "\n") {
			if !isGuardDrop(line) {
				continue
			}
			guards++
			var family, proto string
			switch {
			case strings.Contains(line, " ip daddr "):
				family = "ip"
			case strings.Contains(line, " ip6 daddr "):
				family = "ip6"
			default:
				t.Fatalf("lan=%v: guard without family daddr: %s", lanServices, line)
			}
			switch {
			case strings.Contains(line, " tcp dport "):
				proto = "tcp"
			case strings.Contains(line, " udp dport "):
				proto = "udp"
			default:
				t.Fatalf("lan=%v: guard without TCP/UDP dport: %s", lanServices, line)
			}
			spec := line[strings.Index(line, " dport ")+len(" dport "):]
			if end := strings.LastIndex(spec, " drop"); end >= 0 {
				spec = spec[:end]
			}
			if strings.Contains(spec, "-") {
				t.Fatalf("lan=%v: guard dport range (catalog is discrete-only): %s", lanServices, line)
			}
			catalog := xnft.HostInboundStaleReplyCatalog(family)
			allowed := map[uint16]bool{}
			ports := catalog.TCP
			if proto == "udp" {
				ports = catalog.UDP
			}
			for _, p := range ports {
				allowed[p] = true
			}
			for _, token := range strings.FieldsFunc(spec, func(r rune) bool {
				return r == ' ' || r == '{' || r == '}' || r == ','
			}) {
				port, err := strconv.ParseUint(token, 10, 16)
				if err != nil {
					t.Fatalf("lan=%v: unparsable guard dport token %q: %s", lanServices, token, line)
				}
				if !allowed[uint16(port)] {
					t.Errorf("lan=%v: guard drops non-catalog %s/%d (ephemeral silence broken): %s", lanServices, proto, port, line)
				}
			}
		}
		if guards == 0 {
			t.Fatalf("lan=%v: expected guard DROP lines to check", lanServices)
		}
	}
}

func TestHostInboundKeptSuspiciousWarnScope10752(t *testing.T) {
	// The evidence-based tightening WARN must fire exactly for kept
	// box-oriented non-catalog service-like flows: custom sports below the
	// ephemeral floor (TCP+UDP 2222), plus TCP sports inside the range that
	// back a local LISTEN socket (bound custom service). It stays silent
	// for plain ephemeral egress, exempt control-plane/client ports,
	// in-range UDP (no listen state to distinguish bound services),
	// flushed catalogued tuples, admitted tuples, peer-oriented flows, and
	// uncovered sources.
	origRange := readEphemeralPortRange
	readEphemeralPortRange = func() (uint16, uint16) { return 32768, 60999 }
	defer func() { readEphemeralPortRange = origRange }()
	origListeners := readLocalTCPListenerPorts
	readLocalTCPListenerPorts = func() map[uint16]bool { return map[uint16]bool{45000: true} }
	defer func() { readLocalTCPListenerPorts = origListeners }()

	cfg := hostInboundFlushTestConfig("snmp")
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"snmp"}}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, []uint16{51820})
	if filter == nil {
		t.Fatal("expected a filter for the enforcing configuration")
	}
	feed := func(flow *netlink.ConntrackFlow) {
		t.Helper()
		filter.MatchConntrackFlow(flow)
	}
	// Suspicious: denied custom sports below the ephemeral floor.
	feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 2222))
	feed(boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 2222))
	feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 32767))
	// Suspicious: TCP sport inside the range backed by a LISTEN socket (a
	// bound custom service on 45000 is not ordinary egress).
	feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 45000))
	// Silent: ephemeral floor and above without a listener.
	feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 32768))
	feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 41000))
	feed(boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 60999))
	// Silent: in-range UDP even with the same numeric port "listening" — UDP
	// has no listen state, so bound services are indistinguishable there.
	feed(boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 45000))
	// Silent: exempt control-plane/client ports.
	feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 179))
	feed(boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 123))
	// Silent: WireGuard, flushed catalogued, peer-oriented, uncovered.
	feed(boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 51820))
	if !filter.MatchConntrackFlow(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 22)) {
		t.Fatal("denied catalogued SSH must flush (control)")
	}
	feed(ctFlow(config.HostInboundProtoTCP, "172.16.50.8", 2222))
	feed(boxOrientedFlow(config.HostInboundProtoUDP, "203.0.113.7", 2222))
	got, samples := filter.keptSuspiciousReport()
	if got != 4 {
		t.Fatalf("kept-suspicious count = %d, want 4 (TCP/UDP 2222 + TCP 32767 + TCP 45000-listener); samples=%v", got, samples)
	}
	if len(samples) != 4 {
		t.Fatalf("samples = %v, want 4 tuples", samples)
	}
	// Sample cap: flood more suspicious flows; count grows, samples stop at 5.
	for range 10 {
		feed(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 3000))
	}
	got, samples = filter.keptSuspiciousReport()
	if got != 14 || len(samples) != 5 {
		t.Fatalf("after flood: count=%d samples=%d, want 14 and 5", got, len(samples))
	}
	// Flush-vs-evidence asymmetry: with another ingress still open, the
	// flush keeps an owner-denied custom (per-ingress guard would judge a
	// catalogued tuple, but customs have no guard anywhere), while the
	// evidence MUST still record it — an ingress-permitted custom bypasses
	// on every denying ingress with no per-packet backstop.
	openCfg := hostInboundFlushTestConfig("snmp")
	openViews := dpuserspace.BuildZoneHostInboundViews(openCfg)
	openV4, openV6 := dpuserspace.BuildUnzonedHostInboundAddrs(openCfg)
	openFilter := buildHostInboundConntrackFlushFilter(openViews, openV4, openV6, nil)
	if openFilter == nil {
		t.Fatal("expected a filter for the open-ingress configuration")
	}
	deniedCustom := boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 2222)
	if openFilter.MatchConntrackFlow(deniedCustom) {
		t.Fatal("ingress-permitted custom must not flush (would break the permitted use)")
	}
	evidence := openFilter.keptEvidenceReport()
	var evCustom, evOther uint64
	for _, ev := range evidence {
		evCustom += ev.custom
		evOther += ev.other
	}
	if evCustom != 1 || evOther != 0 {
		t.Fatalf("ingress-permitted custom must record evidence (custom=1, other=0), got %d/%d", evCustom, evOther)
	}
}

func TestHostInputFenceConntrackMatchesCataloguedBoxFlows10752And10764(t *testing.T) {
	filter := buildHostInputFenceConntrackFilter([]string{"172.16.50.8", "2001:db8:50::8"})
	if filter == nil {
		t.Fatal("expected a fence filter")
	}
	for _, tc := range []struct {
		name string
		flow *netlink.ConntrackFlow
		want bool
	}{
		{"tcp-service", boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 22), true},
		{"udp-ike", boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 500), true},
		{"ipv6-udp-ike", boxOrientedFlow(config.HostInboundProtoUDP, "2001:db8:50::8", 4500), true},
		{"ephemeral-egress", boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 41000), false},
		{"ntp-client", boxOrientedFlow(config.HostInboundProtoUDP, "172.16.50.8", 123), false},
		{"control-plane-client", boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 179), false},
		{"uncovered-source", boxOrientedFlow(config.HostInboundProtoUDP, "203.0.113.7", 500), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := filter.MatchConntrackFlow(tc.flow); got != tc.want {
				t.Fatalf("MatchConntrackFlow(%+v) = %v, want %v", tc.flow.Forward, got, tc.want)
			}
		})
	}
}

func TestHostInboundStaleReplyGuardsPrecedeReplyAccept10752And10764(t *testing.T) {
	cfg := hostInboundFlushTestConfig("snmp")
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, false)
	lines := strings.Split(payload, "\n")
	guardEnd, replyAccept := -1, -1
	var wanGuards []string
	for i, line := range lines {
		if strings.Contains(line, "ct state established,related ct direction reply") && strings.HasSuffix(line, " drop") {
			guardEnd = i
			if strings.Contains(line, "daddr 172.16.50.8") {
				wanGuards = append(wanGuards, line)
			}
		}
		if strings.TrimSpace(line) == "ct state established,related ct direction reply accept" {
			replyAccept = i
		}
	}
	if len(wanGuards) == 0 || guardEnd < 0 || replyAccept < 0 || guardEnd >= replyAccept {
		t.Fatalf("catalog guards must precede the broad reply accept; guardEnd=%d replyAccept=%d guards=%q", guardEnd, replyAccept, wanGuards)
	}
	for _, tuple := range []struct {
		proto string
		port  uint16
		want  bool
	}{
		{"tcp", 22, true}, {"udp", 500, true}, {"udp", 4500, true},
		{"udp", 161, false}, {"udp", 123, false}, {"tcp", 41000, false},
	} {
		got := false
		for _, line := range wanGuards {
			if strings.Contains(line, " "+tuple.proto+" dport ") && nftTextRuleHasPort(line, tuple.port) {
				got = true
			}
		}
		if got != tuple.want {
			t.Errorf("guard for %s/%d = %v, want %v; rules=%q", tuple.proto, tuple.port, got, tuple.want, wanGuards)
		}
	}
	for _, line := range lines {
		if strings.Contains(line, "ct state established,related ct direction reply") && strings.HasSuffix(line, " drop") && strings.Contains(line, "iifname !=") && strings.Contains(line, "daddr 10.0.61.1") {
			t.Fatalf("any-service address must not appear in the uncovered-ingress fallback: %s", line)
		}
	}

	admittedCfg := hostInboundFlushTestConfig("ssh", "ike", "snmp")
	admitted := strings.Split(buildHostInboundFilterPayload(
		dpuserspace.BuildZoneHostInboundViews(admittedCfg), nil, nil, nil, nil, false,
	), "\n")
	for _, line := range admitted {
		if !strings.Contains(line, "ct state established,related ct direction reply") || !strings.HasSuffix(line, " drop") || !strings.Contains(line, "daddr 172.16.50.8") {
			continue
		}
		if strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 22) {
			t.Fatalf("still-admitted SSH appears in stale-reply guard: %s", line)
		}
		if strings.Contains(line, " udp dport ") && (nftTextRuleHasPort(line, 500) || nftTextRuleHasPort(line, 4500)) {
			t.Fatalf("still-admitted IKE appears in stale-reply guard: %s", line)
		}
	}
	identResetViews := dpuserspace.BuildZoneHostInboundViews(hostInboundFlushTestConfig("ident-reset"))
	identResetPayload := buildHostInboundFilterPayload(identResetViews, nil, nil, nil, nil, false)
	identResetGuarded := false
	for _, line := range strings.Split(identResetPayload, "\n") {
		if strings.Contains(line, "ct state established,related ct direction reply") &&
			strings.HasSuffix(line, " drop") && strings.Contains(line, "daddr 172.16.50.8") &&
			strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 113) {
			identResetGuarded = true
		}
	}
	if !identResetGuarded {
		t.Fatal("ident-reset TCP/113 reject must not admit its box-oriented reply through the broad reply accept")
	}

	fence := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, nil, nil, nil, nil, dhcpBackstopVRFLists{})
	gap := buildHostInboundGapFencePayload(nil, []string{"172.16.50.8"}, nil, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopVRFLists{}, nil, nil)
	for name, text := range map[string]string{"cold-boot": fence, "gap": gap} {
		guardAt, acceptAt := -1, -1
		for i, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "ct state established,related ct direction reply") && strings.HasSuffix(line, " drop") && strings.Contains(line, "udp dport") && nftTextRuleHasPort(line, 500) {
				guardAt = i
			}
			if strings.TrimSpace(line) == "ct state established,related accept" {
				acceptAt = i
			}
		}
		if guardAt < 0 || acceptAt < 0 || guardAt >= acceptAt {
			t.Errorf("%s fence does not drop denied UDP service replies before broad established accept: guard=%d accept=%d", name, guardAt, acceptAt)
		}
	}
	lo0Fence := buildLo0FencePayload(views, unzonedV4, unzonedV6, nil)
	if strings.Contains(lo0Fence, "ct state established,related ct direction reply") {
		t.Fatal("host-inbound stale-reply guard must not change the lo0 fence's established-flow policy")
	}
	if got := hostForwardingPostureSysctls["/proc/sys/net/netfilter/nf_conntrack_tcp_loose"]; got != "0" {
		t.Fatalf("runtime TCP conntrack posture = %q, want 0", got)
	}
}
func TestHostInboundStaleReplyGuardsFollowIngressPolicy10752(t *testing.T) {
	// Both disagreement directions, verified on the production text renderer
	// (parity proves netlink identical; pkg/nftables pins netlink directly).
	// wan ingress netdev is reth0.50, lan is reth1 (see dump in review).
	t.Run("ingress-permits-owner-denies", func(t *testing.T) {
		cfg := hostInboundFlushTestConfig("snmp")
		views := dpuserspace.BuildZoneHostInboundViews(cfg)
		payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
		lines := strings.Split(payload, "\n")
		// Wan ingress denies SSH/IKE: its per-ingress guard must cover them
		// to every judged destination (including the open lan address).
		if !payloadHasGuard(lines, `"reth0.50"`, false, "172.16.50.8", "tcp", 22) {
			t.Error("wan ingress guard must drop TCP/22 replies arriving on reth0.50")
		}
		if !payloadHasGuard(lines, `"reth0.50"`, false, "10.0.61.1", "tcp", 22) {
			t.Error("wan ingress guard must cover cross-zone destination 10.0.61.1 for TCP/22")
		}
		if !payloadHasGuard(lines, `"reth0.50"`, false, "172.16.50.8", "udp", 500) {
			t.Error("wan ingress guard must drop UDP/500 replies arriving on reth0.50")
		}
		// Lan ingress is open: no per-ingress guard for its netdev.
		for _, line := range lines {
			if isGuardDrop(line) && strings.Contains(line, `iifname "reth1"`) {
				t.Errorf("open lan ingress must emit no per-ingress guard, got: %s", line)
			}
		}
		// Uncovered fallback still guards the owner-denied wan address and
		// excludes the trusted reinject TUN.
		foundFallback := false
		for _, line := range lines {
			if isGuardDrop(line) && strings.Contains(line, "iifname !=") && strings.Contains(line, "daddr 172.16.50.8") && strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 22) {
				foundFallback = true
				if !strings.Contains(line, `"xpf-usp0"`) {
					t.Errorf("fallback must exclude trusted reinject TUN xpf-usp0: %s", line)
				}
			}
		}
		if !foundFallback {
			t.Error("uncovered-ingress fallback must guard owner-denied TCP/22 to 172.16.50.8")
		}
		// Admitted-client control: ephemeral and NTP never guarded.
		for _, line := range lines {
			if !isGuardDrop(line) {
				continue
			}
			if strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 41000) {
				t.Errorf("ephemeral TCP must never be guarded: %s", line)
			}
			if strings.Contains(line, " udp dport ") && nftTextRuleHasPort(line, 123) {
				t.Errorf("NTP client must never be guarded: %s", line)
			}
		}
	})
	t.Run("ingress-denies-owner-permits", func(t *testing.T) {
		cfg := hostInboundFlushTestConfig("ssh", "ike", "snmp")
		cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"snmp"}}
		views := dpuserspace.BuildZoneHostInboundViews(cfg)
		payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
		lines := strings.Split(payload, "\n")
		// Lan ingress denies SSH: its guard must cover the wan address even
		// though the wan owner permits it.
		if !payloadHasGuard(lines, `"reth1"`, false, "172.16.50.8", "tcp", 22) {
			t.Error("lan ingress guard must drop TCP/22 replies arriving on reth1 to 172.16.50.8")
		}
		if !payloadHasGuard(lines, `"reth1"`, false, "172.16.50.8", "udp", 500) {
			t.Error("lan ingress guard must drop UDP/500 replies arriving on reth1 to 172.16.50.8")
		}
		// Wan ingress permits: no wan per-ingress guard for SSH/IKE.
		for _, line := range lines {
			if !isGuardDrop(line) || !strings.Contains(line, `iifname "reth0.50"`) {
				continue
			}
			if strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 22) {
				t.Errorf("wan ingress permits SSH, must not guard TCP/22: %s", line)
			}
			if strings.Contains(line, " udp dport ") && (nftTextRuleHasPort(line, 500) || nftTextRuleHasPort(line, 4500)) {
				t.Errorf("wan ingress permits IKE, must not guard UDP/500/4500: %s", line)
			}
		}
		// Owner-permitted wan address has no uncovered fallback for SSH/IKE.
		for _, line := range lines {
			if !isGuardDrop(line) || !strings.Contains(line, "iifname !=") || !strings.Contains(line, "daddr 172.16.50.8") {
				continue
			}
			if strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 22) {
				t.Errorf("owner-permitted wan address must have no fallback for TCP/22: %s", line)
			}
			if strings.Contains(line, " udp dport ") && (nftTextRuleHasPort(line, 500) || nftTextRuleHasPort(line, 4500)) {
				t.Errorf("owner-permitted wan address must have no fallback for UDP/500/4500: %s", line)
			}
		}
		// Owner-denied lan address retains its fallback.
		found := false
		for _, line := range lines {
			if isGuardDrop(line) && strings.Contains(line, "iifname !=") && strings.Contains(line, "daddr 10.0.61.1") && strings.Contains(line, " tcp dport ") && nftTextRuleHasPort(line, 22) {
				found = true
			}
		}
		if !found {
			t.Error("owner-denied lan address must retain uncovered fallback for TCP/22")
		}
	})
}

func isGuardDrop(line string) bool {
	return strings.Contains(line, "ct state established,related ct direction reply") && strings.HasSuffix(line, " drop")
}

func payloadHasGuard(lines []string, iifsubstr string, negated bool, daddrSubstr, proto string, port uint16) bool {
	for _, line := range lines {
		if !isGuardDrop(line) {
			continue
		}
		hasNeg := strings.Contains(line, "iifname !=")
		if hasNeg != negated {
			continue
		}
		if !strings.Contains(line, iifsubstr) {
			continue
		}
		if !strings.Contains(line, daddrSubstr) {
			continue
		}
		if !strings.Contains(line, " "+proto+" dport ") || !nftTextRuleHasPort(line, port) {
			continue
		}
		return true
	}
	return false
}
func TestHostInboundAdmittedTCPAcceptsAreFlagless10752(t *testing.T) {
	// Availability: admitted host services must accept SYN-less mid-stream
	// TCP (no conntrack) flaglessly, so loose=0 does not break legitimate
	// service recovery after conntrack loss. Ephemeral replies without
	// conntrack still drop (pinned by the no-conntrack packet-path subtest);
	// host-originated TCP clients must re-establish after eviction (accepted
	// risk: established timeout ~5d, only on table-full/eviction; reboot and
	// failover sockets are gone anyway).
	cfg := hostInboundFlushTestConfig("ssh", "snmp")
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, false)
	foundAdmit := false
	for _, line := range strings.Split(payload, "\n") {
		if !strings.Contains(line, "tcp dport 22") || !strings.HasSuffix(line, " accept") {
			continue
		}
		foundAdmit = true
		if strings.Contains(line, "tcp flags") {
			t.Fatalf("admitted SSH accept must be flagless (SYN-less mid-stream must match): %s", line)
		}
	}
	if !foundAdmit {
		t.Fatal("expected an admitted SSH accept rule for flagless check")
	}
}

func TestHostInboundInstallPrecedesConntrackFlush10752(t *testing.T) {
	// Race bound: the Install→flush window is closed for catalogued tuples
	// because the guard installs atomically WITH the table, before the
	// conntrack sweep runs. This test pins install-before-flush ORDER only —
	// not a packet count. Peer-oriented uncovered arrivals ride the residual
	// accept for the Install→flush code duration (rate×duration packets under
	// flood; sweep misses extend it with no retry debt), and non-catalog
	// box-oriented tuples have no guard at all (HIGH residuals in the matrix).
	var order []string
	origInstaller, origDelete := nftInstaller, conntrackDeleteFilters
	defer func() { nftInstaller, conntrackDeleteFilters = origInstaller, origDelete }()
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error {
			order = append(order, "install")
			return nil
		},
	}
	conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
		order = append(order, "flush")
		return 0, nil
	}
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundFlushTestConfig("snmp")); err != nil {
		t.Fatalf("applyHostInboundFilter: %v", err)
	}
	installAt, flushAt := -1, -1
	for i, step := range order {
		if step == "install" && installAt < 0 {
			installAt = i
		}
		if step == "flush" && flushAt < 0 {
			flushAt = i
		}
	}
	if installAt < 0 || flushAt < 0 || installAt >= flushAt {
		t.Fatalf("guard-first ordering violated: install@%d flush@%d order=%v", installAt, flushAt, order)
	}
}

func boxOrientedFlow(proto uint8, localIP string, sport uint16) *netlink.ConntrackFlow {
	return &netlink.ConntrackFlow{Forward: netlink.IPTuple{
		SrcIP: net.ParseIP(localIP), DstIP: net.ParseIP("203.0.113.7"),
		Protocol: proto, SrcPort: sport, DstPort: 40000,
	}}
}

func nftTextRuleHasPort(line string, want uint16) bool {
	marker := " dport "
	start := strings.Index(line, marker)
	if start < 0 {
		return false
	}
	spec := line[start+len(marker):]
	if end := strings.LastIndex(spec, " drop"); end >= 0 {
		spec = spec[:end]
	}
	for _, token := range strings.FieldsFunc(spec, func(r rune) bool { return r == ' ' || r == '{' || r == '}' || r == ',' }) {
		port, err := strconv.ParseUint(token, 10, 16)
		if err == nil && uint16(port) == want {
			return true
		}
	}
	return false
}

// TestNotrackEvidenceLogPresent10752 pins the committed verbose-run snapshot
// for the no-conntrack proof (Opus4 F3): reviewers without a privileged
// netns can read the per-tuple hit lines and dump check here instead of
// re-running. The live subtest re-proves the same facts on every run, so
// this only guards the snapshot against accidental deletion or silent edit
// (structural markers, not exact ports/timings, which vary per run).
func TestNotrackEvidenceLogPresent10752(t *testing.T) {
	raw, err := os.ReadFile("testdata/notrack_evidence_10752.log")
	if err != nil {
		t.Fatalf("committed NOTRACK evidence log missing: %v", err)
	}
	for _, marker := range []string{
		"NOTRACK pre rule",
		"NOTRACK out rule",
		"addrOff=16 portOff=2",
		"conntrack dump:",
		"none reference box",
		"availability-no-conntrack",
		"--- PASS",
	} {
		if !strings.Contains(string(raw), marker) {
			t.Errorf("evidence log must contain %q (recapture from a verbose child run if the format changed)", marker)
		}
	}
}

func TestHostInboundStaleReplyPacketPath10752And10764(t *testing.T) {
	const childEnv = "XPF_HOSTINBOUND_STALE_REPLY_NETNS_CHILD"
	if os.Getenv(childEnv) == "1" {
		runHostInboundStaleReplyPacketPath(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare is not installed; packet-path proof needs an isolated network namespace")
	}
	cmd := exec.Command(unshare, "-Urn", os.Args[0], "-test.run=^TestHostInboundStaleReplyPacketPath10752And10764$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	output, err := cmd.CombinedOutput()
	if strings.Contains(string(output), "XPF-NETNS-SKIP:") {
		t.Skipf("packet-path proof unavailable: %s", strings.TrimSpace(string(output)))
	}
	if err != nil {
		if !strings.Contains(string(output), "=== RUN") {
			t.Skipf("network namespace is unavailable: %v: %s", err, strings.TrimSpace(string(output)))
		}
		t.Fatalf("isolated packet-path test failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: TestHostInboundStaleReplyPacketPath10752And10764") {
		t.Fatalf("isolated packet-path child did not report success:\n%s", output)
	}
}

func runHostInboundStaleReplyPacketPath(t *testing.T) {
	t.Helper()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("lookup loopback: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		netnsSkipOrFail(t, "bring loopback up", err)
	}
	localIP, peerIP := "192.0.2.10", "198.51.100.7"
	for _, raw := range []string{localIP, peerIP} {
		ip, network, err := net.ParseCIDR(raw + "/32")
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		network.IP = ip
		if err := netlink.AddrAdd(lo, &netlink.Addr{IPNet: network}); err != nil {
			netnsSkipOrFail(t, "add loopback address "+raw, err)
		}
	}

	installer := xnft.NewNetlinkInstaller()
	if err := installer.InstallHostInbound(xnft.HostInboundSpec{Views: []xnft.HostInboundZoneView{{
		Zone: "wan", SystemServices: []string{"snmp"}, V4Addrs: []string{localIP},
	}}}); err != nil {
		netnsSkipOrFail(t, "install host-inbound rules", err)
	}
	defer func() {
		if err := installer.DeleteTable(xnft.HostInboundTableName); err != nil {
			t.Errorf("delete isolated host-inbound table: %v", err)
		}
	}()

	// Loose posture is recorded, not gated: guard tests run regardless of
	// sysctl availability (F3 decoupling). The TCP subtest uses a
	// source-bound Dial (reply guarding), not loose mid-stream pickup; loose
	// lifecycle is proven separately by the fault-injected unit test.
	applyHostForwardingPosture()
	looseRaw, looseErr := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_tcp_loose")
	looseVal := ""
	if looseErr == nil {
		looseVal = strings.TrimSpace(string(looseRaw))
	}
	t.Logf("loose posture in packet netns: value=%q err=%v (guard verdicts independent)", looseVal, looseErr)

	t.Run("udp", func(t *testing.T) {
		runStaleReplyUDPPacketPath(t, localIP, peerIP)
	})
	t.Run("tcp", func(t *testing.T) {
		runStaleReplyTCPPacketPath(t, localIP, peerIP)
	})
	t.Run("availability-no-conntrack", func(t *testing.T) {
		runStaleReplyNoConntrackPacketPath(t, localIP, peerIP)
	})
}

func runStaleReplyUDPPacketPath(t *testing.T, localIP, peerIP string) {
	t.Helper()
	peerAddr := &net.UDPAddr{IP: net.ParseIP(peerIP), Port: 4500}
	localAddr := &net.UDPAddr{IP: net.ParseIP(localIP), Port: 4500}
	peer, err := net.ListenUDP("udp", peerAddr)
	if err != nil {
		netnsSkipOrFail(t, "bind peer UDP/4500", err)
	}
	defer peer.Close()
	box, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		netnsSkipOrFail(t, "bind box UDP/4500", err)
	}
	defer box.Close()
	if err := box.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := box.WriteToUDP([]byte("dpd-request"), peerAddr); err != nil {
		t.Fatalf("send box-originated UDP request: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, 32)
	n, source, err := peer.ReadFromUDP(request)
	if err != nil || string(request[:n]) != "dpd-request" {
		t.Fatalf("peer did not receive outbound UDP request: n=%d source=%v err=%v", n, source, err)
	}
	if _, err := peer.WriteToUDP([]byte("dpd-reply"), source); err != nil {
		t.Fatalf("send UDP reply: %v", err)
	}
	if _, _, err := box.ReadFromUDP(request); !isTimeout(err) {
		t.Fatalf("denied UDP/4500 reply was delivered (read error %v), want timeout after guard DROP", err)
	}

	// An ephemeral client tuple remains on the broad reply accept path.
	ephemeral, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(localIP)})
	if err != nil {
		t.Fatalf("bind ephemeral UDP client: %v", err)
	}
	defer ephemeral.Close()
	if err := ephemeral.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ephemeral.WriteToUDP([]byte("client-request"), peerAddr); err != nil {
		t.Fatalf("send ephemeral UDP client request: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, source, err = peer.ReadFromUDP(request)
	if err != nil || string(request[:n]) != "client-request" {
		t.Fatalf("peer did not receive ephemeral request: n=%d source=%v err=%v", n, source, err)
	}
	if _, err := peer.WriteToUDP([]byte("client-reply"), source); err != nil {
		t.Fatalf("send ephemeral UDP reply: %v", err)
	}
	if n, _, err = ephemeral.ReadFromUDP(request); err != nil || string(request[:n]) != "client-reply" {
		t.Fatalf("ephemeral UDP reply was not delivered: n=%d err=%v", n, err)
	}

	// HIGH residual pin: exempt BFD control-plane replies are NOT guarded.
	// Each SSOT bfd dport — single-hop control 3784 (RFC 5881 §4),
	// echo 3785 (RFC 5880), multihop control 4784 (RFC 5883) — is
	// sourced by conformant bfdd from an ephemeral sport, so the box
	// socket binds ephemeral — NOT the dport (an explicit fixed-sport
	// bind would manufacture an artificial ORIG tuple no conforming peer
	// produces). The box-originated entry recreates all the same, and
	// the peer reply rides the broad accept. RIP/SAP/LDP-UDP share the
	// exclusion.
	for _, port := range []int{3784, 3785, 4784} {
		bfdPeerAddr := &net.UDPAddr{IP: net.ParseIP(peerIP), Port: port}
		bfdPeer, err := net.ListenUDP("udp", bfdPeerAddr)
		if err != nil {
			netnsSkipOrFail(t, "bind peer UDP/"+strconv.Itoa(port), err)
		}
		defer bfdPeer.Close()
		bfdBox, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(localIP)})
		if err != nil {
			netnsSkipOrFail(t, "bind box ephemeral BFD socket", err)
		}
		defer bfdBox.Close()
		if sport := bfdBox.LocalAddr().(*net.UDPAddr).Port; sport == port {
			t.Fatalf("box BFD socket must source ephemeral, got sport %d for dport %d", sport, port)
		}
		if err := bfdBox.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := bfdBox.WriteToUDP([]byte("bfd-hello"), bfdPeerAddr); err != nil {
			t.Fatalf("send box-originated BFD hello: %v", err)
		}
		if err := bfdPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, source, err = bfdPeer.ReadFromUDP(request)
		if err != nil || string(request[:n]) != "bfd-hello" {
			t.Fatalf("peer did not receive BFD hello: n=%d err=%v", n, err)
		}
		if _, err := bfdPeer.WriteToUDP([]byte("bfd-reply"), source); err != nil {
			t.Fatalf("send BFD reply: %v", err)
		}
		if n, _, err = bfdBox.ReadFromUDP(request); err != nil || string(request[:n]) != "bfd-reply" {
			t.Fatalf("exempt BFD reply was not delivered (HIGH residual pins allow): n=%d err=%v dport=%d", n, err, port)
		}
	}
}

// TestUnguardedBFDProcedureCoversEcho10752 pins the BFD removal procedure's
// discovery filter against the SSOT: the filter must cover every UDP dport
// the bfd token admits (control 3784, echo 3785, multihop 4784), and must
// stay destination-based (a --sport filter would miss conforming
// ephemeral-source flows). Fail-on-revert: dropping 3785 from the filter
// REDs this test while the packet proof above still passes.
func TestUnguardedBFDProcedureCoversEcho10752(t *testing.T) {
	raw, err := os.ReadFile("../../docs/host-inbound-service-matrix.md")
	if err != nil {
		t.Fatalf("read service matrix: %v", err)
	}
	var row string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "| BFD |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("BFD removal-procedure row not found in the service matrix")
	}
	start := strings.Index(row, "dport=(")
	if start < 0 {
		t.Fatalf("BFD row carries no dport=(...) discovery filter: %q", row)
	}
	rest := row[start+len("dport=("):]
	end := strings.Index(rest, ")")
	if end < 0 {
		t.Fatalf("BFD row discovery filter is unterminated: %q", row)
	}
	covered := map[string]bool{}
	for _, p := range strings.Split(rest[:end], "|") {
		covered[p] = true
	}
	for _, m := range config.HostInboundProtocolMatch("bfd", "ip") {
		if m.Proto != config.HostInboundProtoUDP {
			continue
		}
		for _, r := range m.Ports {
			for p := r.Lo; p <= r.Hi; p++ {
				if !covered[strconv.Itoa(int(p))] {
					t.Errorf("SSOT bfd dport %d missing from the BFD discovery filter (covered=%v)", p, covered)
				}
			}
		}
	}
	if !strings.Contains(row, "never `--sport 3784`") {
		t.Error("BFD row must retain the destination-based discipline note (never --sport 3784)")
	}
}

func runStaleReplyTCPPacketPath(t *testing.T, localIP, peerIP string) {
	t.Helper()
	// The same chain must stop a TCP reply sourced from a catalogued service
	// port while continuing to accept an ordinary ephemeral-source connection.
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(peerIP), Port: 29000})
	if err != nil {
		netnsSkipOrFail(t, "bind peer TCP listener", err)
	}
	defer listener.Close()
	deniedDialer := net.Dialer{
		Timeout:   time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP), Port: 2900},
	}
	conn, err := deniedDialer.Dial("tcp", net.JoinHostPort(peerIP, "29000"))
	if err == nil {
		conn.Close()
		t.Fatal("TCP reply to denied service source port 2900 established despite stale-reply guard")
	}
	if !isTimeout(err) {
		t.Fatalf("catalogued TCP flow failed without the expected reply-drop timeout: %v", err)
	}

	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	acceptResult := make(chan error, 1)
	go func() {
		accepted, err := listener.AcceptTCP()
		if err == nil {
			accepted.Close()
		}
		acceptResult <- err
	}()
	// Allowed control binds the covered local address with an ephemeral source
	// port, proving the same covered-address return path stays open.
	allowedDialer := net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)},
	}
	allowed, err := allowedDialer.Dial("tcp", net.JoinHostPort(peerIP, "29000"))
	if err != nil {
		t.Fatalf("ordinary ephemeral TCP client connection was blocked: %v", err)
	}
	allowed.Close()
	select {
	case err := <-acceptResult:
		if err != nil {
			t.Fatalf("accept ordinary TCP client: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not accept ordinary TCP client")
	}
}

func runStaleReplyNoConntrackPacketPath(t *testing.T, localIP, peerIP string) {
	t.Helper()
	// True no-conntrack availability proof: a raw-table NOTRACK rule exempts
	// the test tuples from conntrack in both directions, and a conntrack
	// dump afterwards verifies no entry was created. An admitted service
	// dport must still deliver (flagless service accept); an ephemeral dport
	// with no conntrack must drop. This is the mechanism behind the
	// TCP-client recovery note: admitted host services survive conntrack
	// loss; host-originated ephemeral clients must re-establish (accepted
	// risk, documented).
	//
	// CI vs lab: this runs wherever the netns packet-path runs (`unshare
	// -Urn` with CAP_NET_ADMIN in the child, same gate as T1 parity, plus
	// kernel raw-table support). Without those the parent skips with an
	// explicit XPF-NETNS-SKIP reason instead of faking green.
	box := net.ParseIP(localIP)
	snmpBox, err := net.ListenUDP("udp", &net.UDPAddr{IP: box, Port: 161})
	if err != nil {
		netnsSkipOrFail(t, "bind box UDP/161", err)
	}
	defer snmpBox.Close()
	if err := snmpBox.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ephemeralBox, err := net.ListenUDP("udp", &net.UDPAddr{IP: box})
	if err != nil {
		t.Fatalf("bind ephemeral box socket: %v", err)
	}
	defer ephemeralBox.Close()
	ephemeralPort := ephemeralBox.LocalAddr().(*net.UDPAddr).Port
	if err := ephemeralBox.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(peerIP)})
	if err != nil {
		netnsSkipOrFail(t, "bind peer UDP ephemeral", err)
	}
	defer peer.Close()

	cleanupNotrack := installNotrackTestRules(t, box, 161, uint16(ephemeralPort))
	defer cleanupNotrack()

	snmpDst := &net.UDPAddr{IP: box, Port: 161}
	if _, err := peer.WriteToUDP([]byte("snmp-new"), snmpDst); err != nil {
		t.Fatalf("send untracked SNMP request: %v", err)
	}
	buf := make([]byte, 32)
	n, _, err := snmpBox.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "snmp-new" {
		t.Fatalf("untracked SNMP to admitted dport was not delivered: n=%d err=%v", n, err)
	}

	ephemeralDst := &net.UDPAddr{IP: box, Port: ephemeralPort}
	if _, err := peer.WriteToUDP([]byte("ephemeral-new"), ephemeralDst); err != nil {
		t.Fatalf("send untracked ephemeral request: %v", err)
	}
	if _, _, err := ephemeralBox.ReadFromUDP(buf); !isTimeout(err) {
		t.Fatalf("untracked ephemeral without conntrack was delivered (err %v), want DROP", err)
	}

	assertNotrackRulesHit(t, 161, uint16(ephemeralPort))
	assertNoConntrackForUDPTuples(t, box, 161, uint16(ephemeralPort))
}

// installNotrackTestRules creates an `ip`-family raw table exempting the given
// box UDP tuples from conntrack via NOTRACK in prerouting (peer→box) and
// output (box→peer). Built with google/nftables directly: this daemon test
// package cannot use the unexported nftables.nlPlan builder. Returns cleanup.
func installNotrackTestRules(t *testing.T, box net.IP, dports ...uint16) func() {
	t.Helper()
	c, err := gnft.New()
	if err != nil {
		netnsSkipOrFail(t, "open nftables conn for NOTRACK", err)
	}
	box4 := box.To4()
	if box4 == nil {
		t.Fatalf("NOTRACK test needs an IPv4 box address, got %v", box)
	}
	be16 := func(p uint16) []byte {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, p)
		return b
	}
	l4udp := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
	}
	tbl := c.AddTable(&gnft.Table{Family: gnft.TableFamilyIPv4, Name: "xpf_nt_10752"})
	pol := gnft.ChainPolicyAccept
	pre := c.AddChain(&gnft.Chain{Name: "pre", Table: tbl, Type: gnft.ChainTypeFilter, Hooknum: gnft.ChainHookPrerouting, Priority: gnft.ChainPriorityRaw, Policy: &pol})
	out := c.AddChain(&gnft.Chain{Name: "out", Table: tbl, Type: gnft.ChainTypeFilter, Hooknum: gnft.ChainHookOutput, Priority: gnft.ChainPriorityRaw, Policy: &pol})
	for _, port := range dports {
		// Each rule carries a trailing anonymous counter so the test can
		// prove the NOTRACK path actually matched the test traffic (read
		// back via GetRules after the exchange).
		preExprs := append(append([]expr.Any{}, l4udp...),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(nil), box4...)},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
			&expr.Notrack{},
			&expr.Counter{},
		)
		c.AddRule(&gnft.Rule{Table: tbl, Chain: pre, Exprs: preExprs})
		outExprs := append(append([]expr.Any{}, l4udp...),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(nil), box4...)},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
			&expr.Notrack{},
			&expr.Counter{},
		)
		c.AddRule(&gnft.Rule{Table: tbl, Chain: out, Exprs: outExprs})
		// Locally-generated peer→box packets hit OUTPUT conntrack before
		// they loop to prerouting, so prerouting-only NOTRACK would be too
		// late on loopback: exempt them at OUTPUT by destination too.
		outInExprs := append(append([]expr.Any{}, l4udp...),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(nil), box4...)},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
			&expr.Notrack{},
			&expr.Counter{},
		)
		c.AddRule(&gnft.Rule{Table: tbl, Chain: out, Exprs: outInExprs})
	}
	if err := c.Flush(); err != nil {
		netnsSkipOrFail(t, "install NOTRACK rules", err)
	}
	return func() {
		d, derr := gnft.New()
		if derr != nil {
			return
		}
		d.DelTable(&gnft.Table{Family: gnft.TableFamilyIPv4, Name: "xpf_nt_10752"})
		_ = d.Flush()
	}
}

// assertNoConntrackForUDPTuples dumps the v4 conntrack table and fails if any
// entry references the box address with one of the given UDP ports in either
// direction. This is what makes the no-conntrack label honest: delivery (or
// drop) verdicts above are only meaningful untracked if no entry exists.
// The dump size is logged so -v output shows the check ran over a live table
// (earlier subtests leave tracked entries behind; only the NOTRACK tuples
// must be absent).
func assertNoConntrackForUDPTuples(t *testing.T, box net.IP, ports ...uint16) {
	t.Helper()
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
	if err != nil {
		netnsSkipOrFail(t, "dump conntrack table", err)
	}
	want := map[uint16]bool{}
	for _, p := range ports {
		want[p] = true
	}
	for _, f := range flows {
		if f.Forward.Protocol != unix.IPPROTO_UDP {
			continue
		}
		if net.IP(f.Forward.SrcIP).Equal(box) && want[f.Forward.SrcPort] {
			t.Fatalf("conntrack entry exists for supposedly untracked box sport %d: %+v", f.Forward.SrcPort, f.Forward)
		}
		if net.IP(f.Forward.DstIP).Equal(box) && want[f.Forward.DstPort] {
			t.Fatalf("conntrack entry exists for supposedly untracked box dport %d: %+v", f.Forward.DstPort, f.Forward)
		}
	}
	t.Logf("conntrack dump: %d v4 flows, none reference box %v UDP ports %v", len(flows), box, ports)
}

// assertNotrackRulesHit reads back the raw-table rules and requires EACH
// tuple's NOTRACK rules to have matched individually: per port, the
// prerouting daddr/dport rule and the output daddr/dport rule (which catches
// locally-generated loopback traffic) must each show >= 1 packet, while the
// output saddr/sport rules must show exactly 0 (the box never sends in this
// subtest — a hit there would mean confounding origination). Chain-wide sums
// are NOT accepted: one tuple's duplicate hits must not mask another tuple
// bypassing its rules. Every rule's key and count is logged so -v output
// retains the evidence; a captured run is also committed at
// testdata/notrack_evidence_10752.log.
func assertNotrackRulesHit(t *testing.T, ports ...uint16) {
	t.Helper()
	c, err := gnft.New()
	if err != nil {
		netnsSkipOrFail(t, "open nftables conn for NOTRACK readback", err)
	}
	tbl := &gnft.Table{Family: gnft.TableFamilyIPv4, Name: "xpf_nt_10752"}
	type ruleKey struct {
		chain   string
		addrOff uint32
		portOff uint32
		port    uint16
	}
	hits := map[ruleKey]uint64{}
	for _, chain := range []string{"pre", "out"} {
		rules, err := c.GetRules(tbl, &gnft.Chain{Name: chain, Table: tbl})
		if err != nil {
			t.Fatalf("read back NOTRACK %s rules: %v", chain, err)
		}
		for i, r := range rules {
			addrOff, portOff, port, packets, ok := notrackRuleKey(r.Exprs)
			if !ok {
				t.Fatalf("NOTRACK %s rule %d has unexpected shape (cannot attribute hits)", chain, i)
			}
			key := ruleKey{chain: chain, addrOff: addrOff, portOff: portOff, port: port}
			hits[key] += packets
			t.Logf("NOTRACK %s rule %d: addrOff=%d portOff=%d port=%d packets=%d", chain, i, addrOff, portOff, port, packets)
		}
	}
	for _, port := range ports {
		for _, want := range []struct {
			key ruleKey
			min uint64
			max uint64
			why string
		}{
			{ruleKey{"pre", 16, 2, port}, 1, ^uint64(0), "prerouting must NOTRACK the inbound tuple"},
			{ruleKey{"out", 16, 2, port}, 1, ^uint64(0), "output must NOTRACK the locally-generated inbound tuple before conntrack sees it"},
			{ruleKey{"out", 12, 0, port}, 0, 0, "box-originated rule must stay idle (box never sends here)"},
		} {
			got := hits[want.key]
			if got < want.min || got > want.max {
				t.Fatalf("NOTRACK %s addrOff=%d portOff=%d port=%d: packets=%d, want %d..%d (%s)", want.key.chain, want.key.addrOff, want.key.portOff, want.key.port, got, want.min, want.max, want.why)
			}
		}
	}
}

// notrackRuleKey identifies one test-constructed NOTRACK rule by its network
// address offset (16=daddr, 12=saddr), transport port offset (2=dport,
// 0=sport), and compared port, plus its counter's packet count. Only the
// shapes installNotrackTestRules emits are recognized.
func notrackRuleKey(exprs []expr.Any) (addrOff, portOff uint32, port uint16, packets uint64, ok bool) {
	var seenAddr, seenPort, seenCounter bool
	for _, e := range exprs {
		switch x := e.(type) {
		case *expr.Payload:
			switch x.Base {
			case expr.PayloadBaseNetworkHeader:
				if x.Len != 4 {
					return 0, 0, 0, 0, false
				}
				addrOff, seenAddr = x.Offset, true
			case expr.PayloadBaseTransportHeader:
				if x.Len != 2 {
					return 0, 0, 0, 0, false
				}
				portOff = x.Offset
			}
		case *expr.Cmp:
			if len(x.Data) == 2 {
				port, seenPort = binary.BigEndian.Uint16(x.Data), true
			}
		case *expr.Counter:
			packets, seenCounter = x.Packets, true
		}
	}
	if !seenAddr || !seenPort || !seenCounter {
		return 0, 0, 0, 0, false
	}
	return addrOff, portOff, port, packets, true
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func netnsSkipOrFail(t *testing.T, action string, err error) {
	t.Helper()
	if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") ||
		strings.Contains(strings.ToLower(err.Error()), "permission denied") ||
		strings.Contains(strings.ToLower(err.Error()), "protocol not supported") {
		t.Skipf("XPF-NETNS-SKIP: %s unavailable: %v", action, err)
	}
	t.Fatalf("%s: %v", action, err)
}
