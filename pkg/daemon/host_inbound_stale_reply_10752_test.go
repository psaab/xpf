package daemon

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundBoxOrientedConntrackFlush10752And10764(t *testing.T) {
	cfg := hostInboundFlushTestConfig("snmp")
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
	identViews := dpuserspace.BuildZoneHostInboundViews(identResetCfg)
	identV4, identV6 := dpuserspace.BuildUnzonedHostInboundAddrs(identResetCfg)
	identFilter := buildHostInboundConntrackFlushFilter(identViews, identV4, identV6, nil)
	if !identFilter.MatchConntrackFlow(boxOrientedFlow(config.HostInboundProtoTCP, "172.16.50.8", 113)) {
		t.Fatal("ident-reset is a reject, not an admit; box-oriented TCP/113 must remain flushable")
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
		if strings.Contains(line, "ct state established,related ct direction reply") && strings.HasSuffix(line, " drop") && strings.Contains(line, "daddr 10.0.61.1") {
			t.Fatalf("any-service address was guarded: %s", line)
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

	fence := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, nil)
	gap := buildHostInboundGapFencePayload([]string{"172.16.50.8"}, nil, nil)
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

	applyHostForwardingPosture()
	value, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_tcp_loose")
	if err != nil || strings.TrimSpace(string(value)) != "0" {
		t.Skipf("XPF-NETNS-SKIP: runtime nf_conntrack_tcp_loose=0 unavailable (value=%q err=%v)", strings.TrimSpace(string(value)), err)
	}

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
	allowed, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp", net.JoinHostPort(peerIP, "29000"))
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
