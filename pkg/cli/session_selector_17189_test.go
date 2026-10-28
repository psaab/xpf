// #17189: pkg/cli's two peer builders (show + summary) used to each
// hand-project the same sessionFilter fields; a selector added to one
// and not the other would make the peer summary count a different set
// than the peer list shows. Both now project through toSelector, and
// this test fails if their selector fields ever diverge again.
//
// FAIL-ON-REVERT: restoring the hand-projected buildPeerSummaryRequest
// with a dropped field (the #15236 shape) makes the summary request
// differ from the show request here.
package cli

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSessionSelectorBuildersAgree17189(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.0/8")
	_, dst, _ := net.ParseCIDR("192.0.2.0/24")
	f := sessionFilter{
		zoneID: 3, hasProto: true, proto: 6, srcNet: src, dstNet: dst,
		srcPort: 1024, dstPort: 443, natOnly: true,
		appName: "junos-https", iface: "reth1.0", snatPool: "pool1",
	}
	show := buildPeerShowRequest(f)
	sum := buildPeerSummaryRequest(f)
	if show.GetZone() != sum.GetZone() || show.GetProtocol() != sum.GetProtocol() ||
		show.GetSourcePrefix() != sum.GetSourcePrefix() ||
		show.GetDestinationPrefix() != sum.GetDestinationPrefix() ||
		show.GetSourcePort() != sum.GetSourcePort() ||
		show.GetDestinationPort() != sum.GetDestinationPort() ||
		show.GetNatOnly() != sum.GetNatOnly() ||
		show.GetApplication() != sum.GetApplication() ||
		show.GetInterfaceFilter() != sum.GetInterfaceFilter() ||
		show.GetSourceNatPool() != sum.GetSourceNatPool() {
		t.Errorf("peer show/summary selector divergence:\n show=%v\n sum=%v", show, sum)
	}
	if sum.GetZone() != 3 || sum.GetProtocol() == "" || sum.GetSourceNatPool() != "pool1" {
		t.Errorf("summary request dropped filters: %+v", sum)
	}

	// Protocol 0 (HOPOPT) must stay present as "0" on BOTH builders:
	// dropping it widens the peer query to every protocol.
	zero := sessionFilter{hasProto: true, proto: 0}
	if got := buildPeerShowRequest(zero).GetProtocol(); got != "0" {
		t.Errorf("show request protocol 0 = %q, want %q", got, "0")
	}
	if got := buildPeerSummaryRequest(zero).GetProtocol(); got != "0" {
		t.Errorf("summary request protocol 0 = %q, want %q (absent would widen to all protocols)", got, "0")
	}
	// ICMPv6 forwarding parity (previously only clear had this coverage).
	v6 := sessionFilter{hasProto: true, proto: dataplane.ProtoICMPv6}
	if got := buildPeerSummaryRequest(v6).GetProtocol(); got != "ICMPV6" {
		t.Errorf("summary request icmpv6 = %q, want ICMPV6", got)
	}
	// Empty filter stays unfiltered on both.
	if got := buildPeerSummaryRequest(sessionFilter{}); got.GetZone() != 0 || got.GetProtocol() != "" {
		t.Errorf("empty filter should stay unfiltered: %+v", got)
	}
}
