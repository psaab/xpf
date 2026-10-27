package userspace

import "testing"

// TestClassifyHostInboundProtocolsAllNotFullAdmit locks #4411 A4
// (avo-review-002): a zone carrying BOTH `host-inbound-traffic protocols all`
// AND `system-services ssh`. `protocols all` is deliberately NOT a full admit
// (#3199) — it expands to the routing-protocol set via HostInboundProtocolMatch,
// NOT arbitrary L4 ports (unlike `any-service`, which
// HostInboundFullAdmitService opens wholesale — note `system-services all` is
// no longer in that company either, since #3226 scoped it to the named union). The boundary this pins:
//
//   - ssh (tcp/22) IS admitted, via the system-services token (admitted, not
//     denied — the "ssh should be admitted-not-denied" property);
//   - a routing protocol in the `all` expansion (bgp tcp/179) IS admitted, via
//     the protocols token (positive control that `all` genuinely expands);
//   - an arbitrary non-routing, non-ssh port (tcp/9999) is DENIED — the NEGATIVE
//     boundary proving `protocols all` does not over-admit.
//
// host_inbound_classify_3627_test.go covers ssh+ping+bgp and the
// `system-services all` named-service union (`all` is NOT a full admit since
// #3226 — only `any-service` is), but no case pairs `protocols all` with a
// service to assert this non-over-admit boundary.
//
// FAIL-ON-REVERT: turning `protocols all` into a full admit (e.g. teaching
// HostInboundFullAdmitService to accept "all" as a protocol, or expanding
// HostInboundProtocolMatch("all") to a catch-all) admits tcp/9999, reddening
// the denied row.
func TestClassifyHostInboundProtocolsAllNotFullAdmit(t *testing.T) {
	const TCP = uint8(6)
	// system-services ssh + protocols all.
	cfg := cfgWithHostInbound("edge", []string{"ssh"}, []string{"all"})

	// ssh admitted via system-services (not swallowed by `protocols all`).
	if got := ClassifyHostInbound(cfg, "edge", TCP, true, 22, true, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != "ssh" || got.Kind != "system-services" {
		t.Fatalf("ssh tcp/22: got %+v, want token-admit ssh/system-services", got)
	}

	// bgp (tcp/179) admitted via `protocols all` -> token "all", kind protocols.
	if got := ClassifyHostInbound(cfg, "edge", TCP, true, 179, true, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != "all" || got.Kind != "protocols" {
		t.Fatalf("bgp tcp/179 via protocols all: got %+v, want token-admit all/protocols", got)
	}

	// tcp/9999 is neither ssh nor a routing protocol in the `all` expansion, so
	// it is DENIED. This is the boundary: `protocols all` must not open arbitrary
	// ports the way a full-admit system-service would.
	if got := ClassifyHostInbound(cfg, "edge", TCP, true, 9999, true, nil, "ip"); got.Status != HostInboundDenied {
		t.Fatalf("tcp/9999 with protocols all + ssh: got %+v, want denied (protocols all is not a full admit)", got)
	}
}
