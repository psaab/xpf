package nftables

import (
	"encoding/hex"
	"strings"
	"testing"
)

// #17192 (F2): NETLINK twin of pkg/daemon's
// TestKernelNDCatalogPosture17192. Pins the actual kernel verdict for
// ND (ICMPv6 133-136) to v6 catalog groups on the live netlink build
// path (buildHostInboundNetlink), so the Rust parity cell
// ndp_zone_override_catalog_parity_17192 cites kernel truth instead of
// asserting Rust-vs-Rust alone.
//
// Matrix: {ssh-only, ndp-positive, ndp-except, any-service} x
// {ff02::5 (catalog), ff02::1 (non-catalog)} on SCOPED ingress, plus
// ssh-only UNSCOPED (destination-fallback and wholly scopeless).
//
// Verdicts are read off the built rule list by FIRST-MATCH order over
// canonical rules (verdict(1)=accept, verdict(0)=drop), matching the
// probe: ingress ge-17192 (hex in canon), daddr ff02::5 exact or
// ff02::/16 prefix (masked cmp ff0200.. with ffff0000.. mask),
// icmpv6 ND type set {85,86,87,88} hex carried by a set lookup at
// payload(base=2,off=0,len=1) with l4proto guard 3a (ICMPv6).
// Matching is protocol-aware: the probe is ICMPv6 type 135, so a rule
// decides it only if the probe header can satisfy every predicate —
// a service rule pinning another L4 protocol (l4proto 06/11, port
// payload(base=2,off=2)) or a different transport type set can never
// match it. A rule with no deciding match is skipped;
// "policy-accept" means no rule decided and the chain policy
// (accept) admits — the unscoped kernel fail-open userspace
// deliberately does not reproduce (see host_inbound_decide in
// userspace-dp/.../forwarding/host_inbound.rs).

const kernelNDNetlinkIface17192 = "ge-17192"

var kernelNDCatalogV6Hex17192 = []string{
	"ff020000000000000000000000000005", // ff02::5
	"ff020000000000000000000000000006", // ff02::6
	"ff020000000000000000000000000009", // ff02::9
	"ff02000000000000000000000000000d", // ff02::d
	"ff020000000000000000000000000012", // ff02::12
}

// kernelNDNetlinkVerdict17192 returns "accept", "drop", or
// "policy-accept" for an ND probe (icmpv6 133-136) to dst on iface.
func kernelNDNetlinkVerdict17192(p *nlPlan, iface, dst string) string {
	ifaceHex := hex.EncodeToString([]byte(iface))
	isCatalog := dst == "ff02::5"
	for _, exprs := range p.rules {
		line := canonRule(p, exprs)
		verdict := ""
		switch {
		case strings.HasSuffix(line, "verdict(1)"):
			verdict = "accept"
		case strings.HasSuffix(line, "verdict(0)"):
			verdict = "drop"
		default:
			continue
		}
		if strings.Contains(line, "meta(key=6") && !strings.Contains(line, ifaceHex) {
			continue // scoped to a different ingress
		}
		scopedToProbe := strings.Contains(line, ifaceHex)
		// Catalog-set rule: lookup containing the v6 catalog groups.
		isCatalogSet := false
		for _, g := range kernelNDCatalogV6Hex17192 {
			if strings.Contains(line, g) {
				isCatalogSet = true
				break
			}
		}
		if isCatalogSet && strings.Contains(line, "lookup") {
			if isCatalog && (scopedToProbe || !strings.Contains(line, "meta(key=6")) {
				return verdict
			}
			continue
		}
		// ND probe protocol: ICMPv6 (l4proto 3a) type in
		// {85,86,87,88} hex = {133,134,135,136}. A rule carries the
		// ND protocol only if it pins that type set at the transport
		// header (in practice only when l4proto 3a is also pinned).
		// Other icmpv6 type sets (e.g. MLD 82,83,84,8f) are not ND.
		isNDType := strings.Contains(line, "payload(base=2,off=0") && (strings.Contains(line, "lookup(inv=false,set=[85,86,87,88])") || strings.Contains(line, "lookup(inv=false,set=[85,86,87,88,") || strings.Contains(line, ",85,86,87,88]") || strings.Contains(line, ",85,86,87,88,"))
		isFF02Prefix := strings.Contains(line, "payload(base=1,off=24,len=16") && strings.Contains(line, "ff020000000000000000000000000000") && strings.Contains(line, "ffff0000000000000000000000000000")
		if isNDType && isFF02Prefix {
			return verdict
		}
		if isNDType && !strings.Contains(line, "payload(base=1,off=24") {
			// Unscoped ND accept (no daddr payload at all).
			if !strings.Contains(line, "meta(key=6") {
				return verdict
			}
		}
		// Non-unicast ff02::/16 rules decide ff02::1 only if they can
		// match the ND probe header. Service rules pin a different
		// L4 protocol (meta(key=16 cmp 06/11) and/or a transport port
		// (payload(base=2,off=2)) and never match an ICMPv6/135
		// probe; rules pinning a non-ND transport type set likewise
		// skip. A bare ff02::/16 drop (and any-service accept) has
		// no l4proto/transport pin beyond the address and decides.
		if dst == "ff02::1" && isFF02Prefix {
			if strings.Contains(line, "meta(key=16,reg=1) cmp(op=0,reg=1,06)") || strings.Contains(line, "meta(key=16,reg=1) cmp(op=0,reg=1,11)") || strings.Contains(line, "meta(key=16,reg=1) cmp(op=1,reg=1,06)") || strings.Contains(line, "meta(key=16,reg=1) cmp(op=1,reg=1,11)") {
				continue
			}
			if strings.Contains(line, "payload(base=2,off=2") {
				continue
			}
			if strings.Contains(line, "payload(base=2,off=0") && !isNDType {
				continue
			}
			return verdict
		}
	}
	return "policy-accept"
}

func kernelNDNetlinkPlan17192(t *testing.T, v HostInboundZoneView) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_17192", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{Views: []HostInboundZoneView{v}})
	if p.err != nil {
		t.Fatalf("build netlink host-inbound: %v", p.err)
	}
	if len(p.rules) == 0 {
		t.Fatal("netlink plan emitted no rules (vacuous)")
	}
	return p
}

func TestKernelNDCatalogPostureNetlink17192(t *testing.T) {
	scoped := func(services, protocols, except []string) HostInboundZoneView {
		return HostInboundZoneView{
			Zone: "z17192", SystemServices: services, Protocols: protocols,
			ProtocolsExcept: except, V6Addrs: []string{"2001:db8::1"},
			IngressNetdevs: []string{kernelNDNetlinkIface17192},
		}
	}
	cases := []struct {
		name       string
		view       HostInboundZoneView
		wantFF02_5 string
		wantFF02_1 string
	}{
		{"ssh-only scoped", scoped([]string{"ssh"}, nil, nil), "drop", "accept"},
		{"ndp-positive scoped", scoped(nil, []string{"ndp"}, nil), "drop", "accept"},
		{"ndp-except scoped", scoped([]string{"ssh"}, []string{"ospf"}, []string{"ndp"}), "drop", "drop"},
		{"any-service scoped", scoped([]string{"any-service"}, nil, nil), "accept", "accept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := kernelNDNetlinkPlan17192(t, tc.view)
			if got := kernelNDNetlinkVerdict17192(p, kernelNDNetlinkIface17192, "ff02::5"); got != tc.wantFF02_5 {
				t.Errorf("netlink kernel ND to ff02::5 = %s, want %s\n%s", got, tc.wantFF02_5, canonRules(p))
			}
			if got := kernelNDNetlinkVerdict17192(p, kernelNDNetlinkIface17192, "ff02::1"); got != tc.wantFF02_1 {
				t.Errorf("netlink kernel ND to ff02::1 = %s, want %s\n%s", got, tc.wantFF02_1, canonRules(p))
			}
		})
	}
	unscoped := []struct {
		name string
		view HostInboundZoneView
	}{
		{"ssh-only destination-fallback", HostInboundZoneView{Zone: "z17192", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8::1"}}},
		{"ssh-only scopeless", HostInboundZoneView{Zone: "z17192", SystemServices: []string{"ssh"}}},
	}
	for _, tc := range unscoped {
		t.Run(tc.name, func(t *testing.T) {
			p := kernelNDNetlinkPlan17192(t, tc.view)
			if got := kernelNDNetlinkVerdict17192(p, kernelNDNetlinkIface17192, "ff02::5"); got != "accept" && got != "policy-accept" {
				t.Errorf("netlink kernel unscoped ND to ff02::5 = %s, want accept/policy-accept (kernel admits; no catalog drop ahead)\n%s", got, canonRules(p))
			}
		})
	}
}
