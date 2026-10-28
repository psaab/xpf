package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17192 (F2): KERNEL-side rendering assertions pinning the actual kernel
// verdict for ND (ICMPv6 133-136) to v6 catalog groups, so the Rust
// parity cell ndp_zone_override_catalog_parity_17192 cites kernel truth
// instead of asserting Rust-vs-Rust alone.
//
// Matrix: {ssh-only, ndp-positive, ndp-except, any-service} x
// {ff02::5 (catalog), ff02::1 (non-catalog)} on SCOPED ingress, plus
// ssh-only UNSCOPED (destination-fallback and wholly scopeless).
//
// Verdicts are read off the rendered chain by FIRST-MATCH order, exactly
// as nft evaluates it: for the probe packet (ingress ge-17192, daddr in
// ff02::/16, icmpv6 type in {133..136}) the first line that both matches
// the probe header and carries a terminal verdict (accept/drop) decides.
// Non-matching lines (unicast daddr, other icmp types, ct/reply guards,
// MLD return) are skipped by the matcher below.
//
// Scoped truth: the ingress-scoped catalog drop
// (emitHostInboundMulticastIngressGuards: `iifname "ge-17192" ip6 daddr
// { ff02::12, ff02::5, ff02::6, ff02::9, ff02::d } drop`) precedes every
// ND accept, so scoped ND to ff02::5 is DENIED for ssh-only and for
// ndp-except, and also for an ndp-token-only view (the ndp token opens
// no catalog group; only its scoped ff02::/16 ND accept exists, behind
// the drop). any-service emits a catalog ACCEPT ahead of its own drop,
// so any-service scoped ND to ff02::5 is ADMITTED. ff02::1 is not in
// the catalog set, so the catalog drop never matches it. Matching is
// protocol-aware: the probe is ICMPv6 type 135, so a line decides it
// only if the probe header can satisfy every predicate on that line.
// Retaining views admit ff02::1 via the scoped ff02::/16 ND accept,
// which precedes the non-unicast guard. For ndp-except the view emits
// no such ND accept, so the first decidable line is the non-unicast
// guard's ff02::/16 drop: its earlier `tcp dport 22 accept` service
// line cannot match an ICMPv6/135 probe, so ff02::1 is DROP there.
//
// Unscoped truth (the F1 correction): with no IngressNetdevs the kernel
// emits NO catalog drop for the view at all. The destination-fallback
// ND accept (`ip6 daddr 2001:db8::1 ...`) is unicast-only and does not
// match ff02::5, so that shape admits via the chain `policy accept`;
// a wholly scopeless view emits a bare unscoped ND accept, which
// admits directly. Either way the kernel ADMITS an ssh-only view's ND
// to ff02::5 unscoped. Userspace deliberately stays stricter there
// (fail-closed for a catalog destination on an unknown view); see
// host_inbound_decide in userspace-dp/.../forwarding/host_inbound.rs.

const kernelNDProbeIface17192 = "ge-17192"

// kernelNDVerdict17192 returns "accept", "drop", or "policy-accept"
// (no deciding rule matched; the chain policy decides) for an ND probe
// (icmpv6 type 135) to dst arriving on iface, by first-match order.
func kernelNDVerdict17192(payload, iface, dst string) string {
	isCatalog := dst == "ff02::5"
	for _, raw := range strings.Split(payload, "\n") {
		line := strings.TrimSpace(raw)
		// Must be scoped to the probe ingress when it names an ingress.
		if strings.Contains(line, "iifname") && !strings.Contains(line, `"`+iface+`"`) {
			continue
		}
		if !strings.Contains(line, `iifname "`+iface+`"`) && strings.Contains(line, "iifname") {
			continue
		}
		verdict := ""
		switch {
		case strings.HasSuffix(line, " accept"):
			verdict = "accept"
		case strings.HasSuffix(line, " drop"):
			verdict = "drop"
		default:
			continue
		}
		// Catalog-set drop/accept lines: they name the v6 catalog set.
		if strings.Contains(line, "ip6 daddr {") && strings.Contains(line, "ff02::") {
			if isCatalog {
				return verdict
			}
			continue
		}
		// ND lines to ff02::/16.
		if strings.Contains(line, "ff02::/16") && strings.Contains(line, "133, 134, 135, 136") {
			return verdict
		}
		// Unscoped ND accept (no iifname, no daddr).
		if strings.HasPrefix(line, "icmpv6 type { 133, 134, 135, 136 }") {
			return verdict
		}
		// Non-unicast ff02::/16 lines decide ff02::1 only if they can
		// match the ND probe header. Service lines pin a different
		// L4 protocol/port (e.g. `tcp dport 22`) and never match an
		// ICMPv6/135 probe; icmpv6 lines outside 133-136 likewise
		// skip. Bare ff02::/16 drops (and any-service accepts) carry
		// no L4 pin and do decide.
		if dst == "ff02::1" && strings.Contains(line, "ff02::/16") && !strings.Contains(line, "130, 131, 132, 143") {
			if strings.Contains(line, "icmpv6") && !strings.Contains(line, "133, 134, 135, 136") {
				continue
			}
			if strings.Contains(line, "icmp type") {
				continue
			}
			if strings.Contains(line, " tcp ") || strings.Contains(line, " udp ") || strings.Contains(line, "meta l4proto") {
				continue
			}
			if i := strings.Index(line, "ff02::/16"); i >= 0 {
				rest := strings.TrimSpace(line[i+len("ff02::/16"):])
				if rest != "accept" && rest != "drop" && !strings.HasPrefix(rest, "counter name") {
					continue
				}
			}
			return verdict
		}
	}
	return "policy-accept"
}

func kernelNDScopedView17192(services, protocols, except []string) dpuserspace.ZoneHostInboundView {
	return dpuserspace.ZoneHostInboundView{
		Zone:            "z17192",
		SystemServices:  services,
		Protocols:       protocols,
		ProtocolsExcept: except,
		V6Addrs:         []string{"2001:db8::1"},
		IngressNetdevs:  []string{kernelNDProbeIface17192},
	}
}

func TestKernelNDCatalogPosture17192(t *testing.T) {
	cases := []struct {
		name       string
		view       dpuserspace.ZoneHostInboundView
		wantFF02_5 string
		wantFF02_1 string
	}{
		{"ssh-only scoped", kernelNDScopedView17192([]string{"ssh"}, nil, nil), "drop", "accept"},
		{"ndp-positive scoped", kernelNDScopedView17192(nil, []string{"ndp"}, nil), "drop", "accept"},
		{"ndp-except scoped", kernelNDScopedView17192([]string{"ssh"}, []string{"ospf"}, []string{"ndp"}), "drop", "drop"},
		{"any-service scoped", kernelNDScopedView17192([]string{"any-service"}, nil, nil), "accept", "accept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildHostInboundFilterPayload([]dpuserspace.ZoneHostInboundView{tc.view}, nil, nil, nil, nil, true)
			if got := kernelNDVerdict17192(payload, kernelNDProbeIface17192, "ff02::5"); got != tc.wantFF02_5 {
				t.Errorf("kernel ND to ff02::5 = %s, want %s\n%s", got, tc.wantFF02_5, payload)
			}
			if got := kernelNDVerdict17192(payload, kernelNDProbeIface17192, "ff02::1"); got != tc.wantFF02_1 {
				t.Errorf("kernel ND to ff02::1 = %s, want %s\n%s", got, tc.wantFF02_1, payload)
			}
		})
	}

	// Unscoped ssh-only: destination-fallback view (addresses, no
	// ingress) and wholly scopeless view. Neither emits a catalog drop
	// ahead of any ND rule matching ff02::5, so the kernel admits via
	// chain policy — the F1 fail-open userspace deliberately does not
	// reproduce.
	unscoped := []struct {
		name string
		view dpuserspace.ZoneHostInboundView
	}{
		{"ssh-only destination-fallback", dpuserspace.ZoneHostInboundView{Zone: "z17192", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8::1"}}},
		{"ssh-only scopeless", dpuserspace.ZoneHostInboundView{Zone: "z17192", SystemServices: []string{"ssh"}}},
	}
	for _, tc := range unscoped {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildHostInboundFilterPayload([]dpuserspace.ZoneHostInboundView{tc.view}, nil, nil, nil, nil, true)
			if strings.Contains(payload, "ff02::5") && strings.Contains(payload, "drop") {
				// A catalog drop naming ff02::5 must not exist ahead of
				// the ND accepts for an unscoped view.
				for _, raw := range strings.Split(payload, "\n") {
					if strings.Contains(raw, "ff02::") && strings.HasSuffix(strings.TrimSpace(raw), " drop") {
						t.Errorf("unscoped view unexpectedly emits a catalog drop: %q\n%s", raw, payload)
					}
				}
			}
			if got := kernelNDVerdict17192(payload, kernelNDProbeIface17192, "ff02::5"); got != "accept" && got != "policy-accept" {
				t.Errorf("kernel unscoped ND to ff02::5 = %s, want accept/policy-accept (kernel admits; no catalog drop ahead)\n%s", got, payload)
			}
			if got := kernelNDVerdict17192(payload, kernelNDProbeIface17192, "ff02::1"); got != "policy-accept" && got != "accept" {
				t.Errorf("kernel unscoped ND to ff02::1 = %s, want accept/policy-accept\n%s", got, payload)
			}
		})
	}
}
