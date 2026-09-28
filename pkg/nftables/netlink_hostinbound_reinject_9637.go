package nftables

// netlink_hostinbound_reinject_9637.go is the netlink mirror of the daemon
// oracle's reinject helpers (pkg/daemon/host_inbound_reinject_9637.go):
// the views-scoped destination set plus the iifname-scoped accept. Rendered
// immediately before the #9637 ingress-zone rules, in both chain shapes —
// the T1 parity gate proves the two renderers bit-identical.

// hostInboundReinjectDestinations mirrors the oracle's helper of the same
// name: every VIEW (zoned) firewall-local address per family, first-seen
// order, no duplicates. Unzoned addresses are EXCLUDED by construction — the
// #4420 catch-all DROP must keep judging unzoned-dst reinjects.
func hostInboundReinjectDestinations(views []HostInboundZoneView) (v4, v6 []string) {
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	add := func(out *[]string, seen map[string]bool, addrs []string) {
		for _, a := range addrs {
			if !seen[a] {
				seen[a] = true
				*out = append(*out, a)
			}
		}
	}
	for _, v := range views {
		add(&v4, seen4, v.V4Addrs)
		add(&v6, seen6, v.V6Addrs)
	}
	return v4, v6
}

// hostInboundTrustedReinject reports whether the chain will actually render
// the reinject accept: dataplane fresh AND addressed views. The stale-reply
// fallback excludes the TUN only then; otherwise TUN arrivals are guarded
// like any other uncovered ingress since no exemption exists to preserve.
func hostInboundTrustedReinject(spec HostInboundSpec) bool {
	if !spec.DataplaneFresh {
		return false
	}
	v4, v6 := hostInboundReinjectDestinations(spec.Views)
	return len(v4) > 0 || len(v6) > 0
}

// emitHostInboundReinjectAcceptNetlink mirrors emitHostInboundReinjectAccept
// (#9637 residual): the userspace-adjudicated reinject accept, scoped to the
// slow-path TUN and the view addresses, carrying the named accept counter.
// No-op per family without view addresses.
func emitHostInboundReinjectAcceptNetlink(p *nlPlan, f nlFamily, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	p.rule().iifname([]string{HostInboundReinjectIfname}).daddr(f, addrs, false).
		counterRef(HostInboundAcceptCounterName(HostInboundAcceptReinject)).emit(verdictAccept()...)
}
