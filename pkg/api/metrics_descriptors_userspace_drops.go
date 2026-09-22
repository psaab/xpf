package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceDropsDescriptors() {
	c.userspaceGreDecapEcnIllegalDrops = prometheus.NewDesc(
		"xpf_userspace_gre_decap_ecn_illegal_drops_total",
		"GRE-decap frames dropped by the RFC 6040 4.2 decap-side ECN "+
			"combine because the outer header carried a CE (congestion "+
			"experienced) mark over an inner packet that was Not-ECT "+
			"(the illegal combination: a congested router CE-marked a "+
			"packet whose endpoints never negotiated ECN). RFC 6040 "+
			"mandates dropping this rather than silently clearing the "+
			"bogus CE. A nonzero value flags a misbehaving tunnel "+
			"ingress that ECT-marked the outer for un-ECN inner "+
			"traffic on a congested path (#2315).",
		nil, nil,
	)
	c.userspaceWgDecapEcnIllegalDrops = prometheus.NewDesc(
		"xpf_userspace_wg_decap_ecn_illegal_drops_total",
		"WireGuard-decap inner packets dropped by the RFC 6040 4.2 "+
			"decap-side ECN combine because the (recvmsg-captured) "+
			"outer header carried a CE (congestion experienced) mark "+
			"over an inner packet that was Not-ECT (the illegal "+
			"combination: a congested router CE-marked a packet whose "+
			"endpoints never negotiated ECN). The WG decap path reads "+
			"the outer ECN out-of-band via IP_RECVTOS/IPV6_RECVTCLASS "+
			"(the kernel UDP socket strips the outer IP header before "+
			"userspace) and applies the same combine. RFC 6040 mandates "+
			"dropping this rather than silently clearing the bogus CE. "+
			"A nonzero value flags a misbehaving WG ingress that "+
			"ECT-marked the outer for un-ECN inner traffic on a "+
			"congested path (#2317).",
		nil, nil,
	)
	c.userspaceGreEncapDfOversizeDrops = prometheus.NewDesc(
		"xpf_userspace_gre_encap_df_oversize_drops_total",
		"Native-GRE encap frames dropped because the fully built "+
			"outer datagram (outer IP + GRE header, including the "+
			"optional 4-byte key, + inner packet) exceeded the "+
			"resolved transport/egress MTU while the IPv4 outer "+
			"carries DF=1 (the only outer the native encap builder "+
			"emits; the IPv6 outer cannot be fragmented in-path "+
			"either). A DF-set oversized outer cannot be fragmented "+
			"downstream and would silently blackhole every inner flow "+
			"over the tunnel with no PMTUD signal back to the inner "+
			"source, so the builder refuses to emit it. A nonzero "+
			"value flags inner flows whose encapped size exceeds the "+
			"tunnel path MTU (typically a missing or too-high inner "+
			"MSS clamp, or a non-TCP inner with no segmentation "+
			"lever). PTB signalling for this path is implemented in "+
			"the TX dispatcher (#2330) and pre-empts the encap when a "+
			"PTB is owed, so this counter is the residual case where "+
			"none is owed: a non-DF IPv4 inner (#2331).",
		nil, nil,
	)
	c.userspaceGreDecapChecksumInvalidDrops = prometheus.NewDesc(
		"xpf_userspace_gre_decap_checksum_invalid_drops_total",
		"Native-GRE decap frames dropped because the GRE "+
			"Checksum-Present (C) bit was set but the GRE checksum "+
			"failed to verify (or the header was truncated past the "+
			"4-byte Checksum+Reserved1 field). Per RFC 2784 2.1 and "+
			"RFC 2890 the checksum is the IP-style one's-complement "+
			"checksum of the GRE header and payload; a checksummed "+
			"peer (for example a vSRX with GRE checksum enabled) is "+
			"now decapped after skipping and validating the checksum "+
			"field instead of being silently blackholed, and only a "+
			"frame the path corrupted is dropped here. A nonzero "+
			"value flags a checksummed GRE peer delivering corrupt "+
			"frames or a truncated GRE header (#2782).",
		nil, nil,
	)
	c.userspaceGreDecapUnsupportedVersionRefusals = prometheus.NewDesc(
		"xpf_userspace_gre_decap_unsupported_version_refusals_total",
		"Native-GRE frames refused for decapsulation because the GRE "+
			"version field was non-zero while the outer tuple named a "+
			"configured GRE tunnel endpoint. RFC 2784 and RFC 2890 GRE "+
			"is version 0; RFC 2637 (PPTP) enhanced GRE is version 1 and "+
			"re-purposes the same 32 bits the Key occupies as a 16-bit "+
			"Payload Length plus a 16-bit Call ID, and adds an "+
			"Acknowledgment Number field the RFC 2890 field order does "+
			"not skip, so parsing it with version-0 rules would read a "+
			"per-packet-varying length as a tunnel key and promote "+
			"attacker-chosen bytes as the inner packet. This is a "+
			"refusal, not a drop: the frame continues on the ordinary "+
			"transit or host-inbound path, and ordinary transit PPTP "+
			"(no configured endpoint for the outer tuple) is not "+
			"counted. A nonzero value flags a peer offering PPTP or "+
			"enhanced GRE to a tunnel endpoint xpf has no ALG to "+
			"terminate (#6842).",
		nil, nil,
	)
	c.userspaceTimeExceededRateLimited = prometheus.NewDesc(
		"xpf_userspace_time_exceeded_rate_limited_total",
		"Locally-generated ICMP/ICMPv6 Time Exceeded (TTL/hop-limit) "+
			"error replies dropped because the per-reason token bucket "+
			"was empty. The generator is rate-limited (global-per-reason, "+
			"Linux icmp_msgs_per_sec model, default 1000/s + 1000 burst) "+
			"so a low-TTL flood or a routing loop cannot drive unbounded "+
			"generated-error emission (CPU/TX amplification + reflection). "+
			"A nonzero value flags an error-amplification attempt (or a "+
			"real routing loop) being clamped (#2472).",
		nil, nil,
	)
	c.userspacePacketTooBigRateLimited = prometheus.NewDesc(
		"xpf_userspace_packet_too_big_rate_limited_total",
		"Locally-generated ICMPv4 Frag-Needed / ICMPv6 Packet Too Big "+
			"PMTUD replies dropped because the per-reason token bucket "+
			"was empty (same limiter as Time Exceeded, independent "+
			"bucket). A nonzero value flags an oversized-DF / IPv6 flood "+
			"being clamped before it amplifies into unbounded PTB "+
			"emission (#2472).",
		nil, nil,
	)
	c.userspaceRejectRateLimited = prometheus.NewDesc(
		"xpf_userspace_reject_rate_limited_total",
		"Locally-generated policy/filter `reject` replies (TCP RST or "+
			"ICMP/ICMPv6 administratively-prohibited unreachable) dropped "+
			"because the per-reason token bucket was empty. This is in "+
			"ADDITION to the SYN-cookie TX-frame budget gate "+
			"(which is queue protection, not a rate cap). A nonzero value "+
			"flags a rejected-flow flood being clamped before it amplifies "+
			"into unbounded RST/ICMP backscatter (#2472). Source-neutral "+
			"aggregate: the rate-limit bucket is a single global-per-reason "+
			"bucket. The per-source breakdown is "+
			"xpf_userspace_reject_rate_limited_by_source_total (#3661).",
		nil, nil,
	)
	// #3657 (H13/H15/M02): source-split reject reply telemetry. #3615
	// wired the per-source sent / TX-frame reply-budget / egress
	// output-filter legs onto BindingStatus; these expose them so
	// alerting can tell policy-reject from filter-reject and success from
	// suppression. Summed across bindings, labeled source=policy|filter,
	// emitted unconditionally (a 0 is a real "no reject activity" signal).
	c.userspaceRejectSent = prometheus.NewDesc(
		"xpf_userspace_reject_sent_total",
		"Locally-generated `reject` replies (TCP RST or ICMP/ICMPv6 "+
			"administratively-prohibited unreachable) actually enqueued, "+
			"split by source: a security-policy `then reject` "+
			"(source=policy, includes a zone `tcp-rst`) vs a "+
			"firewall-filter `then reject` (source=filter). This is the "+
			"active reject SUCCESS volume — as important as the suppression "+
			"counters for validating vSRX-style reject under load "+
			"(#3615/#3657 H13).",
		[]string{"source"}, nil,
	)
	c.userspaceRejectReplyBudgetDrops = prometheus.NewDesc(
		"xpf_userspace_reject_reply_budget_drops_total",
		"Locally-generated `reject` replies suppressed because the "+
			"per-tick TX-frame budget was exhausted, split by source "+
			"(policy vs firewall-filter). Budget pressure during a flood is "+
			"exactly when a `reject` is silently downgraded to a truthful "+
			"`deny`; the source split tells policy-reject starvation from "+
			"filter-reject starvation and is distinct from the global "+
			"rate-limit bucket (xpf_userspace_reject_rate_limited_total) "+
			"and an egress output-filter drop (#3615 L04/#3657 H14/M02).",
		[]string{"source"}, nil,
	)
	c.userspaceRejectOutputFilterDrops = prometheus.NewDesc(
		"xpf_userspace_reject_output_filter_drops_total",
		"Locally-generated `reject` replies dropped by an egress output "+
			"firewall filter (terminal discard/reject or three-color "+
			"policer) applied to the reflected reply's own egress tuple, "+
			"split by source (policy vs firewall-filter). Distinguishes an "+
			"operator-installed output filter suppressing a reject from a "+
			"TX-frame budget or rate-limit drop (#3615 L05/#3657 H15/M02).",
		[]string{"source"}, nil,
	)
	// #3661 (M02 Rust follow-up): per-source breakdown of the reject
	// rate-limit drop leg. The aggregate
	// xpf_userspace_reject_rate_limited_total stays source-neutral for
	// back-compat; this attributes each drop (at the consume site, where
	// the reply source is known) to a security-policy `then reject`
	// (source=policy) or a firewall-filter `then reject` (source=filter),
	// so a rejected-flow flood's bucket starvation is attributable. Both
	// sources share the one global-per-reason bucket, so policy+filter sum
	// to the aggregate. Summed across bindings, labeled source=policy|
	// filter, emitted unconditionally (a 0 is a real "no rate-limit drop"
	// signal).
	c.userspaceRejectRateLimitedBySource = prometheus.NewDesc(
		"xpf_userspace_reject_rate_limited_by_source_total",
		"Locally-generated `reject` replies (TCP RST or ICMP/ICMPv6 "+
			"administratively-prohibited unreachable) dropped because the "+
			"shared per-reason rate-limit token bucket was empty, split by "+
			"source (policy vs firewall-filter). Distinguishes "+
			"policy-reject starvation from filter-reject starvation under a "+
			"rejected-flow flood. The source-neutral aggregate is "+
			"xpf_userspace_reject_rate_limited_total; policy+filter sum to "+
			"it (#3661).",
		[]string{"source"}, nil,
	)
	c.userspaceMartianDropped = prometheus.NewDesc(
		"xpf_userspace_martian_dropped_total",
		"Packets dropped with a NoRoute disposition whose destination is a "+
			"martian address (IPv4 multicast/broadcast/unspecified/loopback, "+
			"IPv6 multicast/unspecified/loopback) — a firewall never forwards "+
			"these and they have no legitimate route, so they miss the FIB and "+
			"drop as NoRoute. A strict sub-breakout of the route-miss total "+
			"(every martian drop also bumps route_miss_packets), summed across "+
			"bindings, so an operator can tell a martian-dst drop apart from an "+
			"ordinary route miss and correlate it with a firewall-filter accept "+
			"log (#4743/#4768). Emitted unconditionally so 0 is a real "+
			"\"no martian drops\" signal.",
		nil, nil,
	)
	c.userspaceIPv6ExtHeaderDropped = prometheus.NewDesc(
		"xpf_userspace_ipv6_ext_header_dropped_total",
		"Packets fail-closed-dropped because their IPv6 extension-header "+
			"chain is unparseable or exceeds the MAX_IPV6_EXT_HEADERS walk "+
			"bound (an over-limit chain the helper cannot inspect), summed "+
			"across bindings. Distinct from a truncated chain; makes the "+
			"otherwise-silent fail-closed drop observable (#4743/#4768, "+
			"relates to #4555). Emitted unconditionally so 0 is a real "+
			"\"no ext-header drops\" signal.",
		nil, nil,
	)
	c.userspaceUMEMSliceDropped = prometheus.NewDesc(
		"xpf_userspace_umem_slice_dropped_total",
		"Packets dropped before raw-frame access because the UMEM slice "+
			"descriptor was invalid or outside the configured frame. "+
			"Summed across bindings and emitted unconditionally (#10498).",
		nil, nil,
	)
	c.userspaceUnknownVLANDropped = prometheus.NewDesc(
		"xpf_userspace_unknown_vlan_dropped_total",
		"Packets dropped during pre-L3 admission because their VLAN "+
			"identity was not configured. Summed across bindings and "+
			"emitted unconditionally (#10498).",
		nil, nil,
	)
	c.userspaceDstMACDropped = prometheus.NewDesc(
		"xpf_userspace_dst_mac_dropped_total",
		"Packets dropped during pre-L3 admission because their destination "+
			"MAC did not match a configured local or transit identity. "+
			"Summed across bindings and emitted unconditionally (#10498).",
		nil, nil,
	)
	c.userspaceEmbeddedQuoteSubminimalRefused = prometheus.NewDesc(
		"xpf_userspace_embedded_quote_subminimal_refused_total",
		"#9901 (F-077): embedded ICMP error quotes refused by the 8-byte "+
			"quoted-L4 adequacy floor — atomic-outer errors whose quoted "+
			"TCP/UDP/ICMP(v6) header carries fewer than 8 bytes. Before the "+
			"floor, 4 port bytes parsed and the error matched a live "+
			"session, so a minimal forged quote could steer an ICMP error "+
			"onto any session whose 4-tuple the quoter guessed.",
		nil, nil,
	)
	c.userspaceEmbeddedErrorPerSessionSuppressed = prometheus.NewDesc(
		"xpf_userspace_embedded_error_per_session_suppressed_total",
		"#9901 (F-077): embedded ICMP errors suppressed by the "+
			"per-session GCRA — errors that MATCHED a session but were "+
			"over that session's 64/64 budget. Without the budget, one "+
			"quoter can steer an UNBOUNDED error stream onto a live "+
			"session (forged PTB/TE as a PMTUD / throughput weapon).",
		nil, nil,
	)
}
