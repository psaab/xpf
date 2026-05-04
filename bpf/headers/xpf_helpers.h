#ifndef __BPFRX_HELPERS_H__
#define __BPFRX_HELPERS_H__

#include "xpf_common.h"

/* ============================================================
 * Packet parsing helpers
 * ============================================================ */

/* VLAN header for 802.1Q */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/*
 * Parse Ethernet header, handling one level of VLAN tagging.
 * Returns the EtherType of the inner protocol and updates l3_offset.
 * If vlan_id is non-NULL, writes the extracted VLAN ID (0 if untagged or
 * priority-tagged). If vlan_present is non-NULL, writes 1 when an 802.1Q/ad
 * header was present on ingress, including priority-tagged frames with VID 0.
 */
static __always_inline int
parse_ethhdr(void *data, void *data_end, __u16 *l3_offset, __u16 *eth_proto,
	     __u16 *vlan_id, __u8 *vlan_pcp, __u8 *vlan_present)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	*eth_proto = bpf_ntohs(eth->h_proto);
	*l3_offset = sizeof(struct ethhdr);
	if (vlan_id)
		*vlan_id = 0;
	if (vlan_pcp)
		*vlan_pcp = 0;
	if (vlan_present)
		*vlan_present = 0;

	/* Handle one level of VLAN */
	if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {
		struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
		if ((void *)(vlan + 1) > data_end)
			return -1;
		if (vlan_id || vlan_pcp) {
			__u16 vlan_tci = bpf_ntohs(vlan->h_vlan_TCI);
			if (vlan_id)
				*vlan_id = vlan_tci & 0x0FFF;
			if (vlan_pcp)
				*vlan_pcp = (vlan_tci >> 13) & 0x07;
		}
		if (vlan_present)
			*vlan_present = 1;
		*eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		*l3_offset += sizeof(struct vlan_hdr);
	}

	return 0;
}

/*
 * Strip the pseudo-Ethernet header prepended by xdp_main for tunnel
 * (POINTOPOINT) packets before XDP_PASS to the kernel stack.
 * The kernel expects raw IP on tunnel devices, not Ethernet frames.
 */
static __always_inline int
tunnel_pass(struct xdp_md *ctx, struct pkt_meta *meta)
{
	if (meta->meta_flags & META_FLAG_TUNNEL) {
		if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ethhdr)))
			return XDP_DROP;
	}
	return XDP_PASS;
}

/*
 * Strip 802.1Q VLAN tag from an XDP packet by shifting the Ethernet
 * header 4 bytes forward and shrinking the head.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
xdp_vlan_tag_pop(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Save the original Ethernet src/dst MAC and copy them after the shift */
	__u8 dmac[ETH_ALEN];
	__u8 smac[ETH_ALEN];
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);

	/* Move head forward by 4 bytes (VLAN header size) */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)))
		return -1;

	/* Re-read pointers after adjust */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Restore MACs -- the inner EtherType is already in place
	 * because we shifted past the VLAN header. But the MACs were
	 * in the old position, so copy them into the new eth header. */
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);

	return 0;
}

/*
 * Push an 802.1Q VLAN tag onto an XDP packet by growing the head
 * by 4 bytes and inserting the VLAN header.
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int
xdp_vlan_tag_push(struct xdp_md *ctx, __u16 vid)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Save MACs and inner EtherType to stack before adjust_head,
	 * avoiding overlapping memcpy after the head grows by 4 bytes. */
	__u8 dmac[ETH_ALEN];
	__u8 smac[ETH_ALEN];
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);
	__be16 inner_proto = eth->h_proto;

	/* Grow head by 4 bytes */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
		return -1;

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	/* Restore MACs from stack (no overlap) */
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_8021Q);

	/* Write VLAN header between Ethernet and inner EtherType */
	struct vlan_hdr *vhdr = data + sizeof(struct ethhdr);
	if ((void *)(vhdr + 1) > data_end)
		return -1;

	vhdr->h_vlan_TCI = bpf_htons(vid);
	vhdr->h_vlan_encapsulated_proto = inner_proto;

	return 0;
}

/*
 * Resolve the ingress zone before the screen stage so callers can bypass the
 * extra tail call when no effective screen work exists for this packet.
 *
 * Returns:
 *   XDP_PROG_ZONE   when screen can be skipped safely
 *   XDP_PROG_SCREEN when the packet still needs the screen stage
 *   -1             when ingress zone resolution failed
 */
static __always_inline int
resolve_ingress_xdp_target(struct pkt_meta *meta)
{
	struct iface_zone_key zk = {
		.ifindex = meta->ingress_ifindex,
		.vlan_id = meta->ingress_vlan_id,
	};
	struct iface_zone_value *izv = bpf_map_lookup_elem(&iface_zone_map, &zk);
	if (!izv)
		return -1;

	meta->ingress_zone = izv->zone_id;
	meta->meta_flags |= META_FLAG_INGRESS_RESOLVED;
	if (izv->flags & IFACE_FLAG_TUNNEL)
		meta->meta_flags |= META_FLAG_TUNNEL;
	if (izv->routing_table != 0)
		meta->routing_table = izv->routing_table;

	__u32 screen_flags = izv->screen_flags;
	if (screen_flags == 0)
		return XDP_PROG_ZONE;

	/*
	 * Common-case fast path: established TCP data/ACK packets don't need
	 * the SYN-centric screen logic. Keep the slow path for the few checks
	 * that can still apply mid-flow.
	 *
	 * #856: require the ACK bit so pure NULL scans (tf==0) never qualify
	 * for the bypass — they must run xdp_screen's SCREEN_TCP_NO_FLAG
	 * branch. Gate off when SCREEN_TCP_NO_FLAG is configured so the
	 * screen check always fires.  We deliberately do NOT gate on
	 * SCREEN_IP_SWEEP: the ip_sweep counter is keyed only on src+zone
	 * (no dst IP), so routing every established ACK through it would
	 * generate false positives on normal forwarding traffic.  ACK-only
	 * sweep detection is a follow-up (see TODO below).
	 */
	if (meta->protocol == PROTO_TCP && !meta->is_fragment) {
		__u8 tf = meta->tcp_flags;
		if ((tf & 0x10 /* ACK */) &&
		    !(tf & (0x02 /* SYN */ | 0x01 /* FIN */ |
			    0x04 /* RST */ | 0x20 /* URG */)) &&
		    !(screen_flags & SCREEN_TCP_NO_FLAG) &&
		    !(screen_flags & SCREEN_LAND_ATTACK) &&
		    !(meta->addr_family == AF_INET &&
		      (screen_flags & SCREEN_IP_SOURCE_ROUTE))) {
			/*
			 * #867: mark this packet as having bypassed
			 * xdp_screen so the conntrack miss path can run
			 * SCREEN_IP_SWEEP accounting on first-ACK flows
			 * that evade the SYN-centric screen.  Setting the
			 * bit here (and only here) is what makes the
			 * post-CT helper safe under LAND/TCP_NO_FLAG/
			 * SOURCE_ROUTE configurations: those packets
			 * fall through to xdp_screen and never carry
			 * the bit, so the helper bails for them.
			 */
			meta->meta_flags |= META_FLAG_SCREEN_SKIPPED;
			return XDP_PROG_ZONE;
		}
	}

	return XDP_PROG_SCREEN;
}

static __always_inline __u64
get_precise_ktime_ns(struct pkt_meta *meta)
{
	if (meta->ktime_ns == 0)
		meta->ktime_ns = bpf_ktime_get_ns();
	return meta->ktime_ns;
}

/*
 * Parse IPv4 header. Validates version and IHL.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_iphdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct iphdr *iph = data + meta->l3_offset;

	if ((void *)(iph + 1) > data_end)
		return -1;

	if (iph->version != 4)
		return -1;

	__u32 ihl = iph->ihl * 4;
	if (ihl < 20)
		return -1;
	if ((void *)iph + ihl > data_end)
		return -1;

	meta->src_ip.v4 = iph->saddr;
	meta->dst_ip.v4 = iph->daddr;
	meta->protocol  = iph->protocol;
	meta->ip_ttl    = iph->ttl;
	meta->dscp      = iph->tos >> 2;  /* top 6 bits of TOS = DSCP */
	meta->l4_offset = meta->l3_offset + ihl;
	meta->pkt_len   = bpf_ntohs(iph->tot_len);
	meta->addr_family = AF_INET;

	/* Fragmentation check (#866).
	 * 0x2000 = More Fragments (MF) bit, 0x1FFF = fragment offset.
	 *   is_fragment       = MF || offset != 0   (any frag piece)
	 *   is_first_fragment = MF && offset == 0   (first fragment by criteria)
	 * The first fragment typically contains the full L4 header for
	 * legitimate traffic, but RFC 791 doesn't strictly require it; a
	 * crafted tiny first-fragment may truncate the L4 header. Callers
	 * gating L4 parse on is_first_fragment rely on parse_l4hdr's
	 * bounds checks to drop truncated frames. Subsequent fragments
	 * (offset>0) have is_fragment=1, is_first_fragment=0. */
	__u16 frag_off = bpf_ntohs(iph->frag_off);
	meta->is_fragment = (frag_off & 0x2000) || (frag_off & 0x1FFF);
	meta->is_first_fragment = (frag_off & 0x2000) && !(frag_off & 0x1FFF);

	return 0;
}

/*
 * Parse IPv6 header with extension header chain walking.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_ipv6hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct ipv6hdr *ip6h = data + meta->l3_offset;

	if ((void *)(ip6h + 1) > data_end)
		return -1;

	if (ip6h->version != 6)
		return -1;

	/* Copy 128-bit addresses */
	__builtin_memcpy(meta->src_ip.v6, &ip6h->saddr, 16);
	__builtin_memcpy(meta->dst_ip.v6, &ip6h->daddr, 16);

	meta->ip_ttl      = ip6h->hop_limit;
	meta->dscp        = (ip6h->priority << 2) | (ip6h->flow_lbl[0] >> 6);
	/* #860: cast to u32 before the +40 — bpf_ntohs returns u16; the
	 * sum can wrap u16 for payload_len > 65495 even though pkt_len
	 * is now u32. */
	meta->pkt_len     = (__u32)bpf_ntohs(ip6h->payload_len) + 40;
	meta->addr_family = AF_INET6;
	meta->is_fragment = 0;
	meta->is_first_fragment = 0;

	/* Walk extension header chain to find the upper-layer protocol */
	__u8 nexthdr = ip6h->nexthdr;
	__u16 offset = meta->l3_offset + sizeof(struct ipv6hdr);

	#pragma unroll
	for (int i = 0; i < MAX_EXT_HDRS; i++) {
		switch (nexthdr) {
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST: {
			struct ipv6_opt_hdr *opt = data + offset;
			if ((void *)(opt + 1) > data_end)
				return -1;
			nexthdr = opt->nexthdr;
			offset += (opt->hdrlen + 1) * 8;
			break;
		}
		case NEXTHDR_AUTH: {
			struct ipv6_opt_hdr *opt = data + offset;
			if ((void *)(opt + 1) > data_end)
				return -1;
			nexthdr = opt->nexthdr;
			offset += (opt->hdrlen + 2) * 4;
			break;
		}
		case NEXTHDR_FRAGMENT: {
			struct frag_hdr *frag = data + offset;
			if ((void *)(frag + 1) > data_end)
				return -1;
			nexthdr = frag->nexthdr;
			offset += sizeof(struct frag_hdr);
			/* IPv6 frag header (#866).
			 * 0x1 = MF bit (lowest), 0xFFF8 = offset (top 13 bits).
			 *   is_fragment       = MF || offset != 0
			 *   is_first_fragment = MF && offset == 0
			 * As with IPv4, the first fragment typically contains
			 * the upper-layer (L4) header for legitimate traffic,
			 * but RFC 8200 doesn't strictly require it; parse_l4hdr
			 * bounds-checks and drops truncated headers. */
			__u16 frag_off = bpf_ntohs(frag->frag_off);
			if ((frag_off & 0x1) || (frag_off & 0xFFF8))
				meta->is_fragment = 1;
			if ((frag_off & 0x1) && !(frag_off & 0xFFF8))
				meta->is_first_fragment = 1;
			break;
		}
		case NEXTHDR_NONE:
			/* No next header */
			meta->protocol = nexthdr;
			meta->l4_offset = offset;
			return 0;
		default:
			/* Upper-layer protocol found */
			goto done;
		}
	}

done:
	meta->protocol  = nexthdr;
	meta->l4_offset = offset;
	return 0;
}

/* ============================================================
 * CHECKSUM_PARTIAL handling for XDP + TC paths.
 *
 * Virtio NICs deliver TCP/UDP packets with CHECKSUM_PARTIAL: the
 * L4 checksum field contains fold(PH) — a non-complemented
 * pseudo-header checksum seed.  The NIC (or skb_checksum_help)
 * finalizes by summing the actual L4 data bytes.
 *
 * Detection: parse_l4hdr computes the pseudo-header checksum from
 * the IP header and compares it with the L4 checksum field.
 * A match means the checksum field is only a pseudo-header seed.
 *
 * Generic XDP path: XDP_REDIRECT goes through dev_queue_xmit ->
 * validate_xmit_skb which DOES finalize the checksum.  We must
 * skip incremental updates for non-pseudo-header fields (ports,
 * MSS options) to keep the PH seed intact for kernel finalization.
 * IP address updates still apply since they change pseudo-header
 * fields, but must use csum_update_partial_4 (not csum_update_4)
 * because the seed is non-complemented: PH' = fold(PH + ~old + new).
 *
 * Native XDP path: XDP_REDIRECT uses __dev_direct_xmit which
 * bypasses finalization.  For native XDP, finalize_csum_partial()
 * must be called to compute the full checksum before nat_rewrite.
 *
 * TC path: Like generic XDP, the kernel finalizes after TC.
 * The same skip logic applies.
 * ============================================================ */

/*
 * Compute IPv4 pseudo-header checksum (folded to 16 bits, native byte order).
 * Uses the byte-order independence property of the internet checksum.
 */
static __always_inline __u16
compute_ph_csum_v4(__be32 saddr, __be32 daddr, __u8 protocol, __u16 l4_len)
{
	__u32 sum = 0;
	sum += ((__u32)saddr & 0xFFFF) + ((__u32)saddr >> 16);
	sum += ((__u32)daddr & 0xFFFF) + ((__u32)daddr >> 16);
	sum += (__u32)bpf_htons((__u16)protocol);
	sum += (__u32)bpf_htons(l4_len);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	/* Kernel CHECKSUM_PARTIAL stores fold(PH) in the L4 checksum
	 * field (see __tcp_v4_send_check: th->check = ~csum_fold(PH),
	 * and csum_fold returns ~fold, so th->check = fold(PH)). */
	return (__u16)sum;
}

/*
 * Compute IPv6 pseudo-header checksum (folded to 16 bits, native byte order).
 * IPv6 pseudo-header: src(128) + dst(128) + length(32) + next-hdr(32).
 */
static __always_inline __u16
compute_ph_csum_v6(const __u8 *saddr, const __u8 *daddr,
		   __u8 protocol, __u16 l4_len)
{
	__u32 sum = 0;
	const __u16 *s = (const __u16 *)saddr;
	const __u16 *d = (const __u16 *)daddr;
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		sum += (__u32)s[i];
		sum += (__u32)d[i];
	}
	sum += (__u32)bpf_htons((__u16)protocol);
	sum += (__u32)bpf_htons(l4_len);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (__u16)sum;
}

static __always_inline void
set_l4_csum_flags(struct pkt_meta *meta, __sum16 l4_csum)
{
	meta->csum_partial = 0;
	meta->l4_csum_saved = 0;

	/* Native XDP never has CHECKSUM_PARTIAL — skip expensive
	 * pseudo-header computation (saves ~10 insns IPv4, ~30 IPv6). */
	if (meta->native_xdp)
		return;

	if (l4_csum != 0) {
		__u16 l4_len = meta->pkt_len -
			       (meta->l4_offset - meta->l3_offset);
		__u16 ph;
		if (meta->addr_family == AF_INET)
			ph = compute_ph_csum_v4(meta->src_ip.v4,
						meta->dst_ip.v4,
						meta->protocol,
						l4_len);
		else
			ph = compute_ph_csum_v6(meta->src_ip.v6,
						meta->dst_ip.v6,
						meta->protocol,
						l4_len);
		if ((__u16)l4_csum == ph)
			meta->csum_partial = 1;
	}
}

/*
 * Conservative fast path for the common IPv4 TCP/UDP case.
 * Returns:
 *   1  packet fully parsed
 *   0  caller should fall back to the generic parse path
 *  -1  malformed packet
 */
static __always_inline int
parse_ipv4_l4_fast(void *data, void *data_end, struct pkt_meta *meta)
{
	struct iphdr *iph = data + meta->l3_offset;
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->version != 4 || iph->ihl != 5)
		return 0;

	meta->src_ip.v4 = iph->saddr;
	meta->dst_ip.v4 = iph->daddr;
	meta->protocol = iph->protocol;
	meta->ip_ttl = iph->ttl;
	meta->dscp = iph->tos >> 2;
	meta->l4_offset = meta->l3_offset + sizeof(struct iphdr);
	meta->pkt_len = bpf_ntohs(iph->tot_len);
	meta->addr_family = AF_INET;

	__u16 frag_off = bpf_ntohs(iph->frag_off);
	meta->is_fragment = (frag_off & 0x2000) || (frag_off & 0x1FFF);
	meta->is_first_fragment = (frag_off & 0x2000) && !(frag_off & 0x1FFF);
	/* Fast path bails on any fragment; first-fragment L4 parse is
	 * handled by the slow-path parse_l4hdr (see xdp_main.c gate). */
	if (meta->is_fragment)
		return 0;

	void *l4 = data + meta->l4_offset;
	__sum16 l4_csum = 0;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		meta->src_port = tcp->source;
		meta->dst_port = tcp->dest;
		meta->tcp_flags = ((__u8 *)tcp)[13];
		meta->tcp_seq = tcp->seq;
		meta->tcp_ack_seq = tcp->ack_seq;
		meta->payload_offset = meta->l4_offset + tcp->doff * 4;
		l4_csum = tcp->check;
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		meta->src_port = udp->source;
		meta->dst_port = udp->dest;
		meta->payload_offset = meta->l4_offset +
				       sizeof(struct udphdr);
		l4_csum = udp->check;
	} else {
		return 0;
	}

	set_l4_csum_flags(meta, l4_csum);
	return 1;
}

/*
 * Conservative fast path for the common IPv6 TCP/UDP case with no
 * extension headers. Falls back for any extension-header packet.
 */
static __always_inline int
parse_ipv6_l4_fast(void *data, void *data_end, struct pkt_meta *meta)
{
	struct ipv6hdr *ip6h = data + meta->l3_offset;
	if ((void *)(ip6h + 1) > data_end)
		return -1;
	if (ip6h->version != 6)
		return -1;

	__u8 nexthdr = ip6h->nexthdr;
	if (nexthdr != PROTO_TCP && nexthdr != PROTO_UDP)
		return 0;

	__builtin_memcpy(meta->src_ip.v6, &ip6h->saddr, 16);
	__builtin_memcpy(meta->dst_ip.v6, &ip6h->daddr, 16);
	meta->protocol = nexthdr;
	meta->ip_ttl = ip6h->hop_limit;
	meta->dscp = (ip6h->priority << 2) | (ip6h->flow_lbl[0] >> 6);
	/* #860: cast to u32 to avoid u16 wrap for jumbo frames. */
	meta->pkt_len = (__u32)bpf_ntohs(ip6h->payload_len) + sizeof(struct ipv6hdr);
	meta->addr_family = AF_INET6;
	meta->is_fragment = 0;
	meta->l4_offset = meta->l3_offset + sizeof(struct ipv6hdr);

	void *l4 = data + meta->l4_offset;
	__sum16 l4_csum = 0;

	if (nexthdr == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		meta->src_port = tcp->source;
		meta->dst_port = tcp->dest;
		meta->tcp_flags = ((__u8 *)tcp)[13];
		meta->tcp_seq = tcp->seq;
		meta->tcp_ack_seq = tcp->ack_seq;
		meta->payload_offset = meta->l4_offset + tcp->doff * 4;
		l4_csum = tcp->check;
	} else {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		meta->src_port = udp->source;
		meta->dst_port = udp->dest;
		meta->payload_offset = meta->l4_offset +
				       sizeof(struct udphdr);
		l4_csum = udp->check;
	}

	set_l4_csum_flags(meta, l4_csum);
	return 1;
}

/*
 * Optional CHECKSUM_PARTIAL resolution for IPv6.
 *
 * Some call sites can choose to defer IPv6 pseudo-header checksum
 * detection by saving the raw L4 checksum in l4_csum_saved.  When
 * parse_l4hdr() resolves the checksum inline, l4_csum_saved stays 0
 * and this becomes a no-op.
 *
 * Reads source/destination addresses from the PACKET (not meta),
 * so must be called BEFORE any packet header modification.
 */
static __always_inline void
resolve_csum_partial(void *data, void *data_end, struct pkt_meta *meta)
{
	if (!meta->l4_csum_saved)
		return;

	__u16 saved = meta->l4_csum_saved;
	meta->l4_csum_saved = 0;

	if (meta->l3_offset >= 64)
		return;

	struct ipv6hdr *ip6h = data + (meta->l3_offset & 0x3F);
	if ((void *)(ip6h + 1) > data_end)
		return;

	__u16 l4_len = meta->pkt_len -
		       (meta->l4_offset - meta->l3_offset);
	__u16 ph = compute_ph_csum_v6((__u8 *)&ip6h->saddr,
				      (__u8 *)&ip6h->daddr,
				      meta->protocol, l4_len);
	if (saved == ph)
		meta->csum_partial = 1;
}

/*
 * Finalize a CHECKSUM_PARTIAL packet's L4 checksum for XDP path.
 *
 * For native XDP, XDP_REDIRECT bypasses the kernel's TX path
 * (validate_xmit_skb / skb_checksum_help), so CHECKSUM_PARTIAL
 * packets would go out with only the pseudo-header seed in the
 * L4 checksum field.  This function computes the full checksum
 * from raw packet data, equivalent to skb_checksum_help().
 *
 * The L4 checksum field already contains the pseudo-header seed.
 * Summing all L4 bytes (which includes this seed) and folding
 * gives the correct final checksum -- same as skb_checksum_help.
 *
 * Must be called BEFORE any incremental checksum updates (NAT,
 * MSS clamping) in the XDP pipeline.  After this, csum_partial
 * is set to 0 and normal incremental updates can proceed.
 *
 * Do NOT call from TC programs -- the kernel handles finalization.
 */
static __always_inline void
finalize_csum_partial(void *data, void *data_end, struct pkt_meta *meta)
{
	if (!meta->csum_partial)
		return;

	if (meta->l4_offset >= 128)
		return;

	void *l4 = data + meta->l4_offset;
	if (l4 + 20 > data_end)
		return;

	/*
	 * Sum all L4 data as 16-bit words.  The checksum field
	 * contains the pseudo-header seed, which participates in
	 * the sum correctly (same as skb_checksum_help).
	 *
	 * Bounded loop with per-iteration packet check satisfies
	 * the BPF verifier.  Max 750 iterations for 1500-byte MTU.
	 */
	__u32 sum = 0;
	__u16 *p = (__u16 *)l4;

	#pragma unroll 1
	for (int i = 0; i < 750; i++) {
		if ((void *)(p + 1) > data_end)
			break;
		sum += *p;
		p++;
	}

	/* Handle trailing odd byte */
	__u8 *bp = (__u8 *)p;
	if ((void *)(bp + 1) <= data_end)
		sum += (__u32)*bp;

	/* Fold to 16 bits and complement */
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	__sum16 final_csum = (__sum16)(~sum & 0xFFFF);

	/* Write the finalized checksum back to the packet */
	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) <= data_end)
			tcp->check = final_csum;
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) <= data_end)
			udp->check = final_csum;
	} else if (meta->protocol == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) <= data_end)
			icmp6->icmp6_cksum = final_csum;
	}

	meta->csum_partial = 0;
}

/*
 * Parse L4 header (TCP, UDP, ICMP, or ICMPv6).
 * Returns 0 on success.
 */
static __always_inline int
parse_l4hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	void *l4 = data + meta->l4_offset;
	__sum16 l4_csum = 0;

	switch (meta->protocol) {
	case PROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		meta->src_port = tcp->source;
		meta->dst_port = tcp->dest;
		meta->tcp_flags = ((__u8 *)tcp)[13];
		meta->tcp_seq = tcp->seq;
		meta->tcp_ack_seq = tcp->ack_seq;
		meta->payload_offset = meta->l4_offset + tcp->doff * 4;
		l4_csum = tcp->check;
		break;
	}
	case PROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		meta->src_port = udp->source;
		meta->dst_port = udp->dest;
		meta->payload_offset = meta->l4_offset + sizeof(struct udphdr);
		l4_csum = udp->check;
		break;
	}
	case PROTO_ICMP: {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) > data_end)
			return -1;
		meta->icmp_type = icmp->type;
		meta->icmp_code = icmp->code;
		meta->icmp_id   = icmp->un.echo.id;
		meta->src_port  = icmp->un.echo.id; /* use as port for CT */
		/* For echo req/reply, set dst_port = echo_id so pre-routing
		 * DNAT lookup works for return traffic */
		meta->dst_port  = (icmp->type == 8 || icmp->type == 0) ?
				  icmp->un.echo.id : 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmphdr);
		/* ICMP has no pseudo-header -- l4_csum stays 0 */
		break;
	}
	case PROTO_ICMPV6: {
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return -1;
		meta->icmp_type = icmp6->icmp6_type;
		meta->icmp_code = icmp6->icmp6_code;
		meta->icmp_id   = icmp6->un.echo.id;
		meta->src_port  = icmp6->un.echo.id; /* use as port for CT */
		/* For echo req/reply, set dst_port = echo_id */
		meta->dst_port  = (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129) ?
				  icmp6->un.echo.id : 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmp6hdr);
		l4_csum = icmp6->icmp6_cksum;
		break;
	}
	case PROTO_ESP: {
		/* ESP header: 4-byte SPI + 4-byte sequence number */
		struct {
			__be32 spi;
			__be32 seq;
		} *esp = l4;
		if ((void *)(esp + 1) > data_end)
			return -1;
		/* Split 32-bit SPI into two 16-bit halves for session tracking.
		 * Combined src_port+dst_port reconstructs the full SPI. */
		meta->src_port = (__be16)(esp->spi >> 16);
		meta->dst_port = (__be16)(esp->spi & 0xFFFF);
		meta->payload_offset = meta->l4_offset + 8;
		/* No L4 checksum for ESP (auth covers entire payload) */
		break;
	}
	case PROTO_GRE: {
		/* GRE header (RFC 2784/2890):
		 *   bytes 0-1: flags (C|res|K|S|Reserved0|Ver)
		 *   bytes 2-3: protocol type
		 *   optional:  checksum+reserved1 (4B if C=1),
		 *              key (4B if K=1), sequence (4B if S=1)
		 *
		 * When gre_accel is enabled, split the 32-bit GRE key
		 * into src_port/dst_port for per-tunnel session tracking
		 * (same pattern as ESP SPI). */
		struct {
			__be16 flags;
			__be16 protocol;
		} *gre = l4;
		if ((void *)(gre + 1) > data_end)
			return -1;

		__u16 flags = bpf_ntohs(gre->flags);
		__u16 gre_hdr_len = 4; /* minimum */

		if (flags & 0x8000) /* C: checksum present */
			gre_hdr_len += 4;

		/* Check gre_accel before parsing key — only extract key
		 * into ports when acceleration is enabled. */
		if (flags & 0x2000) { /* K: key present */
			__u32 fc_z = 0;
			struct flow_config *fc =
				bpf_map_lookup_elem(&flow_config_map, &fc_z);
			if (fc && fc->gre_accel) {
				/* Read key at constant offset per branch
				 * to keep verifier happy. */
				if (flags & 0x8000) {
					/* C+K: key at offset 8 */
					__be32 *kp = l4 + 8;
					if ((void *)(kp + 1) <= data_end) {
						meta->src_port =
							(__be16)(*kp >> 16);
						meta->dst_port =
							(__be16)(*kp & 0xFFFF);
					}
				} else {
					/* K only: key at offset 4 */
					__be32 *kp = l4 + 4;
					if ((void *)(kp + 1) <= data_end) {
						meta->src_port =
							(__be16)(*kp >> 16);
						meta->dst_port =
							(__be16)(*kp & 0xFFFF);
					}
				}
			}
			gre_hdr_len += 4;
		}

		if (flags & 0x1000) /* S: sequence present */
			gre_hdr_len += 4;

		meta->payload_offset = meta->l4_offset + gre_hdr_len;
		/* No L4 checksum field used for session tracking */
		break;
	}
	default:
		meta->payload_offset = meta->l4_offset;
		break;
	}

	/*
	 * Detect CHECKSUM_PARTIAL: if the L4 checksum field equals the
	 * pseudo-header checksum, the packet uses hardware checksum
	 * offload and we must NOT do incremental updates for non-
	 * pseudo-header fields (ports, TCP options) -- the NIC or
	 * skb_checksum_help will sum the actual data bytes later.
	 *
	 * Detect inline for both IPv4 and IPv6. The lazy IPv6 path is
	 * retained as a helper, but eager detection keeps forwarding
	 * behavior correct across all packet paths.
	 */
	set_l4_csum_flags(meta, l4_csum);

	return 0;
}

/* ============================================================
 * Checksum helpers
 * ============================================================ */

/*
 * Incremental checksum update (RFC 1624) for a 4-byte field change.
 * For standard (complemented) checksums where field = ~fold(sum).
 */
static __always_inline void
csum_update_4(__sum16 *csum, __be32 old_val, __be32 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~bpf_ntohl(old_val) & 0xFFFF;
	sum += ~(bpf_ntohl(old_val) >> 16) & 0xFFFF;
	sum += bpf_ntohl(new_val) & 0xFFFF;
	sum += (bpf_ntohl(new_val) >> 16) & 0xFFFF;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental pseudo-header seed update for CHECKSUM_PARTIAL packets.
 *
 * CHECKSUM_PARTIAL L4 field contains fold(PH) — a non-complemented
 * pseudo-header checksum.  The standard RFC 1624 formula (csum_update_4)
 * complements input and output, which is wrong for this representation.
 * Correct formula: PH' = fold(PH + ~old + new).
 */
static __always_inline void
csum_update_partial_4(__sum16 *csum, __be32 old_val, __be32 new_val)
{
	__u32 sum;

	sum = ((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~bpf_ntohl(old_val) & 0xFFFF;
	sum += ~(bpf_ntohl(old_val) >> 16) & 0xFFFF;
	sum += bpf_ntohl(new_val) & 0xFFFF;
	sum += (bpf_ntohl(new_val) >> 16) & 0xFFFF;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 2-byte field change.
 */
static __always_inline void
csum_update_2(__sum16 *csum, __be16 old_val, __be16 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~((__u32)bpf_ntohs(old_val)) & 0xFFFF;
	sum += (__u32)bpf_ntohs(new_val);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 128-bit (IPv6) address change.
 * Processes the address as four 32-bit words.
 */
static __always_inline void
csum_update_16(__sum16 *csum, const __u8 *old_addr, const __u8 *new_addr)
{
	/* Process as four 32-bit words */
	#pragma unroll
	for (int i = 0; i < 4; i++) {
		__be32 old_word, new_word;
		__builtin_memcpy(&old_word, old_addr + i * 4, 4);
		__builtin_memcpy(&new_word, new_addr + i * 4, 4);
		if (old_word != new_word)
			csum_update_4(csum, old_word, new_word);
	}
}

/*
 * Incremental pseudo-header seed update for a 128-bit (IPv6) address
 * change on CHECKSUM_PARTIAL packets.
 */
static __always_inline void
csum_update_partial_16(__sum16 *csum, const __u8 *old_addr,
		       const __u8 *new_addr)
{
	#pragma unroll
	for (int i = 0; i < 4; i++) {
		__be32 old_word, new_word;
		__builtin_memcpy(&old_word, old_addr + i * 4, 4);
		__builtin_memcpy(&new_word, new_addr + i * 4, 4);
		if (old_word != new_word)
			csum_update_partial_4(csum, old_word, new_word);
	}
}

/* ============================================================
 * IPv6 address comparison helper
 * ============================================================ */

static __always_inline int
ip_addr_eq_v6(const __u8 *a, const __u8 *b)
{
	const __u32 *a32 = (const __u32 *)a;
	const __u32 *b32 = (const __u32 *)b;
	return (a32[0] == b32[0]) && (a32[1] == b32[1]) &&
	       (a32[2] == b32[2]) && (a32[3] == b32[3]);
}

/* ============================================================
 * Configurable session timeout lookup (falls back to defaults)
 * ============================================================ */

static __always_inline __u32
ct_get_timeout(__u8 protocol, __u8 state)
{
	__u32 idx;
	switch (protocol) {
	case PROTO_TCP:
		switch (state) {
		case SESS_STATE_ESTABLISHED:
			idx = FLOW_TIMEOUT_TCP_ESTABLISHED;
			break;
		case SESS_STATE_FIN_WAIT:
		case SESS_STATE_CLOSE_WAIT:
			idx = FLOW_TIMEOUT_TCP_CLOSING;
			break;
		case SESS_STATE_TIME_WAIT:
			idx = FLOW_TIMEOUT_TCP_TIME_WAIT;
			break;
		default:
			idx = FLOW_TIMEOUT_TCP_INITIAL;
			break;
		}
		break;
	case PROTO_UDP:
		idx = FLOW_TIMEOUT_UDP;
		break;
	case PROTO_ICMP:
	case PROTO_ICMPV6:
		idx = FLOW_TIMEOUT_ICMP;
		break;
	default:
		idx = FLOW_TIMEOUT_OTHER;
		break;
	}
	__u32 *val = bpf_map_lookup_elem(&flow_timeouts, &idx);
	if (val && *val > 0)
		return *val;
	return ct_get_timeout_default(protocol, state);
}

/* ============================================================
 * Global counter increment helper
 * ============================================================ */

static __always_inline void
inc_counter(__u32 ctr_idx)
{
	__u64 *ctr = bpf_map_lookup_elem(&global_counters, &ctr_idx);
	if (ctr)
		(*ctr)++;
}

/* Map a SCREEN_* flag bit to a per-screen-type counter index. */
static __always_inline void
inc_screen_counter(__u32 screen_flag)
{
	__u32 idx;
	switch (screen_flag) {
	case SCREEN_SYN_FLOOD:      idx = GLOBAL_CTR_SCREEN_SYN_FLOOD; break;
	case SCREEN_ICMP_FLOOD:     idx = GLOBAL_CTR_SCREEN_ICMP_FLOOD; break;
	case SCREEN_UDP_FLOOD:      idx = GLOBAL_CTR_SCREEN_UDP_FLOOD; break;
	case SCREEN_PORT_SCAN:      idx = GLOBAL_CTR_SCREEN_PORT_SCAN; break;
	case SCREEN_IP_SWEEP:       idx = GLOBAL_CTR_SCREEN_IP_SWEEP; break;
	case SCREEN_LAND_ATTACK:    idx = GLOBAL_CTR_SCREEN_LAND_ATTACK; break;
	case SCREEN_PING_OF_DEATH:  idx = GLOBAL_CTR_SCREEN_PING_OF_DEATH; break;
	case SCREEN_TEAR_DROP:      idx = GLOBAL_CTR_SCREEN_TEAR_DROP; break;
	case SCREEN_TCP_SYN_FIN:    idx = GLOBAL_CTR_SCREEN_TCP_SYN_FIN; break;
	case SCREEN_TCP_NO_FLAG:    idx = GLOBAL_CTR_SCREEN_TCP_NO_FLAG; break;
	case SCREEN_TCP_FIN_NO_ACK: idx = GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK; break;
	case SCREEN_WINNUKE:        idx = GLOBAL_CTR_SCREEN_WINNUKE; break;
	case SCREEN_IP_SOURCE_ROUTE:idx = GLOBAL_CTR_SCREEN_IP_SRC_ROUTE; break;
	case SCREEN_SYN_FRAG:       idx = GLOBAL_CTR_SCREEN_SYN_FRAG; break;
	case SCREEN_SESSION_LIMIT_SRC: idx = GLOBAL_CTR_SCREEN_SESSION_LIMIT; break;
	case SCREEN_SESSION_LIMIT_DST: idx = GLOBAL_CTR_SCREEN_SESSION_LIMIT; break;
	default: return;
	}
	inc_counter(idx);
}

/* interface_counters is a PERCPU_HASH (#756). Go control plane pre-seeds
 * entries on interface registration (AddTxPort / AttachXDP) so the
 * hot path stays lookup-only — no allocation or update from softirq.
 * A missing entry on an unregistered interface reads as zero. */
static __always_inline void
inc_iface_rx(__u32 ifindex, __u32 pkt_len)
{
	struct iface_counter_value *ic = bpf_map_lookup_elem(&interface_counters, &ifindex);
	if (ic) { ic->rx_packets++; ic->rx_bytes += pkt_len; }
}

static __always_inline void
inc_iface_tx(__u32 ifindex, __u32 pkt_len)
{
	struct iface_counter_value *ic = bpf_map_lookup_elem(&interface_counters, &ifindex);
	if (ic) { ic->tx_packets++; ic->tx_bytes += pkt_len; }
}

static __always_inline void
inc_zone_ingress(__u32 zone_id, __u32 pkt_len)
{
	__u32 idx = zone_id * 2;
	struct counter_value *zc = bpf_map_lookup_elem(&zone_counters, &idx);
	if (zc) { zc->packets++; zc->bytes += pkt_len; }
}

static __always_inline void
inc_zone_egress(__u32 zone_id, __u32 pkt_len)
{
	__u32 idx = zone_id * 2 + 1;
	struct counter_value *zc = bpf_map_lookup_elem(&zone_counters, &idx);
	if (zc) { zc->packets++; zc->bytes += pkt_len; }
}

static __always_inline void
inc_policy_counter(__u32 policy_id, __u32 pkt_len)
{
	struct counter_value *pc = bpf_map_lookup_elem(&policy_counters, &policy_id);
	if (pc) { pc->packets++; pc->bytes += pkt_len; }
}

/* ============================================================
 * Ring buffer event emission helper (shared by policy + screen)
 * ============================================================ */

static __always_inline void
emit_event(struct pkt_meta *meta, __u8 event_type, __u8 action,
	   __u64 packets, __u64 bytes, __u8 close_reason)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	/* Copy IP addresses based on address family */
	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);
	__builtin_memset(evt->nat_src_ip, 0, 16);
	__builtin_memset(evt->nat_dst_ip, 0, 16);

	if (meta->addr_family == AF_INET) {
		__builtin_memcpy(evt->src_ip, &meta->src_ip.v4, 4);
		__builtin_memcpy(evt->dst_ip, &meta->dst_ip.v4, 4);
	} else {
		__builtin_memcpy(evt->src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(evt->dst_ip, meta->dst_ip.v6, 16);
	}

	evt->src_port = meta->src_port;
	evt->dst_port = meta->dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;
	evt->nat_src_port = 0;
	evt->nat_dst_port = 0;
	evt->created = 0;
	evt->rev_packets = 0;
	evt->rev_bytes = 0;
	evt->ingress_ifindex = meta->ingress_ifindex;
	evt->app_id = 0;
	evt->close_reason = close_reason;
	evt->pad_event = 0;

	bpf_ringbuf_submit(evt, 0);
}

/*
 * Drop a packet due to a screen check.
 * Stores the screen flag in policy_id for event logging,
 * increments the screen drop counter, emits a ring buffer event,
 * and returns XDP_DROP.
 *
 * Promoted from xdp_screen.c so the conntrack ACK-evasion path
 * (#867) can share the same screen-drop side effects (policy_id,
 * GLOBAL_CTR_SCREEN_DROPS, per-screen counter, EVENT_TYPE_SCREEN_DROP).
 * Placed AFTER emit_event() to satisfy the forward declaration.
 */
static __always_inline int
screen_drop(struct pkt_meta *meta, __u32 screen_flag)
{
	meta->policy_id = screen_flag;
	inc_counter(GLOBAL_CTR_SCREEN_DROPS);
	inc_screen_counter(screen_flag);
	emit_event(meta, EVENT_TYPE_SCREEN_DROP, ACTION_DENY, 0, 0, 0);
	return XDP_DROP;
}

/*
 * Emit event with NAT translation fields from a session_value (IPv4).
 * Used at SESSION_CLOSE and SESSION_OPEN when session NAT info is available.
 */
static __always_inline void
emit_event_nat4(struct pkt_meta *meta, __u8 event_type, __u8 action,
		__u64 packets, __u64 bytes,
		__be32 nat_src_ip, __be32 nat_dst_ip,
		__be16 nat_src_port, __be16 nat_dst_port,
		__u32 created,
		__u64 rev_packets, __u64 rev_bytes,
		__u16 app_id, __u8 close_reason)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);
	__builtin_memset(evt->nat_src_ip, 0, 16);
	__builtin_memset(evt->nat_dst_ip, 0, 16);

	if (meta->addr_family == AF_INET) {
		__builtin_memcpy(evt->src_ip, &meta->src_ip.v4, 4);
		__builtin_memcpy(evt->dst_ip, &meta->dst_ip.v4, 4);
		__builtin_memcpy(evt->nat_src_ip, &nat_src_ip, 4);
		__builtin_memcpy(evt->nat_dst_ip, &nat_dst_ip, 4);
	} else {
		__builtin_memcpy(evt->src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(evt->dst_ip, meta->dst_ip.v6, 16);
	}

	evt->src_port = meta->src_port;
	evt->dst_port = meta->dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;
	evt->nat_src_port = nat_src_port;
	evt->nat_dst_port = nat_dst_port;
	evt->created = created;
	evt->rev_packets = rev_packets;
	evt->rev_bytes = rev_bytes;
	evt->ingress_ifindex = meta->ingress_ifindex;
	evt->app_id = app_id;
	evt->close_reason = close_reason;
	evt->pad_event = 0;

	bpf_ringbuf_submit(evt, 0);
}

/*
 * Emit event with explicit original + translated IPv4 tuples.
 * Used when meta has already been rewritten for post-policy NAT.
 */
static __always_inline void
emit_event_nat4_orig(struct pkt_meta *meta, __u8 event_type, __u8 action,
		     __u64 packets, __u64 bytes,
		     __be32 orig_src_ip, __be32 orig_dst_ip,
		     __be16 orig_src_port, __be16 orig_dst_port,
		     __be32 nat_src_ip, __be32 nat_dst_ip,
		     __be16 nat_src_port, __be16 nat_dst_port,
		     __u32 created,
		     __u64 rev_packets, __u64 rev_bytes,
		     __u16 app_id, __u8 close_reason)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);
	__builtin_memset(evt->nat_src_ip, 0, 16);
	__builtin_memset(evt->nat_dst_ip, 0, 16);

	__builtin_memcpy(evt->src_ip, &orig_src_ip, 4);
	__builtin_memcpy(evt->dst_ip, &orig_dst_ip, 4);
	__builtin_memcpy(evt->nat_src_ip, &nat_src_ip, 4);
	__builtin_memcpy(evt->nat_dst_ip, &nat_dst_ip, 4);

	evt->src_port = orig_src_port;
	evt->dst_port = orig_dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;
	evt->nat_src_port = nat_src_port;
	evt->nat_dst_port = nat_dst_port;
	evt->created = created;
	evt->rev_packets = rev_packets;
	evt->rev_bytes = rev_bytes;
	evt->ingress_ifindex = meta->ingress_ifindex;
	evt->app_id = app_id;
	evt->close_reason = close_reason;
	evt->pad_event = 0;

	bpf_ringbuf_submit(evt, 0);
}

/*
 * Emit event with NAT translation fields from a session_value_v6.
 */
static __always_inline void
emit_event_nat6(struct pkt_meta *meta, __u8 event_type, __u8 action,
		__u64 packets, __u64 bytes,
		const __u8 *nat_src_ip, const __u8 *nat_dst_ip,
		__be16 nat_src_port, __be16 nat_dst_port,
		__u32 created,
		__u64 rev_packets, __u64 rev_bytes,
		__u16 app_id, __u8 close_reason)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);

	__builtin_memcpy(evt->src_ip, meta->src_ip.v6, 16);
	__builtin_memcpy(evt->dst_ip, meta->dst_ip.v6, 16);
	__builtin_memcpy(evt->nat_src_ip, nat_src_ip, 16);
	__builtin_memcpy(evt->nat_dst_ip, nat_dst_ip, 16);

	evt->src_port = meta->src_port;
	evt->dst_port = meta->dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;
	evt->nat_src_port = nat_src_port;
	evt->nat_dst_port = nat_dst_port;
	evt->created = created;
	evt->rev_packets = rev_packets;
	evt->rev_bytes = rev_bytes;
	evt->ingress_ifindex = meta->ingress_ifindex;
	evt->app_id = app_id;
	evt->close_reason = close_reason;
	evt->pad_event = 0;

	bpf_ringbuf_submit(evt, 0);
}

/*
 * Emit event with explicit original + translated IPv6 tuples.
 * Used when meta has already been rewritten for post-policy NAT.
 */
static __always_inline void
emit_event_nat6_orig(struct pkt_meta *meta, __u8 event_type, __u8 action,
		     __u64 packets, __u64 bytes,
		     const __u8 *orig_src_ip, const __u8 *orig_dst_ip,
		     __be16 orig_src_port, __be16 orig_dst_port,
		     const __u8 *nat_src_ip, const __u8 *nat_dst_ip,
		     __be16 nat_src_port, __be16 nat_dst_port,
		     __u32 created,
		     __u64 rev_packets, __u64 rev_bytes,
		     __u16 app_id, __u8 close_reason)
{
	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp = bpf_ktime_get_ns();

	__builtin_memset(evt->src_ip, 0, 16);
	__builtin_memset(evt->dst_ip, 0, 16);
	__builtin_memset(evt->nat_src_ip, 0, 16);
	__builtin_memset(evt->nat_dst_ip, 0, 16);

	__builtin_memcpy(evt->src_ip, orig_src_ip, 16);
	__builtin_memcpy(evt->dst_ip, orig_dst_ip, 16);
	__builtin_memcpy(evt->nat_src_ip, nat_src_ip, 16);
	__builtin_memcpy(evt->nat_dst_ip, nat_dst_ip, 16);

	evt->src_port = orig_src_port;
	evt->dst_port = orig_dst_port;
	evt->policy_id = meta->policy_id;
	evt->ingress_zone = meta->ingress_zone;
	evt->egress_zone = meta->egress_zone;
	evt->event_type = event_type;
	evt->protocol = meta->protocol;
	evt->action = action;
	evt->addr_family = meta->addr_family;
	evt->session_packets = packets;
	evt->session_bytes = bytes;
	evt->nat_src_port = nat_src_port;
	evt->nat_dst_port = nat_dst_port;
	evt->created = created;
	evt->rev_packets = rev_packets;
	evt->rev_bytes = rev_bytes;
	evt->ingress_ifindex = meta->ingress_ifindex;
	evt->app_id = app_id;
	evt->close_reason = close_reason;
	evt->pad_event = 0;

	bpf_ringbuf_submit(evt, 0);
}

/* ============================================================
 * Host-inbound traffic flag resolution
 *
 * Maps a packet's protocol/port to the corresponding
 * HOST_INBOUND_* flag bit from xpf_common.h.
 * Returns 0 for unrecognized services (denied when allowlist is active).
 * ============================================================ */
static __always_inline __u32
host_inbound_flag(struct pkt_meta *meta)
{
	__u8 proto = meta->protocol;

	/* ICMP/ICMPv6 echo request + reply → HOST_INBOUND_PING */
	if (proto == PROTO_ICMP || proto == PROTO_ICMPV6) {
		if (meta->icmp_type == 8 || meta->icmp_type == 0 ||
		    meta->icmp_type == 128 || meta->icmp_type == 129)
			return HOST_INBOUND_PING;
		/* IRDP: Router Advertisement (9) / Router Solicitation (10) */
		if (proto == PROTO_ICMP &&
		    (meta->icmp_type == 9 || meta->icmp_type == 10))
			return HOST_INBOUND_ROUTER_DISCOVERY;
		/* ICMPv6 NDP: RS(133), RA(134), NS(135), NA(136) */
		if (proto == PROTO_ICMPV6 &&
		    meta->icmp_type >= 133 && meta->icmp_type <= 136)
			return HOST_INBOUND_ROUTER_DISCOVERY;
		/* Other ICMP (errors, redirects) — always allow through
		 * any allowlist.  HOST_INBOUND_ALL matches all non-zero
		 * zone flags. */
		return HOST_INBOUND_ALL;
	}

	/* OSPF is IP protocol 89, not port-based */
	if (proto == 89)
		return HOST_INBOUND_OSPF;

	/* ESP (protocol 50) → HOST_INBOUND_ESP */
	if (proto == PROTO_ESP)
		return HOST_INBOUND_ESP;

	/* GRE (protocol 47) → HOST_INBOUND_GRE (tunnel termination) */
	if (proto == PROTO_GRE)
		return HOST_INBOUND_GRE;

	/* TCP/UDP port-based services */
	__u16 port = bpf_ntohs(meta->dst_port);
	switch (port) {
	case 22:           return HOST_INBOUND_SSH;
	case 53:           return HOST_INBOUND_DNS;
	case 80:           return HOST_INBOUND_HTTP;
	case 443:          return HOST_INBOUND_HTTPS;
	case 67: case 68:  return HOST_INBOUND_DHCP;
	case 546: case 547: return HOST_INBOUND_DHCPV6;
	case 123:          return HOST_INBOUND_NTP;
	case 161:          return HOST_INBOUND_SNMP;
	case 179:          return HOST_INBOUND_BGP;
	case 23:           return HOST_INBOUND_TELNET;
	case 21:           return HOST_INBOUND_FTP;
	case 830:          return HOST_INBOUND_NETCONF;
	case 514:          return HOST_INBOUND_SYSLOG;
	case 1812: case 1813: return HOST_INBOUND_RADIUS;
	case 500:          return HOST_INBOUND_IKE;
	case 4500:         return HOST_INBOUND_IKE;   /* IKE NAT-T */
	}

	/* Traceroute: UDP ports 33434-33523 */
	if (proto == PROTO_UDP && port >= 33434 && port <= 33523)
		return HOST_INBOUND_TRACEROUTE;

	return 0; /* unknown service → denied when allowlist is active */
}

/* ============================================================
 * Policer evaluation (single-rate two-color + three-color)
 *
 * Returns:
 *   0 = conforming (green)
 *   1 = exceed (yellow — exceeds committed but within peak/excess)
 *   2 = violate (red — exceeds peak rate)
 * For single-rate two-color: only returns 0 or 1.
 * Uses per-CPU state for lock-free operation.
 * ============================================================ */
static __always_inline int
evaluate_policer(__u32 policer_id, __u32 pkt_len, __u64 ktime_ns)
{
	struct policer_config *cfg =
		bpf_map_lookup_elem(&policer_configs, &policer_id);
	if (!cfg || cfg->rate_bytes_sec == 0)
		return 0; /* no policer or unconfigured, pass */

	struct policer_state *state =
		bpf_map_lookup_elem(&policer_states, &policer_id);
	if (!state)
		return 0;

	__u64 now = ktime_ns;
	__u64 elapsed = now - state->last_refill_ns;

	/* Refill committed tokens: elapsed_ns * rate_bytes_sec / 1e9 */
	__u64 c_tokens = state->tokens +
		(elapsed / 1000) * cfg->rate_bytes_sec / 1000000;
	if (c_tokens > cfg->burst_bytes)
		c_tokens = cfg->burst_bytes;

	if (cfg->color_mode == POLICER_MODE_SINGLE_RATE) {
		/* Single-rate two-color (original behavior) */
		if (c_tokens < pkt_len) {
			state->last_refill_ns = now;
			state->tokens = c_tokens;
			return 1; /* exceeded */
		}
		state->tokens = c_tokens - pkt_len;
		state->last_refill_ns = now;
		return 0; /* conforming */
	}

	if (cfg->color_mode == POLICER_MODE_TWO_RATE) {
		/* Two-rate three-color (RFC 2698) */
		__u64 p_tokens = state->peak_tokens +
			(elapsed / 1000) * cfg->peak_rate / 1000000;
		if (p_tokens > cfg->peak_burst)
			p_tokens = cfg->peak_burst;

		state->last_refill_ns = now;

		if (p_tokens < pkt_len) {
			/* Red: exceeds peak rate */
			state->tokens = c_tokens;
			state->peak_tokens = p_tokens;
			return 2; /* violate */
		}
		if (c_tokens < pkt_len) {
			/* Yellow: within peak but exceeds committed */
			state->tokens = c_tokens;
			state->peak_tokens = p_tokens - pkt_len;
			return 1; /* exceed */
		}
		/* Green: within both rates */
		state->tokens = c_tokens - pkt_len;
		state->peak_tokens = p_tokens - pkt_len;
		return 0; /* conform */
	}

	/* Single-rate three-color (RFC 2697): CIR fills C, C overflow fills E */
	__u64 e_tokens = state->peak_tokens;
	if (c_tokens > cfg->burst_bytes) {
		__u64 overflow = c_tokens - cfg->burst_bytes;
		e_tokens += overflow;
		c_tokens = cfg->burst_bytes;
		if (e_tokens > cfg->peak_burst)
			e_tokens = cfg->peak_burst;
	}

	state->last_refill_ns = now;

	if (c_tokens >= pkt_len) {
		/* Green: fits in committed bucket */
		state->tokens = c_tokens - pkt_len;
		state->peak_tokens = e_tokens;
		return 0;
	}
	if (e_tokens >= pkt_len) {
		/* Yellow: fits in excess bucket */
		state->tokens = c_tokens;
		state->peak_tokens = e_tokens - pkt_len;
		return 1;
	}
	/* Red: exceeds both */
	state->tokens = c_tokens;
	state->peak_tokens = e_tokens;
	return 2;
}

/* ============================================================
 * Firewall filter evaluation
 *
 * Called from xdp_main after header parsing.
 * Evaluates the filter assigned to the ingress interface.
 * Returns:
 *   0  = no filter or "accept" — continue pipeline
 *   -1 = "discard" — drop the packet
 *   -2 = "reject" — reject the packet (currently same as discard in XDP)
 * On FILTER_ACTION_ROUTE: sets meta->routing_table and returns 0.
 * ============================================================ */
static __always_inline int
evaluate_firewall_filter(struct pkt_meta *meta)
{
	/* Look up filter ID for this interface + family */
	struct iface_filter_key fkey = {
		.ifindex = meta->ingress_ifindex,
		.vlan_id = meta->ingress_vlan_id,
		.family  = meta->addr_family,
	};
	__u32 *filter_id = bpf_map_lookup_elem(&iface_filter_map, &fkey);
	if (!filter_id)
		return 0; /* no filter assigned */

	/* Get filter config (num_rules, rule_start) */
	struct filter_config *fcfg = bpf_map_lookup_elem(&filter_configs, filter_id);
	if (!fcfg || fcfg->num_rules == 0)
		return 0;

	/* Protocol pre-filter: if ALL terms specify a protocol and the
	 * packet protocol doesn't match any of them, skip the loop. */
	if (fcfg->all_have_proto && fcfg->proto_count > 0) {
		__u8 p = meta->protocol;
		int hit = 0;
		if (fcfg->proto_list[0] == p) hit = 1;
		if (fcfg->proto_count >= 2 && fcfg->proto_list[1] == p) hit = 1;
		if (fcfg->proto_count >= 3 && fcfg->proto_list[2] == p) hit = 1;
		if (fcfg->proto_count >= 4 && fcfg->proto_list[3] == p) hit = 1;
		if (!hit) return 0;
	}

	__u32 start = fcfg->rule_start;
	__u32 count = fcfg->num_rules;
	if (count > MAX_FILTER_RULES_PER_FILTER)
		count = MAX_FILTER_RULES_PER_FILTER;

	/* Evaluate terms sequentially (first-match wins) */
	#pragma unroll
	for (__u32 i = 0; i < MAX_FILTER_RULES_PER_FILTER; i++) {
		if (i >= count)
			break;

		__u32 idx = start + i;
		if (idx >= MAX_FILTER_RULES)
			break;

		struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &idx);
		if (!rule)
			break;

		__u16 flags = rule->match_flags;
		int match = 1;

		/* Check DSCP */
		if ((flags & FILTER_MATCH_DSCP) && rule->dscp != meta->dscp)
			match = 0;

		/* Check protocol */
		if (match && (flags & FILTER_MATCH_PROTOCOL) &&
		    rule->protocol != meta->protocol)
			match = 0;

		/* Check destination port (exact or range) */
		if (match && (flags & FILTER_MATCH_DST_PORT)) {
			if (rule->dst_port_hi) {
				__u16 p = bpf_ntohs(meta->dst_port);
				if (p < bpf_ntohs(rule->dst_port) ||
				    p > bpf_ntohs(rule->dst_port_hi))
					match = 0;
			} else if (rule->dst_port != meta->dst_port) {
				match = 0;
			}
		}

		/* Check source port (exact or range) */
		if (match && (flags & FILTER_MATCH_SRC_PORT)) {
			if (rule->src_port_hi) {
				__u16 p = bpf_ntohs(meta->src_port);
				if (p < bpf_ntohs(rule->src_port) ||
				    p > bpf_ntohs(rule->src_port_hi))
					match = 0;
			} else if (rule->src_port != meta->src_port) {
				match = 0;
			}
		}

		/* Check ICMP type */
		if (match && (flags & FILTER_MATCH_ICMP_TYPE) &&
		    rule->icmp_type != meta->icmp_type)
			match = 0;

		/* Check ICMP code */
		if (match && (flags & FILTER_MATCH_ICMP_CODE) &&
		    rule->icmp_code != meta->icmp_code)
			match = 0;

		/* Check TCP flags (all specified flags must be set) */
		if (match && (flags & FILTER_MATCH_TCP_FLAGS) &&
		    (meta->tcp_flags & rule->tcp_flags) != rule->tcp_flags)
			match = 0;

		/* Check IP fragment */
		if (match && (flags & FILTER_MATCH_FRAGMENT) &&
		    !meta->is_fragment)
			match = 0;

		/* Check flexible byte-offset match */
		if (match && (flags & FILTER_MATCH_FLEX) &&
		    rule->flex_length > 0) {
			/* Read bytes at L3 offset + flex_offset from meta.
			 * We compare against the pre-extracted value stored
			 * in the rule (not reading packet data to avoid
			 * verifier complexity). The flex_value in the rule
			 * is already masked. We use meta fields as proxy:
			 * flex_offset 9=TTL/proto, 12=src_ip, 16=dst_ip. */
			__u32 pkt_val = 0;
			__u8 off = rule->flex_offset;
			if (off == 9 && meta->addr_family == AF_INET)
				pkt_val = meta->protocol;
			else if (off == 12 && meta->addr_family == AF_INET)
				pkt_val = meta->src_ip.v4;
			else if (off == 16 && meta->addr_family == AF_INET)
				pkt_val = meta->dst_ip.v4;
			/* Apply mask and compare */
			if ((pkt_val & rule->flex_mask) != rule->flex_value)
				match = 0;
		}

		/* Check source address (v4 or v6 depending on family) */
		if (match && (flags & FILTER_MATCH_SRC_ADDR)) {
			int src_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->src_ip.v4 &
					*(__be32 *)rule->src_mask;
				if (masked != *(__be32 *)rule->src_addr)
					src_hit = 0;
			} else {
				/* IPv6: compare 4 x 32-bit words */
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->src_ip.v6 + j) &
						  *(__u32 *)(rule->src_mask + j);
					if (m != *(__u32 *)(rule->src_addr + j)) {
						src_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_SRC_NEGATE)
				src_hit = !src_hit;
			if (!src_hit)
				match = 0;
		}

		/* Check destination address */
		if (match && (flags & FILTER_MATCH_DST_ADDR)) {
			int dst_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->dst_ip.v4 &
					*(__be32 *)rule->dst_mask;
				if (masked != *(__be32 *)rule->dst_addr)
					dst_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->dst_ip.v6 + j) &
						  *(__u32 *)(rule->dst_mask + j);
					if (m != *(__u32 *)(rule->dst_addr + j)) {
						dst_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_DST_NEGATE)
				dst_hit = !dst_hit;
			if (!dst_hit)
				match = 0;
		}

		if (!match)
			continue;

		/* Increment per-rule counter */
		struct counter_value *fc =
			bpf_map_lookup_elem(&filter_counters, &idx);
		if (fc) { fc->packets++; fc->bytes += meta->pkt_len; }

		/* Policer: if rule has a policer, evaluate token bucket.
		 * If exceeded, apply policer action (discard). */
		if (rule->policer_id) {
			__u32 pid = rule->policer_id;
			if (evaluate_policer(pid, meta->pkt_len, get_precise_ktime_ns(meta)))
				return -1; /* policer exceeded → discard */
		}

		/* Emit log event if configured */
		if (rule->log_flag) {
			__u8 act = (rule->action == FILTER_ACTION_ACCEPT ||
				    rule->action == FILTER_ACTION_ROUTE)
				   ? ACTION_PERMIT : ACTION_DENY;
			emit_event(meta, EVENT_TYPE_FILTER_LOG, act, 0, 0, 0);
		}

		/* DSCP rewrite if configured */
		if (rule->dscp_rewrite != 0xFF)
			meta->dscp_rewrite = rule->dscp_rewrite;

		/* Term matched — apply action */
		switch (rule->action) {
		case FILTER_ACTION_ACCEPT:
			return 0;
		case FILTER_ACTION_DISCARD:
			return -1;
		case FILTER_ACTION_REJECT:
			return -2;
		case FILTER_ACTION_ROUTE:
			meta->routing_table = rule->routing_table;
			return 0;
		}
	}

	/* No term matched — implicit accept */
	return 0;
}

/* evaluate_firewall_filter_output — same as input but uses egress
 * interface index and direction=1 for the map lookup.
 * Returns:
 *   0  = no filter or "accept"
 *   -1 = "discard" — drop the packet
 */
static __always_inline int
evaluate_firewall_filter_output(struct pkt_meta *meta, __u32 egress_ifindex)
{
	struct iface_filter_key fkey = {
		.ifindex   = egress_ifindex,
		.vlan_id   = 0,  /* egress VLAN not tracked separately */
		.family    = meta->addr_family,
		.direction = 1,
	};
	__u32 *filter_id = bpf_map_lookup_elem(&iface_filter_map, &fkey);
	if (!filter_id)
		return 0;

	struct filter_config *fcfg = bpf_map_lookup_elem(&filter_configs, filter_id);
	if (!fcfg || fcfg->num_rules == 0)
		return 0;

	/* Protocol pre-filter */
	if (fcfg->all_have_proto && fcfg->proto_count > 0) {
		__u8 p = meta->protocol;
		int hit = 0;
		if (fcfg->proto_list[0] == p) hit = 1;
		if (fcfg->proto_count >= 2 && fcfg->proto_list[1] == p) hit = 1;
		if (fcfg->proto_count >= 3 && fcfg->proto_list[2] == p) hit = 1;
		if (fcfg->proto_count >= 4 && fcfg->proto_list[3] == p) hit = 1;
		if (!hit) return 0;
	}

	__u32 start = fcfg->rule_start;
	__u32 count = fcfg->num_rules;
	if (count > MAX_FILTER_RULES_PER_FILTER)
		count = MAX_FILTER_RULES_PER_FILTER;

	#pragma unroll
	for (__u32 i = 0; i < MAX_FILTER_RULES_PER_FILTER; i++) {
		if (i >= count)
			break;

		__u32 idx = start + i;
		if (idx >= MAX_FILTER_RULES)
			break;

		struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &idx);
		if (!rule)
			break;

		__u16 flags = rule->match_flags;
		int match = 1;

		if ((flags & FILTER_MATCH_DSCP) && rule->dscp != meta->dscp)
			match = 0;
		if (match && (flags & FILTER_MATCH_PROTOCOL) &&
		    rule->protocol != meta->protocol)
			match = 0;
		if (match && (flags & FILTER_MATCH_DST_PORT)) {
			if (rule->dst_port_hi) {
				__u16 p = bpf_ntohs(meta->dst_port);
				if (p < bpf_ntohs(rule->dst_port) ||
				    p > bpf_ntohs(rule->dst_port_hi))
					match = 0;
			} else if (rule->dst_port != meta->dst_port) {
				match = 0;
			}
		}
		if (match && (flags & FILTER_MATCH_SRC_PORT)) {
			if (rule->src_port_hi) {
				__u16 p = bpf_ntohs(meta->src_port);
				if (p < bpf_ntohs(rule->src_port) ||
				    p > bpf_ntohs(rule->src_port_hi))
					match = 0;
			} else if (rule->src_port != meta->src_port) {
				match = 0;
			}
		}
		if (match && (flags & FILTER_MATCH_ICMP_TYPE) &&
		    rule->icmp_type != meta->icmp_type)
			match = 0;
		if (match && (flags & FILTER_MATCH_ICMP_CODE) &&
		    rule->icmp_code != meta->icmp_code)
			match = 0;

		/* Check TCP flags (all specified flags must be set) */
		if (match && (flags & FILTER_MATCH_TCP_FLAGS) &&
		    (meta->tcp_flags & rule->tcp_flags) != rule->tcp_flags)
			match = 0;

		/* Check IP fragment */
		if (match && (flags & FILTER_MATCH_FRAGMENT) &&
		    !meta->is_fragment)
			match = 0;

		/* Flexible byte-offset match */
		if (match && (flags & FILTER_MATCH_FLEX) &&
		    rule->flex_length > 0) {
			__u32 pkt_val = 0;
			__u8 off = rule->flex_offset;
			if (off == 9 && meta->addr_family == AF_INET)
				pkt_val = meta->protocol;
			else if (off == 12 && meta->addr_family == AF_INET)
				pkt_val = meta->src_ip.v4;
			else if (off == 16 && meta->addr_family == AF_INET)
				pkt_val = meta->dst_ip.v4;
			if ((pkt_val & rule->flex_mask) != rule->flex_value)
				match = 0;
		}

		if (match && (flags & FILTER_MATCH_SRC_ADDR)) {
			int src_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->src_ip.v4 &
					*(__be32 *)rule->src_mask;
				if (masked != *(__be32 *)rule->src_addr)
					src_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->src_ip.v6 + j) &
						  *(__u32 *)(rule->src_mask + j);
					if (m != *(__u32 *)(rule->src_addr + j)) {
						src_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_SRC_NEGATE)
				src_hit = !src_hit;
			if (!src_hit)
				match = 0;
		}

		if (match && (flags & FILTER_MATCH_DST_ADDR)) {
			int dst_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->dst_ip.v4 &
					*(__be32 *)rule->dst_mask;
				if (masked != *(__be32 *)rule->dst_addr)
					dst_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->dst_ip.v6 + j) &
						  *(__u32 *)(rule->dst_mask + j);
					if (m != *(__u32 *)(rule->dst_addr + j)) {
						dst_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_DST_NEGATE)
				dst_hit = !dst_hit;
			if (!dst_hit)
				match = 0;
		}

		if (!match)
			continue;

		struct counter_value *fc =
			bpf_map_lookup_elem(&filter_counters, &idx);
		if (fc) { fc->packets++; fc->bytes += meta->pkt_len; }

		/* Policer: if rule has a policer, evaluate token bucket. */
		if (rule->policer_id) {
			__u32 pid = rule->policer_id;
			if (evaluate_policer(pid, meta->pkt_len, get_precise_ktime_ns(meta)))
				return -1; /* policer exceeded → discard */
		}

		if (rule->log_flag) {
			__u8 act = (rule->action == FILTER_ACTION_ACCEPT ||
				    rule->action == FILTER_ACTION_ROUTE)
				   ? ACTION_PERMIT : ACTION_DENY;
			emit_event(meta, EVENT_TYPE_FILTER_LOG, act, 0, 0, 0);
		}

		if (rule->dscp_rewrite != 0xFF)
			meta->dscp_rewrite = rule->dscp_rewrite;

		switch (rule->action) {
		case FILTER_ACTION_ACCEPT:
			return 0;
		case FILTER_ACTION_DISCARD:
		case FILTER_ACTION_REJECT:
			return -1;
		}
	}

	return 0;
}

/* ============================================================
 * Lo0 (loopback) firewall filter evaluation by filter ID
 *
 * Used for host-bound traffic filtering (lo0 input filter).
 * Takes a filter ID directly (from flow_config_map) rather than
 * looking it up from iface_filter_map.
 * Returns:
 *   0  = no filter or "accept"
 *   -1 = "discard" / "reject" / policer exceeded
 * ============================================================ */
static __always_inline int
evaluate_filter_by_id(__u32 fid, struct pkt_meta *meta)
{
	if (fid == 0xFFFF)
		return 0;

	struct filter_config *fcfg = bpf_map_lookup_elem(&filter_configs, &fid);
	if (!fcfg || fcfg->num_rules == 0)
		return 0;

	/* Protocol pre-filter */
	if (fcfg->all_have_proto && fcfg->proto_count > 0) {
		__u8 p = meta->protocol;
		int hit = 0;
		if (fcfg->proto_list[0] == p) hit = 1;
		if (fcfg->proto_count >= 2 && fcfg->proto_list[1] == p) hit = 1;
		if (fcfg->proto_count >= 3 && fcfg->proto_list[2] == p) hit = 1;
		if (fcfg->proto_count >= 4 && fcfg->proto_list[3] == p) hit = 1;
		if (!hit) return 0;
	}

	__u32 start = fcfg->rule_start;
	__u32 count = fcfg->num_rules;
	if (count > MAX_FILTER_RULES_PER_FILTER)
		count = MAX_FILTER_RULES_PER_FILTER;

	#pragma unroll
	for (__u32 i = 0; i < MAX_FILTER_RULES_PER_FILTER; i++) {
		if (i >= count)
			break;

		__u32 idx = start + i;
		if (idx >= MAX_FILTER_RULES)
			break;

		struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &idx);
		if (!rule)
			break;

		__u16 flags = rule->match_flags;
		int match = 1;

		if ((flags & FILTER_MATCH_DSCP) && rule->dscp != meta->dscp)
			match = 0;
		if (match && (flags & FILTER_MATCH_PROTOCOL) &&
		    rule->protocol != meta->protocol)
			match = 0;
		if (match && (flags & FILTER_MATCH_DST_PORT)) {
			if (rule->dst_port_hi) {
				__u16 p = bpf_ntohs(meta->dst_port);
				if (p < bpf_ntohs(rule->dst_port) ||
				    p > bpf_ntohs(rule->dst_port_hi))
					match = 0;
			} else if (rule->dst_port != meta->dst_port) {
				match = 0;
			}
		}
		if (match && (flags & FILTER_MATCH_SRC_PORT)) {
			if (rule->src_port_hi) {
				__u16 p = bpf_ntohs(meta->src_port);
				if (p < bpf_ntohs(rule->src_port) ||
				    p > bpf_ntohs(rule->src_port_hi))
					match = 0;
			} else if (rule->src_port != meta->src_port) {
				match = 0;
			}
		}
		if (match && (flags & FILTER_MATCH_ICMP_TYPE) &&
		    rule->icmp_type != meta->icmp_type)
			match = 0;
		if (match && (flags & FILTER_MATCH_ICMP_CODE) &&
		    rule->icmp_code != meta->icmp_code)
			match = 0;
		if (match && (flags & FILTER_MATCH_TCP_FLAGS) &&
		    (meta->tcp_flags & rule->tcp_flags) != rule->tcp_flags)
			match = 0;
		if (match && (flags & FILTER_MATCH_FRAGMENT) &&
		    !meta->is_fragment)
			match = 0;

		/* Flexible byte-offset match */
		if (match && (flags & FILTER_MATCH_FLEX) &&
		    rule->flex_length > 0) {
			__u32 pkt_val = 0;
			__u8 off = rule->flex_offset;
			if (off == 9 && meta->addr_family == AF_INET)
				pkt_val = meta->protocol;
			else if (off == 12 && meta->addr_family == AF_INET)
				pkt_val = meta->src_ip.v4;
			else if (off == 16 && meta->addr_family == AF_INET)
				pkt_val = meta->dst_ip.v4;
			if ((pkt_val & rule->flex_mask) != rule->flex_value)
				match = 0;
		}

		if (match && (flags & FILTER_MATCH_SRC_ADDR)) {
			int src_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->src_ip.v4 &
					*(__be32 *)rule->src_mask;
				if (masked != *(__be32 *)rule->src_addr)
					src_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->src_ip.v6 + j) &
						  *(__u32 *)(rule->src_mask + j);
					if (m != *(__u32 *)(rule->src_addr + j)) {
						src_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_SRC_NEGATE)
				src_hit = !src_hit;
			if (!src_hit)
				match = 0;
		}

		if (match && (flags & FILTER_MATCH_DST_ADDR)) {
			int dst_hit = 1;
			if (meta->addr_family == AF_INET) {
				__be32 masked = meta->dst_ip.v4 &
					*(__be32 *)rule->dst_mask;
				if (masked != *(__be32 *)rule->dst_addr)
					dst_hit = 0;
			} else {
				for (int j = 0; j < 16; j += 4) {
					__u32 m = *(__u32 *)(meta->dst_ip.v6 + j) &
						  *(__u32 *)(rule->dst_mask + j);
					if (m != *(__u32 *)(rule->dst_addr + j)) {
						dst_hit = 0;
						break;
					}
				}
			}
			if (flags & FILTER_MATCH_DST_NEGATE)
				dst_hit = !dst_hit;
			if (!dst_hit)
				match = 0;
		}

		if (!match)
			continue;

		struct counter_value *fc =
			bpf_map_lookup_elem(&filter_counters, &idx);
		if (fc) { fc->packets++; fc->bytes += meta->pkt_len; }

		if (rule->policer_id) {
			__u32 pid = rule->policer_id;
			if (evaluate_policer(pid, meta->pkt_len, get_precise_ktime_ns(meta)))
				return -1;
		}

		if (rule->log_flag) {
			__u8 act = (rule->action == FILTER_ACTION_ACCEPT)
				   ? ACTION_PERMIT : ACTION_DENY;
			emit_event(meta, EVENT_TYPE_FILTER_LOG, act, 0, 0, 0);
		}

		if (rule->dscp_rewrite != 0xFF)
			meta->dscp_rewrite = rule->dscp_rewrite;

		switch (rule->action) {
		case FILTER_ACTION_ACCEPT:
			return 0;
		case FILTER_ACTION_DISCARD:
		case FILTER_ACTION_REJECT:
			return -1;
		}
	}

	return 0; /* no term matched — implicit accept */
}

/* ============================================================
 * TCP MSS clamping
 *
 * Walk TCP options in a SYN packet, find MSS option (kind=2, len=4),
 * and clamp it to the configured maximum.
 * ============================================================ */

/* TCP option kinds */
#define TCPOPT_EOL  0
#define TCPOPT_NOP  1
#define TCPOPT_MSS  2
#define TCPOPT_MSS_LEN 4

/*
 * Clamp TCP MSS option in a SYN packet.
 *
 * The MSS option (kind=2, len=4) in standard SYN packets is found
 * at one of a few well-known positions in the TCP options area.
 * We check the first few positions with constant offsets to keep
 * the verifier happy (avoids loop + variable offset issues).
 *
 * Returns 0 on success/no-op.
 */
static __always_inline int
tcp_mss_clamp(struct xdp_md *ctx, __u16 l4_offset, __u16 max_mss,
	      int csum_partial)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Sanity limit on l4_offset to help verifier */
	if (l4_offset > 200)
		return -1;

	/* Ensure at least TCP header + 4 bytes of options to peek at
	 * option kind/length fields.  The MSS value read is separately
	 * guarded by the (mss_ptr + 1) > data_end check below. */
	if (data + l4_offset + 24 > data_end)
		return 0;

	/* Account for TCP timestamps (NOP+NOP+TS = 12 bytes) that
	 * will be present in every data segment.  Without this,
	 * data packets exceed the tunnel/path MTU by 12 bytes
	 * (IP 20 + TCP 32 + MSS vs the MTU = IP 20 + TCP 20 + MSS).
	 * Nearly all modern TCP stacks use timestamps. */
	if (max_mss > 12)
		max_mss -= 12;

	__u8 *opt_base = (__u8 *)data + l4_offset + 20;
	__be16 *mss_ptr = 0;
	struct tcphdr *tcp = data + l4_offset;

	/* Position 0: MSS at start of options (most common) */
	if (opt_base[0] == TCPOPT_MSS && opt_base[1] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 2);
	}
	/* Position 1: NOP + MSS */
	else if (opt_base[0] == TCPOPT_NOP &&
		 opt_base[1] == TCPOPT_MSS && opt_base[2] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 3);
	}
	/* Position 2: NOP + NOP + MSS */
	else if (opt_base[0] == TCPOPT_NOP && opt_base[1] == TCPOPT_NOP &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}
	/* Position: after SACK_PERM (kind=4,len=2) + MSS */
	else if (opt_base[0] == 4 && opt_base[1] == 2 &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}

	if (!mss_ptr)
		return 0;

	if ((void *)(mss_ptr + 1) > data_end)
		return 0;

	__u16 cur_mss = bpf_ntohs(*mss_ptr);
	if (cur_mss > max_mss) {
		__be16 old_mss = *mss_ptr;
		__be16 new_mss = bpf_htons(max_mss);
		*mss_ptr = new_mss;

		/* For CHECKSUM_PARTIAL, the MSS is in the L4 data that
		 * the NIC/skb_checksum_help will sum -- skip incremental
		 * update to avoid double-counting the delta. */
		if (!csum_partial) {
			/* Re-read data pointers after packet write for verifier */
			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			if (data + l4_offset + 20 > data_end)
				return 0;
			tcp = data + l4_offset;
			csum_update_2(&tcp->check, old_mss, new_mss);
		}
	}

	return 0;
}

/*
 * TC egress variant of tcp_mss_clamp.
 * Identical logic but takes struct __sk_buff * context.
 */
static __always_inline int
tc_tcp_mss_clamp(struct __sk_buff *skb, __u16 l4_offset, __u16 max_mss,
		 int csum_partial)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (l4_offset > 200)
		return -1;

	if (data + l4_offset + 24 > data_end)
		return 0;

	/* Account for TCP timestamps (same as XDP variant above). */
	if (max_mss > 12)
		max_mss -= 12;

	__u8 *opt_base = (__u8 *)data + l4_offset + 20;
	__be16 *mss_ptr = 0;
	struct tcphdr *tcp = data + l4_offset;

	if (opt_base[0] == TCPOPT_MSS && opt_base[1] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 2);
	}
	else if (opt_base[0] == TCPOPT_NOP &&
		 opt_base[1] == TCPOPT_MSS && opt_base[2] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 3);
	}
	else if (opt_base[0] == TCPOPT_NOP && opt_base[1] == TCPOPT_NOP &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}
	else if (opt_base[0] == 4 && opt_base[1] == 2 &&
		 opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (__be16 *)(opt_base + 4);
	}

	if (!mss_ptr)
		return 0;
	if ((void *)(mss_ptr + 1) > data_end)
		return 0;

	__u16 cur_mss = bpf_ntohs(*mss_ptr);
	if (cur_mss > max_mss) {
		__be16 old_mss = *mss_ptr;
		__be16 new_mss = bpf_htons(max_mss);
		*mss_ptr = new_mss;

		if (!csum_partial) {
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
			if (data + l4_offset + 20 > data_end)
				return 0;
			tcp = data + l4_offset;
			csum_update_2(&tcp->check, old_mss, new_mss);
		}
	}

	return 0;
}

/* ============================================================
 * Check whether the egress interface's redundancy group is locally
 * active.  Returns 1 if active (or non-RETH/standalone), 0 if the
 * RG is inactive on this node (traffic should cross fabric).
 * ============================================================ */
static __always_inline int
check_egress_rg_active(__u32 ifindex, __u16 vlan_id)
{
	struct iface_zone_key ezk = { .ifindex = ifindex, .vlan_id = vlan_id };
	struct iface_zone_value *ezv = bpf_map_lookup_elem(&iface_zone_map, &ezk);
	if (!ezv || ezv->rg_id == 0)
		return 1; /* No RG — standalone or non-RETH, always active */
	__u32 rg_key = ezv->rg_id;
	__u8 *active = bpf_map_lookup_elem(&rg_active, &rg_key);
	if (!active || !*active)
		return 0;

	/* Userspace liveness watchdog: if Go daemon hasn't written a
	 * heartbeat within 2 seconds, treat RG as inactive (fail-closed
	 * on SIGKILL/panic).  Value 0 = standalone/uninit → skip. */
	__u64 *last_ts = bpf_map_lookup_elem(&ha_watchdog, &rg_key);
	if (last_ts && *last_ts != 0) {
		__u64 now_ns = bpf_ktime_get_ns();
		__u64 now_s = now_ns / 1000000000ULL;
		if (now_s - *last_ts > 2)
			return 0;
	}
	return 1;
}

static __always_inline int
fabric_ingress_match(__u32 ingress, struct fabric_fwd_info *ff0,
		       struct fabric_fwd_info *ff1)
{
	if (ff0 && ff0->ifindex != 0 && ingress == ff0->ifindex)
		return 1;
	if (ff1 && ff1->ifindex != 0 && ingress == ff1->ifindex)
		return 1;
	return 0;
}

static __always_inline struct fabric_fwd_info *
fabric_main_fib_peer(struct fabric_fwd_info *ff0, struct fabric_fwd_info *ff1)
{
	if (ff0 && ff0->fib_ifindex)
		return ff0;
	if (ff1 && ff1->fib_ifindex)
		return ff1;
	return NULL;
}

/* ============================================================
 * Fabric cross-chassis redirect for cluster failback.
 *
 * When bpf_fib_lookup fails for an existing session (NO_NEIGH or
 * NOT_FWDED during asymmetric routing window), redirect the ORIGINAL
 * (pre-NAT) packet to the peer via the fabric link.  The peer processes
 * it through its full pipeline.
 *
 * Returns >= 0 (XDP_REDIRECT) on success, -1 on failure (caller falls
 * back to META_FLAG_KERNEL_ROUTE).
 * ============================================================ */
static __always_inline int
try_fabric_redirect_cached(struct xdp_md *ctx, struct pkt_meta *meta,
			   struct fabric_fwd_info *ff0,
			   struct fabric_fwd_info *ff1)
{
	/* Anti-loop: skip if ingressed on either fabric */
	if (fabric_ingress_match(ctx->ingress_ifindex, ff0, ff1))
		return -1;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__u32 pkt_len = (__u32)(data_end - data);

	/* Try fab0 first */
	if (ff0 && ff0->ifindex != 0) {
		__builtin_memcpy(eth->h_dest, ff0->peer_mac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, ff0->local_mac, ETH_ALEN);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT_FAB0);
		inc_iface_tx(ff0->ifindex, pkt_len);
		return bpf_redirect_map(&tx_ports, ff0->ifindex, 0);
	}

	/* Try fab1 */
	if (ff1 && ff1->ifindex != 0) {
		__builtin_memcpy(eth->h_dest, ff1->peer_mac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, ff1->local_mac, ETH_ALEN);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT_FAB1);
		inc_iface_tx(ff1->ifindex, pkt_len);
		return bpf_redirect_map(&tx_ports, ff1->ifindex, 0);
	}

	return -1;
}

static __always_inline int
try_fabric_redirect(struct xdp_md *ctx, struct pkt_meta *meta)
{
	__u32 zero = 0, one = 1;
	struct fabric_fwd_info *ff0 = bpf_map_lookup_elem(&fabric_fwd, &zero);
	struct fabric_fwd_info *ff1 = bpf_map_lookup_elem(&fabric_fwd, &one);

	return try_fabric_redirect_cached(ctx, meta, ff0, ff1);
}

/* ============================================================
 * Zone-encoded fabric redirect for new connections.
 *
 * When a new connection arrives on one node but the egress RG is on
 * the peer, the packet must cross the fabric.  Unlike existing sessions
 * (where the peer has synced session state with zone info), new
 * connections have no session on the peer — so the peer doesn't know
 * the original ingress zone.  This helper encodes the ingress zone
 * in the source MAC (02:bf:72:fe:00:ZZ) before redirect.  The peer's
 * xdp_zone detects this magic prefix and uses h_source[5] as the
 * ingress zone instead of the fabric interface's zone.
 *
 * We use MAC encoding instead of VLAN tags because Linux bridges
 * strip 802.1Q tags into skb->vlan_tci before generic XDP runs,
 * making VLAN-encoded zones invisible to the BPF program.
 *
 * Returns >= 0 (XDP_REDIRECT) on success, -1 on failure.
 * ============================================================ */
static __always_inline int
try_fabric_redirect_with_zone_cached(struct xdp_md *ctx,
				     struct pkt_meta *meta,
				     struct fabric_fwd_info *ff0,
				     struct fabric_fwd_info *ff1)
{
	/* Anti-loop: don't redirect if packet arrived on either fabric */
	if (fabric_ingress_match(ctx->ingress_ifindex, ff0, ff1))
		return -1;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__u32 pkt_len = (__u32)(data_end - data);

	/* Encode ingress zone in source MAC: 02:bf:72:fe:00:ZZ */
	eth->h_source[0] = 0x02;
	eth->h_source[1] = 0xbf;
	eth->h_source[2] = 0x72;
	eth->h_source[3] = FABRIC_ZONE_MAC_MAGIC;
	eth->h_source[4] = 0x00;
	eth->h_source[5] = (__u8)(meta->ingress_zone & 0xff);

	/* Try fab0 first */
	if (ff0 && ff0->ifindex != 0) {
		__builtin_memcpy(eth->h_dest, ff0->peer_mac, ETH_ALEN);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT_FAB0);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT_ZONE);
		inc_iface_tx(ff0->ifindex, pkt_len);
		return bpf_redirect_map(&tx_ports, ff0->ifindex, 0);
	}

	/* Try fab1 */
	if (ff1 && ff1->ifindex != 0) {
		__builtin_memcpy(eth->h_dest, ff1->peer_mac, ETH_ALEN);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT_FAB1);
		inc_counter(GLOBAL_CTR_FABRIC_REDIRECT_ZONE);
		inc_iface_tx(ff1->ifindex, pkt_len);
		return bpf_redirect_map(&tx_ports, ff1->ifindex, 0);
	}

	return -1;
}

static __always_inline int
try_fabric_redirect_with_zone(struct xdp_md *ctx, struct pkt_meta *meta)
{
	__u32 zero = 0, one = 1;
	struct fabric_fwd_info *ff0 = bpf_map_lookup_elem(&fabric_fwd, &zero);
	struct fabric_fwd_info *ff1 = bpf_map_lookup_elem(&fabric_fwd, &one);

	return try_fabric_redirect_with_zone_cached(ctx, meta, ff0, ff1);
}

#endif /* __BPFRX_HELPERS_H__ */
