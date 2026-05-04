// SPDX-License-Identifier: GPL-2.0
/*
 * xpf XDP screen/IDS stage.
 *
 * Runs before zone classification. Looks up the ingress zone's screen
 * profile and applies stateless anomaly checks (LAND, TCP SYN+FIN,
 * TCP no-flag, TCP FIN-no-ACK, WinNuke, tear-drop, IP source-route,
 * Ping of Death) and rate-based flood protection (SYN flood, ICMP flood,
 * UDP flood). Supports both IPv4 and IPv6.
 *
 * When SCREEN_SYN_COOKIE is enabled, SYN floods trigger cookie-based
 * source validation instead of indiscriminate drops. Legitimate sources
 * pass after a single extra RTT; spoofed sources fail validation.
 */

#include "../headers/xpf_common.h"
#include "../headers/xpf_maps.h"
#include "../headers/xpf_helpers.h"

/*
 * SYN cookie helpers: bpf_tcp_raw_gen_syncookie_ipv4/v6 and
 * bpf_tcp_raw_check_syncookie_ipv4/v6 are already declared in
 * <bpf/bpf_helper_defs.h> as BPF helpers (IDs 204-207).
 * gen returns __s64: negative on error, lower 32 bits = cookie.
 * check returns long: 0 on success, negative on error.
 */

/*
 * screen_drop() lives in bpf/headers/xpf_helpers.h (promoted from
 * here for #867 so xdp_conntrack.c can share the same side effects).
 */

/*
 * Check flood rate limits for a given zone.
 * Returns the SCREEN_* flag that was exceeded, or 0 if within limits.
 *
 * When SCREEN_SYN_COOKIE is set:
 *   - SYN flood above threshold activates synproxy_active (returns 0)
 *   - SYN rate below threshold/2 in a new window deactivates synproxy
 */
static __always_inline __u32
check_flood(struct pkt_meta *meta, struct screen_config *sc)
{
	__u32 zone = meta->ingress_zone;
	struct flood_state *fs = bpf_map_lookup_elem(&flood_counters, &zone);
	if (!fs)
		return 0;

	__u64 now_sec = meta->now_sec;

	/* Reset window when duration expires.
	 * syn_flood_timeout configures the window in seconds (0 = 1s default). */
	__u32 window_dur = sc->syn_flood_timeout;
	if (window_dur == 0)
		window_dur = 1;
	if (now_sec - fs->window_start >= window_dur) {
		/* Deactivate synproxy if rate dropped below half threshold */
		if (fs->synproxy_active &&
		    fs->syn_count < sc->syn_flood_thresh / 2)
			fs->synproxy_active = 0;
		fs->syn_count = 0;
		fs->icmp_count = 0;
		fs->udp_count = 0;
		fs->window_start = now_sec;
	}

	/* SYN flood: count TCP SYN (without ACK) */
	if ((sc->flags & SCREEN_SYN_FLOOD) && sc->syn_flood_thresh > 0) {
		if (meta->protocol == PROTO_TCP) {
			__u8 tf = meta->tcp_flags;
			if ((tf & 0x02) && !(tf & 0x10)) { /* SYN set, ACK not set */
				fs->syn_count++;
				if (fs->syn_count > sc->syn_flood_thresh) {
					if (sc->flags & SCREEN_SYN_COOKIE) {
						/* Activate syn-cookie mode instead of dropping */
						fs->synproxy_active = 1;
					} else {
						return SCREEN_SYN_FLOOD;
					}
				}
			}
		}
	}

	/* ICMP flood: count ICMP + ICMPv6 */
	if ((sc->flags & SCREEN_ICMP_FLOOD) && sc->icmp_flood_thresh > 0) {
		if (meta->protocol == PROTO_ICMP ||
		    meta->protocol == PROTO_ICMPV6) {
			fs->icmp_count++;
			if (fs->icmp_count > sc->icmp_flood_thresh)
				return SCREEN_ICMP_FLOOD;
		}
	}

	/* UDP flood: count UDP */
	if ((sc->flags & SCREEN_UDP_FLOOD) && sc->udp_flood_thresh > 0) {
		if (meta->protocol == PROTO_UDP) {
			fs->udp_count++;
			if (fs->udp_count > sc->udp_flood_thresh)
				return SCREEN_UDP_FLOOD;
		}
	}

	return 0;
}

/* ============================================================
 * SYN cookie: generate SYN-ACK response (IPv4)
 *
 * Uses bpf_tcp_raw_gen_syncookie_ipv4 kfunc to compute cookie,
 * then builds a SYN-ACK with: seq=cookie, ack=client_seq+1,
 * MSS option (1460), window 65535.
 *
 * Packet format: ETH(14) + IP(20) + TCP(24 = hdr+MSS) = 58 bytes.
 * ============================================================ */
static __noinline int
send_syncookie_synack_v4(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Validate IP + TCP headers and call helper FIRST,
	 * before any packet modifications. */
	__u16 l3_off = meta->l3_offset & 0x3F;
	__u16 l4_off = meta->l4_offset & 0x7F;

	struct iphdr *iph = data + l3_off;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	struct tcphdr *tcph = data + l4_off;
	if ((void *)(tcph + 1) > data_end)
		return XDP_DROP;

	/* Generate SYN cookie via BPF helper.
	 * Use constant header length to satisfy verifier range tracking
	 * (variable doff*4 gives wide var_off that fails bounds check). */
	__s64 cookie_ret = bpf_tcp_raw_gen_syncookie_ipv4(
		iph, tcph, sizeof(struct tcphdr));
	if (cookie_ret < 0)
		return XDP_DROP;
	__u32 cookie = (__u32)cookie_ret;

	/* Read values from meta (not packet) */
	__be32 orig_saddr = meta->src_ip.v4;
	__be32 orig_daddr = meta->dst_ip.v4;
	__be16 orig_sport = meta->src_port;
	__be16 orig_dport = meta->dst_port;
	__be32 orig_seq = meta->tcp_seq;

	/* Truncate to ETH(14) + IP(20) + TCP(20) + MSS(4) = 58 bytes */
	long cur_len = (long)ctx->data_end - (long)ctx->data;
	int delta = 58 - (int)cur_len;
	if (delta != 0) {
		if (bpf_xdp_adjust_tail(ctx, delta))
			return XDP_DROP;
	}

	/* Re-read after adjust — all packet reads below use fresh pointers */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 58 > data_end)
		return XDP_DROP;

	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	/* Read MACs from packet (beginning unchanged by tail truncation) */
	__u8 orig_smac[ETH_ALEN], orig_dmac[ETH_ALEN];
	__builtin_memcpy(orig_smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(orig_dmac, eth->h_dest, ETH_ALEN);

	/* Swap MACs */
	__builtin_memcpy(eth->h_source, orig_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, orig_smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	/* Build IP header */
	struct iphdr ip_hdr = {};
	ip_hdr.version  = 4;
	ip_hdr.ihl      = 5;
	ip_hdr.tot_len  = bpf_htons(44); /* IP(20) + TCP(24) */
	ip_hdr.frag_off = bpf_htons(0x4000);
	ip_hdr.ttl      = 64;
	ip_hdr.protocol = PROTO_TCP;
	ip_hdr.saddr    = orig_daddr;
	ip_hdr.daddr    = orig_saddr;

	__u32 csum = 0;
	__u16 *ip16 = (__u16 *)&ip_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		csum += ip16[i];
	csum = (csum >> 16) + (csum & 0xffff);
	csum += csum >> 16;
	ip_hdr.check = ~csum;
	*ip = ip_hdr;

	/* Build TCP header: SYN-ACK with cookie */
	struct tcphdr tcp_hdr = {};
	tcp_hdr.source  = orig_dport;
	tcp_hdr.dest    = orig_sport;
	tcp_hdr.seq     = bpf_htonl(cookie);
	tcp_hdr.ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + 1);
	tcp_hdr.doff    = 6; /* 24 bytes: 20 + 4 MSS option */
	tcp_hdr.syn     = 1;
	tcp_hdr.ack     = 1;
	tcp_hdr.window  = bpf_htons(65535);

	/* MSS option: kind=2, len=4, value=1460 */
	__u16 mss_words[2];
	mss_words[0] = bpf_htons(0x0204); /* kind=2, len=4 */
	mss_words[1] = bpf_htons(1460);

	/* TCP checksum: pseudo-header + TCP header(20) + MSS(4) */
	struct {
		__be32 saddr;  __be32 daddr;
		__u8 zero;     __u8 proto;   __be16 tcp_len;
	} pseudo = {
		.saddr = ip_hdr.saddr, .daddr = ip_hdr.daddr,
		.proto = PROTO_TCP,    .tcp_len = bpf_htons(24),
	};
	__u32 tcp_csum = 0;
	__u16 *p16 = (__u16 *)&pseudo;
	#pragma unroll
	for (int i = 0; i < 6; i++)
		tcp_csum += p16[i];
	__u16 *t16 = (__u16 *)&tcp_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		tcp_csum += t16[i];
	tcp_csum += mss_words[0];
	tcp_csum += mss_words[1];
	tcp_csum = (tcp_csum >> 16) + (tcp_csum & 0xffff);
	tcp_csum += tcp_csum >> 16;
	tcp_hdr.check = ~tcp_csum;

	/* Write TCP header + MSS option to packet */
	*tcp = tcp_hdr;
	__builtin_memcpy((void *)(tcp + 1), mss_words, 4);

	/* #857: push back the 802.1Q tag xdp_main_prog popped before the
	 * pipeline so the reply reaches the VLAN client.  Without this the
	 * SYN-ACK is sent untagged on the physical port, lands on the
	 * native VLAN, and never reaches clients on tagged sub-interfaces
	 * — effectively turning SYN-cookie flood protection into a self-DoS
	 * for VLAN clients. */
	if (meta->ingress_vlan_present) {
		if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0)
			return XDP_DROP;
	}

	return XDP_TX;
}

/* ============================================================
 * SYN cookie: generate SYN-ACK response (IPv6)
 *
 * Same as v4 but for IPv6: ETH(14) + IPv6(40) + TCP(24) = 78 bytes.
 * No IP checksum; TCP uses IPv6 pseudo-header.
 * ============================================================ */
static __noinline int
send_syncookie_synack_v6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Validate headers and call helper FIRST */
	__u16 l3_off = meta->l3_offset & 0x3F;
	__u16 l4_off = meta->l4_offset & 0x7F;

	struct ipv6hdr *ip6h = data + l3_off;
	if ((void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	struct tcphdr *tcph = data + l4_off;
	if ((void *)(tcph + 1) > data_end)
		return XDP_DROP;

	/* Generate SYN cookie via BPF helper (constant header len for verifier) */
	__s64 cookie_ret = bpf_tcp_raw_gen_syncookie_ipv6(
		ip6h, tcph, sizeof(struct tcphdr));
	if (cookie_ret < 0)
		return XDP_DROP;
	__u32 cookie = (__u32)cookie_ret;

	/* Read from meta (not packet) */
	struct in6_addr orig_saddr, orig_daddr;
	__builtin_memcpy(&orig_saddr, meta->src_ip.v6, 16);
	__builtin_memcpy(&orig_daddr, meta->dst_ip.v6, 16);
	__be16 orig_sport = meta->src_port;
	__be16 orig_dport = meta->dst_port;
	__be32 orig_seq = meta->tcp_seq;

	/* Truncate to ETH(14) + IPv6(40) + TCP(24) = 78 bytes */
	long cur_len = (long)ctx->data_end - (long)ctx->data;
	int delta = 78 - (int)cur_len;
	if (delta != 0) {
		if (bpf_xdp_adjust_tail(ctx, delta))
			return XDP_DROP;
	}

	/* Re-read after adjust — fresh packet pointers */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 78 > data_end)
		return XDP_DROP;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

	/* Read MACs from packet (beginning unchanged by tail truncation) */
	__u8 orig_smac[ETH_ALEN], orig_dmac[ETH_ALEN];
	__builtin_memcpy(orig_smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(orig_dmac, eth->h_dest, ETH_ALEN);

	/* Swap MACs */
	__builtin_memcpy(eth->h_source, orig_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, orig_smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Build IPv6 header (no checksum) */
	ip6->version     = 6;
	ip6->priority    = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;
	ip6->payload_len = bpf_htons(24); /* TCP(24) */
	ip6->nexthdr     = PROTO_TCP;
	ip6->hop_limit   = 64;
	ip6->saddr       = orig_daddr;
	ip6->daddr       = orig_saddr;

	/* Build TCP header: SYN-ACK with cookie */
	struct tcphdr tcp_hdr = {};
	tcp_hdr.source  = orig_dport;
	tcp_hdr.dest    = orig_sport;
	tcp_hdr.seq     = bpf_htonl(cookie);
	tcp_hdr.ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + 1);
	tcp_hdr.doff    = 6;
	tcp_hdr.syn     = 1;
	tcp_hdr.ack     = 1;
	tcp_hdr.window  = bpf_htons(65535);

	/* MSS option */
	__u16 mss_words[2];
	mss_words[0] = bpf_htons(0x0204);
	mss_words[1] = bpf_htons(1440); /* slightly smaller for IPv6 */

	/* TCP checksum with IPv6 pseudo-header */
	__u32 tcp_csum = 0;
	/* Pseudo-header: saddr(16) + daddr(16) + tcp_len(4) + zero(3) + proto(1) */
	__u16 *s16 = (__u16 *)&ip6->saddr;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tcp_csum += s16[i];
	__u16 *d16 = (__u16 *)&ip6->daddr;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tcp_csum += d16[i];
	tcp_csum += bpf_htons(24);    /* TCP length */
	tcp_csum += bpf_htons(PROTO_TCP);
	/* TCP header */
	__u16 *t16 = (__u16 *)&tcp_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		tcp_csum += t16[i];
	tcp_csum += mss_words[0];
	tcp_csum += mss_words[1];
	tcp_csum = (tcp_csum >> 16) + (tcp_csum & 0xffff);
	tcp_csum += tcp_csum >> 16;
	tcp_hdr.check = ~tcp_csum;

	*tcp = tcp_hdr;
	__builtin_memcpy((void *)(tcp + 1), mss_words, 4);

	/* #857: push back 802.1Q tag so reply reaches VLAN clients. */
	if (meta->ingress_vlan_present) {
		if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0)
			return XDP_DROP;
	}

	return XDP_TX;
}

/* ============================================================
 * SYN cookie: validate ACK and whitelist source (IPv4)
 *
 * Called for bare ACKs during synproxy_active. Uses the kernel
 * kfunc to validate the cookie. On success:
 *   1. Adds source to validated_clients LRU map
 *   2. Sends RST to tear down the half-open cookie connection
 *   3. Client retransmits SYN which passes as validated
 *
 * Returns XDP_TX if cookie valid (RST sent), or -1 to fall through
 * (ACK may belong to an existing session, not a cookie response).
 * ============================================================ */
static __noinline int
validate_syncookie_v4(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Access IP + TCP headers for kfunc */
	__u16 l3_off = meta->l3_offset & 0x3F;
	__u16 l4_off = meta->l4_offset & 0x7F;

	struct iphdr *iph = data + l3_off;
	if ((void *)(iph + 1) > data_end)
		return -1;

	struct tcphdr *tcph = data + l4_off;
	if ((void *)(tcph + 1) > data_end)
		return -1;

	/* Validate cookie via BPF helper */
	long rc = bpf_tcp_raw_check_syncookie_ipv4(iph, tcph);
	if (rc != 0) {
		inc_counter(GLOBAL_CTR_SYNCOOKIE_INVALID);
		return -1; /* Not a cookie ACK — fall through to conntrack */
	}

	/* Cookie valid — add source to validated_clients map.  #859: key
	 * fields are 16 bytes so v4 addresses zero-extend cleanly. */
	struct validated_client_key vk = { .dst_port = meta->dst_port };
	__builtin_memcpy(&vk.src_ip[12], &meta->src_ip.v4, 4);
	__builtin_memcpy(&vk.dst_ip[12], &meta->dst_ip.v4, 4);
	struct validated_client_value vv = {
		.validated_at = meta->now_sec,
	};
	bpf_map_update_elem(&validated_clients, &vk, &vv, BPF_ANY);
	inc_counter(GLOBAL_CTR_SYNCOOKIE_VALID);

	/* Send RST to tear down the cookie half-connection.
	 * Client will retransmit SYN which now passes as validated. */
	__be32 orig_saddr = meta->src_ip.v4;
	__be32 orig_daddr = meta->dst_ip.v4;
	__be16 orig_sport = meta->src_port;
	__be16 orig_dport = meta->dst_port;
	__be32 orig_ack   = meta->tcp_ack_seq;
	__be32 orig_seq   = meta->tcp_seq;

	/* Truncate to ETH(14) + IP(20) + TCP(20) = 54 bytes */
	long cur_len = (long)ctx->data_end - (long)ctx->data;
	int d = 54 - (int)cur_len;
	if (d != 0) {
		if (bpf_xdp_adjust_tail(ctx, d))
			return XDP_DROP;
	}

	/* Re-read after adjust — read MACs from fresh pointers */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 54 > data_end)
		return XDP_DROP;

	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	/* Read MACs (beginning unchanged by tail truncation) then swap */
	__u8 orig_smac[ETH_ALEN], orig_dmac[ETH_ALEN];
	__builtin_memcpy(orig_smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(orig_dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, orig_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, orig_smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	/* Build IP header */
	struct iphdr ip_hdr = {};
	ip_hdr.version  = 4;
	ip_hdr.ihl      = 5;
	ip_hdr.tot_len  = bpf_htons(40);
	ip_hdr.frag_off = bpf_htons(0x4000);
	ip_hdr.ttl      = 64;
	ip_hdr.protocol = PROTO_TCP;
	ip_hdr.saddr    = orig_daddr;
	ip_hdr.daddr    = orig_saddr;

	__u32 csum = 0;
	__u16 *ip16 = (__u16 *)&ip_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		csum += ip16[i];
	csum = (csum >> 16) + (csum & 0xffff);
	csum += csum >> 16;
	ip_hdr.check = ~csum;
	*ip = ip_hdr;

	/* Build TCP RST+ACK: seq=their_ack, ack=their_seq+1 */
	struct tcphdr tcp_hdr = {};
	tcp_hdr.source  = orig_dport;
	tcp_hdr.dest    = orig_sport;
	tcp_hdr.seq     = orig_ack;
	tcp_hdr.ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + 1);
	tcp_hdr.doff    = 5;
	tcp_hdr.rst     = 1;
	tcp_hdr.ack     = 1;

	/* TCP checksum */
	struct {
		__be32 saddr;  __be32 daddr;
		__u8 zero;     __u8 proto;   __be16 tcp_len;
	} pseudo = {
		.saddr = ip_hdr.saddr, .daddr = ip_hdr.daddr,
		.proto = PROTO_TCP,    .tcp_len = bpf_htons(20),
	};
	__u32 tcp_csum = 0;
	__u16 *p16 = (__u16 *)&pseudo;
	#pragma unroll
	for (int i = 0; i < 6; i++)
		tcp_csum += p16[i];
	__u16 *t16 = (__u16 *)&tcp_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		tcp_csum += t16[i];
	tcp_csum = (tcp_csum >> 16) + (tcp_csum & 0xffff);
	tcp_csum += tcp_csum >> 16;
	tcp_hdr.check = ~tcp_csum;
	*tcp = tcp_hdr;

	/* #857: push back 802.1Q tag so reply reaches VLAN clients. */
	if (meta->ingress_vlan_present) {
		if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0)
			return XDP_DROP;
	}

	return XDP_TX;
}

/* ============================================================
 * SYN cookie: validate ACK and whitelist source (IPv6)
 * ============================================================ */
static __noinline int
validate_syncookie_v6(struct xdp_md *ctx, struct pkt_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Access headers for kfunc */
	__u16 l3_off = meta->l3_offset & 0x3F;
	__u16 l4_off = meta->l4_offset & 0x7F;

	struct ipv6hdr *ip6h = data + l3_off;
	if ((void *)(ip6h + 1) > data_end)
		return -1;

	struct tcphdr *tcph = data + l4_off;
	if ((void *)(tcph + 1) > data_end)
		return -1;

	/* Validate cookie via BPF helper */
	long rc = bpf_tcp_raw_check_syncookie_ipv6(ip6h, tcph);
	if (rc != 0) {
		inc_counter(GLOBAL_CTR_SYNCOOKIE_INVALID);
		return -1;
	}

	/* Cookie valid — add source to validated_clients map.  #859: store
	 * full 16-byte v6 src + dst so whitelist is per-address, not per /32. */
	struct validated_client_key vk = { .dst_port = meta->dst_port };
	__builtin_memcpy(vk.src_ip, meta->src_ip.v6, 16);
	__builtin_memcpy(vk.dst_ip, meta->dst_ip.v6, 16);
	struct validated_client_value vv = {
		.validated_at = meta->now_sec,
	};
	bpf_map_update_elem(&validated_clients, &vk, &vv, BPF_ANY);
	inc_counter(GLOBAL_CTR_SYNCOOKIE_VALID);

	/* Send RST to tear down cookie half-connection */
	struct in6_addr orig_saddr, orig_daddr;
	__builtin_memcpy(&orig_saddr, meta->src_ip.v6, 16);
	__builtin_memcpy(&orig_daddr, meta->dst_ip.v6, 16);
	__be16 orig_sport = meta->src_port;
	__be16 orig_dport = meta->dst_port;
	__be32 orig_ack   = meta->tcp_ack_seq;
	__be32 orig_seq   = meta->tcp_seq;

	/* Truncate to ETH(14) + IPv6(40) + TCP(20) = 74 bytes */
	long cur_len = (long)ctx->data_end - (long)ctx->data;
	int d = 74 - (int)cur_len;
	if (d != 0) {
		if (bpf_xdp_adjust_tail(ctx, d))
			return XDP_DROP;
	}

	/* Re-read after adjust — fresh pointers */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + 74 > data_end)
		return XDP_DROP;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

	/* Read MACs (beginning unchanged) then swap */
	__u8 orig_smac[ETH_ALEN], orig_dmac[ETH_ALEN];
	__builtin_memcpy(orig_smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(orig_dmac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, orig_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, orig_smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Build IPv6 header */
	ip6->version     = 6;
	ip6->priority    = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;
	ip6->payload_len = bpf_htons(20);
	ip6->nexthdr     = PROTO_TCP;
	ip6->hop_limit   = 64;
	ip6->saddr       = orig_daddr;
	ip6->daddr       = orig_saddr;

	/* Build TCP RST+ACK */
	struct tcphdr tcp_hdr = {};
	tcp_hdr.source  = orig_dport;
	tcp_hdr.dest    = orig_sport;
	tcp_hdr.seq     = orig_ack;
	tcp_hdr.ack_seq = bpf_htonl(bpf_ntohl(orig_seq) + 1);
	tcp_hdr.doff    = 5;
	tcp_hdr.rst     = 1;
	tcp_hdr.ack     = 1;

	/* TCP checksum with IPv6 pseudo-header */
	__u32 tcp_csum = 0;
	__u16 *s16 = (__u16 *)&ip6->saddr;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tcp_csum += s16[i];
	__u16 *d16 = (__u16 *)&ip6->daddr;
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tcp_csum += d16[i];
	tcp_csum += bpf_htons(20);
	tcp_csum += bpf_htons(PROTO_TCP);
	__u16 *t16 = (__u16 *)&tcp_hdr;
	#pragma unroll
	for (int i = 0; i < 10; i++)
		tcp_csum += t16[i];
	tcp_csum = (tcp_csum >> 16) + (tcp_csum & 0xffff);
	tcp_csum += tcp_csum >> 16;
	tcp_hdr.check = ~tcp_csum;
	*tcp = tcp_hdr;

	/* #857: push back 802.1Q tag so reply reaches VLAN clients. */
	if (meta->ingress_vlan_present) {
		if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0)
			return XDP_DROP;
	}

	return XDP_TX;
}

SEC("xdp")
int xdp_screen_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* xdp_main/xdp_cpumap may already resolve ingress zone/routing so zones
	 * without screen config can bypass this stage entirely. */
	__u32 zone_key;
	if (meta->meta_flags & META_FLAG_INGRESS_RESOLVED) {
		zone_key = (__u32)meta->ingress_zone;
	} else {
		struct iface_zone_key zk = {
			.ifindex = meta->ingress_ifindex,
			.vlan_id = meta->ingress_vlan_id,
		};
		struct iface_zone_value *izv =
			bpf_map_lookup_elem(&iface_zone_map, &zk);
		if (!izv) {
			inc_counter(GLOBAL_CTR_DROPS);
			return XDP_DROP;
		}
		meta->ingress_zone = izv->zone_id;
		if (izv->flags & IFACE_FLAG_TUNNEL)
			meta->meta_flags |= META_FLAG_TUNNEL;
		if (izv->routing_table != 0)
			meta->routing_table = izv->routing_table;
		zone_key = (__u32)izv->zone_id;
	}

	/* Look up zone config to find screen profile ID */
	struct zone_config *zc = bpf_map_lookup_elem(&zone_configs, &zone_key);
	if (!zc || zc->screen_profile_id == 0) {
		/* No screen profile assigned -- fast path to zone */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);
		return XDP_PASS;
	}

	/* Look up screen config by profile ID */
	__u32 profile_key = (__u32)zc->screen_profile_id;
	struct screen_config *sc = bpf_map_lookup_elem(&screen_configs, &profile_key);
	if (!sc || sc->flags == 0) {
		/* Empty profile -- fast path */
		bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);
		return XDP_PASS;
	}

	/* ============================================================
	 * Stateless checks
	 * ============================================================ */

	/* LAND attack: src_ip == dst_ip */
	if (sc->flags & SCREEN_LAND_ATTACK) {
		if (meta->addr_family == AF_INET) {
			if (meta->src_ip.v4 == meta->dst_ip.v4)
				return screen_drop(meta, SCREEN_LAND_ATTACK);
		} else {
			if (ip_addr_eq_v6(meta->src_ip.v6, meta->dst_ip.v6))
				return screen_drop(meta, SCREEN_LAND_ATTACK);
		}
	}

	/* TCP-specific stateless checks.
	 *
	 * Gated on !is_fragment for the same reason as tc_screen_egress.c:
	 * xdp_main skips parse_l4hdr for non-first fragments, so
	 * tcp_flags is 0 under the top-of-pipeline memset for those.
	 * The outer guard rules them out of the SYN-centric checks
	 * below to avoid false SCREEN_TCP_NO_FLAG drops (#853). First
	 * fragments DO get parse_l4hdr (#866) so we let them through
	 * the guard and the SCREEN_SYN_FRAG check fires correctly.
	 */
	if (meta->protocol == PROTO_TCP &&
	    (!meta->is_fragment || meta->is_first_fragment)) {
		__u8 tf = meta->tcp_flags;

		/* TCP SYN+FIN */
		if ((sc->flags & SCREEN_TCP_SYN_FIN) &&
		    (tf & 0x02) && (tf & 0x01))
			return screen_drop(meta, SCREEN_TCP_SYN_FIN);

		/* TCP no-flag */
		if ((sc->flags & SCREEN_TCP_NO_FLAG) && tf == 0)
			return screen_drop(meta, SCREEN_TCP_NO_FLAG);

		/* TCP FIN-no-ACK */
		if ((sc->flags & SCREEN_TCP_FIN_NO_ACK) &&
		    (tf & 0x01) && !(tf & 0x10))
			return screen_drop(meta, SCREEN_TCP_FIN_NO_ACK);

		/* WinNuke: TCP URG to port 139 */
		if ((sc->flags & SCREEN_WINNUKE) &&
		    (tf & 0x20) && meta->dst_port == bpf_htons(139))
			return screen_drop(meta, SCREEN_WINNUKE);

		/* #866: TCP SYN on a first-fragment is the SYN-fragment
		 * attack pattern. Subsequent fragments don't have L4 so
		 * is_first_fragment=0 and they don't reach this branch. */
		if ((sc->flags & SCREEN_SYN_FRAG) &&
		    (tf & 0x02) && meta->is_first_fragment)
			return screen_drop(meta, SCREEN_SYN_FRAG);
	}

	/* Tear-drop attack: overlapping IP fragments (IPv4 only).
	 * Detect fragments where the payload is too small (< 8 bytes)
	 * for non-first fragments, indicating reassembly overlap. */
	if ((sc->flags & SCREEN_TEAR_DROP) &&
	    meta->addr_family == AF_INET &&
	    meta->is_fragment &&
	    meta->l3_offset < 64) {
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) <= data_end) {
			__u16 frag_off = bpf_ntohs(iph->frag_off);
			/* Non-first fragment (offset > 0) with tiny payload */
			if ((frag_off & 0x1FFF) > 0) {
				__u16 payload = bpf_ntohs(iph->tot_len) - ((__u16)iph->ihl << 2);
				if (payload < 8)
					return screen_drop(meta, SCREEN_TEAR_DROP);
			}
		}
	}

	/* IP source-route option (IPv4 only) */
	if ((sc->flags & SCREEN_IP_SOURCE_ROUTE) &&
	    meta->addr_family == AF_INET &&
	    meta->l3_offset < 64) {
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) <= data_end && iph->ihl > 5)
			return screen_drop(meta, SCREEN_IP_SOURCE_ROUTE);
	}

	/* Ping of Death: a fragment whose contribution to the
	 * reassembled IP datagram would exceed 65535 bytes. xpf
	 * doesn't reassemble; check per-fragment:
	 *
	 *   reassembled_tot_len = first_frag_ihl + max(offset + payload)
	 *   ≈ offset_bytes + tot_len  (when this fragment's ihl matches
	 *     the first fragment's — the typical case)
	 *
	 * Limitation: a first fragment with IP options + non-first
	 * fragments without them can craft offset+tot_len ≤ 65535
	 * while the reassembled total overflows by up to 40 bytes.
	 * Operators concerned about this should ALSO enable
	 * SCREEN_IP_SOURCE_ROUTE, which drops any packet with ihl>5
	 * and closes the gap. IP options are also blocked by most
	 * middleboxes. IPv4 only — IPv6 ping-of-death needs
	 * NEXTHDR_FRAGMENT parsing, filed as follow-up. */
	if ((sc->flags & SCREEN_PING_OF_DEATH) &&
	    meta->addr_family == AF_INET &&
	    meta->is_fragment &&
	    meta->l3_offset < 64) {
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) <= data_end) {
			__u16 frag_off = bpf_ntohs(iph->frag_off);
			__u32 offset_bytes = (frag_off & 0x1FFF) << 3;
			__u32 tot_len = bpf_ntohs(iph->tot_len);
			if (offset_bytes + tot_len > 65535)
				return screen_drop(meta, SCREEN_PING_OF_DEATH);
		}
	}

	/* ============================================================
	 * Rate-based flood checks
	 * ============================================================ */
	__u32 flood_flag = check_flood(meta, sc);
	if (flood_flag)
		return screen_drop(meta, flood_flag);

	/* ============================================================
	 * SYN cookie protection
	 *
	 * When syn-cookie mode is configured AND the zone's SYN rate
	 * exceeds the threshold, challenge unvalidated sources with
	 * SYN-ACK cookies instead of dropping all SYNs.
	 * ============================================================ */
	if ((sc->flags & SCREEN_SYN_COOKIE) && meta->protocol == PROTO_TCP) {
		struct flood_state *fs2 = bpf_map_lookup_elem(&flood_counters,
							      &zone_key);
		if (fs2 && fs2->synproxy_active) {
			__u8 tf = meta->tcp_flags;

			/* Pure SYN (no ACK) — challenge with cookie */
			if ((tf & 0x02) && !(tf & 0x10)) {
				/* Check if source is already validated.  #859:
				 * full 16-byte src/dst for both v4 (zero-extended)
				 * and v6 (full address). */
				struct validated_client_key vk = {
					.dst_port = meta->dst_port,
				};
				if (meta->addr_family == AF_INET) {
					__builtin_memcpy(&vk.src_ip[12], &meta->src_ip.v4, 4);
					__builtin_memcpy(&vk.dst_ip[12], &meta->dst_ip.v4, 4);
				} else {
					__builtin_memcpy(vk.src_ip, meta->src_ip.v6, 16);
					__builtin_memcpy(vk.dst_ip, meta->dst_ip.v6, 16);
				}
				if (bpf_map_lookup_elem(&validated_clients, &vk)) {
					inc_counter(GLOBAL_CTR_SYNCOOKIE_BYPASS);
					goto pass;
				}

				inc_counter(GLOBAL_CTR_SYNCOOKIE_SENT);
				if (meta->addr_family == AF_INET)
					return send_syncookie_synack_v4(ctx, meta);
				else
					return send_syncookie_synack_v6(ctx, meta);
			}

			/* Bare ACK (no SYN/FIN/RST) — try cookie validation */
			if ((tf & 0x10) && !(tf & 0x02) &&
			    !(tf & 0x01) && !(tf & 0x04)) {
				int rc;
				if (meta->addr_family == AF_INET)
					rc = validate_syncookie_v4(ctx, meta);
				else
					rc = validate_syncookie_v6(ctx, meta);
				if (rc == XDP_TX)
					return XDP_TX;
				/* else: not a cookie ACK, fall through */
			}
		}
	}

	/* ============================================================
	 * Per-source-IP scan/sweep detection
	 * ============================================================ */

	/* Port scan: count TCP SYN attempts per source IP */
	if ((sc->flags & SCREEN_PORT_SCAN) && sc->port_scan_thresh > 0 &&
	    meta->protocol == PROTO_TCP &&
	    (meta->tcp_flags & 0x02) && !(meta->tcp_flags & 0x10)) {
		__u32 src = (meta->addr_family == AF_INET) ?
			meta->src_ip.v4 :
			(meta->src_ip.v6[0] ^ meta->src_ip.v6[4] ^
			 meta->src_ip.v6[8] ^ meta->src_ip.v6[12]);

		struct scan_track_key sk = {
			.src_ip = src,
			.zone_id = meta->ingress_zone,
		};
		struct scan_track_value *sv =
			bpf_map_lookup_elem(&port_scan_track, &sk);
		__u64 now_sec = meta->now_sec;

		if (sv) {
			__u32 window_dur = sc->syn_flood_timeout;
			if (window_dur == 0)
				window_dur = 1;
			if (now_sec - sv->window_start >= window_dur) {
				sv->count = 1;
				sv->window_start = (__u32)now_sec;
			} else {
				sv->count++;
				if (sv->count > sc->port_scan_thresh)
					return screen_drop(meta, SCREEN_PORT_SCAN);
			}
		} else {
			struct scan_track_value new_sv = {
				.count = 1,
				.window_start = (__u32)now_sec,
			};
			bpf_map_update_elem(&port_scan_track, &sk,
					    &new_sv, BPF_ANY);
		}
	}

	/* IP sweep: count unique destination IPs per source IP */
	if ((sc->flags & SCREEN_IP_SWEEP) && sc->ip_sweep_thresh > 0) {
		__u32 src = (meta->addr_family == AF_INET) ?
			meta->src_ip.v4 :
			(meta->src_ip.v6[0] ^ meta->src_ip.v6[4] ^
			 meta->src_ip.v6[8] ^ meta->src_ip.v6[12]);

		struct scan_track_key sk = {
			.src_ip = src,
			.zone_id = meta->ingress_zone,
		};
		struct scan_track_value *sv =
			bpf_map_lookup_elem(&ip_sweep_track, &sk);
		__u64 now_sec = meta->now_sec;

		if (sv) {
			__u32 window_dur = sc->syn_flood_timeout;
			if (window_dur == 0)
				window_dur = 1;
			if (now_sec - sv->window_start >= window_dur) {
				sv->count = 1;
				sv->window_start = (__u32)now_sec;
			} else {
				sv->count++;
				if (sv->count > sc->ip_sweep_thresh)
					return screen_drop(meta, SCREEN_IP_SWEEP);
			}
		} else {
			struct scan_track_value new_sv = {
				.count = 1,
				.window_start = (__u32)now_sec,
			};
			bpf_map_update_elem(&ip_sweep_track, &sk,
					    &new_sv, BPF_ANY);
		}
	}

	/* ============================================================
	 * Per-IP session limiting (counts populated by Go GC sweep)
	 * Only check for new TCP SYN packets.
	 * ============================================================ */

	/* Session limiting: per-source-IP */
	if ((sc->flags & SCREEN_SESSION_LIMIT_SRC) && meta->protocol == PROTO_TCP &&
	    (meta->tcp_flags & 0x02) && !(meta->tcp_flags & 0x10)) {
		__u32 src = (meta->addr_family == AF_INET) ?
			meta->src_ip.v4 :
			(meta->src_ip.v6[0] ^ meta->src_ip.v6[4] ^
			 meta->src_ip.v6[8] ^ meta->src_ip.v6[12]);
		struct session_count_key sck = {
			.ip = src,
			.zone_id = meta->ingress_zone,
		};
		struct session_count_value *scv =
			bpf_map_lookup_elem(&session_count_src, &sck);
		if (scv && scv->count >= sc->session_limit_src)
			return screen_drop(meta, SCREEN_SESSION_LIMIT_SRC);
	}

	/* Session limiting: per-destination-IP */
	if ((sc->flags & SCREEN_SESSION_LIMIT_DST) && meta->protocol == PROTO_TCP &&
	    (meta->tcp_flags & 0x02) && !(meta->tcp_flags & 0x10)) {
		__u32 dst = (meta->addr_family == AF_INET) ?
			meta->dst_ip.v4 :
			(meta->dst_ip.v6[0] ^ meta->dst_ip.v6[4] ^
			 meta->dst_ip.v6[8] ^ meta->dst_ip.v6[12]);
		struct session_count_key dck = {
			.ip = dst,
			.zone_id = meta->ingress_zone,
		};
		struct session_count_value *dcv =
			bpf_map_lookup_elem(&session_count_dst, &dck);
		if (dcv && dcv->count >= sc->session_limit_dst)
			return screen_drop(meta, SCREEN_SESSION_LIMIT_DST);
	}

pass:
	/* All checks passed -- proceed to zone classification */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
