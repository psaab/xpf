#ifndef __BPFRX_CONNTRACK_H__
#define __BPFRX_CONNTRACK_H__

#include "xpf_common.h"

/* Session key -- 5-tuple. Both forward and reverse entries stored. */
struct session_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   pad[3];
} __attribute__((packed));

/* Session value -- full connection state. */
struct session_value {
	/* Connection state */
	__u8  state;           /* SESS_STATE_* */
	__u16 flags;           /* SESS_FLAG_* -- __u16: SESS_FLAG_NPTV6 is bit 8
				* (0x100), which does not fit a __u8 (#5460). The
				* compiler inserts one pad byte after `state` and
				* two after `is_reverse`; the C/Rust/Go layouts
				* stay byte-identical (size-asserted 152/200 -- 144/192
				* before #9546 appended routing_domain, 136/184
				* before #4983 appended the ingress-identity pair). */
	__u8  tcp_state;       /* TCP-specific sub-state */
	__u8  is_reverse;      /* 1 if this is the reverse direction entry */
	__u32 app_timeout;     /* per-application inactivity timeout (seconds), 0=use default */

	__u64 session_id;      /* unique ID, same on both cluster nodes */

	/* Timestamps (seconds since boot) */
	__u64 created;
	__u64 last_seen;
	__u32 timeout;         /* idle timeout in seconds */
	__u32 policy_id;

	/* Zone info */
	__u16 ingress_zone;
	__u16 egress_zone;

	/* NAT translations (original -> translated) */
	__be32 nat_src_ip;
	__be32 nat_dst_ip;
	__be16 nat_src_port;
	__be16 nat_dst_port;

	/* Counters -- forward direction */
	__u64 fwd_packets;
	__u64 fwd_bytes;

	/* Counters -- reverse direction */
	__u64 rev_packets;
	__u64 rev_bytes;

	/* Reverse key for paired entry deletion */
	struct session_key reverse_key;

	/* ALG tracking */
	__u8  alg_type;    /* 0=none, 1=FTP, 2=SIP, 3=DNS */
	__u8  log_flags;
	__u16 app_id;      /* application ID for structured logging */

	/* Cached FIB result (set by xdp_zone, 0 = not cached) */
	__u32 fib_ifindex;
	__u16 fib_vlan_id;
	__u8  fib_dmac[6];
	__u8  fib_smac[6];
	__u16 fib_gen;      /* FIB cache generation (matches fib_gen_map[0]) */

	/* #4983: the ifindex of the binding the session's FIRST packet arrived
	 * on -- the session's TRUE ingress-interface identity, stamped once at
	 * install and never re-derived. Distinct from fib_ifindex above, which
	 * is the resolved EGRESS. 0 means "no ingress identity carried" and is
	 * NOT a valid ifindex: the reverse companion (whose own ingress has not
	 * been OBSERVED yet -- the forward flow's egress is known at install but
	 * is a PREDICTION of where the reply will arrive, not an observation of
	 * where it did, and routing may be asymmetric), an HA peer-synced session
	 * (an ifindex is node-local -- the peer's number names a different NIC
	 * here), and the host-outbound GRE encapsulation path (self-originated
	 * traffic read off the TUN device, which has no ingress binding to
	 * record) all leave it 0. There is deliberately NO "pre-#4983 helper"
	 * population here (#6928): this struct's size is part of the shim ABI
	 * pre-flight's checked set, and validateUserspaceShimLivePins hard-refuses
	 * a ValueSize mismatch against the live pin, so a new reader never sees an
	 * old writer's shorter rows (136/184
	 * before #4983, 144/192 before #9546). Consumers MUST treat
	 * 0 as "fall back to the zone approximation", never as "matches
	 * nothing" or "matches everything". */
	__u32 ingress_ifindex;
	/* #4983: the 802.1Q VLAN id the session's first packet arrived with. 0 is
	 * BOTH an untagged frame AND an 802.1p priority-tagged one (a real 802.1Q
	 * tag with VID 0 and PCP/DEI set); this bare VID does not distinguish
	 * them, so do NOT read 0 as "arrived untagged" (#6928 -- the counter-
	 * example is in-tree at userspace-dp/src/afxdp/frame/prop_tests/inspect.rs,
	 * a real tag with PCP 5 and VID 0). The TX side DOES distinguish, via
	 * TxVlanTag on tag PRESENCE (#2149).
	 * Paired with ingress_ifindex it names the LOGICAL ingress
	 * unit -- the same {parent ifindex, vlan} identity the egress side is
	 * already resolved by (fib_ifindex/fib_vlan_id), so two units of one
	 * trunk NIC are distinguishable.
	 *
	 * Padding, stated once so the figures elsewhere agree: appending
	 * ingress_ifindex at the old 136/184 tail took the struct to 140/188, and
	 * the 8-byte alignment padded it to 144/192 -- a 4-byte growth.
	 * ingress_vlan_id then lands INSIDE that pad at 140/188, leaving 2 unused
	 * bytes after it. So "4 bytes of tail pad" (the growth the append cost,
	 * as bpf_map_tests.rs and the Rust mirror put it) and "2 bytes of tail
	 * pad" (what remains unused) describe the SAME layout from either end.
	 * sizeof grows 136 -> 144, not 136 -> 152. */
	__u16 ingress_vlan_id;
	/* #9546: the session's ROUTING DOMAIN in the #7239 wire encoding
	 * (0 = not stated, 1 = default instance, else a reserved-band domain).
	 * The Go delete paths read it back so a helper delete names the domain the
	 * row was installed under (#9146 singular, #9364 batch); before this field
	 * existed the mirror dropped it and both were inert. Appended AFTER
	 * ingress_vlan_id so no existing offset moves: a __u32 needs a 4-byte
	 * boundary, so it skips the 2 unused pad bytes and lands at 144, and the
	 * 8-byte alignment grows sizeof 144 -> 152. */
	__u32 routing_domain;
};

/* IPv6 session key -- 5-tuple with 128-bit addresses. */
struct session_key_v6 {
	__u8   src_ip[16];
	__u8   dst_ip[16];
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   pad[3];
} __attribute__((packed));

/* IPv6 session value -- full connection state with 128-bit addresses. */
struct session_value_v6 {
	/* Connection state */
	__u8  state;           /* SESS_STATE_* */
	__u16 flags;           /* SESS_FLAG_* -- __u16 (see session_value.flags,
				* #5460): SESS_FLAG_NPTV6 (bit 8) overflows __u8. */
	__u8  tcp_state;       /* TCP-specific sub-state */
	__u8  is_reverse;      /* 1 if this is the reverse direction entry */
	__u32 app_timeout;     /* per-application inactivity timeout (seconds), 0=use default */

	__u64 session_id;      /* unique ID, same on both cluster nodes */

	/* Timestamps (seconds since boot) */
	__u64 created;
	__u64 last_seen;
	__u32 timeout;         /* idle timeout in seconds */
	__u32 policy_id;

	/* Zone info */
	__u16 ingress_zone;
	__u16 egress_zone;

	/* NAT translations (original -> translated) */
	__u8  nat_src_ip[16];
	__u8  nat_dst_ip[16];
	__be16 nat_src_port;
	__be16 nat_dst_port;

	/* Counters -- forward direction */
	__u64 fwd_packets;
	__u64 fwd_bytes;

	/* Counters -- reverse direction */
	__u64 rev_packets;
	__u64 rev_bytes;

	/* Reverse key for paired entry deletion */
	struct session_key_v6 reverse_key;

	/* ALG tracking */
	__u8  alg_type;    /* 0=none, 1=FTP, 2=SIP, 3=DNS */
	__u8  log_flags;
	__u16 app_id;      /* application ID for structured logging */

	/* Cached FIB result (set by xdp_zone, 0 = not cached) */
	__u32 fib_ifindex;
	__u16 fib_vlan_id;
	__u8  fib_dmac[6];
	__u8  fib_smac[6];
	__u16 fib_gen;      /* FIB cache generation (matches fib_gen_map[0]) */

	/* #4983: ingress-binding ifindex -- see session_value.ingress_ifindex
	 * for the full contract (0 = no identity carried, fall back to the
	 * zone approximation). */
	__u32 ingress_ifindex;
	/* #4983: ingress 802.1Q VLAN id -- see session_value.ingress_vlan_id.
	 * 0 is BOTH untagged and 802.1p priority-tagged (real tag, VID 0); this
	 * bare VID does not distinguish them (#6928). sizeof grows 184 -> 192. */
	__u16 ingress_vlan_id;
	/* #9546: routing domain -- see session_value.routing_domain. Lands at 192;
	 * sizeof grows 192 -> 200. */
	__u32 routing_domain;
};

/* TCP state machine transition. Returns new state. */
static __always_inline __u8
ct_tcp_update_state(__u8 current_state, __u8 tcp_flags, __u8 direction)
{
	__u8 syn = tcp_flags & 0x02;
	__u8 ack = tcp_flags & 0x10;
	__u8 fin = tcp_flags & 0x01;
	__u8 rst = tcp_flags & 0x04;

	if (rst)
		return SESS_STATE_CLOSED;

	switch (current_state) {
	case SESS_STATE_NEW:
		if (direction == 0 && syn && !ack)
			return SESS_STATE_SYN_SENT;
		break;
	case SESS_STATE_SYN_SENT:
		if (direction == 1 && syn && ack)
			return SESS_STATE_SYN_RECV;
		break;
	case SESS_STATE_SYN_RECV:
		if (direction == 0 && ack)
			return SESS_STATE_ESTABLISHED;
		break;
	case SESS_STATE_ESTABLISHED:
		if (fin)
			return SESS_STATE_FIN_WAIT;
		break;
	case SESS_STATE_FIN_WAIT:
		if (fin)
			return SESS_STATE_CLOSE_WAIT;
		break;
	case SESS_STATE_CLOSE_WAIT:
		if (ack)
			return SESS_STATE_TIME_WAIT;
		break;
	}

	return current_state;
}

/* Get default session timeout based on protocol and state. */
static __always_inline __u32
ct_get_timeout_default(__u8 protocol, __u8 state)
{
	switch (protocol) {
	case PROTO_TCP:
		switch (state) {
		case SESS_STATE_NEW:
		case SESS_STATE_SYN_SENT:
		case SESS_STATE_SYN_RECV:
			return 30;
		case SESS_STATE_ESTABLISHED:
			return 1800;
		case SESS_STATE_FIN_WAIT:
		case SESS_STATE_CLOSE_WAIT:
			return 30;
		case SESS_STATE_TIME_WAIT:
			return 120;
		default:
			return 10;
		}
	case PROTO_UDP:
		return 60;
	case PROTO_ICMP:
	case PROTO_ICMPV6:
		return 30;
	default:
		return 30;
	}
}

/* Build reverse session key (IPv4). */
static __always_inline void
ct_reverse_key(const struct session_key *fwd, struct session_key *rev)
{
	rev->src_ip   = fwd->dst_ip;
	rev->dst_ip   = fwd->src_ip;
	rev->src_port = fwd->dst_port;
	rev->dst_port = fwd->src_port;
	rev->protocol = fwd->protocol;
	rev->pad[0] = rev->pad[1] = rev->pad[2] = 0;
}

/* Build reverse session key (IPv6). */
static __always_inline void
ct_reverse_key_v6(const struct session_key_v6 *fwd, struct session_key_v6 *rev)
{
	__builtin_memcpy(rev->src_ip, fwd->dst_ip, 16);
	__builtin_memcpy(rev->dst_ip, fwd->src_ip, 16);
	rev->src_port = fwd->dst_port;
	rev->dst_port = fwd->src_port;
	rev->protocol = fwd->protocol;
	rev->pad[0] = rev->pad[1] = rev->pad[2] = 0;
}

#endif /* __BPFRX_CONNTRACK_H__ */
