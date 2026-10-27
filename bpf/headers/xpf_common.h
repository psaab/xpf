#ifndef __XPF_COMMON_H__
#define __XPF_COMMON_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* #17146: retained ABI mirror, not compiled code. No BPF program or
 * .c file includes this header since the #1476 eBPF retirement. The
 * file survives only for the identifiers its live readers consume:
 * the shim build (MAX_INTERFACES), Go parity tests (MAX_INTERFACES,
 * MAX_NAT_POOLS, GLOBAL_CTR_MAX, struct event) and
 * C-side layout sizing in xpf_conntrack.h / xpf_maps.h. Everything
 * else from the retired pipeline's copy has been removed; adding a
 * define or struct here without a non-comment reader in a build
 * script or test outside bpf/ fails
 * TestEveryHeaderIdentifierHasLiveReader17146. */

/* Maximum values */
#define MAX_ZONES              64
#define MAX_INTERFACES         65536
#define MAX_POLICIES           4096
#define MAX_RULES_PER_POLICY   256
#define MAX_SESSIONS           10000000 /* 10M sessions */
#define MAX_NAT_POOLS          32
#define MAX_NAT_RULE_COUNTERS  256
#define MAX_ADDRESSES          8192
#define MAX_APP_RANGES         32     /* range-based application entries */
#define MAX_CPUS               256

/* XDP tail call program indices */
#define XDP_PROG_SCREEN        0
#define XDP_PROG_ZONE          1
#define XDP_PROG_CONNTRACK     2
#define XDP_PROG_POLICY        3
#define XDP_PROG_NAT           4
#define XDP_PROG_FORWARD       5
#define XDP_PROG_NAT64         6

/* TC tail call program indices */
#define TC_PROG_CONNTRACK      0
#define TC_PROG_NAT            1
#define TC_PROG_SCREEN_EGRESS  2
#define TC_PROG_FORWARD        3

/* Session states */
#define SESS_STATE_NONE        0
#define SESS_STATE_NEW         1
#define SESS_STATE_SYN_SENT    2
#define SESS_STATE_SYN_RECV    3
#define SESS_STATE_ESTABLISHED 4
#define SESS_STATE_FIN_WAIT    5
#define SESS_STATE_CLOSE_WAIT  6
#define SESS_STATE_TIME_WAIT   7
#define SESS_STATE_CLOSED      8

/* Session flags -- stored in session_value.flags, a __u16 (xpf_conntrack.h).
 * Bits 0-7 occupy the low byte; SESS_FLAG_NPTV6 is bit 8 and needs the high
 * byte, which is why `flags` is __u16 and not __u8 (#5460). Keep the field
 * width >= the highest bit used here, and mirror any new bit into the Rust
 * (BpfSessionValue*) and Go (bpfSessionValue*) structs. */
#define SESS_FLAG_SNAT         (1 << 0)
#define SESS_FLAG_DNAT         (1 << 1)
#define SESS_FLAG_LOG          (1 << 2)
#define SESS_FLAG_STATIC_NAT   (1 << 6)
#define SESS_FLAG_NAT64        (1 << 7)
#define SESS_FLAG_NPTV6        (1 << 8)   /* bit 8 -- requires __u16 flags */
/* #10227 (#9655 second half): set on a row installed from a cluster peer
 * (Go putClusterSynced* or userspace publish with a peer origin). Fresh local
 * installs clear it, and promotion clears it with a read/modify/write, so the
 * bit records the row's current provenance: set means peer-synced, clear means
 * locally authoritative (or legacy). The cluster wire carries it as a
 * trailing length-gated high-flags byte (the #5460 prescription); the
 * receiver stamps it at install and bulk reconcile deletes a stale row only
 * when it is set, so a genuinely local row is never reconciled away. */
#define SESS_FLAG_CLUSTER_SYNCED (1 << 9)
/* #12187: known-provenance marker for the source-NAT origin carried in
 * `flags`. With the marker set, SESS_FLAG_STATIC_NAT (bit 6) says static
 * SNAT when set and dynamic SNAT when clear; with the marker clear the
 * provenance is unknown/legacy and bit 6 is ignored. Mirror any new bit
 * into the Rust (BpfSessionValue*) and Go (bpfSessionValue*) structs. */
#define SESS_FLAG_SNAT_PROVENANCE_KNOWN (1 << 10)

/* Policy actions */
#define ACTION_DENY            0
#define ACTION_PERMIT          1
#define ACTION_REJECT          2

/* Protocol numbers */
#define PROTO_TCP              6
#define PROTO_UDP              17
#define PROTO_ICMP             1
#define PROTO_ICMPV6           58

/* Event types for ring buffer */
#define EVENT_TYPE_SESSION_OPEN   1
#define EVENT_TYPE_SESSION_CLOSE  2
#define EVENT_TYPE_POLICY_DENY    3
#define EVENT_TYPE_SCREEN_DROP    4
#define EVENT_TYPE_FILTER_LOG     6

/* Session close reason codes for structured logging */
#define CLOSE_REASON_NONE         0
#define CLOSE_REASON_TIMEOUT      1
#define CLOSE_REASON_TCP_FIN      2
#define CLOSE_REASON_TCP_RST      3
#define CLOSE_REASON_AGE_OUT      4
#define CLOSE_REASON_POLICY       5

/* Global counter indices */
#define GLOBAL_CTR_RX_PACKETS      0
#define GLOBAL_CTR_TX_PACKETS      1
#define GLOBAL_CTR_DROPS           2
#define GLOBAL_CTR_SESSIONS_NEW    3
#define GLOBAL_CTR_SESSIONS_CLOSED 4
#define GLOBAL_CTR_SCREEN_DROPS    5
#define GLOBAL_CTR_POLICY_DENY     6
#define GLOBAL_CTR_NAT_ALLOC_FAIL      7
#define GLOBAL_CTR_HOST_INBOUND_DENY   8
#define GLOBAL_CTR_TC_EGRESS_PACKETS   9
#define GLOBAL_CTR_NAT64_XLATE        10
#define GLOBAL_CTR_HOST_INBOUND       11
/* Per-screen-type drop counters (indices 12..25). */
#define GLOBAL_CTR_SCREEN_SYN_FLOOD      12
#define GLOBAL_CTR_SCREEN_ICMP_FLOOD     13
#define GLOBAL_CTR_SCREEN_UDP_FLOOD      14
#define GLOBAL_CTR_SCREEN_PORT_SCAN      15
#define GLOBAL_CTR_SCREEN_IP_SWEEP       16
#define GLOBAL_CTR_SCREEN_LAND_ATTACK    17
#define GLOBAL_CTR_SCREEN_PING_OF_DEATH  18
#define GLOBAL_CTR_SCREEN_TEAR_DROP      19
#define GLOBAL_CTR_SCREEN_TCP_SYN_FIN    20
#define GLOBAL_CTR_SCREEN_TCP_NO_FLAG    21
#define GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK 22
#define GLOBAL_CTR_SCREEN_WINNUKE        23
#define GLOBAL_CTR_SCREEN_IP_SRC_ROUTE   24
#define GLOBAL_CTR_SCREEN_SYN_FRAG       25
#define GLOBAL_CTR_FABRIC_REDIRECT       26
#define GLOBAL_CTR_SYNCOOKIE_SENT        27
#define GLOBAL_CTR_SYNCOOKIE_VALID       28
#define GLOBAL_CTR_SYNCOOKIE_INVALID     29
#define GLOBAL_CTR_SYNCOOKIE_BYPASS      30
#define GLOBAL_CTR_SCREEN_SESSION_LIMIT  31
#define GLOBAL_CTR_FABRIC_FWD_DROP       32
#define GLOBAL_CTR_FABRIC_REDIRECT_FAB0  33
#define GLOBAL_CTR_FABRIC_REDIRECT_FAB1  34
#define GLOBAL_CTR_FABRIC_REDIRECT_ZONE  35
#define GLOBAL_CTR_FLOW_CACHE_HIT        36
#define GLOBAL_CTR_FLOW_CACHE_MISS       37
#define GLOBAL_CTR_FLOW_CACHE_FLUSH      38
#define GLOBAL_CTR_FLOW_CACHE_INVALIDATE 39
#define GLOBAL_CTR_VLAN_PUSH_FAIL        40
#define GLOBAL_CTR_UNKNOWN_VLAN_DROPS    41
#define GLOBAL_CTR_DST_MAC_DROPS         42
/* #13286: userspace-only screen reasons / SYN-cookie budget (43..47). */
#define GLOBAL_CTR_SCREEN_ICMP_FRAGMENT        43
#define GLOBAL_CTR_SCREEN_IP_MALFORMED         44
#define GLOBAL_CTR_SCREEN_SYN_COOKIE_UNAVAIL   45
#define GLOBAL_CTR_SCREEN_SYN_COOKIE_INVALID   46
#define GLOBAL_CTR_SYNCOOKIE_ACTIVE_BUDGET     47
#define GLOBAL_CTR_MAX                   48

/* Flow timeout indices for flow_timeouts ARRAY map */
#define FLOW_TIMEOUT_MAX               7

/* Screen option flags */
#define SCREEN_SYN_FLOOD         (1 << 0)
#define SCREEN_ICMP_FLOOD        (1 << 1)
#define SCREEN_UDP_FLOOD         (1 << 2)
#define SCREEN_PORT_SCAN         (1 << 3)
#define SCREEN_IP_SWEEP          (1 << 4)
#define SCREEN_LAND_ATTACK       (1 << 5)
#define SCREEN_PING_OF_DEATH     (1 << 6)
#define SCREEN_TEAR_DROP         (1 << 7)
#define SCREEN_TCP_SYN_FIN       (1 << 8)
#define SCREEN_TCP_NO_FLAG       (1 << 9)
#define SCREEN_TCP_FIN_NO_ACK    (1 << 10)
#define SCREEN_WINNUKE           (1 << 11)
#define SCREEN_IP_SOURCE_ROUTE   (1 << 12)
#define SCREEN_SYN_FRAG          (1 << 13)
#define SCREEN_SYN_COOKIE        (1 << 14)
#define SCREEN_SESSION_LIMIT_SRC (1 << 15)
#define SCREEN_SESSION_LIMIT_DST (1 << 16)

/* Host-inbound-traffic service flags (zone_config.host_inbound_flags) */
#define HOST_INBOUND_SSH         (1 << 0)
#define HOST_INBOUND_PING        (1 << 1)   /* ICMP + ICMPv6 echo */
#define HOST_INBOUND_DNS         (1 << 2)
#define HOST_INBOUND_HTTP        (1 << 3)
#define HOST_INBOUND_HTTPS       (1 << 4)
#define HOST_INBOUND_DHCP        (1 << 5)
#define HOST_INBOUND_NTP         (1 << 6)
#define HOST_INBOUND_SNMP        (1 << 7)
#define HOST_INBOUND_BGP         (1 << 8)
#define HOST_INBOUND_OSPF        (1 << 9)
#define HOST_INBOUND_TRACEROUTE  (1 << 10)
#define HOST_INBOUND_TELNET      (1 << 11)
#define HOST_INBOUND_FTP         (1 << 12)
#define HOST_INBOUND_NETCONF     (1 << 13)
#define HOST_INBOUND_SYSLOG      (1 << 14)
#define HOST_INBOUND_RADIUS      (1 << 15)
#define HOST_INBOUND_IKE         (1 << 16)
#define HOST_INBOUND_DHCPV6      (1 << 17)
#define HOST_INBOUND_VRRP        (1 << 18)
#define HOST_INBOUND_ESP              (1 << 19)
#define HOST_INBOUND_ROUTER_DISCOVERY (1 << 20)
#define HOST_INBOUND_NDP              (1 << 22)
#define HOST_INBOUND_GRE             (1 << 21)
#define HOST_INBOUND_ALL              0xFFFFFFFF  /* permit all services */

/* ============================================================
 * Address family agnostic IP address.
 * Used in pkt_meta to handle both v4 and v6.
 * For v4: address stored in .v4, v6 bytes zeroed.
 * ============================================================ */

struct ip_addr {
	union {
		__be32 v4;
		__u8   v6[16];
	};
};

/* ============================================================
 * VLAN / logical interface support
 * ============================================================ */

/* Composite key for iface_zone_map (HASH): {ifindex, vlan_id} -> zone + routing table */
struct iface_zone_key {
	__u32 ifindex;
	__u16 vlan_id;
	__u16 pad;
};

/* Value for iface_zone_map: zone assignment + optional VRF routing table */
struct iface_zone_value {
	__u16 zone_id;
	__u8  flags;          /* IFACE_FLAG_* bits */
	__u8  rg_id;          /* redundancy group ID (0 = standalone/non-RETH) */
	__u32 routing_table;  /* kernel table ID, 0 = main table */
	__u32 screen_flags;   /* precomputed screen_config.flags for ingress fast-path */
};

#define MAX_REDUNDANCY_GROUPS 16

#define IFACE_FLAG_TUNNEL       (1 << 0)  /* GRE/IPsec tunnel interface */
#define IFACE_FLAG_NATIVE_XDP   (1 << 1)  /* interface runs native/driver XDP */
#define IFACE_FLAG_XDP_ATTACHED (1 << 2)  /* #863: XDP (native or generic) attached on
                                           * the ingress side; positive proof for the
                                           * tc_main tunnel-egress bypass */

/* Reverse mapping: sub-interface ifindex -> parent physical info */
struct vlan_iface_info {
	__u32 parent_ifindex;
	__u16 vlan_id;
	__u16 pad;
};

/* ============================================================
 * Packet metadata -- passed between tail call stages via
 * per-CPU scratch map at index 0.
 * ============================================================ */

struct pkt_meta {
	/* Parsed header fields (network byte order for IPs/ports) */
	struct ip_addr src_ip;     /* 16 bytes */
	struct ip_addr dst_ip;     /* 16 bytes */
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   tcp_flags;
	__u8   ip_ttl;
	__u8   addr_family;  /* AF_INET=2, AF_INET6=10 */
	__u8   dscp;          /* DSCP value (top 6 bits of TOS/traffic-class) */
	__u8   csum_partial;  /* 1 = L4 csum is pseudo-header only (CHECKSUM_PARTIAL) */
	__u8   meta_flags;     /* META_FLAG_* bits */
	__u8   embedded_proto; /* inner protocol for ICMP error rewrite */

	/* ICMP specific */
	__be16 icmp_id;
	__u8   icmp_type;
	__u8   icmp_code;

	/* TCP sequence numbers (for RST generation) */
	__be32 tcp_seq;
	__be32 tcp_ack_seq;

	/* Header offsets from packet start */
	__u16 l3_offset;
	__u16 l4_offset;
	__u16 payload_offset;
	/* #860: pkt_len is u32, not u16. IPv4 tot_len fits in u16, but
	 * IPv6 payload_len + sizeof(ipv6hdr) can wrap u16 for jumbo
	 * frames (payload > 65495). Widening also makes the
	 * SCREEN_PING_OF_DEATH `pkt_len > 65535` check meaningful —
	 * with u16 the comparison was always false (dead code). */
	__u32 pkt_len;

	/* Zone classification */
	__u16 ingress_zone;
	__u16 egress_zone;
	__u32 ingress_ifindex;
	__u16 ingress_vlan_id;
	__u8  ingress_pcp;
	__u8  ingress_vlan_present;
	__u16 egress_vlan_id;

	/* Pipeline state */
	__u8  direction;    /* 0=ingress, 1=egress */
	__u8  is_fragment;
	/* #866: 1 = packet is a first-fragment by criteria
	 * (IPv4: MF=1 && offset==0; IPv6: MF=1 && offset==0). The L4
	 * header is *typically* present in the first fragment for
	 * legitimate traffic given minimum MTUs, but the protocol
	 * doesn't strictly guarantee it — an attacker can craft a
	 * tiny first fragment that doesn't contain the full L4 header.
	 * `parse_l4hdr` does bounds-check and drops if the L4 header
	 * isn't fully present, so this flag is safe to use as a gate.
	 * Subsequent fragments (offset>0) have is_fragment=1 and
	 * is_first_fragment=0; non-fragmented datagrams have both 0.
	 * Enables real SCREEN_SYN_FRAG detection — a SYN packet that's
	 * also a first-fragment is a fragmentation-based attack. */
	__u8  is_first_fragment;
	__u8  ct_state;     /* SESS_STATE_* */
	__u8  ct_direction; /* 0=forward, 1=reverse */

	__u32 policy_id;

	/* NAT translations to apply */
	struct ip_addr nat_src_ip;  /* 16 bytes */
	struct ip_addr nat_dst_ip;  /* 16 bytes */
	__be16 nat_src_port;
	__be16 nat_dst_port;
	__u32  nat_flags;

	/* Forwarding decision */
	__u32 fwd_ifindex;
	__u8  fwd_dmac[6];
	__u8  fwd_smac[6];

	/* Policy-based routing (set by firewall filter) */
	__u32 routing_table;  /* VRF table ID, 0 = main table */

	/* DSCP rewrite (set by firewall filter, 0xFF = no rewrite) */
	__u8  dscp_rewrite;
	__u8  native_xdp;  /* 1 = ingress iface has native XDP (no CHECKSUM_PARTIAL) */

	/* Per-application inactivity timeout override (seconds, 0 = use default) */
	__u16 l4_csum_saved;  /* deferred L4 checksum for lazy CHECKSUM_PARTIAL (IPv6) */
	__u32 app_timeout;

	/* Port mirroring (set by xdp_forward for TC egress to clone) */
	__u32 mirror_ifindex;  /* 0 = no mirroring */
	__u32 mirror_rate;     /* 1-in-N rate (0 = mirror all) */

	/* Cached coarse seconds for conntrack/screen aging. */
	__u32 now_sec;
	__u32 pad_time;

	/* Cached precise bpf_ktime_get_ns() — populated lazily when policers
	 * or other precise timers need it. */
	__u64 ktime_ns;
};

/* ============================================================
 * Event structure for ring buffer
 * ============================================================ */

struct event {
	__u64  timestamp;
	__u8   src_ip[16];
	__u8   dst_ip[16];
	__be16 src_port;
	__be16 dst_port;
	__u32  policy_id;
	__u16  ingress_zone;
	__u16  egress_zone;
	__u8   event_type;
	__u8   protocol;
	__u8   action;
	__u8   addr_family;  /* AF_INET=2, AF_INET6=10 */
	__u64  session_packets;
	__u64  session_bytes;
	/* NAT translation addresses (post-NAT) */
	__u8   nat_src_ip[16];
	__u8   nat_dst_ip[16];
	__be16 nat_src_port;
	__be16 nat_dst_port;
	__u32  created;      /* session creation time (seconds since boot) */
	/* Extended fields for structured logging (vSRX RT_FLOW compat) */
	__u64  rev_packets;       /* reverse direction packets (server→client) */
	__u64  rev_bytes;         /* reverse direction bytes */
	__u32  ingress_ifindex;   /* incoming interface ifindex */
	__u16  app_id;            /* application ID from policy rule match */
	__u8   close_reason;      /* CLOSE_REASON_* */
	__u8   pad_event;         /* alignment padding */
};

/* ============================================================
 * Zone configuration
 * ============================================================ */

struct zone_config {
	__u16 zone_id;
	__u16 screen_profile_id;
	__u32 host_inbound_flags;
	__u8  tcp_rst;      /* send TCP RST for non-SYN without session */
	__u8  pad[3];
};

/* ============================================================
 * Counter value (per-CPU)
 * ============================================================ */

struct counter_value {
	__u64 packets;
	__u64 bytes;
};

/* ============================================================
 * Screen/IDS configuration
 * ============================================================ */

struct screen_config {
	__u32 flags;              /* SCREEN_* bitmask */
	__u32 syn_flood_thresh;   /* SYN pkts/sec/zone, 0=disabled */
	__u32 icmp_flood_thresh;
	__u32 udp_flood_thresh;
	__u32 syn_flood_src_thresh;  /* per-source-IP threshold (future) */
	__u32 syn_flood_dst_thresh;  /* per-dest-IP threshold (future) */
	__u32 syn_flood_timeout;     /* flood window duration in seconds (0=1s) */
	__u32 port_scan_thresh;      /* TCP SYN attempts per source IP in window */
	__u32 ip_sweep_thresh;       /* unique dest IPs per source IP in window */
	__u32 session_limit_src;     /* max sessions per source IP, 0=disabled */
	__u32 session_limit_dst;     /* max sessions per destination IP, 0=disabled */
};

struct flood_state {
	__u64 syn_count;
	__u64 icmp_count;
	__u64 udp_count;
	__u64 window_start;       /* ktime_ns / 1e9 (seconds) */
	__u8  synproxy_active;    /* 1 when syn-cookie mode active for zone */
	__u8  pad_fs[7];
};

/* Per-IP session count (populated by Go GC sweep for session limiting). */
struct session_count_key {
	__u32 ip;        /* IPv4 addr or XOR hash of IPv6 */
	__u16 zone_id;
	__u16 pad;
};

struct session_count_value {
	__u32 count;
};

/* ============================================================
 * NAT pool configuration
 * ============================================================ */

#define MAX_NAT_POOL_IPS_PER_POOL  256  /* max IPs per individual pool (CGNAT pools may have 125+) */

struct nat_pool_config {
	__u16 num_ips;        /* number of v4 IPs in this pool */
	__u16 num_ips_v6;     /* number of v6 IPs in this pool */
	__u16 port_low;       /* default 1024 */
	__u16 port_high;      /* default 65535 */
	__u8  addr_persistent; /* same src IP always maps to same pool IP */
	__u8  deterministic;  /* 0=off, 1=IPv4 host, 2=IPv6 host */
	__u16 block_size;     /* ports per subscriber (deterministic) */
	__be32 host_base;     /* subscriber range base IP (deterministic==1) */
	__u32 host_count;     /* number of subscriber IPs (deterministic) */
	__u16 blocks_per_ip;  /* precomputed port_range / block_size */
	__u8  host_prefix_len; /* IPv6 prefix length: 32 or 64 (deterministic==2) */
	__u8  interface_mode;  /* 1 = source-nat interface: use egress IP from snat_egress_ips */
	__be32 host_base_v6[4]; /* IPv6 subscriber base (deterministic==2) */
};

/* Key for snat_egress_ips: egress interface identity */
struct snat_egress_key {
	__u32 ifindex;   /* parent interface index (meta->fwd_ifindex) */
	__u16 vlan_id;   /* egress VLAN (meta->egress_vlan_id), 0 for non-VLAN */
	__u16 pad;
};

/* Value for snat_egress_ips: per-interface SNAT address */
struct snat_egress_value {
	__be32 ipv4;
	__u8   ipv6[16];
};

struct nat_port_counter {
	__u64 counter;
};

/* ============================================================
 * NAT64 configuration
 * ============================================================ */

#define MAX_NAT64_PREFIXES 4

/* Firewall filter limits */
#define MAX_FILTER_CONFIGS 64
#define MAX_FILTER_RULES   512

/* Policer limits */
#define MAX_POLICERS 64

/* Policer action when rate exceeded */

/* Filter match flags */
#define FILTER_MATCH_DSCP      (1 << 0)
#define FILTER_MATCH_PROTOCOL  (1 << 1)
#define FILTER_MATCH_SRC_ADDR  (1 << 2)
#define FILTER_MATCH_DST_ADDR  (1 << 3)
#define FILTER_MATCH_DST_PORT  (1 << 4)
#define FILTER_MATCH_ICMP_TYPE (1 << 5)
#define FILTER_MATCH_ICMP_CODE (1 << 6)
#define FILTER_MATCH_SRC_PORT  (1 << 7)
#define FILTER_MATCH_SRC_NEGATE (1 << 8)  /* negate source address match (prefix-list except) */
#define FILTER_MATCH_DST_NEGATE (1 << 9)  /* negate destination address match (prefix-list except) */
#define FILTER_MATCH_TCP_FLAGS  (1 << 10) /* match TCP flags bitmask */
#define FILTER_MATCH_FRAGMENT   (1 << 11) /* match IP fragments */
#define FILTER_MATCH_FLEX       (1 << 12) /* flexible byte-offset match */

/* Filter actions */
#define FILTER_ACTION_ACCEPT   0
#define FILTER_ACTION_DISCARD  1
#define FILTER_ACTION_REJECT   2
#define FILTER_ACTION_ROUTE    3  /* routing-instance */

/* DSCP codepoint values */
#define DSCP_EF  46
#define DSCP_AF11 10
#define DSCP_AF31 26
#define DSCP_AF43 38

/* NAT64 prefix lookup key: first 96 bits of IPv6 destination address. */
struct nat64_prefix_key {
	__be32 prefix[3];
};

/* NAT64 prefix config entry:
 * snat_pool_id points to the IPv4 source pool for translated packets. */
struct nat64_config {
	__be32 prefix[3];  /* first 96 bits of NAT64 prefix (3 x 32-bit words) */
	__u8   snat_pool_id;
	__u8   pad[3];
};

/* ============================================================
 * Firewall filter configuration
 * ============================================================ */

/* Per-filter config: number of rules and where they start in the rules array */
struct filter_config {
	__u32 num_rules;
	__u32 rule_start;   /* index into filter_rules array */
	__u8  all_have_proto; /* 1 if every term specifies FILTER_MATCH_PROTOCOL */
	__u8  proto_count;    /* distinct protocol values across all terms (max 4) */
	__u8  proto_list[4];  /* the distinct protocol numbers */
	__u8  pad[2];
};

/* Interface filter assignment key: {ifindex, vlan_id, family, direction} -> filter_id */
struct iface_filter_key {
	__u32 ifindex;
	__u16 vlan_id;
	__u8  family;     /* AF_INET=2, AF_INET6=10 */
	__u8  direction;  /* 0=input, 1=output */
};

/* Unified filter rule (works for both v4 and v6) */
struct filter_rule {
	__u16  match_flags;     /* FILTER_MATCH_* bitmask */
	__u8   dscp;            /* DSCP/traffic-class value (6 bits) */
	__u8   protocol;        /* IP protocol number, 0=any */
	__u8   action;          /* FILTER_ACTION_* */
	__u8   icmp_type;       /* ICMP type, valid if FILTER_MATCH_ICMP_TYPE */
	__u8   icmp_code;       /* ICMP code, valid if FILTER_MATCH_ICMP_CODE */
	__u8   family;          /* AF_INET or AF_INET6 */
	__be16 dst_port;        /* network byte order, 0=any */
	__be16 src_port;        /* network byte order, 0=any */
	__be16 dst_port_hi;     /* range upper bound, 0=exact match */
	__be16 src_port_hi;     /* range upper bound, 0=exact match */
	__u8   dscp_rewrite;    /* DSCP rewrite value (0xFF = no rewrite) */
	__u8   log_flag;        /* 1 = emit ring buffer event on match */
	__u8   tcp_flags;       /* TCP flags bitmask to match (SYN=0x02, ACK=0x10, etc.) */
	__u8   is_fragment;     /* 1 = match IP fragments */
	__u8   src_addr[16];    /* v4: first 4 bytes, v6: all 16 */
	__u8   src_mask[16];    /* prefix mask */
	__u8   dst_addr[16];
	__u8   dst_mask[16];
	__u32  routing_table;   /* VRF table ID (for FILTER_ACTION_ROUTE) */
	__u8   policer_id;      /* policer index (0=none, 1-based) */
	__u8   flex_offset;     /* flexible match: byte offset from L3 header start */
	__u8   flex_length;     /* flexible match: match length in bytes (1,2,4) */
	__u8   pad_rule;
	__u32  flex_value;      /* flexible match: expected value (host byte order, masked) */
	__u32  flex_mask;       /* flexible match: mask to apply before comparison */
};

/* ============================================================
 * Policer configuration (supports single-rate and two-rate three-color)
 * ============================================================ */

/* color_mode values */
#define POLICER_MODE_SINGLE_RATE  0  /* single-rate two-color (default) */
#define POLICER_MODE_TWO_RATE     1  /* two-rate three-color (RFC 2698) */

struct policer_config {
	__u64 rate_bytes_sec;   /* CIR: token refill rate (bytes per second) */
	__u64 burst_bytes;      /* CBS: max committed bucket capacity (bytes) */
	__u8  action;           /* POLICER_ACTION_DISCARD=0 */
	__u8  color_mode;       /* POLICER_MODE_* */
	__u8  pad[6];
	__u64 peak_rate;        /* PIR: peak refill rate (two-rate only, 0=unused) */
	__u64 peak_burst;       /* PBS/EBS: peak/excess burst size (0=unused) */
};

struct policer_state {
	__u64 tokens;           /* committed token count (bytes) */
	__u64 last_refill_ns;   /* last refill timestamp (bpf_ktime_get_ns) */
	__u64 peak_tokens;      /* peak/excess token count (three-color only) */
	__u64 pad_state;        /* alignment */
};

/* ============================================================
 * Global flow configuration (single-entry array map)
 * ============================================================ */

struct flow_config {
	__u16 tcp_mss_ipsec;   /* TCP MSS clamp for IPsec VPN (0=disabled) */
	__u16 tcp_mss_gre_in;  /* TCP MSS clamp for GRE ingress (0=disabled) */
	__u16 tcp_mss_gre_out; /* TCP MSS clamp for GRE egress (0=disabled) */
	__u8  allow_dns_reply;
	__u8  allow_embedded_icmp;
	__u8  gre_accel;       /* GRE performance acceleration */
	__u8  alg_flags;       /* bit 0: DNS disable, bit 1: FTP disable,
	                          bit 2: SIP disable, bit 3: TFTP disable */
	__u16 lo0_filter_v4;   /* filter ID for lo0 inet input (0xFFFF=none) */
	__u16 lo0_filter_v6;   /* filter ID for lo0 inet6 input (0xFFFF=none) */
	__u8  tcp_flags;       /* retired (#2078): bit 0: no-syn-check,
	                          bit 1: rst-invalidate, bit 2:
	                          no-syn-check-in-tunnel. The tcp-session knobs
	                          are config-only on the userspace dataplane; this
	                          field is no longer populated (the legacy
	                          flow_config_map was retired with the eBPF
	                          dataplane, #1373/#1476). Kept for layout parity. */
	__u8  app_flags;       /* bit 0: AppID enabled,
	                          bit 1: pre-ID log session-init,
	                          bit 2: pre-ID log session-close */
};

/* ============================================================
 * Port mirroring (SPAN) configuration
 * ============================================================ */

struct mirror_config {
	__u32 mirror_ifindex;  /* destination interface ifindex */
	__u32 rate;            /* 1-in-N sampling rate (0 = mirror all) */
};

#endif /* __XPF_COMMON_H__ */
