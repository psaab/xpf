#ifndef __BPFRX_MAPS_H__
#define __BPFRX_MAPS_H__

#include "xpf_common.h"
#include "xpf_conntrack.h"

/* ============================================================
 * Tail call program arrays
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, XDP_PROG_MAX);
	__type(key, __u32);
	__type(value, __u32);
} xdp_progs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, TC_PROG_MAX);
	__type(key, __u32);
	__type(value, __u32);
} tc_progs SEC(".maps");

/* ============================================================
 * CPU map for distributing XDP processing across CPUs
 * ============================================================ */

struct cpumap_val {
	__u32 qsize;
	__u32 bpf_prog_fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct cpumap_val);
} cpu_map SEC(".maps");

/* Number of CPUs in cpu_map; 0 = cpumap disabled */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cpumap_available SEC(".maps");

/* ============================================================
 * Per-CPU scratch space for passing metadata between tail calls
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pkt_meta);
} pkt_meta_scratch SEC(".maps");

/* ============================================================
 * Per-CPU scratch space for session value staging
 * (avoids 512-byte BPF stack limit in xdp_policy)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2); /* index 0: fwd_val, index 1: rev_val */
	__type(key, __u32);
	__type(value, struct session_value);
} session_v4_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	/* index 0: fwd_val, index 1: rev_val,
	 * index 2: orig-address stash for SESSION_OPEN event emission (#861).
	 * Previously index 1 was double-used for rev_val and orig stash,
	 * causing emit_event_nat6_orig to log post-NAT addresses as "original". */
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, struct session_value_v6);
} session_v6_scratch SEC(".maps");

/* Per-CPU session ID generator. Each CPU increments independently.
 * Go seeds with node-specific base at startup. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} session_id_gen SEC(".maps");

/* ============================================================
 * Session table (connection tracking)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct session_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sessions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct session_key_v6);
	__type(value, struct session_value_v6);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sessions_v6 SEC(".maps");

/* ============================================================
 * Zone configuration
 * ============================================================ */

/* {ifindex, vlan_id} -> zone_id (HASH for VLAN support) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_LOGICAL_INTERFACES);
	__type(key, struct iface_zone_key);
	__type(value, struct iface_zone_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} iface_zone_map SEC(".maps");

/* sub-interface ifindex -> {parent_ifindex, vlan_id} */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_LOGICAL_INTERFACES);
	__type(key, __u32);
	__type(value, struct vlan_iface_info);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} vlan_iface_map SEC(".maps");

/* zone_id -> zone_config */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ZONES);
	__type(key, __u32);
	__type(value, struct zone_config);
} zone_configs SEC(".maps");

/* ============================================================
 * Policy lookup
 *
 * Two-level:
 *   1. (from_zone, to_zone) -> policy_set via zone_pair_policies
 *   2. policy_set_id * MAX_RULES_PER_POLICY + index -> policy_rule
 * ============================================================ */

struct zone_pair_key {
	__u16 from_zone;
	__u16 to_zone;
};

struct policy_set {
	__u32 policy_set_id;
	__u16 num_rules;
	__u16 default_action;
};

struct policy_rule {
	__u32 rule_id;
	__u32 policy_set_id;
	__u16 sequence;
	__u8  action;     /* ACTION_* */
	__u8  log;

	/* Match criteria -- 0 means "any" */
	__u32 src_addr_id;
	__u32 dst_addr_id;
	__u16 dst_port_low;
	__u16 dst_port_high;
	__u8  protocol;   /* 0 = any */
	__u8  active;     /* 1=active, 0=inactive (scheduler) */
	__u8  pad[2];

	__u32 app_id;
	__u32 nat_rule_id;
	__u32 counter_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ZONES * MAX_ZONES);
	__type(key, __u32);
	__type(value, struct policy_set);
} zone_pair_policies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_POLICIES * MAX_RULES_PER_POLICY);
	__type(key, __u32);
	__type(value, struct policy_rule);
} policy_rules SEC(".maps");

/* ============================================================
 * Address book -- LPM trie for prefix matching
 * ============================================================ */

struct lpm_key_v4 {
	__u32 prefixlen;
	__be32 addr;
};

struct lpm_key_v6 {
	__u32 prefixlen;
	__u8  addr[16];
};

struct addr_value {
	__u32 address_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ADDRESSES);
	__type(key, struct lpm_key_v4);
	__type(value, struct addr_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} address_book_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ADDRESSES);
	__type(key, struct lpm_key_v6);
	__type(value, struct addr_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} address_book_v6 SEC(".maps");

/* Address membership: (ip, address_id) -> exists */
struct addr_membership_key {
	__be32 ip;
	__u32  address_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ADDRESSES * 8);
	__type(key, struct addr_membership_key);
	__type(value, __u8);
} address_membership SEC(".maps");

/* ============================================================
 * Application table
 * ============================================================ */

struct app_key {
	__u8  protocol;
	__u8  pad;
	__be16 dst_port;
};

struct app_value {
	__u32 app_id;
	__u8  alg_type;  /* 0=none */
	__u8  pad;
	__u16 pad2;
	__u32 timeout;   /* inactivity timeout override (seconds), 0=default */
	__u16 src_port_low;  /* source port range low, host byte order (0=any) */
	__u16 src_port_high; /* source port range high, host byte order (0=any) */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_APPLICATIONS);
	__type(key, struct app_key);
	__type(value, struct app_value);
} applications SEC(".maps");

/* Range-based application entries for large port ranges.
 * When a port range exceeds a threshold (e.g., 256 ports), the compiler
 * stores a single range entry here instead of expanding per-port into
 * the HASH map. Checked after exact HASH lookup misses. */
struct app_range_entry {
	__u8  protocol;
	__u8  alg_type;
	__u16 port_low;     /* host byte order */
	__u16 port_high;    /* host byte order */
	__u16 src_port_low; /* host byte order, 0=any */
	__u16 src_port_high;/* host byte order, 0=any */
	__u16 pad;
	__u32 app_id;
	__u32 timeout;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_APP_RANGES);
	__type(key, __u32);
	__type(value, struct app_range_entry);
} app_ranges SEC(".maps");

/* ============================================================
 * Counters & statistics (per-CPU for lock-free increments)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_POLICIES);
	__type(key, __u32);
	__type(value, struct counter_value);
} policy_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_ZONES * 2);
	__type(key, __u32);
	__type(value, struct counter_value);
} zone_counters SEC(".maps");

/* Keyed on kernel ifindex which can exceed MAX_INTERFACES on long-lived
 * VMs/namespaces (incus/k8s). HASH + NO_PREALLOC allocates only for
 * registered interfaces and accepts arbitrary ifindex values. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_INTERFACES);
	__type(key, __u32);
	__type(value, struct iface_counter_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} interface_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, GLOBAL_CTR_MAX);
	__type(key, __u32);
	__type(value, __u64);
} global_counters SEC(".maps");

/* ============================================================
 * FIB cache generation counter.
 * Bumped by Go on recompile; BPF checks session.fib_gen == fib_gen_map[0]
 * to validate cached FIB entries. Avoids userspace session write-back
 * (which causes RCU replacement and stale BPF pointers).
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} fib_gen_map SEC(".maps");

/* ============================================================
 * Forwarding -- device map for XDP_REDIRECT
 * ============================================================ */

/* #767: keep plain DEVMAP on this map.
 *
 * #759 converted this to BPF_MAP_TYPE_DEVMAP_HASH so sparse ifindex
 * values above MAX_INTERFACES would not hit E2BIG. That broke
 * forwarding on mlx5 SR-IOV VFs running kernel 7.0.0-rc7+. Observed
 * symptoms: ping RTT 0.4 ms → 300 ms with 33% loss, iperf3 sustained
 * 0 bps, and the Rust helper emitted `DBG SEG_MISS` for every
 * frame it handled. (The SEG_MISS log fires from tx/dispatch.rs on
 * frame-length criteria independent of bpf_redirect_map's result,
 * so it's a symptom that packets reached the helper in a state the
 * TX path couldn't service — not direct evidence about the redirect.)
 *
 * Bisection of the five HASH conversions in #759 (see the #767
 * investigation) confirmed this was the only one mlx5 could not
 * tolerate. The driver-level mechanism has not been source-verified;
 * the consistent hypothesis is that mlx5 native XDP's
 * bpf_redirect_map fast-path assumes DEVMAP layout and DEVMAP_HASH
 * routes through a different path that does not deliver end-to-end
 * on this kernel. DEVMAP_HASH worked on virtio-net on kernel 6.x.
 *
 * The ifindex-above-cap case #759 was fixing is only realistic on
 * long-lived namespaces where ifindex has drifted past
 * MAX_INTERFACES. When that becomes a live concern again, the fix
 * is to raise MAX_INTERFACES rather than reintroduce DEVMAP_HASH.
 *
 * Note: this header change alone would not flip the runtime map
 * type unless the bpf2go-generated objects in pkg/dataplane/*.o are
 * also regenerated and committed. That regeneration is part of this
 * PR's commit (see `make generate` artifacts). */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, MAX_INTERFACES);
	__type(key, __u32);
	__type(value, struct bpf_devmap_val);
} tx_ports SEC(".maps");

/* Per-interface flag: 1 = native XDP redirect capable (has ndo_xdp_xmit).
 * xdp_forward checks this before bpf_redirect_map; interfaces without
 * native redirect support get XDP_PASS so the kernel forwards instead.
 * HASH + NO_PREALLOC tolerates sparse ifindex values. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INTERFACES);
	__type(key, __u32);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} redirect_capable SEC(".maps");

/* ============================================================
 * Event ring buffer (kernel -> userspace)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* ============================================================
 * Screen/IDS configuration & flood rate state
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SCREEN_PROFILES);
	__type(key, __u32);
	__type(value, struct screen_config);
} screen_configs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_ZONES);
	__type(key, __u32);
	__type(value, struct flood_state);
} flood_counters SEC(".maps");

/* Validated SYN cookie clients -- sources that passed cookie challenge.
 * LRU_HASH auto-evicts oldest entries when full. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct validated_client_key);
	__type(value, struct validated_client_value);
} validated_clients SEC(".maps");

/* Per-source-IP tracking for port scan / IP sweep detection.
 * LRU_HASH auto-evicts oldest entries when full. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PORT_SCAN_TRACK);
	__type(key, struct scan_track_key);
	__type(value, struct scan_track_value);
} port_scan_track SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PORT_SCAN_TRACK);
	__type(key, struct scan_track_key);
	__type(value, struct scan_track_value);
} ip_sweep_track SEC(".maps");

/* ============================================================
 * NAT pool configuration & port allocation
 * Only included in programs that define BPFRX_NAT_POOLS
 * (xdp_main owns the maps, xdp_policy uses alloc helpers)
 * ============================================================ */

#ifdef BPFRX_NAT_POOLS

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_NAT_POOLS);
	__type(key, __u32);
	__type(value, struct nat_pool_config);
} nat_pool_configs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_NAT_POOLS * MAX_NAT_POOL_IPS_PER_POOL);
	__type(key, __u32);
	__type(value, __be32);
} nat_pool_ips_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_NAT_POOLS * MAX_NAT_POOL_IPS_PER_POOL);
	__type(key, __u32);
	__type(value, struct nat_pool_ip_v6);
} nat_pool_ips_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_NAT_POOLS);
	__type(key, __u32);
	__type(value, struct nat_port_counter);
} nat_port_counters SEC(".maps");

/* Per-rule NAT hit counters (translation hits) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_NAT_RULE_COUNTERS);
	__type(key, __u32);
	__type(value, struct counter_value);
} nat_rule_counters SEC(".maps");

#endif /* BPFRX_NAT_POOLS */

/* ============================================================
 * NAT tables (IPv4)
 * ============================================================ */

/* Pre-routing NAT table: (proto, dst_ip, dst_port, from_zone) -> new destination.
 * Static DNAT config entries use the configured ingress zone. Dynamic SNAT
 * return entries use from_zone=0 as a wildcard. */
struct dnat_key {
	__u8   protocol;
	__u8   pad[3];
	__be32 dst_ip;
	__be16 dst_port;
	__u16  from_zone;
};

struct dnat_value {
	__be32 new_dst_ip;
	__be16 new_dst_port;
	__u8   flags;       /* 0=dynamic/SNAT-return, 1=static/DNAT-config */
	__u8   pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct dnat_key);
	__type(value, struct dnat_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dnat_table SEC(".maps");

/* Source NAT config: (from_zone, to_zone, rule_idx) -> SNAT IP + match.
 * Populated by the compiler on commit. Multiple rules per zone-pair
 * are iterated sequentially (0..MAX-1) until first match. */
#define MAX_SNAT_RULES_PER_PAIR 8

struct snat_key {
	__u16 from_zone;
	__u16 to_zone;
	__u16 rule_idx;    /* 0-based rule index within zone-pair */
	__u16 pad;
};

struct snat_value {
	__be32 snat_ip;
	__u32  src_addr_id;  /* 0 = any */
	__u32  dst_addr_id;  /* 0 = any */
	__u8   mode;         /* pool ID, or SNAT_MODE_OFF (0xFF) for no-NAT exemption */
	__u8   pad;
	__u16  counter_id;   /* index into nat_rule_counters */
};

#define SNAT_MODE_OFF 0xFF  /* source-nat off: match but don't translate */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ZONES * MAX_ZONES * MAX_SNAT_RULES_PER_PAIR);
	__type(key, __u32);
	__type(value, struct snat_value);
} snat_rules SEC(".maps");

/* Per-egress-interface SNAT addresses for "source-nat interface" mode.
 * Key: (parent_ifindex, vlan_id) — same identity used by fwd_ifindex/egress_vlan_id.
 * Value: IPv4 + IPv6 address of that interface.
 * Populated by Go compiler; looked up at SNAT allocation time when pool
 * has interface_mode=1 to pick the correct egress IP. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_LOGICAL_INTERFACES);
	__type(key, struct snat_egress_key);
	__type(value, struct snat_egress_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} snat_egress_ips SEC(".maps");

/* ============================================================
 * NAT tables (IPv6)
 * ============================================================ */

struct dnat_key_v6 {
	__u8   protocol;
	__u8   pad[3];
	__u8   dst_ip[16];
	__be16 dst_port;
	__u16  from_zone;
};

struct dnat_value_v6 {
	__u8   new_dst_ip[16];
	__be16 new_dst_port;
	__u8   flags;       /* 0=dynamic/SNAT-return, 1=static/DNAT-config */
	__u8   pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct dnat_key_v6);
	__type(value, struct dnat_value_v6);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dnat_table_v6 SEC(".maps");

struct snat_value_v6 {
	__u8   snat_ip[16];
	__u32  src_addr_id;  /* 0 = any */
	__u32  dst_addr_id;  /* 0 = any */
	__u8   mode;         /* pool ID, or SNAT_MODE_OFF for no-NAT exemption */
	__u8   pad;
	__u16  counter_id;   /* index into nat_rule_counters */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ZONES * MAX_ZONES * MAX_SNAT_RULES_PER_PAIR);
	__type(key, __u32);
	__type(value, struct snat_value_v6);
} snat_rules_v6 SEC(".maps");

/* ============================================================
 * Static 1:1 NAT tables
 * ============================================================ */

#define MAX_STATIC_NAT_ENTRIES 2048
#define STATIC_NAT_DNAT 0  /* key.ip is external addr */
#define STATIC_NAT_SNAT 1  /* key.ip is internal addr */

struct static_nat_key_v4 {
	__be32 ip;
	__u8   direction;
	__u8   pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STATIC_NAT_ENTRIES);
	__type(key, struct static_nat_key_v4);
	__type(value, __be32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} static_nat_v4 SEC(".maps");

struct static_nat_key_v6 {
	__u8 ip[16];
	__u8 direction;
	__u8 pad[3];
};

struct static_nat_value_v6 {
	__u8 ip[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STATIC_NAT_ENTRIES);
	__type(key, struct static_nat_key_v6);
	__type(value, struct static_nat_value_v6);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} static_nat_v6 SEC(".maps");

/* ============================================================
 * NPTv6 prefix translation (RFC 6296)
 * ============================================================ */

#define MAX_NPTV6_RULES 128

/* Direction constants for NPTv6 */
#define NPTV6_INBOUND  0  /* external → internal (rewrite dst) */
#define NPTV6_OUTBOUND 1  /* internal → external (rewrite src) */

/* Key: 48-bit prefix (3 x 16-bit words) + direction.
 * For /48 prefixes (the common case), we store the first 6 bytes. */
struct nptv6_key {
	__u8 prefix[8];    /* first 48 or 64 bits of IPv6 address (zero-padded for /48) */
	__u8 direction;    /* NPTV6_INBOUND or NPTV6_OUTBOUND */
	__u8 prefix_len;   /* 48 or 64 (bits) */
	__u8 pad[6];
};

/* Value: translation prefix + precomputed adjustment.
 * The adjustment is computed at config time per RFC 6296.
 * For /48: adjusts word[3].  For /64: adjusts word[4]. */
struct nptv6_value {
	__u8  xlat_prefix[8]; /* replacement prefix (first 48 or 64 bits) */
	__u16 adjustment;     /* ones'-complement adjustment (native byte order) */
	__u8  prefix_words;   /* 3 for /48, 4 for /64 — number of prefix words */
	__u8  pad[5];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_NPTV6_RULES);
	__type(key, struct nptv6_key);
	__type(value, struct nptv6_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} nptv6_rules SEC(".maps");

/* ============================================================
 * Default policy (global fallback when no zone-pair policy exists)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);  /* ACTION_DENY=0, ACTION_PERMIT=1 */
} default_policy SEC(".maps");

/* ============================================================
 * Configurable flow/session timeouts
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_TIMEOUT_MAX);
	__type(key, __u32);
	__type(value, __u32);
} flow_timeouts SEC(".maps");

/* ============================================================
 * Global flow configuration (TCP MSS clamp, etc.)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct flow_config);
} flow_config_map SEC(".maps");

/* ============================================================
 * NAT64 configuration & state
 * ============================================================ */

/* NAT64 prefix array: index -> nat64_config (legacy, kept for loader) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_NAT64_PREFIXES);
	__type(key, __u32);
	__type(value, struct nat64_config);
} nat64_configs SEC(".maps");

/* Number of active NAT64 prefixes (single-entry array, legacy) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} nat64_count SEC(".maps");

/* NAT64 prefix hash map: O(1) lookup by /96 prefix (replaces array scan) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_NAT64_PREFIXES);
	__type(key, struct nat64_prefix_key);
	__type(value, struct nat64_config);
} nat64_prefix_map SEC(".maps");

/* NAT64 reverse state: translated IPv4 5-tuple -> original IPv6 info */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct nat64_state_key);
	__type(value, struct nat64_state_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} nat64_state SEC(".maps");

/* NAT64 FIB cache: translated IPv4 dst -> FIB result (LRU).
 * Avoids bpf_fib_lookup on every NAT64 forward-path packet.
 * Invalidated via fib_gen_map generation counter. */
struct nat64_fib_cache_key {
	__be32 ipv4_dst;
	__u32  tbid;
};
struct nat64_fib_cache_val {
	__u32 ifindex;     /* resolved physical ifindex */
	__u16 vlan_id;
	__u16 gen;         /* matches fib_gen_map[0] */
	__u8  dmac[6];
	__u8  smac[6];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct nat64_fib_cache_key);
	__type(value, struct nat64_fib_cache_val);
} nat64_fib_cache SEC(".maps");

/* ============================================================
 * Firewall filter maps
 * ============================================================ */

/* Interface filter assignment: {ifindex, vlan_id, family} -> filter_id */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_LOGICAL_INTERFACES * 2); /* *2 for inet + inet6 */
	__type(key, struct iface_filter_key);
	__type(value, __u32); /* filter_id (index into filter_configs) */
	__uint(map_flags, BPF_F_NO_PREALLOC);
} iface_filter_map SEC(".maps");

/* Per-filter config: filter_id -> {num_rules, rule_start} */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_FILTER_CONFIGS);
	__type(key, __u32);
	__type(value, struct filter_config);
} filter_configs SEC(".maps");

/* Global filter rule array: indexed by rule_start + i */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_FILTER_RULES);
	__type(key, __u32);
	__type(value, struct filter_rule);
} filter_rules SEC(".maps");

/* Per-rule filter counters: indexed by rule_start + i */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_FILTER_RULES);
	__type(key, __u32);
	__type(value, struct counter_value);
} filter_counters SEC(".maps");

/* ============================================================
 * Port mirroring (SPAN) -- per-interface mirror config
 * Key: ingress ifindex, Value: mirror destination + rate
 * ============================================================ */

/* HASH + NO_PREALLOC accepts sparse ifindex keys (see tx_ports). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INTERFACES);
	__type(key, __u32);
	__type(value, struct mirror_config);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} mirror_config SEC(".maps");

/* Per-CPU counter for 1-in-N mirror sampling */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} mirror_counter SEC(".maps");

/* ============================================================
 * Per-RG active state (for active/active fabric forwarding)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_REDUNDANCY_GROUPS);
	__type(key, __u32);
	__type(value, __u8);
} rg_active SEC(".maps");

/* ============================================================
 * Fabric cross-chassis forwarding (cluster failback)
 * ============================================================ */

struct fabric_fwd_info {
	__u32 ifindex;       /* fabric interface ifindex, 0 = disabled */
	__u32 fib_ifindex;   /* non-VRF ifindex for zone-decoded FIB lookups */
	__u8  peer_mac[6];   /* peer's fabric MAC */
	__u8  local_mac[6];  /* our fabric MAC */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct fabric_fwd_info);
} fabric_fwd SEC(".maps");

/* ============================================================
 * Policer maps (single-rate two-color token bucket)
 * ============================================================ */

/* Policer configuration: policer_id -> config (written by userspace) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_POLICERS);
	__type(key, __u32);
	__type(value, struct policer_config);
} policer_configs SEC(".maps");

/* Policer runtime state: per-CPU for lock-free token bucket */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_POLICERS);
	__type(key, __u32);
	__type(value, struct policer_state);
} policer_states SEC(".maps");

/* ============================================================
 * RETIRED (#1476/#10791): the ha_watchdog BPF liveness consumer.
 * The array remains for Go-owned HA bookkeeping, but no live BPF caller
 * uses it to check per-RG freshness. The current daemon-loss backstop is
 * the helper's receipt-anchored 10s update_ha_state lease.
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_REDUNDANCY_GROUPS);
	__type(key, __u32);
	__type(value, __u64);
} ha_watchdog SEC(".maps");

/* ============================================================
 * Per-IP session count maps (populated by Go GC sweep)
 * Used by xdp_screen for per-source/destination session limiting.
 * ============================================================ */

/* Per-source-IP session count */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct session_count_key);
	__type(value, struct session_count_value);
} session_count_src SEC(".maps");

/* Per-destination-IP session count */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct session_count_key);
	__type(value, struct session_count_value);
} session_count_dst SEC(".maps");

#endif /* __BPFRX_MAPS_H__ */
