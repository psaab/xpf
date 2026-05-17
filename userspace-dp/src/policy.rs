use crate::prefix::{PrefixV4, PrefixV6};
use crate::prefix_set::{PrefixSetV4, PrefixSetV6};
use crate::{PolicyApplicationSnapshot, PolicyRuleSnapshot};
use ipnet::IpNet;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// #922: zone-pair key packed as u32 (`from_id << 16 | to_id`).
/// Replaces the previous `(String, String)` key that allocated two
/// `String`s on every `evaluate_policy` call.
pub(crate) type ZonePairKey = u32;

#[inline]
pub(crate) fn zone_pair_key(from_id: u16, to_id: u16) -> ZonePairKey {
    ((from_id as u32) << 16) | (to_id as u32)
}

/// #919/#922: sentinel for `junos-global` policy rules. Reserved at
/// the top of the u16 space; `forwarding_build` rejects any zone
/// snapshot with id ≥ ZONE_ID_RESERVED_MIN.
pub(crate) const JUNOS_GLOBAL_ZONE_ID: u16 = u16::MAX;
pub(crate) const ZONE_ID_RESERVED_MIN: u16 = u16::MAX - 1;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const PROTO_GRE: u8 = 47;
const PROTO_OSPF: u8 = 89;
const PROTO_IPIP: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyAction {
    Permit,
    Deny,
    Reject,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Deny
    }
}

#[derive(Debug)]
pub(crate) struct PolicyRule {
    pub(crate) rule_id: String,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) scheduler_name: String,
    pub(crate) inactive: bool,
    /// #923: adaptive prefix set (MatchAny / Linear ≤16 / Trie >16).
    /// Replaces the legacy `Vec<PrefixV*>` linear scan in
    /// `nets_match_v4/v6`. Empty input collapses to `MatchAny`,
    /// preserving the legacy `is_empty()` match-all behavior.
    pub(crate) source_v4: PrefixSetV4,
    pub(crate) source_v6: PrefixSetV6,
    pub(crate) destination_v4: PrefixSetV4,
    pub(crate) destination_v6: PrefixSetV6,
    pub(crate) applications: Vec<ApplicationMatch>,
    /// Precompiled application matcher (protocol-indexed, exact-port sets).
    compiled_apps: CompiledApplications,
    pub(crate) action: PolicyAction,
    pub(crate) hit_count: Arc<AtomicU64>,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            from_zone: String::new(),
            to_zone: String::new(),
            scheduler_name: String::new(),
            inactive: false,
            source_v4: PrefixSetV4::default(),
            source_v6: PrefixSetV6::default(),
            destination_v4: PrefixSetV4::default(),
            destination_v6: PrefixSetV6::default(),
            applications: Vec::new(),
            compiled_apps: CompiledApplications {
                match_any: true,
                by_protocol: FxHashMap::default(),
            },
            action: PolicyAction::Deny,
            hit_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Clone for PolicyRule {
    fn clone(&self) -> Self {
        Self {
            rule_id: self.rule_id.clone(),
            from_zone: self.from_zone.clone(),
            to_zone: self.to_zone.clone(),
            scheduler_name: self.scheduler_name.clone(),
            inactive: self.inactive,
            source_v4: self.source_v4.clone(),
            source_v6: self.source_v6.clone(),
            destination_v4: self.destination_v4.clone(),
            destination_v6: self.destination_v6.clone(),
            applications: self.applications.clone(),
            compiled_apps: self.compiled_apps.clone(),
            action: self.action,
            hit_count: self.hit_count.clone(),
        }
    }
}

type PolicyCounterRegistry = FxHashMap<String, Arc<AtomicU64>>;

const POLICY_COUNTER_REGISTRY_PRUNE_THRESHOLD: usize = 16_384;

static POLICY_COUNTERS: OnceLock<Mutex<PolicyCounterRegistry>> = OnceLock::new();

fn policy_counter_registry() -> &'static Mutex<PolicyCounterRegistry> {
    POLICY_COUNTERS.get_or_init(|| Mutex::new(FxHashMap::default()))
}

fn prune_policy_counter_registry(active_rule_ids: &FxHashSet<String>) {
    if let Ok(mut counters) = policy_counter_registry().lock() {
        if counters.len() <= POLICY_COUNTER_REGISTRY_PRUNE_THRESHOLD {
            return;
        }
        counters.retain(|rule_id, counter| {
            active_rule_ids.contains(rule_id) || Arc::strong_count(counter) > 1
        });
    }
}

fn policy_rule_hit_counter(rule_id: &str) -> Arc<AtomicU64> {
    let mut counters = policy_counter_registry()
        .lock()
        .expect("policy counter registry poisoned");
    if let Some(counter) = counters.get(rule_id) {
        return counter.clone();
    }

    let counter = Arc::new(AtomicU64::new(0));
    counters.insert(rule_id.to_string(), counter.clone());
    counter
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationMatch {
    pub(crate) protocol: u8,
    pub(crate) source_ports: Vec<PortRange>,
    pub(crate) destination_ports: Vec<PortRange>,
}

/// Pre-indexed application matcher: groups terms by protocol for O(1) lookup.
/// For exact single-port rules (the common case), stores them in a set
/// for O(1) hit instead of linear range scan.
#[derive(Clone, Debug)]
struct CompiledApplications {
    /// If true, matches any protocol/port (application "any").
    match_any: bool,
    /// Grouped by protocol for fast lookup. Key = protocol number.
    by_protocol: FxHashMap<u8, ProtoTerms>,
}

#[derive(Clone, Debug, Default)]
struct ProtoTerms {
    /// Exact destination port set (single-port terms compiled for O(1) lookup).
    exact_dst_ports: rustc_hash::FxHashSet<u16>,
    /// Port range terms that need linear scan (multi-port ranges).
    range_terms: Vec<(Vec<PortRange>, Vec<PortRange>)>, // (src_ranges, dst_ranges)
}

impl CompiledApplications {
    fn from_matches(apps: &[ApplicationMatch]) -> Self {
        if apps.is_empty() {
            return Self {
                match_any: true,
                by_protocol: FxHashMap::default(),
            };
        }
        let mut by_protocol: FxHashMap<u8, ProtoTerms> = FxHashMap::default();
        for app in apps {
            let entry = by_protocol.entry(app.protocol).or_default();
            // Optimise the common case: single exact dst port, no src port restriction.
            if app.source_ports.is_empty()
                && app.destination_ports.len() == 1
                && app.destination_ports[0].low == app.destination_ports[0].high
            {
                entry.exact_dst_ports.insert(app.destination_ports[0].low);
            } else {
                entry
                    .range_terms
                    .push((app.source_ports.clone(), app.destination_ports.clone()));
            }
        }
        Self {
            match_any: false,
            by_protocol,
        }
    }

    #[inline]
    fn matches(&self, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if self.match_any {
            return true;
        }
        let Some(terms) = self.by_protocol.get(&protocol) else {
            return false;
        };
        // Fast path: check exact dst port set first (O(1)).
        if terms.exact_dst_ports.contains(&dst_port) {
            return true;
        }
        // Slow path: check range terms.
        terms.range_terms.iter().any(|(src_ranges, dst_ranges)| {
            port_ranges_match(src_ranges, src_port) && port_ranges_match(dst_ranges, dst_port)
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    /// All rules in original order (kept for hit-counter reporting).
    pub(crate) rules: Vec<PolicyRule>,
    /// Zone-pair index: maps `(from_id, to_id)` packed u32 →
    /// indices into `rules`. Avoids scanning unrelated zone-pairs.
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    /// Indices of global rules (from_zone or to_zone = "junos-global").
    global_indices: Vec<usize>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            rules: Vec::new(),
            zone_pair_index: FxHashMap::default(),
            global_indices: Vec::new(),
        }
    }
}

pub(crate) fn parse_policy_state(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FxHashMap<String, u16>,
) -> PolicyState {
    let active_rule_ids = rules.iter().map(stable_policy_rule_id).collect();
    prune_policy_counter_registry(&active_rule_ids);
    let mut state = PolicyState {
        default_action: parse_action(default_policy),
        rules: Vec::with_capacity(rules.len()),
        zone_pair_index: FxHashMap::default(),
        global_indices: Vec::new(),
    };
    for snap in rules {
        // #923: buffer prefixes in temporary Vecs, then collapse
        // each side to a `PrefixSet*` (MatchAny / Linear / Trie)
        // when the rule is fully parsed.
        let mut src_v4: Vec<PrefixV4> = Vec::new();
        let mut src_v6: Vec<PrefixV6> = Vec::new();
        let mut dst_v4: Vec<PrefixV4> = Vec::new();
        let mut dst_v6: Vec<PrefixV6> = Vec::new();
        for prefix in &snap.source_addresses {
            parse_address(prefix, &mut src_v4, &mut src_v6);
        }
        for prefix in &snap.destination_addresses {
            parse_address(prefix, &mut dst_v4, &mut dst_v6);
        }
        let rule_id = stable_policy_rule_id(snap);
        let mut rule = PolicyRule {
            rule_id: rule_id.clone(),
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            scheduler_name: snap.scheduler_name.clone(),
            inactive: snap.inactive,
            action: parse_action(&snap.action),
            hit_count: policy_rule_hit_counter(&rule_id),
            source_v4: PrefixSetV4::from_prefixes(src_v4),
            source_v6: PrefixSetV6::from_prefixes(src_v6),
            destination_v4: PrefixSetV4::from_prefixes(dst_v4),
            destination_v6: PrefixSetV6::from_prefixes(dst_v6),
            ..PolicyRule::default()
        };
        rule.applications = parse_applications(&snap.application_terms);
        rule.compiled_apps = CompiledApplications::from_matches(&rule.applications);
        let idx = state.rules.len();
        let is_global = rule.from_zone == "junos-global" || rule.to_zone == "junos-global";
        state.rules.push(rule);

        if is_global {
            state.global_indices.push(idx);
        } else {
            // #922: translate zone names to IDs at config-load time.
            // A rule referencing an unknown zone is kept in `rules`
            // (so hit-counter reporting still works) but omitted from
            // the index — it becomes a dead rule with the same
            // semantics as today's "name not in any session" case.
            match (
                zone_name_to_id.get(&snap.from_zone).copied(),
                zone_name_to_id.get(&snap.to_zone).copied(),
            ) {
                (Some(from_id), Some(to_id)) => {
                    let key = zone_pair_key(from_id, to_id);
                    state.zone_pair_index.entry(key).or_default().push(idx);
                }
                _ => {
                    eprintln!(
                        "xpf-userspace-dp: policy rule references unknown zone(s): from={:?} to={:?} (rule kept, but not indexed)",
                        snap.from_zone, snap.to_zone
                    );
                }
            }
        }
    }
    state
}

pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> PolicyAction {
    // Phase 2 optimisation: look up only the rules for this zone-pair
    // instead of scanning all rules. Global rules are checked afterward.
    // #922: zero-allocation key (packed u32).
    let key = zone_pair_key(from_id, to_id);
    if let Some(indices) = state.zone_pair_index.get(&key) {
        for &idx in indices {
            if let Some(action) = try_match_rule(
                &state.rules[idx],
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            ) {
                return action;
            }
        }
    }
    // Global policies (junos-global) apply to any zone-pair.
    for &idx in &state.global_indices {
        if let Some(action) = try_match_rule(
            &state.rules[idx],
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
        ) {
            return action;
        }
    }
    state.default_action
}

/// Try to match a single policy rule against packet fields.
/// Returns the rule's action if all criteria match, None otherwise.
#[inline]
fn try_match_rule(
    rule: &PolicyRule,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> Option<PolicyAction> {
    if rule.inactive {
        return None;
    }
    if !rule.compiled_apps.matches(protocol, src_port, dst_port) {
        return None;
    }
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst))
            if rule.source_v4.contains(src) && rule.destination_v4.contains(dst) =>
        {
            rule.hit_count.fetch_add(1, Ordering::Relaxed);
            Some(rule.action)
        }
        (IpAddr::V6(src), IpAddr::V6(dst))
            if rule.source_v6.contains(src) && rule.destination_v6.contains(dst) =>
        {
            rule.hit_count.fetch_add(1, Ordering::Relaxed);
            Some(rule.action)
        }
        _ => None,
    }
}

fn stable_policy_rule_id(snap: &PolicyRuleSnapshot) -> String {
    if !snap.rule_id.is_empty() {
        return snap.rule_id.clone();
    }
    format!("{}->{}/{}", snap.from_zone, snap.to_zone, snap.name)
}

fn parse_action(action: &str) -> PolicyAction {
    match action {
        "permit" => PolicyAction::Permit,
        "reject" => PolicyAction::Reject,
        _ => PolicyAction::Deny,
    }
}

fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => out_v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net)),
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
            }
        }
    }
}

fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> Vec<ApplicationMatch> {
    let mut out = Vec::with_capacity(terms.len());
    for term in terms {
        let Some(protocol) = parse_protocol(&term.protocol) else {
            continue;
        };
        let Some(source_ports) = parse_port_spec(&term.source_port) else {
            continue;
        };
        let Some(destination_ports) = parse_port_spec(&term.destination_port) else {
            continue;
        };
        out.push(ApplicationMatch {
            protocol,
            source_ports,
            destination_ports,
        });
    }
    out
}

fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        _ => protocol.parse::<u8>().ok(),
    }
}

fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() {
        return Some(Vec::new());
    }
    let normalized = match spec {
        "http" => "80",
        "https" => "443",
        "ssh" => "22",
        "telnet" => "23",
        "ftp" => "21",
        "ftp-data" => "20",
        "smtp" => "25",
        "dns" => "53",
        "pop3" => "110",
        "imap" => "143",
        "snmp" => "161",
        "ntp" => "123",
        "bgp" => "179",
        "ldap" => "389",
        "syslog" => "514",
        other => other,
    };
    if let Some((low, high)) = normalized.split_once('-') {
        let low = low.parse::<u16>().ok()?;
        let high = high.parse::<u16>().ok()?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = normalized.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

fn port_ranges_match(ranges: &[PortRange], port: u16) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| port >= range.low && port <= range.high)
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
