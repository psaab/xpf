//! Firewall filter and policer evaluation for the userspace dataplane.
//!
//! Implements Junos-style firewall filters with ordered terms (first match wins)
//! and token-bucket policers. Mirrors the eBPF filter pipeline
//! (`bpf/xdp/xdp_forward.c` lo0 filter evaluation).
//!
//! Filters can be applied:
//! - Per-interface (input direction): evaluated after zone resolution, before session lookup
//! - lo0 (host-bound traffic): evaluated on local delivery path

use crate::prefix::{PrefixV4, PrefixV6};
// #1049 P2: Snapshot types come from the crate root (protocol.rs) and are
// referenced by both compiler.rs and the tests module. Importing here makes
// them visible to all submodules via `use super::*;`.
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot,
};
use ipnet::IpNet;
#[cfg(not(test))]
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const PROTO_GRE: u8 = 47;
const PROTO_OSPF: u8 = 89;
const PROTO_IPIP: u8 = 4;

/// Result of evaluating a filter term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FilterAction {
    /// Accept the packet (default if no term matches).
    Accept,
    /// Silently drop the packet.
    Discard,
    /// Drop with ICMP unreachable.
    Reject,
}

/// Compiled filter term with pre-parsed match criteria.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct FilterTerm {
    pub(crate) name: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) dest_v4: Vec<PrefixV4>,
    pub(crate) dest_v6: Vec<PrefixV6>,
    pub(crate) protocol_bitmap: [u64; 4],
    pub(crate) protocol_match_enabled: bool,
    pub(crate) source_ports: PortMatcher,
    pub(crate) dest_ports: PortMatcher,
    pub(crate) dscp_bitmap: u64,
    pub(crate) dscp_match_enabled: bool,
    pub(crate) action: FilterAction,
    pub(crate) count: String,
    pub(crate) has_count: bool,
    pub(crate) log: bool,
    pub(crate) policer_name: String,
    pub(crate) three_color_policer: Option<Arc<ThreeColorPolicerRuntime>>,
    pub(crate) routing_instance: String,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) counter: Arc<FilterTermCounter>,
}

/// Inclusive port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PortMatcher {
    Any,
    Single(u16),
    Range(PortRange),
    Set(Box<[PortRange]>),
}

impl PortMatcher {
    #[inline(always)]
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(expected) => port == *expected,
            Self::Range(range) => port >= range.low && port <= range.high,
            Self::Set(ranges) => ranges
                .iter()
                .any(|range| port >= range.low && port <= range.high),
        }
    }
}

/// A compiled firewall filter (ordered list of terms).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct Filter {
    pub(crate) name: String,
    pub(crate) family: String,
    pub(crate) terms: Vec<FilterTerm>,
    pub(crate) affects_tx_selection: bool,
    pub(crate) affects_route_lookup: bool,
    pub(crate) has_counter_terms: bool,
    pub(crate) has_three_color_policer_terms: bool,
}

#[derive(Debug, Default)]
pub(crate) struct FilterTermCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
}

#[derive(Debug, Default)]
pub(crate) struct ThreeColorPolicerCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
}

impl ThreeColorPolicerCounter {
    fn record(&self, packet_bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub(crate) struct ThreeColorPolicerCounters {
    pub(crate) green: ThreeColorPolicerCounter,
    pub(crate) yellow: ThreeColorPolicerCounter,
    pub(crate) red: ThreeColorPolicerCounter,
    pub(crate) drop: ThreeColorPolicerCounter,
}

#[derive(Debug)]
pub(crate) struct ThreeColorPolicerRuntime {
    pub(crate) id: u32,
    pub(crate) name: Arc<str>,
    state: Mutex<ThreeColorPolicerState>,
    counters: ThreeColorPolicerCounters,
}

impl PartialEq for ThreeColorPolicerRuntime {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.name == other.name
    }
}

impl Eq for ThreeColorPolicerRuntime {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CachedThreeColorPolicers {
    first: Option<Arc<ThreeColorPolicerRuntime>>,
    second: Option<Arc<ThreeColorPolicerRuntime>>,
}

impl CachedThreeColorPolicers {
    #[inline]
    pub(crate) fn from_option(runtime: Option<Arc<ThreeColorPolicerRuntime>>) -> Self {
        Self {
            first: runtime,
            second: None,
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, runtime: Arc<ThreeColorPolicerRuntime>) {
        if self
            .first
            .as_ref()
            .is_some_and(|existing| existing.id == runtime.id)
            || self
                .second
                .as_ref()
                .is_some_and(|existing| existing.id == runtime.id)
        {
            return;
        }
        if self.first.is_none() {
            self.first = Some(runtime);
        } else if self.second.is_none() {
            self.second = Some(runtime);
        }
    }

    #[inline]
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(runtime) = other.first {
            self.push(runtime);
        }
        if let Some(runtime) = other.second {
            self.push(runtime);
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        usize::from(self.first.is_some()) + usize::from(self.second.is_some())
    }

    #[inline]
    pub(crate) fn for_each(&self, mut f: impl FnMut(&Arc<ThreeColorPolicerRuntime>)) {
        if let Some(runtime) = self.first.as_ref() {
            f(runtime);
        }
        if let Some(runtime) = self.second.as_ref() {
            f(runtime);
        }
    }
}

impl ThreeColorPolicerRuntime {
    pub(crate) fn new(id: u32, name: String, state: ThreeColorPolicerState) -> Self {
        Self {
            id,
            name: Arc::<str>::from(name),
            state: Mutex::new(state),
            counters: ThreeColorPolicerCounters::default(),
        }
    }

    pub(crate) fn meter(
        &self,
        now_ns: u64,
        packet_bytes: u64,
        incoming_color: PacketColor,
    ) -> ThreeColorDecision {
        let decision = self
            .state
            .lock()
            .map(|mut state| state.meter(now_ns, packet_bytes, incoming_color))
            .unwrap_or_else(|_| ThreeColorDecision {
                color: PacketColor::Red,
                dscp_rewrite: None,
                drop: true,
            });
        match decision.color {
            PacketColor::Green => self.counters.green.record(packet_bytes),
            PacketColor::Yellow => self.counters.yellow.record(packet_bytes),
            PacketColor::Red => self.counters.red.record(packet_bytes),
        }
        if decision.drop {
            self.counters.drop.record(packet_bytes);
        }
        decision
    }

    pub(crate) fn status(&self) -> crate::protocol::ThreeColorPolicerStatus {
        let (mode, color_blind) = self
            .state
            .lock()
            .map(|state| (state.mode_name().to_string(), state.color_blind()))
            .unwrap_or_else(|_| ("unknown".to_string(), false));
        crate::protocol::ThreeColorPolicerStatus {
            id: self.id,
            name: self.name.to_string(),
            mode,
            color_blind,
            green_packets: self.counters.green.packets.load(Ordering::Relaxed),
            green_bytes: self.counters.green.bytes.load(Ordering::Relaxed),
            yellow_packets: self.counters.yellow.packets.load(Ordering::Relaxed),
            yellow_bytes: self.counters.yellow.bytes.load(Ordering::Relaxed),
            red_packets: self.counters.red.packets.load(Ordering::Relaxed),
            red_bytes: self.counters.red.bytes.load(Ordering::Relaxed),
            drop_packets: self.counters.drop.packets.load(Ordering::Relaxed),
            drop_bytes: self.counters.drop.bytes.load(Ordering::Relaxed),
        }
    }
}

impl FilterTermCounter {
    pub(crate) fn record(&self, packet_bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_bytes, Ordering::Relaxed);
    }
}

#[cfg(not(test))]
#[derive(Default)]
struct PendingFilterCounterRecord {
    counter: Option<Arc<FilterTermCounter>>,
    packets: u64,
    bytes: u64,
}

#[cfg(not(test))]
const FILTER_COUNTER_FLUSH_PACKETS: u64 = 64;

#[cfg(not(test))]
thread_local! {
    static PENDING_FILTER_COUNTER_RECORD: RefCell<PendingFilterCounterRecord> =
        RefCell::new(PendingFilterCounterRecord::default());
}

#[cfg(not(test))]
#[inline(always)]
fn flush_pending_filter_counter_record(record: &mut PendingFilterCounterRecord) {
    let Some(counter) = record.counter.take() else {
        return;
    };
    counter.packets.fetch_add(record.packets, Ordering::Relaxed);
    counter.bytes.fetch_add(record.bytes, Ordering::Relaxed);
    record.packets = 0;
    record.bytes = 0;
}

#[cfg(not(test))]
#[inline(always)]
pub(crate) fn record_filter_counter(counter: &Arc<FilterTermCounter>, packet_bytes: u64) {
    PENDING_FILTER_COUNTER_RECORD.with(|pending| {
        let mut pending = pending.borrow_mut();
        if pending
            .counter
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, counter))
        {
            pending.packets = pending.packets.saturating_add(1);
            pending.bytes = pending.bytes.saturating_add(packet_bytes);
        } else {
            flush_pending_filter_counter_record(&mut pending);
            pending.counter = Some(counter.clone());
            pending.packets = 1;
            pending.bytes = packet_bytes;
        }
        if pending.packets >= FILTER_COUNTER_FLUSH_PACKETS {
            flush_pending_filter_counter_record(&mut pending);
        }
    });
}

#[cfg(test)]
#[inline(always)]
pub(crate) fn record_filter_counter(counter: &Arc<FilterTermCounter>, packet_bytes: u64) {
    counter.record(packet_bytes);
}

#[cfg(not(test))]
pub(crate) fn flush_recorded_filter_counters() {
    PENDING_FILTER_COUNTER_RECORD.with(|pending| {
        flush_pending_filter_counter_record(&mut pending.borrow_mut());
    });
}

#[cfg(test)]
pub(crate) fn flush_recorded_filter_counters() {}

// #1049 P2: structural split — engine, compiler, and policer extracted
// into sibling submodules. mod.rs hosts the shared type vocabulary,
// constants, and counter-flush helpers; the submodules import them via
// `use super::*;`.
mod compiler;
mod engine;
mod policer;

// Glob re-exports surface the `pub(crate) fn`/`pub(crate) struct` items from
// each submodule. Private helpers inside compiler/engine stay invisible
// because the glob only re-exports `pub`-visible items.
pub(crate) use compiler::*;
pub(crate) use engine::*;
pub(crate) use policer::*;
/// Aggregate filter state: all compiled filters and policers.
#[derive(Clone, Debug, Default)]
pub(crate) struct FilterState {
    /// Named filters keyed by "family:name" (e.g. "inet:protect-RE").
    pub(crate) filters: rustc_hash::FxHashMap<String, Arc<Filter>>,
    /// Named policer states keyed by policer name.
    pub(crate) policers: rustc_hash::FxHashMap<String, PolicerState>,
    /// Stable three-color policer runtimes keyed by policer name.
    pub(crate) three_color_policer_by_name:
        rustc_hash::FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
    /// Stable ID-indexed three-color policer runtimes.
    pub(crate) three_color_policers: Vec<Arc<ThreeColorPolicerRuntime>>,
    /// Per-interface (ifindex) input filter key for inet.
    pub(crate) iface_filter_v4: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet input filters that can affect CoS TX selection.
    pub(crate) iface_filter_v4_affects_tx_selection: rustc_hash::FxHashSet<i32>,
    /// Whether any inet input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v4: bool,
    /// Whether any inet input filter contains a three-color policer.
    pub(crate) has_input_three_color_policer_v4: bool,
    /// Per-interface inet input filters that can affect route-table selection.
    pub(crate) iface_filter_v4_affects_route_lookup: rustc_hash::FxHashSet<i32>,
    /// Per-interface (ifindex) input filter key for inet6.
    pub(crate) iface_filter_v6: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet6 filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet6 input filters that can affect CoS TX selection.
    pub(crate) iface_filter_v6_affects_tx_selection: rustc_hash::FxHashSet<i32>,
    /// Whether any inet6 input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v6: bool,
    /// Whether any inet6 input filter contains a three-color policer.
    pub(crate) has_input_three_color_policer_v6: bool,
    /// Per-interface inet6 input filters that can affect route-table selection.
    pub(crate) iface_filter_v6_affects_route_lookup: rustc_hash::FxHashSet<i32>,
    /// Per-interface (ifindex) output filter key for inet.
    pub(crate) iface_filter_out_v4: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet output filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_out_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet output filters that must still be evaluated in the TX path.
    pub(crate) iface_filter_out_v4_needs_tx_eval: rustc_hash::FxHashSet<i32>,
    /// Whether any inet output filter can affect CoS TX selection.
    pub(crate) has_output_tx_selection_v4: bool,
    /// Per-interface (ifindex) output filter key for inet6.
    pub(crate) iface_filter_out_v6: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet6 output filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_out_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet6 output filters that must still be evaluated in the TX path.
    pub(crate) iface_filter_out_v6_needs_tx_eval: rustc_hash::FxHashSet<i32>,
    /// Whether any inet6 output filter can affect CoS TX selection.
    pub(crate) has_output_tx_selection_v6: bool,
    /// lo0 inet input filter key.
    pub(crate) lo0_filter_v4: String,
    /// Direct lo0 inet filter reference for packet hot-path evaluation.
    pub(crate) lo0_filter_v4_fast: Option<Arc<Filter>>,
    /// lo0 inet6 input filter key.
    pub(crate) lo0_filter_v6: String,
    /// Direct lo0 inet6 filter reference for packet hot-path evaluation.
    pub(crate) lo0_filter_v6_fast: Option<Arc<Filter>>,
}

impl FilterState {
    pub(crate) fn three_color_policer_statuses(
        &self,
    ) -> Vec<crate::protocol::ThreeColorPolicerStatus> {
        let mut statuses = self
            .three_color_policers
            .iter()
            .map(|policer| policer.status())
            .collect::<Vec<_>>();
        statuses.sort_by_key(|status| status.id);
        statuses
    }
}

/// Result of filter evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FilterResult {
    pub(crate) action: FilterAction,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) policer_name: String,
    pub(crate) routing_instance: String,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) log: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TxSelectionFilterResult<'a> {
    pub(crate) forwarding_class: Option<&'a str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) policer_drop: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CachedTxSelectionFilterResult {
    pub(crate) forwarding_class: Option<Arc<str>>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) counter: Option<Arc<FilterTermCounter>>,
    pub(crate) three_color_policers: CachedThreeColorPolicers,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreeColorPolicerAction {
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

impl Default for FilterResult {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            dscp_rewrite: None,
            policer_name: String::new(),
            routing_instance: String::new(),
            forwarding_class: Arc::<str>::from(""),
            log: false,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
