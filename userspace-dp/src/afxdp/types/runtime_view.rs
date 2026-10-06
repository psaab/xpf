//! #6592: the atomically-paired worker-visible runtime view.
//!
//! # Why this type exists
//!
//! Validation (`config_generation` / `fib_generation`, the values
//! `classify_metadata` matches a packet's shim stamp against) and the
//! `ForwardingState` (the policy/FIB/NAT tables a `Valid` packet is then
//! forwarded under) used to be published through TWO independent `ArcSwap`s.
//! A worker refreshing its per-tick view performed two separate acquire-loads,
//! so a coordinator publish landing between them left the worker holding one
//! half from generation N and the other from N-1 — a TORN pair. Both
//! orientations were reachable and both are unsafe:
//!
//! - `(old validation, new forwarding)` — a packet stamped at the OLD
//!   generation matches the worker's old validation, classifies `Valid`, and
//!   is then forwarded under the NEW tables. (#6291.)
//! - `(new validation, old forwarding)` — once the coordinator's reply reaches
//!   Go and Go writes the new generation into `userspace_ctrl`, the shim stamps
//!   NEW. Those packets match the worker's new validation, classify `Valid`,
//!   and are forwarded under the STALE tables — a withdrawn route still
//!   resolves, a newly added deny is not applied. (#6592, the mirror.)
//!
//! Reordering the two loads can only ever exclude ONE orientation (the
//! producer and consumer must run in opposite orders for an acquire/release
//! pair, which is exactly one of the two). Closing BOTH needs the two values to
//! travel in ONE `Arc`, which is this type: a worker's refresh is a single
//! `ArcSwap` load, and whichever `RuntimeView` it observes, `validation` and
//! `forwarding` came from the same publish. There is no pair to tear.
//!
//! Holding an OLD view is still possible and is still SAFE — that is the
//! intended fail-closed behaviour. A worker that has not refreshed matches
//! new-stamped packets against old validation, they mismatch, and they DROP.
//! The defect this type closes is specifically an INCOHERENT pair, not a stale
//! coherent one; nothing here forces a refresh.
//!
//! # Why `forwarding` is a nested `Arc`, not an inlined field
//!
//! The obvious alternative — make `ValidationState` a field of
//! `ForwardingState` — is structurally simpler but breaks the #1188 worker
//! short-circuit. `Coordinator::bump_fib_generation` advances validation with
//! NO forwarding rebuild (that is its entire purpose: Go's
//! `Manager.BumpFIBGeneration` fires repeatedly during route convergence
//! precisely to avoid the full `buildSnapshot()` + `apply_snapshot` round
//! trip). Inlining would force a full `ForwardingState` clone — 69 fields, ~20
//! heap-owning collections including the FIB — per bump on the coordinator,
//! and on every worker would rotate the forwarding `Arc`, taking the expensive
//! rotation branch (screen-profile + opening-override clones, cold-path slot
//! rescan, input-filter session purges, CoS runtime reset) for a change that
//! touched neither policy nor FIB tables.
//!
//! With the nested `Arc`, a validation-only publish allocates one small
//! `RuntimeView` and REUSES the inner forwarding `Arc`. The worker's
//! `Arc::ptr_eq` short-circuit still hits, so #1188 is preserved exactly.
//!
//! # Publish ordering is unchanged
//!
//! The `RuntimeView` store sits exactly where the `ha.forwarding` store sat: it
//! is still THE single worker-visible release gate, and #5166 still holds —
//! the CoS owner/live/lease/backlog/vtime maps and `ha.fabrics` are stored
//! BEFORE it, and the worker reads them AFTER its view load.
use super::*;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;


/// The worker-visible `(validation, forwarding)` pair, published as ONE
/// `Arc` so the two can never be observed from different generations.
///
/// # Immutable and non-`Clone` on purpose
///
/// The fields are PRIVATE to this module and the type deliberately does NOT
/// implement `Clone`. That is the language-level half of the invariant, and it
/// exists because a review probe defeated the earlier source-canary version:
///
/// ```ignore
/// let mut torn = channel.load_full().as_ref().clone();
/// torn.validation.fib_generation = torn.validation.fib_generation.wrapping_add(1);
/// channel.store(Arc::new(torn));      // published a torn pair
/// ```
///
/// That compiled, published exactly the `(new validation, old forwarding)`
/// tear, and every textual canary rule passed — the store was not the choke
/// point's literal spelling, and the value came from a CLONE rather than a
/// construction, so "a publish needs a constructed view" was simply false.
///
/// With private fields the mutation line does not compile, and without `Clone`
/// the clone line does not compile. [`RuntimeView::new`] becomes the only way
/// to obtain a view value anywhere in the tree, which is what makes the
/// canary's construction rule a true statement rather than an enumeration of
/// the spellings someone happened to think of.
///
/// Cheap to publish: `ValidationState` is `Copy` and `forwarding` is an `Arc`
/// refcount bump, so a view reusing the current forwarding costs one small
/// allocation and no table copying.
/// A per-generation P-MECH tunnel row. It is stored inside the immutable
/// `RuntimeView`, not beside it, so a D13 worker cannot accidentally pair
/// generation-N tunnel identity with generation-(N+1) forwarding/zone maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct IpsecTunnelRow {
    pub(in crate::afxdp) stn: String,
    pub(in crate::afxdp) if_id: u32,
    pub(in crate::afxdp) logical_ifindex: i32,
}

/// Immutable exact-STN tunnel-row set published as part of one RuntimeView.
/// Duplicate STNs and duplicate if_id claims are tracked per claimant:
/// unrelated rows remain usable while every ambiguous claimant resolves to
/// `None` at D14.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct IpsecTunnelRows {
    rows: BTreeMap<String, IpsecTunnelRow>,
    duplicate_stns: BTreeSet<String>,
    ambiguous_if_ids: BTreeSet<u32>,
}

impl IpsecTunnelRows {
    pub(in crate::afxdp) fn new(rows: impl IntoIterator<Item = IpsecTunnelRow>) -> Self {
        let mut out = Self::default();
        let mut if_id_claims: BTreeMap<u32, usize> = BTreeMap::new();
        for row in rows {
            if row.stn.is_empty() || row.if_id == 0 || row.logical_ifindex <= 0 {
                continue;
            }
            *if_id_claims.entry(row.if_id).or_default() += 1;
            let stn = row.stn.clone();
            if out.rows.insert(stn.clone(), row).is_some() {
                out.duplicate_stns.insert(stn);
            }
        }
        for (if_id, count) in if_id_claims {
            if count > 1 {
                out.ambiguous_if_ids.insert(if_id);
            }
        }
        out
    }

    #[inline]
    pub(in crate::afxdp) fn exact(&self, stn: &str) -> Option<&IpsecTunnelRow> {
        let row = self.rows.get(stn)?;
        if self.duplicate_stns.contains(stn) || self.ambiguous_if_ids.contains(&row.if_id) {
            None
        } else {
            Some(row)
        }
    }

    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(in crate::afxdp) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Rows are immutable after construction; this accessor is only for
    /// snapshot/control tests that need to inspect the published set.
    pub(in crate::afxdp) fn duplicate(&self) -> bool {
        !self.duplicate_stns.is_empty() || !self.ambiguous_if_ids.is_empty()
    }
}

/// One strict, immutable inventory of the forwarding inputs used to bound
/// P-MECH ingress. Raw selector projections and route rows remain attached to
/// the same worker view as the compiled ingress prefixes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct PMechInventory {
    policy_identity: [u8; 32],
    generation: u64,
    fib_generation: u32,
    complete: bool,
    main_routes: Vec<crate::protocol::IpsecMainRouteSnapshot>,
    tunnels: BTreeMap<String, PMechTunnelRow>,
    duplicate_stns: BTreeSet<String>,
    ambiguous_if_ids: BTreeSet<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct PMechTunnelRow {
    stn: String,
    if_id: u32,
    logical_ifindex: i32,
    explicit_selectors: Vec<crate::protocol::IpsecTrafficSelectorSnapshot>,
    effective_prefixes: Vec<String>,
    ingress_prefixes: Vec<IpNet>,
    inventory_generation: u64,
    fib_generation: u32,
    source_kind: String,
    selector_provenance: String,
    inventory_complete: bool,
    inventory_valid: bool,
    inventory_reason: String,
}

impl PMechInventory {
    pub(in crate::afxdp) fn from_snapshot(
        snapshot: Option<&crate::protocol::IpsecPMechInventorySnapshot>,
    ) -> Self {
        let Some(snapshot) = snapshot else {
            return Self::default();
        };
        let identity = decode_policy_identity(&snapshot.policy_identity);
        let routes_valid = main_routes_valid(&snapshot.main_routes);
        let mut out = Self {
            policy_identity: identity.unwrap_or_default(),
            generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
            complete: snapshot.complete
                && !snapshot.main_routes.is_empty()
                && identity.is_some()
                && snapshot.generation != 0
                && snapshot.fib_generation != 0
                && routes_valid,
            main_routes: snapshot.main_routes.clone(),
            ..Self::default()
        };
        let mut if_id_claims = BTreeMap::<u32, usize>::new();
        for row in &snapshot.tunnel_rows {
            let effective_prefixes = row.effective_prefixes.clone();
            let (effective_parsed, effective_valid) =
                parse_canonical_prefixes(&row.effective_prefixes);
            let (ingress_prefixes, prefixes_valid) = parse_canonical_prefixes(&row.ingress_prefixes);
            let recomputed_projection =
                recompute_selector_projection(&snapshot.main_routes, row);
            let projection_valid = routes_valid
                && recomputed_projection.as_ref().is_some_and(|projection| {
                    effective_valid
                        && prefixes_valid
                        && canonical_prefix_strings(&effective_parsed).eq(projection)
                        && canonical_prefix_strings(&ingress_prefixes).eq(projection)
                });
            let inventory_reason = if routes_valid && !projection_valid {
                "SELECTOR_PROJECTION_MISMATCH".to_string()
            } else {
                row.inventory_reason.clone()
            };
            let row_valid = out.complete
                && row.inventory_complete
                && row.inventory_valid
                && row.if_id != 0
                && row.logical_ifindex > 0
                && row.inventory_generation == out.generation
                && row.fib_generation == out.fib_generation
                && !row.stn.is_empty()
                && !row.explicit_selectors.is_empty()
                && !effective_prefixes.is_empty()
                && row.source_kind == "xfrmi"
                && !row.selector_provenance.is_empty()
                && row.inventory_reason.is_empty()
                && effective_valid
                && projection_valid
                && prefixes_valid
                && !ingress_prefixes.is_empty();
            if row.if_id != 0 {
                *if_id_claims.entry(row.if_id).or_default() += 1;
            }
            let tunnel = PMechTunnelRow {
                stn: row.stn.clone(),
                if_id: row.if_id,
                logical_ifindex: row.logical_ifindex,
                explicit_selectors: row.explicit_selectors.clone(),
                effective_prefixes,
                ingress_prefixes,
                inventory_generation: row.inventory_generation,
                fib_generation: row.fib_generation,
                source_kind: row.source_kind.clone(),
                selector_provenance: row.selector_provenance.clone(),
                inventory_complete: row.inventory_complete,
                inventory_valid: row_valid,
                inventory_reason,
            };
            if out.tunnels.insert(row.stn.clone(), tunnel).is_some() {
                out.duplicate_stns.insert(row.stn.clone());
            }
        }
        out.ambiguous_if_ids.extend(
            if_id_claims
                .into_iter()
                .filter_map(|(if_id, claims)| (claims > 1).then_some(if_id)),
        );
        out
    }

    pub(in crate::afxdp) fn generation(&self) -> u64 {
        self.generation
    }

    pub(in crate::afxdp) fn fib_generation(&self) -> u32 {
        self.fib_generation
    }

    pub(in crate::afxdp) fn complete(&self) -> bool {
        self.complete
    }

    pub(in crate::afxdp) fn policy_identity(&self) -> [u8; 32] {
        self.policy_identity
    }

    pub(in crate::afxdp) fn matches_policy_identity(&self, identity: &[u8; 32]) -> bool {
        self.complete && &self.policy_identity == identity
    }

    pub(in crate::afxdp) fn exact_tunnel(
        &self,
        stn: &str,
        if_id: u32,
        logical_ifindex: i32,
    ) -> Option<&PMechTunnelRow> {
        if !self.complete
            || self.duplicate_stns.contains(stn)
            || self.ambiguous_if_ids.contains(&if_id)
        {
            return None;
        }
        let row = self.tunnels.get(stn)?;
        (row.stn == stn
            && row.inventory_valid
            && row.inventory_complete
            && row.if_id == if_id
            && row.logical_ifindex == logical_ifindex
            && row.inventory_generation == self.generation
            && row.fib_generation == self.fib_generation)
            .then_some(row)
    }

    pub(in crate::afxdp) fn has_main_table_routes(&self) -> bool {
        self.complete
            && !self.main_routes.is_empty()
            && self
                .main_routes
                .iter()
                .all(|route| route.domain == 0 && route.table == 254)
    }
}

impl PMechTunnelRow {
    pub(in crate::afxdp) fn allows_source(&self, source: IpAddr) -> bool {
        self.ingress_prefixes
            .iter()
            .any(|prefix| prefix.contains(&source))
    }

    pub(in crate::afxdp) fn selector_projection(
        &self,
    ) -> (&[crate::protocol::IpsecTrafficSelectorSnapshot], &[String]) {
        (&self.explicit_selectors, &self.effective_prefixes)
    }
}
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;

fn main_routes_valid(
    routes: &[crate::protocol::IpsecMainRouteSnapshot],
) -> bool {
    let prefixes = routes
        .iter()
        .map(main_route_prefix)
        .collect::<Option<Vec<_>>>();
    let Some(prefixes) = prefixes else {
        return false;
    };
    for (index, prefix) in prefixes.iter().enumerate() {
        for other_index in index + 1..prefixes.len() {
            if prefix == &prefixes[other_index]
                && !same_route_projection(&routes[index], &routes[other_index])
            {
                return false;
            }
        }
    }
    true
}

fn main_route_prefix(route: &crate::protocol::IpsecMainRouteSnapshot) -> Option<IpNet> {
    if route.domain != 0 || route.table != 254 {
        return None;
    }
    let known_disposition = matches!(
        route.disposition,
        RTN_UNICAST | RTN_LOCAL | RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT
    );
    if !known_disposition
        || route.next_hops.iter().any(|hop| hop.ifindex == 0 || hop.weight == 0)
        || (route.disposition == RTN_UNICAST && route.next_hops.is_empty())
    {
        return None;
    }
    let prefix = IpNet::from_str(&route.destination).ok()?.trunc();
    if prefix.to_string() != route.destination
        || (route.family == "inet" && !matches!(prefix, IpNet::V4(_)))
        || (route.family == "inet6" && !matches!(prefix, IpNet::V6(_)))
        || !matches!(route.family.as_str(), "inet" | "inet6")
    {
        return None;
    }
    Some(prefix)
}

fn same_route_projection(
    left: &crate::protocol::IpsecMainRouteSnapshot,
    right: &crate::protocol::IpsecMainRouteSnapshot,
) -> bool {
    if left.domain != right.domain
        || left.table != right.table
        || left.family != right.family
        || left.destination != right.destination
        || left.protocol != right.protocol
        || left.disposition != right.disposition
    {
        return false;
    }
    let mut left_legs = left
        .next_hops
        .iter()
        .map(|hop| (hop.ifindex, hop.weight))
        .collect::<Vec<_>>();
    let mut right_legs = right
        .next_hops
        .iter()
        .map(|hop| (hop.ifindex, hop.weight))
        .collect::<Vec<_>>();
    left_legs.sort_unstable();
    right_legs.sort_unstable();
    left_legs == right_legs
}

fn recompute_selector_projection(
    routes: &[crate::protocol::IpsecMainRouteSnapshot],
    tunnel: &crate::protocol::IpsecPMechTunnelRowSnapshot,
) -> Option<BTreeSet<String>> {
    let route_prefixes = routes
        .iter()
        .map(main_route_prefix)
        .collect::<Option<Vec<_>>>()?;
    let mut projection = BTreeSet::new();
    for (route_index, route) in routes.iter().enumerate() {
        if route.disposition != RTN_UNICAST {
            continue;
        }
        for hop in &route.next_hops {
            if hop.ifindex != tunnel.logical_ifindex as u32 {
                continue;
            }
            let eligible = route_prefixes_for_leg(route_index, hop.ifindex, routes, &route_prefixes);
            for selector in &tunnel.explicit_selectors {
                if selector.remote_ts.is_empty() {
                    continue;
                }
                let selectors = selector_prefixes(&selector.remote_ts)?;
                for route_prefix in &eligible {
                    for selector_prefix in &selectors {
                        if let Some(intersection) = intersect_prefixes(route_prefix, selector_prefix)
                        {
                            projection.insert(intersection.to_string());
                        }
                    }
                }
            }
        }
    }
    Some(projection)
}

fn route_prefixes_for_leg(
    route_index: usize,
    ifindex: u32,
    routes: &[crate::protocol::IpsecMainRouteSnapshot],
    route_prefixes: &[IpNet],
) -> Vec<IpNet> {
    let base = route_prefixes[route_index];
    let mut prefixes = vec![base];
    for (blocker_index, blocker) in routes.iter().enumerate() {
        let blocker_prefix = route_prefixes[blocker_index];
        if blocker_prefix.prefix_len() <= base.prefix_len()
            || !base.contains(&blocker_prefix.network())
        {
            continue;
        }
        let keeps_leg = blocker.disposition == RTN_UNICAST
            && blocker.next_hops.iter().any(|hop| hop.ifindex == ifindex);
        if !keeps_leg {
            prefixes = subtract_prefix_set(prefixes, blocker_prefix);
            if prefixes.is_empty() {
                break;
            }
        }
    }
    prefixes
}

fn subtract_prefix_set(prefixes: Vec<IpNet>, excluded: IpNet) -> Vec<IpNet> {
    let mut result = Vec::with_capacity(prefixes.len());
    for prefix in prefixes {
        subtract_prefix(prefix, excluded, &mut result);
    }
    result
}

fn subtract_prefix(prefix: IpNet, excluded: IpNet, output: &mut Vec<IpNet>) {
    let overlaps = prefix.contains(&excluded.network()) || excluded.contains(&prefix.network());
    if !overlaps {
        output.push(prefix);
        return;
    }
    if excluded.prefix_len() <= prefix.prefix_len()
        && excluded.contains(&prefix.network())
    {
        return;
    }
    let Some((left, right)) = split_prefix(prefix) else {
        return;
    };
    subtract_prefix(left, excluded, output);
    subtract_prefix(right, excluded, output);
}

fn split_prefix(prefix: IpNet) -> Option<(IpNet, IpNet)> {
    let prefix_len = prefix.prefix_len();
    let address = prefix.network();
    let width = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len >= width {
        return None;
    }
    let left = IpNet::new(address, prefix_len + 1).ok()?;
    let value = match address {
        IpAddr::V4(address) => u32::from(address) as u128,
        IpAddr::V6(address) => u128::from(address),
    };
    let right_value = value | (1u128 << (width - prefix_len - 1));
    let right_address = address_from_value(right_value, width);
    Some((left, IpNet::new(right_address, prefix_len + 1).ok()?))
}

fn intersect_prefixes(left: &IpNet, right: &IpNet) -> Option<IpNet> {
    let left_v4 = matches!(left, IpNet::V4(_));
    if left_v4 != matches!(right, IpNet::V4(_)) {
        return None;
    }
    if !left.contains(&right.network()) && !right.contains(&left.network()) {
        return None;
    }
    Some(if left.prefix_len() >= right.prefix_len() {
        *left
    } else {
        *right
    })
}

fn selector_prefixes(value: &str) -> Option<Vec<IpNet>> {
    if let Ok(prefix) = IpNet::from_str(value) {
        return Some(vec![prefix.trunc()]);
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(vec![IpNet::new(address, address_width(address)).ok()?]);
    }
    let (start, end) = value.split_once('-')?;
    let start = start.parse::<IpAddr>().ok()?;
    let end = end.parse::<IpAddr>().ok()?;
    if !same_address_family(start, end) || start > end {
        return None;
    }
    Some(address_range_prefixes(start, end))
}

fn address_width(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn address_to_value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u32::from(address) as u128,
        IpAddr::V6(address) => u128::from(address),
    }
}
fn address_from_value(value: u128, width: u8) -> IpAddr {
    if width == 32 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

fn address_range_prefixes(start: IpAddr, end: IpAddr) -> Vec<IpNet> {
    let width = address_width(start);
    let start = address_to_value(start);
    let end = address_to_value(end);
    let mut current = start;
    let mut prefixes = Vec::new();
    while current <= end {
        let alignment = current.trailing_zeros().min(u32::from(width)) as u8;
        let difference = end - current;
        let fit = if difference == u128::MAX {
            width
        } else {
            let count = difference + 1;
            (127 - count.leading_zeros()) as u8
        };
        let exponent = alignment.min(fit);
        let prefix_len = width - exponent;
        if let Some(prefix) = IpNet::new(address_from_value(current, width), prefix_len).ok() {
            prefixes.push(prefix.trunc());
        }
        if exponent == width {
            break;
        }
        let Some(next) = current.checked_add(1u128 << exponent) else {
            break;
        };
        current = next;
    }
    prefixes
}

fn canonical_prefix_strings(prefixes: &[IpNet]) -> BTreeSet<String> {
    prefixes.iter().map(ToString::to_string).collect()
}

fn decode_policy_identity(value: &str) -> Option<[u8; 32]> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn parse_canonical_prefixes(values: &[String]) -> (Vec<IpNet>, bool) {
    let mut prefixes = Vec::with_capacity(values.len());
    let mut valid = true;
    for value in values {
        match IpNet::from_str(value) {
            Ok(prefix) if prefix.trunc().to_string() == value.as_str() => {
                prefixes.push(prefix.trunc())
            }
            _ => valid = false,
        }
    }
    (prefixes, valid)
}

/// Number of admitted P-MECH tunnels and exact rows are part of the same
/// immutable runtime binding as `ForwardingState`.
///
/// The normal two-argument `RuntimeView::new` keeps existing non-P-MECH
/// consumers compatible by publishing an empty row set; P-MECH control
/// publication uses `new_with_ipsec_tunnel_rows` below.
#[derive(Debug)]
pub(in crate::afxdp) struct IpsecRuntimeBinding {
    rows: Arc<IpsecTunnelRows>,
    /// Authoritative generation of the tunnel-row/admit contract. It is
    /// published with the same RuntimeView as forwarding + validation; zero is
    /// unavailable and therefore E28, never "current".
    snapshot_generation: u64,
    pmech_inventory: Arc<PMechInventory>,
    runtime_view_publication_generation: u64,
}

impl Default for IpsecRuntimeBinding {
    fn default() -> Self {
        Self {
            rows: Arc::new(IpsecTunnelRows::default()),
            snapshot_generation: 0,
            pmech_inventory: Arc::new(PMechInventory::default()),
            runtime_view_publication_generation: 0,
        }
    }
}

impl IpsecRuntimeBinding {
    pub(in crate::afxdp) fn new(
        rows: Arc<IpsecTunnelRows>,
        snapshot_generation: u64,
        pmech_inventory: Arc<PMechInventory>,
        runtime_view_publication_generation: u64,
    ) -> Self {
        Self {
            rows,
            snapshot_generation,
            pmech_inventory,
            runtime_view_publication_generation,
        }
    }

    #[inline]
    pub(in crate::afxdp) fn rows(&self) -> &IpsecTunnelRows {
        &self.rows
    }

    #[inline]
    pub(in crate::afxdp) fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    #[inline]
    pub(in crate::afxdp) fn pmech_inventory(&self) -> &PMechInventory {
        &self.pmech_inventory
    }

    #[inline]
    pub(in crate::afxdp) fn runtime_view_publication_generation(&self) -> u64 {
        self.runtime_view_publication_generation
    }
}

#[derive(Debug)]
pub(in crate::afxdp) struct RuntimeView {
    /// Generation stamps a packet's shim metadata is matched against
    /// (`classify_metadata`).
    validation: ValidationState,
    /// The policy / FIB / NAT tables a `Valid` packet is forwarded under.
    forwarding: Arc<ForwardingState>,
    /// P-MECH tunnel identity rows are atomically paired with the forwarding
    /// maps and validation generations. D13 receives this through the same
    /// immutable view binding and never accepts a caller-supplied side table.
    ipsec: IpsecRuntimeBinding,
}

impl Default for RuntimeView {
    fn default() -> Self {
        Self {
            validation: ValidationState::default(),
            forwarding: Arc::new(ForwardingState::default()),
            ipsec: IpsecRuntimeBinding::default(),
        }
    }
}

impl RuntimeView {
    /// Build a view pairing `validation` with an already-published forwarding
    /// `Arc` (refcount bump, no table copy). Non-P-MECH callers publish the
    /// empty row set; P-MECH uses the explicit constructor below.
    pub(in crate::afxdp) fn new(
        validation: ValidationState,
        forwarding: Arc<ForwardingState>,
    ) -> Self {
        Self {
            validation,
            forwarding,
            ipsec: IpsecRuntimeBinding::default(),
        }
    }

    /// Build a P-MECH view with tunnel rows as part of the SAME immutable
    /// binding. There is no API to construct a D13 invocation from two
    /// independently loaded views.
    pub(in crate::afxdp) fn new_with_ipsec_tunnel_rows(
        validation: ValidationState,
        forwarding: Arc<ForwardingState>,
        rows: Arc<IpsecTunnelRows>,
        snapshot_generation: u64,
    ) -> Self {
        Self::new_with_ipsec_authority(
            validation,
            forwarding,
            rows,
            snapshot_generation,
            Arc::new(PMechInventory::default()),
            0,
        )
    }

    pub(in crate::afxdp) fn new_with_ipsec_authority(
        validation: ValidationState,
        forwarding: Arc<ForwardingState>,
        rows: Arc<IpsecTunnelRows>,
        snapshot_generation: u64,
        pmech_inventory: Arc<PMechInventory>,
        runtime_view_publication_generation: u64,
    ) -> Self {
        let pmech_inventory = if forwarding.route_table_identity_map_complete {
            pmech_inventory
        } else {
            let mut unavailable = (*pmech_inventory).clone();
            unavailable.complete = false;
            Arc::new(unavailable)
        };
        Self {
            validation,
            forwarding,
            ipsec: IpsecRuntimeBinding::new(
                rows,
                snapshot_generation,
                pmech_inventory,
                runtime_view_publication_generation,
            ),
        }
    }
    /// The generation stamps half. `Copy`, so a caller gets a value it cannot
    /// write back.
    #[inline]
    pub(in crate::afxdp) fn validation(&self) -> ValidationState {
        self.validation
    }

    /// The forwarding half, by reference. A caller may clone the `Arc` (that is
    /// how a worker adopts it) but cannot swap this view's field.
    #[inline]
    pub(in crate::afxdp) fn forwarding(&self) -> &Arc<ForwardingState> {
        &self.forwarding
    }

    /// The exact tunnel-row set paired with this view.
    #[inline]
    pub(in crate::afxdp) fn ipsec_tunnel_rows(&self) -> &IpsecTunnelRows {
        self.ipsec.rows()
    }

    #[inline]
    pub(in crate::afxdp) fn pmech_inventory(&self) -> &PMechInventory {
        self.ipsec.pmech_inventory()
    }

    #[inline]
    pub(in crate::afxdp) fn runtime_view_publication_generation(&self) -> u64 {
        self.ipsec.runtime_view_publication_generation()
    }
    /// Authoritative tunnel-row generation paired with this view.
    #[inline]
    pub(in crate::afxdp) fn ipsec_snapshot_generation(&self) -> u64 {
        self.ipsec.snapshot_generation()
    }

    #[inline]
    pub(in crate::afxdp) fn ipsec_tunnel_rows_arc(&self) -> Arc<IpsecTunnelRows> {
        self.ipsec.rows.clone()
    }
}


/// The WRITE side of the runtime-view channel — the coordinator's handle.
///
/// Wraps the `ArcSwap` with a PRIVATE field and exposes exactly three
/// operations. Nothing hands out the `ArcSwap` itself, so `swap`, `rcu`,
/// `compare_and_swap`, `Deref` and every other mutation route `ArcSwap`
/// provides are simply not reachable — [`RuntimeViewChannel::publish`] is the
/// only way to change what workers see. That closes the "enumerate the
/// mutation spellings" failure mode a textual canary cannot.
pub(in crate::afxdp) struct RuntimeViewChannel {
    inner: Arc<ArcSwap<RuntimeView>>,
}

impl Default for RuntimeViewChannel {
    fn default() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(RuntimeView::default())),
        }
    }
}

impl RuntimeViewChannel {
    /// Hand a READ-ONLY handle to a worker or aux thread. The returned type
    /// cannot publish, so no consumer can become a writer by aliasing.
    pub(in crate::afxdp) fn reader(&self) -> RuntimeViewReader {
        RuntimeViewReader {
            inner: self.inner.clone(),
        }
    }

    /// Acquire-load the current view (coordinator side).
    #[inline]
    pub(in crate::afxdp) fn load(&self) -> arc_swap::Guard<Arc<RuntimeView>> {
        self.inner.load()
    }

    /// Acquire-load and retain the current view (the `#[cfg(test)]` publish
    /// seam keeps the previous view alive with this, so `Arc::ptr_eq` cannot be
    /// fooled by a freed allocation being reused).
    pub(in crate::afxdp) fn load_full(&self) -> Arc<RuntimeView> {
        self.inner.load_full()
    }

    /// Make `view` worker-visible. THE single mutation on this channel; the
    /// coordinator funnels every publish through
    /// `Coordinator::store_runtime_view` so the view is always built from
    /// `self.validation` at the store.
    pub(in crate::afxdp) fn publish(&self, view: Arc<RuntimeView>) {
        self.inner.store(view);
    }
}

/// The READ side of the runtime-view channel — what workers, the GRE
/// local-origin threads, and every other consumer hold.
///
/// The `ArcSwap` is a private field and the only method is [`load`]. There is
/// no `Deref`, no accessor returning the `ArcSwap`, and no publish method, so a
/// consumer cannot obtain a writer at all — the earlier
/// `runtime_reader() -> Arc<ArcSwap<RuntimeView>>` handed one out and a review
/// probe used exactly that to publish a torn pair from `refresh_fabric_links`.
///
/// [`load`]: RuntimeViewReader::load
#[derive(Clone)]
pub(in crate::afxdp) struct RuntimeViewReader {
    inner: Arc<ArcSwap<RuntimeView>>,
}

impl RuntimeViewReader {
    /// THE single-load primitive. Both halves of the pair must come out of one
    /// call: two loads in a tick can observe two different views and pair
    /// halves across generations, which is the defect #6592 closed.
    #[inline]
    pub(in crate::afxdp) fn load(&self) -> arc_swap::Guard<Arc<RuntimeView>> {
        self.inner.load()
    }

    /// Do two handles address the SAME channel? For the launch-wiring test
    /// only — it replaces an `Arc::ptr_eq` on the formerly-exposed `ArcSwap`.
    pub(in crate::afxdp) fn same_channel(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

/// #1188 short-circuit over a [`RuntimeViewReader`] for readers that need ONLY
/// the forwarding half (the GRE local-origin / WG control threads).
///
/// Returns `Some(new_arc)` when the published forwarding `Arc` differs from
/// `cached`, `None` when it is the same allocation. A validation-only publish
/// rotates the view but NOT the inner forwarding `Arc`, so such readers
/// correctly see no change.
#[inline]
pub(in crate::afxdp) fn load_forwarding_if_changed(
    cached: &Arc<ForwardingState>,
    shared_runtime: &RuntimeViewReader,
) -> Option<Arc<ForwardingState>> {
    let view = shared_runtime.load();
    if Arc::ptr_eq(cached, view.forwarding()) {
        None
    } else {
        Some(view.forwarding().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_only_view_reuses_published_ipsec_rows() {
        let rows = Arc::new(IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 9,
            logical_ifindex: 10,
        }]));
        let forwarding = Arc::new(ForwardingState::default());
        let first = RuntimeView::new_with_ipsec_tunnel_rows( // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 7,
                fib_generation: 3,
            },
            forwarding,
            rows,
            7,
        );
        let second = RuntimeView::new_with_ipsec_tunnel_rows( // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 7,
                fib_generation: 4,
            },
            first.forwarding().clone(),
            first.ipsec_tunnel_rows_arc(),
            first.ipsec_snapshot_generation(),
        );
        assert_eq!(second.ipsec_snapshot_generation(), 7);
        assert_eq!(second.ipsec_tunnel_rows().exact("st0").map(|r| r.if_id), Some(9));
    }

    #[test]
    fn ipsec_tunnel_rows_reject_nonpositive_logical_ifindex() {
        let rows = IpsecTunnelRows::new([
            IpsecTunnelRow { stn: "negative".into(), if_id: 1, logical_ifindex: -1 },
            IpsecTunnelRow { stn: "zero".into(), if_id: 2, logical_ifindex: 0 },
            IpsecTunnelRow { stn: "valid".into(), if_id: 3, logical_ifindex: 10 },
        ]);
        assert!(rows.exact("negative").is_none());
        assert!(rows.exact("zero").is_none());
        assert_eq!(rows.exact("valid").map(|row| row.logical_ifindex), Some(10));
        assert_eq!(rows.len(), 1);
    }
    fn route(
        domain: u32,
        table: u32,
        destination: &str,
        disposition: u8,
        next_hops: Vec<crate::protocol::IpsecMainRouteNextHopSnapshot>,
    ) -> crate::protocol::IpsecMainRouteSnapshot {
        crate::protocol::IpsecMainRouteSnapshot {
            domain,
            table,
            family: if destination.contains(':') { "inet6" } else { "inet" }.into(),
            destination: destination.into(),
            protocol: 0,
            disposition,
            next_hops,
        }
    }

    fn hop(ifindex: u32) -> crate::protocol::IpsecMainRouteNextHopSnapshot {
        crate::protocol::IpsecMainRouteNextHopSnapshot { ifindex, weight: 1 }
    }

    fn inventory_snapshot(
        routes: Vec<crate::protocol::IpsecMainRouteSnapshot>,
        remote_ts: &str,
        effective: &[&str],
        ingress: &[&str],
    ) -> crate::protocol::IpsecPMechInventorySnapshot {
        crate::protocol::IpsecPMechInventorySnapshot {
            policy_identity: "ab".repeat(32),
            generation: 77,
            fib_generation: 3,
            complete: true,
            main_routes: routes,
            tunnel_rows: vec![crate::protocol::IpsecPMechTunnelRowSnapshot {
                stn: "st0".into(),
                if_id: 9,
                logical_ifindex: 10,
                explicit_selectors: vec![crate::protocol::IpsecTrafficSelectorSnapshot {
                    name: "selector".into(),
                    local_ts: "192.0.2.0/24".into(),
                    remote_ts: remote_ts.into(),
                    source: "named".into(),
                }],
                effective_prefixes: effective.iter().map(|value| (*value).into()).collect(),
                ingress_prefixes: ingress.iter().map(|value| (*value).into()).collect(),
                inventory_generation: 77,
                fib_generation: 3,
                source_kind: "xfrmi".into(),
                selector_provenance: "named".into(),
                inventory_complete: true,
                inventory_valid: true,
                inventory_reason: String::new(),
            }],
        }
    }

    #[test]
    fn empty_main_routes_are_not_authority_even_when_complete_is_set() {
        let snapshot = inventory_snapshot(Vec::new(), "10.0.0.0/24", &[], &[]);
        let inventory = PMechInventory::from_snapshot(Some(&snapshot));
        assert!(!inventory.complete());
        assert!(!inventory.has_main_table_routes());
    }

    #[test]
    fn nonzero_domain_and_zero_table_poison_main_route_authority() {
        for route in [
            route(1, 254, "10.0.0.0/24", RTN_UNICAST, vec![hop(10)]),
            route(0, 0, "10.0.0.0/24", RTN_UNICAST, vec![hop(10)]),
        ] {
            let snapshot = inventory_snapshot(
                vec![route],
                "10.0.0.0/24",
                &["10.0.0.0/24"],
                &["10.0.0.0/24"],
            );
            let inventory = PMechInventory::from_snapshot(Some(&snapshot));
            assert!(!inventory.complete());
            assert!(!inventory.has_main_table_routes());
        }
    }

    #[test]
    fn mismatched_effective_or_ingress_projection_invalidates_tunnel_row() {
        let routes = vec![route(0, 254, "10.0.0.0/24", RTN_UNICAST, vec![hop(10)])];
        for (effective, ingress) in [
            (&["10.0.1.0/24"][..], &["10.0.0.0/24"][..]),
            (&["10.0.0.0/24"][..], &["10.0.1.0/24"][..]),
            (&["10.0.0.1/24"][..], &["10.0.0.0/24"][..]),
            (&["10.0.0.0/24"][..], &["10.0.0.1/24"][..]),
        ] {
            let snapshot = inventory_snapshot(
                routes.clone(),
                "10.0.0.0/24",
                effective,
                ingress,
            );
            let inventory = PMechInventory::from_snapshot(Some(&snapshot));
            let row = inventory.tunnels.get("st0").expect("tunnel row retained");
            assert!(!row.inventory_valid);
            assert_eq!(row.inventory_reason, "SELECTOR_PROJECTION_MISMATCH");
            assert!(inventory.exact_tunnel("st0", 9, 10).is_none());
        }
    }

    #[test]
    fn selector_ranges_recompute_to_the_same_canonical_cidr_cover() {
        let snapshot = inventory_snapshot(
            vec![route(0, 254, "10.0.0.0/24", RTN_UNICAST, vec![hop(10)])],
            "10.0.0.1-10.0.0.4",
            &["10.0.0.4/32", "10.0.0.2/31", "10.0.0.1/32"],
            &["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/32"],
        );
        let inventory = PMechInventory::from_snapshot(Some(&snapshot));
        let row = inventory.exact_tunnel("st0", 9, 10).expect("matching range projection");
        assert!(row.allows_source("10.0.0.3".parse().expect("IPv4 address")));
        assert!(!row.allows_source("10.0.0.5".parse().expect("IPv4 address")));
    }

    #[test]
    fn blackhole_is_retained_without_poisoning_and_malformed_leg_poisons() {
        let mut effective = vec![
            "10.0.0.0/16",
            "10.128.0.0/9",
            "10.16.0.0/12",
            "10.2.0.0/15",
            "10.32.0.0/11",
            "10.4.0.0/14",
            "10.64.0.0/10",
            "10.8.0.0/13",
        ];
        effective.sort_unstable();
        let snapshot = inventory_snapshot(
            vec![
                route(0, 254, "10.0.0.0/8", RTN_UNICAST, vec![hop(10)]),
                route(0, 254, "10.1.0.0/16", RTN_BLACKHOLE, vec![hop(10)]),
            ],
            "10.0.0.0/8",
            &effective,
            &effective,
        );
        let inventory = PMechInventory::from_snapshot(Some(&snapshot));
        assert!(inventory.complete());
        assert!(inventory.has_main_table_routes());
        assert_eq!(inventory.main_routes.len(), 2, "discard audit row must remain attached");
        let row = inventory.exact_tunnel("st0", 9, 10).expect("valid unshadowed projection");
        assert!(row.allows_source("10.0.1.1".parse().expect("IPv4 address")));
        assert!(!row.allows_source("10.1.1.1".parse().expect("IPv4 address")));
        assert!(row.allows_source("10.2.1.1".parse().expect("IPv4 address")));

        let malformed = inventory_snapshot(
            vec![route(0, 254, "10.0.0.0/24", RTN_UNICAST, vec![hop(0)])],
            "10.0.0.0/24",
            &["10.0.0.0/24"],
            &["10.0.0.0/24"],
        );
        let poisoned = PMechInventory::from_snapshot(Some(&malformed));
        assert!(!poisoned.complete(), "zero output ifindex must poison route inventory");
        assert!(!poisoned.has_main_table_routes());
        let ambiguous = inventory_snapshot(
            vec![
                route(0, 254, "10.0.0.0/24", RTN_UNICAST, vec![hop(10)]),
                route(0, 254, "10.0.0.0/24", RTN_UNICAST, vec![hop(11)]),
            ],
            "10.0.0.0/24",
            &["10.0.0.0/24"],
            &["10.0.0.0/24"],
        );
        let poisoned = PMechInventory::from_snapshot(Some(&ambiguous));
        assert!(!poisoned.complete(), "conflicting same-prefix legs must poison authority");
    }

    #[test]
    fn subtract_prefix_preserves_siblings_for_edge_blockers() {
        let base = "10.0.0.0/8".parse::<IpNet>().expect("base prefix");
        for (excluded, expected) in [
            (
                "10.0.0.0/16",
                vec![
                    "10.1.0.0/16",
                    "10.2.0.0/15",
                    "10.4.0.0/14",
                    "10.8.0.0/13",
                    "10.16.0.0/12",
                    "10.32.0.0/11",
                    "10.64.0.0/10",
                    "10.128.0.0/9",
                ],
            ),
            (
                "10.1.0.0/16",
                vec![
                    "10.0.0.0/16",
                    "10.2.0.0/15",
                    "10.4.0.0/14",
                    "10.8.0.0/13",
                    "10.16.0.0/12",
                    "10.32.0.0/11",
                    "10.64.0.0/10",
                    "10.128.0.0/9",
                ],
            ),
        ] {
            let excluded = excluded.parse::<IpNet>().expect("excluded prefix");
            let got = subtract_prefix_set(vec![base], excluded)
                .into_iter()
                .map(|prefix| prefix.to_string())
                .collect::<Vec<_>>();
            assert_eq!(got, expected, "subtracting {excluded} from {base}");
        }
    }

    #[test]
    fn subtract_prefix_equal_length_blocker_removes_the_whole_prefix() {
        let prefix = "10.0.0.0/16".parse::<IpNet>().expect("prefix");
        assert!(subtract_prefix_set(vec![prefix], prefix).is_empty());
    }

    #[test]
    fn incomplete_route_identity_map_withholds_pmech_authority() {
        let snapshot = inventory_snapshot(
            vec![route(
                0,
                254,
                "10.0.0.0/24",
                RTN_UNICAST,
                vec![hop(10)],
            )],
            "10.0.0.0/24",
            &["10.0.0.0/24"],
            &["10.0.0.0/24"],
        );
        let inventory = Arc::new(PMechInventory::from_snapshot(Some(&snapshot)));
        assert!(inventory.complete(), "premise: P-MECH inventory is otherwise complete");

        let mut forwarding = ForwardingState::default();
        forwarding
            .routes_v4
            .insert("blue.inet.0".into(), Vec::new());
        forwarding.route_table_identity_map_complete = false;
        let view = RuntimeView::new_with_ipsec_authority(
            ValidationState::default(),
            Arc::new(forwarding),
            Arc::new(IpsecTunnelRows::default()),
            snapshot.generation,
            inventory,
            0,
        );
        assert!(!view.pmech_inventory().complete());
        assert!(!view.pmech_inventory().has_main_table_routes());
    }
}
