package flowexport

import (
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// MaskResolver returns the prefix length (subnet mask, in bits) of the FIB
// longest-prefix-match route for an IP, plus whether a mask was resolved. The
// lookup is scoped to the flow's routing table by ifindex (#3744): the ingress
// interface selects the l3mdev VRF table the flow was actually forwarded in, so
// a multi-VRF/routing-instance flow's mask is resolved in ITS table, not the
// global one. ifindex==0 (no attribution) falls back to the global/main table,
// the pre-#3744 behaviour and a bit-identical no-op for single-VRF/default
// deployments where the main table IS the flow's table.
//
// #2866: NetFlow v9 srcMask (IE 9) / dstMask (IE 13) and the IPv6 variants
// (IE 29 / IE 30) are the prefix lengths of the routing-table entries that
// match the flow's source and destination addresses (the same semantics
// Junos/vSRX export). The SESSION_CLOSE wire frame carries no route mask, so
// the exporter resolves it from the local FIB at export time. A default-route
// match legitimately yields 0 — that is the matched route's real prefix
// length, NOT the "unpopulated" zero the field carried before this change.
//
// The bool return lets a caller distinguish "resolved to /0 (default route)"
// from "no route / resolver unavailable"; the exporters write the resolved
// length on either true OR a 0 from a successful default-route match, and count
// an unresolved (!ok) lookup so an operator can see how often an exported mask
// is an unresolved-0 (route absent / cold cache) versus a real default-route /0.
type MaskResolver func(ip net.IP, ifindex int) (mask uint8, ok bool)

// routeMaskCacheMax bounds the number of distinct (ifindex,IP) keys the cache
// retains. The TTL bounds the syscall RATE; this bounds the FOOTPRINT. On an
// internet-facing firewall the destination-IP cardinality is effectively
// unbounded, so without a size cap the map would grow for the daemon's lifetime
// (~50-70 B/entry) — a slow leak. 8192 entries (~0.5 MB worst case) is far above
// the working set of distinct src/dst prefixes for any realistic flow mix yet a
// hard ceiling.
const routeMaskCacheMax = 8192

// defaultRouteMaskInflight bounds the number of concurrent BACKGROUND FIB
// lookups (#3743). resolve() runs inside the EventReader session-close
// callback; a synchronous RTM_GETROUTE netlink round-trip there stalls the
// event reader and every other callback behind it (including the trace writer)
// under netlink latency, and high destination-IP churn turns close handling
// into a netlink-bound path. So a cache miss no longer blocks: it schedules the
// lookup on a background goroutine and returns the default immediately. This
// ceiling caps how many such lookups run at once, so a slow/loaded netlink
// socket under churn cannot spawn unbounded goroutines — once it is reached,
// further misses just return the default and are retried on a later flow.
const defaultRouteMaskInflight = 32

// routeMaskKey is the cache key: the flow's routing table (selected by the
// ingress ifindex, #3744) plus the 16-byte IP being resolved. Keying on
// ifindex as well as IP is what keeps a VRF-A result from being served to a
// VRF-B flow to the same destination — the same host address can have a
// different matching-route prefix length in each VRF's table. ifindex 0 (no
// attribution → global table) is its own key, so single-VRF/default flows share
// one keyspace exactly as before #3744.
type routeMaskKey struct {
	ifindex uint32
	ip      string // 16-byte string form of the IP (net.IP.To16())
}

// routeMaskCache caches FIB-match results for a short TTL so the per-flow
// session-close export path does not issue an RTM_GETROUTE netlink syscall for
// every record. Flows to the same destination/source prefix are common
// (per-host or per-subnet aggregates), so a small TTL cache collapses the
// syscall rate dramatically while keeping the mask fresh across routing
// changes. The cache is keyed by (ifindex, 16-byte IP) and bounded at
// routeMaskCacheMax entries.
type routeMaskCache struct {
	ttl     time.Duration
	maxSize int
	// lookup is the FIB query; a package var/field so tests can inject a
	// deterministic resolver without touching the kernel routing table. The
	// ifindex scopes the lookup to that interface's VRF table (#3744).
	lookup func(ip net.IP, ifindex int) (uint8, bool)

	// maxInflight bounds concurrent background FIB lookups (#3743). 0 selects
	// defaultRouteMaskInflight. See scheduleLookupLocked.
	maxInflight int

	mu       sync.Mutex
	entries  map[routeMaskKey]routeMaskEntry
	pending  map[routeMaskKey]struct{} // keys with a background lookup in flight (dedup)
	inflight int                       // count of background lookups currently running

	// afterPopulate, when non-nil, is invoked after each background lookup has
	// stored its result. Test-only seam for deterministic assertions; nil in
	// production (the resolve() fast path never touches it).
	afterPopulate func()
}

type routeMaskEntry struct {
	mask    uint8
	ok      bool
	expires time.Time
}

// defaultRouteMaskTTL is the cache TTL selected by NewRouteMaskResolver(0) —
// the value every production caller uses.
const defaultRouteMaskTTL = 10 * time.Second

// routeMaskSharedOnce/routeMaskShared hold the PROCESS-SINGLETON cache used by
// every default-TTL resolver (#5250 A9 F3). Both production call sites
// (NewExporter, newIPFIXExporter) run on the flow-export RECONCILE path, so a
// per-exporter cache meant every commit built a fresh instance: its background
// RTM_GETROUTE goroutines (bounded at defaultRouteMaskInflight per instance,
// but per instance) outlived the exporter that scheduled them with nothing able
// to stop them, the in-flight ceiling scaled with the number of exporter
// generations rather than with the process, and each generation restarted from
// a COLD cache — re-issuing the netlink lookups the previous generation had
// already paid for. The FIB mask for an (ifindex, IP) key is a property of the
// kernel routing table, not of any exporter's config, so one shared instance is
// semantically identical to N and is what bounds the background work
// process-wide. A non-default ttl still gets its own instance: that is a
// caller asking for different freshness, and no production path takes it.
var (
	routeMaskSharedOnce sync.Once
	routeMaskShared     *routeMaskCache
)

// NewRouteMaskResolver returns a MaskResolver backed by the kernel FIB
// (RTM_GETROUTE with RTM_F_FIB_MATCH), with a short TTL cache to bound the
// netlink syscall rate on the hot session-close export path. ttl<=0 selects a
// sensible default (10s) and shares the process-wide cache; see
// routeMaskCacheFor.
func NewRouteMaskResolver(ttl time.Duration) MaskResolver {
	return routeMaskCacheFor(ttl).resolve
}

// routeMaskCacheFor returns the cache instance backing a resolver with the
// given ttl: the process singleton for the default TTL (ttl<=0 or exactly
// defaultRouteMaskTTL), a dedicated instance otherwise. Split out from
// NewRouteMaskResolver so the singleton identity is directly assertable.
func routeMaskCacheFor(ttl time.Duration) *routeMaskCache {
	if ttl <= 0 {
		ttl = defaultRouteMaskTTL
	}
	if ttl == defaultRouteMaskTTL {
		routeMaskSharedOnce.Do(func() {
			routeMaskShared = newRouteMaskCache(defaultRouteMaskTTL)
		})
		return routeMaskShared
	}
	return newRouteMaskCache(ttl)
}

func newRouteMaskCache(ttl time.Duration) *routeMaskCache {
	return &routeMaskCache{
		ttl:         ttl,
		maxSize:     routeMaskCacheMax,
		maxInflight: defaultRouteMaskInflight,
		lookup:      fibMatchMask,
		entries:     make(map[routeMaskKey]routeMaskEntry),
		pending:     make(map[routeMaskKey]struct{}),
	}
}

// resolve implements MaskResolver with caching. It NEVER issues the netlink
// FIB lookup on the calling goroutine (#3743): resolve() runs inside the
// EventReader session-close callback, so a synchronous RTM_GETROUTE round-trip
// would serialize the event reader (and every callback behind it) behind
// netlink latency. On a fresh cache hit it returns the cached prefix length; on
// a miss it schedules a bounded, deduplicated background lookup that warms the
// cache for the NEXT flow to this (ifindex, prefix) key and returns the safe
// default (0, false) now. An approximate mask on the first flow to a new prefix
// is the accepted trade-off for never blocking the shared event-reader path.
//
// ifindex scopes the lookup to the flow's l3mdev VRF table (#3744); it is part
// of the cache key so per-VRF masks do not collide.
func (c *routeMaskCache) resolve(ip net.IP, ifindex int) (uint8, bool) {
	if ip == nil {
		return 0, false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, false
	}
	key := routeMaskKey{ifindex: uint32(ifindex), ip: string(ip16)}
	now := time.Now()

	c.mu.Lock()
	if e, found := c.entries[key]; found && now.Before(e.expires) {
		mask, ok := e.mask, e.ok
		c.mu.Unlock()
		return mask, ok
	}
	// Cache miss (or expired): schedule the FIB lookup off this goroutine and
	// return the default now — do NOT block the callback on netlink.
	c.scheduleLookupLocked(key, ip16, ifindex)
	c.mu.Unlock()
	return 0, false
}

// scheduleLookupLocked starts a background FIB lookup for key unless one is
// already in flight for it (dedup) or the concurrent-lookup cap is reached
// (backpressure — the miss is retried on a later flow rather than piling up
// goroutines behind a slow netlink socket). ip16 is copied because the caller's
// slice may be reused after resolve() returns. ifindex scopes the FIB lookup to
// the flow's VRF table (#3744). The caller holds c.mu. #3743.
func (c *routeMaskCache) scheduleLookupLocked(key routeMaskKey, ip16 net.IP, ifindex int) {
	if c.lookup == nil {
		return
	}
	if c.pending == nil {
		c.pending = make(map[routeMaskKey]struct{})
	}
	if _, inFlight := c.pending[key]; inFlight {
		return
	}
	limit := c.maxInflight
	if limit <= 0 {
		limit = defaultRouteMaskInflight
	}
	if c.inflight >= limit {
		return
	}
	c.pending[key] = struct{}{}
	c.inflight++
	ipCopy := append(net.IP(nil), ip16...)
	go c.populate(key, ipCopy, ifindex)
}

// populate runs a single background FIB lookup and stores the result so the
// next flow to this (ifindex, prefix) key resolves from the warm cache. It is
// the goroutine body scheduled by scheduleLookupLocked; the netlink round-trip
// happens here, entirely off the EventReader callback path. #3743.
func (c *routeMaskCache) populate(key routeMaskKey, ip net.IP, ifindex int) {
	mask, ok := c.lookup(ip, ifindex)
	now := time.Now()
	c.mu.Lock()
	c.storeLocked(key, mask, ok, now)
	delete(c.pending, key)
	if c.inflight > 0 {
		c.inflight--
	}
	after := c.afterPopulate
	c.mu.Unlock()
	if after != nil {
		after()
	}
}

// storeLocked bounds the cache then inserts a resolved entry. The caller holds
// c.mu.
func (c *routeMaskCache) storeLocked(key routeMaskKey, mask uint8, ok bool, now time.Time) {
	c.evictLocked(key, now)
	c.entries[key] = routeMaskEntry{mask: mask, ok: ok, expires: now.Add(c.ttl)}
}

// evictLocked bounds the cache before an insert. It is a no-op until the map is
// at the size cap; at the cap it first drops every expired entry (cheap, and it
// usually recovers headroom on a busy cache because TTLs are short), and if the
// map is STILL at the cap (a burst of distinct live keys) it clears the whole
// map. Clearing is the simplest hard bound — it sacrifices the warm set for one
// cold round of syscalls rather than tracking per-entry LRU, which is not worth
// the bookkeeping for a syscall-amortization cache. maxSize<=0 disables the
// bound (used only by tests). The caller holds c.mu.
func (c *routeMaskCache) evictLocked(key routeMaskKey, now time.Time) {
	if c.maxSize <= 0 || len(c.entries) < c.maxSize {
		return
	}
	// Re-inserting an existing key does not grow the map, so it never needs
	// eviction; only a NEW key crossing the cap does.
	if _, exists := c.entries[key]; exists {
		return
	}
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.maxSize {
		clear(c.entries)
	}
}

// resolveMasks returns the src/dst route prefix lengths for a flow using r,
// plus the count of halves that did NOT resolve (0, 1, or 2). Both halves are
// scoped to the flow's INGRESS routing instance (#3744): the session belongs to
// the ingress routing-instance and next-table / rib-group leaked routes to the
// destination appear in that ingress table, so the ingress ifindex (inIf)
// selects the table for BOTH the source and destination lookup. When the
// dataplane could not attribute an ingress interface (inIf==0) the egress
// interface (outIf) is used as a best-effort scope before falling back to the
// global table.
//
// A nil resolver (zero-value exporter) yields 0/0 with 0 misses — the pre-#2866
// behaviour, where the feature is simply off (not an "unresolved" condition).
// A resolver miss (no matching route / cold cache) yields 0 for that half AND
// increments the returned miss count: the u8 wire field (0..128) has no room for
// an "unresolved" sentinel a collector would understand, so the miss is surfaced
// out-of-band via a counter (#3744) rather than silently exported as a bogus /0.
// A successful match to a default route legitimately yields 0 with no miss; that
// is the real matched-route prefix length, not "unpopulated".
func resolveMasks(r MaskResolver, srcIP, dstIP net.IP, inIf, outIf uint32) (srcMask, dstMask uint8, misses uint64) {
	if r == nil {
		return 0, 0, 0
	}
	scope := int(inIf)
	if scope == 0 {
		// No ingress attribution: fall back to the egress interface's table
		// rather than the global table (still better VRF locality than table 0).
		scope = int(outIf)
	}
	var srcOK, dstOK bool
	srcMask, srcOK = r(srcIP, scope)
	dstMask, dstOK = r(dstIP, scope)
	if !srcOK {
		misses++
	}
	if !dstOK {
		misses++
	}
	return srcMask, dstMask, misses
}

// fibMatchMask queries the kernel FIB for the longest-prefix-match route to ip
// and returns the matched route's prefix length. RTM_F_FIB_MATCH makes the
// kernel report the actual matching FIB entry (with its Dst prefix) rather than
// echoing the queried host as a /32 or /128, so a default-route match returns
// the real /0.
//
// ifindex>0 sets RTA_IIF, which makes the kernel perform an INPUT route lookup
// as if the packet arrived on that interface — that follows l3mdev enslavement
// into the interface's VRF table (#3744), so the mask is resolved in the flow's
// own routing instance rather than the main table. ifindex==0 omits RTA_IIF and
// keeps the pre-#3744 main-table output-route lookup, bit-identical for
// single-VRF/default deployments.
func fibMatchMask(ip net.IP, ifindex int) (uint8, bool) {
	opts := &netlink.RouteGetOptions{FIBMatch: true}
	if ifindex > 0 {
		opts.IifIndex = ifindex
	}
	routes, err := netlink.RouteGetWithOptions(ip, opts)
	if err != nil || len(routes) == 0 {
		return 0, false
	}
	// RouteGet may return multiple ECMP nexthops for ONE matched prefix; they
	// all share the same Dst, so the first entry's Dst is authoritative.
	dst := routes[0].Dst
	if dst == nil {
		// No Dst reported (kernel without FIB_MATCH support, or a cache route):
		// the route covers the whole family — treat as default (/0).
		return 0, true
	}
	ones, _ := dst.Mask.Size()
	if ones < 0 || ones > 128 {
		return 0, false
	}
	return uint8(ones), true
}
