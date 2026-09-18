package daemon

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// buildZoneIDs replicates the dataplane compiler's STABLE zone ID assignment
// (#3075): config.StableZoneID(name), a pure FNV-1a fold of the zone NAME into
// [1, ZoneIDReservedMin-1]. It MUST stay byte-identical to
// pkg/dataplane.assignZoneIDs so an HA session delta resolves to the same local
// id the compiler installed (enforced by an HA-symmetry test). The id is a pure
// function of the name — never of the zone set or compile order — so both nodes
// agree by construction and an earlier-sorting zone add/remove never renumbers
// a surviving zone's in-flight session metadata (the sorted-positional defect
// this replaces).
func buildZoneIDs(cfg *config.Config) map[string]uint16 {
	ids := make(map[string]uint16, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		ids[name] = config.StableZoneID(name)
	}
	return ids
}

// userspaceZoneIDsCache pairs a stable zone-id map with the active
// generation it was built from (#9905, F-152). Published through
// Daemon.userspaceZoneIDs; immutable after publication — misses always
// build fresh via buildZoneIDs and swap the pointer, never mutate in place.
type userspaceZoneIDsCache struct {
	gen uint64
	cfg *config.Config
	ids map[string]uint16
}

// cachedUserspaceZoneIDs returns the stable zone-id map for the current
// active generation, rebuilding only when the store's published snapshot
// moves (#9905, F-152). The warm path is one atomic snapshot load plus one
// atomic cache load — zero store locks, zero allocs. Misses serialize on
// userspaceZoneIDsMu and re-check under the lock; the build stores the
// START pair, never a reloaded generation with this build (a commit landing
// mid-build then costs at most one redundant rebuild, whereas the reverse
// order could pair an old map with a newer generation — permanent
// staleness). A nil store or nil snapshot config yields nil (no config),
// which the caller treats as a transient withhold like a nil ActiveConfig.
// WARNING (stale-map zombie direction): a zone REMOVE fails OPEN here —
// the deleted ID still resolves until the next delta rebuilds — while ADD
// fails closed. Window bounded by next-delta rebuild; stable IDs for
// surviving names only (see docs/log/9905.md; z174/z214 collide across
// the boundary, so no cross-boundary aliasing guarantee).
func (d *Daemon) cachedUserspaceZoneIDs() map[string]uint16 {
	if d.store == nil {
		return nil
	}
	gen, cfg := d.store.ActiveSnapshot()
	if c := d.userspaceZoneIDs.Load(); c != nil && c.gen == gen && c.cfg == cfg {
		return c.ids
	}
	d.userspaceZoneIDsMu.Lock()
	defer d.userspaceZoneIDsMu.Unlock()
	gen, cfg = d.store.ActiveSnapshot()
	if c := d.userspaceZoneIDs.Load(); c != nil && c.gen == gen && c.cfg == cfg {
		return c.ids
	}
	if cfg == nil {
		return nil
	}
	ids := buildZoneIDs(cfg)
	d.userspaceZoneIDs.Store(&userspaceZoneIDsCache{gen: gen, cfg: cfg, ids: ids})
	return ids
}

func daemonMonotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// daemonMonotonicNanos is the full-resolution boot clock. daemonMonotonicSeconds
// truncates to whole seconds, which is fine for session Created/LastSeen but NOT
// for seeding an identity: two daemon incarnations whose first allocations land
// in the same integer second would read the same value.
func daemonMonotonicNanos() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// userspaceSyncedSessionIDNamespace reserves the high 16 bits of the node-local
// BPF-ABI SessionID minted for an HA-synced session (#6198).
//
// The Rust dataplane's own stable id (`SessionTable::alloc_session_id`, #4915 —
// carried across the cluster wire as the DISTINCT RTFlowSessionID, #5212) is
// `namespace << 48 | counter48`, where the high-16 namespace is
// `node_bit << 15 | worker_id` since #6311 (`set_session_id_namespace`,
// userspace-dp/src/session/mod.rs): a 15-bit worker/queue index plus a
// chassis-cluster node discriminator. Reserving 0xFFFF for the Go-minted ids
// keeps the two id spaces disjoint inside the shared BPF conntrack mirror: the
// helper stamps its own id for sessions it owns, the control plane stamps one of
// these for a peer-synced session it installs, and neither can ever alias the
// other. The #6311 re-partition preserved the reservation — 0xFFFF is node-bit-1
// plus worker 0x7FFF, which the helper's namespace assert refuses — so this
// constant is unchanged.
const userspaceSyncedSessionIDNamespace = uint64(0xFFFF) << 48

// userspaceSyncedSessionIDCounterMask is the low-48-bit counter space inside
// that namespace — the same width the dataplane allocator uses.
const userspaceSyncedSessionIDCounterMask = uint64(0x0000_FFFF_FFFF_FFFF)

// userspaceSyncedSessionIDSeedShift is how far monotonic NANOSECONDS are shifted
// right to seed the counter. 2^10 ns ≈ 1.024 µs of seed granularity, which sets
// both properties that matter:
//
//   - Two incarnations share the same SEED only if their first allocations land
//     in the same aligned 1.024 µs bucket. A daemon restart is milliseconds at
//     the very least (process teardown, exec, init), so that window is
//     unreachable by three orders of magnitude. Seeding at SECOND resolution —
//     the first cut of this fix — left a window of up to a full second, which
//     systemd's `RestartSec=1` lands squarely inside.
//   - Distinct seeds are necessary but not sufficient: two incarnations can still
//     overlap by RANGE. The seed advances ~976,562 per second, so a successor
//     seeded t nanoseconds later starts (t >> 10) values above its predecessor,
//     and the ranges overlap once the predecessor mints more than that many ids.
//     At a 1 ms gap that is only ~976 ids. What makes overlap unreachable in
//     practice is the ratio: sustaining it needs an average above ~976k synced
//     conversions per second, far above what the dataplane produces.
//
// Be precise about the interval that average is taken over. Seeding is LAZY
// (sync.Once on the first allocation), so both endpoints are FIRST ALLOCATIONS,
// not process starts — the averaging interval begins when the predecessor first
// minted an id, not when it booted. An incarnation that idles for a long time
// and then mints just before being replaced gets only the teardown/restart gap
// of headroom, not its whole lifetime. Conversely, delay before the successor's
// first allocation widens the gap.
//
// The 48-bit seed space covers 2^58 ns ≈ 9.1 years of uptime before it cycles;
// a cycle can only alias ids from an incarnation that old.
const userspaceSyncedSessionIDSeedShift = 10

// userspaceSyncedSessionIDSeed returns the counter value a daemon incarnation
// starts from, given the monotonic nanoseconds at which it began.
//
// A bare counter starting at 0 would make ids REPEAT across an xpfd restart: the
// new incarnation re-mints 1, 2, 3… while entries the peer's conntrack mirror
// still holds from the previous incarnation (sessions this node closed while it
// was down, whose keys the post-restart bulk re-export never overwrites) carry
// exactly those values. The old now<<16|Slot composition did NOT have that flaw,
// because CLOCK_MONOTONIC is system uptime and keeps increasing across a daemon
// restart — so seeding is what keeps this change a strict improvement rather than
// a trade.
func userspaceSyncedSessionIDSeed(monotonicNanos uint64) uint64 {
	return (monotonicNanos >> userspaceSyncedSessionIDSeedShift) & userspaceSyncedSessionIDCounterMask
}

// userspaceSyncedSessionIDs is the node-local monotonic allocator behind
// nextUserspaceSyncedSessionID, seeded from the boot clock on first use.
var (
	userspaceSyncedSessionIDs    atomic.Uint64
	userspaceSyncedSessionIDOnce sync.Once
)

// nextUserspaceSyncedSessionID mints the node-local BPF-ABI SessionID stamped on
// a session converted from a userspace-helper delta (#6198).
//
// It replaces the previous `uint64(now)<<16 | uint64(delta.Slot&0xffff)`
// composition, which was NOT an identity at all: `delta.Slot` is the AF_XDP
// BINDING slot (`BindingIdentity.slot`, userspace-dp/src/afxdp/session_delta.rs
// — one per interface/queue, a handful per node), and the binary event stream
// that carries the primary delta path never decodes it at all
// (`decodeSessionEvent` in pkg/dataplane/userspace/eventstream.go leaves it 0).
// Every session converted within the same monotonic SECOND therefore collapsed
// onto ONE id, conflating unrelated flows in `show security flow session` and in
// the REST/gRPC session views. A monotonic counter gives every CONVERSION a
// distinct id — see the per-conversion note below.
//
// The counter is seeded from the boot clock on first use
// (userspaceSyncedSessionIDSeed) so ids do not repeat across an xpfd restart
// either.
//
// The advance is a CAS rather than a bare Add so the STORED value is the one that
// was returned. `0` is the "no id / unknown" sentinel that makes
// `flowSessionDisplayID` fall back to the per-row ordinal, so the counter skips
// it — and skipping it has to be committed to the atomic. A bare
// `Add(1) & mask; if counter == 0 { counter = 1 }` corrects only the local copy:
// at the wrap the atomic still holds the masked-zero value, so the NEXT call
// reads 1 and returns the id just handed out. That silently breaks the one
// property this whole change exists to establish, and unlike a plain overflow it
// leaves the id inside the namespace, so nothing downstream looks wrong.
//
// The wrap itself is reachable, not theoretical: the seed consumes counter space,
// so the distance to it depends on uptime phase. A wrap only re-mints ids this
// incarnation issued 2^48-1 conversions ago (the ring skips the zero counter,
// so 2^48-1 values are usable, not 2^48), or ids from an incarnation whose
// entries are long gone — so the ring is the right behaviour. Refusing to mint
// would be worse: this id is display-only, but the conversion that carries it
// installs an HA-synced session, and failing that to protect a display field
// would trade a cosmetic alias for lost sessions at failover.
//
// The id is per CONVERSION, not stable per session: a bulk resync re-converts
// live sessions and re-stamps them with fresh ids, and the `close` branch of
// queueUserspaceSessionDeltasLocked converts purely to derive the key and
// discards the id it mints. Both are harmless in a 48-bit space, and the old
// composition churned the id the same way — what changed is that concurrent
// sessions no longer SHARE one.
//
// This id stays NODE-LOCAL by design: the cross-node correlatable id is the
// separate RTFlowSessionID (#5212), which rides its own wire field and is
// adopted verbatim by the peer helper. See docs/session-sync-architecture.md.
// adoptedOrLocalSyncedSessionID returns the id to stamp into the BPF conntrack
// mirror for a peer-synced session (#6666).
//
// The peer's stable cross-node id when it sent one; a fresh node-local id
// otherwise. The fallback is what makes this rolling-upgrade safe: a mixed-base
// peer sends 0, and that path is byte-identical to pre-#6666.
func adoptedOrLocalSyncedSessionID(rtFlowSessionID uint64) uint64 {
	if rtFlowSessionID != 0 {
		return rtFlowSessionID
	}
	return nextUserspaceSyncedSessionID()
}

func nextUserspaceSyncedSessionID() uint64 {
	userspaceSyncedSessionIDOnce.Do(func() {
		userspaceSyncedSessionIDs.Store(userspaceSyncedSessionIDSeed(daemonMonotonicNanos()))
	})
	for {
		cur := userspaceSyncedSessionIDs.Load()
		next := (cur + 1) & userspaceSyncedSessionIDCounterMask
		if next == 0 {
			next = 1
		}
		if userspaceSyncedSessionIDs.CompareAndSwap(cur, next) {
			return userspaceSyncedSessionIDNamespace | next
		}
	}
}

func userspaceSessionTimeout(proto uint8) uint32 {
	switch proto {
	case 6:
		return 300
	case 17:
		return 60
	case 1, 58:
		return 15
	default:
		return 30
	}
}

func userspaceHostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func userspaceNetworkToHost16(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

// userspaceResolvedV4 is one delta's V4 addresses resolved exactly once: the
// parsed or copied bytes plus explicit presence. Presence is NOT "any nonzero
// byte": the JSON leg distinguishes absent (""/nil) from present-but-zero
// ("0.0.0.0" sets SNAT with IP 0 and trips the effective-port fallback), so
// every optional field carries its own bit and bytes copy verbatim even when
// zero-valued (#9905).
type userspaceResolvedV4 struct {
	src, dst               [4]byte
	ok                     bool
	natSrc, natDst         [4]byte
	hasNATSrc, hasNATDst   bool
	natSrcPort, natDstPort uint16
	srcMAC, neighborMAC    [6]byte
}

// userspaceResolvedV6 is the V6 twin, plus the NAT64 pool source.
type userspaceResolvedV6 struct {
	src, dst               [16]byte
	ok                     bool
	natSrc, natDst         [16]byte
	hasNATSrc, hasNATDst   bool
	natSrcPort, natDstPort uint16
	srcMAC, neighborMAC    [6]byte
	nat64Snat              [4]byte
	hasNat64Snat           bool
}

// userspaceResolveV4 resolves one delta's V4 addresses. The leg gate is
// whole-struct: BinAddrLen==0 takes the string path for every field (legacy
// JSON behavior, verbatim); 4 takes the binary path. Anything else — or a
// family/length mismatch — fails closed. Zero binary bytes mirror "" exactly:
// absent NAT/MAC and an unparseable (dropped) src/dst. There is no per-field
// mixing: decoders set one leg, and no Go site remarshals or merges the two.
func userspaceResolveV4(delta dpuserspace.SessionDeltaInfo) userspaceResolvedV4 {
	if delta.BinAddrLen != 0 {
		var r userspaceResolvedV4
		if delta.BinAddrLen != 4 || delta.AddrFamily != dataplane.AFInet {
			return r
		}
		copy(r.src[:], delta.SrcAddr[:4])
		copy(r.dst[:], delta.DstAddr[:4])
		r.ok = r.src != [4]byte{} && r.dst != [4]byte{}
		copy(r.natSrc[:], delta.NATSrcAddr[:4])
		copy(r.natDst[:], delta.NATDstAddr[:4])
		r.hasNATSrc = r.natSrc != [4]byte{}
		r.hasNATDst = r.natDst != [4]byte{}
		r.natSrcPort = userspaceEffectiveNATPort(delta.NATSrcPort, delta.SrcPort, r.hasNATSrc)
		r.natDstPort = userspaceEffectiveNATPort(delta.NATDstPort, delta.DstPort, r.hasNATDst)
		r.srcMAC = delta.SrcMACBin
		r.neighborMAC = delta.NeighborMACBin
		return r
	}
	var r userspaceResolvedV4
	src := net.ParseIP(delta.SrcIP).To4()
	dst := net.ParseIP(delta.DstIP).To4()
	if src == nil || dst == nil {
		return r
	}
	copy(r.src[:], src)
	copy(r.dst[:], dst)
	r.ok = true
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(r.natSrc[:], ip)
		r.hasNATSrc = true
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(r.natDst[:], ip)
		r.hasNATDst = true
	}
	r.natSrcPort = userspaceEffectiveNATPort(delta.NATSrcPort, delta.SrcPort, r.hasNATSrc)
	r.natDstPort = userspaceEffectiveNATPort(delta.NATDstPort, delta.DstPort, r.hasNATDst)
	r.srcMAC = userspaceParseSyncMAC(delta.SrcMAC)
	r.neighborMAC = userspaceParseSyncMAC(delta.NeighborMAC)
	return r
}

// userspaceResolveV6 is the V6 twin: To16 parses, [16]byte copies, and the
// NAT64 pool source (flag-gated + nonzero on the binary leg, ParseIP fallback
// on the string leg) that lets a peer-promoted NAT64 session rebuild its
// reverse BIB (#4565).
func userspaceResolveV6(delta dpuserspace.SessionDeltaInfo) userspaceResolvedV6 {
	if delta.BinAddrLen != 0 {
		var r userspaceResolvedV6
		if delta.BinAddrLen != 16 || delta.AddrFamily != dataplane.AFInet6 {
			return r
		}
		copy(r.src[:], delta.SrcAddr[:])
		copy(r.dst[:], delta.DstAddr[:])
		r.ok = r.src != [16]byte{} && r.dst != [16]byte{}
		copy(r.natSrc[:], delta.NATSrcAddr[:])
		copy(r.natDst[:], delta.NATDstAddr[:])
		r.hasNATSrc = r.natSrc != [16]byte{}
		r.hasNATDst = r.natDst != [16]byte{}
		r.natSrcPort = userspaceEffectiveNATPort(delta.NATSrcPort, delta.SrcPort, r.hasNATSrc)
		r.natDstPort = userspaceEffectiveNATPort(delta.NATDstPort, delta.DstPort, r.hasNATDst)
		r.srcMAC = delta.SrcMACBin
		r.neighborMAC = delta.NeighborMACBin
		if delta.Nat64 && delta.Nat64SnatV4Bin != [4]byte{} {
			r.nat64Snat = delta.Nat64SnatV4Bin
			r.hasNat64Snat = true
		}
		return r
	}
	var r userspaceResolvedV6
	src := net.ParseIP(delta.SrcIP).To16()
	dst := net.ParseIP(delta.DstIP).To16()
	if src == nil || dst == nil {
		return r
	}
	copy(r.src[:], src)
	copy(r.dst[:], dst)
	r.ok = true
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(r.natSrc[:], ip)
		r.hasNATSrc = true
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(r.natDst[:], ip)
		r.hasNATDst = true
	}
	r.natSrcPort = userspaceEffectiveNATPort(delta.NATSrcPort, delta.SrcPort, r.hasNATSrc)
	r.natDstPort = userspaceEffectiveNATPort(delta.NATDstPort, delta.DstPort, r.hasNATDst)
	r.srcMAC = userspaceParseSyncMAC(delta.SrcMAC)
	r.neighborMAC = userspaceParseSyncMAC(delta.NeighborMAC)
	if ip := net.ParseIP(delta.Nat64SnatV4).To4(); ip != nil {
		copy(r.nat64Snat[:], ip)
		r.hasNat64Snat = true
	}
	return r
}

// userspaceEffectiveNATPort is the NAT port a value stamps: the explicit port
// when set, else the base port when NAT is present, else 0. It replaces the
// two delta-taking effectiveUserspaceNAT*Port helpers, whose !="" presence
// test is the string-leg spelling of the resolved bit.
func userspaceEffectiveNATPort(raw, base uint16, present bool) uint16 {
	if raw != 0 {
		return raw
	}
	if present {
		return base
	}
	return 0
}

// userspaceDeltaFlowStrings renders the flow tuple for logs, binary-first:
// the binary leg leaves the strings empty, so the bytes must be consulted
// here. Eager (allocates) — call only behind an slog.Enabled gate so the hot
// path pays nothing at the default level.
func userspaceDeltaFlowStrings(delta dpuserspace.SessionDeltaInfo) (src, dst string) {
	switch delta.BinAddrLen {
	case 4:
		return net.IP(delta.SrcAddr[:4]).String(), net.IP(delta.DstAddr[:4]).String()
	case 16:
		return net.IP(delta.SrcAddr[:]).String(), net.IP(delta.DstAddr[:]).String()
	default:
		return delta.SrcIP, delta.DstIP
	}
}

func userspaceReverseKeyV4(key dataplane.SessionKey, r userspaceResolvedV4) dataplane.SessionKey {
	rev := dataplane.SessionKey{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if r.hasNATDst {
		rev.SrcIP = r.natDst
	}
	if r.hasNATSrc {
		rev.DstIP = r.natSrc
	}
	// Effective ports are behavior-identical to the raw ports this used to
	// read: raw!=0 passes through; raw==0+present falls back to htons(base),
	// which is the key port already in place; raw==0+absent keeps it.
	if r.natDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(r.natDstPort)
	}
	if r.natSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(r.natSrcPort)
	}
	return rev
}

// userspaceForwardWireKeyV4 derives the fabric-redirect forward-wire key
// from an ALREADY-CONVERTED value (#9905): the value carries the NAT IPs
// (network bytes), the effective NAT ports (already htons), and the
// SNAT/DNAT presence bits, so no second resolve — and on the JSON leg no
// second ParseIP — is needed. Each NAT IP is therefore parsed at most once
// per delta, inside the conversion that produced val.
func userspaceForwardWireKeyV4(key dataplane.SessionKey, val dataplane.SessionValue) dataplane.SessionKey {
	wire := key
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		binary.NativeEndian.PutUint32(wire.SrcIP[:], val.NATSrcIP)
		wire.SrcPort = val.NATSrcPort
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		binary.NativeEndian.PutUint32(wire.DstIP[:], val.NATDstIP)
		wire.DstPort = val.NATDstPort
	}
	return wire
}

func userspaceReverseKeyV6(key dataplane.SessionKeyV6, r userspaceResolvedV6) dataplane.SessionKeyV6 {
	rev := dataplane.SessionKeyV6{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if r.hasNATDst {
		rev.SrcIP = r.natDst
	}
	if r.hasNATSrc {
		rev.DstIP = r.natSrc
	}
	// Effective ports are behavior-identical to the raw ports this used to
	// read: raw!=0 passes through; raw==0+present falls back to htons(base),
	// which is the key port already in place; raw==0+absent keeps it.
	if r.natDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(r.natDstPort)
	}
	if r.natSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(r.natSrcPort)
	}
	return rev
}

func userspaceParseSyncMAC(raw string) [6]byte {
	var out [6]byte
	if raw == "" {
		return out
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != len(out) {
		return out
	}
	copy(out[:], mac)
	return out
}

// userspaceSessionOriginFlags preserves the helper's provenance on the Go
// mirror. Authoritative peer-synced helper entries use sync_import or
// shared_materialize; worker_local_import is a local worker replica and must
// clear the cluster-origin bit. All other origins are local (including
// SharedPromote, which is deliberately re-tagged local by the helper). Unknown
// or absent origins default clear for legacy helpers and fail-safe local
// semantics.
func userspaceSessionOriginFlags(origin string) uint16 {
	switch strings.ToLower(origin) {
	case "sync_import", "shared_materialize":
		return dataplane.SessFlagClusterSynced
	default:
		return 0
	}
}

func userspaceSessionFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	r := userspaceResolveV4(delta)
	if !r.ok {
		// #7171: these four conversion drops were SILENT while the V4
		// delta filters in daemon_ha_userspace_stream.go logged every
		// reason at Debug. A session dropped here never reaches the peer,
		// so it is simply missing after a failover with nothing in the log
		// to say a session was seen and discarded. Debug, not Info: this
		// is a per-session path (CLAUDE.md logging rules), and it matches
		// the level the V4 stream-side filters already use.
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			src, dst := userspaceDeltaFlowStrings(delta)
			slog.Debug("userspace delta: dropped (v4 address unparseable)",
				"src", src, "dst", dst, "proto", delta.Protocol)
		}
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	var key dataplane.SessionKey
	key.SrcIP, key.DstIP = r.src, r.dst
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	// #919/#922: prefer the u16 zone IDs from the binary event-stream
	// payload (decoded by eventstream.go; #3075 widened that wire field to
	// u16); fall back to legacy name-string lookup for older helpers that
	// emit JSON deltas only.
	ingressZone := delta.IngressZoneID
	if ingressZone == 0 {
		ingressZone = zoneIDs[delta.IngressZone]
	}
	egressZone := delta.EgressZoneID
	if egressZone == 0 {
		egressZone = zoneIDs[delta.EgressZone]
	}
	if ingressZone == 0 || egressZone == 0 {
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			src, dst := userspaceDeltaFlowStrings(delta)
			slog.Debug("userspace delta: dropped (v4 zone unresolved)",
				"ingress_zone", delta.IngressZone, "egress_zone", delta.EgressZone,
				"ingress_zone_id", ingressZone, "egress_zone_id", egressZone,
				"src", src, "dst", dst)
		}
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValue{
		State: 4, // SESS_STATE_ESTABLISHED
		// SessionID is the BPF-ABI conntrack id the session VIEWS render --
		// `show security flow session`, the REST session views, the gRPC session
		// RPCs. #6666: when the peer sent its stable cross-node id, ADOPT it
		// here instead of minting a node-local one.
		//
		// TWO WRITERS reach this one field. The control plane writes it on every
		// conversion; the helper writes the entry's own stable id whenever a
		// frame drives a local publish for the same key. They minted from
		// disjoint namespaces, so the displayed id FLIPPED depending on which
		// wrote last -- at promotion, and (worse, and not in the issue) at every
		// bulk resync, because the control-plane id is distinct per CONVERSION
		// rather than per session. Adopting makes both writers agree.
		//
		// It also makes #5213's stated invariant true. cli_show_flow.go promises
		// the displayed id is IDENTICAL to the id RT_FLOW emits for the same
		// session; for a peer-synced session it was not, because RT_FLOW carries
		// the adopted id while the mirror carried the local one.
		//
		// SAFE BY CONSTRUCTION, not by bookkeeping. #6311 gave every id a node
		// discriminator bit, so an adopted id carries the ORIGINATING node's bit
		// and cannot collide with anything this node mints -- pinned by
		// adopted_peer_id_cannot_collide_with_a_local_id_6311. And nothing keys
		// on it: pkg/dataplane/types.go states it is "never a lookup key", and a
		// sweep of every non-test SessionID reference finds no map key, index,
		// dedup or generation guard. The blast radius is display-only.
		//
		// 0 means a legacy or rolling-upgrade peer that sent no id; mint as
		// before, which keeps every #6198 mint test exercising the same path.
		SessionID: adoptedOrLocalSyncedSessionID(delta.RTFlowSessionID),
		// #10227: preserve helper provenance through the Go SessionValue.
		Flags: userspaceSessionOriginFlags(delta.Origin),
		// #5212: the ORIGINATING node's stable RT_FLOW session id (distinct from
		// SessionID above). Carried across the cluster sync wire so a peer-synced
		// session adopts it and its SESSION_CREATE/CLOSE records correlate across
		// nodes. 0 on a legacy helper => a fresh local id is allocated on import.
		RTFlowSessionID: delta.RTFlowSessionID,
		// #7239 (#7160/#2387): carry the domain the helper stamped at INSTALL,
		// rather than letting the peer re-derive it from IngressIfaceFold. That
		// fold is stamped on the SEND path against the CURRENT config, so an
		// ifindex recycled onto a sibling between install and sync would import
		// the session into the sibling's routing domain — a cross-tenant
		// mis-file, and a confident one.
		RoutingDomain: delta.RoutingDomain,
		Created:       now,
		LastSeen:      now,
		Timeout:       userspaceSessionTimeout(delta.Protocol),
		IngressZone:   ingressZone,
		EgressZone:    egressZone,
		ReverseKey:    userspaceReverseKeyV4(key, r),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = r.neighborMAC
	val.FibSmac = r.srcMAC
	if r.hasNATSrc {
		val.Flags |= dataplane.SessFlagSNAT
		val.NATSrcIP = binary.NativeEndian.Uint32(r.natSrc[:])
		val.NATSrcPort = userspaceHostToNetwork16(r.natSrcPort)
	}
	if r.hasNATDst {
		val.Flags |= dataplane.SessFlagDNAT
		val.NATDstIP = binary.NativeEndian.Uint32(r.natDst[:])
		val.NATDstPort = userspaceHostToNetwork16(r.natDstPort)
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	// #2785: stamp the admitting policy's per-policy `then log` selection
	// onto the synced session so it emits the same RT_FLOW
	// SESSION_CREATE/CLOSE records after failover. These bits ride the
	// cluster wire on LogFlags and are re-applied to the peer helper's
	// SyncedSessionEntry via buildSessionSyncRequest.
	if delta.LogSessionInit {
		val.LogFlags |= dataplane.LogFlagSessionInit
	}
	if delta.LogSessionClose {
		val.LogFlags |= dataplane.LogFlagSessionClose
	}
	// #3301: carry the admitting policy's firewall metadata so a peer-promoted
	// session is correctly attributed (PolicyID), counted (PolicyCounterIdx),
	// and aged (AppTimeout = per-application idle timeout, seconds) after
	// failover instead of degrading to policy 0 / no counter / global timeout.
	val.PolicyID = delta.PolicyID
	val.PolicyCounterIdx = delta.PolicyCounterIdx
	val.AppTimeout = delta.AppTimeout
	// #7188: carry the helper's tunnel session-identity discriminator so the
	// peer helper folds it back into the key it reconstructs. Opaque here.
	// Protocol 47 has no L4 ports, so two RFC 2890 GRE tunnels between one pair
	// of outer endpoints are ONE Go session key; this value is what keeps them
	// two sessions on the standby. 0 = not carried by this helper, on which the
	// peer withholds a protocol-47 session rather than aliasing it.
	val.TunnelDiscriminator = delta.TunnelDiscriminator
	// #9412: the helper's close class rides the synced value to the peer.
	val.TCPCloseClass = delta.TCPCloseClass
	// #9752: the helper's installing-table identity rides the synced value
	// to the peer, so a PBR-steered session re-resolves in its table after
	// failover instead of inet.0. Opaque here. (0,0) = default table.
	val.InstallTableDomain = delta.InstallTableDomain
	val.InstallTableCheck = delta.InstallTableCheck
	// #9752: carry the purge-retirement marker for the delete sinks below.
	// Set from the delta unconditionally; it is only ever true on closes
	// (the helper never sets it on opens) and only ever read on the delete
	// path, so a stray bit on an open is inert.
	if delta.PurgeRetirement {
		val.LogFlags |= dataplane.LogFlagPurgeRetirementOnly
	}
	return key, val, true
}

// userspaceForwardWireAliasV4 derives the fabric-redirect forward-wire alias
// entry from an ALREADY-CONVERTED base session.
//
// It takes the converted base rather than re-converting the delta because
// nextUserspaceSyncedSessionID mints a FRESH id per conversion (#6198): a second
// conversion of the same delta would split one logical session across two
// SessionIDs, where the alias and its base entry must share one. It also drops a
// redundant conversion from the delta path. Since #9905 the wire key itself is
// derived from the value (NAT bytes + stamped ports + presence flags), so the
// alias path parses nothing — not even on the JSON leg.
func userspaceForwardWireAliasV4(key dataplane.SessionKey, val dataplane.SessionValue) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	wireKey := userspaceForwardWireKeyV4(key, val)
	if wireKey == key {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	return wireKey, val, true
}

func userspaceSessionFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	r := userspaceResolveV6(delta)
	if !r.ok {
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			src, dst := userspaceDeltaFlowStrings(delta)
			slog.Debug("userspace delta: dropped (v6 address unparseable)",
				"src", src, "dst", dst, "proto", delta.Protocol)
		}
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	var key dataplane.SessionKeyV6
	key.SrcIP, key.DstIP = r.src, r.dst
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	// #919/#922: prefer the u16 zone IDs from the binary event-stream
	// payload; fall back to legacy name-string lookup for JSON deltas.
	ingressZone := delta.IngressZoneID
	if ingressZone == 0 {
		ingressZone = zoneIDs[delta.IngressZone]
	}
	egressZone := delta.EgressZoneID
	if egressZone == 0 {
		egressZone = zoneIDs[delta.EgressZone]
	}
	if ingressZone == 0 || egressZone == 0 {
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			src, dst := userspaceDeltaFlowStrings(delta)
			slog.Debug("userspace delta: dropped (v6 zone unresolved)",
				"ingress_zone", delta.IngressZone, "egress_zone", delta.EgressZone,
				"ingress_zone_id", ingressZone, "egress_zone_id", egressZone,
				"src", src, "dst", dst)
		}
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValueV6{
		State: 4, // SESS_STATE_ESTABLISHED
		// SessionID: adopted from the peer when it sent one, else minted
		// node-local (#6666 -- see the V4 converter for the full reasoning).
		SessionID: adoptedOrLocalSyncedSessionID(delta.RTFlowSessionID),
		// #10227: preserve helper provenance through the Go SessionValue.
		Flags: userspaceSessionOriginFlags(delta.Origin),
		// #5212: the ORIGINATING node's stable RT_FLOW session id (see V4) —
		// adopted by a peer-synced session so its RT_FLOW records correlate
		// across HA nodes; 0 on a legacy helper => fresh local id on import.
		RTFlowSessionID: delta.RTFlowSessionID,
		// #7239 (#7160/#2387): carry the domain the helper stamped at INSTALL,
		// rather than letting the peer re-derive it from IngressIfaceFold. That
		// fold is stamped on the SEND path against the CURRENT config, so an
		// ifindex recycled onto a sibling between install and sync would import
		// the session into the sibling's routing domain — a cross-tenant
		// mis-file, and a confident one.
		RoutingDomain: delta.RoutingDomain,
		Created:       now,
		LastSeen:      now,
		Timeout:       userspaceSessionTimeout(delta.Protocol),
		IngressZone:   ingressZone,
		EgressZone:    egressZone,
		ReverseKey:    userspaceReverseKeyV6(key, r),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = r.neighborMAC
	val.FibSmac = r.srcMAC
	if r.hasNATSrc {
		val.Flags |= dataplane.SessFlagSNAT
		val.NATSrcIP = r.natSrc
		val.NATSrcPort = userspaceHostToNetwork16(r.natSrcPort)
	}
	if r.hasNATDst {
		val.Flags |= dataplane.SessFlagDNAT
		val.NATDstIP = r.natDst
		val.NATDstPort = userspaceHostToNetwork16(r.natDstPort)
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	// #2785: stamp the per-policy `then log` selection (see V4).
	if delta.LogSessionInit {
		val.LogFlags |= dataplane.LogFlagSessionInit
	}
	if delta.LogSessionClose {
		val.LogFlags |= dataplane.LogFlagSessionClose
	}
	// #3301: carry the admitting policy's firewall metadata (see V4).
	val.PolicyID = delta.PolicyID
	val.PolicyCounterIdx = delta.PolicyCounterIdx
	val.AppTimeout = delta.AppTimeout
	// #4565: stamp the NAT64 translated pool SOURCE so the cluster wire + peer
	// helper carry it, letting a peer-PROMOTED NAT64 session rebuild its reverse
	// (v4->v6) BIB after failover. A resolved pool source marks a NAT64
	// cross-family session: Nat64SnatV4Bin on the binary leg (#9905,
	// decode-gated on the FLAG_NAT64 open frame) or ParseIP of
	// delta.Nat64SnatV4 on the string leg (flag-blind legacy fallback).
	if r.hasNat64Snat {
		val.Nat64SnatV4 = r.nat64Snat
	}
	// #7188: carry the helper's tunnel session-identity discriminator so the
	// peer helper folds it back into the key it reconstructs. Opaque here.
	// Protocol 47 has no L4 ports, so two RFC 2890 GRE tunnels between one pair
	// of outer endpoints are ONE Go session key; this value is what keeps them
	// two sessions on the standby. 0 = not carried by this helper, on which the
	// peer withholds a protocol-47 session rather than aliasing it.
	val.TunnelDiscriminator = delta.TunnelDiscriminator
	// #9412: the helper's close class rides the synced value to the peer.
	val.TCPCloseClass = delta.TCPCloseClass
	// #9752: v6 analogue of the installing-table mapping above.
	val.InstallTableDomain = delta.InstallTableDomain
	val.InstallTableCheck = delta.InstallTableCheck
	// #9752: v6 analogue of the purge-retirement marker bit above.
	if delta.PurgeRetirement {
		val.LogFlags |= dataplane.LogFlagPurgeRetirementOnly
	}
	return key, val, true
}

// userspaceForwardWireKeyV6 is the V6 twin: the NAT arrays copy directly
// from the value, ports and presence likewise — no second resolve (#9905).
func userspaceForwardWireKeyV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) dataplane.SessionKeyV6 {
	wire := key
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		wire.SrcIP = val.NATSrcIP
		wire.SrcPort = val.NATSrcPort
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		wire.DstIP = val.NATDstIP
		wire.DstPort = val.NATDstPort
	}
	return wire
}

// userspaceForwardWireAliasV6 is the V6 twin of userspaceForwardWireAliasV4 —
// same reason for taking the already-converted base (#6198), same
// no-re-resolve wire derivation (#9905).
func userspaceForwardWireAliasV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	wireKey := userspaceForwardWireKeyV6(key, val)
	if wireKey == key {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	return wireKey, val, true
}
