package cluster

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
)

// definitiveBulkInstallOutcome reports helper results that cannot be repaired
// by replaying the identical row: the helper committed it with worker repair
// pending/overflow, or explicitly rejected the row deterministically. Every
// production deterministic rejection reaches this classifier wrapped in
// dataplane.ErrSyncedImportRejected: userspace/process_control.go classifies
// helper response text, manager_sessions.go prefixes the mirror error, and
// the session-store adapters pass it through unchanged. No in-tree path hands
// the cluster an unwrapped deterministic error.
func definitiveBulkInstallOutcome(err error) bool {
	return errors.Is(err, dataplane.ErrSyncedImportRepairPending) ||
		errors.Is(err, dataplane.ErrSyncedImportRepairOverflow) ||
		errors.Is(err, dataplane.ErrSyncedImportRejected)
}

// scopedDeleteKeyV4 keys receiver generation guards by scoped policy-delete
// identity (#10512): colliding tenants sharing a bare tuple order
// independently. Comparable (all fields comparable) for map + tombstone use.
type scopedDeleteKeyV4 struct {
	Domain uint32
	Key    dataplane.SessionKey
}

// scopedDeleteKeyV6 is the IPv6 twin of scopedDeleteKeyV4.
type scopedDeleteKeyV6 struct {
	Domain uint32
	Key    dataplane.SessionKeyV6
}

// scopedTupleIndex inverts a scoped generation map by bare tuple (#15039):
// bareTuple -> set of scoped keys naming it. A bare close/delete names no
// domain, so it must reach every domain's entry for its tuple (#14358);
// without this side index that was a full-map scan per bare delete, and
// the receiver map is pinned near its cap by tombstones, so every bare
// delete cost O(held entries). The index holds no generations — the
// scoped map stays authoritative — it only names which scoped keys exist
// per tuple. Maintained on every scoped put/delete/evict/reset under the
// same mutex as its map (genSentMu / recvGenMu); an index entry is pruned
// as soon as its set empties, so the index never outlives the map entries
// it names. If index and map ever disagree the map wins for ordering
// (lookups read the map value), and an absent index set names no entries
// to reclaim/tombstone — callers treat it exactly like a tuple with no
// scoped entries, which is the pre-existing no-op case.
type scopedTupleIndex[K comparable, SK comparable] struct {
	byTuple map[K]map[SK]struct{}
}

func (ix *scopedTupleIndex[K, SK]) add(tuple K, skey SK) {
	if ix.byTuple == nil {
		ix.byTuple = make(map[K]map[SK]struct{})
	}
	set := ix.byTuple[tuple]
	if set == nil {
		set = make(map[SK]struct{})
		ix.byTuple[tuple] = set
	}
	set[skey] = struct{}{}
}

func (ix *scopedTupleIndex[K, SK]) remove(tuple K, skey SK) {
	set := ix.byTuple[tuple]
	if set == nil {
		return
	}
	delete(set, skey)
	if len(set) == 0 {
		delete(ix.byTuple, tuple)
	}
}

// keys returns a snapshot of the scoped keys naming tuple (nil when none).
// Callers mutate the scoped map while iterating the result, so it must be
// a copy, not the live set.
func (ix *scopedTupleIndex[K, SK]) keys(tuple K) []SK {
	set := ix.byTuple[tuple]
	if len(set) == 0 {
		return nil
	}
	out := make([]SK, 0, len(set))
	for skey := range set {
		out = append(out, skey)
	}
	return out
}

func (ix *scopedTupleIndex[K, SK]) reset() {
	ix.byTuple = nil
}

// scopedLogicalDomain normalizes a #7239 wire routing domain to the logical
// domain the scoped generation spaces are keyed by: marker 1 (DEFAULT,
// stated) folds to 0; all other values ride unchanged (real domains live
// in the 100000+ band, so 1 is unambiguous). Unstated (0) shares the
// default space — fail-closed: an install of unknown domain consults
// default tombstones rather than bypassing them. Callers holding logical
// domains already (queue/recv paths) pass them straight through.
func scopedLogicalDomain(wire uint32) uint32 {
	if wire == 1 {
		return 0
	}
	return wire
}

func (s *SessionSync) noteHelperMirrorResult(af string, warned *atomic.Bool, err error) {
	if err == nil {
		warned.Store(false)
		return
	}
	s.stats.Errors.Add(1)
	if warned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: failed to mirror synced session into dataplane helper", "af", af, "err", err)
		return
	}
	slog.Debug("cluster sync: repeated synced-session helper mirror failure", "af", af, "err", err)
}

// noteBulkInstallOutcomeV4 records whether key needs a transport retry during
// the active authoritative receive bulk. Definitive outcomes clear old debt.
// It does not affect incremental sync accounting.
func (s *SessionSync) noteBulkInstallOutcomeV4(key dataplane.SessionKey, retry bool) {
	noteBulkInstallOutcomeCore(s, &s.bulkInstallFailedV4, key, retry)
}

// noteBulkInstallOutcomeV6 is the IPv6 twin of noteBulkInstallOutcomeV4.
func (s *SessionSync) noteBulkInstallOutcomeV6(key dataplane.SessionKeyV6, retry bool) {
	noteBulkInstallOutcomeCore(s, &s.bulkInstallFailedV6, key, retry)
}

// genGuardMapCap is the ABSOLUTE CEILING for the per-side EFFECTIVE guard
// caps: half of conntrack.MaxSessions, which counts forward+reverse entries
// while guard keys are forward sessions (#9915 F-044). Nothing reads it
// directly except maxCap()'s clamp; every map goes through sentCap()/recvCap().
//
// TWENTY-EIGHT map families share the two side caps. The sender side bounds
// SIXTEEN by sentCap() — genSentV4/V6, closeClassSentV4/V6 (#9412),
// tcpHandshakeSentV4/V6 (#10888), installTableSentV4/V6 (#9752),
// sourceNatICMPSentV4/V6 (#11064), policyIdentitySentV4/V6 (#14359),
// appTimeoutLogSentV4/V6 (#16700), and
// genSentScopedV4/V6 (#10512). The receiver side bounds TWELVE by recvCap() —
// recvGenV4/V6 (with their #9719 tombstone orders, which index the same
// entries rather than adding new ones), installTableRecvV4/V6,
// sourceNatICMPRecvV4/V6 (#11064), policyIdentityRecvV4/V6 (#14359),
// appTimeoutLogRecvV4/V6 (#16700), and
// recvGenScopedV4/V6 (#10512, with their own tombstone orders). Every family
// grows on full-of-live demand and skip-records at the cap.
//
// The EFFECTIVE cap starts at genGuardMapDefaultCap (the pre-#9915 static
// value) and grows by doubling, per side, whenever a map is full of LIVE
// entries with nothing evictable. Cross-epoch ceiling shrinks clamp the stored
// cap down (growGuardCapSide) and every read clamps to the ceiling in force
// (sentCap/recvCap); the receiver side is additionally reclaimed at a
// namespace-reset bulk barrier (resetRecvGen), while sender maps self-drain on
// delete-echo. All twenty-eight families are evicted on delete (#14358: a
// bare delete reclaims every scoped entry naming its tuple, and a delete in
// either space tombstones the other space at the same generation); the cap
// is a safety valve for keys whose delete never arrives (e.g. dropped close
// delta).
//
// #15039: the four scoped maps carry a tuple side index
// (scopedTupleIndex, one per scoped map). It holds no generations and is
// not a twenty-fifth family: it names the same entries, adds one set
// membership per scoped entry, and exists so a bare delete reaches its
// tuple's scoped entries without scanning the whole scoped map.
//
// Heap honesty (#9915 F-044 review): the ceiling costs nothing until the table
// genuinely fills, and per-map=wired is coverage-correct — one family can hold
// every session (an all-v4 table fills genSentV4 alone), so each map must be
// able to reach the full session count. The existing ~56B/entry measurement
// and 5M-entry heap estimate in docs/log/9915.md cover the original 14 maps;
// #11064 adds four bounded source-NAT identity maps and #14359 four bounded
// policy-identity maps (each entry additionally holds the rule-ID string,
// shared with the frame that stated it), and their possible cost is
// additional. The default 200k effective cap's ~157MB estimate is likewise
// pre-#11064/#14359, and demand growth past it requires helper-attested
// provisioned RAM via SetGenGuardSessionCap, so guard heap stays
// proportionate to the table it protects.
//
// Honesty notes the ceiling does NOT promise: fabric-redirected sessions
// consume TWO stamps (primary plus wire alias), so alias-heavy tables past
// ~50% still degrade safely to gen-0; the receiver records whatever wire keys
// arrive (IsReverse-ungated), so a corrupt peer emitting reverse keys spends
// the same safe fallback. Evicting a LIVE entry to make room would reintroduce
// #2170/#2198 and is FORBIDDEN — only tombstones are ever evicted (#9719).
//
// Overflow handling (#2198 F1): when a map is at cap, a NEW key is NOT
// recorded (skip-record-on-full) and an EXISTING key is updated in place. The
// map is NEVER cleared. Clearing the whole map would drop the stored
// generation of every live key, disabling the guard cluster-wide for a churn
// window — exactly the #2170 hazard the guard exists to close: a stale delete
// could then kill a live re-established session. A skipped new key degrades to
// gen-0 (unconditional delete / unconditional install), which is always SAFE
// — gen-0 never causes a wrongful delete of a *different* live incarnation,
// it only loses the stale-delete protection for that one new key.
//
// #9719: two arms of that safety valve were permanent rather than momentary.
//   - Receiver: a tombstone never frees its entry, so churn filled the map with
//     tombstones and then skip-recorded every new key until the next bulk. A new
//     key at the cap now evicts the oldest tombstone first (genTombstoneOrder).
//   - Sender: above the cap a new key was not stamped, so its delete went out
//     with generation 0. After an overflow, a missing stamp now draws a fresh
//     generation (takeDeleteGenV4).
const genGuardMapCap = conntrack.MaxSessions / 2

// genGuardMapDefaultCap is the starting effective cap: the pre-#9915 static
// value. Growth past it is strictly demand-driven (full-of-live), so quiet
// paths behave exactly as before.
const genGuardMapDefaultCap = 200000

// putGenBounded records gen for key in m without ever clearing the map or
// dropping the stored generation of an existing key. An existing key is always
// updated in place; a new key is recorded only while the map is below
// maxEntries. Returns true if the entry was stored. The caller holds the
// map's mutex and supplies the effective cap (SessionSync.genGuardCap).
// Generic over the two wire-key types.
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64, maxEntries int) bool {
	if _, exists := m[key]; exists {
		m[key] = gen
		return true
	}
	if len(m) >= maxEntries {
		// Map is full and this is a new key: skip-record. The key degrades to
		// gen-0 behavior, which is safe (see genGuardMapCap doc).
		return false
	}
	m[key] = gen
	return true
}

// --- #16173: generic cores behind the V4/V6 twin wrappers. The wrappers
// below stay as thin family-named methods (call sites and tests do not
// churn); the logic lives once here. NO familyTraits mega-generic: the
// dataplane store calls stay in the visibly separate install/delete
// wrappers, and these cores only ever touch the generation maps, their
// tombstone orders and tuple indexes, passed explicitly. Plain generic
// free functions only — no per-record closures on the guard paths (the
// scoped tupleOf extractor below is created once per wrapper call, not
// per record; every other core is closure-free).

// installGenGuardCore is the shared install-guard verdict (#2170):
// refuse a strictly-older install; a gen-0 incoming install applies but
// preserves the stored generation. Caller holds recvGenMu.
func installGenGuardCore[K comparable](m map[K]uint64, key K, incoming uint64) (record uint64, apply bool) {
	stored, ok := m[key]
	if ok && stored != 0 && incoming != 0 && incoming < stored {
		return 0, false
	}
	if incoming == 0 {
		// Legacy / unknown install: apply but keep the stored generation
		// (do not roll it back to 0).
		return stored, true
	}
	return incoming, true
}

// recordInstalledGenCore records a live install (bare space), evicting
// the oldest tombstone at the cap (#9719) and growing once on
// full-of-live. Caller holds recvGenMu.
func recordInstalledGenCore[K comparable](s *SessionSync, m *map[K]uint64, tombs *genTombstoneOrder[K], key K, gen uint64) {
	if gen == 0 {
		return
	}
	if *m == nil {
		*m = make(map[K]uint64)
	}
	stored, evicted := putGenEvictingTombstones(*m, tombs, key, gen, s.recvCap())
	if !stored && !evicted && s.growRecvCap() {
		stored, evicted = putGenEvictingTombstones(*m, tombs, key, gen, s.recvCap())
	}
	if evicted {
		s.stats.GenTombstonesEvicted.Add(1)
	}
	if stored {
		// The key is live again; a tombstone it held is superseded by this
		// generation, which the install guard already required to be >= it.
		tombs.forget(key)
	} else {
		s.stats.GenMapOverflow.Add(1)
	}
}

// recordInstalledGenScopedCore is recordInstalledGenCore for a scoped
// map plus its tuple index. Caller holds recvGenMu.
func recordInstalledGenScopedCore[K comparable, SK comparable](s *SessionSync, m *map[SK]uint64, tombs *genTombstoneOrder[SK], ix *scopedTupleIndex[K, SK], tupleOf func(SK) K, skey SK, gen uint64) {
	if gen == 0 {
		return
	}
	if *m == nil {
		*m = make(map[SK]uint64)
	}
	recordScopedGen(s, m, tombs, ix, tupleOf, skey, gen, false)
}

// tombstoneBareCore records a bare tombstone at gen (or evicts on
// gen-0), mirroring the delete guard's record half without its refusal
// check. Caller holds recvGenMu. (#14358 cross-space coupling.)
func tombstoneBareCore[K comparable](s *SessionSync, m *map[K]uint64, tombs *genTombstoneOrder[K], key K, gen uint64) {
	if gen == 0 {
		delete(*m, key)
		tombs.forget(key)
		return
	}
	if *m == nil {
		*m = make(map[K]uint64)
	}
	stored, evicted := putGenEvictingTombstones(*m, tombs, key, gen, s.recvCap())
	if !stored && !evicted && s.growRecvCap() {
		stored, evicted = putGenEvictingTombstones(*m, tombs, key, gen, s.recvCap())
	}
	if evicted {
		s.stats.GenTombstonesEvicted.Add(1)
	}
	if stored {
		tombs.mark(key)
	} else {
		s.stats.GenMapOverflow.Add(1)
	}
}

// tombstoneScopedCore records a scoped tombstone (or evicts on gen-0)
// without a refusal check. Caller holds recvGenMu.
func tombstoneScopedCore[K comparable, SK comparable](s *SessionSync, m *map[SK]uint64, tombs *genTombstoneOrder[SK], ix *scopedTupleIndex[K, SK], tupleOf func(SK) K, skey SK, gen uint64) {
	if gen == 0 {
		deleteScopedGen(*m, ix, tupleOf(skey), skey)
		tombs.forget(skey)
		return
	}
	if *m == nil {
		*m = make(map[SK]uint64)
	}
	recordScopedGen(s, m, tombs, ix, tupleOf, skey, gen, true)
}

// recordScopedGen records gen for skey under the cap with tombstone
// eviction, then applies marked (tombstone vs live install bookkeeping
// in the tombstone order). Tuple-index membership is maintained by
// putScopedGenEvictingTombstones itself: it removes an evicted oldest
// tombstone from the index and adds every stored key (review H2 on
// PR #16236: no extra bookkeeping here). Caller holds recvGenMu.
func recordScopedGen[K comparable, SK comparable](s *SessionSync, m *map[SK]uint64, tombs *genTombstoneOrder[SK], ix *scopedTupleIndex[K, SK], tupleOf func(SK) K, skey SK, gen uint64, markTomb bool) {
	stored, evicted := putScopedGenEvictingTombstones(*m, tombs, ix, tupleOf, skey, gen, s.recvCap())
	if !stored && !evicted && s.growRecvCap() {
		stored, evicted = putScopedGenEvictingTombstones(*m, tombs, ix, tupleOf, skey, gen, s.recvCap())
	}
	if evicted {
		s.stats.GenTombstonesEvicted.Add(1)
	}
	if stored {
		if markTomb {
			tombs.mark(skey)
		} else {
			tombs.forget(skey)
		}
	} else {
		s.stats.GenMapOverflow.Add(1)
	}
}

// deleteGenGuardCore is the bare delete guard: refuse only a strictly
// older non-zero delete, then tombstone the bare entry and every scoped
// entry for the tuple at the delete generation (#14358 coupling), or
// evict all of them on a gen-0 (legacy) delete. Caller holds recvGenMu.
func deleteGenGuardCore[K comparable, SK comparable](s *SessionSync, bare *map[K]uint64, bareTombs *genTombstoneOrder[K], scoped *map[SK]uint64, scopedTombs *genTombstoneOrder[SK], ix *scopedTupleIndex[K, SK], tupleOf func(SK) K, key K, deleteGen uint64) bool {
	stored := (*bare)[key]
	if stored != 0 && deleteGen != 0 && deleteGen < stored {
		return false
	}
	// A scoped tombstone for this tuple also orders bare deletes (a bare
	// delete names no domain); live scoped entries of colliding tenants
	// never refuse it.
	for _, skey := range ix.keys(key) {
		if _, isTomb := scopedTombs.elems[skey]; !isTomb {
			continue
		}
		if tg := (*scoped)[skey]; tg != 0 && deleteGen != 0 && deleteGen < tg {
			return false
		}
	}
	if deleteGen != 0 {
		tombstoneBareCore(s, bare, bareTombs, key, deleteGen)
		for _, skey := range ix.keys(key) {
			if (*scoped)[skey] > deleteGen {
				continue
			}
			tombstoneScopedCore(s, scoped, scopedTombs, ix, tupleOf, skey, deleteGen)
		}
	} else {
		delete(*bare, key)
		bareTombs.forget(key)
		for _, skey := range ix.keys(key) {
			deleteScopedGen(*scoped, ix, key, skey)
			scopedTombs.forget(skey)
		}
	}
	return true
}

// deleteGenGuardScopedCore is the scoped delete guard (#10512/#14358):
// refuse an older scoped delete against either space's high-water, then
// tombstone the scoped entry and raise (never create, never lower) an
// existing bare entry; a gen-0 delete evicts both. Caller holds recvGenMu.
func deleteGenGuardScopedCore[K comparable, SK comparable](s *SessionSync, scoped *map[SK]uint64, scopedTombs *genTombstoneOrder[SK], scopedIx *scopedTupleIndex[K, SK], tupleOf func(SK) K, bare *map[K]uint64, bareTombs *genTombstoneOrder[K], skey SK, key K, deleteGen uint64) bool {
	stored := (*scoped)[skey]
	if stored != 0 && deleteGen != 0 && deleteGen < stored {
		return false
	}
	if bareGen := (*bare)[key]; bareGen != 0 && deleteGen != 0 && deleteGen < bareGen {
		return false
	}
	if deleteGen != 0 {
		tombstoneScopedCore(s, scoped, scopedTombs, scopedIx, tupleOf, skey, deleteGen)
		// Raise-only: a colliding domain's scoped delete must not lower
		// (or create ordering against) a newer bare high-water.
		if cur := (*bare)[key]; cur != 0 && cur <= deleteGen {
			tombstoneBareCore(s, bare, bareTombs, key, deleteGen)
		}
	} else {
		deleteScopedGen(*scoped, scopedIx, key, skey)
		scopedTombs.forget(skey)
		delete(*bare, key)
		bareTombs.forget(key)
	}
	return true
}

// stampCloseClassSentCore records the close-class memo under the sender
// cap, growing once on full-of-live. Caller holds genSentMu.
func stampCloseClassSentCore[K comparable](s *SessionSync, m *map[K]sentCloseClass, key K, sessionID uint64, class *uint8) {
	if *m == nil {
		*m = make(map[K]sentCloseClass)
	}
	if _, ok := (*m)[key]; !ok && len(*m) >= s.sentCap() {
		s.growSentCap()
	}
	stampCloseClassLocked(*m, key, sessionID, class, s.sentCap())
}

// stampTCPHandshakeStateSentCore is the handshake-state twin of
// stampCloseClassSentCore. Caller holds genSentMu.
func stampTCPHandshakeStateSentCore[K comparable](s *SessionSync, m *map[K]sentTCPHandshakeState, key K, sessionID uint64, state *uint8) {
	if *m == nil {
		*m = make(map[K]sentTCPHandshakeState)
	}
	if _, ok := (*m)[key]; !ok && len(*m) >= s.sentCap() {
		s.growSentCap()
	}
	stampTCPHandshakeStateLocked(*m, key, sessionID, state, s.sentCap())
}

// noteBulkInstallOutcomeCore records whether key needs a transport retry
// during the active authoritative receive bulk. Definitive outcomes
// clear old debt. It does not affect incremental sync accounting.
func noteBulkInstallOutcomeCore[K comparable](s *SessionSync, m *map[K]struct{}, key K, retry bool) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	if !s.bulkInProgress {
		return
	}
	if !retry {
		delete(*m, key)
		return
	}
	// #16039: the failure-marker sets share the receive window's cap.
	// A marker past the combined cap invalidates the window instead of
	// growing without bound on an all-failing peer.
	if s.bulkRecvInvalid {
		return
	}
	if _, ok := (*m)[key]; ok {
		return
	}
	if len(s.bulkInstallFailedV4)+len(s.bulkInstallFailedV6) >= s.bulkRecvCap() {
		s.bulkRecvInvalid = true
		s.stats.BulkRecvCapped.Add(1)
		s.stats.BulkRecvAborted.Add(1)
		return
	}
	if *m == nil {
		*m = make(map[K]struct{})
	}
	(*m)[key] = struct{}{}
}

// putScopedGenBounded is putGenBounded for a scoped map plus its tuple
// index (#15039): the index gains skey exactly when the entry is stored.
// Caller holds the map's mutex.
func putScopedGenBounded[K comparable, SK comparable](m map[SK]uint64, ix *scopedTupleIndex[K, SK], tuple K, skey SK, gen uint64, maxEntries int) bool {
	stored := putGenBounded(m, skey, gen, maxEntries)
	if stored {
		ix.add(tuple, skey)
	}
	return stored
}

// deleteScopedGen deletes skey from a scoped map and its tuple index
// (#15039). Caller holds the map's mutex.
func deleteScopedGen[K comparable, SK comparable](m map[SK]uint64, ix *scopedTupleIndex[K, SK], tuple K, skey SK) {
	delete(m, skey)
	ix.remove(tuple, skey)
}

// sentCap/recvCap return the effective sender/receiver-side guard caps. Zero
// means never grown: the default. Callers hold genSentMu/recvGenMu
// respectively (plain ints, no atomics needed); every read and write runs
// under those mutexes. Stats reports cap-change counters separately and does
// not read either side cap.
//
// Clamp-at-read (#9915 F-044 review): the stored cap is clamped to the CURRENT
// maxCap on every read, so a wired-ceiling shrink (the setter tracks current)
// takes effect immediately even though the stored ints only grow and the maps
// never shrink. This closes the concurrent-shrink window structurally: no
// interleaving of a lock-free setter store with a guard-path read can observe
// an effective cap above the ceiling in force. "Nondecreasing within an epoch"
// (see growGuardCapSide) holds per stable maxCap; across a ceiling change the
// effective cap follows the ceiling down at once.
func (s *SessionSync) sentCap() int {
	if s == nil || s.genState.sentGenGuardCap == 0 {
		return genGuardMapDefaultCap
	}
	if max := s.maxCap(); s.genState.sentGenGuardCap > max {
		return max
	}
	return s.genState.sentGenGuardCap
}

func (s *SessionSync) recvCap() int {
	if s == nil || s.genState.recvGenGuardCap == 0 {
		return genGuardMapDefaultCap
	}
	if max := s.maxCap(); s.genState.recvGenGuardCap > max {
		return max
	}
	return s.genState.recvGenGuardCap
}

// maxCap returns the growth ceiling (#9915 F-044): the injected test override
// when set; else the wired helper session capacity clamped to
// [genGuardMapDefaultCap, genGuardMapCap]; else the default (unwired paths
// never grow past status quo — no provisioning proof, no new headroom).
func (s *SessionSync) maxCap() int {
	if s != nil && s.genState.genGuardMapCeilingOverride != 0 {
		return s.genState.genGuardMapCeilingOverride
	}
	if s != nil {
		if wired := s.genState.genGuardSessionCap.Load(); wired != 0 {
			if wired < uint64(genGuardMapDefaultCap) {
				return genGuardMapDefaultCap
			}
			if wired > uint64(genGuardMapCap) {
				return genGuardMapCap
			}
			return int(wired)
		}
	}
	return genGuardMapDefaultCap
}

// SetGenGuardSessionCap wires the helper-provisioned aggregate session
// capacity (logical sessions, worker_count × 131072) into guard sizing.
//
// Contract (reconciled #9915 review): a NONZERO report always overwrites, up
// AND down — a replacement reporting fewer workers shrinks the ceiling
// honestly instead of pinning it at a stale larger value. ZERO means
// "unknown" (a missed daemon report), not "zero capacity", and retains the
// last known value: a telemetry gap must not shrink live guards and
// skip-record sessions that provisioned RAM still covers. The maps
// themselves never shrink under either; only the growth ceiling moves.
// Lock-free by necessity: read on guard paths under genSentMu/recvGenMu and
// written from the daemon tick — a mutex here could invert lock order.
// Differs from the SetZoneRGMap mutex shape deliberately, for that reason.
func (s *SessionSync) SetGenGuardSessionCap(sessions uint64) {
	if sessions == 0 {
		return
	}
	s.genState.genGuardSessionCap.Store(sessions)
}

// growSentCap/growRecvCap double the side cap up to the ceiling; they report
// whether the cap grew. Called only when a map is full of LIVE entries, so
// churn (which always leaves evictable tombstones) never grows. Nondecreasing
// within an epoch (one stable maxCap); across a ceiling shrink the stored cap
// is clamped down instead of growing (see below). The receiver side is
// additionally reclaimed by resetRecvGen while the sender side self-drains on
// delete-echo and needs no reset. Growths AND clamp-downs are counted and
// logged — an operator-visible demand signal, not silent bloat.
func (s *SessionSync) growSentCap() bool {
	return s.growGuardCapSide(true)
}

func (s *SessionSync) growRecvCap() bool {
	return s.growGuardCapSide(false)
}

func (s *SessionSync) growGuardCapSide(sender bool) bool {
	if s == nil {
		return false
	}
	capPtr := &s.genState.recvGenGuardCap
	side := "receiver"
	if sender {
		capPtr = &s.genState.sentGenGuardCap
		side = "sender"
	}
	// One epoch-pinned ceiling read: maxCap is lock-free (atomic) and the
	// setter may move it mid-call, so every decision below compares against
	// THIS value rather than re-reading.
	max := s.maxCap()
	if s.genState.testGenCapAfterCeilingRead != nil {
		s.genState.testGenCapAfterCeilingRead()
	}
	cur := *capPtr
	if cur == 0 {
		cur = genGuardMapDefaultCap
	}
	if cur > max {
		// Cross-epoch shrink: the wired ceiling dropped below the stored cap.
		// Clamp the stored cap down to the ceiling in force. Maps keep their
		// entries (evicting live entries would reintroduce #2170); new
		// inserts follow the smaller ceiling via clamp-at-read. Reports
		// false: the cap did not grow.
		*capPtr = max
		n := s.stats.GenCapShrunk.Add(1)
		slog.Info("cluster sync: generation-guard cap clamped down to a shrunken ceiling",
			"side", side, "old", cur, "new", max, "shrunk_total", n)
		return false
	}
	if cur >= max {
		return false
	}
	grown := cur * 2
	if grown > max {
		grown = max
	}
	*capPtr = grown
	n := s.stats.GenCapGrown.Add(1)
	slog.Warn("cluster sync: generation-guard cap grew on full-of-live demand",
		"side", side, "old", cur, "new", grown, "grown_total", n)
	return true
}

// nextInstallGen returns the next strictly-monotonic install generation.
func (s *SessionSync) nextInstallGen() uint64 {
	return s.genState.genCounter.Add(1)
}

// fullSetSeqGuard is the receiver-side high-water mark for one FULL-SET sync
// stream (IPsec SA, or DHCP leases per family) under #5706. It records the
// last-applied (incarnation, seq) and admits only a strictly-newer pair, so a
// stale full-set delivered out of order across the redundant fabric
// receiveLoops (conn0/conn1) is dropped instead of regressing the held set.
//
// Ordering is lexicographic on (incarnation, seq): a strictly-higher
// incarnation always supersedes (a peer restart draws a fresh epoch), and
// within an incarnation the per-type seq orders the pushes. A LOWER
// incarnation is stale and refused — EXCEPT that the guard is reset() to zero
// on a namespace-reset peer bulk re-prime (resetRecvGen), so an OS-rebooted
// peer whose monotonic epoch restarts LOWER is re-accepted from its fresh set
// rather than stranded on the pre-reboot set (the #2198 F2 stale-RETAIN
// to full-set sync). The zero value is the initial/legacy state.
//
// Access is serialized by SessionSync.recvSeqMu because the two fabric
// receiveLoops can invoke admit concurrently.
type fullSetSeqGuard struct {
	incarnation uint64
	seq         uint64
}

// admit reports whether a full-set stamped (incarnation, seq) is strictly
// newer than the last-applied pair and, when it is, advances the high-water
// mark. incarnation==0 || seq==0 marks a LEGACY (pre-#5706) sender that sends
// no ordering trailer: admit-always and do NOT advance the mark, mirroring the
// config-gen gen==0 accept-always compat. The caller holds recvSeqMu.
//
// Kept as the atomic check-and-advance operation for callers and tests that
// need it. Receiver full-set arms split the check from the advance so malformed
// or filtered frames do not consume a sequence number.
func (g *fullSetSeqGuard) admit(incarnation, seq uint64) bool {
	if !g.newer(incarnation, seq) {
		return false
	}
	g.advanceIfNewer(incarnation, seq)
	return true
}

// newer reports whether (incarnation, seq) is strictly newer than the
// high-water mark, without moving it. Legacy (0,0) is always newer. The caller
// holds recvSeqMu.
func (g *fullSetSeqGuard) newer(incarnation, seq uint64) bool {
	if incarnation == 0 || seq == 0 {
		return true // legacy sender — no sequence, accept-always
	}
	return g.incarnation == 0 ||
		incarnation > g.incarnation ||
		(incarnation == g.incarnation && seq > g.seq)
}

// advanceIfNewer moves the high-water mark to (incarnation, seq) iff it is
// still strictly newer, reporting whether it advanced. Legacy (0,0) reports
// true without touching the mark (admit-always, never advances). The caller
// holds recvSeqMu; calling it at apply time (after decode+filter) lets a
// duplicate-fabric twin that already applied win the race instead of
// regressing the held set.
func (g *fullSetSeqGuard) advanceIfNewer(incarnation, seq uint64) bool {
	if incarnation == 0 || seq == 0 {
		return true
	}
	if g.incarnation == 0 ||
		incarnation > g.incarnation ||
		(incarnation == g.incarnation && seq > g.seq) {
		g.incarnation = incarnation
		g.seq = seq
		return true
	}
	return false
}

// reset returns the guard to its zero (accept-next) state. Called from
// resetRecvGen on a peer bulk re-prime so a rebooted peer with a lower epoch is
// re-accepted. The caller holds recvSeqMu.
func (g *fullSetSeqGuard) reset() {
	g.incarnation = 0
	g.seq = 0
}

// configEpochReverseTag (#11055) is the stamp-source tag bit carried in the
// top bit of SessionValue.ConfigEpoch. Generations derive from MonotonicNanos
// (initGenState), so the top bit is unused for centuries and reserving it is a
// semantic tag inside the existing field, not a wire-layout change: no
// ProtocolVersion bump, and session trailers stay length-gated as before.
//
// A legacy receiver reads a tagged value as a very large generation, which its
// unsigned epoch < barrier comparison admits — fail-OPEN. A current authority
// strips the tag and compares the raw generation against its own config send
// counter.
const configEpochReverseTag = uint64(1) << 63

const configEpochGenMask = ^configEpochReverseTag

// observeConfigEpochRole records role transitions without taking configGenMu.
// A retained applied high-water from before promotion does not identify the
// current authority's generation namespace, so demotion establishes a floor
// that only a newly applied generation can cross.
func (s *SessionSync) observeConfigEpochRole(primary bool) {
	s.configEpochRoleMu.Lock()
	defer s.configEpochRoleMu.Unlock()
	if !s.configEpochRoleKnown {
		s.configEpochRoleKnown = true
		s.configEpochRolePrimary = primary
		if !primary {
			s.configEpochReverseFloor = s.lastAppliedConfigGen.Load()
		}
		return
	}
	if s.configEpochRolePrimary == primary {
		return
	}
	s.configEpochRolePrimary = primary
	if !primary {
		s.configEpochReverseFloor = s.lastAppliedConfigGen.Load()
	}
}

func (s *SessionSync) resetConfigEpochReverseFloor() {
	s.configEpochRoleMu.Lock()
	s.configEpochReverseFloor = 0
	s.configEpochRoleMu.Unlock()
}

// stampConfigEpoch returns the config epoch to stamp on an outbound synced
// session (#11055). An authority — and an unwired node — stamps its local
// send counter. A non-authority uses its converged applied generation. It
// sends that generation tagged only after the peer advertises support and the
// mark is newer than the floor captured on entry to this authority tenure.
// An unlearned or legacy peer gets the original untagged local send-counter
// stamp; divergent or unproven capable-peer namespaces get epoch 0 to preserve
// fail-open behavior.
func (s *SessionSync) stampConfigEpoch() uint64 {
	if s.IsPrimaryFn == nil {
		return s.configGenCounter.Load()
	}
	primary := s.IsPrimaryFn()
	s.observeConfigEpochRole(primary)
	if primary {
		return s.configGenCounter.Load()
	}
	if !s.peerCapabilitiesLearned() || !s.PeerConfigEpochReverseTagCapable() {
		return s.configGenCounter.Load()
	}
	applied := s.lastAppliedConfigGen.Load()
	if applied == 0 || applied != s.lastRecvConfigGen.Load() {
		return 0
	}
	s.configEpochRoleMu.Lock()
	floor := s.configEpochReverseFloor
	s.configEpochRoleMu.Unlock()
	if applied <= floor {
		return 0
	}
	return configEpochReverseTag | (applied & configEpochGenMask)
}

// stampInstallGenV4 assigns a fresh install generation to a v4 session being
// sent and records it (keyed by wire key) so the matching delete can echo the
// exact generation of the install it cancels (#2170 SMR fix #1). It mutates
// val.Generation in place. A re-send (sweep/bulk) of a live key intentionally
// bumps the generation: the per-key stored generation only ever climbs, so a
// journaled delete from before the re-send is strictly older and refused.
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) {
	// #7095/#12075/#15176: stamp the cluster-stable folds on the same
	// pass as the generation (before the shared record pass).
	val.IngressIfaceFold = s.stampIngressIfaceFold(val.IngressIfindex, val.IngressVlanID)
	val.EgressIfaceFold = s.stampEgressIfaceFold(val.FibIfindex, val.FibVlanID)
	val.NatScopeFold = s.stampNatScopeFold(val.NatScopeIfindex)
	stampInstallGen(s, key, sessionValueView{val}, &val.Generation, &val.ConfigEpoch,
		&s.genState.genSentV4, &s.genState.genSentOverflowV4,
		&s.genState.genSentScopedV4, &s.genState.genSentScopedByTupleV4, &s.genState.genSentOverflowScopedV4,
		scopedKeyOf,
		&s.genState.closeClassSentV4, &s.genState.tcpHandshakeSentV4, &s.genState.installTableSentV4,
		&s.genState.sourceNatICMPSentV4, &s.genState.policyIdentitySentV4, &s.genState.appTimeoutLogSentV4,
		&s.genState.installTableRecvV4, &s.genState.sourceNatICMPRecvV4, &s.genState.policyIdentityRecvV4, &s.genState.appTimeoutLogRecvV4)
}

// stampInstallGenV6 is the IPv6 twin of stampInstallGenV4.
func (s *SessionSync) stampInstallGenV6(key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) {
	val.IngressIfaceFold = s.stampIngressIfaceFold(val.IngressIfindex, val.IngressVlanID)
	val.EgressIfaceFold = s.stampEgressIfaceFold(val.FibIfindex, val.FibVlanID)
	val.NatScopeFold = s.stampNatScopeFold(val.NatScopeIfindex)
	stampInstallGen(s, key, sessionValueV6View{val}, &val.Generation, &val.ConfigEpoch,
		&s.genState.genSentV6, &s.genState.genSentOverflowV6,
		&s.genState.genSentScopedV6, &s.genState.genSentScopedByTupleV6, &s.genState.genSentOverflowScopedV6,
		scopedKeyOfV6,
		&s.genState.closeClassSentV6, &s.genState.tcpHandshakeSentV6, &s.genState.installTableSentV6,
		&s.genState.sourceNatICMPSentV6, &s.genState.policyIdentitySentV6, &s.genState.appTimeoutLogSentV6,
		&s.genState.installTableRecvV6, &s.genState.sourceNatICMPRecvV6, &s.genState.policyIdentityRecvV6, &s.genState.appTimeoutLogRecvV6)
}

// sessionStampView is the per-family field view stampInstallGen needs.
// SessionValue and SessionValueV6 carry the sync-only stamp fields under
// identical names and types; the local wrappers below adapt each to this
// view over its own fields. The dataplane store paths stay
// family-specific (PutClusterSyncedV4/V6 are genuinely different) — only
// the stamping pass is shared (#16173).
type sessionStampView interface {
	stampSessionID() uint64
	stampRoutingDomainWire() uint32
	stampTCPCloseClass() *uint8
	stampTCPHandshakeState() *uint8
	stampInstallTable() (*uint32, *uint32)
	stampSourceNatICMP() (*bool, *uint8, *uint8)
	stampPolicyIdentity() (*string, *uint32)
	stampAppTimeoutLog() (*uint32, *uint8)
}

type sessionValueView struct{ v *dataplane.SessionValue }

func (w sessionValueView) stampSessionID() uint64         { return w.v.SessionID }
func (w sessionValueView) stampRoutingDomainWire() uint32 { return w.v.RoutingDomain }
func (w sessionValueView) stampTCPCloseClass() *uint8     { return &w.v.TCPCloseClass }
func (w sessionValueView) stampTCPHandshakeState() *uint8 { return &w.v.TCPHandshakeState }
func (w sessionValueView) stampInstallTable() (*uint32, *uint32) {
	return &w.v.InstallTableDomain, &w.v.InstallTableCheck
}
func (w sessionValueView) stampSourceNatICMP() (*bool, *uint8, *uint8) {
	return &w.v.SourceNatICMPValid, &w.v.SourceNatICMPType, &w.v.SourceNatICMPCode
}
func (w sessionValueView) stampPolicyIdentity() (*string, *uint32) {
	return &w.v.PolicyRuleID, &w.v.PolicyCounterIdx
}
func (w sessionValueView) stampAppTimeoutLog() (*uint32, *uint8) {
	return &w.v.AppTimeout, &w.v.LogFlags
}

type sessionValueV6View struct{ v *dataplane.SessionValueV6 }

func (w sessionValueV6View) stampSessionID() uint64         { return w.v.SessionID }
func (w sessionValueV6View) stampRoutingDomainWire() uint32 { return w.v.RoutingDomain }
func (w sessionValueV6View) stampTCPCloseClass() *uint8     { return &w.v.TCPCloseClass }
func (w sessionValueV6View) stampTCPHandshakeState() *uint8 { return &w.v.TCPHandshakeState }
func (w sessionValueV6View) stampInstallTable() (*uint32, *uint32) {
	return &w.v.InstallTableDomain, &w.v.InstallTableCheck
}
func (w sessionValueV6View) stampSourceNatICMP() (*bool, *uint8, *uint8) {
	return &w.v.SourceNatICMPValid, &w.v.SourceNatICMPType, &w.v.SourceNatICMPCode
}
func (w sessionValueV6View) stampPolicyIdentity() (*string, *uint32) {
	return &w.v.PolicyRuleID, &w.v.PolicyCounterIdx
}
func (w sessionValueV6View) stampAppTimeoutLog() (*uint32, *uint8) {
	return &w.v.AppTimeout, &w.v.LogFlags
}

// scopedKeyOf/scopedKeyOfV6 build the scoped sender keys; plain
// functions (not closures) so the stamp pass stays allocation-free.
func scopedKeyOf(domain uint32, key dataplane.SessionKey) scopedDeleteKeyV4 {
	return scopedDeleteKeyV4{Domain: domain, Key: key}
}

func scopedKeyOfV6(domain uint32, key dataplane.SessionKeyV6) scopedDeleteKeyV6 {
	return scopedDeleteKeyV6{Domain: domain, Key: key}
}

// stampInstallGen is the shared sender stamping pass behind
// stampInstallGenV4/V6 (#16173 (3) generic recv/send core). It draws a
// fresh generation, stamps the cluster-stable folds and config epoch,
// records the bare + scoped sender generations under genSentMu, and
// refreshes/restores the sync-only memos (close class, handshake state,
// installing-table, source-NAT ICMP, policy identity) exactly as the
// twin bodies did. The store-facing value types stay distinct through
// sessionStampView; no dataplane store call happens here.
func stampInstallGen[K comparable, SK comparable](
	s *SessionSync,
	key K,
	view sessionStampView,
	genOut, configEpochOut *uint64,
	genSent *map[K]uint64,
	overflow *bool,
	genSentScoped *map[SK]uint64,
	scopedIx *scopedTupleIndex[K, SK],
	overflowScoped *bool,
	makeScoped func(uint32, K) SK,
	closeClassSent *map[K]sentCloseClass,
	handshakeSent *map[K]sentTCPHandshakeState,
	installTableSent *map[K]sentInstallTable,
	sourceNatSent *map[K]sourceNatICMPMemo,
	policySent *map[K]policyIdentityMemo,
	appTimeoutLogSent *map[K]appTimeoutLogMemo,
	installTableRecv *map[K]recvInstallTable,
	sourceNatRecv *map[K]sourceNatICMPMemo,
	policyRecv *map[K]policyIdentityMemo,
	appTimeoutLogRecv *map[K]appTimeoutLogMemo,
) {
	g := s.nextInstallGen()
	*genOut = g
	*configEpochOut = s.stampConfigEpoch()
	sessionID := view.stampSessionID()
	s.genState.genSentMu.Lock()
	if *genSent == nil {
		*genSent = make(map[K]uint64)
	}
	stored := putGenBounded(*genSent, key, g, s.sentCap())
	if !stored && s.growSentCap() {
		stored = putGenBounded(*genSent, key, g, s.sentCap())
	}
	if !stored {
		s.stats.GenMapOverflow.Add(1)
		// #9719: from now on a missing stamp no longer means "never sent
		// in this boot"; see takeDeleteGenV4.
		*overflow = true
	}
	// #10512: stamp the scoped sender space alongside (same generation,
	// keyed by installing domain from the value).
	skey := makeScoped(scopedLogicalDomain(view.stampRoutingDomainWire()), key)
	if *genSentScoped == nil {
		*genSentScoped = make(map[SK]uint64)
	}
	storedScoped := putScopedGenBounded(*genSentScoped, scopedIx, key, skey, g, s.sentCap())
	if !storedScoped && s.growSentCap() {
		storedScoped = putScopedGenBounded(*genSentScoped, scopedIx, key, skey, g, s.sentCap())
	}
	if !storedScoped {
		s.stats.GenMapOverflow.Add(1)
		*overflowScoped = true
	}
	// #9412: keep this frame from regressing the close class already sent
	// for the same incarnation (a mirror-sourced resend carries 0).
	stampCloseClassSentCore(s, closeClassSent, key, sessionID, view.stampTCPCloseClass())
	// #10888: mirror resends must retain the last handshake phase sent.
	stampTCPHandshakeStateSentCore(s, handshakeSent, key, sessionID, view.stampTCPHandshakeState())
	// #9752: keep this frame from regressing the installing-table identity.
	itDomain, itCheck := view.stampInstallTable()
	if *installTableSent == nil {
		*installTableSent = make(map[K]sentInstallTable)
	}
	if !stampInstallTableLocked(*installTableSent, key, sessionID, itDomain, itCheck, s.sentCap()) && s.growSentCap() {
		stampInstallTableLocked(*installTableSent, key, sessionID, itDomain, itCheck, s.sentCap())
	}
	if *itDomain != 0 || *itCheck != 0 {
		s.pbrAnnouncedForFence.Store(true)
	}
	// #9752 round 3 item 5: still (0,0)? Restore from the receive record
	// (read-only). genSentMu nests recvGenMu here; recvGenMu never
	// acquires outwards, so no cycle.
	if *itDomain == 0 && *itCheck == 0 && sessionID != 0 {
		s.genState.recvGenMu.Lock()
		if domain, check, ok := lookupRecvInstallTableLocked(*installTableRecv, key, sessionID); ok {
			*itDomain, *itCheck = domain, check
		}
		s.genState.recvGenMu.Unlock()
	}
	// #11064: typed source-NAT identity is sync-only; restore last sent.
	snValid, snType, snCode := view.stampSourceNatICMP()
	if *sourceNatSent == nil {
		*sourceNatSent = make(map[K]sourceNatICMPMemo)
	}
	if !stampSourceNatICMPLocked(*sourceNatSent, key, sessionID, snValid, snType, snCode, s.sentCap()) && s.growSentCap() {
		stampSourceNatICMPLocked(*sourceNatSent, key, sessionID, snValid, snType, snCode, s.sentCap())
	}
	if !*snValid && sessionID != 0 {
		s.genState.recvGenMu.Lock()
		if icmpType, icmpCode, ok := lookupSourceNatICMPLocked(*sourceNatRecv, key, sessionID); ok {
			*snValid, *snType, *snCode = true, icmpType, icmpCode
		}
		s.genState.recvGenMu.Unlock()
	}
	// #14359: policy identity is sync-only; restore last sent / received.
	ruleID, counter := view.stampPolicyIdentity()
	if *policySent == nil {
		*policySent = make(map[K]policyIdentityMemo)
	}
	if !stampPolicyIdentityLocked(*policySent, key, sessionID, ruleID, counter, s.sentCap()) && s.growSentCap() {
		stampPolicyIdentityLocked(*policySent, key, sessionID, ruleID, counter, s.sentCap())
	}
	if *ruleID == "" && *counter == 0 && sessionID != 0 {
		s.genState.recvGenMu.Lock()
		if rid, cnt, ok := lookupPolicyIdentityLocked(*policyRecv, key, sessionID); ok {
			*ruleID, *counter = rid, cnt
		}
		s.genState.recvGenMu.Unlock()
	}
	// #16700: per-app timeout (incl. 86401 never) and then-log flags;
	// restore last sent / received on a stamp-less mirror resend.
	appTimeout, logFlags := view.stampAppTimeoutLog()
	if *appTimeoutLogSent == nil {
		*appTimeoutLogSent = make(map[K]appTimeoutLogMemo)
	}
	if !stampAppTimeoutLogLocked(*appTimeoutLogSent, key, sessionID, appTimeout, logFlags, s.sentCap()) && s.growSentCap() {
		stampAppTimeoutLogLocked(*appTimeoutLogSent, key, sessionID, appTimeout, logFlags, s.sentCap())
	}
	if *appTimeout == 0 && *logFlags == 0 && sessionID != 0 {
		s.genState.recvGenMu.Lock()
		if at, lf, ok := lookupAppTimeoutLogLocked(*appTimeoutLogRecv, key, sessionID); ok {
			*appTimeout, *logFlags = at, lf
		}
		s.genState.recvGenMu.Unlock()
	}
	s.genState.genSentMu.Unlock()
}

// stampCloseClassSentV4/V6 record the close class under the sender-side cap,
// growing once on full-of-live like the generation stamps. Callers hold genSentMu.
func (s *SessionSync) stampCloseClassSentV4(key dataplane.SessionKey, sessionID uint64, class *uint8) {
	stampCloseClassSentCore(s, &s.genState.closeClassSentV4, key, sessionID, class)
}

func (s *SessionSync) stampCloseClassSentV6(key dataplane.SessionKeyV6, sessionID uint64, class *uint8) {
	stampCloseClassSentCore(s, &s.genState.closeClassSentV6, key, sessionID, class)
}

// sentTCPHandshakeState records the greatest TCP handshake stage sent for one
// session incarnation. The BPF mirror drops this sync-only field, so sweep and
// bulk resends restore it from this bounded sender memo.
type sentTCPHandshakeState struct {
	sessionID uint64
	state     uint8
}

// stampTCPHandshakeStateLocked preserves the monotonic stage for one tuple
// and SessionID. A new SessionID discards the old value even when the new
// state is zero; SessionID zero has no safe incarnation identity and is not
// memoized. Callers hold genSentMu and enforce maxEntries.
func stampTCPHandshakeStateLocked[K comparable](
	m map[K]sentTCPHandshakeState,
	key K,
	sessionID uint64,
	state *uint8,
	maxEntries int,
) {
	next := dataplane.NormalizeTCPHandshakeState(*state)
	if sessionID == 0 {
		*state = next
		return
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		delete(m, key)
		ok = false
	}
	if ok && rec.state > next {
		next = rec.state
	}
	*state = next
	if next == dataplane.TCPHandshakeStateAbsent {
		return
	}
	if !ok && len(m) >= maxEntries {
		// Skip-record-on-full; a missed memo degrades only a later mirror
		// resend, never the currently queued stage.
		return
	}
	m[key] = sentTCPHandshakeState{sessionID: sessionID, state: next}
}

func (s *SessionSync) stampTCPHandshakeStateSentV4(
	key dataplane.SessionKey, sessionID uint64, state *uint8,
) {
	stampTCPHandshakeStateSentCore(s, &s.genState.tcpHandshakeSentV4, key, sessionID, state)
}

func (s *SessionSync) stampTCPHandshakeStateSentV6(
	key dataplane.SessionKeyV6, sessionID uint64, state *uint8,
) {
	stampTCPHandshakeStateSentCore(s, &s.genState.tcpHandshakeSentV6, key, sessionID, state)
}

// takeDeleteGenV4 returns the generation a delete for this wire key should
// carry and evicts the sender-side stamp.
//
// #2221: the delete draws a FRESH, strictly-greater generation
// (nextInstallGen) rather than echoing the install's stamp. The stamp and the
// sendCh enqueue are not atomic and two producer goroutines (the sweep
// stamping a live re-send, the delta-drain taking the close) mutate the same
// key, so a delete can be enqueued onto sendCh BEFORE the install it cancels.
// On the wire the receiver then applies delete then install with IDENTICAL
// generations; the receiver guards only refuse a STRICTLY-older operation, so
// the late install resurrects the closed session (the #2170 residual:
// stale-RETAIN rather than stale-delete). Drawing a fresh generation that is
// strictly greater than every prior install of this key makes a delete always
// out-rank the install it cancels: the receiver's install guard refuses a
// reordered older install (incoming < the delete tombstone), while a genuinely
// newer incarnation (re-established + re-stamped by a later sweep) carries an
// even higher generation and still applies. This composes with #2170: the
// per-key generation only ever climbs, so a journaled stale delete from before
// a re-sync is still strictly older than the live entry and refused.
//
// A key never installed in this boot (no stamp recorded) returns 0 (legacy
// fallback → unconditional delete in the apply guard), which is the safe
// behavior and preserves rolling-upgrade compatibility.
//
// #9719: once the stamp map has overflowed, a missing stamp no longer implies
// that. The key may be a live session whose stamp was skipped at the cap, and 0
// would make its delete unconditional on the receiver. So after an overflow a
// missing stamp draws a fresh generation too. The receiver refuses such a
// delete only while it holds a NEWER generation for the key, which is the
// correct answer.
func (s *SessionSync) takeDeleteGenV4(key dataplane.SessionKey) uint64 {
	return takeDeleteGen(s, key,
		&s.genState.genSentV4, &s.genState.genSentOverflowV4,
		&s.genState.genSentScopedV4, &s.genState.genSentScopedByTupleV4,
		&s.genState.closeClassSentV4, &s.genState.tcpHandshakeSentV4,
		&s.genState.installTableSentV4, &s.genState.sourceNatICMPSentV4, &s.genState.policyIdentitySentV4, &s.genState.appTimeoutLogSentV4,
		&s.genState.installTableRecvV4, &s.genState.sourceNatICMPRecvV4, &s.genState.policyIdentityRecvV4, &s.genState.appTimeoutLogRecvV4)
}

func (s *SessionSync) takeDeleteGenV6(key dataplane.SessionKeyV6) uint64 {
	return takeDeleteGen(s, key,
		&s.genState.genSentV6, &s.genState.genSentOverflowV6,
		&s.genState.genSentScopedV6, &s.genState.genSentScopedByTupleV6,
		&s.genState.closeClassSentV6, &s.genState.tcpHandshakeSentV6,
		&s.genState.installTableSentV6, &s.genState.sourceNatICMPSentV6, &s.genState.policyIdentitySentV6, &s.genState.appTimeoutLogSentV6,
		&s.genState.installTableRecvV6, &s.genState.sourceNatICMPRecvV6, &s.genState.policyIdentityRecvV6, &s.genState.appTimeoutLogRecvV6)
}

// takeDeleteGen is the shared sender take-delete behind
// takeDeleteGenV4/V6 (#16173): forget the incarnation's sync-only memos,
// reclaim every scoped stamp for the tuple, then draw a fresh
// strictly-greater generation for a stamped key (0 for a never-stamped
// key, fresh again once the stamp map has overflowed, #9719). The long
// #2221/#9719 rationale lives on takeDeleteGenV4 above.
func takeDeleteGen[K comparable, SK comparable](
	s *SessionSync,
	key K,
	genSent *map[K]uint64,
	overflow *bool,
	genSentScoped *map[SK]uint64,
	scopedIx *scopedTupleIndex[K, SK],
	closeClassSent *map[K]sentCloseClass,
	handshakeSent *map[K]sentTCPHandshakeState,
	installTableSent *map[K]sentInstallTable,
	sourceNatSent *map[K]sourceNatICMPMemo,
	policySent *map[K]policyIdentityMemo,
	appTimeoutLogSent *map[K]appTimeoutLogMemo,
	installTableRecv *map[K]recvInstallTable,
	sourceNatRecv *map[K]sourceNatICMPMemo,
	policyRecv *map[K]policyIdentityMemo,
	appTimeoutLogRecv *map[K]appTimeoutLogMemo,
) uint64 {
	if hook := s.testBeforeDeleteGen; hook != nil {
		hook()
	}
	s.bulkSnapshotGenMu.Lock()
	defer s.bulkSnapshotGenMu.Unlock()
	s.genState.genSentMu.Lock()
	defer s.genState.genSentMu.Unlock()
	// #9412: the incarnation is being deleted; forget its close class.
	// Before the early return, so a key with no generation stamp is
	// still evicted.
	delete(*closeClassSent, key)
	delete(*handshakeSent, key)
	// #14358: a bare close names no domain, so reclaim every scoped
	// stamp for this tuple (#15039: via the tuple index, not a scan).
	for _, skey := range scopedIx.keys(key) {
		deleteScopedGen(*genSentScoped, scopedIx, key, skey)
	}
	// #9752: same for its installing-table identity.
	delete(*installTableSent, key)
	delete(*sourceNatSent, key)
	delete(*policySent, key)
	delete(*appTimeoutLogSent, key)
	// #9752 round 3: and for the identity received for it (genSentMu is
	// a leaf, so nesting recvGenMu here cannot cycle).
	s.genState.recvGenMu.Lock()
	delete(*installTableRecv, key)
	delete(*sourceNatRecv, key)
	delete(*policyRecv, key)
	delete(*appTimeoutLogRecv, key)
	s.genState.recvGenMu.Unlock()
	if _, ok := (*genSent)[key]; !ok {
		if *overflow {
			// #9719: the stamp map has overflowed in this process, so
			// this key may be a LIVE session whose stamp was skipped at
			// the cap. Sending 0 would make the receiver apply the
			// delete unconditionally.
			return s.nextInstallGen()
		}
		return 0
	}
	delete(*genSent, key)
	gen := s.nextInstallGen()
	if hook := s.testAfterDeleteGen; hook != nil {
		hook()
	}
	return gen
}

// takeDeleteGenScopedV4 draws the delete generation for a SCOPED
// (domain, tuple) policy delete (#10512) against the per-scoped-key
// stamp space (plan §1.2 keyed sender state): fresh strictly greater
// than the install it cancels, evicting the stamp; unstamped draws 0
// legacy fallback (fresh on #9719 overflow). Scoped touches
// scoped-only: bare sender stamps (possibly another tenant's) are
// never disturbed. Test hooks shared with the bare twin.
func (s *SessionSync) takeDeleteGenScopedV4(domain uint32, key dataplane.SessionKey) uint64 {
	return takeDeleteGenScoped(s, scopedKeyOf(domain, key), key,
		&s.genState.genSentScopedV4, &s.genState.genSentScopedByTupleV4, &s.genState.genSentOverflowScopedV4)
}

// takeDeleteGenScopedV6 is the IPv6 twin of takeDeleteGenScopedV4.
func (s *SessionSync) takeDeleteGenScopedV6(domain uint32, key dataplane.SessionKeyV6) uint64 {
	return takeDeleteGenScoped(s, scopedKeyOfV6(domain, key), key,
		&s.genState.genSentScopedV6, &s.genState.genSentScopedByTupleV6, &s.genState.genSentOverflowScopedV6)
}

func takeDeleteGenScoped[K comparable, SK comparable](
	s *SessionSync,
	skey SK,
	key K,
	genSentScoped *map[SK]uint64,
	scopedIx *scopedTupleIndex[K, SK],
	overflowScoped *bool,
) uint64 {
	if hook := s.testBeforeDeleteGen; hook != nil {
		hook()
	}
	s.bulkSnapshotGenMu.Lock()
	defer s.bulkSnapshotGenMu.Unlock()
	s.genState.genSentMu.Lock()
	defer s.genState.genSentMu.Unlock()
	if _, ok := (*genSentScoped)[skey]; !ok {
		if *overflowScoped {
			return s.nextInstallGen() // #9719: see takeDeleteGenV4.
		}
		return 0
	}
	deleteScopedGen(*genSentScoped, scopedIx, key, skey)
	gen := s.nextInstallGen()
	if hook := s.testAfterDeleteGen; hook != nil {
		hook()
	}
	return gen
}

// installGenGuardV4 implements the receiver-side install-side guard (#2170 SMR
// fix #2): refuse to overwrite a stored entry with a strictly-older-generation
// install so the per-key stored generation never regresses. Returns the
// generation to record on a successful apply (the incoming generation, or the
// preserved stored generation when the incoming one is 0). The bool reports
// whether the install should proceed.
// WHAT THESE GUARDS ARE, AND THE ONE THING THEY ARE REPEATEDLY READ AS (#9048).
//
// installGenGuardV4/V6 and deleteGenGuardV4/V6 are per-key REORDERING guards
// for ONE sender's stream (#2170). They answer "is this delta older than the
// last one I applied for this key?" and nothing else.
//
// `stored == 0` therefore means "I HAVE NO ORDERING INFORMATION FOR THIS KEY",
// not "this delta is safe". recvGenV4 is populated solely by
// recordInstalledGenV4 — prior PEER installs — so a session THIS node created
// itself has no stored generation and both guards admit anything for it. That
// reads like a fall-through defect and it is not one: with no prior peer
// install there is no ordering to violate, and refusing on gen-0 would break
// every legitimate first install and every legacy (pre-#2170) sender, which is
// exactly what the `incoming == 0` / `deleteGen == 0` arms are for.
//
// THEY ARE NOT OWNERSHIP GUARDS, and nothing here should become one. "May this
// peer touch a session this node owns and is forwarding for?" is a different
// question with different inputs (local origin + local HA state), and it is
// answered one layer down in the dataplane helper, where both facts actually
// live:
//
//   - INSTALL: SessionTable::upsert_synced_with_origin refuses to clobber a
//     local-origin entry unless synced_entry_allows_local_replace says the
//     incoming entry's owner RG is not locally forwarding-active.
//   - DELETE: handle_delete_synced refuses to tear down a local-origin entry
//     whose owner RG IS locally forwarding-active, counting
//     PEER_DELETE_REFUSED_LOCAL_OWNED (#9048). Until then only the install
//     verb had a guard, and the asymmetry was invisible because the two verbs
//     are guarded in different files at different layers.
//
// Both are inert in normal operation: the delta EMITTER is gated on
// IsPrimaryForRGFn, so exactly one node emits and the receiver's entries at
// those keys carry a peer-synced origin. They fire only when both nodes are
// primary for the same RG, which is what makes that helper counter a
// split-brain indicator rather than a tuning knob.
func (s *SessionSync) installGenGuardV4(key dataplane.SessionKey, incoming uint64) (record uint64, apply bool) {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return installGenGuardCore(s.genState.recvGenV4, key, incoming)
}

func (s *SessionSync) installGenGuardV6(key dataplane.SessionKeyV6, incoming uint64) (record uint64, apply bool) {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return installGenGuardCore(s.genState.recvGenV6, key, incoming)
}

// installGenGuardScopedV4 is the scoped-space half of installGenGuardV4
// (#10512): refuse an install older than the scoped tombstone for
// (domain, tuple) so a delayed pre-delete install cannot land after the
// scoped delete that cancelled it. Same record/apply contract as the bare
// twin; production applies only when BOTH agree (either stale refuses).
// Domain comes from the installed value (0 = default instance, a real
// scoped space — every install consults exactly one).
func (s *SessionSync) installGenGuardScopedV4(domain uint32, key dataplane.SessionKey, incoming uint64) (record uint64, apply bool) {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return installGenGuardCore(s.genState.recvGenScopedV4, scopedDeleteKeyV4{Domain: domain, Key: key}, incoming)
}

// installGenGuardScopedV6 is the IPv6 twin of installGenGuardScopedV4.
func (s *SessionSync) installGenGuardScopedV6(domain uint32, key dataplane.SessionKeyV6, incoming uint64) (record uint64, apply bool) {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return installGenGuardCore(s.genState.recvGenScopedV6, scopedDeleteKeyV6{Domain: domain, Key: key}, incoming)
}

// recordInstalledGenScopedV4 records a live install into the scoped space
// (#10512): a newer replacement is what transitions a scoped entry back
// to live, advancing the high-water past its delete tombstone (which is
// forgotten, mirroring the bare twin) so later scoped deletes order
// against the install instead of the stale tombstone.
func (s *SessionSync) recordInstalledGenScopedV4(domain uint32, key dataplane.SessionKey, gen uint64) {
	s.genState.recvGenMu.Lock()
	recordInstalledGenScopedCore(s, &s.genState.recvGenScopedV4, &s.genState.recvTombScopedV4, &s.genState.recvGenScopedByTupleV4,
		func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key },
		scopedDeleteKeyV4{Domain: domain, Key: key}, gen)
	s.genState.recvGenMu.Unlock()
}

// recordInstalledGenScopedV6 is the IPv6 twin of recordInstalledGenScopedV4.
func (s *SessionSync) recordInstalledGenScopedV6(domain uint32, key dataplane.SessionKeyV6, gen uint64) {
	s.genState.recvGenMu.Lock()
	recordInstalledGenScopedCore(s, &s.genState.recvGenScopedV6, &s.genState.recvTombScopedV6, &s.genState.recvGenScopedByTupleV6,
		func(sk scopedDeleteKeyV6) dataplane.SessionKeyV6 { return sk.Key },
		scopedDeleteKeyV6{Domain: domain, Key: key}, gen)
	s.genState.recvGenMu.Unlock()
}

// recordInstalledGenV4 stores the per-key generation after a successful
// install-apply, bounded by the effective receiver cap.
func (s *SessionSync) recordInstalledGenV4(key dataplane.SessionKey, gen uint64) {
	s.genState.recvGenMu.Lock()
	recordInstalledGenCore(s, &s.genState.recvGenV4, &s.genState.recvTombV4, key, gen)
	s.genState.recvGenMu.Unlock()
}

func (s *SessionSync) recordInstalledGenV6(key dataplane.SessionKeyV6, gen uint64) {
	s.genState.recvGenMu.Lock()
	recordInstalledGenCore(s, &s.genState.recvGenV6, &s.genState.recvTombV6, key, gen)
	s.genState.recvGenMu.Unlock()
}

// deleteGenGuardV4 implements the receiver-side delete guard (#2170): a delete
// is refused only when both the stored and delete generations are non-zero and
// the delete generation is STRICTLY older than the stored entry's. Equality
// applies (it is the delete of the very session installed); gen==0 on either
// side falls back to today's unconditional delete (rolling-upgrade safe). The
// bool reports whether the delete should proceed.
//
// #2221: on an applied delete the stored generation is NOT evicted — it is
// upgraded to the (strictly-greater, see takeDeleteGenV4) delete generation as
// a TOMBSTONE. A subsequent reordered install that carries the OLDER generation
// of the very session this delete cancelled is then refused by installGenGuard*
// (incoming < the tombstone), so the standby converges to the master's state
// (session GONE) regardless of install/delete arrival order. A genuinely newer
// incarnation re-established and re-stamped by a later sweep carries a higher
// generation and still applies (incoming > tombstone). A gen-0 (legacy) delete
// evicts (no tombstone to record) — the legacy unconditional path is unchanged.
// Tombstones are bounded by the effective receiver cap (and the absolute
// genGuardMapCap ceiling). They survive a same-incarnation resetRecvGen so a
// post-fence delete continues to refuse an older snapshot row; a known
// peer-boot switch explicitly drops them because the sender's generation
// namespace has restarted and the old values are no longer comparable.
//
// #9719: a tombstone never frees its entry, so between bulks the map used to
// fill with tombstones of closed sessions and then skip-record every NEW key.
// The oldest tombstone is now evicted to make room (genTombstoneOrder); a live
// entry never is.

func (s *SessionSync) tombstoneBareLocked(key dataplane.SessionKey, gen uint64) {
	tombstoneBareCore(s, &s.genState.recvGenV4, &s.genState.recvTombV4, key, gen)
}

// tombstoneBareLockedV6 is the IPv6 twin of tombstoneBareLocked.
func (s *SessionSync) tombstoneBareLockedV6(key dataplane.SessionKeyV6, gen uint64) {
	tombstoneBareCore(s, &s.genState.recvGenV6, &s.genState.recvTombV6, key, gen)
}

// tombstoneScopedLocked records a scoped tombstone (or evicts on gen-0)
// without a refusal check. Caller holds recvGenMu.
func (s *SessionSync) tombstoneScopedLocked(skey scopedDeleteKeyV4, gen uint64) {
	tombstoneScopedCore(s, &s.genState.recvGenScopedV4, &s.genState.recvTombScopedV4, &s.genState.recvGenScopedByTupleV4,
		func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key }, skey, gen)
}

// tombstoneScopedLockedV6 is the IPv6 twin of tombstoneScopedLocked.
func (s *SessionSync) tombstoneScopedLockedV6(skey scopedDeleteKeyV6, gen uint64) {
	tombstoneScopedCore(s, &s.genState.recvGenScopedV6, &s.genState.recvTombScopedV6, &s.genState.recvGenScopedByTupleV6,
		func(sk scopedDeleteKeyV6) dataplane.SessionKeyV6 { return sk.Key }, skey, gen)
}

func (s *SessionSync) deleteGenGuardV4(key dataplane.SessionKey, deleteGen uint64) bool {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return deleteGenGuardCore(s, &s.genState.recvGenV4, &s.genState.recvTombV4, &s.genState.recvGenScopedV4, &s.genState.recvTombScopedV4,
		&s.genState.recvGenScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key }, key, deleteGen)
}

func (s *SessionSync) deleteGenGuardV6(key dataplane.SessionKeyV6, deleteGen uint64) bool {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return deleteGenGuardCore(s, &s.genState.recvGenV6, &s.genState.recvTombV6, &s.genState.recvGenScopedV6, &s.genState.recvTombScopedV6,
		&s.genState.recvGenScopedByTupleV6, func(sk scopedDeleteKeyV6) dataplane.SessionKeyV6 { return sk.Key }, key, deleteGen)
}

// deleteGenGuardScopedV4 is the receiver-side reorder guard for scoped
// policy deletes (#10512): same refuse-older + tombstone semantics as
// deleteGenGuardV4, in a dedicated per-(domain, tuple) space. #14358
// couples deletes (not installs) across spaces when the bare space
// already tracks the tuple: an accepted scoped delete is refused if it
// would regress the bare high-water, and raises an existing bare entry
// to a tombstone at the same generation, so a delayed same-generation
// install is refused by the bare guard if the scoped tombstone is
// evicted at cap. It never creates a bare entry for a tuple the bare
// space never tracked (preserving per-domain independence, #10512),
// and never lowers it. Symmetrically, scoped tombstones order bare
// deletes. Install guards stay per-space.
func (s *SessionSync) deleteGenGuardScopedV4(domain uint32, key dataplane.SessionKey, deleteGen uint64) bool {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return deleteGenGuardScopedCore(s, &s.genState.recvGenScopedV4, &s.genState.recvTombScopedV4, &s.genState.recvGenScopedByTupleV4,
		func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key },
		&s.genState.recvGenV4, &s.genState.recvTombV4, scopedDeleteKeyV4{Domain: domain, Key: key}, key, deleteGen)
}

// deleteGenGuardScopedV6 is the IPv6 twin of deleteGenGuardScopedV4.
func (s *SessionSync) deleteGenGuardScopedV6(domain uint32, key dataplane.SessionKeyV6, deleteGen uint64) bool {
	s.genState.recvGenMu.Lock()
	defer s.genState.recvGenMu.Unlock()
	return deleteGenGuardScopedCore(s, &s.genState.recvGenScopedV6, &s.genState.recvTombScopedV6, &s.genState.recvGenScopedByTupleV6,
		func(sk scopedDeleteKeyV6) dataplane.SessionKeyV6 { return sk.Key },
		&s.genState.recvGenV6, &s.genState.recvTombV6, scopedDeleteKeyV6{Domain: domain, Key: key}, key, deleteGen)
}

// resetRecvSessionGen resets only receiver-side session generation maps. A
// same-incarnation bulk uses preserve=true to reclaim live high-waters while
// retaining delete tombstones and without resetting comparable config/full-set
// namespaces.
func (s *SessionSync) resetRecvSessionGen(preserve bool) {
	// #9715: under applyMu, so an install on the other receive loop that passed
	// its guard before this reset cannot record its pre-reboot generation after
	// it.
	s.applyMu.Lock()
	s.genState.recvGenMu.Lock()
	if preserve {
		// Keep exactly the map entries indexed by the tombstone order. Every
		// live entry is discarded, while the order itself remains in place and
		// continues to bound/evict tombstones normally.
		recvGenV4 := make(map[dataplane.SessionKey]uint64, s.genState.recvTombV4.size())
		for key := range s.genState.recvTombV4.elems {
			if gen, ok := s.genState.recvGenV4[key]; ok {
				recvGenV4[key] = gen
			}
		}
		recvGenV6 := make(map[dataplane.SessionKeyV6]uint64, s.genState.recvTombV6.size())
		for key := range s.genState.recvTombV6.elems {
			if gen, ok := s.genState.recvGenV6[key]; ok {
				recvGenV6[key] = gen
			}
		}
		recvGenScopedV4 := make(map[scopedDeleteKeyV4]uint64, s.genState.recvTombScopedV4.size())
		for key := range s.genState.recvTombScopedV4.elems {
			if gen, ok := s.genState.recvGenScopedV4[key]; ok {
				recvGenScopedV4[key] = gen
			}
		}
		recvGenScopedV6 := make(map[scopedDeleteKeyV6]uint64, s.genState.recvTombScopedV6.size())
		for key := range s.genState.recvTombScopedV6.elems {
			if gen, ok := s.genState.recvGenScopedV6[key]; ok {
				recvGenScopedV6[key] = gen
			}
		}
		s.genState.recvGenV4 = recvGenV4
		s.genState.recvGenV6 = recvGenV6
		s.genState.recvGenScopedV4 = recvGenScopedV4
		s.genState.recvGenScopedV6 = recvGenScopedV6
		// #15039: rebuild the tuple indexes from exactly the retained
		// tombstone entries above; live entries were dropped.
		s.genState.recvGenScopedByTupleV4.reset()
		for skey := range recvGenScopedV4 {
			s.genState.recvGenScopedByTupleV4.add(skey.Key, skey)
		}
		s.genState.recvGenScopedByTupleV6.reset()
		for skey := range recvGenScopedV6 {
			s.genState.recvGenScopedByTupleV6.add(skey.Key, skey)
		}
		preserved := len(recvGenV4)
		if len(recvGenV6) > preserved {
			preserved = len(recvGenV6)
		}
		if len(recvGenScopedV4) > preserved {
			preserved = len(recvGenScopedV4)
		}
		if len(recvGenScopedV6) > preserved {
			preserved = len(recvGenScopedV6)
		}
		// Keep the smallest growth tier that can contain the retained
		// tombstones. A test ceiling below the historical default is also
		// honored because recvCap's zero value intentionally ignores overrides.
		maxCap := s.maxCap()
		cap := genGuardMapDefaultCap
		if maxCap < cap {
			cap = maxCap
		}
		for cap < preserved && cap < maxCap {
			next := cap * 2
			if next > maxCap {
				next = maxCap
			}
			cap = next
		}
		if cap == genGuardMapDefaultCap && maxCap >= genGuardMapDefaultCap {
			s.genState.recvGenGuardCap = 0
		} else {
			s.genState.recvGenGuardCap = cap
		}
	} else {
		s.genState.recvGenV4 = make(map[dataplane.SessionKey]uint64)
		s.genState.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
		s.genState.recvGenScopedV4 = make(map[scopedDeleteKeyV4]uint64)
		s.genState.recvGenScopedV6 = make(map[scopedDeleteKeyV6]uint64)
		// #14157: the received installing-table identity is per-incarnation
		// like the source-NAT memo below: a rebooted peer may reuse a tuple
		// AND a sessionID, so a surviving record would restore the dead
		// incarnation's domain/check into the new session on a stamp-less
		// (0,0) install (restoreInstallTableLocked) and on the promoted-
		// standby resend path (lookupRecvInstallTableLocked). Discard both.
		s.genState.installTableRecvV4 = make(map[dataplane.SessionKey]recvInstallTable)
		s.genState.installTableRecvV6 = make(map[dataplane.SessionKeyV6]recvInstallTable)
		// #11064: discard typed source-NAT identities from the peer's prior
		// namespace; its rebooted sessions may reuse old session identifiers.
		s.genState.sourceNatICMPRecvV4 = make(map[dataplane.SessionKey]sourceNatICMPMemo)
		s.genState.sourceNatICMPRecvV6 = make(map[dataplane.SessionKeyV6]sourceNatICMPMemo)
		// #14359: same for the received policy identity — a surviving record
		// would re-bind the dead incarnation's rule on a stamp-less re-prime.
		s.genState.policyIdentityRecvV4 = make(map[dataplane.SessionKey]policyIdentityMemo)
		s.genState.policyIdentityRecvV6 = make(map[dataplane.SessionKeyV6]policyIdentityMemo)
		// #16700: same for received app timeout / log flags.
		s.genState.appTimeoutLogRecvV4 = make(map[dataplane.SessionKey]appTimeoutLogMemo)
		s.genState.appTimeoutLogRecvV6 = make(map[dataplane.SessionKeyV6]appTimeoutLogMemo)
		s.genState.recvTombV4.reset()
		s.genState.recvTombV6.reset()
		s.genState.recvTombScopedV4.reset()
		s.genState.recvTombScopedV6.reset()
		s.genState.recvGenScopedByTupleV4.reset()
		s.genState.recvGenScopedByTupleV6.reset()
		// #9915 F-044: a namespace reset starts the next epoch at the
		// default cap and clears all session tombstones.
		s.genState.recvGenGuardCap = 0
	}
	s.genState.recvGenMu.Unlock()
	s.applyMu.Unlock()
}

// reclaimRecvLiveGen preserves delete tombstones while reclaiming live
// high-waters for a same-incarnation authoritative bulk. Config and full-set
// generations remain comparable and are deliberately untouched.
func (s *SessionSync) reclaimRecvLiveGen() {
	s.resetRecvSessionGen(true)
}

// resetRecvGen performs the full receiver namespace reset for an un-incarnated
// legacy prime or a known boot-incarnation switch. It clears session,
// config, and full-set high-waters so a lower-generation rebooted namespace can
// re-prime.
func (s *SessionSync) resetRecvGen() {
	s.resetRecvSessionGen(false)
	// #3931: also reset the last-applied config generation. A reconnecting
	// peer may have REBOOTED, restarting its monotonic configGenCounter at a
	// value LOWER than the generation we stored from its previous boot.
	// Without this reset the config guard (admitConfigGen) would refuse the
	// reconnect config re-push as stale (last > incoming) — the same
	// stale-RETAIN inverse the session reset closes (#2198 F2). Resetting to
	// 0 makes the next config apply unconditionally; it is always the peer's
	// CURRENT config (pushConfigToPeer sends ShowActive), so the newest
	// content still wins.
	//
	// #5084: the three clears below are ONE transaction under configGenMu, and
	// every advance of these marks takes the same lock. Without it a clear could
	// land between a concurrent advance's load and its store and be LOST, so a
	// pre-reboot generation survived the reset and refused every one of the
	// reconnected peer's lower current generations — permanently, since the
	// marks are monotone-max. The clears run on a receive-loop goroutine and the
	// applied-mark advance runs on configApplyLoop, so they genuinely race.
	s.configGenMu.Lock()
	s.lastAppliedConfigGen.Store(0)
	// #6284: drop the apply-in-progress fence alongside the high-water so a
	// concurrent bulk re-prime restores the accept-everything posture the reset
	// intends. A re-prime admits the rebooted peer's lower-generation set; a
	// stale fence from an apply that raced the reset would otherwise keep
	// refusing it. configApplyLoop may re-raise the fence on its NEXT apply,
	// which is benign — the re-primed installs are re-sent by the next sweep.
	// (The pre-#5084 wording called that "the same benign race the high-water
	// reset already has with a concurrent advance". The fence half is benign;
	// the high-water half is not, which is what configGenMu now closes.)
	s.applyingConfigGen.Store(0)
	// #5563: reset the received-config high-water alongside the applied mark so
	// the manual-failover readiness gate's applied<=received invariant holds
	// across the reset window. The reconnect re-push then re-establishes both
	// (received on receive, applied on successful apply).
	s.lastRecvConfigGen.Store(0)
	s.configGenMu.Unlock()
	s.resetConfigEpochReverseFloor()
	// #5706: reset the full-set (IPsec/DHCP) ordering high-water marks for the
	// same reason. A reconnecting peer that OS-rebooted restarts its monotonic
	// incarnation LOWER; without this reset the guard would refuse its fresh
	// full-set re-push (nudged on reconnect) as stale and strand the standby on
	// the pre-reboot set. Resetting to the zero state admits the next push
	// unconditionally — it is always the peer's CURRENT set.
	//
	// #9634: EVERY full-set guard, from one list. The three resets used to be
	// written out one per line, and the fourth guard (#8121's persistent-NAT
	// lease set) was declared without one. A rebooted peer's lease sets were then
	// dropped as stale until its monotonic epoch passed the dead process's.
	s.recvSeqMu.Lock()
	for _, g := range s.fullSetGuardsLocked() {
		g.reset()
	}
	// Fold-2 HIGH-2: bump the commit epoch with the guard resets (same
	// critical section): a DHCP commit that checked newer() before this
	// reset must fail its re-verification instead of restoring the dead
	// boot's high-water over the replacement's.
	s.recvEpoch++
	s.recvSeqMu.Unlock()
}

// fullSetGuardsLocked returns every full-set receive guard on SessionSync
// (#9634). resetRecvGen resets exactly this list. TestEveryFullSetGuardIsResetOnRePrime_9634
// enumerates the fullSetSeqGuard fields of SessionSync by reflection and requires
// every one of them to be reset, so a new full-set family cannot be added
// without joining this list. The caller holds recvSeqMu.
func (s *SessionSync) fullSetGuardsLocked() []*fullSetSeqGuard {
	return []*fullSetSeqGuard{
		&s.ipsecRecvSeq,
		&s.dhcpV4RecvSeq,
		&s.dhcpV6RecvSeq,
		&s.persistentNatLeaseRecvSeq,
	}
}

// Apply atomicity (#2198 F3, corrected by #9715).
//
// The helpers (installGenGuard*, recordInstalledGen*, deleteGenGuard*) each take
// recvGenMu separately. The apply as a whole runs as ONE critical section under
// applyMu: an install from its guard, through the dataplane write, to its record
// or rollback; a delete from its guard through the dataplane delete.
//
// F3 used to argue no such lock was needed, because the receive apply path is
// single-threaded: the peer sends over one active stream. That holds within one
// receiveLoop, but every installed fabric connection runs its own loop. When the
// stream moves (a fabric flap, or the #9508 preferred-fabric switch), the old
// loop can still be applying frames it already read while the new loop applies
// newer frames for the same key. The #9715 cells drive both interleavings the
// old sequence allowed:
//   - an older install parked in its dataplane write recorded its generation
//     over a newer install's;
//   - an admitted delete removed a newer install that landed during its write.
//
// applyMu does hold across dataplane I/O, which F3 declined to do with
// recvGenMu. The cost F3 named, serializing unrelated keys, is paid only while
// two loops apply at once: in steady state one loop applies and the lock is
// uncontended.
// configEpochStale reports whether a synced session was stamped under an older
// config that may deny it (#5274/#11055). A current authority interprets a
// tagged epoch in its own send-counter namespace only when the peer advertised
// reverse-tag support. Untagged frames at an authority and tagged frames at a
// non-authority are role mismatches and fail open. The non-authority continues
// comparing untagged authority epochs against its apply-in-progress and
// last-applied barriers.
func (s *SessionSync) configEpochStale(epoch uint64) bool {
	if epoch == 0 {
		return false
	}
	if s.IsPrimaryFn != nil {
		primary := s.IsPrimaryFn()
		s.observeConfigEpochRole(primary)
		if primary {
			if epoch&configEpochReverseTag == 0 || !s.peerCapabilitiesLearned() || !s.PeerConfigEpochReverseTagCapable() {
				return false
			}
			epoch &= configEpochGenMask
			return epoch < s.configGenCounter.Load()
		}
		if epoch&configEpochReverseTag != 0 {
			return false
		}
	}
	barrier := s.applyingConfigGen.Load()
	if applied := s.lastAppliedConfigGen.Load(); applied > barrier {
		barrier = applied
	}
	return epoch < barrier
}

// rollBackStaleConfigInstallV4 removes a synced session whose config epoch went
// STALE between the pre-install check and the dataplane write (#6368).
//
// configEpochStale and PutClusterSynced* are not one critical section: the
// check reads max(applyingConfigGen, lastAppliedConfigGen) and the Put lands
// several statements later, on the receiveLoop goroutine, while configApplyLoop
// runs on its own. If the receiveLoop is descheduled across that gap — a GC
// pause or a loaded box is enough, and the window is the whole of
// OnConfigReceived, which compiles and promotes a config and runs
// clearSessionsForDeletedPolicies inside it, not "a few instructions" — the
// install can pass the check against the OLD threshold and land its Put AFTER
// the sweep that was supposed to invalidate it. The result is a stale PERMIT
// that no later sweep re-examines: it survives until the next config apply,
// which on a quiet box may be never, and a session installed on the standby is
// exactly what that node forwards on after a failover.
//
// The fix is act-then-verify rather than a lock. Serializing the check with the
// Put against configApplyLoop would mean holding one lock across dataplane I/O
// and across a whole config apply. applyMu (#9715) does not do that: it orders
// the receive loops against each other, not against configApplyLoop. Re-reading the threshold after
// the Put costs one atomic load per install and detects precisely the case the
// pre-check could not see; the rollback then applies the SAME verdict the guard
// would have reached, just later. That introduces no new semantic:
// configEpochStale never consults policy, it refuses on epoch alone, so a late
// refusal is the guard's own decision rather than a fresh judgement about this
// session.
//
// The generation is deliberately NOT recorded for a rolled-back install: the
// per-key recv-gen high-water must stay where it was so the peer's next
// re-sync of this key is admitted rather than refused as stale.
func (s *SessionSync) rollBackStaleConfigInstallV4(key dataplane.SessionKey, epoch uint64) {
	rollBackStaleConfigInstall(s, epoch, "v4",
		func() error { return s.sessions.DeleteWithCompanionsV4(key, dataplane.DeleteReasonClusterStale, false) })
}

// rollBackStaleConfigInstallV6 is the v6 twin of
// rollBackStaleConfigInstallV4; see there for why the check is re-run after
// the write instead of being serialized with it.
func (s *SessionSync) rollBackStaleConfigInstallV6(key dataplane.SessionKeyV6, epoch uint64) {
	rollBackStaleConfigInstall(s, epoch, "v6",
		func() error { return s.sessions.DeleteWithCompanionsV6(key, dataplane.DeleteReasonClusterStale, false) })
}

// rollBackStaleConfigInstall is the shared rollback behind the V4/V6
// wrappers (#16173): the store delete itself stays a family call passed
// by the wrapper (SessionKey vs SessionKeyV6 stores are genuinely
// different); only the counting/logging is shared.
func rollBackStaleConfigInstall(s *SessionSync, epoch uint64, af string, del func() error) {
	s.stats.SessionsStaleConfigIgnored.Add(1)
	if err := del(); err != nil {
		slog.Warn("cluster sync: could not roll back a "+af+" install whose config epoch went stale during the dataplane write — a stale permit may survive until the next config apply",
			"session_config_epoch", epoch, "applied_config_gen", s.lastAppliedConfigGen.Load(), "err", err)
		return
	}
	slog.Debug("cluster sync: rolled back a "+af+" install whose config epoch went stale during the dataplane write (#6368)",
		"session_config_epoch", epoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
}

// installClusterSyncedV4 applies a received v4 install through the ordering
// and config guards. It reports whether the install LANDED (dataplane write
// accepted and kept); guard refusals, helper refusals, and rollbacks report
// false so callers count only effects, not attempts (#9915 F-118 review).
func (s *SessionSync) installClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if s.sessions == nil {
		return false
	}
	// #9715: guard, write and record are one apply across receive loops; see applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	record, apply := s.installGenGuardV4(key, val.Generation)
	scopedRecord, scopedApply := s.installGenGuardScopedV4(scopedLogicalDomain(val.RoutingDomain), key, val.Generation)
	if !apply || !scopedApply {
		s.stats.InstallsStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v4 install",
			"incoming_gen", val.Generation)
		return false
	}
	if s.configEpochStale(val.ConfigEpoch) {
		s.stats.SessionsStaleConfigIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-config-epoch v4 install (peer moved to a newer config that may deny this session)",
			"session_config_epoch", val.ConfigEpoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
		return false
	}
	// #9752 round 3: restore the received installing-table identity before
	// the dataplane write (the BPF mirror cannot supply it on read-back).
	s.genState.recvGenMu.Lock()
	if s.genState.installTableRecvV4 == nil {
		s.genState.installTableRecvV4 = make(map[dataplane.SessionKey]recvInstallTable)
	}
	if !restoreInstallTableLocked(s.genState.installTableRecvV4, key, val.SessionID, &val.InstallTableDomain, &val.InstallTableCheck, s.recvCap()) && s.growRecvCap() {
		restoreInstallTableLocked(s.genState.installTableRecvV4, key, val.SessionID, &val.InstallTableDomain, &val.InstallTableCheck, s.recvCap())
	}
	if val.InstallTableDomain != 0 || val.InstallTableCheck != 0 {
		s.pbrAnnouncedForFence.Store(true)
	}
	if s.genState.sourceNatICMPRecvV4 == nil {
		s.genState.sourceNatICMPRecvV4 = make(map[dataplane.SessionKey]sourceNatICMPMemo)
	}
	if !stampSourceNatICMPLocked(s.genState.sourceNatICMPRecvV4, key, val.SessionID, &val.SourceNatICMPValid, &val.SourceNatICMPType, &val.SourceNatICMPCode, s.recvCap()) && s.growRecvCap() {
		stampSourceNatICMPLocked(s.genState.sourceNatICMPRecvV4, key, val.SessionID, &val.SourceNatICMPValid, &val.SourceNatICMPType, &val.SourceNatICMPCode, s.recvCap())
	}
	if s.genState.policyIdentityRecvV4 == nil {
		s.genState.policyIdentityRecvV4 = make(map[dataplane.SessionKey]policyIdentityMemo)
	}
	if !stampPolicyIdentityLocked(s.genState.policyIdentityRecvV4, key, val.SessionID, &val.PolicyRuleID, &val.PolicyCounterIdx, s.recvCap()) && s.growRecvCap() {
		stampPolicyIdentityLocked(s.genState.policyIdentityRecvV4, key, val.SessionID, &val.PolicyRuleID, &val.PolicyCounterIdx, s.recvCap())
	}
	if s.genState.appTimeoutLogRecvV4 == nil {
		s.genState.appTimeoutLogRecvV4 = make(map[dataplane.SessionKey]appTimeoutLogMemo)
	}
	if !stampAppTimeoutLogLocked(s.genState.appTimeoutLogRecvV4, key, val.SessionID, &val.AppTimeout, &val.LogFlags, s.recvCap()) && s.growRecvCap() {
		stampAppTimeoutLogLocked(s.genState.appTimeoutLogRecvV4, key, val.SessionID, &val.AppTimeout, &val.LogFlags, s.recvCap())
	}
	s.genState.recvGenMu.Unlock()
	err := s.sessions.PutClusterSyncedV4(key, val)
	if err == nil {
		// #6368: re-read the threshold after the write (see the shared
		// core's contract via logInstallOutcome's rollback arm).
		if s.configEpochStale(val.ConfigEpoch) {
			s.rollBackStaleConfigInstallV4(key, val.ConfigEpoch)
			return false
		}
		s.recordInstalledGenV4(key, record)
		s.recordInstalledGenScopedV4(scopedLogicalDomain(val.RoutingDomain), key, scopedRecord)
		return logInstallOutcome(s, "v4", nil, val.IsReverse, &s.bulkInstallFailedV4, key, &s.sessionMirrorWarnedV4)
	}
	return logInstallOutcome(s, "v4", err, val.IsReverse, &s.bulkInstallFailedV4, key, &s.sessionMirrorWarnedV4)
}

// installClusterSyncedV6 applies a received v6 install through the ordering
// and config guards. It reports whether the install LANDED, like the v4 twin.
func (s *SessionSync) installClusterSyncedV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if s.sessions == nil {
		return false
	}
	// #9715: see the v4 twin and applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	record, apply := s.installGenGuardV6(key, val.Generation)
	scopedRecord, scopedApply := s.installGenGuardScopedV6(scopedLogicalDomain(val.RoutingDomain), key, val.Generation)
	if !apply || !scopedApply {
		s.stats.InstallsStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v6 install",
			"incoming_gen", val.Generation)
		return false
	}
	if s.configEpochStale(val.ConfigEpoch) {
		s.stats.SessionsStaleConfigIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-config-epoch v6 install (peer moved to a newer config that may deny this session)",
			"session_config_epoch", val.ConfigEpoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
		return false
	}
	// #9752 round 3: v6 twin of the received-identity restore above.
	s.genState.recvGenMu.Lock()
	if s.genState.installTableRecvV6 == nil {
		s.genState.installTableRecvV6 = make(map[dataplane.SessionKeyV6]recvInstallTable)
	}
	if !restoreInstallTableLocked(s.genState.installTableRecvV6, key, val.SessionID, &val.InstallTableDomain, &val.InstallTableCheck, s.recvCap()) && s.growRecvCap() {
		restoreInstallTableLocked(s.genState.installTableRecvV6, key, val.SessionID, &val.InstallTableDomain, &val.InstallTableCheck, s.recvCap())
	}
	if val.InstallTableDomain != 0 || val.InstallTableCheck != 0 {
		s.pbrAnnouncedForFence.Store(true)
	}
	if s.genState.sourceNatICMPRecvV6 == nil {
		s.genState.sourceNatICMPRecvV6 = make(map[dataplane.SessionKeyV6]sourceNatICMPMemo)
	}
	if !stampSourceNatICMPLocked(s.genState.sourceNatICMPRecvV6, key, val.SessionID, &val.SourceNatICMPValid, &val.SourceNatICMPType, &val.SourceNatICMPCode, s.recvCap()) && s.growRecvCap() {
		stampSourceNatICMPLocked(s.genState.sourceNatICMPRecvV6, key, val.SessionID, &val.SourceNatICMPValid, &val.SourceNatICMPType, &val.SourceNatICMPCode, s.recvCap())
	}
	if s.genState.policyIdentityRecvV6 == nil {
		s.genState.policyIdentityRecvV6 = make(map[dataplane.SessionKeyV6]policyIdentityMemo)
	}
	if !stampPolicyIdentityLocked(s.genState.policyIdentityRecvV6, key, val.SessionID, &val.PolicyRuleID, &val.PolicyCounterIdx, s.recvCap()) && s.growRecvCap() {
		stampPolicyIdentityLocked(s.genState.policyIdentityRecvV6, key, val.SessionID, &val.PolicyRuleID, &val.PolicyCounterIdx, s.recvCap())
	}
	if s.genState.appTimeoutLogRecvV6 == nil {
		s.genState.appTimeoutLogRecvV6 = make(map[dataplane.SessionKeyV6]appTimeoutLogMemo)
	}
	if !stampAppTimeoutLogLocked(s.genState.appTimeoutLogRecvV6, key, val.SessionID, &val.AppTimeout, &val.LogFlags, s.recvCap()) && s.growRecvCap() {
		stampAppTimeoutLogLocked(s.genState.appTimeoutLogRecvV6, key, val.SessionID, &val.AppTimeout, &val.LogFlags, s.recvCap())
	}
	s.genState.recvGenMu.Unlock()
	err := s.sessions.PutClusterSyncedV6(key, val)
	if err == nil {
		// #6368: see the v4 twin — re-read the threshold after the write.
		if s.configEpochStale(val.ConfigEpoch) {
			s.rollBackStaleConfigInstallV6(key, val.ConfigEpoch)
			return false
		}
		s.recordInstalledGenV6(key, record)
		s.recordInstalledGenScopedV6(scopedLogicalDomain(val.RoutingDomain), key, scopedRecord)
		return logInstallOutcome(s, "v6", nil, val.IsReverse, &s.bulkInstallFailedV6, key, &s.sessionMirrorWarnedV6)
	}
	return logInstallOutcome(s, "v6", err, val.IsReverse, &s.bulkInstallFailedV6, key, &s.sessionMirrorWarnedV6)
}

// logInstallOutcome is the shared post-write outcome tail behind
// installClusterSyncedV4/V6 (#16173): on success it counts the install,
// clears the bulk-retry debt, notes mirror health and fires the
// forward-installed hook; on the helper's semantic refusal (#6785) or a
// definitive outcome it counts the dedicated debt without poisoning
// mirror health; otherwise it records the transient mirror failure.
// The dataplane write itself stays in the family wrappers above —
// PutClusterSyncedV4/V6 are genuinely different stores.
func logInstallOutcome[K comparable](s *SessionSync, af string, err error, isReverse uint8, bulkFailed *map[K]struct{}, key K, warned *atomic.Bool) bool {
	if err == nil {
		s.stats.SessionsInstalled.Add(1)
		noteBulkInstallOutcomeCore(s, bulkFailed, key, false)
		s.noteHelperMirrorResult(af, warned, nil)
		if isReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
		return true
	}
	if errors.Is(err, dataplane.ErrSyncedImportRefused) {
		// #6785: the helper REFUSED this import on semantic grounds and
		// Go has already rolled its BPF mirror row back, so there is no
		// split truth and no sick socket — count it as its own debt.
		s.stats.ImportsRefusedByHelper.Add(1)
		slog.Debug("cluster sync: helper refused a synced-session import; the "+
			"local mirror was rolled back and the peer holds a session this node does not",
			"af", af, "err", err)
		noteBulkInstallOutcomeCore(s, bulkFailed, key, false)
	} else if definitiveBulkInstallOutcome(err) {
		// A committed worker-repair result or deterministic helper
		// rejection cannot be repaired by re-sending the identical row.
		if errors.Is(err, dataplane.ErrSyncedImportRejected) {
			s.stats.ImportsRejectedByHelper.Add(1)
		}
		slog.Debug("cluster sync: helper returned a committed or deterministic synced-session outcome",
			"af", af, "err", err)
		noteBulkInstallOutcomeCore(s, bulkFailed, key, false)
	} else {
		s.noteHelperMirrorResult(af, warned, err)
		noteBulkInstallOutcomeCore(s, bulkFailed, key, true)
	}
	return false
}

func (s *SessionSync) deleteClusterSyncedV4(key dataplane.SessionKey, deleteGen uint64, forwardOnly bool) bool {
	if s.sessions == nil {
		return false
	}
	// #9715: the guard and the dataplane delete are one apply across receive
	// loops, so a newer install cannot land between them; see applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.deleteGenGuardV4(key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v4 delete (replacement session survives)",
			"delete_gen", deleteGen)
		return false
	}
	// #9752 round 3: the incarnation is being deleted; forget its received
	// identity (after the guard — a stale delete must not evict the live
	// incarnation's record).
	s.genState.recvGenMu.Lock()
	delete(s.genState.installTableRecvV4, key)
	delete(s.genState.sourceNatICMPRecvV4, key)
	delete(s.genState.policyIdentityRecvV4, key)
	delete(s.genState.appTimeoutLogRecvV4, key)
	s.genState.recvGenMu.Unlock()
	if err := s.sessions.DeleteWithCompanionsV4(key, dataplane.DeleteReasonClusterStale, forwardOnly); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v4 session", "err", err)
		return false
	} else {
		s.noteBulkInstallOutcomeV4(key, false)
		s.removeBulkRecvV4(key)
	}
	return true
}

func (s *SessionSync) deleteClusterSyncedV6(key dataplane.SessionKeyV6, deleteGen uint64, forwardOnly bool) bool {
	if s.sessions == nil {
		return false
	}
	// #9715: see the v4 twin and applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.deleteGenGuardV6(key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v6 delete (replacement session survives)",
			"delete_gen", deleteGen)
		return false
	}
	// #9752 round 3: v6 twin of the received-identity eviction above.
	s.genState.recvGenMu.Lock()
	delete(s.genState.installTableRecvV6, key)
	delete(s.genState.sourceNatICMPRecvV6, key)
	delete(s.genState.policyIdentityRecvV6, key)
	delete(s.genState.appTimeoutLogRecvV6, key)
	s.genState.recvGenMu.Unlock()
	if err := s.sessions.DeleteWithCompanionsV6(key, dataplane.DeleteReasonClusterStale, forwardOnly); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v6 session", "err", err)
		return false
	} else {
		s.noteBulkInstallOutcomeV6(key, false)
		s.removeBulkRecvV6(key)
	}
	return true
}

func (s *SessionSync) deleteClusterSyncedScopedV4(domain uint32, key dataplane.SessionKey, deleteGen uint64, expectedID uint64) bool {
	if s.sessions == nil {
		return false
	}
	// #9715: guard + delete are one apply; see the bare twin.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.deleteGenGuardScopedV4(domain, key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation scoped v4 delete",
			"domain", domain, "delete_gen", deleteGen)
		return false
	}
	// #14358: forget the received identity, as the bare twin does.
	s.genState.recvGenMu.Lock()
	delete(s.genState.installTableRecvV4, key)
	delete(s.genState.sourceNatICMPRecvV4, key)
	delete(s.genState.policyIdentityRecvV4, key)
	delete(s.genState.appTimeoutLogRecvV4, key)
	s.genState.recvGenMu.Unlock()
	if err := s.sessions.DeleteClusterScopedV4(key, domain, expectedID); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete scoped v4 session", "err", err)
		return false
	} else {
		s.noteBulkInstallOutcomeV4(key, false)
		s.removeBulkRecvV4(key)
	}
	return true
}

func (s *SessionSync) deleteClusterSyncedScopedV6(domain uint32, key dataplane.SessionKeyV6, deleteGen uint64, expectedID uint64) bool {
	if s.sessions == nil {
		return false
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.deleteGenGuardScopedV6(domain, key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation scoped v6 delete",
			"domain", domain, "delete_gen", deleteGen)
		return false
	}
	s.genState.recvGenMu.Lock()
	delete(s.genState.installTableRecvV6, key)
	delete(s.genState.sourceNatICMPRecvV6, key)
	delete(s.genState.policyIdentityRecvV6, key)
	delete(s.genState.appTimeoutLogRecvV6, key)
	s.genState.recvGenMu.Unlock()
	if err := s.sessions.DeleteClusterScopedV6(key, domain, expectedID); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete scoped v6 session", "err", err)
		return false
	} else {
		s.noteBulkInstallOutcomeV6(key, false)
		s.removeBulkRecvV6(key)
	}
	return true
}
