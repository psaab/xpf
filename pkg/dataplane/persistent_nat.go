package dataplane

import (
	"net/netip"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// PersistentNATBinding holds a NAT port mapping that survives session GC.
type PersistentNATBinding struct {
	SrcIP    netip.Addr
	SrcPort  uint16
	NatIP    netip.Addr
	NatPort  uint16
	PoolName string
	LastSeen time.Time
	Timeout  time.Duration
	// Permit is the three-way persistent-NAT remote scope (#2823/#3193):
	// any-remote-host / target-host / target-host-port. The pre-#2823
	// binary PermitAnyRemoteHost bool could not distinguish target-host
	// from target-host-port in the operator SHOW path (#3193).
	Permit config.PersistentNATPermit
}

// PermitMode returns the human-readable persistent-NAT permit scope for
// the SHOW path, resolving the zero value to the target-host-port default
// (#2823 default / #3193). It renders the actual three-way mode rather
// than the pre-#3193 binary any-remote-host flag.
func (b *PersistentNATBinding) PermitMode() string {
	if b.Permit == "" {
		return string(config.PersistentNATPermitTargetHostPort)
	}
	return string(b.Permit)
}

type persistentNATKey struct {
	SrcIP   netip.Addr
	SrcPort uint16
	Pool    string
}

// PersistentNATPoolInfo holds per-pool persistent NAT configuration.
type PersistentNATPoolInfo struct {
	Timeout time.Duration
	// Permit is the three-way persistent-NAT remote scope (#2823/#3193).
	Permit config.PersistentNATPermit
}

// PersistentNATTable stores NAT bindings that persist after session close.
type PersistentNATTable struct {
	mu          sync.RWMutex
	bindings    map[persistentNATKey]*PersistentNATBinding
	poolConfigs map[string]PersistentNATPoolInfo // pool name -> config
	natIPToPool map[netip.Addr]string            // NAT IP -> pool name

	// clearGen fences a SHOW refresh against an operator clear (#10784).
	// Every Clear bumps it; a refresh that exported the helper's view before
	// the bump must drop its stale set instead of replacing the cleared table.
	clearGen uint64
}

// NewPersistentNATTable creates a new persistent NAT table.
func NewPersistentNATTable() *PersistentNATTable {
	return &PersistentNATTable{
		bindings:    make(map[persistentNATKey]*PersistentNATBinding),
		poolConfigs: make(map[string]PersistentNATPoolInfo),
		natIPToPool: make(map[netip.Addr]string),
	}
}

// SetPoolConfig registers a persistent NAT pool configuration.
func (t *PersistentNATTable) SetPoolConfig(poolName string, cfg PersistentNATPoolInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.poolConfigs[poolName] = cfg
}

// RegisterNATIP maps a NAT IP address to its pool name for reverse lookup.
func (t *PersistentNATTable) RegisterNATIP(ip netip.Addr, poolName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.natIPToPool[ip] = poolName
}

// ClearPoolConfigs removes all pool configuration and IP mappings.
// Called before recompilation to ensure stale pools are removed.
//
// IT DELIBERATELY DOES NOT DROP BINDINGS (#8597 K76), and the reason is #8607.
//
// The complaint is real and was measured: after a recompile that removes a
// pool, that pool's bindings survive here and `show security nat source
// persistent-nat-table` keeps rendering them under their stale PoolName until
// they expire. Both fix directions the finding offers — dropping the bindings
// here, or filtering All()/the renderer against poolConfigs — reintroduce the
// defect #8607 exists to remove, as a window after EVERY commit rather than a
// permanent state:
//
//   - compileNAT calls this at its TOP and re-registers the surviving pools
//     later in the same function, under a SEPARATE acquisition of t.mu. A
//     renderer that takes All()'s RLock in between sees zero pools.
//   - so a poolConfigs-filtered render answers "No persistent NAT bindings" for
//     that window, and dropping the bindings outright answers it until the next
//     refresher tick — up to persistentNatShowRefreshInterval.
//
// "No persistent NAT bindings" printed for a pool that is demonstrably
// translating is the exact false statement #8607 was filed for. Trading a
// permanent one for an intermittent one is not a fix; an intermittent wrong
// answer is harder to diagnose than a constant one.
//
// What makes the ghost rows self-limiting instead: under the userspace
// dataplane — the only runtime forwarding path — this table is not an
// accumulator. daemon_persistent_nat_show_8607.go replaces it wholesale every
// persistentNatShowRefreshInterval from the helper's own view (ReplaceAll), so
// a deconfigured pool's rows disappear as soon as the helper stops reporting
// them, whatever this function does.
//
// A future fix that genuinely wants pool-scoped rendering needs the clear and
// the re-register to be ONE atomic swap of poolConfigs/natIPToPool, so the
// filtered set is never transiently empty. That is a change to compileNAT's
// registration protocol, not to this function.
// TestClearPoolConfigsKeepsBindings_8597 fails if the bindings are dropped here.
func (t *PersistentNATTable) ClearPoolConfigs() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.poolConfigs = make(map[string]PersistentNATPoolInfo)
	t.natIPToPool = make(map[netip.Addr]string)
}

// LookupPool finds the pool name and config for a given NAT IP.
// Returns empty string and zero config if the IP is not in any persistent pool.
func (t *PersistentNATTable) LookupPool(natIP netip.Addr) (string, PersistentNATPoolInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	poolName, ok := t.natIPToPool[natIP]
	if !ok {
		return "", PersistentNATPoolInfo{}, false
	}
	cfg, ok := t.poolConfigs[poolName]
	if !ok {
		return "", PersistentNATPoolInfo{}, false
	}
	return poolName, cfg, true
}

// Lookup finds an existing persistent binding. Returns nil if not found
// or if the binding has expired.
func (t *PersistentNATTable) Lookup(srcIP netip.Addr, srcPort uint16, pool string) *PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := persistentNATKey{SrcIP: srcIP, SrcPort: srcPort, Pool: pool}
	b, ok := t.bindings[key]
	if !ok {
		return nil
	}
	if time.Since(b.LastSeen) > b.Timeout {
		return nil
	}
	return b
}

// Save stores a persistent NAT binding, refreshing an existing entry for the
// same source IP, port and pool IN FULL rather than by timestamp alone.
//
// #8597 K77: it used to refresh only LastSeen and discard the rest of the
// caller's record, so a pool edit that changed the mapping, the timeout or the
// permit scope did not take effect until the old binding expired. Measured —
// re-saving 10.0.0.5:1000 with NatIP 198.51.100.9:6000, a 1m timeout and
// permit any-remote-host left the table rendering 192.0.2.1:5000, 1h,
// target-host.
//
// The key is (SrcIP, SrcPort, Pool), so a re-save under the same key is the
// SAME binding with new facts about it, never a different one. There is
// nothing in the discarded record the stored one was more right about: the only
// caller, preservePersistentNATV4/V6, builds every field fresh from the session
// being deleted and the pool config it just looked up.
//
// WHY THE FIELDS ARE COPIED RATHER THAN THE ENTRY REPLACED. The finding offers
// both ("overwrite mutable fields alongside LastSeen, or replace the entry"),
// and the second arm was written first — then TestPersistentNATTable_SaveUpdates
// LastSeen went red. That cell re-saves with a DELIBERATELY STALE LastSeen and
// asserts the stored one advanced, which is the documented contract of this
// method: a re-save is a REFRESH, and the caller does not have to supply the
// clock for it. Replacing the entry stores the caller's timestamp verbatim and
// silently drops that. Production passes time.Now() either way, so the change
// was invisible in effect and visible only to the control — which is the case
// the control exists for.
//
// So LastSeen keeps coming from the clock here, and only the four fields that
// describe the MAPPING follow the caller. Mutating in place under the write
// lock keeps the #4811 property: All() copies, so no reader aliases this.
func (t *PersistentNATTable) Save(b *PersistentNATBinding) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := persistentNATKey{SrcIP: b.SrcIP, SrcPort: b.SrcPort, Pool: b.PoolName}
	if existing, ok := t.bindings[key]; ok {
		existing.NatIP = b.NatIP
		existing.NatPort = b.NatPort
		existing.Timeout = b.Timeout
		existing.Permit = b.Permit
		existing.LastSeen = time.Now()
		return
	}
	t.bindings[key] = b
}

// GC removes expired bindings. Returns the number of bindings removed.
func (t *PersistentNATTable) GC() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, b := range t.bindings {
		if now.Sub(b.LastSeen) > b.Timeout {
			delete(t.bindings, key)
			removed++
		}
	}
	return removed
}

// ReplaceAll makes the table a SNAPSHOT of bindings, atomically (#8607).
//
// WHY A REPLACE AND NOT A LOOP OF Save. Under the userspace dataplane this
// table is not an accumulator that ages out — it is a copy of state the Rust
// helper owns, and the helper is authoritative for both existence AND expiry.
// Two things follow:
//
//   - Save would be wrong on the way in: it treats a repeat as a refresh and
//     stamps LastSeen = time.Now(), which would reset every binding's remaining
//     lifetime to the full timeout on every refresh and make the SHOW column
//     count down from a value it never had.
//   - GC would be wrong on the way out, and is unreachable anyway: it is called
//     from the conntrack sweep, which daemon_run.go disables outright on this
//     path (`gc.SkipSweep = func() bool { return true }`). A binding the helper
//     has released must disappear because it is ABSENT from the next snapshot,
//     not because a local timer expired it.
//
// Atomic because a renderer holds no lock across All(): a Clear followed by a
// loop of Save has a window in which the table is empty or half-filled, and the
// symptom of that window is the exact "No persistent NAT bindings" line #8607 is
// about — reintroduced as a rare flake instead of a permanent state.
//
// A nil or empty slice empties the table, deliberately: "the helper has no
// bindings" is an answer, and the caller is responsible for not calling this
// when it could not ASK (see the daemon refresher, which skips on error).
func (t *PersistentNATTable) ReplaceAll(bindings []*PersistentNATBinding) {
	next := indexPersistentNATBindings(bindings)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bindings = next
}

// ClearGeneration reports the table's clear generation. A SHOW refresh captures
// it before exporting the helper's view and hands it back to
// ReplaceAllUnlessClearedSince, so an export that started before an operator
// clear is dropped instead of repopulating the mirror (#10784).
func (t *PersistentNATTable) ClearGeneration() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.clearGen
}

// ReplaceAllUnlessClearedSince replaces the table only if no Clear has landed
// since gen was captured. It reports whether the table was replaced, so the
// refresher can tell "clear won" apart from "replaced" without reading back.
func (t *PersistentNATTable) ReplaceAllUnlessClearedSince(bindings []*PersistentNATBinding, gen uint64) bool {
	next := indexPersistentNATBindings(bindings)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.clearGen != gen {
		return false
	}
	t.bindings = next
	return true
}

func indexPersistentNATBindings(bindings []*PersistentNATBinding) map[persistentNATKey]*PersistentNATBinding {
	next := make(map[persistentNATKey]*PersistentNATBinding, len(bindings))
	for _, b := range bindings {
		if b == nil {
			continue
		}
		next[persistentNATKey{SrcIP: b.SrcIP, SrcPort: b.SrcPort, Pool: b.PoolName}] = b
	}
	return next
}

// Clear removes all bindings.
//
// It also bumps the clear generation: a SHOW refresh that exported before this
// clear must not ReplaceAll its stale set back over the table (#10784).
func (t *PersistentNATTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.bindings = make(map[persistentNATKey]*PersistentNATBinding)
	t.clearGen++
}

// Len returns the number of active bindings.
func (t *PersistentNATTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.bindings)
}

// All returns a snapshot of all current bindings. Each returned pointer
// addresses a fresh COPY of the binding, not the live table entry — so a
// caller iterating the result never aliases table state that a concurrent
// Save()/GC() mutates in place (e.g. Save updating LastSeen under the write
// lock). Returning the live pointers here was a real, -race-detectable data
// race between the SHOW path (pkg/natshow) reading LastSeen and the packet
// path calling Save() (#4811). All PersistentNATBinding fields are value
// types (netip.Addr, ints, string, time.Time, config.PersistentNATPermit),
// so a struct value copy is a complete, independent snapshot.
func (t *PersistentNATTable) All() []*PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*PersistentNATBinding, 0, len(t.bindings))
	for _, b := range t.bindings {
		cp := *b
		result = append(result, &cp)
	}
	return result
}
