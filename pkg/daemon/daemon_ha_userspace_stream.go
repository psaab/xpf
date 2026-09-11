package daemon

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
)

type userspaceSessionDeltaDrainer interface {
	DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceEventStreamProvider interface {
	EventStream() *dpuserspace.EventStream
}

// shouldSyncUserspaceDelta decides whether a userspace session delta should be
// transientLocalSeedOrigins mirrors the helper's
// `SessionOrigin::is_transient_local_seed` (userspace-dp/src/session/entry.rs).
// A seed is a LOCAL artefact of a decision one node made — it is not a claim of
// authority over the flow, and the authoritative session lives on the other
// node.
//
// The helper already suppresses the Open delta for these origins at install
// (`install.rs`'s `counted` gate), so nothing here should ever see one. This
// filter is the belt to that suspenders, and the reason it is worth having is
// recorded directly below in the fabric-redirect branch: #6599 measured what a
// FabricRedirect-disposition Open delta does when it reaches the peer, which is
// to overwrite the owner's authoritative session family under
// latest-generation-wins. A #7770 punt seed has exactly that disposition and is
// NAT-free by construction, so a regression in the helper's suppression would
// land the worst shape of that class on the wire. Filtering by origin costs one
// string compare and removes the whole class from this path's reach.
//
// It is a LIST rather than two `EqualFold` calls so the pair cannot drift apart
// as the helper's set grows; `TestShouldSyncUserspaceDeltaSkipsTransientLocalSeeds`
// pins every member and carries a non-seed control.
var transientLocalSeedOrigins = []string{
	"missing_neighbor_seed",
	// #7770: the punting node's record of "I redirected this flow across the
	// fabric and my own policy permitted it", which exists so the peer's RETURN
	// is a session hit instead of a `wan -> lan` default deny.
	"fabric_punt_seed",
}

func isTransientLocalSeedOrigin(origin string) bool {
	for _, seed := range transientLocalSeedOrigins {
		if strings.EqualFold(origin, seed) {
			return true
		}
	}
	return false
}

// synced to the peer. ss is the caller's captured session-sync object (#4958):
// the per-delta hot path takes the snapshot once in queueUserspaceSessionDeltas
// rather than re-reading the shared field under lock for every delta.
func (d *Daemon) shouldSyncUserspaceDelta(ss *cluster.SessionSync, delta dpuserspace.SessionDeltaInfo, ingressZone uint16) bool {
	// Local-delivery sessions are traffic destined TO the firewall itself
	// (management SSH, BGP peering, DHCP, NDP, ICMP echo, etc.).  These are
	// intentionally excluded from HA session sync because:
	//  1. Each cluster node handles its own host-bound traffic independently;
	//     the peer's kernel stack processes its own local-delivery sessions
	//     after failover with no need for synced state.
	//  2. Local-delivery sessions reference node-local ifindexes and addresses
	//     that are meaningless on the peer.
	//  3. The userspace dataplane already sets track_in_userspace=false for
	//     these (afxdp.rs), so they are not in the session sweep; this guard
	//     covers the helper event-stream path.
	// See #315 for discussion.
	if strings.EqualFold(delta.Disposition, "local_delivery") {
		slog.Debug("userspace delta: filtered (local_delivery)", "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	if isTransientLocalSeedOrigin(delta.Origin) {
		slog.Debug("userspace delta: filtered (transient local seed)",
			"origin", delta.Origin, "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	// A fabric redirect means the PEER owns the flow's egress side, so
	// delta.OwnerRGID names an RG this node is by construction not primary
	// for. Judging the delta by the owner-RG gate below would therefore refuse
	// every legitimate split-RG handoff (a flow that ingresses on an RG this
	// node owns and leaves via an RG the peer owns), which is why this branch
	// exists at all.
	//
	// #6599: it used to bypass ownership ENTIRELY (`return ss != nil`), which
	// made it the emission channel for the transient-purge re-entry class. On a
	// node that is not the RG owner, a spoofed first packet carrying a
	// peer-owned flow's translated wire tuple drives
	// should_keep_synced_hit_transient -> purge_translated_synced_hit
	// (userspace-dp/src/afxdp/session_glue/promote.rs); the following packet
	// clean-misses and installs a fresh ForwardFlow whose resolution is a
	// FABRIC REDIRECT — precisely because this node does not own the RG, the
	// same condition that fired the purge. The Open delta (and the forward-wire
	// alias the walk emits alongside it) then reached QueueSessionV4 with a
	// fresh #2170 install generation and overwrote the owner's authoritative
	// session family under latest-generation-wins.
	//
	// The fence is ownership of the INGRESS side: sync the handoff only when
	// this node is primary for the RG the flow's ingress zone belongs to, i.e.
	// only when it actually owns the traffic it is handing off. That keeps the
	// split-RG handoff (ingress RG is local) and drops the fabrication (ingress
	// RG is the peer's — a node that owns neither side of the flow has no
	// authority to install anything on the peer). ShouldSyncZone is the same
	// predicate the non-fabric fallback below already uses, so the two branches
	// now agree on what "this node owns this flow's ingress" means.
	if delta.FabricRedirect && !delta.FabricIngress {
		ok := ss != nil && ss.ShouldSyncZone(ingressZone)
		if !ok {
			slog.Debug("userspace delta: filtered (fabric redirect from a zone this node does not own)", "zone", ingressZone, "rg", delta.OwnerRGID, "src", delta.SrcIP, "dst", delta.DstIP)
		}
		return ok
	}
	if delta.OwnerRGID > 0 && ss != nil && ss.IsPrimaryForRGFn != nil {
		ok := ss.IsPrimaryForRGFn(delta.OwnerRGID)
		if !ok {
			slog.Debug("userspace delta: filtered (not primary for owner RG)", "rg", delta.OwnerRGID, "src", delta.SrcIP, "dst", delta.DstIP)
		}
		return ok
	}
	ok := ss != nil && ss.ShouldSyncZone(ingressZone)
	if !ok {
		slog.Debug("userspace delta: filtered (zone not synced)", "zone", ingressZone, "src", delta.SrcIP, "dst", delta.DstIP)
	}
	return ok
}

// runUserspaceEventStream consumes session events from the helper's binary
// event stream, falling back to DrainSessionDeltas polling whenever the
// stream is unavailable or disconnected.
//
// Codex PR #6743 r7-F1b: this used to open with a ONE-SHOT probe —
// `if _, ok := d.dataplane().(userspaceEventStreamProvider); !ok` — and, on
// a miss, hand off permanently to a separate polling loop that had no
// wiring logic at all. An empty cell at that instant (the daemon has not
// armed the helper yet, or a bootstrap-arm failure cleared it) therefore
// LATCHED the daemon into pure polling: a corrected commit could publish a
// perfectly healthy provider afterwards and its callbacks were never
// installed, so every helper event sat in the callback-not-ready queue for
// the rest of the process's life. The per-tick drainer resolution (r7-F1)
// does not reach this one — the decision was already made, and on the
// standalone path the goroutine had already returned.
//
// eventStreamFallbackLoop is now the single loop for both roles: it
// re-resolves the provider, the stream and the drainer from the #2114 cell
// every tick, installs callbacks the first time it sees a stream (passing
// nil for `wired` means "nothing wired yet"), and polls at 100 ms while
// disconnected — which is exactly what the deleted polling loop did. So a
// backend published after entry is picked up on the next tick instead of
// being missed forever.
func (d *Daemon) runUserspaceEventStream(ctx context.Context) {
	if d.cluster == nil || d.getSessionSync() == nil {
		// Standalone: no session sync, so nothing to poll or drain — but
		// the helper's DATAPLANE events (RT_FLOW records into the event
		// buffer) still arrive through these callbacks, so they must be
		// installed, and they must STAY installed across a stream
		// replacement.
		//
		// #7017: this arm used to call wireUserspaceEventStreamCallbacks
		// and RETURN. That helper re-reads the #2114 cell every 500 ms
		// until a provider with a stream appears, so an empty cell at entry
		// was a retry rather than a latch — but it returns the moment it
		// installs, and the arm returned with it. The re-install on a
		// REPLACED stream instance (the `es != wired` block r6-F4 added)
		// lived only in eventStreamFallbackLoop, which this path never
		// runs. So on a standalone daemon, a commit-confirmed rollback that
		// closes the armed backend's stream followed by a corrected re-arm
		// that constructs a new one left the replacement with no callbacks:
		// its dataplane events accumulated in the callback-not-ready queue
		// instead of reaching the event buffer, and RT_FLOW records stopped
		// reaching `show log`, syslog and the flow exporter for the rest of
		// the process's life. Only a restart recovered.
		//
		// watchUserspaceEventStreamCallbacks keeps the same 500 ms cadence
		// and the same first-wire behaviour, but never returns: it applies
		// the fallback loop's `es != wired` re-install on every tick, which
		// is the asymmetry #7017 names.
		d.watchUserspaceEventStreamCallbacks(ctx)
		return
	}

	slog.Info("userspace: event stream consumer started, polling is primary until stream connects")

	// Monitor connection. When the stream is connected, events arrive via
	// callback and polling drops to 5s reconciliation. When disconnected,
	// polling resumes at 100ms.
	d.eventStreamFallbackLoop(ctx, nil)
}

// currentEventStreamProvider re-resolves the event-stream provider from the
// #2114 cell.
//
// Codex PR #6743 r6-F4: this loop used to CAPTURE the provider once, at
// Phase 5 (daemon_run.go), from the constructed-but-unarmed bootstrap
// backend — before any helper socket existed. If the bootstrap arm then
// failed and cleared the cell (daemon_run_naming.go), nothing cancelled
// this goroutine: it kept polling the STALE, disowned backend every 500ms
// for the daemon's lifetime, which is exactly the escape #2114 exists to
// close. Re-resolving per tick means an emptied cell yields no provider
// and a REPLACED backend yields the new one.
func (d *Daemon) currentEventStreamProvider() (userspaceEventStreamProvider, bool) {
	p, ok := d.dataplane().(userspaceEventStreamProvider)
	return p, ok
}

// currentSessionDeltaDrainer re-resolves the session-delta drainer from the
// #2114 cell. Every tick of the two polling loops must call this immediately
// before the drain, for the SAME reason currentEventStreamProvider exists.
//
// Codex PR #6743 r7-F1: r6-F4 made the provider and the stream per-tick but
// left the drainer captured once, at loop entry, in eventStreamFallbackLoop
// and in the (since removed, see runUserspaceEventStream) sibling polling
// loop. The loop is launched with commsCtx (daemon_ha_sync.go), which only
// stopClusterComms cancels — a dataplane disown does not. So after a
// commit-confirmed
// rollback + a failed corrected re-arm cleared the cell
// (daemon_run_naming.go), the provider correctly resolved to nothing, the
// stream reported disconnected, and the loop dropped to its FAST 100 ms
// branch — where the captured `hasDrainer` was still true and it kept
// calling DrainSessionDeltas on the torn-down, disowned backend (taking
// userspaceDeltaSyncMu each time) for the daemon's lifetime. That is the
// escape #2114 exists to close, at 10 Hz.
//
// The reverse arm matters just as much: a cell that is momentarily empty at
// loop entry used to latch hasDrainer=false (and, in the sibling polling
// loop, RETURN outright), so the reconciliation drain stayed dead for the
// goroutine's life even after a healthy backend was republished. Resolving
// per tick makes both directions self-correcting.
func (d *Daemon) currentSessionDeltaDrainer() (userspaceSessionDeltaDrainer, bool) {
	dr, ok := d.dataplane().(userspaceSessionDeltaDrainer)
	return dr, ok
}

// wireUserspaceEventStreamCallbacks waits for a stream to exist on the
// CURRENTLY published backend and installs the callbacks on it. It returns
// the stream it wired, or nil if ctx ended first.
func (d *Daemon) wireUserspaceEventStreamCallbacks(ctx context.Context) *dpuserspace.EventStream {
	// Wait for the event stream to become available (helper may not have started yet).
	for {
		if provider, ok := d.currentEventStreamProvider(); ok {
			if es := provider.EventStream(); es != nil {
				d.installEventStreamCallbacks(es)
				return es
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// watchUserspaceEventStreamCallbacks keeps the callbacks installed on
// WHATEVER stream instance the #2114 cell currently publishes, for as long as
// ctx lives. It is the standalone (no-cluster) counterpart of the
// eventStreamFallbackLoop re-install: same 500 ms cadence as
// wireUserspaceEventStreamCallbacks, same `es != wired` predicate as the
// clustered loop, minus the session-sync drain work there is nothing to do on
// this path.
//
// #7017: the clustered path was fixed for a REPLACED stream in #6743 r6-F4
// and this arm was never converted, so it wired once and returned. A
// commit-confirmed rollback tears the armed backend's stream down
// (pkg/dataplane/userspace/process.go) and the corrected re-arm constructs a
// NEW one; without this loop that replacement never got SetOnEvent /
// SetOnFullResync / the dataplane-event callback, and every helper event from
// that point sat in the callback-not-ready queue.
//
// Installing is idempotent per instance: the guard is instance IDENTITY, so a
// stream that has not been replaced is never re-wired and the callbacks are
// not reinstalled on every tick.
func (d *Daemon) watchUserspaceEventStreamCallbacks(ctx context.Context) {
	var wired *dpuserspace.EventStream
	for {
		var es *dpuserspace.EventStream
		if provider, ok := d.currentEventStreamProvider(); ok {
			es = provider.EventStream()
		}
		if es != nil && es != wired {
			d.installEventStreamCallbacks(es)
			if wired != nil {
				slog.Info("userspace: event stream replaced (rollback/re-arm), callbacks re-installed")
			}
			wired = es
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// installEventStreamCallbacks binds the daemon's handlers onto es.
//
// Split out for r6-F4's rewire: the commit-confirmed rollback CLOSES the
// armed backend's stream (pkg/dataplane/userspace/process.go) and a
// corrected re-arm constructs a NEW one. Before r6 the wiring ran once, at
// startup, on a goroutine that had already returned — so the replacement
// stream had no callbacks and its events accumulated in the
// callback-not-ready queue instead of reaching session sync. The fallback
// loop now re-installs whenever it observes a different stream instance.
func (d *Daemon) installEventStreamCallbacks(es *dpuserspace.EventStream) {
	es.SetOnEvent(func(eventType uint8, seq uint64, delta dpuserspace.SessionDeltaInfo) bool {
		return d.handleEventStreamDelta(eventType, delta)
	})
	es.SetOnFullResync(func() bool {
		return d.handleEventStreamFullResync()
	})
	if d.eventReader != nil {
		es.SetOnRawDataplaneEvent(func(seq uint64, payload []byte) {
			if !d.eventReader.ProcessRawEvent(payload) {
				slog.Debug("userspace event stream: dropped undecodable dataplane event", "seq", seq)
			}
		})
	} else {
		es.SetOnDataplaneEvent(func(seq uint64, rec logging.EventRecord) {
			if d.eventBuf != nil {
				d.eventBuf.Add(rec)
			}
		})
	}
}

// handleEventStreamDelta processes a single session event from the event
// stream. It returns true when the delta has been handled, including permanent
// non-owner no-op handling on HA backups. It returns false only for transient
// readiness gaps where EventStream should withhold ACK so the helper can replay.
func (d *Daemon) handleEventStreamDelta(eventType uint8, delta dpuserspace.SessionDeltaInfo) bool {
	ss := d.getSessionSync()
	if d.cluster == nil || ss == nil {
		slog.Debug("userspace delta: ignored (no cluster/sync)", "type", eventType)
		return true
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace delta: ignored (not primary for any RG)", "type", eventType)
		return true
	}
	if !ss.IsConnected() {
		slog.Debug("userspace delta: dropped (sync not connected)", "type", eventType)
		return false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false
	}
	zoneIDs := buildZoneIDs(cfg)

	// Map binary event type to the string event expected by queueUserspaceSessionDeltas.
	switch eventType {
	case dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionUpdate:
		delta.Event = "open"
	case dpuserspace.EventTypeSessionClose:
		delta.Event = "close"
	}

	d.queueUserspaceSessionDeltas(zoneIDs, []dpuserspace.SessionDeltaInfo{delta})
	return true
}

// handleEventStreamFullResync handles a FullResync frame from the helper.
// This means the helper's replay buffer was trimmed past our last ack; we need
// a one-shot bulk export to catch up.
func (d *Daemon) handleEventStreamFullResync() bool {
	slog.Warn("userspace event stream: full resync requested, triggering bulk export")
	ss := d.getSessionSync()
	if d.cluster == nil || ss == nil {
		slog.Debug("userspace event stream: full resync ignored (no cluster/sync)")
		return true
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace event stream: full resync ignored (not primary for any RG)")
		return true
	}
	if !ss.IsConnected() {
		slog.Debug("userspace event stream: full resync deferred (sync not connected)")
		return false
	}
	exporter, ok := d.dataplane().(userspaceSessionExporter)
	if !ok {
		return false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false
	}
	rgIDs := d.primaryOwnerRGIDs(cfg)
	if len(rgIDs) == 0 {
		return false
	}
	// #9767: the event stream retries a withheld FullResync on every later frame
	// and every ACK tick. Inside the backoff after a failed attempt, decline
	// without re-running the export.
	if d.fullResyncHeldOff(time.Now()) {
		return false
	}
	// #9766: hold the fallback loop's drain off the whole export-and-queue
	// transaction; see full_resync_transaction_9767.go.
	d.userspaceDeltaSyncMu.Lock()
	_, err := d.exportUserspaceOwnerRGSessionsWithConfig(exporter, cfg, rgIDs)
	d.userspaceDeltaSyncMu.Unlock()
	if err != nil {
		d.holdOffFullResync(time.Now())
		slog.Warn("userspace event stream: full resync export failed; the frame is not acknowledged",
			"err", err, "retry_after", fullResyncRetryBackoff)
		return false
	}
	return true
}

// eventStreamFallbackLoop monitors the event stream connection and falls back
// to polling via DrainSessionDeltas when the stream is disconnected.
// When the event stream is live, polling slows to 5s reconciliation;
// when disconnected, it runs at 100ms to compensate for the lost stream.
// wired is the stream whose callbacks are already installed; a different
// instance observed on a later tick is re-wired in place (r6-F4).
func (d *Daemon) eventStreamFallbackLoop(ctx context.Context, wired *dpuserspace.EventStream) {
	if d.cluster == nil || d.getSessionSync() == nil {
		return
	}

	const (
		fastInterval      = 100 * time.Millisecond // event stream disconnected
		reconcileInterval = 5 * time.Second        // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	defer d.eventStreamConnected.Store(false)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// r6-F4 / r7-F1: re-resolve the provider, the stream AND the
		// drainer each tick. The provider must come from the cell (a
		// captured one can be a backend the daemon disowned), a stream
		// instance that is not the one we wired is a post-rollback
		// replacement whose callbacks were never installed, and the
		// drainer resolves at each of its two use sites below (see
		// currentSessionDeltaDrainer — a captured one kept draining a
		// disowned backend at 10 Hz).
		var es *dpuserspace.EventStream
		if provider, ok := d.currentEventStreamProvider(); ok {
			es = provider.EventStream()
		}
		if es != nil && es != wired {
			d.installEventStreamCallbacks(es)
			wired = es
			slog.Info("userspace: event stream replaced (rollback/re-arm), callbacks re-installed")
		}
		connected := es != nil && es.IsConnected()

		// Track transitions and adjust cadence.
		if connected != wasConnected {
			wasConnected = connected
			d.eventStreamConnected.Store(connected)
			if connected {
				ticker.Reset(reconcileInterval)
				slog.Info("userspace: event stream connected, polling reduced to reconciliation (5s)")
			} else {
				ticker.Reset(fastInterval)
				slog.Info("userspace: event stream disconnected, polling resumed at 100ms")
			}
		}

		if connected {
			// Stream is live — run reconciliation drain to catch any
			// missed events, but at the slow 5s cadence.
			drainer, hasDrainer := d.currentSessionDeltaDrainer()
			if !hasDrainer {
				continue
			}
			ss := d.getSessionSync()
			if d.cluster == nil || ss == nil {
				return
			}
			if !d.cluster.IsLocalPrimaryAny() || !ss.IsConnected() {
				continue
			}
			cfg := d.store.ActiveConfig()
			if cfg == nil {
				continue
			}
			n, _ := d.drainUserspaceSessionDeltasLocked(drainer, cfg)
			if n > 0 {
				slog.Info("userspace: reconciliation drain caught missed deltas", "count", n)
			}
			continue
		}

		// Stream disconnected — fall back to fast polling.
		drainer, hasDrainer := d.currentSessionDeltaDrainer()
		if !hasDrainer {
			continue
		}
		ss := d.getSessionSync()
		if d.cluster == nil || ss == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !ss.IsConnected() {
			continue
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		_, _ = d.drainUserspaceSessionDeltasLocked(drainer, cfg)
	}
}

// userspaceDeltaSink receives the sessions one helper delta batch resolves to,
// after conversion and the sync-eligibility filter have both run.
//
// #6031: the incremental queue path and the cold-prime table-truth snapshot
// collector are two SINKS over ONE walk, deliberately. The standby must end up
// holding the same session set whichever path delivered it, and the bulk window
// DELETES every eligible session it omits — so a divergence between the two
// filters is always a bug, never a legitimate difference. Single-sourcing the
// walk makes that divergence unrepresentable instead of merely tested.
//
// #7188: the delete arms take the converted VALUE as well as the key. A
// dataplane.SessionKey is a 5-tuple, and protocol 47 carries no L4 ports, so
// two RFC 2890 GRE tunnels between one pair of outer endpoints have EQUAL keys
// and differ only in val.TunnelDiscriminator. A sink that dedupes or retracts
// on the key alone therefore merges them; the value is what tells them apart.
type userspaceDeltaSink interface {
	openV4(key dataplane.SessionKey, val dataplane.SessionValue)
	openV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6)
	deleteV4(key dataplane.SessionKey, val dataplane.SessionValue)
	deleteV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6)
}

// queueDeltaSink forwards each resolved session onto the incremental
// session-sync send queue — the historical behavior of
// queueUserspaceSessionDeltas.
type queueDeltaSink struct{ ss *cluster.SessionSync }

func (q queueDeltaSink) openV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	q.ss.QueueSessionV4(key, val)
}

func (q queueDeltaSink) openV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	q.ss.QueueSessionV6(key, val)
}

// The cluster delete message carries the key and the #2170 delete generation
// only, so the #7188 discriminator on `val` has nowhere to ride here. The peer
// helper reconstructs a delete key with `Delete` intent and resolves an absent
// discriminator to the None class, so such a delete can only UNDER-match: a
// keyed-GRE synced session is retracted by its idle timeout rather than by an
// explicit delete. Under-matching is the safe direction — it never merges two
// identities — which is why the install arm fails closed and this one does not.
func (q queueDeltaSink) deleteV4(key dataplane.SessionKey, _ dataplane.SessionValue) {
	q.ss.QueueDeleteV4(key)
}

func (q queueDeltaSink) deleteV6(key dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
	q.ss.QueueDeleteV6(key)
}

// snapshotDeltaSink accumulates a point-in-time set of LIVE sessions for one
// authoritative bulk window (#6031). A close delta drained alongside the export
// retracts its key: the exported open and the close can both appear in one
// batch, and framing an already-closed session would resurrect it on the peer.
// Keys are accumulated in maps, so a repeated open is idempotent and window
// order is irrelevant (the receiver keys the window by session key).
//
// #7188: the map key is the session key PLUS the tunnel discriminator, not the
// session key alone. A dataplane.SessionKey is a 5-tuple and protocol 47 has no
// L4 ports, so two RFC 2890 GRE tunnels between one pair of outer endpoints
// produce EQUAL keys; deduping on the key alone silently dropped one of them
// from every cold-prime window, and the standby then held one session for two
// tunnels — the same collapse #7188 removes from the helper's own key. The
// emitted BulkSnapshot is a SLICE, so two entries with equal keys and different
// discriminators both ride the window and the peer helper folds each
// discriminator into the key it reconstructs.
type snapshotDeltaSink struct {
	v4 map[snapshotDedupKeyV4]dataplane.SessionValue
	v6 map[snapshotDedupKeyV6]dataplane.SessionValueV6
}

// snapshotDedupKeyV4 is the IDENTITY the cold-prime window dedupes on: the
// 5-tuple the peer's wire key carries plus the #7188 discriminator the peer
// folds into it. Comparable by construction (both members are comparable), so
// it is a valid map key.
type snapshotDedupKeyV4 struct {
	key           dataplane.SessionKey
	discriminator uint64
}

type snapshotDedupKeyV6 struct {
	key           dataplane.SessionKeyV6
	discriminator uint64
}

func newSnapshotDeltaSink() *snapshotDeltaSink {
	return &snapshotDeltaSink{
		v4: make(map[snapshotDedupKeyV4]dataplane.SessionValue),
		v6: make(map[snapshotDedupKeyV6]dataplane.SessionValueV6),
	}
}

func (c *snapshotDeltaSink) openV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	c.v4[snapshotDedupKeyV4{key: key, discriminator: val.TunnelDiscriminator}] = val
}

func (c *snapshotDeltaSink) openV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	c.v6[snapshotDedupKeyV6{key: key, discriminator: val.TunnelDiscriminator}] = val
}

func (c *snapshotDeltaSink) deleteV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	delete(c.v4, snapshotDedupKeyV4{key: key, discriminator: val.TunnelDiscriminator})
}

func (c *snapshotDeltaSink) deleteV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	delete(c.v6, snapshotDedupKeyV6{key: key, discriminator: val.TunnelDiscriminator})
}

func (c *snapshotDeltaSink) snapshot() cluster.BulkSnapshot {
	snap := cluster.BulkSnapshot{
		V4: make([]dataplane.SessionEntryV4, 0, len(c.v4)),
		V6: make([]dataplane.SessionEntryV6, 0, len(c.v6)),
	}
	for dedup, val := range c.v4 {
		snap.V4 = append(snap.V4, dataplane.SessionEntryV4{Key: dedup.key, Value: val})
	}
	for dedup, val := range c.v6 {
		snap.V6 = append(snap.V6, dataplane.SessionEntryV6{Key: dedup.key, Value: val})
	}
	return snap
}

// walkUserspaceSessionDeltas converts each helper delta, applies the
// sync-eligibility filter, and hands every admitted session to sink. It returns
// the number of sink calls made.
func (d *Daemon) walkUserspaceSessionDeltas(
	ss *cluster.SessionSync,
	zoneIDs map[string]uint16,
	deltas []dpuserspace.SessionDeltaInfo,
	sink userspaceDeltaSink,
) int {
	n := 0
	for _, delta := range deltas {
		switch strings.ToLower(delta.Event) {
		// #9412: "update" is a close-state update for a live session. It carries
		// the same record as an open and syncs the same way: the peer upserts it
		// with the new close class.
		case "open", "update":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if !ok {
					slog.Debug("userspace delta: V4 conversion failed", "src", delta.SrcIP, "dst", delta.DstIP, "disposition", delta.Disposition)
					continue
				}
				if !d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					continue
				}
				sink.openV4(key, val)
				slog.Debug("userspace delta: admitted V4", "src", delta.SrcIP, "dst", delta.DstIP, "ownerRG", delta.OwnerRGID)
				n++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasV4(key, val, delta); ok {
						sink.openV4(wireKey, wireVal)
						n++
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if !ok || !d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					continue
				}
				sink.openV6(key, val)
				n++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasV6(key, val, delta); ok {
						sink.openV6(wireKey, wireVal)
						n++
					}
				}
			}
		case "close":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					sink.deleteV4(key, val)
					n++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV4(key, delta)
						if wireKey != key {
							sink.deleteV4(wireKey, val)
							n++
						}
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(ss, delta, val.IngressZone) {
					sink.deleteV6(key, val)
					n++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV6(key, delta)
						if wireKey != key {
							sink.deleteV6(wireKey, val)
							n++
						}
					}
				}
			}
		}
	}
	return n
}

func (d *Daemon) queueUserspaceSessionDeltas(
	zoneIDs map[string]uint16,
	deltas []dpuserspace.SessionDeltaInfo,
) int {
	// Snapshot the live session-sync object once for the whole batch (#4958):
	// the per-delta filter and queue calls all operate on this pointer instead
	// of re-reading the shared field, so the hot path never locks per delta and
	// a concurrent stopClusterComms cannot nil the field mid-batch.
	ss := d.getSessionSync()
	if ss == nil {
		return 0
	}
	// #7194 fail-closed gate. The binary event stream and the JSON drain
	// fallback queue through here. The FullResync export queues through
	// queueUserspaceSessionDeltasComplete, which applies the same gate and
	// reports a withheld batch as a failure (#9767).
	if !d.userspaceDeltaSchemaAdmits(len(deltas)) {
		return 0
	}
	return d.walkUserspaceSessionDeltas(ss, zoneIDs, deltas, queueDeltaSink{ss: ss})
}

func (d *Daemon) drainUserspaceSessionDeltasWithConfig(
	drainer userspaceSessionDeltaDrainer,
	cfg *config.Config,
	maxBatches int,
) (int, error) {
	if drainer == nil || cfg == nil || maxBatches <= 0 {
		return 0, nil
	}
	zoneIDs := buildZoneIDs(cfg)
	total := 0
	for batch := 0; batch < maxBatches; batch++ {
		deltas, status, err := drainer.DrainSessionDeltas(256)
		if err != nil {
			return total, err
		}
		// #7194: the drain already carries the helper's ProcessStatus; record
		// the advertised delta-schema fingerprint so the consumption gate can
		// see it. Also reached while the binary stream is UP, because the
		// fallback loop still reconciles over JSON every 5s.
		d.recordUserspaceDeltaSchema(status.SessionDeltaSchemaFingerprint)
		if len(deltas) == 0 {
			break
		}
		total += d.queueUserspaceSessionDeltas(zoneIDs, deltas)
		if len(deltas) < 256 {
			break
		}
	}
	return total, nil
}
