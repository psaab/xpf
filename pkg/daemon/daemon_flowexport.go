// daemon_flowexport.go — NetFlow v9 / IPFIX exporter lifecycle wiring
// (#2075).
//
// Before #2075 the flow exporters were started once at daemon boot and
// stopped only at shutdown: the apply path (daemon_apply.go) had zero
// flowexport references, so a runtime commit that changed
// forwarding-options sampling (collector address/port, source-address,
// 1-in-N input-rate, which zones sample, a v9 export-extension) was
// silently ignored until a daemon restart — and flow export ADDED in a
// later commit never started at all.
//
// reconcileFlowExporters runs on every apply (and at boot, after the
// EventReader exists) but is CONFIG-HASH-GATED per family: it
// (re)starts or stops an exporter only when the rendered v9 / IPFIX
// stanza actually changed, so an unrelated commit never bounces a
// healthy exporter (preserving its template-refresh cadence and the
// 1-in-N sampling counter).
//
// The EventReader callback list is append-only with only a clear-ALL
// primitive (no per-callback removal), and the same EventReader carries
// callbacks for the trace writer too. A naive stop/start reconcile
// would therefore leak a closure (closed over a now-closed exporter) on
// every commit. Instead we register stable indirection callbacks exactly
// once that read the live (exporter, config) pair from atomic.Pointer
// bundles; reconcile swaps the bundles atomically. SESSION_OPEN has its
// own single fanout callback (#16303): EventReader invokes every
// callback for every record, so routing opens through both protocol
// callbacks sampled each open twice in dual-format deployments. The
// resolved *ExportConfig is held by pointer everywhere — in the bundle,
// by the callbacks' sampling decision, AND inside the exporter (#2224)
// — so there is exactly ONE live 1-in-N sampleCounter per instance and
// protocol. ExportConfig embeds that counter as an atomic.Uint64;
// passing it by value would copy the atomic (a go-vet "copies lock
// value" failure) and fork the counter, silently re-seeding the modulo
// cadence the moment any caller sampled off the copy.

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/logging"
)

// ensureFlowExportOpenCallback registers the single SESSION_OPEN fanout
// callback the first time either exporter family publishes groups.
func (d *Daemon) ensureFlowExportOpenCallback() {
	if d == nil || d.eventReader == nil {
		return
	}
	d.flowOpenCBOnce.Do(func() {
		d.eventReader.AddCallback(d.flowExportOpenCallback)
	})
}

// flowLiveFeedInterval is the live session-counter poll cadence. One
// second matches the exporters' own 100ms collect tick granularity
// without adding a control-plane round-trip per tick: each poll only
// reads counters for flows some tracker actually holds.
const flowLiveFeedInterval = time.Second

// ensureFlowLiveFeed starts the daemon-lifetime poll that feeds live
// session counters into every published exporter tracker (#16303 F5).
// Before this, TouchFlow ran only inside the close callbacks, so the
// active timer exported zero counters for long-lived flows and the
// inactive timer forgot continuously-active flows as idle.
func (d *Daemon) ensureFlowLiveFeed() {
	if d == nil || d.daemonCtx == nil {
		return
	}
	d.flowLiveFeedOnce.Do(func() {
		go d.flowLiveFeedLoop(d.daemonCtx)
	})
}

func (d *Daemon) flowLiveFeedLoop(ctx context.Context) {
	t := time.NewTicker(flowLiveFeedInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.feedFlowLiveCounters(now)
		}
	}
}

// feedFlowLiveCounters polls the live counter source once per tracked
// key per exporter group and touches that group's tracker. TrackedKeys
// includes sampled-idle marker keys (#16747), so a flow that resumed
// after inactive expiry is observed and re-armed. Keys are unioned per
// group so a flow tracked by several template groups of one instance is
// read once and fed to each. A key the source no longer holds is
// skipped (its close or inactive expiry will forget it) and counted in
// flowLiveFeedMisses (#16760): before the port byte-order fix every
// lookup missed, so this counter is the operator-visible signal that
// the live feed is not reaching the session store.
func (d *Daemon) feedFlowLiveCounters(now time.Time) {
	for _, ff := range d.flowFamiliesOrNil() {
		ff.feedLiveCounters(d, now)
	}
}

// feedLiveCounters feeds live counters into this family's groups.
func (ff *flowFamily) feedLiveCounters(d *Daemon, now time.Time) {
	b := ff.bundle.Load()
	if b == nil {
		return
	}
	for _, g := range b.groups {
		for _, key := range g.exp.TrackedKeys() {
			if fp, fb, rp, rb, ok := d.liveFlowCounters(key); ok {
				g.exp.TouchFlowBidirectional(key, now, fp, fb, rp, rb)
			} else {
				d.flowLiveFeedMisses.Add(1)
			}
		}
	}
}

// FlowLiveFeedMisses returns the cumulative count of live-counter
// lookups that found no session-store entry for a tracked flow
// (#16760). A sustained climb while flows are tracked means the live
// feed cannot reach the session store (wrong key encoding, store
// absent), so active interims export zero counters and the inactive
// timer forgets continuously-active flows as idle.
func (d *Daemon) FlowLiveFeedMisses() uint64 {
	if d == nil {
		return 0
	}
	return d.flowLiveFeedMisses.Load()
}

// liveFlowCounters is the production per-key counter source: the
// dataplane session store's forward entry for the tracked tuple. The
// forward entry's counters already sum both directions' volume as the
// helper maintains them (fwd = initiator direction, rev = responder).
// SessionKey ports carry __be16 (network order) on the map — the Rust
// helper writes them with src_port.to_be() (#16760) — while FlowKey
// ports are host order (parseSrcPort), so convert with
// userspaceHostToNetwork16 or every lookup misses on the raw key bytes.
// The IP must be parsed directly, not via parseHost: FlowKey addresses
// are the bare IP strings FlowKeyFromClose stored (net.IP.String()),
// and parseHost's last-colon strip would truncate a bare IPv6 address
// at its final hextet. Tests override d.flowLiveCounters instead of
// standing up a dataplane.
func (d *Daemon) liveFlowCounters(key flowexport.FlowKey) (uint64, uint64, uint64, uint64, bool) {
	if d.flowLiveCounters != nil {
		return d.flowLiveCounters(key)
	}
	dp := d.dataplane()
	if dp == nil {
		return 0, 0, 0, 0, false
	}
	store := dp.Sessions()
	if store == nil {
		return 0, 0, 0, 0, false
	}
	if key.IsIPv6 {
		var src, dst [16]byte
		copy(src[:], net.ParseIP(key.SrcIP).To16())
		copy(dst[:], net.ParseIP(key.DstIP).To16())
		val, err := store.GetV6(dataplane.SessionKeyV6{SrcIP: src, DstIP: dst, SrcPort: userspaceHostToNetwork16(key.SrcPort), DstPort: userspaceHostToNetwork16(key.DstPort), Protocol: key.Protocol})
		if err != nil {
			return 0, 0, 0, 0, false
		}
		return val.FwdPackets, val.FwdBytes, val.RevPackets, val.RevBytes, true
	}
	var src, dst [4]byte
	copy(src[:], net.ParseIP(key.SrcIP).To4())
	copy(dst[:], net.ParseIP(key.DstIP).To4())
	val, err := store.GetV4(dataplane.SessionKey{SrcIP: src, DstIP: dst, SrcPort: userspaceHostToNetwork16(key.SrcPort), DstPort: userspaceHostToNetwork16(key.DstPort), Protocol: key.Protocol})
	if err != nil {
		return 0, 0, 0, 0, false
	}
	return val.FwdPackets, val.FwdBytes, val.RevPackets, val.RevBytes, true
}

// flowExporter is the method set both stateful encoders expose through
// the shared exporterCore (#16126). The encoders stay distinct types;
// the daemon lifecycle speaks only this interface (#17057).
//
// Production calls only the lifecycle/tracker/stats methods below.
// CollectDueExports, SetMaskResolver and ExportSessionClose are a test
// surface: hermetic cells drive them via firstExp()/group exporters to
// observe interims and mask resolution without a collector round-trip;
// production sets the mask resolver inside the flowexport constructors
// and exports closes via ExportSessionCloseRemainder. TransferFlowStateTo
// is likewise test-only — production carry uses AbsorbSampledInto.
type flowExporter interface {
	Run(ctx context.Context)
	Close()
	Retire()
	SetHandoffCounter(*atomic.Uint64)
	CloseFlowOrSample(key flowexport.FlowKey, decide func() bool) (bool, uint64, uint64, uint64, uint64)
	ExportSessionCloseRemainder(rec logging.EventRecord, evt flowexport.SessionCloseData, basePkts, baseBytes, baseRevPkts, baseRevBytes uint64)
	MarkFlowSampledAtOpen(key flowexport.FlowKey)
	MarkFlowRejectedAtOpen(key flowexport.FlowKey)
	TrackFlowOpenRecord(key flowexport.FlowKey, start time.Time, template flowexport.FlowRecord)
	TrackedKeys() []flowexport.FlowKey
	Tracked(key flowexport.FlowKey) bool
	HasFlowState(key flowexport.FlowKey) bool
	TouchFlowBidirectional(key flowexport.FlowKey, now time.Time, fwdPackets, fwdBytes, revPackets, revBytes uint64)
	CollectorHealth() []flowexport.CollectorHealth
	Stats() (flows, packets uint64)
	BatchDepth() uint64
	BatchMaxDepth() uint64
	BatchDropped() uint64
	HandoffDropped() uint64
	RouteMaskUnresolved() uint64
	EstimatedDurations() uint64
	ClockSkewClamped() uint64
	AbsorbSampledInto(dst flowExporter)

	// Test surface (see comment above); not called by production code.
	CollectDueExports(now time.Time) []flowexport.FlowRecord
	SetMaskResolver(r flowexport.MaskResolver)
	TransferFlowStateTo(dst flowExporter, key flowexport.FlowKey)
	ExportSessionClose(rec logging.EventRecord, evt flowexport.SessionCloseData)
}

type v9Exporter struct{ e *flowexport.Exporter }

func (w v9Exporter) Run(ctx context.Context) { w.e.Run(ctx) }
func (w v9Exporter) Close()                  { w.e.Close() }
func (w v9Exporter) Retire()                 { w.e.Retire() }
func (w v9Exporter) SetHandoffCounter(c *atomic.Uint64) {
	w.e.SetHandoffCounter(c)
}
func (w v9Exporter) CloseFlowOrSample(key flowexport.FlowKey, decide func() bool) (bool, uint64, uint64, uint64, uint64) {
	return w.e.CloseFlowOrSample(key, decide)
}
func (w v9Exporter) ExportSessionCloseRemainder(rec logging.EventRecord, evt flowexport.SessionCloseData, a, b, c, e uint64) {
	w.e.ExportSessionCloseRemainder(rec, evt, a, b, c, e)
}
func (w v9Exporter) ExportSessionClose(rec logging.EventRecord, evt flowexport.SessionCloseData) {
	w.e.ExportSessionClose(rec, evt)
}
func (w v9Exporter) MarkFlowSampledAtOpen(key flowexport.FlowKey)  { w.e.MarkFlowSampledAtOpen(key) }
func (w v9Exporter) MarkFlowRejectedAtOpen(key flowexport.FlowKey) { w.e.MarkFlowRejectedAtOpen(key) }
func (w v9Exporter) TrackFlowOpenRecord(key flowexport.FlowKey, start time.Time, tmpl flowexport.FlowRecord) {
	w.e.TrackFlowOpenRecord(key, start, tmpl)
}
func (w v9Exporter) TrackedKeys() []flowexport.FlowKey { return w.e.TrackedKeys() }
func (w v9Exporter) Tracked(key flowexport.FlowKey) bool {
	return w.e.Tracked(key)
}
func (w v9Exporter) HasFlowState(key flowexport.FlowKey) bool { return w.e.HasFlowState(key) }
func (w v9Exporter) TouchFlowBidirectional(key flowexport.FlowKey, now time.Time, a, b, c, e uint64) {
	w.e.TouchFlowBidirectional(key, now, a, b, c, e)
}
func (w v9Exporter) CollectorHealth() []flowexport.CollectorHealth {
	return w.e.CollectorHealth()
}
func (w v9Exporter) Stats() (uint64, uint64) { return w.e.Stats() }
func (w v9Exporter) BatchDepth() uint64      { return w.e.BatchDepth() }
func (w v9Exporter) BatchMaxDepth() uint64   { return w.e.BatchMaxDepth() }
func (w v9Exporter) BatchDropped() uint64    { return w.e.BatchDropped() }
func (w v9Exporter) HandoffDropped() uint64  { return w.e.HandoffDropped() }
func (w v9Exporter) RouteMaskUnresolved() uint64 {
	return w.e.RouteMaskUnresolved()
}
func (w v9Exporter) EstimatedDurations() uint64 { return w.e.EstimatedDurations() }
func (w v9Exporter) ClockSkewClamped() uint64   { return w.e.ClockSkewClamped() }
func (w v9Exporter) CollectDueExports(now time.Time) []flowexport.FlowRecord {
	return w.e.CollectDueExports(now)
}
func (w v9Exporter) SetMaskResolver(r flowexport.MaskResolver) { w.e.MaskResolver = r }
func (w v9Exporter) TransferFlowStateTo(dst flowExporter, key flowexport.FlowKey) {
	if d, ok := dst.(v9Exporter); ok {
		w.e.TransferFlowStateTo(d.e, key)
	}
}
func (w v9Exporter) AbsorbSampledInto(dst flowExporter) {
	if d, ok := dst.(v9Exporter); ok {
		w.e.AbsorbSampledInto(d.e)
	}
}

type ipfixExporter struct{ e *flowexport.IPFIXExporter }

func (w ipfixExporter) Run(ctx context.Context) { w.e.Run(ctx) }
func (w ipfixExporter) Close()                  { w.e.Close() }
func (w ipfixExporter) Retire()                 { w.e.Retire() }
func (w ipfixExporter) SetHandoffCounter(c *atomic.Uint64) {
	w.e.SetHandoffCounter(c)
}
func (w ipfixExporter) CloseFlowOrSample(key flowexport.FlowKey, decide func() bool) (bool, uint64, uint64, uint64, uint64) {
	return w.e.CloseFlowOrSample(key, decide)
}
func (w ipfixExporter) ExportSessionCloseRemainder(rec logging.EventRecord, evt flowexport.SessionCloseData, a, b, c, e uint64) {
	w.e.ExportSessionCloseRemainder(rec, evt, a, b, c, e)
}
func (w ipfixExporter) ExportSessionClose(rec logging.EventRecord, evt flowexport.SessionCloseData) {
	w.e.ExportSessionClose(rec, evt)
}
func (w ipfixExporter) MarkFlowSampledAtOpen(key flowexport.FlowKey) { w.e.MarkFlowSampledAtOpen(key) }
func (w ipfixExporter) MarkFlowRejectedAtOpen(key flowexport.FlowKey) {
	w.e.MarkFlowRejectedAtOpen(key)
}
func (w ipfixExporter) TrackFlowOpenRecord(key flowexport.FlowKey, start time.Time, tmpl flowexport.FlowRecord) {
	w.e.TrackFlowOpenRecord(key, start, tmpl)
}
func (w ipfixExporter) TrackedKeys() []flowexport.FlowKey { return w.e.TrackedKeys() }
func (w ipfixExporter) Tracked(key flowexport.FlowKey) bool {
	return w.e.Tracked(key)
}
func (w ipfixExporter) HasFlowState(key flowexport.FlowKey) bool { return w.e.HasFlowState(key) }
func (w ipfixExporter) TouchFlowBidirectional(key flowexport.FlowKey, now time.Time, a, b, c, e uint64) {
	w.e.TouchFlowBidirectional(key, now, a, b, c, e)
}
func (w ipfixExporter) CollectorHealth() []flowexport.CollectorHealth {
	return w.e.CollectorHealth()
}
func (w ipfixExporter) Stats() (uint64, uint64) { return w.e.Stats() }
func (w ipfixExporter) BatchDepth() uint64      { return w.e.BatchDepth() }
func (w ipfixExporter) BatchMaxDepth() uint64   { return w.e.BatchMaxDepth() }
func (w ipfixExporter) BatchDropped() uint64    { return w.e.BatchDropped() }
func (w ipfixExporter) HandoffDropped() uint64  { return w.e.HandoffDropped() }
func (w ipfixExporter) RouteMaskUnresolved() uint64 {
	return w.e.RouteMaskUnresolved()
}
func (w ipfixExporter) EstimatedDurations() uint64 { return w.e.EstimatedDurations() }
func (w ipfixExporter) ClockSkewClamped() uint64   { return w.e.ClockSkewClamped() }
func (w ipfixExporter) CollectDueExports(now time.Time) []flowexport.FlowRecord {
	return w.e.CollectDueExports(now)
}
func (w ipfixExporter) SetMaskResolver(r flowexport.MaskResolver) { w.e.MaskResolver = r }
func (w ipfixExporter) TransferFlowStateTo(dst flowExporter, key flowexport.FlowKey) {
	if d, ok := dst.(ipfixExporter); ok {
		w.e.TransferFlowStateTo(d.e, key)
	}
}
func (w ipfixExporter) AbsorbSampledInto(dst flowExporter) {
	if d, ok := dst.(ipfixExporter); ok {
		w.e.AbsorbSampledInto(d.e)
	}
}

// flowGroup is one running template-group exporter and its resolved
// config (#2461). cancel/wg retire exactly this exporter (#16752).
type flowGroup struct {
	exp    flowExporter
	ec     *flowexport.ExportConfig
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// flowBundle is the immutable per-family set of template-group exporters
// the session-close callback reads. An empty groups slice means "no
// exporter configured" for that family. The groups share one
// ExportConfig.sampleCounter, so the callback evaluates SampledForOpen
// EXACTLY ONCE per instance and fans out to every group (#2461).
type flowBundle struct {
	groups []flowGroup
}

// firstExp returns the first running group exporter, or nil.
func (b *flowBundle) firstExp() flowExporter {
	if b == nil || len(b.groups) == 0 {
		return nil
	}
	return b.groups[0].exp
}

// flowFamily holds all per-protocol lifecycle state once (#17057).
type flowFamily struct {
	name string
	d    *Daemon
	mu   sync.Mutex

	bundle atomic.Pointer[flowBundle]
	hash   [32]byte
	hasSet bool
	cbOnce sync.Once
	err    error

	exporters []flowExporter
	cancel    context.CancelFunc
	wg        *sync.WaitGroup

	configured     atomic.Int64
	excluded       atomic.Int64
	handoffDropped atomic.Uint64
	failedGroups   map[string]bool

	stateCarryTestHook func()
}

func newFlowFamilies(d *Daemon) [2]*flowFamily {
	return [2]*flowFamily{
		{name: "netflow-v9", d: d},
		{name: "ipfix", d: d},
	}
}

// resolvedFlowFamilies returns the two parameterized families. New
// initializes them in the constructor; the lazy fallback here runs
// exactly once behind flowFamiliesOnce so that &Daemon{} fixtures
// (which never went through New) still get families without an
// unsynchronized write to d.flowFamilies racing a concurrent metrics
// scrape or reconcile. Nil-family guards below keep a partially built
// fixture safe.
func (d *Daemon) resolvedFlowFamilies() []*flowFamily {
	if d == nil {
		return nil
	}
	d.flowFamiliesOnce.Do(func() {
		if d.flowFamilies[0] == nil {
			d.flowFamilies = newFlowFamilies(d)
		}
	})
	out := make([]*flowFamily, 0, 2)
	for _, ff := range d.flowFamilies {
		if ff != nil {
			out = append(out, ff)
		}
	}
	return out
}

// flowFamiliesOrNil is the nil-receiver-safe name used by the exported
// stats accessors; it shares the Once-guarded initialization above.
func (d *Daemon) flowFamiliesOrNil() []*flowFamily { return d.resolvedFlowFamilies() }

func (d *Daemon) v9Family() *flowFamily {
	fams := d.resolvedFlowFamilies()
	if len(fams) == 0 {
		return &flowFamily{name: "netflow-v9", d: d}
	}
	return d.flowFamilies[0]
}

func (d *Daemon) ipfixFamily() *flowFamily {
	fams := d.resolvedFlowFamilies()
	if len(fams) == 0 {
		return &flowFamily{name: "ipfix", d: d}
	}
	return d.flowFamilies[1]
}

func (ff *flowFamily) buildConfigs(cfg *config.Config) []*flowexport.ExportConfig {
	var ecs []*flowexport.ExportConfig
	if ff.name == "netflow-v9" {
		ff.excluded.Store(int64(flowexport.CountExcludedFlowServers(
			&cfg.Services, &cfg.ForwardingOptions, config.FlowServerVersion9)))
		ecs = flowexport.ResolveV9TemplateGroups(&cfg.Services, &cfg.ForwardingOptions)
	} else {
		ff.excluded.Store(int64(flowexport.CountExcludedFlowServers(
			&cfg.Services, &cfg.ForwardingOptions, config.FlowServerVersionIPFIX)))
		ecs = flowexport.ResolveIPFIXTemplateGroups(&cfg.Services, &cfg.ForwardingOptions)
	}
	if len(ecs) == 0 {
		return nil
	}
	zoneIDs := buildZoneIDs(cfg)
	zones := flowexport.BuildSamplingZones(cfg, zoneIDs)
	for _, ec := range ecs {
		ec.SamplingZones = zones
	}
	return ecs
}

func (ff *flowFamily) newExporter(ec *flowexport.ExportConfig) (flowExporter, error) {
	if ff.name == "netflow-v9" {
		e, err := flowexport.NewExporter(ec)
		if err != nil {
			return nil, err
		}
		return v9Exporter{e: e}, nil
	}
	e, err := flowexport.NewIPFIXExporter(ec)
	if err != nil {
		return nil, err
	}
	return ipfixExporter{e: e}, nil
}

// flowExportConfigHash hashes the resolved per-family template groups
// ([]*ExportConfig: Collectors, TemplateName, timeouts, SamplingZones,
// SamplingRate, V9TemplateOpts). The unexported atomic.Uint64 sampleCounter
// is invisible to json.Marshal, and Go marshals map[uint16]SamplingDir keys
// in sorted numeric order, so the encoding is deterministic — provided the
// resolver returns the groups in a stable order (it sorts by template name;
// #2461). An empty slice hashes to a distinct sentinel so "configured ->
// removed" registers as a real change.
func flowExportConfigHash(ecs []*flowexport.ExportConfig) [32]byte {
	if len(ecs) == 0 {
		// Distinct, stable sentinel for the unconfigured state.
		return sha256.Sum256([]byte("flowexport:nil"))
	}
	data, err := json.Marshal(ecs)
	if err != nil {
		// Marshal of plain structs cannot realistically fail; fall back
		// to a zero hash (forces re-apply) rather than silently skip.
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

func flowGroupKey(ec *flowexport.ExportConfig) string {
	if ec == nil {
		return ""
	}
	return ec.InstanceName + "\x00" + ec.TemplateName + "\x00" + flowExportAddressFamily(ec.GroupIsV6)
}

func flowFailedKey(family string, ec *flowexport.ExportConfig) string {
	if ec == nil {
		return family + "\x00"
	}
	return family + "\x00" + ec.InstanceName
}

// reconcileFlowExporters reconciles BOTH the NetFlow v9 and IPFIX
// exporters against the committed config. Safe to call from boot (after
// the EventReader exists) and from applyConfigLocked. Returns true when
// either family actually (re)started or stopped.
//
// No-ops (returns false) when the EventReader does not yet exist — the
// boot apply runs before the EventReader is created, so the
// post-EventReader boot block is what first starts the exporters; the
// apply-path call handles every later commit.
func (d *Daemon) reconcileFlowExporters(cfg *config.Config) bool {
	if cfg == nil || d.eventReader == nil || d.daemonCtx == nil {
		return false
	}
	changed := false
	for _, ff := range d.flowFamiliesOrNil() {
		if ff.reconcile(cfg) {
			changed = true
		}
	}
	// #9166: a build failure here used to wait for the NEXT COMMIT, which on a
	// stable box is never — while the two faults that cause one (unresolvable
	// collector DNS, a pinned source bind before the interface is up) both
	// clear on their own minutes later. Arm the autonomous retry instead.
	//
	// Armed HERE, outside both reconcile mutexes: armFlowExportRetry's loop
	// re-enters reconcileFlowExporters, which takes them.
	d.noteFlowExportBuildResult()
	return changed
}

// reconcile reconciles this family's template-group exporters (one per
// per-flow-server template, #2461). #15230: groups build independently.
func (ff *flowFamily) reconcile(cfg *config.Config) bool {
	d := ff.d
	ff.mu.Lock()
	defer ff.mu.Unlock()
	ecs := ff.buildConfigs(cfg)
	ff.configured.Store(int64(len(ecs)))
	h := flowExportConfigHash(ecs)
	if ff.hasSet && h == ff.hash {
		return false
	}
	wasRunning := len(ff.exporters) > 0
	if len(ecs) == 0 {
		ff.teardownLocked()
		ff.hash, ff.hasSet = h, true
		ff.err = nil
		ff.failedGroups = nil
		if !wasRunning {
			return false
		}
		slog.Info("flow exporter stopped (flow export removed)", "family", ff.name)
		return true
	}
	oldByKey := make(map[string]flowGroup)
	if b := ff.bundle.Load(); b != nil {
		for _, g := range b.groups {
			oldByKey[flowGroupKey(g.ec)] = g
		}
	}
	var newGroups []flowGroup
	var newExps []flowExporter
	var failedErr error
	failed := make(map[string]bool)
	failedInstances := make(map[string]bool)
	desiredKeys := make(map[string]bool)
	for _, ec := range ecs {
		desiredKeys[flowGroupKey(ec)] = true
	}
	for _, ec := range ecs {
		exp, err := ff.newExporter(ec)
		if err != nil {
			slog.Warn("failed to create flow exporter group; other groups continue",
				"family", ff.name, "template", ec.TemplateName, "instance", ec.InstanceName, "err", err)
			failed[flowFailedKey(ff.name, ec)] = true
			failedInstances[ec.InstanceName] = true
			if failedErr == nil {
				failedErr = err
			}
			continue
		}
		exp.SetHandoffCounter(&ff.handoffDropped)
		newExps = append(newExps, exp)
		newGroups = append(newGroups, flowGroup{exp: exp, ec: ec})
	}
	retainedGroups, retainedExps := ff.retainedLocked(failedInstances, desiredKeys, oldByKey)
	if len(newGroups) == 0 && len(retainedGroups) == 0 {
		if !wasRunning {
			d.flowStateMu.Lock()
			ff.bundle.Store(&flowBundle{})
			d.flowStateMu.Unlock()
		}
		ff.hasSet = false
		ff.err = failedErr
		ff.failedGroups = failed
		return true
	}
	d.ensureFlowExportOpenCallback()
	d.ensureFlowLiveFeed()
	ff.cbOnce.Do(func() {
		d.eventReader.AddCallback(ff.closeCallback)
	})
	for i := range newGroups {
		childCtx, childCancel := context.WithCancel(d.daemonCtx)
		wg := &sync.WaitGroup{}
		wg.Add(1)
		newGroups[i].cancel = childCancel
		newGroups[i].wg = wg
		exp := newGroups[i].exp
		go func() {
			defer wg.Done()
			exp.Run(childCtx)
		}()
	}
	newByKey := make(map[string]flowGroup)
	for _, g := range newGroups {
		newByKey[flowGroupKey(g.ec)] = g
	}
	retByKey := make(map[string]flowGroup)
	for _, g := range retainedGroups {
		retByKey[flowGroupKey(g.ec)] = g
	}
	var published []flowGroup
	for _, ec := range ecs {
		k := flowGroupKey(ec)
		if g, ok := newByKey[k]; ok {
			published = append(published, g)
		} else if g, ok := retByKey[k]; ok {
			published = append(published, g)
		}
	}
	allExps := make([]flowExporter, 0, len(newExps)+len(retainedExps))
	allExps = append(allExps, retainedExps...)
	allExps = append(allExps, newExps...)
	ff.exporters = allExps
	if len(published) > 0 {
		last := published[len(published)-1]
		ff.cancel = last.cancel
		ff.wg = last.wg
	} else {
		ff.cancel = nil
		ff.wg = nil
	}
	d.flowStateMu.Lock()
	ff.carryFlowStateLocked(published)
	if ff.stateCarryTestHook != nil {
		ff.stateCarryTestHook()
	}
	ff.bundle.Store(&flowBundle{groups: published})
	d.flowStateMu.Unlock()
	publishedExp := make(map[flowExporter]bool)
	for _, g := range published {
		publishedExp[g.exp] = true
	}
	ff.retireGroups(oldByKey, publishedExp)
	if failedErr != nil {
		ff.hasSet = false
		ff.err = failedErr
		ff.failedGroups = failed
	} else {
		ff.hash, ff.hasSet = h, true
		ff.err = nil
		ff.failedGroups = nil
	}
	slog.Info("flow exporter reconciled", "family", ff.name,
		"template_groups", len(published),
		"failed_groups", len(failed),
		"sampling_zones", len(ecs[0].SamplingZones.V4)+len(ecs[0].SamplingZones.V6),
		"sampling_rate", ecs[0].SamplingRate)
	return true
}

// retireGroups stops exactly the exporters of oldByKey not in publishedExp.
func (ff *flowFamily) retireGroups(oldByKey map[string]flowGroup, publishedExp map[flowExporter]bool) {
	var doomed []flowGroup
	seen := make(map[flowExporter]bool)
	for _, g := range oldByKey {
		if g.exp == nil || publishedExp[g.exp] || seen[g.exp] {
			continue
		}
		seen[g.exp] = true
		doomed = append(doomed, g)
	}
	for _, g := range doomed {
		g.exp.Retire()
	}
	for _, g := range doomed {
		if g.cancel != nil {
			g.cancel()
		}
		joinWithBudget(g.wg, ff.name)
		g.exp.Close()
	}
}

// retainedLocked returns old groups/exps that must stay live because
// their instance failed to build (#15230 per-group #3742).
func (ff *flowFamily) retainedLocked(failedInstances map[string]bool, desiredKeys map[string]bool, oldByKey map[string]flowGroup) ([]flowGroup, []flowExporter) {
	var groups []flowGroup
	var exps []flowExporter
	seenExp := make(map[flowExporter]bool)
	for k, g := range oldByKey {
		if !desiredKeys[k] || !failedInstances[g.ec.InstanceName] {
			continue
		}
		groups = append(groups, g)
		if !seenExp[g.exp] {
			seenExp[g.exp] = true
			exps = append(exps, g.exp)
		}
	}
	return groups, exps
}

// teardownLocked captures the live bundle BEFORE unpublishing it.
// Caller MUST hold ff.mu. Nil-safe / idempotent.
// telemetryDrainBudget bounds a flow-exporter generation join at shutdown
// (#9035).
//
// The join it bounds was UNTIMED, and the work behind it is serial with a
// per-collector deadline and no cardinality cap: collectorWriteTimeout is 2 s
// per collector in `collectorConns.writeAll`, so eleven blocked collectors in
// one group is 22 s against `TimeoutStopSec=20`. The source comment claiming
// 2 s is "well within the 20s systemd stop timeout even for several hung
// collectors" is true for "several" and false at eleven, and nothing enforced
// the boundary between the two.
//
// The number is NOT tuned to today's cardinality, deliberately. A constant
// picked to make eleven collectors fit drifts the moment collectorWriteTimeout
// or TimeoutStopSec changes, which is precisely the failure the issue's own
// acceptance rules out ("a bare constant drifts"). It is instead sized as the
// share of the stop budget telemetry may spend AT MOST, chosen so that the
// fail-closed actions — which now run BEFORE this join, see the #9035 block in
// daemon_run_shutdown.go — plus this bound plus the remaining teardown stay
// inside the budget for ANY collector count. The bound is what makes the drain
// count-independent; the ORDERING is what makes exceeding it survivable.
//
// A drain that hits this bound LOSES the final flush for the collectors that
// had not been written yet. That is the correct trade at shutdown: the flush is
// telemetry, and the thing it would otherwise delay is this node relinquishing
// ownership of a segment its peer is about to serve.
const telemetryDrainBudget = 3 * time.Second

// joinWithBudget waits for wg, or gives up after telemetryDrainBudget and says
// so. It returns whether the join completed.
//
// It does NOT abandon a goroutine that is still writing — the exporters are
// closed by the caller either way, which unblocks the write — it abandons only
// the WAIT. The distinction matters: the leak is bounded by the collectors'
// own deadlines, while the wait was not bounded by anything.
func joinWithBudget(wg *sync.WaitGroup, what string) bool {
	if wg == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(telemetryDrainBudget):
		slog.Warn("shutdown: telemetry drain exceeded its budget; abandoning the "+
			"join so the stop budget is not spent here. The final flush for the "+
			"collectors not yet written is LOST, which is the intended trade — "+
			"the fail-closed HA and DHCP actions already ran ahead of this "+
			"point (#9035)", "exporter", what, "budget", telemetryDrainBudget)
		return false
	}
}

// teardownLocked unpublishes and tears down this family. Caller holds ff.mu.
func (ff *flowFamily) teardownLocked() {
	d := ff.d
	d.flowStateMu.Lock()
	live := ff.bundle.Load()
	ff.bundle.Store(&flowBundle{})
	d.flowStateMu.Unlock()
	ff.teardownGroupsLocked(liveGroups(live))
}

func liveGroups(b *flowBundle) []flowGroup {
	if b == nil {
		return nil
	}
	return b.groups
}

// teardownGroupsLocked retires exactly groups (#4963 + #16752).
func (ff *flowFamily) teardownGroupsLocked(groups []flowGroup) {
	if len(groups) == 0 {
		for _, exp := range ff.exporters {
			exp.Retire()
		}
		if ff.cancel != nil {
			ff.cancel()
		}
		joinWithBudget(ff.wg, ff.name)
		for _, exp := range ff.exporters {
			exp.Close()
		}
	} else {
		seen := make(map[flowExporter]bool)
		var live []flowGroup
		for _, g := range groups {
			if g.exp == nil || seen[g.exp] {
				continue
			}
			seen[g.exp] = true
			live = append(live, g)
		}
		for _, g := range live {
			g.exp.Retire()
		}
		for _, g := range live {
			if g.cancel != nil {
				g.cancel()
			}
			joinWithBudget(g.wg, ff.name)
			g.exp.Close()
		}
	}
	ff.exporters = nil
	ff.cancel = nil
	ff.wg = nil
}

// exportError returns this family's last build error.
func (ff *flowFamily) exportError() error {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	return ff.err
}

func (ff *flowFamily) buildFailed() bool {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	return ff.err != nil
}

// stop stops this family at shutdown.
func (ff *flowFamily) stop() {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	d := ff.d
	d.flowStateMu.Lock()
	live := ff.bundle.Load()
	ff.bundle.Store(&flowBundle{})
	d.flowStateMu.Unlock()
	ff.teardownGroupsLocked(liveGroups(live))
	ff.err = nil
}

// FlowExportError returns the last NetFlow v9 build error (#3742 wrappers).
func (d *Daemon) FlowExportError() error { return d.v9Family().exportError() }

// IPFIXExportError returns the last IPFIX build error.
func (d *Daemon) IPFIXExportError() error { return d.ipfixFamily().exportError() }

// stopFlowExporter / stopIPFIXExporter are shutdown wrappers (names kept
// for the shutdown sequence and its AST canary).
func (d *Daemon) stopFlowExporter()  { d.v9Family().stop() }
func (d *Daemon) stopIPFIXExporter() { d.ipfixFamily().stop() }

// closeCallback is the single, stable per-family session-close
// handler registered on the EventReader exactly once. It loads the live
// set of template-group exporters from the atomic bundle while holding
// flowStateMu, which also serializes state carry and publication.
//
// #2461: the template groups of ONE instance share one SampledForOpen state
// (the 1-in-N counter + sampling zones), so the sampling decision is made
// EXACTLY ONCE per instance and fanned to that instance's groups — each
// group encodes with the template its collectors referenced. Deciding per
// template group would over-increment the shared counter and corrupt 1-in-N.
//
// #2462: sampling instances are independent export policies. A flow is
// attributed to an instance by address family (ServesFamily) and then
// sampled at THAT instance's own rate via THAT instance's own counter, so a
// flow eligible for instance A exports only to A's collectors at A's rate and
// never crosses to instance B. The per-instance decision is made once
// (groupedByInstance walks contiguous same-instance runs — the resolver
// emits an instance's groups consecutively) so the shared per-instance
// counter advances exactly once per eligible flow.
func (ff *flowFamily) closeCallback(rec logging.EventRecord, raw []byte) {
	d := ff.d
	// #16303: SESSION_OPEN sampling is owned by the single fanout
	// callback below, not by each protocol callback. EventReader invokes
	// every registered callback for every record, so letting both the v9
	// and IPFIX callbacks call trackFlowOpen consumed each instance's
	// 1-in-N counter twice in dual-format deployments.
	if rec.Type == "SESSION_OPEN" {
		return
	}
	if rec.Type != "SESSION_CLOSE" {
		return
	}
	d.flowStateMu.Lock()
	defer d.flowStateMu.Unlock()
	b := ff.bundle.Load()
	if b == nil || len(b.groups) == 0 {
		return
	}
	sd := flowexport.SessionCloseData{
		SrcPort: parseSrcPort(rec.SrcAddr),
		DstPort: parseSrcPort(rec.DstAddr),
		// #3939: carry the record's raw numeric IP protocol (rec.ProtocolNum,
		// 0-255) verbatim. The prior parseProtocol(rec.Protocol) name lookup
		// only covered TCP/UDP/ICMP/ICMPv6, so GRE/ESP/AH and every other
		// protocol collapsed to 0. The exporter sources protocolIdentifier from
		// rec.ProtocolNum directly; keeping sd.Protocol consistent here also
		// fixes the flowStartTime duration heuristic for non-TCP protocols.
		Protocol: rec.ProtocolNum,
		// #2749: ingress ifindex (SNMP ifIndex) for the NetFlow v9
		// ingressInterface field; carried on the close frame since #2615.
		InIf: rec.IngressIfindex,
		// #2749: class-of-service + egress-interface attribution carried on the
		// extended SESSION_CLOSE frame's [144:152] block.
		TOS:      rec.TOS,
		TCPFlags: rec.TCPControlBits,
		OutIf:    rec.EgressIfindex,
	}
	sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
	// #2526: parse the post-NAT translated tuple; the exporter falls back to
	// the pre-NAT tuple for any half that is absent/unspecified.
	sd.NATSrcIP = parseHost(rec.NATSrcAddr)
	sd.NATDstIP = parseHost(rec.NATDstAddr)
	sd.NATSrcPort = parseSrcPort(rec.NATSrcAddr)
	sd.NATDstPort = parseSrcPort(rec.NATDstAddr)

	i := 0
	for i < len(b.groups) {
		inst := b.groups[i].ec.InstanceName
		lead := b.groups[i].ec
		j := i
		for j < len(b.groups) && b.groups[j].ec.InstanceName == inst {
			j++
		}
		key := flowexport.FlowKeyFromClose(sd.SrcIP, sd.DstIP, sd.SrcPort, sd.DstPort, rec.ProtocolNum, sd.IsIPv6)
		if lead.ServesFamily(sd.IsIPv6) {
			// #16303: a close whose open was recorded does not make a
			// second sampling decision. CloseFlow reports (and
			// forgets) the one decision made at SESSION_OPEN for this
			// exporter, so a sampled open exports its close without
			// consuming another 1-in-N slot.
			// #16742: when NO group of this instance recorded the
			// open — an RG failover (the promoted node's helper emits
			// no CREATE for peer-synced sessions), an exporter-
			// replacing reconcile that did not carry state, or a lost
			// SESSION_OPEN — the close makes ONE close-time 1-in-N
			// decision (SampledForClose) shared across the instance's
			// groups via the sync.OnceValue below, instead of
			// exporting nothing while the sampler advertises 1-in-N.
			// #16303 fold 3: baselines are PER EXPORTER. Same-instance
			// template groups carry different active timeouts, so group A
			// may hold baseline 200 while group B still holds 0 (or is
			// untracked). Collapsing them into one tuple and applying it
			// to every group over/under-subtracts all but the last.
			anyState := false
			for k := i; k < j; k++ {
				if b.groups[k].ec.GroupIsV6 != sd.IsIPv6 {
					continue
				}
				if b.groups[k].exp.HasFlowState(key) {
					anyState = true
					break
				}
			}
			var decide func() bool
			if !anyState {
				decide = sync.OnceValue(func() bool {
					return lead.SampledForClose(rec.InZone, rec.OutZone, sd.IsIPv6, rec.IngressIface, rec.EgressIface)
				})
			}
			sampled := false
			for k := i; k < j; k++ {
				if b.groups[k].ec.GroupIsV6 != sd.IsIPv6 {
					continue
				}
				s, p, by, rp, rb := b.groups[k].exp.CloseFlowOrSample(key, decide)
				if !s {
					continue
				}
				if !sampled {
					sd.Direction = lead.FlowDirectionIface(rec.InZone, rec.OutZone, sd.IsIPv6, rec.IngressIface, rec.EgressIface)
					sampled = true
				}
				// Entry already forgotten by this group's CloseFlow;
				// export this group's own unexported remainder only.
				b.groups[k].exp.ExportSessionCloseRemainder(rec, sd, p, by, rp, rb)
			}
		}
		i = j
	}
}

// flowExportOpenCallback is the ONLY EventReader callback that consumes
// SESSION_OPEN sampling decisions. It is registered once when the first
// exporter family starts (see ensureFlowExportOpenCallback) and fans the
// record to whichever v9/IPFIX bundles are currently published. Keeping
// opens out of both protocol callbacks prevents dual-format deployments
// from evaluating (and counting) the same open twice.
func (d *Daemon) flowExportOpenCallback(rec logging.EventRecord, raw []byte) {
	if rec.Type != "SESSION_OPEN" {
		return
	}
	d.trackFlowOpen(rec)
}

// trackFlowOpen is the shared SESSION_OPEN tracker feed (#15946,
// #16303). For each protocol and instance it makes one sampling
// decision. The exporter records either selected state or a rejected
// decision so duplicate local/sync opens and the matching close cannot
// consume another slot or reset tracker baselines (#17815).
//
// #16742 promote arm: a peer->local promote after an RG failover gets
// no SESSION_CREATE from the helper (#15126: only fresh admissions
// emit CREATE, so no syslog CREATE is produced). The promoted node's
// Go session-sync path still installs the session locally; the first
// post-promote SESSION_OPEN-shaped signal the flowexport feed can see
// is therefore absent by design. Registration for such flows happens
// through trackFlowOpenFromSync, driven by the HA session-sync walker
// for peer-synced opens, which calls the same locked admission path with
// the gate byte clear — an open for flow export without a syslog CREATE.
func (d *Daemon) trackFlowOpen(rec logging.EventRecord) {
	d.flowStateMu.Lock()
	defer d.flowStateMu.Unlock()
	d.trackFlowOpenLocked(rec)
}

// trackFlowOpenLocked makes the per-instance decision and registers its
// selected/rejected state atomically. The caller must hold flowStateMu.
func (d *Daemon) trackFlowOpenLocked(rec logging.EventRecord) {
	srcIP, dstIP, isV6 := parseAddrPair(rec.SrcAddr, rec.DstAddr)
	key := flowexport.FlowKeyFromClose(srcIP, dstIP, parseSrcPort(rec.SrcAddr), parseSrcPort(rec.DstAddr), rec.ProtocolNum, isV6)
	tmpl := flowexport.FlowRecord{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: key.SrcPort, DstPort: key.DstPort,
		Protocol: rec.ProtocolNum, IsIPv6: isV6, StartTime: rec.Time,
		InIf: rec.IngressIfindex, OutIf: rec.EgressIfindex, TOS: rec.TOS, TCPFlags: rec.TCPControlBits,
		NATSrcIP: parseHost(rec.NATSrcAddr), NATDstIP: parseHost(rec.NATDstAddr),
		NATSrcPort: parseSrcPort(rec.NATSrcAddr), NATDstPort: parseSrcPort(rec.NATDstAddr),
		// #16754: snapshot the open-time attribution for tracker records.
		// Direction itself is derived per exporter at drain time (each
		// template group has its own sampling config); the zone/iface
		// facts are exporter-independent and captured once here. Route
		// masks are resolved at drain with the ingress VRF (InIf/OutIf).
		InZone: rec.InZone, OutZone: rec.OutZone,
		InIface: rec.IngressIface, OutIface: rec.EgressIface,
	}
	if tmpl.NATSrcIP == nil {
		tmpl.NATSrcIP = srcIP
		tmpl.NATSrcPort = key.SrcPort
	}
	if tmpl.NATDstIP == nil {
		tmpl.NATDstIP = dstIP
		tmpl.NATDstPort = key.DstPort
	}
	for _, ff := range d.flowFamiliesOrNil() {
		ff.trackOpenLocked(rec, key, tmpl, isV6)
	}
}

func (ff *flowFamily) trackOpenLocked(rec logging.EventRecord, key flowexport.FlowKey, tmpl flowexport.FlowRecord, isV6 bool) {
	b := ff.bundle.Load()
	if b == nil {
		return
	}
	for i := 0; i < len(b.groups); {
		inst := b.groups[i].ec.InstanceName
		lead := b.groups[i].ec
		j := i
		for j < len(b.groups) && b.groups[j].ec.InstanceName == inst {
			j++
		}
		if lead.ServesFamily(isV6) {
			decided := false
			for k := i; k < j; k++ {
				if b.groups[k].ec.GroupIsV6 == isV6 && b.groups[k].exp.HasFlowState(key) {
					decided = true
					break
				}
			}
			if !decided {
				selected := lead.SampledForOpen(rec.InZone, rec.OutZone, isV6, rec.IngressIface, rec.EgressIface)
				for k := i; k < j; k++ {
					if b.groups[k].ec.GroupIsV6 != isV6 {
						continue
					}
					if selected {
						b.groups[k].exp.MarkFlowSampledAtOpen(key)
						b.groups[k].exp.TrackFlowOpenRecord(key, rec.Time, tmpl)
					} else {
						b.groups[k].exp.MarkFlowRejectedAtOpen(key)
					}
				}
			}
		}
		i = j
	}
}

// trackFlowOpenFromSync registers a peer-synced open for flow export
// (#16742 promote arm). After an RG failover the promoted node's
// helper emits no SESSION_CREATE for the session (#15126: only fresh
// admissions emit CREATE), so the flowexport feed never sees a
// SESSION_OPEN for it and its close would fall back to a fresh
// close-time decision — or, before #16742, export nothing. The Go
// session-sync path does learn the session: handleEventStreamDelta /
// the fallback drain queue its open delta for the peer. That queueing
// is the promote signal; this hook converts the delta into the same
// SESSION_OPEN record trackFlowOpen consumes, WITHOUT any syslog
// CREATE (no EventRecord is logged; only the exporter sampling /
// tracker state is registered). Interface names use EventReader's
// existing ifindex map so per-interface sampling remains authoritative
// for resolved identities; unknown names retain daemon zone fallback.
func (d *Daemon) trackFlowOpenFromSync(delta dpuserspace.SessionDeltaInfo) {
	if d == nil {
		return
	}
	d.flowStateMu.Lock()
	defer d.flowStateMu.Unlock()
	hasBundle := false
	for _, ff := range d.flowFamiliesOrNil() {
		if ff.bundle.Load() != nil {
			hasBundle = true
		}
	}
	if !hasBundle {
		return
	}
	rec := logging.EventRecord{
		Type:        "SESSION_OPEN",
		Time:        delta.Timestamp,
		SrcAddr:     net.JoinHostPort(delta.SrcIP, strconv.Itoa(int(delta.SrcPort))),
		DstAddr:     net.JoinHostPort(delta.DstIP, strconv.Itoa(int(delta.DstPort))),
		ProtocolNum: delta.Protocol,
		// #18148: EventRecord.InZone/OutZone stay u16 — they share the
		// frozen BPF/RT_FLOW u16 zone ABI; a full u32 delta id is stored
		// truncated here exactly as on the SessionValue.
		InZone:         uint16(delta.IngressZoneID),
		OutZone:        uint16(delta.EgressZoneID),
		IngressIfindex: uint32(delta.IngressIfindex),
		EgressIfindex:  uint32(delta.EgressIfindex),
	}
	if d.eventReader != nil {
		rec.IngressIface = d.eventReader.InterfaceName(rec.IngressIfindex)
		rec.EgressIface = d.eventReader.InterfaceName(rec.EgressIfindex)
	}
	if delta.NATSrcIP != "" {
		rec.NATSrcAddr = net.JoinHostPort(delta.NATSrcIP, strconv.Itoa(int(delta.NATSrcPort)))
	}
	if delta.NATDstIP != "" {
		rec.NATDstAddr = net.JoinHostPort(delta.NATDstIP, strconv.Itoa(int(delta.NATDstPort)))
	}
	// Zone names on the delta (JSON leg) do not map to IDs here; when
	// only names are present the record carries zone 0 and the
	// nameless/zone fallback in SampledForOpen decides as for an
	// unresolved-ifindex open. Binary-leg deltas carry the IDs.
	d.trackFlowOpenLocked(rec)
}

// carryFlowStateLocked transfers live open state from the previously
// published groups to their same-key replacements (#16742).
func (ff *flowFamily) carryFlowStateLocked(published []flowGroup) {
	old := ff.bundle.Load()
	if old == nil || len(old.groups) == 0 {
		return
	}
	oldByKey := make(map[string]flowGroup, len(old.groups))
	for _, g := range old.groups {
		oldByKey[flowGroupKey(g.ec)] = g
	}
	for _, ng := range published {
		og, ok := oldByKey[flowGroupKey(ng.ec)]
		if !ok || og.exp == ng.exp {
			continue
		}
		og.exp.AbsorbSampledInto(ng.exp)
	}
}

// flowExportAddressFamily returns the configuration-family label used by
// flow-export telemetry for an already-partitioned exporter group.
func flowExportAddressFamily(isV6 bool) string {
	if isV6 {
		return "inet6"
	}
	return "inet"
}

// FlowExportSamplingStats snapshots per-instance sampling decisions for
// Prometheus. Template groups share stats, so emit one bounded row per
// (protocol, instance), rather than duplicating totals per template.
func (d *Daemon) FlowExportSamplingStats() []flowexport.SamplingStatsSnapshot {
	var out []flowexport.SamplingStatsSnapshot
	seen := make(map[string]bool)
	appendStats := func(protocol string, ec *flowexport.ExportConfig) {
		key := protocol + "\x00" + ec.InstanceName
		if seen[key] {
			return
		}
		seen[key] = true
		evaluated, selected, zoneFiltered := ec.SamplingStats()
		out = append(out, flowexport.SamplingStatsSnapshot{
			Protocol: protocol, Instance: ec.InstanceName,
			Evaluated: evaluated, Selected: selected, ZoneFiltered: zoneFiltered,
		})
	}
	for _, ff := range d.flowFamiliesOrNil() {
		if b := ff.bundle.Load(); b != nil {
			for _, g := range b.groups {
				appendStats(ff.name, g.ec)
			}
		}
	}
	return out
}

// running NetFlow v9 and IPFIX exporter group (#2464). The slice is
// empty when no flow export is configured. Safe to call concurrently

func (d *Daemon) FlowCollectorHealth() []flowexport.ExporterCollectorHealth {
	var out []flowexport.ExporterCollectorHealth
	for _, ff := range d.flowFamiliesOrNil() {
		if b := ff.bundle.Load(); b != nil {
			for _, g := range b.groups {
				for _, h := range g.exp.CollectorHealth() {
					out = append(out, flowexport.ExporterCollectorHealth{
						Protocol:        ff.name,
						Instance:        g.ec.InstanceName,
						Template:        g.ec.TemplateName,
						Family:          flowExportAddressFamily(g.ec.GroupIsV6),
						CollectorHealth: h,
					})
				}
			}
		}
	}
	return out
}

// FlowExportBatchStats returns pending-batch queue and flow-record data-quality
// counters (unresolved route masks, missing start timestamps, and clock-skew
// clamps) for every running NetFlow v9 and IPFIX exporter group (#3747,
// #13305). The slice is empty when no flow export is configured. Safe to call
// concurrently with reconcile and export-flush goroutines: it reads live
// bundles lock-free and exporters expose counters atomically / depth through a
// mutex-guarded read. Surfaced through the daemon to REST/Prometheus.
func (d *Daemon) FlowExportBatchStats() []flowexport.ExporterBatchStats {
	var out []flowexport.ExporterBatchStats
	for _, ff := range d.flowFamiliesOrNil() {
		if b := ff.bundle.Load(); b != nil {
			for _, g := range b.groups {
				flows, packets := g.exp.Stats()
				out = append(out, flowexport.ExporterBatchStats{
					Protocol:            ff.name,
					Instance:            g.ec.InstanceName,
					Template:            g.ec.TemplateName,
					Family:              flowExportAddressFamily(g.ec.GroupIsV6),
					Depth:               g.exp.BatchDepth(),
					MaxDepth:            g.exp.BatchMaxDepth(),
					Dropped:             g.exp.BatchDropped(),
					ExportedFlows:       flows,
					ExportedPackets:     packets,
					HandoffDropped:      g.exp.HandoffDropped(),
					RouteMaskUnresolved: g.exp.RouteMaskUnresolved(),
					EstimatedDurations:  g.exp.EstimatedDurations(),
					ClockSkewClamped:    g.exp.ClockSkewClamped(),
				})
			}
		}
	}
	return out
}

// FlowExportHandoffDropped returns the fixed-cardinality per-family totals of
// session-close records rejected because they reached an exporter that had
// already been retired during a reconcile (#4963). Before the admission lease
// such a record was silently appended into a batch nothing would drain again —
// permanently stranded with every queue/collector metric looking healthy.
// These two counters survive exporter churn (each exporter increments the
// shared family counter), so a nonzero value is the operator-visible signal
// that day-2 flow-export reconciles are losing close records at handoff.
func (d *Daemon) FlowExportHandoffDropped() (netflowV9, ipfix uint64) {
	fams := d.flowFamiliesOrNil()
	if len(fams) < 2 {
		return 0, 0
	}
	return fams[0].handoffDropped.Load(), fams[1].handoffDropped.Load()
}
