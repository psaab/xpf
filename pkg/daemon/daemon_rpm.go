// daemon_rpm.go — RPM probe lifecycle wiring (#1827 PR-1a).
//
// Before #1827 the RPM manager was applied once at daemon start and
// never re-applied on commit: probe config changes required a restart.
// reconcileRPM runs on every config apply but is CONFIG-HASH-GATED — it
// re-applies probes (and the probe next-hop pin rules) only when the
// rendered RPM stanza actually changed, so probe state (and the
// ip-monitoring engine's sensor input) is never wiped by unrelated
// commits or by route-overlay actuations.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// rpmConfigHash computes a stable hash of the effective RPM stanza plus
// the RETH→physical map (which affects destination-interface
// resolution). Go's json.Marshal emits map keys in sorted order, so the
// encoding is deterministic.
func rpmConfigHash(rpmCfg *config.RPMConfig, rethMap map[string]string) [32]byte {
	payload := struct {
		RPM     *config.RPMConfig
		RethMap map[string]string
	}{RPM: rpmCfg, RethMap: rethMap}
	data, err := json.Marshal(&payload)
	if err != nil {
		// Marshal of plain config structs cannot realistically fail;
		// fall back to a zero hash (forces re-apply) rather than
		// silently skipping one.
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// effectiveRPMConfig returns the RPM config that should actually run
// on this node: in cluster mode the §4.4 ip-monitoring gating scope
// removes gated probes while the node is not primary for their data
// RG; everything else (and all standalone probes) keeps today's
// run-everywhere behavior.
func (d *Daemon) effectiveRPMConfig(cfg *config.Config) *config.RPMConfig {
	if cfg == nil {
		return nil
	}
	return d.filterRPMForHAGating(cfg)
}

// filterRPMForHAGating implements the §4.4 primary-only gating scope
// (#1827 PR-1b). Gating applies ONLY to probes that are (a) referenced
// by a `services ip-monitoring` policy, or (b) bound via
// destination-interface / source-address to a VIP-owned (RETH)
// interface — uplink addresses are VRRP-owned VIPs, so a standby probe
// would fail structurally, not informatively. All other probes are
// untouched. Within the gated scope, a probe runs only on the node
// that is primary for the probe's redundancy group.
func (d *Daemon) filterRPMForHAGating(cfg *config.Config) *config.RPMConfig {
	rpmCfg := cfg.Services.RPM
	if rpmCfg == nil || d.cluster == nil || cfg.Chassis.Cluster == nil {
		return rpmCfg
	}

	gatedRG := rpmProbeGatingRGs(cfg)
	if len(gatedRG) == 0 {
		return rpmCfg
	}

	filtered := &config.RPMConfig{Probes: make(map[string]*config.RPMProbe, len(rpmCfg.Probes))}
	dropped := 0
	for name, probe := range rpmCfg.Probes {
		if rgID, gated := gatedRG[name]; gated && !d.cluster.IsLocalPrimary(rgID) {
			dropped++
			continue
		}
		filtered.Probes[name] = probe
	}
	if dropped > 0 {
		slog.Info("RPM probes gated off while secondary", "gated", dropped)
	}
	return filtered
}

// rpmProbeGatingRGs returns the probes inside the §4.4 gating scope,
// mapped to the redundancy group whose primaryship gates them: the RG
// of a bound RETH interface when one exists, otherwise the lowest
// configured data RG.
func rpmProbeGatingRGs(cfg *config.Config) map[string]int {
	rpmCfg := cfg.Services.RPM
	if rpmCfg == nil {
		return nil
	}

	// Probes referenced by ip-monitoring policies.
	referenced := make(map[string]bool)
	if cfg.Services.IPMonitoring != nil {
		for _, pol := range cfg.Services.IPMonitoring.Policies {
			if pol != nil && pol.MatchRPMProbe != "" {
				referenced[pol.MatchRPMProbe] = true
			}
		}
	}

	// RETH interface → RG, plus RETH unit VIP addresses for
	// source-address matching.
	rethRG := make(map[string]int)
	rethVIPs := make(map[string]int)
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || ifc.RedundancyGroup <= 0 || !strings.HasPrefix(name, "reth") {
			continue
		}
		rethRG[name] = ifc.RedundancyGroup
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, addr := range unit.Addresses {
				ip := addr
				if i := strings.IndexByte(ip, '/'); i >= 0 {
					ip = ip[:i]
				}
				rethVIPs[ip] = ifc.RedundancyGroup
			}
		}
	}

	defaultRG := lowestDataRG(cfg)

	gated := make(map[string]int)
	for probeName, probe := range rpmCfg.Probes {
		if probe == nil {
			continue
		}
		rgID, inScope := defaultRG, false
		if referenced[probeName] {
			inScope = true
		}
		for _, test := range probe.Tests {
			if test == nil {
				continue
			}
			if test.DestinationInterface != "" {
				base := test.DestinationInterface
				if i := strings.IndexByte(base, '.'); i >= 0 {
					base = base[:i]
				}
				if rg, ok := rethRG[base]; ok {
					inScope, rgID = true, rg
				}
			}
			if test.SourceAddress != "" {
				if rg, ok := rethVIPs[test.SourceAddress]; ok {
					inScope, rgID = true, rg
				}
			}
		}
		if inScope {
			gated[probeName] = rgID
		}
	}
	return gated
}

// lowestDataRG returns the lowest configured redundancy group ID >= 1
// (the data RG), falling back to 0 when only RG 0 exists.
func lowestDataRG(cfg *config.Config) int {
	rg := -1
	if cfg.Chassis.Cluster != nil {
		for _, g := range cfg.Chassis.Cluster.RedundancyGroups {
			if g == nil || g.ID < 1 {
				continue
			}
			if rg == -1 || g.ID < rg {
				rg = g.ID
			}
		}
	}
	if rg == -1 {
		return 0
	}
	return rg
}

// probePinApplyFn returns the probe-pin programmer: the test seam
// when set, otherwise routing.Manager.ApplyProbePins, otherwise nil
// (no routing manager — unit-test daemons, or a daemon whose netlink
// routing manager failed to construct).
func (d *Daemon) probePinApplyFn() func([]routing.ProbePin) map[string]error {
	if d.probePinApply != nil {
		return d.probePinApply
	}
	if d.routing != nil {
		return d.routing.ApplyProbePins
	}
	return nil
}

// probePinVerifyFn returns the probe-pin kernel readback function: the test
// seam when set, otherwise routing.Manager.VerifyProbePins, otherwise nil.
func (d *Daemon) probePinVerifyFn() func([]routing.ProbePin) map[string]error {
	if d.probePinVerify != nil {
		return d.probePinVerify
	}
	if d.routing != nil {
		return d.routing.VerifyProbePins
	}
	return nil
}

// errProbePinReprogram pre-marks every pin while the kernel band is
// being cleared-and-reprogrammed: a pinned probe that ticks inside the
// reprogram window holds state (ErrProbeSetup) instead of sending an
// SO_MARK probe against a band whose rule may be momentarily absent —
// which would fall through to the main table and measure the wrong
// path (Codex PR #1899 r1 MAJOR-1). The window that remains is the
// gate-check→sendto microseconds of a probe already past the gate.
var errProbePinReprogram = errors.New("probe pin reprogram in progress")

// errNoProbePinInstaller marks every pin failed when next-hop pins are
// configured but no routing manager exists to install them: marks are
// still derived from config in rpm.Apply, so without this the probes
// would send marked-but-unbacked packets through the main table
// (Codex PR #1899 r1 MAJOR-2).
var errNoProbePinInstaller = errors.New("no routing manager; probe pins cannot be installed")

// probePinsAllFailed maps every pin's TestKey to err (nil for no pins).
func probePinsAllFailed(pins []routing.ProbePin, err error) map[string]error {
	if len(pins) == 0 {
		return nil
	}
	m := make(map[string]error, len(pins))
	for _, p := range pins {
		m[p.TestKey] = err
	}
	return m
}

// probePinKeys extracts the TestKeys of a pin set.
func probePinKeys(pins []routing.ProbePin) []string {
	keys := make([]string, 0, len(pins))
	for _, p := range pins {
		keys = append(keys, p.TestKey)
	}
	return keys
}

// applyProbePinsHeld programs the pin band with the pinned probes
// held: it pre-holds the UNION of every currently-marked (live)
// pinned test and the new pin set — live goroutines whose keys were
// removed or whose marks are about to be reassigned must not send
// during the band reprogram either (Codex PR #1899 r2) — then runs
// the installer (clear-then-program over the whole band). The caller
// publishes the real per-pin results via SetPinInstallResults: the
// retry path immediately (probe set unchanged), the full-apply path
// only AFTER rpm.Apply has drained the old goroutines and rebuilt the
// marks. Callers hold rpmMu.
func (d *Daemon) applyProbePinsHeld(applyPins func([]routing.ProbePin) map[string]error, pins []routing.ProbePin) map[string]error {
	d.rpm.HoldPinsForReprogram(probePinKeys(pins), errProbePinReprogram)
	return applyPins(pins)
}

// probePinRetryInterval is the slow periodic probe-pin health-check and retry
// cadence (#12088). The check uses a handful of netlink dumps only while probe
// pins are configured; link/address notifications make drift detection prompt.
const probePinRetryInterval = 30 * time.Second

// retainProbePinInstallFailures preserves only installer errors that the
// authoritative readback still confirms. These alone keep the legacy
// unchanged-hash immediate retry behavior; readback-only drift waits for the
// periodic monitor retry.
func retainProbePinInstallFailures(installed, verified map[string]error) map[string]error {
	if len(installed) == 0 || len(verified) == 0 {
		return nil
	}
	retained := make(map[string]error)
	for key, err := range installed {
		if _, stillFailed := verified[key]; stillFailed {
			retained[key] = err
		}
	}
	if len(retained) == 0 {
		return nil
	}
	return retained
}

// verifyProbePinsLocked publishes per-pin readback failures immediately, so
// the RPM gate returns ErrProbeSetup instead of sending with an unbacked mark.
// Callers hold rpmMu. nil means this daemon has no readback implementation.
func (d *Daemon) verifyProbePinsLocked(pins []routing.ProbePin) {
	verify := d.probePinVerifyFn()
	if verify == nil || len(pins) == 0 {
		return
	}
	failed := verify(pins)
	d.rpmPinInstallFailures = retainProbePinInstallFailures(d.rpmPinInstallFailures, failed)
	if len(failed) > 0 && !d.rpmPinsFailed {
		slog.Warn("kernel probe pin drift detected — affected tests held until retry",
			"failed", len(failed))
	}
	d.rpm.SetPinInstallResults(failed)
	d.rpmPinsFailed = len(failed) > 0
}

// retryFailedProbePinsLocked re-runs the pin install against the last-applied
// effective probe set while any pin is failed, publishing installer and
// readback results without restarting probes. A first readback-detected drift
// is held by the caller and left for the next retry interval. Caller holds
// rpmMu.
func (d *Daemon) retryFailedProbePinsLocked() {
	pins := routing.BuildProbePins(d.rpmEffective, d.rpmRethMap)
	if len(pins) == 0 {
		d.rpmPinsFailed = false
		d.rpmPinInstallFailures = nil
		d.rpm.SetPinInstallResults(nil)
		return
	}
	if !d.rpmPinsFailed {
		d.verifyProbePinsLocked(pins)
		return
	}
	applyPins := d.probePinApplyFn()
	if applyPins == nil {
		return
	}
	installFailed := d.applyProbePinsHeld(applyPins, pins)
	d.rpmPinInstallFailures = installFailed
	failed := installFailed
	if verify := d.probePinVerifyFn(); verify != nil {
		verified := verify(pins)
		d.rpmPinInstallFailures = retainProbePinInstallFailures(installFailed, verified)
		failed = verified
	}
	d.rpm.SetPinInstallResults(failed)
	d.rpmPinsFailed = len(failed) > 0
	if !d.rpmPinsFailed {
		slog.Info("probe pin install recovered on retry")
	}
}

// maybeStartPinRetryLoopLocked starts the pin health monitor when pins are
// configured and a readback path exists, or when failed installs need retry.
// Caller holds rpmMu.
func (d *Daemon) maybeStartPinRetryLoopLocked() {
	if d.pinRetryStopped || d.rpmPinRetryActive || d.daemonCtx == nil {
		return
	}
	pins := routing.BuildProbePins(d.rpmEffective, d.rpmRethMap)
	if len(pins) == 0 || (!d.rpmPinsFailed && d.probePinVerifyFn() == nil) {
		return
	}
	d.rpmPinRetryActive = true
	// Bind the loop to a CANCELLABLE child of d.daemonCtx (not d.daemonCtx
	// itself, which is never cancelled in production) so shutdown can stop it
	// before FRR/routing teardown, and track it on pinRetryWg so shutdown can
	// join it (#5308). Callers hold rpmMu.
	ctx, cancel := context.WithCancel(d.daemonCtx)
	d.pinRetryCancel = cancel
	d.pinRetryWg.Add(1)
	go func() {
		defer d.pinRetryWg.Done()
		d.probePinRetryLoop(ctx)
	}()
}

// stopPinRetryLoop cancels the probePinRetryLoop goroutine and joins it. It is
// called from the shutdown sequence BEFORE FRR/routing teardown so a late
// retry tick can never run a routing-pin syscall against a torn-down routing
// manager (#5308). rpmMu is held only to read+cancel pinRetryCancel and latch
// pinRetryStopped, then RELEASED before the join: probePinRetryLoop takes rpmMu
// on both its ctx.Done() and ticker branches, so holding it across the join
// would deadlock. Idempotent / nil-safe: a loop that was never started (no pin
// failures) joins cleanly.
func (d *Daemon) stopPinRetryLoop() {
	d.rpmMu.Lock()
	d.pinRetryStopped = true
	cancel := d.pinRetryCancel
	d.pinRetryCancel = nil
	d.rpmMu.Unlock()
	if cancel != nil {
		cancel()
	}
	d.pinRetryWg.Wait()
}

// probePinRetryLoop verifies pins on link/address notifications and on the
// periodic fallback. A missing pin is held on notification/reconcile and
// restored on the next retry tick; once healthy, the loop remains active as
// long as pins are configured so later kernel deletions are detected.
func (d *Daemon) probePinRetryLoop(ctx context.Context) {
	interval := d.probePinRetryEvery
	if interval <= 0 {
		interval = probePinRetryInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var linkUpdates <-chan netlink.LinkUpdate
	var addrUpdates <-chan netlink.AddrUpdate
	var linkDone, addrDone chan struct{}
	subscriptionErrors := make(chan struct{}, 1)
	if d.probePinVerifyFn() != nil {
		onError := func(error) {
			select {
			case subscriptionErrors <- struct{}{}:
			default:
			}
		}
		linkCh := make(chan netlink.LinkUpdate, 32)
		linkDone = make(chan struct{})
		if err := netlink.LinkSubscribeWithOptions(linkCh, linkDone,
			netlink.LinkSubscribeOptions{ErrorCallback: onError}); err != nil {
			slog.Warn("probe pin link subscription unavailable; periodic readback remains active",
				"err", err)
			close(linkDone)
			linkDone = nil
		} else {
			linkUpdates = linkCh
		}
		addrCh := make(chan netlink.AddrUpdate, 32)
		addrDone = make(chan struct{})
		if err := netlink.AddrSubscribeWithOptions(addrCh, addrDone,
			netlink.AddrSubscribeOptions{ErrorCallback: onError}); err != nil {
			slog.Warn("probe pin address subscription unavailable; periodic readback remains active",
				"err", err)
			close(addrDone)
			addrDone = nil
		} else {
			addrUpdates = addrCh
		}
	}
	if linkDone != nil {
		defer close(linkDone)
	}
	if addrDone != nil {
		defer close(addrDone)
	}

	for {
		select {
		case <-ctx.Done():
			d.rpmMu.Lock()
			d.rpmPinRetryActive = false
			d.rpmMu.Unlock()
			return
		case update := <-linkUpdates:
			if update.Attrs() != nil {
				d.verifyProbePinsForLink(update.Attrs().Name)
			}
		case update := <-addrUpdates:
			d.verifyProbePinsForAddress(update.LinkIndex)
		case <-subscriptionErrors:
			slog.Warn("probe pin netlink subscription reported a gap; checking all pins")
			d.verifyProbePinsForAll()
		case <-ticker.C:
			d.rpmMu.Lock()
			pins := routing.BuildProbePins(d.rpmEffective, d.rpmRethMap)
			if len(pins) == 0 {
				d.rpmPinRetryActive = false
				d.rpmMu.Unlock()
				return
			}
			d.verifyProbePinsLocked(pins)
			if d.rpmPinsFailed {
				d.retryFailedProbePinsLocked()
			}
			done := !d.rpmPinsFailed && d.probePinVerifyFn() == nil
			if done {
				d.rpmPinRetryActive = false
			}
			d.rpmMu.Unlock()
			if done {
				return
			}
		}
	}
}

func (d *Daemon) verifyProbePinsForLink(name string) {
	d.rpmMu.Lock()
	defer d.rpmMu.Unlock()
	pins := routing.BuildProbePins(d.rpmEffective, d.rpmRethMap)
	for _, pin := range pins {
		if pin.Interface == name {
			d.verifyProbePinsLocked(pins)
			return
		}
	}
}

func (d *Daemon) verifyProbePinsForAddress(linkIndex int) {
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil || link.Attrs() == nil {
		return
	}
	d.verifyProbePinsForLink(link.Attrs().Name)
}

func (d *Daemon) verifyProbePinsForAll() {
	d.rpmMu.Lock()
	defer d.rpmMu.Unlock()
	d.verifyProbePinsLocked(routing.BuildProbePins(d.rpmEffective, d.rpmRethMap))
}

// reconcileRPM applies the RPM probe set when (and only when) the rendered
// stanza changed, returning whether a re-apply happened. Pin rules are
// reprogrammed on that same gate; unchanged-hash reconciles instead read back
// the live rule and route so kernel link/address cleanup cannot leave an
// unbacked SO_MARK. A detected drift holds the affected probe until the
// periodic retry restores the pin. The periodic loop also subscribes to
// link/address events, with a slow ticker as a gap-recovery fallback.
// Safe to call from applyConfigLocked and other reconcile paths; rpmMu
// serializes callers.
func (d *Daemon) reconcileRPM(cfg *config.Config) bool {
	return d.reconcileRPMMode(cfg, false)
}

// reconcileRPMForHATransition re-evaluates probes after an RG state change;
// newly enabled ip-monitoring probes get an immediate initial burst.
func (d *Daemon) reconcileRPMForHATransition(cfg *config.Config) bool {
	return d.reconcileRPMMode(cfg, true)
}

func (d *Daemon) reconcileRPMMode(cfg *config.Config, haTransition bool) bool {
	if d.rpm == nil || d.daemonCtx == nil || cfg == nil {
		return false
	}
	d.rpmMu.Lock()
	defer d.rpmMu.Unlock()

	effective := d.effectiveRPMConfig(cfg)
	var burstProbeNames map[string]struct{}
	if haTransition {
		burstProbeNames = newlyEnabledIPMonProbeNames(cfg, d.rpmEffective, effective)
	}
	rethMap := cfg.RethToPhysical()
	h := rpmConfigHash(effective, rethMap)
	applyPins := d.probePinApplyFn()
	pins := routing.BuildProbePins(effective, rethMap)
	d.rpmEffective, d.rpmRethMap = effective, rethMap
	if h == d.activeRPMHash {
		d.verifyProbePinsLocked(pins)
		// Retain immediate hash-gated retries only for installer failures that
		// readback still confirms. Readback-only drift is held until the monitor
		// retry tick.
		if len(d.rpmPinInstallFailures) > 0 && d.rpmPinsFailed {
			d.retryFailedProbePinsLocked()
		}
		d.maybeStartPinRetryLoopLocked()
		return false
	}

	// Pin state follows the prober lifecycle: clear-and-program the
	// reserved band alongside every probe re-apply. Hold the union of
	// old (live) and new pinned tests FIRST, then mutate the kernel band.
	// A regular Apply publishes results afterwards: old goroutines stay
	// held until StopAll drains them, and new goroutines see the real
	// results on their next gate check. The HA burst apply publishes
	// results after StopAll but before starting new goroutines, so the
	// burst cannot be consumed by the temporary reprogram hold. With no
	// installer, every configured pin is failed by definition
	// (errNoProbePinInstaller) — never let a next-hop test probe with a
	// marked-but-unbacked socket.
	d.rpm.HoldPinsForReprogram(probePinKeys(pins), errProbePinReprogram)
	var failed map[string]error
	if applyPins != nil {
		installFailed := applyPins(pins)
		d.rpmPinInstallFailures = installFailed
		failed = installFailed
		if verify := d.probePinVerifyFn(); verify != nil {
			verified := verify(pins)
			d.rpmPinInstallFailures = retainProbePinInstallFailures(installFailed, verified)
			failed = verified
		}
		if len(failed) > 0 {
			slog.Warn("probe pin install or readback failures — affected tests hold state until a retry succeeds",
				"failed", len(failed))
		}
	} else {
		d.rpmPinInstallFailures = nil
		failed = probePinsAllFailed(pins, errNoProbePinInstaller)
		if len(failed) > 0 {
			slog.Warn("next-hop probe pins configured but no routing manager — pinned tests hold state",
				"pins", len(failed))
		}
	}
	d.rpmPinsFailed = applyPins != nil && len(failed) > 0
	d.maybeStartPinRetryLoopLocked()

	d.rpm.SetRethMap(rethMap)
	if len(burstProbeNames) > 0 {
		d.rpm.ApplyWithProbeBurst(d.daemonCtx, effective, burstProbeNames, failed)
	} else {
		d.rpm.Apply(d.daemonCtx, effective)
		d.rpm.SetPinInstallResults(failed)
	}
	d.activeRPMHash = h
	probes := 0
	if effective != nil {
		probes = len(effective.Probes)
	}
	slog.Info("RPM probe set applied", "probes", probes)
	return true
}
func newlyEnabledIPMonProbeNames(cfg *config.Config, previous, effective *config.RPMConfig) map[string]struct{} {
	if cfg == nil || previous == nil || effective == nil || cfg.Services.IPMonitoring == nil {
		return nil
	}
	gated := rpmProbeGatingRGs(cfg)
	var burst map[string]struct{}
	for _, policy := range cfg.Services.IPMonitoring.Policies {
		if policy == nil || policy.MatchRPMProbe == "" {
			continue
		}
		name := policy.MatchRPMProbe
		if _, isHAGated := gated[name]; !isHAGated {
			continue
		}
		if _, wasActive := previous.Probes[name]; wasActive {
			continue
		}
		if probe, nowActive := effective.Probes[name]; !nowActive || probe == nil {
			continue
		}
		if burst == nil {
			burst = make(map[string]struct{})
		}
		burst[name] = struct{}{}
	}
	return burst
}
