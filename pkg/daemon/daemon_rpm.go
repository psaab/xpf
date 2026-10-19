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
	"net"
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
// removes gated tests while the node is not primary for their data
// RG; everything else (and all standalone tests) keeps today's
// run-everywhere behavior.
func (d *Daemon) effectiveRPMConfig(cfg *config.Config) *config.RPMConfig {
	if cfg == nil {
		return nil
	}
	return d.filterRPMForHAGating(cfg)
}

// filterRPMForHAGating implements the §4.4 primary-only gating scope
// (#1827 PR-1b). Gating applies ONLY to tests that are (a) in a probe
// referenced by a `services ip-monitoring` policy, or (b) bound via
// destination-interface / source-address to a VIP-owned (RETH)
// interface — uplink addresses are VRRP-owned VIPs, so a standby probe
// would fail structurally, not informatively (#15074).
//
// Gating is PER TEST, not per probe: a probe whose tests resolve to
// different RGs keeps exactly the tests this node is primary for and
// stops the rest. Junos keys a probe to a single routing instance and
// has no multi-RG probe spelling, so the mixed shape is an xpf
// artefact; running the locally-owned tests and stopping the foreign
// ones is preferred to dropping the whole probe (which loses the owned
// RG's monitoring) or picking one gate RG by map iteration order
// (the pre-#15074 last-writer-wins behaviour — the probe then ran on
// both nodes, on neither, or flipped across reconciles). Tests are
// only removed, never added, so the filtered probe's runs stay a
// subset of the authored probe.
func (d *Daemon) filterRPMForHAGating(cfg *config.Config) *config.RPMConfig {
	rpmCfg := cfg.Services.RPM
	if rpmCfg == nil || d.cluster == nil || cfg.Chassis.Cluster == nil {
		return rpmCfg
	}

	gating := rpmProbeTestGating(cfg)
	if len(gating) == 0 {
		return rpmCfg
	}

	filtered := &config.RPMConfig{Probes: make(map[string]*config.RPMProbe, len(rpmCfg.Probes))}
	droppedTests, droppedProbes := 0, 0
	for name, probe := range rpmCfg.Probes {
		if probe == nil {
			filtered.Probes[name] = probe
			continue
		}
		kept := make(map[string]*config.RPMTest, len(probe.Tests))
		for testName, test := range probe.Tests {
			if rgID, gated := gating[probeTestKey{name, testName}]; gated && !d.cluster.IsLocalPrimary(rgID) {
				droppedTests++
				continue
			}
			kept[testName] = test
		}
		if len(kept) == 0 {
			droppedProbes++
			continue
		}
		if len(kept) == len(probe.Tests) {
			filtered.Probes[name] = probe
			continue
		}
		filtered.Probes[name] = &config.RPMProbe{Name: probe.Name, Tests: kept}
	}
	if droppedTests > 0 {
		slog.Info("RPM probe tests gated off while secondary",
			"tests", droppedTests, "probes", droppedProbes)
	}
	return filtered
}

// probeTestKey identifies one RPM test inside its probe; used as the
// key of the per-test gating map (#15074).
type probeTestKey struct {
	// probe is the authored probe name, test the test name inside it.
	probe, test string
}

// rpmProbeTestGating returns the gated tests, keyed per test and mapped
// to the redundancy group whose primaryship gates them: the test's own
// bound RETH RG when it has one, otherwise the lowest configured data
// RG for a test that is in the gating scope only through its probe's
// ip-monitoring reference.
//
// Every test resolves independently, so the result cannot depend on
// the iteration order of probe.Tests (a Go map): a test bound to
// reth0.50 in RG1 is gated by RG1 regardless of what another test binds
// (#15074). Iteration order of the input maps is irrelevant because
// each key is written exactly once from that key's own test.
func rpmProbeTestGating(cfg *config.Config) map[probeTestKey]int {
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

	gated := make(map[probeTestKey]int)
	for probeName, probe := range rpmCfg.Probes {
		if probe == nil {
			continue
		}
		probeReferenced := referenced[probeName]
		for testName, test := range probe.Tests {
			key := probeTestKey{probeName, testName}
			if test == nil {
				if probeReferenced {
					gated[key] = defaultRG
				}
				continue
			}
			// A test's own binding wins over its probe-sibling's: the
			// destination-interface pin is the test's egress contract,
			// then the source-address VIP contract.
			if test.DestinationInterface != "" {
				base := test.DestinationInterface
				if i := strings.IndexByte(base, '.'); i >= 0 {
					base = base[:i]
				}
				if rg, ok := rethRG[base]; ok {
					gated[key] = rg
					continue
				}
			}
			if test.SourceAddress != "" {
				if rg, ok := rethVIPs[test.SourceAddress]; ok {
					gated[key] = rg
					continue
				}
			}
			if probeReferenced {
				gated[key] = defaultRG
			}
		}
	}
	return gated
}

// rpmProbeGatingRGs returns the probes inside the §4.4 gating scope,
// mapped to a representative gating RG: the lowest RG among the
// probe's gated tests. Probes whose tests span several RGs have no
// single gating RG — gating itself is per test (see
// rpmProbeTestGating) — so this probe-level view is retained only for
// call sites that ask "is this probe in scope, and on which RG does it
// (at least partly) run": the HA takeover burst and the issue #3764
// publish comment. The minimum is deterministic (the pre-#15074
// last-writer-wins-over-map-order pick was not).
func rpmProbeGatingRGs(cfg *config.Config) map[string]int {
	gated := make(map[string]int)
	for key, rg := range rpmProbeTestGating(cfg) {
		if cur, ok := gated[key.probe]; !ok || rg < cur {
			gated[key.probe] = rg
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

func defaultProbePinLinkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onError func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done,
		netlink.LinkSubscribeOptions{ErrorCallback: onError})
}

func defaultProbePinAddrSubscribe(ch chan<- netlink.AddrUpdate, done <-chan struct{}, onError func(error)) error {
	return netlink.AddrSubscribeWithOptions(ch, done,
		netlink.AddrSubscribeOptions{ErrorCallback: onError})
}

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

// probePinEgressState distinguishes definite administrative state from a
// missing or unreadable link. Unknown is deliberately fail-closed: it cannot
// release a pin hold.
type probePinEgressState uint8

const (
	probePinEgressUnknown probePinEgressState = iota
	probePinEgressUp
	probePinEgressDown
)

// probePinEgressStateForName reports the administrative IFF_UP state for an
// egress, using the test seam when configured. Failed or incomplete lookups
// return Unknown so they cannot release a pin hold.
func (d *Daemon) probePinEgressStateForName(name string) probePinEgressState {
	if d.probePinEgressStateFn != nil {
		return d.probePinEgressStateFn(name)
	}
	link, err := netlink.LinkByName(name)
	if err != nil || link == nil || link.Attrs() == nil {
		return probePinEgressUnknown
	}
	if link.Attrs().Flags&net.FlagUp != 0 {
		return probePinEgressUp
	}
	return probePinEgressDown
}

// probePinFailuresExceptAdminDownEgress holds missing/mismatched pins unless
// LinkByName confirms the egress exists with IFF_UP clear. Bound sends on an
// admin-down link report ENETUNREACH, so those probes must remain able to drive
// loss thresholds instead of being hidden by ErrProbeSetup. Missing or
// unreadable links remain held because their state is unknown.
func (d *Daemon) probePinFailuresExceptAdminDownEgress(pins []routing.ProbePin, failed map[string]error) map[string]error {
	if len(failed) == 0 {
		return nil
	}
	filtered := make(map[string]error, len(failed))
	for key, err := range failed {
		found := false
		for _, pin := range pins {
			if pin.TestKey != key {
				continue
			}
			found = true
			if d.probePinEgressStateForName(pin.Interface) != probePinEgressDown {
				filtered[key] = err
			}
			break
		}
		if !found {
			filtered[key] = err
		}
	}
	if len(filtered) == len(failed) {
		return failed
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// verifyProbePinsLocked publishes readback failures except for a confirmed
// admin-down egress. A missing route on an up egress can false-pass through
// the main table; a missing or unreadable egress remains held because its
// state is unknown. A confirmed down link instead fails bound sends with
// ENETUNREACH and must feed RPM's loss threshold. Callers hold rpmMu. nil
// means this daemon has no readback implementation.
func (d *Daemon) verifyProbePinsLocked(pins []routing.ProbePin) {
	verify := d.probePinVerifyFn()
	if verify == nil || len(pins) == 0 {
		return
	}
	failed := d.probePinFailuresExceptAdminDownEgress(pins, verify(pins))
	// Retire installer-failure history that authoritative readback disproves:
	// without this, a later independent readback-only drift re-triggers an
	// immediate full-band retry off stale history (Astra R5-confirmation M1).
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
	installFailed := d.probePinFailuresExceptAdminDownEgress(pins,
		d.applyProbePinsHeld(applyPins, pins))
	d.rpmPinInstallFailures = installFailed
	failed := installFailed
	if verify := d.probePinVerifyFn(); verify != nil {
		verified := d.probePinFailuresExceptAdminDownEgress(pins, verify(pins))
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
	resubBackoff := d.probePinResubBackoff
	if resubBackoff <= 0 {
		resubBackoff = linkStateResubBackoffDefault
	}

	var linkUpdates <-chan netlink.LinkUpdate
	var addrUpdates <-chan netlink.AddrUpdate
	var linkDone, addrDone chan struct{}
	var linkRetry, addrRetry <-chan time.Time
	subscriptionErrors := make(chan struct{}, 1)
	onError := func(err error) {
		slog.Warn("probe pin netlink subscription reported a gap; checking all pins", "err", err)
		select {
		case subscriptionErrors <- struct{}{}:
		default:
		}
	}
	linkSubscribe := d.probePinLinkSubscribe
	if linkSubscribe == nil {
		linkSubscribe = defaultProbePinLinkSubscribe
	}
	addrSubscribe := d.probePinAddrSubscribe
	if addrSubscribe == nil {
		addrSubscribe = defaultProbePinAddrSubscribe
	}
	subscribeLink := func() (<-chan netlink.LinkUpdate, chan struct{}, error) {
		updates := make(chan netlink.LinkUpdate, 32)
		done := make(chan struct{})
		if err := linkSubscribe(updates, done, onError); err != nil {
			close(done)
			return nil, nil, err
		}
		return updates, done, nil
	}
	subscribeAddr := func() (<-chan netlink.AddrUpdate, chan struct{}, error) {
		updates := make(chan netlink.AddrUpdate, 32)
		done := make(chan struct{})
		if err := addrSubscribe(updates, done, onError); err != nil {
			close(done)
			return nil, nil, err
		}
		return updates, done, nil
	}
	if d.probePinVerifyFn() != nil {
		var err error
		linkUpdates, linkDone, err = subscribeLink()
		if err != nil {
			slog.Warn("probe pin link subscription unavailable; retrying", "err", err)
			linkRetry = time.After(resubBackoff)
		}
		addrUpdates, addrDone, err = subscribeAddr()
		if err != nil {
			slog.Warn("probe pin address subscription unavailable; retrying", "err", err)
			addrRetry = time.After(resubBackoff)
		}
	}
	defer func() {
		if linkDone != nil {
			close(linkDone)
		}
		if addrDone != nil {
			close(addrDone)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			d.rpmMu.Lock()
			d.rpmPinRetryActive = false
			d.rpmMu.Unlock()
			return
		case update, ok := <-linkUpdates:
			if !ok {
				slog.Warn("probe pin link subscription closed; resubscribing")
				if linkDone != nil {
					close(linkDone)
					linkDone = nil
				}
				linkUpdates = nil
				linkRetry = time.After(resubBackoff)
				continue
			}
			if update.Attrs() != nil {
				d.verifyProbePinsForLink(update.Attrs().Name)
			}
		case update, ok := <-addrUpdates:
			if !ok {
				slog.Warn("probe pin address subscription closed; resubscribing")
				if addrDone != nil {
					close(addrDone)
					addrDone = nil
				}
				addrUpdates = nil
				addrRetry = time.After(resubBackoff)
				continue
			}
			d.verifyProbePinsForAddress(update.LinkIndex)
		case <-linkRetry:
			linkRetry = nil
			updates, done, err := subscribeLink()
			if err != nil {
				slog.Warn("probe pin link resubscription failed; retrying", "err", err)
				linkRetry = time.After(resubBackoff)
				continue
			}
			linkUpdates, linkDone = updates, done
			slog.Info("probe pin link subscription restored; resynchronizing")
			d.verifyProbePinsForAll()
		case <-addrRetry:
			addrRetry = nil
			updates, done, err := subscribeAddr()
			if err != nil {
				slog.Warn("probe pin address resubscription failed; retrying", "err", err)
				addrRetry = time.After(resubBackoff)
				continue
			}
			addrUpdates, addrDone = updates, done
			slog.Info("probe pin address subscription restored; resynchronizing")
			d.verifyProbePinsForAll()
		case <-subscriptionErrors:
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
	// marked-but-unbacked socket. Unlike installer/readback failures, this
	// hold is unconditional: nothing re-evaluates it if the egress comes
	// up later, so filtering it now could false-pass through the main table
	// after an egress bounce (#12088).
	d.rpm.HoldPinsForReprogram(probePinKeys(pins), errProbePinReprogram)
	var failed map[string]error
	if applyPins != nil {
		installFailed := d.probePinFailuresExceptAdminDownEgress(pins, applyPins(pins))
		d.rpmPinInstallFailures = installFailed
		failed = installFailed
		if verify := d.probePinVerifyFn(); verify != nil {
			verified := d.probePinFailuresExceptAdminDownEgress(pins, verify(pins))
			d.rpmPinInstallFailures = retainProbePinInstallFailures(installFailed, verified)
			failed = verified
		}
	} else {
		d.rpmPinInstallFailures = nil
		failed = probePinsAllFailed(pins, errNoProbePinInstaller)
	}
	if len(failed) > 0 {
		if applyPins == nil {
			slog.Warn("next-hop probe pins configured but no routing manager — pinned tests hold state",
				"pins", len(failed))
		} else {
			slog.Warn("probe pin install or readback failures — affected tests hold state until a retry succeeds",
				"failed", len(failed))
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

// newlyEnabledIPMonProbeNames reports ip-monitoring probes that gained at
// least one runnable test in effective versus previous, for the HA takeover
// burst. The gate is probe-membership (rpmProbeGatingRGs is only an
// in-scope marker here): with per-test gating (#15074) a probe that was
// already partly running on this node is not re-burst — its newly enabled
// tests join on the normal hash-gated apply — while a probe that becomes
// runnable at all still bursts as before.
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
