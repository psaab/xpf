package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// dnsAddressRefreshInterval is the periodic re-resolution cadence for
// dns-name address-book entries (#15673). DNS answers change outside config
// commits, so the daemon re-resolves on this ticker and republishes through
// the normal apply path when an answer changes.
var dnsAddressRefreshInterval = 5 * time.Minute

// markDNSResolved records cfg as already resolved outside applySem
// (#16601) so resolveDNSBeforeApply does not resolve it again.
func (d *Daemon) markDNSResolved(cfg *config.Config) {
	if cfg == nil {
		return
	}
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.dnsResolvedConfigs == nil {
		d.dnsResolvedConfigs = make(map[*config.Config]struct{})
	}
	d.dnsResolvedConfigs[cfg] = struct{}{}
}

func (d *Daemon) isDNSResolved(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	_, ok := d.dnsResolvedConfigs[cfg]
	return ok
}

func (d *Daemon) consumeDNSResolved(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	_, ok := d.dnsResolvedConfigs[cfg]
	if ok {
		delete(d.dnsResolvedConfigs, cfg)
	}
	return ok
}

// resolveDNSBeforeApply resolves dns-name entries OUTSIDE applySem
// (#16601) and returns the config to apply. Marked configs (refresher
// clone) return as-is. Every other config is resolved into a private
// CloneForDNSRefresh clone and that clone is returned: the argument is
// NEVER written through (#16687). Before #16687 the owned-config arm
// resolved a throwaway clone for the network work and then called
// PopulateDNSFromCache(cfg) on the caller's pointer — safe only while
// every caller owned its pointer, and a published-config race the
// moment any caller (commit, sync, rollback, debt retry) handed in the
// store's ActiveConfig() or the frozen confirmPrevCfg, both of which
// several callers do. Returning the clone for every arm makes the
// no-write-through-published-pointer contract hold by construction,
// independent of caller provenance. Callers that need the caller's
// pointer identity (digest/stamp keying) already tolerate a DNS clone:
// recordAppliedDNSBaseline re-keys a clone of the active config onto
// the active pointer, and text digests hash the tree, not the pointer.
func (d *Daemon) resolveDNSBeforeApply(cfg *config.Config) *config.Config {
	if cfg == nil || !config.HasDNSNames(cfg) {
		return cfg
	}
	if d.consumeDNSResolved(cfg) {
		return cfg
	}
	clone := cfg.CloneForDNSRefresh()
	config.RefreshDNSAddressBooks(clone)
	d.markDNSResolved(clone)
	return clone
}

func compileDNSRefreshTree(tree *config.ConfigTree, nodeID int) (*config.Config, error) {
	if nodeID >= 0 {
		return config.CompileConfigForNodeLenient(tree, nodeID)
	}
	return config.CompileConfigLenient(tree)
}

// resolveCandidateDNSBeforeApply refreshes the current candidate's DNS
// answers before a commit acquires applySem. CandidateGateSample returns an
// immutable tree and its generation together; this pass expands node groups
// with the local node ID before DNS extraction. The commit preflight checks
// that generation before promoting a DNS-bearing candidate, so a concurrent
// edit cannot introduce names that this pass did not refresh.
func (d *Daemon) resolveCandidateDNSBeforeApply() uint64 {
	if d == nil || d.store == nil {
		return 0
	}
	tree, generation, _ := d.store.CandidateGateSample()
	if tree == nil {
		return generation
	}
	cfg, err := compileDNSRefreshTree(tree, d.store.NodeID())
	if err != nil {
		return generation
	}
	if config.HasDNSNames(cfg) {
		config.RefreshDNSAddressBooks(cfg)
	}
	return generation
}

// dnsBookHasNames reports whether cfg carries any dns-name entry.
func dnsBookHasNames(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	has := false
	scan := func(b *config.AddressBook) {
		if b == nil {
			return
		}
		for _, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				has = true
			}
		}
	}
	scan(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			scan(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			scan(z.AddressBook)
		}
	}
	return has
}

// snapshotDNSAnswers captures identity->prefixes for every dns-name entry,
// for change detection across a refresh (#15933, #15962 fold). Published
// configs are immutable (#16687): their DNS fields change only by
// publishing a new generation, so readers need no applySem. The
// enumeration itself lives in config.DNSAnswersSnapshot so the
// userspace hybrid guard compares exactly the same identities (#16606).
func snapshotDNSAnswers(cfg *config.Config) map[string][]string {
	return config.DNSAnswersSnapshot(cfg)
}

func dnsAnswersEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

// cloneDNSAnswers deep-copies an answer snapshot for baseline storage.
func cloneDNSAnswers(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// refreshDNSOnce performs one periodic dns-name refresh tick (#15933).
//
// Protocol (deliberately simple — #15962 round-2 removed the lease
// design): the tick takes a coherent snapshot of the published
// generation's DNS state (DNS-field reads and CloneForDNSRefresh) UNDER
// applySem — short, with no I/O — then releases the semaphore before
// any network resolution. Resolution runs outside the lock into the
// private clone. Publication re-acquires applySem and applies ONLY if
// the base generation is still active, else discards; a background
// apply may publish a newer clone of the same generation in between,
// which is harmless: the generation check, not answer stability,
// decides publication. Baseline = actually-applied answers read back
// under applySem at applyConfigLocked exit (B2), so a background
// re-apply of the same generation reconciles it and a flap-back is
// detected next tick.
func (d *Daemon) refreshDNSOnce() {
	if d.store == nil || d.applySem == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.beginBackgroundApply(d.backgroundApplyCtx(), "dnsAddressRefreshSnapshot") {
		return
	}
	if d.store.ActiveConfig() != cfg {
		d.applySem.Release(1)
		return
	}
	if !dnsBookHasNames(cfg) {
		d.applySem.Release(1)
		return
	}
	before := snapshotDNSAnswers(cfg)
	if baseline := d.dnsBaselineFor(cfg); baseline != nil {
		before = baseline
	}
	refreshed := cfg.CloneForDNSRefresh()
	d.applySem.Release(1)

	config.RefreshDNSAddressBooks(refreshed)
	d.markDNSResolved(refreshed)
	if dnsAnswersEqual(before, snapshotDNSAnswers(refreshed)) {
		// No change: drop the marker; the clone is discarded.
		d.consumeDNSResolved(refreshed)
		return
	}
	slog.Info("dns-name address-book answer changed, recompiling dataplane")
	// Baseline is written ONLY inside applyDNSRefreshedConfig's
	// applySem hold (publish + actually-applied read-back, recorded
	// unconditionally — inside the single hold the read-back IS the
	// newest applied state, so no CAS is needed or correct). There is
	// NO baseline write after the semaphore is released.
	if _, err := d.applyDNSRefreshedConfig(cfg, refreshed); err != nil {
		slog.Warn("dns-name refresh re-apply failed", "err", err)
	}
}

// dnsBaselineFor returns the recorded applied answers for cfg, or nil.
// #16601: after #16606 publishes a refreshed clone, the active pointer
// is the clone; a baseline recorded under the previous active pointer
// (background apply of that generation) still describes the same
// authored generation, so fall back to it when the pointer differs
// but a baseline exists. Generation changes record a new baseline or
// clear it, so the fallback cannot cross generations in practice
// (commits record/clear under applySem before the next tick reads).
func (d *Daemon) dnsBaselineFor(cfg *config.Config) map[string][]string {
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.lastDNSRefreshAnswers == nil {
		return nil
	}
	if d.lastDNSRefreshBase == cfg {
		return cloneDNSAnswers(d.lastDNSRefreshAnswers)
	}
	// Fallback: any recorded baseline (see above).
	return cloneDNSAnswers(d.lastDNSRefreshAnswers)
}

func (d *Daemon) clearDNSBaseline() {
	d.dnsRefreshMu.Lock()
	d.lastDNSRefreshBase = nil
	d.lastDNSRefreshAnswers = nil
	d.dnsRefreshMu.Unlock()
}

// recordAppliedDNSBaseline reconciles the refresher baseline after a
// NON-refresher apply completes (under applySem): on failure the baseline
// is invalidated; on success of the active generation it is replaced by
// what that apply actually resolved. This closes the flap-back desync
// (#15962 B2) without refreshing on every apply.
//
// #17744: a successful ordinary apply whose cfg is a DNS-resolved clone
// of the still-active generation must PUBLISH that clone
// (Store.PublishRefreshedDNS, the same base-CAS the #16606 refresher
// uses) before recording the baseline, and the baseline is keyed to the
// clone actually published — never to the stale active pointer the clone
// was resolved from. Recording the clone's answers against the old
// pointer left store.ActiveConfig() (and every reader keyed to it: the
// scheduler, the userspace manager compile guard, the policymatch query
// cache) on the stale answers while the baseline already claimed the
// fresh ones, so the next refresh tick compared equal against the
// baseline and never repaired the store. Publishing first is safe
// because PublishRefreshedDNS never touches the persisted operator tree
// (DNS answers are runtime state) and refuses the swap when base is no
// longer active, so a newer promoted generation is never overwritten.
// When the applied clone carries the SAME answers as the active
// generation there is nothing to publish: the baseline is recorded
// against the active pointer and the store generation does not churn.
// The periodic refresher clone is explicitly excluded from this
// ordinary-apply path: applyDNSRefreshedConfig owns its base-CAS
// publication and baseline record.
func (d *Daemon) recordAppliedDNSBaseline(cfg *config.Config, applyErr error) {
	if cfg == nil {
		return
	}
	if d.applyBodyForTest != nil {
		return
	}
	if cfg == d.dnsRefreshApplying {
		if applyErr != nil {
			d.clearDNSBaseline()
		}
		return
	}
	base := cfg
	isCloneOfActive := false
	if d.store != nil {
		if active := d.store.ActiveConfig(); active != nil && active != cfg && dnsBookHasNames(cfg) {
			base = active
			isCloneOfActive = true
		}
	}
	if applyErr != nil {
		if d.store != nil && (d.store.ActiveConfig() == cfg || isCloneOfActive) {
			d.clearDNSBaseline()
		}
		return
	}
	if d.store == nil || !dnsBookHasNames(cfg) {
		return
	}
	if !isCloneOfActive && d.store.ActiveConfig() != cfg {
		return
	}
	if isCloneOfActive {
		answers := snapshotDNSAnswers(cfg)
		if dnsAnswersEqual(answers, snapshotDNSAnswers(base)) {
			// Unchanged answers: the applied clone adds nothing over
			// the published generation; skip the republish so the
			// store generation does not churn on every ordinary apply.
			d.recordDNSBaselineForce(base, answers)
			return
		}
		if !d.store.PublishRefreshedDNS(base, cfg) {
			// The base stopped being active, so this resolved clone
			// was superseded and must not become a baseline for the
			// newly active config.
			d.clearDNSBaseline()
			return
		}
		d.recordDNSBaselineForce(cfg, answers)
		return
	}
	d.recordDNSBaselineForce(base, snapshotDNSAnswers(cfg))
}

// recordDNSBaselineForce unconditionally sets the baseline (under
// applySem at a real apply exit, where the writer IS the newest).
func (d *Daemon) recordDNSBaselineForce(cfg *config.Config, answers map[string][]string) {
	d.dnsRefreshMu.Lock()
	d.lastDNSRefreshBase = cfg
	d.lastDNSRefreshAnswers = cloneDNSAnswers(answers)
	d.dnsRefreshMu.Unlock()
}

// applyDNSRefreshedConfig publishes a privately refreshed DNS copy of
// base under applySem ONLY if base is still active, and records the
// actually-applied baseline UNCONDITIONALLY in the same hold: inside
// the single hold the read-back is by construction the newest applied
// state (any competing record was written before this hold began and
// has just been superseded on the dataplane), so a CAS would only ever
// drop the newest record (round-4 B1). Returns (true,nil) only when
// actually applied.
//
// #16606: on success the refreshed clone is ALSO published as the
// store's compiled active config (Store.PublishRefreshedDNS, still
// under this same applySem hold and only if base is still active).
// Before this, the clone lived only in the dataplane's lastSnapshot:
// store.ActiveConfig() kept the stale answers, so the next scheduler
// edge or route-overlay republish rebuilt address-book rows from the
// stale generation and silently re-shipped the old answer. Publishing
// the applied clone keeps the store, the baseline, and the helper on
// exactly the same answers. The baseline is keyed to the published clone.
func (d *Daemon) applyDNSRefreshedConfig(base, refreshed *config.Config) (bool, error) {
	if !d.beginBackgroundApply(d.backgroundApplyCtx(), "dnsAddressRefresh") {
		// The refresh clone is marked before this call; admission refusal
		// must not retain that marker.
		d.consumeDNSResolved(refreshed)
		return false, nil
	}
	defer func() {
		// Consume before releasing applySem so a superseded clone cannot
		// remain marked for the next serialized apply.
		d.consumeDNSResolved(refreshed)
		d.applySem.Release(1)
	}()
	if d.store == nil || d.store.ActiveConfig() != base {
		return false, nil
	}
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(refreshed)
		d.policyInvalidationPublishLanded = true
		if !d.store.PublishRefreshedDNS(base, refreshed) {
			return false, nil
		}
		d.recordDNSBaselineForce(refreshed, snapshotDNSAnswers(refreshed))
		// Test hook: PublishLanded was forced true just above, so this
		// stamps exactly when the pre-helper hook gate did (store is
		// already known non-nil here; the helper re-checks it).
		d.stampActiveAppliedIfConvergedUnderSem(nil)
		return true, nil
	}
	// #16601: consume the refresher marker BEFORE the apply so
	// the resolve stage does not repeat DNS I/O. The apply-deferred
	// baseline recognizes this clone via dnsRefreshApplying and
	// leaves publication + baseline to this helper.
	d.consumeDNSResolved(refreshed)
	d.dnsRefreshApplying = refreshed
	defer func() { d.dnsRefreshApplying = nil }()
	err := d.applyConfigLocked(context.Background(), refreshed)
	if err != nil {
		return false, err
	}
	// Publish AFTER the real apply: recordAppliedDNSBaseline recognized
	// dnsRefreshApplying and did not record or publish the refresher clone;
	// these answers are stored only after the base-CAS succeeds below.
	if !d.store.PublishRefreshedDNS(base, refreshed) {
		// A newer generation was promoted concurrently; the refreshed
		// apply was superseded. Do not claim this generation's baseline.
		return false, nil
	}
	d.recordDNSBaselineForce(refreshed, snapshotDNSAnswers(refreshed))
	d.stampActiveAppliedIfConvergedUnderSem(nil)
	return true, nil
}

// startDNSAddressRefresher launches the periodic dns-name re-resolution
// goroutine. It is a no-op when the daemon has no store; each tick takes a
// coherent snapshot under the apply lock, resolves on a private copy, and
// applies only on a real change. Runs for the daemon lifetime (parent ctx
// is never cancelled by design; see daemonCtx).
func (d *Daemon) startDNSAddressRefresher() {
	if d.store == nil {
		return
	}
	ctx := d.daemonCtx
	if ctx == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(dnsAddressRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.refreshDNSOnce()
			}
		}
	}()
}
