package daemon

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// dnsAddressRefreshInterval is the periodic re-resolution cadence for
// dns-name address-book entries (#15673). DNS answers change outside config
// commits, so the daemon re-resolves on this ticker and republishes through
// the normal apply path when an answer changes.
var dnsAddressRefreshInterval = 5 * time.Minute

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

// dnsIdentityKey builds a collision-free snapshot key for one dns-name
// entry. The scope is length-prefixed so no operator-authored name (which
// may legally contain '/', e.g. "address-book/eng-book/svc") can alias
// another scope — change detection must merge views on identity, not on
// name shadowing (#15933 C4, #15962 fold).
func dnsIdentityKey(scope, name string) string {
	return fmt.Sprintf("%d:%s%s", len(scope), scope, name)
}

// snapshotDNSAnswers captures identity->prefixes for every dns-name entry,
// for change detection across a refresh (#15933, #15962 fold). Callers
// that read a published config's DNS fields must hold applySem (or own
// the config), because the apply path re-resolves in place under applySem.
func snapshotDNSAnswers(cfg *config.Config) map[string][]string {
	out := map[string][]string{}
	if cfg == nil {
		return out
	}
	scan := func(scope string, b *config.AddressBook) {
		if b == nil {
			return
		}
		for name, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				out[dnsIdentityKey(scope, name)] = append([]string(nil), a.DNSAddresses...)
			}
		}
	}
	scan("global/", cfg.Security.AddressBook)
	for bookName, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			scan("address-book/"+bookName+"/", &nb.AddressBook)
		}
	}
	for zoneName, z := range cfg.Security.Zones {
		if z != nil {
			scan(config.ZoneLocalQualify(zoneName, ""), z.AddressBook)
		}
	}
	return out
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
// applySem — the only place the apply path may write those fields, and
// short, with no I/O — then releases the semaphore before any network
// resolution. Resolution runs outside the lock into the private clone.
// Publication re-acquires applySem and applies ONLY if the base
// generation is still active, else discards; the apply path's own
// in-place re-resolution under the same semaphore may move the
// published answers between snapshot and publish, which is harmless:
// the generation check, not answer stability, decides publication.
// Baseline = actually-applied answers read back under applySem at
// applyConfigLocked exit (B2), so a background re-apply of the same
// generation reconciles it and a flap-back is detected next tick.
func (d *Daemon) refreshDNSOnce() {
	if d.store == nil || d.applySem == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.beginBackgroundApply(context.Background(), "dnsAddressRefreshSnapshot") {
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
	gen, _ := d.store.ActiveSnapshot()
	var expectDigest uint64
	hasBaseline := false
	if baseline := d.dnsBaselineFor(cfg); baseline != nil {
		before = baseline
		expectDigest = dnsAnswersDigest(baseline)
		hasBaseline = true
		// Prefer the recorded generation for CAS identity.
		if bg, bb, _ := d.dnsBaselineState(); bb == cfg {
			gen = bg
		}
	}
	_ = hasBaseline
	refreshed := cfg.CloneForDNSRefresh()
	d.applySem.Release(1)

	config.RefreshDNSAddressBooks(refreshed)
	if dnsAnswersEqual(before, snapshotDNSAnswers(refreshed)) {
		return
	}
	slog.Info("dns-name address-book answer changed, recompiling dataplane")
	// R1 (round-3): baseline is written ONLY inside the publish
	// applySem hold (publish + read-back + generation/digest CAS in one
	// critical section, keyed to (gen, expectDigest) from snapshot).
	// There is NO baseline write after the semaphore is released.
	if _, err := d.applyDNSRefreshedConfigCAS(cfg, refreshed, gen, expectDigest, hasBaseline); err != nil {
		slog.Warn("dns-name refresh re-apply failed", "err", err)
	}
}

// dnsAnswersDigest is a stable digest of an answer snapshot for the
// baseline CAS (FNV-1a over sorted identity keys + answers).
func dnsAnswersDigest(answers map[string][]string) uint64 {
	keys := make([]string, 0, len(answers))
	for k := range answers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := fnv.New64a()
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		h.Write([]byte{0})
		for _, v := range answers[k] {
			_, _ = h.Write([]byte(v))
			h.Write([]byte{0})
		}
		h.Write([]byte{0xff})
	}
	return h.Sum64()
}

// recordDNSBaselineCAS records answers as the applied baseline for
// (gen, cfg) ONLY if no newer-or-different state is already recorded:
// a newer generation always wins; the same generation wins only with
// the identical digest (idempotent re-record of the same applied
// state). A late writer carrying different answers for the same
// generation is dropped — the round-3 lost-update guard. Callers hold
// applySem (or own cfg). Test-only fail-on-revert: setting
// dnsBaselineTickGuardOff makes this an unconditional write (the
// pre-fix lost-update shape).
func (d *Daemon) recordDNSBaselineCAS(gen uint64, cfg *config.Config, answers map[string][]string) {
	digest := dnsAnswersDigest(answers)
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.dnsBaselineTickGuardOff {
		// FAIL-ON-REVERT shape (test control only): unconditional.
	} else {
		if d.lastDNSRefreshGen > gen {
			return
		}
		if d.lastDNSRefreshBase == cfg && d.lastDNSRefreshGen == gen &&
			d.lastDNSRefreshAnswers != nil && d.lastDNSRefreshDigest != digest {
			return
		}
	}
	d.lastDNSRefreshGen = gen
	d.lastDNSRefreshBase = cfg
	d.lastDNSRefreshDigest = digest
	d.lastDNSRefreshAnswers = cloneDNSAnswers(answers)
}

// recordDNSBaselineIfDigest is the tick publish record (inside the
// publish applySem hold): records answers ONLY if the recorded
// baseline still has expectDigest (the digest the tick snapshot at
// publish start) or the same digest — keyed to the snapshot digest it
// just published, so a same-generation apply that landed newer answers
// is never overwritten by an older tick snapshot (round-3 R1).
func (d *Daemon) recordDNSBaselineIfDigest(gen uint64, cfg *config.Config, expectDigest uint64, answers map[string][]string) {
	digest := dnsAnswersDigest(answers)
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.dnsBaselineTickGuardOff {
		// FAIL-ON-REVERT control (test only): unconditional write.
	} else if d.lastDNSRefreshBase == cfg && d.lastDNSRefreshGen == gen && d.lastDNSRefreshAnswers != nil &&
		d.lastDNSRefreshDigest != expectDigest && d.lastDNSRefreshDigest != digest {
		return
	}
	d.lastDNSRefreshGen = gen
	d.lastDNSRefreshBase = cfg
	d.lastDNSRefreshDigest = digest
	d.lastDNSRefreshAnswers = cloneDNSAnswers(answers)
}

// recordDNSBaseline unconditionally records (seam-path publish, where no
// competing same-generation writer can interleave under applySem).
func (d *Daemon) recordDNSBaseline(cfg *config.Config, answers map[string][]string) {
	d.recordDNSBaselineCAS(d.activeGen(cfg), cfg, answers)
}

// dnsBaselineFor returns the recorded applied answers for cfg, or nil.
func (d *Daemon) dnsBaselineFor(cfg *config.Config) map[string][]string {
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.lastDNSRefreshBase == cfg && d.lastDNSRefreshAnswers != nil {
		return cloneDNSAnswers(d.lastDNSRefreshAnswers)
	}
	return nil
}

func (d *Daemon) dnsBaselineState() (uint64, *config.Config, map[string][]string) {
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.lastDNSRefreshAnswers == nil {
		return d.lastDNSRefreshGen, d.lastDNSRefreshBase, nil
	}
	return d.lastDNSRefreshGen, d.lastDNSRefreshBase, cloneDNSAnswers(d.lastDNSRefreshAnswers)
}

func (d *Daemon) clearDNSBaseline() {
	d.dnsRefreshMu.Lock()
	d.lastDNSRefreshBase = nil
	d.lastDNSRefreshGen = 0
	d.lastDNSRefreshDigest = 0
	d.lastDNSRefreshAnswers = nil
	d.dnsRefreshMu.Unlock()
}

// activeGen returns the store publication generation for cfg identity.
func (d *Daemon) activeGen(cfg *config.Config) uint64 {
	if d.store == nil || cfg == nil {
		return 0
	}
	gen, cur := d.store.ActiveSnapshot()
	if cur == cfg {
		return gen
	}
	if d.store.ActiveConfig() == cfg {
		return gen
	}
	return 0
}

// recordAppliedDNSBaseline reconciles the refresher baseline after a
// NON-refresher apply completes (under applySem): on failure the baseline
// is invalidated; on success of the active generation it is replaced by
// what that apply actually resolved. This closes the flap-back desync
// (#15962 B2) without refreshing on every apply.
func (d *Daemon) recordAppliedDNSBaseline(cfg *config.Config, applyErr error) {
	if cfg == nil {
		return
	}
	if d.applyBodyForTest != nil {
		return
	}
	if applyErr != nil {
		if d.store != nil && d.store.ActiveConfig() == cfg {
			d.clearDNSBaseline()
		}
		return
	}
	if d.store == nil || d.store.ActiveConfig() != cfg || !dnsBookHasNames(cfg) {
		return
	}
	// Under applySem the applied state is the newest by construction, so
	// this record must win over a same-generation tick record: force it
	// by recording with the guard satisfied via a direct write.
	d.recordDNSBaselineForce(cfg, snapshotDNSAnswers(cfg))
}

// recordDNSBaselineForce unconditionally sets the baseline (under
// applySem at a real apply exit, where the writer IS the newest).
func (d *Daemon) recordDNSBaselineForce(cfg *config.Config, answers map[string][]string) {
	gen := d.activeGen(cfg)
	d.dnsRefreshMu.Lock()
	d.lastDNSRefreshGen = gen
	d.lastDNSRefreshBase = cfg
	d.lastDNSRefreshDigest = dnsAnswersDigest(answers)
	d.lastDNSRefreshAnswers = cloneDNSAnswers(answers)
	d.dnsRefreshMu.Unlock()
}

// applyDNSRefreshedConfig publishes a privately refreshed DNS copy
// (no CAS key; used by the stale-generation guard test).
func (d *Daemon) applyDNSRefreshedConfig(base, refreshed *config.Config) (bool, error) {
	return d.applyDNSRefreshedConfigCAS(base, refreshed, 0, 0, false)
}

// applyDNSRefreshedConfigCAS publishes under applySem ONLY if base is
// still active, and records the actually-applied baseline in the SAME
// hold via generation+digest CAS (record only if recorded gen < gen,
// or == gen with digest unchanged since snapshot / equal to applied).
func (d *Daemon) applyDNSRefreshedConfigCAS(base, refreshed *config.Config, snapGen uint64, expectDigest uint64, hasExpect bool) (bool, error) {
	if !d.beginBackgroundApply(context.Background(), "dnsAddressRefresh") {
		return false, nil
	}
	defer d.applySem.Release(1)
	if d.store == nil || d.store.ActiveConfig() != base {
		return false, nil
	}
	gen, _ := d.store.ActiveSnapshot()
	if hasExpect && snapGen != 0 {
		gen = snapGen
	}
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(refreshed)
		d.policyInvalidationPublishLanded = true
		applied := snapshotDNSAnswers(refreshed)
		if hasExpect {
			d.recordDNSBaselineIfDigest(gen, base, expectDigest, applied)
		} else {
			d.recordDNSBaselineForce(base, applied)
		}
		if d.store != nil && d.policyInvalidationDebt == nil {
			d.store.MarkActiveApplied()
		}
		return true, nil
	}
	err := d.applyConfigLocked(context.Background(), refreshed)
	if err != nil {
		return false, err
	}
	appliedAnswers := snapshotDNSAnswers(refreshed)
	if hasExpect {
		d.recordDNSBaselineIfDigest(gen, base, expectDigest, appliedAnswers)
	} else {
		d.recordDNSBaselineForce(base, appliedAnswers)
	}
	if d.policyInvalidationDebt == nil && d.policyInvalidationPublishLanded {
		d.store.MarkActiveApplied()
	}
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
