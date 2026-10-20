package daemon

import (
	"context"
	"fmt"
	"log/slog"
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
	if baseline := d.dnsBaselineFor(cfg); baseline != nil {
		before = baseline
	}
	refreshed := cfg.CloneForDNSRefresh()
	d.applySem.Release(1)

	config.RefreshDNSAddressBooks(refreshed)
	if dnsAnswersEqual(before, snapshotDNSAnswers(refreshed)) {
		return
	}
	slog.Info("dns-name address-book answer changed, recompiling dataplane")
	applied, err := d.applyDNSRefreshedConfig(cfg, refreshed)
	if err != nil {
		slog.Warn("dns-name refresh re-apply failed", "err", err)
		return
	}
	if applied {
		// Record only what was actually applied (applyDNSRefreshedConfig
		// reads it back under the semaphore); refused/discarded ticks
		// leave the baseline untouched (#15962 M1).
		d.recordDNSBaseline(cfg, snapshotDNSAnswers(refreshed))
	}
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

func (d *Daemon) recordDNSBaseline(cfg *config.Config, answers map[string][]string) {
	d.dnsRefreshMu.Lock()
	d.lastDNSRefreshBase = cfg
	d.lastDNSRefreshAnswers = cloneDNSAnswers(answers)
	d.dnsRefreshMu.Unlock()
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
func (d *Daemon) recordAppliedDNSBaseline(cfg *config.Config, applyErr error) {
	if cfg == nil {
		return
	}
	// Test-seam applies (applyBodyForTest) return before the apply path
	// touches DNS, so there is nothing to reconcile there.
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
	d.recordDNSBaseline(cfg, snapshotDNSAnswers(cfg))
}

// applyDNSRefreshedConfig publishes a privately refreshed DNS copy of base
// under the apply semaphore. It returns (true, nil) only when the copy
// was actually applied, (false, nil) when the publish was refused or the
// generation moved on (a newer generation's own apply re-resolves DNS).
func (d *Daemon) applyDNSRefreshedConfig(base, refreshed *config.Config) (bool, error) {
	if !d.beginBackgroundApply(context.Background(), "dnsAddressRefresh") {
		return false, nil
	}
	defer d.applySem.Release(1)
	if d.store == nil || d.store.ActiveConfig() != base {
		return false, nil
	}
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(refreshed)
		d.policyInvalidationPublishLanded = true
		if d.store != nil && d.policyInvalidationDebt == nil {
			d.store.MarkActiveApplied()
		}
		return true, nil
	}
	err := d.applyConfigLocked(context.Background(), refreshed)
	if err != nil {
		return false, err
	}
	// Baseline honesty (#15962 gate 3): read back what the apply actually
	// resolved (applyConfigLocked re-resolves under this same semaphore).
	d.recordDNSBaseline(base, snapshotDNSAnswers(refreshed))
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
