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
// for change detection across a refresh.
//
// Keys are the EFFECTIVE identity of each entry, never the bare authored
// name (#15933 C4): the global book is keyed by its (already folded) map
// key — a zone-local entry lives there as zone-local/<zone>/<name>, a
// distinct identity from a global entry of the same authored name — named
// books are qualified by book name, and zone-local books by zone. Keying by
// bare name let a stable same-named zone-local entry overwrite a changed
// global entry in this map, so the global change compared equal and was
// never republished.
func snapshotDNSAnswers(cfg *config.Config) map[string][]string {
	out := map[string][]string{}
	if cfg == nil {
		return out
	}
	scan := func(prefix string, b *config.AddressBook) {
		if b == nil {
			return
		}
		for name, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				out[prefix+name] = append([]string(nil), a.DNSAddresses...)
			}
		}
	}
	scan("", cfg.Security.AddressBook)
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

// refreshDNSOnce performs one periodic dns-name refresh tick (#15933).
//
// Ownership: the active config is a PUBLISHED generation shared with
// concurrent applies and readers (configstore hands out the store's own
// *Config). This tick therefore never writes into it. It clones the DNS
// state (CloneForDNSRefresh), resolves into the private copy outside the
// apply lock (resolution can block on the network), and — only when an
// answer actually changed — publishes the copy under the apply semaphore
// via applyDNSRefreshedConfig, re-checking that the active generation is
// still the one the copy was taken from. A generation that moved on (a
// commit landed meanwhile) is left alone: the incoming apply re-resolves
// DNS itself (daemon_apply_dataplane.go), so no answer is lost and the
// newer generation is never overwritten by a stale refresh.
func (d *Daemon) refreshDNSOnce() {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || !dnsBookHasNames(cfg) {
		return
	}
	before := snapshotDNSAnswers(cfg)
	if d.lastDNSRefreshBase == cfg && d.lastDNSRefreshAnswers != nil {
		// The published generation is never mutated by a refresh, so
		// the last successfully published answers are the effective
		// baseline for this generation — not the (stale-by-design)
		// answers frozen in the store's copy.
		before = d.lastDNSRefreshAnswers
	}
	refreshed := cfg.CloneForDNSRefresh()
	config.RefreshDNSAddressBooks(refreshed)
	after := snapshotDNSAnswers(refreshed)
	if dnsAnswersEqual(before, after) {
		return
	}
	slog.Info("dns-name address-book answer changed, recompiling dataplane")
	if err := d.applyDNSRefreshedConfig(cfg, refreshed); err != nil {
		slog.Warn("dns-name refresh re-apply failed", "err", err)
		return
	}
	d.lastDNSRefreshBase = cfg
	d.lastDNSRefreshAnswers = after
}

// applyDNSRefreshedConfig publishes a privately refreshed DNS copy of base
// under the apply semaphore. It applies base ONLY if base is still the
// active generation when the semaphore is acquired; if a commit promoted a
// newer generation while DNS was resolving, the copy is discarded and nil
// is returned (that generation's own apply re-resolves DNS under the same
// semaphore). When applyBodyForTest is set (unit tests) the body seam is
// invoked directly, mirroring applyConfigLocked's own seam handling.
func (d *Daemon) applyDNSRefreshedConfig(base, refreshed *config.Config) error {
	if !d.beginBackgroundApply(context.Background(), "dnsAddressRefresh") {
		return nil
	}
	defer d.applySem.Release(1)
	if d.store == nil || d.store.ActiveConfig() != base {
		return nil
	}
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(refreshed)
		d.policyInvalidationPublishLanded = true
		if d.store != nil && d.policyInvalidationDebt == nil {
			d.store.MarkActiveApplied()
		}
		return nil
	}
	err := d.applyConfigLocked(context.Background(), refreshed)
	if err == nil && d.policyInvalidationDebt == nil && d.policyInvalidationPublishLanded {
		d.store.MarkActiveApplied()
	}
	return err
}

// startDNSAddressRefresher launches the periodic dns-name re-resolution
// goroutine. It is a no-op when the daemon has no store; each tick re-reads
// the active config, refreshes its DNS entries on a private copy, and —
// only when an answer actually changed — re-applies under the apply lock
// so the new prefixes reach the dataplane. The published active config is
// never mutated (#15933). Runs for the daemon lifetime (parent ctx is
// never cancelled by design; see daemonCtx).
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
