package daemon

import (
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
	for _, z := range cfg.Security.Zones {
		if z != nil {
			scan(z.AddressBook)
		}
	}
	return has
}

// snapshotDNSAnswers captures name->prefixes for every dns-name entry, for
// change detection across a refresh.
func snapshotDNSAnswers(cfg *config.Config) map[string][]string {
	out := map[string][]string{}
	if cfg == nil {
		return out
	}
	scan := func(b *config.AddressBook) {
		if b == nil {
			return
		}
		for name, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				out[name] = append([]string(nil), a.DNSAddresses...)
			}
		}
	}
	scan(cfg.Security.AddressBook)
	for _, z := range cfg.Security.Zones {
		if z != nil {
			scan(z.AddressBook)
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

// startDNSAddressRefresher launches the periodic dns-name re-resolution
// goroutine. It is a no-op when the daemon has no store; each tick re-reads
// the active config, refreshes its DNS entries, and — only when an answer
// actually changed — re-applies so the new prefixes reach the dataplane.
// Runs for the daemon lifetime (parent ctx is never cancelled by design;
// see daemonCtx).
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
				cfg := d.store.ActiveConfig()
				if cfg == nil || !dnsBookHasNames(cfg) {
					continue
				}
				before := snapshotDNSAnswers(cfg)
				config.RefreshDNSAddressBooks(cfg)
				if dnsAnswersEqual(before, snapshotDNSAnswers(cfg)) {
					continue
				}
				slog.Info("dns-name address-book answer changed, recompiling dataplane")
				if err := d.applyActiveConfigResult(); err != nil {
					slog.Warn("dns-name refresh re-apply failed", "err", err)
				}
			}
		}
	}()
}
