package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// dnsAddressRefreshInterval is the periodic re-resolution cadence for
// dns-name address-book entries (#15673). DNS answers change outside config
// commits, so the daemon re-resolves on this ticker and republishes through
// the normal apply path when an answer changes.
var dnsAddressRefreshInterval = 5 * time.Minute

// dnsRefreshLease pins one owed dns-name refresh (#15933, fold #15962).
// While it is held, applyDataplaneAndHACore defers the apply path's DNS
// re-resolution to the refresh owner (the periodic tick, whose clone is
// the one config an apply that consumes the lease applies); optimistic
// applies that race lease acquisition instead return without applying and
// let the owner drive. Leases are per-config-pointer and single-use.
type dnsRefreshLease struct {
	cfg  *config.Config
	done chan struct{}
	once sync.Once
}

func (l *dnsRefreshLease) finish() {
	// Idempotent: publication consumes the lease under applySem, then the
	// tick's deferred drop fires again. sync.Once makes the pair safe;
	// a bare close(done) here panicked on double close (#15962 fold,
	// reproduced by TestDNSRefreshDetectsGlobalChangeShadowedByZoneLocal).
	if l != nil {
		l.once.Do(func() { close(l.done) })
	}
}

// acquireDNSRefreshLease tries to become the refresh owner for cfg. It
// fails when another refresh is already owed for cfg.
func (d *Daemon) acquireDNSRefreshLease(cfg *config.Config) (*dnsRefreshLease, bool) {
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.dnsRefreshLease != nil {
		if d.dnsRefreshLease.cfg == cfg {
			return nil, false
		}
		// A refresh owed for an older generation must not block this one:
		// the old owner's generation check will discard its result.
		d.dnsRefreshLease = nil
	}
	l := &dnsRefreshLease{cfg: cfg, done: make(chan struct{})}
	d.dnsRefreshLease = l
	return l, true
}

// dnsWaitForRefresh blocks (outside applySem) until any owed refresh for
// cfg is dropped or consumed, so a deferring background applier can retry.
func (d *Daemon) dnsWaitForRefresh(cfg *config.Config) {
	for {
		l := d.peekDNSRefreshLease(cfg)
		if l == nil {
			return
		}
		<-l.done
	}
}

func (d *Daemon) dropDNSRefreshLease(l *dnsRefreshLease) {
	l.finish()
	d.dnsRefreshMu.Lock()
	if d.dnsRefreshLease == l {
		d.dnsRefreshLease = nil
	}
	d.dnsRefreshMu.Unlock()
}

// takeDNSRefreshLease consumes and returns the lease owed for cfg (the
// publishing apply may then run under applySem), or nil.
func (d *Daemon) takeDNSRefreshLease(cfg *config.Config) *dnsRefreshLease {
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	l := d.dnsRefreshLease
	if l == nil || l.cfg != cfg {
		return nil
	}
	d.dnsRefreshLease = nil
	return l
}

// peekDNSRefreshLease returns the lease owed for cfg without consuming it.
func (d *Daemon) peekDNSRefreshLease(cfg *config.Config) *dnsRefreshLease {
	d.dnsRefreshMu.Lock()
	defer d.dnsRefreshMu.Unlock()
	if d.dnsRefreshLease != nil && d.dnsRefreshLease.cfg == cfg {
		return d.dnsRefreshLease
	}
	return nil
}

// dnsRefreshOwedFor reports whether the refresh owner owes publication for
// cfg (used by applyConfigLocked to defer instead of racing).
func (d *Daemon) dnsRefreshOwedFor(cfg *config.Config) bool {
	return d.peekDNSRefreshLease(cfg) != nil
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

// refreshDNSOnce performs one periodic dns-name refresh tick (#15933,
// fold #15962 B1/B2).
//
// Protocol: the tick acquires a per-generation lease plus a coherent
// snapshot of the published generation's DNS state (DNS-field reads and
// the clone) UNDER applySem — the only place the apply path may write
// those fields — then releases the semaphore before any network
// resolution. While the lease is held, applyDataplaneAndHACore defers
// DNS re-resolution to this owner and optimistic background applies of
// the same generation defer to it, so published DNS state cannot move
// mid-tick. Resolution runs outside the lock into the private clone;
// publication re-checks (under applySem) that the base generation is
// still active and reads what was actually applied back into the
// baseline.
func (d *Daemon) refreshDNSOnce() {
	if d.store == nil || d.applySem == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	lease, ok := d.acquireDNSRefreshLease(cfg)
	if !ok {
		return
	}
	if !d.beginBackgroundApply(context.Background(), "dnsAddressRefreshSnapshot") {
		d.dropDNSRefreshLease(lease)
		return
	}
	if d.store.ActiveConfig() != cfg {
		d.applySem.Release(1)
		d.dropDNSRefreshLease(lease)
		return
	}
	if !dnsBookHasNames(cfg) {
		d.applySem.Release(1)
		d.dropDNSRefreshLease(lease)
		return
	}
	before := snapshotDNSAnswers(cfg)
	if baseline := d.dnsBaselineFor(cfg); baseline != nil {
		before = baseline
	}
	refreshed := cfg.CloneForDNSRefresh()
	d.applySem.Release(1)

	defer d.dropDNSRefreshLease(lease)
	config.RefreshDNSAddressBooks(refreshed)
	if dnsAnswersEqual(before, snapshotDNSAnswers(refreshed)) {
		return
	}
	slog.Info("dns-name address-book answer changed, recompiling dataplane")
	applied, err := d.applyDNSRefreshedConfig(cfg, refreshed, lease)
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
func (d *Daemon) applyDNSRefreshedConfig(base, refreshed *config.Config, lease *dnsRefreshLease) (bool, error) {
	_ = lease // consumption is via takeDNSRefreshLease under applySem
	if !d.beginBackgroundApply(context.Background(), "dnsAddressRefresh") {
		return false, nil
	}
	defer d.applySem.Release(1)
	if d.store == nil || d.store.ActiveConfig() != base {
		return false, nil
	}
	l := d.takeDNSRefreshLease(base)
	if l == nil {
		return false, nil
	}
	defer func() {
		l.finish()
	}()
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
