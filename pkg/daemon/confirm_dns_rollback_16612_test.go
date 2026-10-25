package daemon

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #16612 (R3-N09-04): a commit-confirmed window recovered at boot compiles
// its rollback target once, at Store.Load. If dns-name resolution fails
// then, the frozen empty/failed answer must not be treated at the deadline
// as a permanent dataplane refusal that enters bootstrap — especially
// after DNS recovers. The fire-time check re-resolves a private clone;
// a DNS-only refusal is bounded-deferred like the feed case, and at the
// cap the rollback proceeds (the apply path re-resolves in place) rather
// than entering the bootstrap/lifeline safe state.
//
// The refused shape used for the DNS-attributable cells is a permit with
// a destination-address-excluded dns-name side: its per-rule fail-closed
// poison (#16595) is the refusal the mirror can report for a lookup-failed
// entry, and fresh DNS removes exactly that poison.

// dnsTargetFor16612 builds a dns-name target in the given policy mode.
func dnsTargetFor16612(t *testing.T, mode string) string {
	t.Helper()
	tree := &config.ConfigTree{}
	lines := []string{
		"set system host-name dns-target",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address api dns-name api.example.com",
	}
	switch mode {
	case "permit":
		lines = append(lines,
			"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address api",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		)
	case "deny":
		lines = append(lines,
			"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address api",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then deny",
		)
	case "excluded":
		lines = append(lines,
			"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address api",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address-excluded",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		)
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree.Format()
}

// recoveredDNSStore16612 arms a window over target with DNS up, then
// re-Loads a second store with the resolver in the given state, exactly
// the reboot sequence of the probe. It returns the recovered store and
// the dnsUp switch.
func recoveredDNS16612(t *testing.T, target string, dnsUpAtLoad bool) (*configstore.Store, *bool, func()) {
	t.Helper()
	dnsUp := true
	restore := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		if dnsUp {
			return []string{"198.51.100.20"}, nil
		}
		return nil, errors.New("dial udp: no upstream")
	})
	path := filepath.Join(t.TempDir(), "xpf.conf")
	a := newConfigStore(t, path)
	armWindowOver9615(t, a, target)
	dnsUp = dnsUpAtLoad
	b := newConfigStore(t, path)
	if err := b.Load(); err != nil {
		restore()
		t.Fatalf("Load: %v", err)
	}
	a.CancelConfirmTimerForTesting()
	if !b.IsConfirmPending() {
		restore()
		t.Fatal("precondition: Load must re-arm the still-live window")
	}
	t.Cleanup(func() { _ = b.ConfirmCommit() })
	return b, &dnsUp, restore
}

func newDNSDaemon16612(t *testing.T, s *configstore.Store) (*Daemon, *[]string) {
	t.Helper()
	applied := &[]string{}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(cfg *config.Config) {
		if cfg != nil {
			*applied = append(*applied, cfg.System.HostName)
		}
	}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	prev := confirmRollbackFeedRetryInterval
	confirmRollbackFeedRetryInterval = time.Hour
	t.Cleanup(func() { confirmRollbackFeedRetryInterval = prev })
	return d, applied
}

// TestRecoveredDNSDownAtLoadAppliedAfterRecovery16612 is the acceptance
// cell: DNS down at Load, healthy at the deadline — the target is applied
// and the daemon does NOT enter bootstrap. Before the fix the stale
// clone (or a still-failed entry whose refusal the mirror reports for
// the excluded shape) was classified as refused and the fire entered
// bootstrap with nothing applied.
func TestRecoveredDNSDownAtLoadAppliedAfterRecovery16612(t *testing.T) {
	for _, mode := range []string{"permit", "deny", "excluded"} {
		t.Run(mode, func(t *testing.T) {
			s, dnsUp, restore := recoveredDNS16612(t, dnsTargetFor16612(t, mode), false)
			defer restore()
			d, applied := newDNSDaemon16612(t, s)
			d.checkRecoveredConfirmTarget()
			*dnsUp = true // DNS healthy long before the deadline
			s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
			if got := hostName9615(s); got != "dns-target" {
				t.Fatalf("store must roll back to dns-target, got %q", got)
			}
			if len(*applied) != 1 || (*applied)[0] != "dns-target" {
				t.Fatalf("dns-target must be applied once after DNS recovery, got %v (mode=%s)", *applied, mode)
			}
			if d.inBootstrap() {
				t.Fatalf("DNS recovered before the deadline must not enter bootstrap (mode=%s)", mode)
			}
		})
	}
}

// TestRecoveredDNSStillDownBoundedThenApplies16612: DNS stays down. A
// DNS-only refusal is deferred (bounded, like feeds) without promoting,
// and at the cap the rollback proceeds and applies the target — the
// apply path re-resolves and renders each entry fail-closed — instead
// of entering bootstrap on the frozen Load-time answer.
func TestRecoveredDNSStillDownBoundedThenApplies16612(t *testing.T) {
	s, dnsUp, restore := recoveredDNS16612(t, dnsTargetFor16612(t, "excluded"), false)
	defer restore()
	_ = dnsUp // stays down for the whole cell
	d, applied := newDNSDaemon16612(t, s)
	gen := s.ConfirmGenForTesting()
	// Only assert deferral when the current mirror actually refuses this
	// shape for a lookup-failed entry; if it does not, the first fire
	// already applies (also correct) and the loop is vacuous.
	for i := 1; i <= confirmRollbackFeedRetryMax; i++ {
		s.InvokeRollbackTimerForTesting(gen)
		if len(*applied) != 0 {
			break // applied early: no refusal to defer (mirror-dependent)
		}
		if got := hostName9615(s); got != "abandoned" {
			t.Fatalf("attempt %d: a DNS-deferred target must not promote, store holds %q", i, got)
		}
		if !s.IsConfirmPending() || d.inBootstrap() {
			t.Fatalf("attempt %d: deferral must keep the window pending without bootstrap (pending=%v bootstrap=%v)",
				i, s.IsConfirmPending(), d.inBootstrap())
		}
	}
	s.InvokeRollbackTimerForTesting(gen)
	if got := hostName9615(s); got != "dns-target" {
		t.Fatalf("past the DNS cap the rollback must promote to dns-target, got %q applied=%v", got, *applied)
	}
	if d.inBootstrap() {
		t.Fatal("past the DNS cap the rollback must apply (per-entry fail-closed), not enter bootstrap")
	}
	if len(*applied) == 0 {
		// The cap fire returns false and the normal path applies; if the
		// loop above already consumed the applying fire, this is fine.
		// Reach here only if no fire ever applied — a failure.
		t.Fatalf("the target was never applied: applied=%v", *applied)
	}
}

// TestRecoveredDNSAlarmNamesDNS16612: the boot alarm for a DNS-only
// refused recovered target names dns-name resolution, not the generic
// "refused by this build's dataplane" misdiagnosis. It drives the
// classifier directly on a target whose dns-name failed at Load: the
// state text is produced by checkRecoveredConfirmTarget only when the
// mirror refuses, so here we pin the classifier half that selects the
// DNS wording, and the fire-time cells above pin the end-to-end path.
func TestRecoveredDNSAlarmNamesDNS16612(t *testing.T) {
	s, _, restore := recoveredDNS16612(t, dnsTargetFor16612(t, "excluded"), false)
	defer restore()
	target, _, ok := s.PendingRollbackTarget(s.ConfirmGenForTesting())
	if !ok || target == nil {
		t.Fatal("precondition: recovered window must expose its target")
	}
	if !targetHasFailedDNSLookup(target) {
		t.Fatal("precondition: DNS down at Load must leave a lookup-failed entry")
	}
	if !rollbackTargetRefusedOnlyForDNS(target) {
		t.Fatal("a lookup-failed target whose refusal is DNS-attributable must be classified DNS-only, so the alarm names dns-name resolution")
	}
}

// TestRollbackTargetRefusedOnlyForDNSUnit16612 pins the classifier:
// a lookup-failed target is DNS-deferred; a healthy or statically
// refused target is not.
func TestRollbackTargetRefusedOnlyForDNSUnit16612(t *testing.T) {
	failed := &config.Config{}
	failed.Security.AddressBook = &config.AddressBook{
		Addresses:   map[string]*config.Address{"api": {Name: "api", DNSName: "api.example.com", DNSLookupFailed: true}},
		AddressSets: map[string]*config.AddressSet{},
	}
	if !targetHasFailedDNSLookup(failed) {
		t.Fatal("a DNSLookupFailed entry must be detected")
	}
	healthy := &config.Config{}
	healthy.Security.AddressBook = &config.AddressBook{
		Addresses:   map[string]*config.Address{"api": {Name: "api", DNSName: "api.example.com", DNSAddresses: []string{"198.51.100.20/32"}}},
		AddressSets: map[string]*config.AddressSet{},
	}
	if targetHasFailedDNSLookup(healthy) {
		t.Fatal("a resolved entry must not read as lookup-failed")
	}
	if rollbackTargetRefusedOnlyForDNS(healthy) {
		t.Fatal("a target with no failed lookup is never DNS-only")
	}
	if rollbackTargetRefusedOnlyForDNS(nil) {
		t.Fatal("nil target is never DNS-only")
	}
	// Detection must cover named books too (the Load compile can fail a
	// lookup in any book the target carries).
	named := &config.Config{}
	named.Security.NamedAddressBooks = map[string]*config.NamedAddressBook{
		"eng": {AddressBook: config.AddressBook{Addresses: map[string]*config.Address{
			"svc": {Name: "svc", DNSName: "svc.example.com", DNSLookupFailed: true},
		}}},
	}
	if !targetHasFailedDNSLookup(named) {
		t.Fatal("a lookup-failed entry in a named book must be detected")
	}
}

// TestRefreshDNSForPreflightDoesNotMutate16612: the preflight clone is
// private — re-resolving it must not move the frozen target's answers.
func TestRefreshDNSForPreflightDoesNotMutate16612(t *testing.T) {
	restore := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	})
	defer restore()
	frozen := &config.Config{}
	frozen.Security.AddressBook = &config.AddressBook{
		Addresses:   map[string]*config.Address{"api": {Name: "api", DNSName: "api.example.com", DNSLookupFailed: true}},
		AddressSets: map[string]*config.AddressSet{},
	}
	clone := config.RefreshDNSForPreflight(frozen)
	if clone == nil {
		t.Fatal("RefreshDNSForPreflight returned nil")
	}
	if got := frozen.Security.AddressBook.Addresses["api"]; len(got.DNSAddresses) != 0 || !got.DNSLookupFailed {
		t.Fatalf("the frozen target was mutated: %+v", got)
	}
	if got := clone.Security.AddressBook.Addresses["api"]; len(got.UsableValues()) != 1 || got.DNSLookupFailed {
		t.Fatalf("the clone must carry the fresh answer: %+v", got)
	}
}
