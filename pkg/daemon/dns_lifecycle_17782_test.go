package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

const dnsAnswer17782 = "203.0.113.77/32"

func dnsPolicyConfig17782(t *testing.T, host, fqdn string) string {
	t.Helper()
	tree := &config.ConfigTree{}
	lines := []string{
		"set system host-name " + host,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address api dns-name " + fqdn,
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address api",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
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

func nodeGroupedDNSPolicy17782(t *testing.T) string {
	t.Helper()
	tree := &config.ConfigTree{}
	lines := []string{
		"set groups node0 security address-book global address api dns-name node0-17782.example.invalid",
		"set groups node1 security address-book global address api dns-name node1-17782.example.invalid",
		`set apply-groups "${node}"`,
		"set system host-name node1-dns",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address api",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
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

func dnsApplyDaemon17782(t *testing.T, store *configstore.Store) (*Daemon, <-chan []string) {
	t.Helper()
	applied := make(chan []string, 1)
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.applyBodyForTest = func(cfg *config.Config) {
		if cfg == nil || cfg.Security.AddressBook == nil || cfg.Security.AddressBook.Addresses["api"] == nil {
			applied <- nil
			return
		}
		values := cfg.Security.AddressBook.Addresses["api"].UsableValues()
		applied <- append([]string(nil), values...)
	}
	return d, applied
}

func TestColdCacheDNSPolicyCommit17782(t *testing.T) {
	fqdn := "cold-commit-17782.example.invalid"
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(dnsPolicyConfig17782(t, "cold-dns", fqdn)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	coldCfg, err := config.CompileConfigLenient(store.CandidateTree())
	if err != nil {
		t.Fatalf("cold-cache compile: %v", err)
	}
	coldEntry := coldCfg.Security.AddressBook.Addresses["api"]
	if coldEntry == nil || !coldEntry.DNSUnresolved || coldEntry.DNSLookupFailed {
		t.Fatalf("cold-cache DNS state = %+v, want unresolved without resolver-failed", coldEntry)
	}
	t.Cleanup(func() { store.ExitConfigure() })
	d, applied := dnsApplyDaemon17782(t, store)

	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseLookup) }) }
	defer release()
	var calls atomic.Int32
	restoreLookup := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		calls.Add(1)
		close(lookupStarted)
		<-releaseLookup
		return []string{"203.0.113.77"}, nil
	})
	defer restoreLookup()

	done := make(chan error, 1)
	go func() {
		_, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "cold DNS", peerSyncNever)
		done <- err
	}()
	select {
	case <-lookupStarted:
	case err := <-done:
		t.Fatalf("commit returned before the cold-cache lookup ran: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("cold-cache commit did not start DNS resolution")
	}
	if !d.applySem.TryAcquire(1) {
		release()
		<-done
		t.Fatal("cold-cache resolver held applySem before commit promotion")
	}
	d.applySem.Release(1)
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("commitAndApply: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DNS policy commit did not finish after resolver release")
	}
	if calls.Load() == 0 {
		t.Fatal("cold-cache commit did not invoke the resolver")
	}
	select {
	case got := <-applied:
		if !reflect.DeepEqual(got, []string{dnsAnswer17782}) {
			t.Fatalf("applied DNS values = %v, want [%s]", got, dnsAnswer17782)
		}
	default:
		t.Fatal("commit did not reach the apply body")
	}
	active := store.ActiveConfig()
	if active == nil || active.Security.AddressBook.Addresses["api"] == nil {
		t.Fatal("commit did not publish the DNS address")
	}
	activeEntry := active.Security.AddressBook.Addresses["api"]
	if activeEntry.DNSUnresolved || activeEntry.DNSLookupFailed {
		t.Fatalf("resolved commit state retained unresolved/failure marker: %+v", activeEntry)
	}
	d.dnsRefreshMu.Lock()
	markers := len(d.dnsResolvedConfigs)
	d.dnsRefreshMu.Unlock()
	if markers != 0 {
		t.Fatalf("resolved-config markers after ordinary commit = %d, want 0", markers)
	}
}

func TestCommitRejectsDNSCandidateChangedDuringRefresh17782(t *testing.T) {
	initialFQDN := "initial-17782.example.invalid"
	changedFQDN := "changed-17782.example.invalid"
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(dnsPolicyConfig17782(t, "initial-dns", initialFQDN)); err != nil {
		t.Fatalf("LoadOverride initial candidate: %v", err)
	}
	t.Cleanup(func() { store.ExitConfigure() })
	d, applied := dnsApplyDaemon17782(t, store)

	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseLookup) }) }
	defer release()
	restoreLookup := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		close(lookupStarted)
		<-releaseLookup
		return []string{"203.0.113.77"}, nil
	})
	defer restoreLookup()

	done := make(chan error, 1)
	go func() {
		_, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "racing DNS", peerSyncNever)
		done <- err
	}()
	select {
	case <-lookupStarted:
	case err := <-done:
		t.Fatalf("commit returned before refreshing the DNS candidate: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("commit did not start DNS refresh")
	}
	if err := store.LoadOverride(dnsPolicyConfig17782(t, "changed-dns", changedFQDN)); err != nil {
		release()
		<-done
		t.Fatalf("LoadOverride changed candidate: %v", err)
	}
	release()
	select {
	case err := <-done:
		if !errors.Is(err, configstore.ErrCandidateGenerationConflict) {
			t.Fatalf("commit error = %v, want candidate-generation conflict", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("commit did not reject the changed DNS candidate")
	}
	select {
	case got := <-applied:
		t.Fatalf("changed DNS candidate unexpectedly applied: %v", got)
	default:
	}
}

func TestNode1GroupedDNSCommitPrepass17782(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	store.SetNodeID(1)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(nodeGroupedDNSPolicy17782(t)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	t.Cleanup(func() { store.ExitConfigure() })
	d, applied := dnsApplyDaemon17782(t, store)
	lookups := make(chan string, 2)
	restoreLookup := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		lookups <- fqdn
		return []string{"203.0.113.177"}, nil
	})
	defer restoreLookup()

	done := make(chan error, 1)
	go func() {
		_, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "node1 DNS", peerSyncNever)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("commitAndApply: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("node1 grouped-DNS commit did not finish")
	}
	select {
	case got := <-lookups:
		if got != "node1-17782.example.invalid" {
			t.Fatalf("DNS prepass resolved %q, want node1 grouped name", got)
		}
	default:
		t.Fatal("node1 grouped-DNS prepass did not resolve a name")
	}
	select {
	case got := <-applied:
		if !reflect.DeepEqual(got, []string{"203.0.113.177/32"}) {
			t.Fatalf("node1 grouped DNS values = %v, want [203.0.113.177/32]", got)
		}
	default:
		t.Fatal("node1 grouped-DNS commit did not reach the apply body")
	}
}

func TestNode1GroupedDNSSyncPrepass17782(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	store.SetNodeID(1)
	d, applied := dnsApplyDaemon17782(t, store)
	lookups := make(chan string, 2)
	restoreLookup := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		lookups <- fqdn
		return []string{"203.0.113.177"}, nil
	})
	defer restoreLookup()

	text := nodeGroupedDNSPolicy17782(t)
	done := make(chan error, 1)
	go func() {
		_, err := d.syncAndApplyWithAncestry(context.Background(), text, nil, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("syncAndApplyWithAncestry: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("node1 grouped-DNS sync did not finish")
	}
	select {
	case got := <-lookups:
		if got != "node1-17782.example.invalid" {
			t.Fatalf("DNS prepass resolved %q, want node1 grouped name", got)
		}
	default:
		t.Fatal("node1 grouped-DNS sync prepass did not resolve a name")
	}
	select {
	case got := <-applied:
		if !reflect.DeepEqual(got, []string{"203.0.113.177/32"}) {
			t.Fatalf("node1 grouped DNS values = %v, want [203.0.113.177/32]", got)
		}
	default:
		t.Fatal("node1 grouped-DNS sync did not reach the apply body")
	}
}

func TestSyncDNSDoesNotResolveUnderApplySem17782(t *testing.T) {
	fqdn := "sync-17782.example.invalid"
	restoreCache := config.SeedDNSAnswerCacheForTest(fqdn, "", []string{dnsAnswer17782})
	defer restoreCache()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	d, _ := dnsApplyDaemon17782(t, store)
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseLookup) }) }
	defer release()
	var calls atomic.Int32
	restoreLookup := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		calls.Add(1)
		close(lookupStarted)
		<-releaseLookup
		return []string{"203.0.113.77"}, nil
	})
	defer restoreLookup()

	text := dnsPolicyConfig17782(t, "sync-dns", fqdn)
	done := make(chan error, 1)
	go func() {
		_, err := d.syncAndApplyWithAncestry(context.Background(), text, nil, nil)
		done <- err
	}()
	var syncErr error
	syncFinished := false
	select {
	case <-lookupStarted:
		if !d.applySem.TryAcquire(1) {
			release()
			<-done
			t.Fatal("peer-sync resolver blocked another applySem acquisition")
		}
		d.applySem.Release(1)
		release()
	case syncErr = <-done:
		syncFinished = true
		if syncErr != nil {
			t.Fatalf("syncAndApplyWithAncestry: %v", syncErr)
		}
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("peer-sync neither completed nor attempted an unexpected live lookup")
	}
	if !syncFinished {
		select {
		case syncErr = <-done:
			if syncErr != nil {
				t.Fatalf("syncAndApplyWithAncestry after DNS release: %v", syncErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("peer-sync did not finish")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("peer-sync resolver calls = %d, want exactly one outside applySem", got)
	}
}

func TestRecoveredRollbackDNSRefreshRunsOutsideApplySem17782(t *testing.T) {
	fqdn := "rollback-17782.example.invalid"
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	armWindowOver9615(t, store, dnsPolicyConfig17782(t, "rollback-dns", fqdn))
	defer store.ConfirmCommit()
	d, applied := dnsApplyDaemon17782(t, store)
	gen := store.ConfirmGenForTesting()
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseLookup) }) }
	defer release()
	restoreLookup := config.SetLookupAddressDNSNameForTest(func(string) ([]string, error) {
		close(lookupStarted)
		<-releaseLookup
		return []string{"203.0.113.77"}, nil
	})
	defer restoreLookup()

	done := make(chan struct{})
	go func() {
		d.executeConfirmedRollback(gen)
		close(done)
	}()
	select {
	case <-lookupStarted:
	case <-done:
		t.Fatal("rollback returned before refreshing its recovered DNS target")
	case <-time.After(5 * time.Second):
		t.Fatal("rollback did not start its DNS refresh")
	}
	if !d.applySem.TryAcquire(1) {
		release()
		<-done
		t.Fatal("rollback preflight resolver blocked another applySem acquisition")
	}
	d.applySem.Release(1)
	release()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not finish after DNS recovery")
	}
	if d.inBootstrap() {
		t.Fatal("healthy DNS refresh left the recovered rollback in bootstrap")
	}
	if got := hostName9615(store); got != "rollback-dns" {
		t.Fatalf("rollback promoted host-name %q, want rollback-dns", got)
	}
	select {
	case got := <-applied:
		if !reflect.DeepEqual(got, []string{dnsAnswer17782}) {
			t.Fatalf("rollback applied DNS values = %v, want [%s]", got, dnsAnswer17782)
		}
	default:
		t.Fatal("recovered rollback did not apply the refreshed target")
	}
}
