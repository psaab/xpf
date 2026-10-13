// #5281: factoryReset is the daemon-owned zeroize gate. It runs the wipe under
// the SAME applySem commit/apply/HA-sync serialize on, and enters a TERMINAL
// reset generation so no concurrent or subsequent config writer can re-persist
// the erased SSOT or re-render the wiped secrets before the daemon is stopped.
package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func isolateFactoryResetOwnershipPaths(t *testing.T) {
	t.Helper()
	oldLease, oldSurfaceA, oldIPsec, oldHistory := resetDDNSLeaseStatePath, resetDDNSSurfaceAPath, resetIPsecStatePath, feedShrinkHistoryPath
	root := t.TempDir()
	resetDDNSLeaseStatePath = filepath.Join(root, "dhcp-ddns-state.json")
	resetDDNSSurfaceAPath = filepath.Join(root, "interface-ddns-state.json")
	resetIPsecStatePath = filepath.Join(root, "ipsec-conn-state.json")
	feedShrinkHistoryPath = filepath.Join(root, "state", "feed-shrink-history.json")
	t.Cleanup(func() {
		resetDDNSLeaseStatePath, resetDDNSSurfaceAPath, resetIPsecStatePath, feedShrinkHistoryPath = oldLease, oldSurfaceA, oldIPsec, oldHistory
	})
}

// isolateFactoryResetIdentityPaths redirects the identity snapshot/restore
// files and the post-wipe lease verification into a disposable tree, and
// stubs the kernel-hostname seams. Every factoryReset test must call it:
// without isolation a failed-wipe test would restore into the REAL
// /etc/hostname, /etc/hosts, /etc/resolv.conf and
// /etc/ssh/ssh_known_hosts, rename the REAL kernel hostname, and verify
// the REAL Kea lease paths.
func isolateFactoryResetIdentityPaths(t *testing.T) {
	t.Helper()
	oldHostname, oldHosts, oldResolv, oldKnown := hostnamePath, resetHostsPath, resetResolvConfPath, resetKnownHostsPath
	oldKea := resetKeaLeaseCurrents
	oldOsHostname, oldSethostname := osHostname, sethostname
	root := t.TempDir()
	hostnamePath = filepath.Join(root, "etc", "hostname")
	resetHostsPath = filepath.Join(root, "etc", "hosts")
	resetResolvConfPath = filepath.Join(root, "etc", "resolv.conf")
	resetKnownHostsPath = filepath.Join(root, "etc", "ssh", "ssh_known_hosts")
	resetKeaLeaseCurrents = []string{
		filepath.Join(root, "var", "lib", "kea", "kea-leases4.csv"),
		filepath.Join(root, "var", "lib", "kea", "kea-leases6.csv"),
	}
	osHostname = func() (string, error) { return "test-kernel", nil }
	sethostname = func([]byte) error { return nil }
	t.Cleanup(func() {
		hostnamePath, resetHostsPath, resetResolvConfPath, resetKnownHostsPath = oldHostname, oldHosts, oldResolv, oldKnown
		resetKeaLeaseCurrents = oldKea
		osHostname, sethostname = oldOsHostname, oldSethostname
	})
}

// factoryReset must Acquire applySem BEFORE wiping, enter the terminal reset
// generation on success, release the gate afterward, and thereafter REJECT new
// config work (commit / HA-sync).
func TestFactoryResetGatesAndEntersResetGeneration(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	// (1) Gate-first: hold applySem externally with a tight deadline. factoryReset
	// must surface ctx.Err() and neither wipe nor enter the reset generation —
	// nothing has been erased, so an aborted acquire is safe.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("setup acquire: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	wiped := false
	err := d.factoryReset(ctx, func() error { wiped = true; return nil })
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("factoryReset must surface ctx err while the gate is held; got %v", err)
	}
	if wiped {
		t.Fatal("factoryReset must not wipe when it cannot acquire the gate")
	}
	if d.isResetting() {
		t.Fatal("factoryReset must not enter the reset generation when the acquire failed")
	}
	d.applySem.Release(1)

	// (2) Success: the wipe runs under the gate, the daemon stays in the terminal
	// reset generation, and the gate is RELEASED (so shutdown-time work can still
	// acquire it).
	wiped = false
	if err := d.factoryReset(context.Background(), func() error { wiped = true; return fakePendingWipe(t)() }); err != nil {
		t.Fatalf("factoryReset success: %v", err)
	}
	if !wiped {
		t.Fatal("factoryReset must run the wipe")
	}
	if !d.isResetting() {
		t.Fatal("factoryReset must enter the terminal reset generation on a successful wipe")
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("applySem must be released after a successful factoryReset; got %v", err)
	}
	d.applySem.Release(1)

	// (3) In the reset generation, a racing commit / HA-sync must be REJECTED
	// before it persists (which would re-create the erased .configdb SSOT). The
	// guard sits before any nil-store access, so these return cleanly.
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, errDaemonResetting) {
		t.Fatalf("commitAndApply must be rejected during a factory reset; got %v", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 1, peerSyncNever); !errors.Is(err, errDaemonResetting) {
		t.Fatalf("commitConfirmedAndApply must be rejected during a factory reset; got %v", err)
	}
	if _, err := d.syncAndApply(context.Background(), "", nil); !errors.Is(err, errDaemonResetting) {
		t.Fatalf("syncAndApply must be rejected during a factory reset; got %v", err)
	}
	// The central reconcile is also gated (defense-in-depth).
	if err := d.applyConfigLocked(context.Background(), &config.Config{}); !errors.Is(err, errDaemonResetting) {
		t.Fatalf("applyConfigLocked must be rejected during a factory reset; got %v", err)
	}
	// The periodic DHCP-lease IPsec rebind (swanctl PSK re-render) is gated too.
	if err := d.ipsecApplyForLeaseChange(&config.Config{}); !errors.Is(err, errDaemonResetting) {
		t.Fatalf("ipsecApplyForLeaseChange must be rejected during a factory reset; got %v", err)
	}
}

// factoryReset must FAIL CLOSED on a wipe error: exit the reset generation and
// release the gate so the half-reset box is recoverable and normal config work
// resumes (the SystemAction handler then reports the reset incomplete and does
// NOT stop the daemon).
func TestFactoryResetFailClosedClearsResetGeneration(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	wantErr := errors.New("wipe boom")
	if err := d.factoryReset(context.Background(), func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("factoryReset must surface the wipe error; got %v", err)
	}
	if d.isResetting() {
		t.Fatal("factoryReset must EXIT the reset generation on a failed wipe (fail-closed, recoverable)")
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("applySem must be released after a failed factoryReset; got %v", err)
	}
	d.applySem.Release(1)
}

func TestFactoryResetFailedWipeResumesFeedHistoryPersistence12170(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	oldPath := feedShrinkHistoryPath
	feedShrinkHistoryPath = filepath.Join(t.TempDir(), "state", "feed-shrink-history.json")
	t.Cleanup(func() { feedShrinkHistoryPath = oldPath })
	if err := os.MkdirAll(filepath.Dir(feedShrinkHistoryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	history := []byte(`[{"name":"stable-feed","count":64,"hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]`)
	if err := os.WriteFile(feedShrinkHistoryPath, history, 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.ensureFeedManager()
	t.Cleanup(d.feeds.StopAll)
	wantErr := errors.New("wipe failed")
	if err := d.factoryReset(context.Background(), func() error {
		if err := os.Remove(feedShrinkHistoryPath); err != nil {
			return err
		}
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("factoryReset error = %v, want %v", err, wantErr)
	}
	d.persistFeedShrinkHistory(d.feeds)
	records := readFeedShrinkHistory()
	if len(records) != 1 || records[0].Name != "stable-feed" || records[0].Count != 64 {
		t.Fatalf("failed wipe did not resume prior-tenant history persistence: %+v", records)
	}
}

func TestFactoryResetSuccessKeepsFeedHistoryFenceSticky12170(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	oldPath := feedShrinkHistoryPath
	feedShrinkHistoryPath = filepath.Join(t.TempDir(), "state", "feed-shrink-history.json")
	t.Cleanup(func() { feedShrinkHistoryPath = oldPath })
	if err := os.MkdirAll(filepath.Dir(feedShrinkHistoryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	history := []byte(`[{"name":"stable-feed","count":64,"hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]`)
	if err := os.WriteFile(feedShrinkHistoryPath, history, 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.ensureFeedManager()
	t.Cleanup(d.feeds.StopAll)
	if err := d.factoryReset(context.Background(), func() error {
		if err := os.Remove(feedShrinkHistoryPath); err != nil {
			return err
		}
		return fakePendingWipe(t)()
	}); err != nil {
		t.Fatalf("successful factoryReset: %v", err)
	}
	d.persistFeedShrinkHistory(d.feeds)
	if _, err := os.Stat(feedShrinkHistoryPath); !os.IsNotExist(err) {
		t.Fatalf("successful wipe must keep history fenced: %v", err)
	}
	busy := errors.New("zeroize: upgrade lock busy")
	if err := d.factoryReset(context.Background(), func() error { return busy }); !errors.Is(err, busy) {
		t.Fatalf("second factoryReset error = %v, want %v", err, busy)
	}
	d.persistFeedShrinkHistory(d.feeds)
	if _, err := os.Stat(feedShrinkHistoryPath); !os.IsNotExist(err) {
		t.Fatalf("failed re-entry lifted the successful wipe's history fence: %v", err)
	}
}

// #12616: a failed retry after a successful wipe must not clear the terminal
// reset generation. The first call wipes and returns nil (the caller would
// stop the daemon, but before shutdown a second call must stay fenced).
func TestFactoryResetFailedRetryAfterSuccessfulWipeKeepsTerminalGeneration(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	if err := d.factoryReset(context.Background(), func() error { return fakePendingWipe(t)() }); err != nil {
		t.Fatalf("successful factoryReset: %v", err)
	}
	if !d.isResetting() {
		t.Fatal("successful wipe must enter the terminal reset generation")
	}
	wantErr := errors.New("retry wipe busy")
	if err := d.factoryReset(context.Background(), func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("failed retry must surface the wipe error; got %v", err)
	}
	if !d.isResetting() {
		t.Fatal("failed retry after a successful wipe must not clear the terminal reset generation")
	}
}

// #12616: a failed wipe, then a successful retry, ends terminal.
func TestFactoryResetFailureThenSuccessEndsTerminal12616(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	wantErr := errors.New("first wipe boom")
	if err := d.factoryReset(context.Background(), func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("failed wipe must surface error; got %v", err)
	}
	if d.isResetting() {
		t.Fatal("first-attempt failed wipe must exit the reset generation")
	}
	if err := d.factoryReset(context.Background(), func() error { return fakePendingWipe(t)() }); err != nil {
		t.Fatalf("successful retry: %v", err)
	}
	if !d.isResetting() {
		t.Fatal("failure-then-success must end in the terminal reset generation")
	}
}
