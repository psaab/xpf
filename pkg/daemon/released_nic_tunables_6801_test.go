// Released-NIC tuning teardown tests (#6801).
//
// The defect these pin is invisible to any fixture whose allowlist never
// SHRINKS: every reconciler walks the current allowlist, so with a fixed
// set the teardown has nothing to do and deleting it changes nothing.
// Every case here therefore runs at least two reconciles and moves an
// interface OUT of the userspace-dp binding set between them.
//
// The pre-xpfd fixture deliberately uses rx-usecs 42 / tx-usecs 43 —
// values xpf never writes (it writes the operator's 8/8) — so a restore
// assertion cannot be satisfied by an apply that happened to run.
package daemon

import (
	"errors"
	"strings"
	"testing"
)

// mlx5CoalesceProbePreXpfd is an `ethtool -c` dump whose adaptive state
// and usecs are all distinct from anything xpf writes, so "restored to
// the capture" and "applied xpf's config" are never confusable.
const mlx5CoalesceProbePreXpfd = `Coalesce parameters for ge-0-0-1:
Adaptive RX: on  TX: on
stats-block-usecs: 0
sample-interval: 0
pkt-rate-low: 0
pkt-rate-high: 0

rx-usecs: 42
rx-frames: 128
rx-usecs-irq: 0
rx-frames-irq: 0

tx-usecs: 43
tx-frames: 128
tx-usecs-irq: 0
tx-frames-irq: 0
`

// errEthtoolDenied is a transient ethtool failure injected through
// fakeRSSExecutor.argvErr to exercise the retain-on-failure path.
var errEthtoolDenied = errors.New("transient ethtool failure (test)")

// twoNICExecer returns a fake whose ifaceA/ifaceB are both mlx5 NICs
// reporting the pre-xpfd coalescence dump above.
func twoNICExecer() *fakeRSSExecutor {
	return &fakeRSSExecutor{
		drivers: map[string]string{"ge-0-0-1": mlx5Driver, "ge-0-0-2": mlx5Driver},
		ethtoolC: map[string][]byte{
			"ge-0-0-1": []byte(mlx5CoalesceProbePreXpfd),
			"ge-0-0-2": []byte(mlx5CoalesceProbePreXpfd),
		},
	}
}

// callIndex returns the index of the first recorded ethtool argv whose
// verb is `verb` and whose target interface is `iface`, or -1.
func callIndex(calls [][]string, verb, iface string) int {
	for i, c := range calls {
		if len(c) >= 2 && c[0] == verb && c[1] == iface {
			return i
		}
	}
	return -1
}

// coalesceArgs flattens the key/value tail of an `ethtool -C` argv.
func coalesceArgs(c []string) map[string]string {
	kv := map[string]string{}
	for i := 2; i+1 < len(c); i += 2 {
		kv[c[i]] = c[i+1]
	}
	return kv
}

// findCoalesceRestore reports whether an `ethtool -C <iface>` call
// restoring the pre-xpfd capture (adaptive back on, rx 42 / tx 43) was
// issued. An apply writes adaptive off + 8/8, so this can only match a
// restore.
func findCoalesceRestore(calls [][]string, iface string) bool {
	for _, c := range calls {
		if len(c) < 2 || c[0] != "-C" || c[1] != iface {
			continue
		}
		kv := coalesceArgs(c)
		if kv["adaptive-rx"] == "on" && kv["adaptive-tx"] == "on" &&
			kv["rx-usecs"] == "42" && kv["tx-usecs"] == "43" {
			return true
		}
	}
	return false
}

// seedTwoBoundNICs runs the first reconcile with both NICs bound and
// asserts the ownership records that the teardown later consumes.
func seedTwoBoundNICs(t *testing.T) (*Daemon, *fakeHostFS, *fakeRSSExecutor) {
	t.Helper()
	d := &Daemon{}
	fs := newFakeHostFS()
	execer := twoNICExecer()

	d.applyStep0TunablesWith(
		true,  // userspaceDP
		false, // claimHostTunables — irrelevant, coalescence is not gated on it
		"", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1", "ge-0-0-2"},
		fs, execer,
	)

	if d.priorTunables == nil {
		t.Fatal("setup: priorTunables must exist after a userspace-dp apply")
	}
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		if _, ok := d.priorTunables.rssOwned[iface]; !ok {
			t.Fatalf("setup: %s must be claimed as RSS-owned, got %v", iface, d.priorTunables.rssOwned)
		}
		st, ok := d.priorTunables.mlx5Adaptive[iface]
		if !ok {
			t.Fatalf("setup: %s must have a coalescence capture, got %v", iface, d.priorTunables.mlx5Adaptive)
		}
		if !st.adaptiveRX || st.rxUsecs != 42 || st.txUsecs != 43 {
			t.Fatalf("setup: %s captured the wrong pre-xpfd state: %+v", iface, st)
		}
	}
	execer.calls = nil
	return d, fs, execer
}

// TestAllowlistShrink_ReleasesRSSAndCoalescence_6801 is the core case:
// {ge-0-0-1, ge-0-0-2} -> {ge-0-0-1}. The released NIC must get its
// default RSS table and its pre-xpfd coalescence back; the retained NIC
// must not be touched by the teardown; and ownership must move.
func TestAllowlistShrink_ReleasesRSSAndCoalescence_6801(t *testing.T) {
	d, fs, execer := seedTwoBoundNICs(t)

	// Second reconcile: ge-0-0-2 has left the userspace-dp binding set.
	d.applyStep0TunablesWith(
		true, false,
		"", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1"},
		fs, execer,
	)

	if callIndex(execer.calls, "-X", "ge-0-0-2") < 0 {
		t.Errorf("#6801: released ge-0-0-2 must get `ethtool -X ge-0-0-2 default`, calls=%v", execer.calls)
	}
	if !findCoalesceRestore(execer.calls, "ge-0-0-2") {
		t.Errorf("#6801: released ge-0-0-2 must be restored to its pre-xpfd coalescence "+
			"(adaptive on, rx 42 / tx 43), calls=%v", execer.calls)
	}

	// The RETAINED interface must not be released. `-X ge-0-0-1 default`
	// would hand back a NIC the dataplane is still bound to.
	if i := callIndex(execer.calls, "-X", "ge-0-0-1"); i >= 0 {
		t.Errorf("#6801: retained ge-0-0-1 must NOT be released, saw %v", execer.calls[i])
	}
	if findCoalesceRestore(execer.calls, "ge-0-0-1") {
		t.Errorf("#6801: retained ge-0-0-1 must NOT have its coalescence restored, calls=%v", execer.calls)
	}

	// Ownership moved: the released NIC is gone from both records, the
	// retained one is still held.
	if _, ok := d.priorTunables.rssOwned["ge-0-0-2"]; ok {
		t.Errorf("#6801: RSS ownership of the released NIC must be dropped, got %v", d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.mlx5Adaptive["ge-0-0-2"]; ok {
		t.Errorf("#6801: coalescence capture of the released NIC must be dropped, got %v",
			d.priorTunables.mlx5Adaptive)
	}
	if _, ok := d.priorTunables.rssOwned["ge-0-0-1"]; !ok {
		t.Errorf("#6801: retained NIC must stay RSS-owned, got %v", d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.mlx5Adaptive["ge-0-0-1"]; !ok {
		t.Errorf("#6801: retained NIC must keep its coalescence capture, got %v",
			d.priorTunables.mlx5Adaptive)
	}
}

// TestAllowlistShrink_TeardownRunsBeforeReapply_6801 pins the WIRING
// ORDER documented in applyStep0TunablesWith: the released NIC is handed
// back before xpfd re-applies tuning to the set it retains. The two sets
// are disjoint, so this is the documented device_map-style
// teardown-before-apply ordering rather than a correctness dependency —
// moving the release call below applyCoalescence reds this cell.
func TestAllowlistShrink_TeardownRunsBeforeReapply_6801(t *testing.T) {
	d, fs, execer := seedTwoBoundNICs(t)

	d.applyStep0TunablesWith(
		true, false,
		"", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1"},
		fs, execer,
	)

	release := callIndex(execer.calls, "-X", "ge-0-0-2")
	// The retained NIC's re-apply opens with its `ethtool -c` probe.
	reapply := callIndex(execer.calls, "-c", "ge-0-0-1")
	if release < 0 {
		t.Fatalf("#6801: no release call for ge-0-0-2, calls=%v", execer.calls)
	}
	if reapply < 0 {
		t.Fatalf("#6801: no re-apply probe for ge-0-0-1, calls=%v", execer.calls)
	}
	if release > reapply {
		t.Errorf("#6801: released-NIC teardown (index %d) must run BEFORE the retained-set "+
			"re-apply (index %d), calls=%v", release, reapply, execer.calls)
	}
}

// TestUserspaceDataplaneDisabled_WithdrawsFullPriorSet_6801: turning the
// userspace dataplane off at runtime is a withdrawal of the ENTIRE prior
// set, not a shrink. Both NICs must be handed back and both ownership
// records emptied.
func TestUserspaceDataplaneDisabled_WithdrawsFullPriorSet_6801(t *testing.T) {
	d, fs, execer := seedTwoBoundNICs(t)

	// userspaceDP=false is the config signal; the allowlist goes empty
	// with it, exactly as daemon_apply_tail.go derives it.
	d.applyStep0TunablesWith(
		false, false,
		"", 0,
		false, false, 8, 8,
		nil,
		fs, execer,
	)

	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		if callIndex(execer.calls, "-X", iface) < 0 {
			t.Errorf("#6801: %s must get its default RSS table back on userspace-dp disable, calls=%v",
				iface, execer.calls)
		}
		if !findCoalesceRestore(execer.calls, iface) {
			t.Errorf("#6801: %s must get its pre-xpfd coalescence back on userspace-dp disable, calls=%v",
				iface, execer.calls)
		}
	}
	if len(d.priorTunables.rssOwned) != 0 {
		t.Errorf("#6801: RSS ownership must be fully released, got %v", d.priorTunables.rssOwned)
	}
	if len(d.priorTunables.mlx5Adaptive) != 0 {
		t.Errorf("#6801: coalescence captures must be fully released, got %v", d.priorTunables.mlx5Adaptive)
	}
}

// TestEmptyAllowlistWhileUserspaceEnabled_RetainsOwnership_6801 is the
// middle row that separates a real withdrawal from a derivation
// failure. UserspaceBoundLinuxInterfaces degrades to nil when its
// snapshot build fails (#2514) and when its xfrm-device dump hard-fails
// (#12580, on a commit that otherwise succeeds), and the tunable step
// still runs on a commit whose dataplane apply failed — so "no names"
// must NOT mean "release everything". Ripping the tuning off a NIC the
// dataplane is still forwarding on costs a mid-traffic RX re-steer.
//
// Deleting the empty-allowlist guard reds this cell while every other
// cell in this file stays green.
func TestEmptyAllowlistWhileUserspaceEnabled_RetainsOwnership_6801(t *testing.T) {
	d, fs, execer := seedTwoBoundNICs(t)

	// userspace-dp is STILL enabled; only the derived list is empty.
	d.applyStep0TunablesWith(
		true, false,
		"", 0,
		false, false, 8, 8,
		nil,
		fs, execer,
	)

	for _, c := range execer.calls {
		if len(c) >= 1 && (c[0] == "-X" || c[0] == "-C") {
			t.Errorf("#6801: an empty allowlist under an ENABLED userspace-dp must not "+
				"release anything, saw %v", c)
		}
	}
	if len(d.priorTunables.rssOwned) != 2 {
		t.Errorf("#6801: RSS ownership must be retained, got %v", d.priorTunables.rssOwned)
	}
	if len(d.priorTunables.mlx5Adaptive) != 2 {
		t.Errorf("#6801: coalescence captures must be retained, got %v", d.priorTunables.mlx5Adaptive)
	}
}

// TestReleaseFailure_RetainsOwnershipAndRetries_6801 pins the #5114
// retry-debt shape on the new path: a failed restore write keeps the
// interface owned so the next reconcile — which recomputes the same
// `owned - current` set — retries it, and only a SUCCESSFUL restore
// releases ownership.
func TestReleaseFailure_RetainsOwnershipAndRetries_6801(t *testing.T) {
	d, fs, execer := seedTwoBoundNICs(t)

	// Both restores fail on the released NIC.
	execer.argvErr = map[string]argvErrSpec{
		"-X ge-0-0-2": {err: errEthtoolDenied},
		"-C ge-0-0-2": {err: errEthtoolDenied},
	}

	d.applyStep0TunablesWith(
		true, false, "", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1"},
		fs, execer,
	)

	if _, ok := d.priorTunables.rssOwned["ge-0-0-2"]; !ok {
		t.Errorf("#6801: a FAILED RSS restore must retain ownership as retry debt, got %v",
			d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.mlx5Adaptive["ge-0-0-2"]; !ok {
		t.Errorf("#6801: a FAILED coalescence restore must retain the capture as retry debt, got %v",
			d.priorTunables.mlx5Adaptive)
	}

	// Next reconcile with the same (still shrunk) allowlist: the debt is
	// retried and, on success, released.
	execer.argvErr = nil
	execer.calls = nil
	d.applyStep0TunablesWith(
		true, false, "", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1"},
		fs, execer,
	)

	if callIndex(execer.calls, "-X", "ge-0-0-2") < 0 {
		t.Errorf("#6801: retry must re-issue the RSS restore, calls=%v", execer.calls)
	}
	if !findCoalesceRestore(execer.calls, "ge-0-0-2") {
		t.Errorf("#6801: retry must re-issue the coalescence restore, calls=%v", execer.calls)
	}
	if _, ok := d.priorTunables.rssOwned["ge-0-0-2"]; ok {
		t.Errorf("#6801: a successful retry must release RSS ownership, got %v", d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.mlx5Adaptive["ge-0-0-2"]; ok {
		t.Errorf("#6801: a successful retry must release the coalescence capture, got %v",
			d.priorTunables.mlx5Adaptive)
	}
}

// TestReleasedNICGone_DropsOwnershipWithoutEthtool_6801: a released name
// whose driver can no longer be read (unplugged, renamed, or rebound --
// readDriver returns "") took its ring/coalescence configuration with
// it. Ownership must be dropped WITHOUT an ethtool call, so the retry
// debt cannot grow without bound on a NIC that can never accept the
// restore. RE-ANCHORED by #15253: a name that still reads as a real
// non-mlx5 driver is different -- xpfd may have reshaped it under the
// #9040 capability probe, so its RSS restore DOES run (see the 15253
// cells); only the vanished case drops without a call.
func TestReleasedNICGone_DropsOwnershipWithoutEthtool_6801(t *testing.T) {
	d, fs, execer := seedTwoBoundNICs(t)

	// The NIC vanished from sysfs between reconciles.
	delete(execer.drivers, "ge-0-0-2")

	d.applyStep0TunablesWith(
		true, false, "", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1"},
		fs, execer,
	)

	for _, c := range execer.calls {
		if strings.Contains(strings.Join(c, " "), "ge-0-0-2") {
			t.Errorf("#6801: no ethtool call may target a released non-mlx5 netdev, saw %v", c)
		}
	}
	if _, ok := d.priorTunables.rssOwned["ge-0-0-2"]; ok {
		t.Errorf("#6801: a vanished NIC must not accrue unbounded RSS retry debt, got %v",
			d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.mlx5Adaptive["ge-0-0-2"]; ok {
		t.Errorf("#6801: a vanished NIC must not accrue unbounded coalescence retry debt, got %v",
			d.priorTunables.mlx5Adaptive)
	}
}

// TestClaimNICTunableOwnership_SkipsNonMlx5_6801 pins the claim scope.
// RE-ANCHORED by #15253: since #9040 the RSS reconciler DOES touch
// non-mlx5 netdevs (capability-probed), so the original expectation --
// a non-mlx5 allowlist member must NOT be claimed -- was itself the
// stale-driver-guard defect. What survives is the narrower true
// contract: every allowlisted member is claimed (the potential-apply
// set), and `lo` is never claimed.
func TestClaimNICTunableOwnership_SkipsNonMlx5_6801(t *testing.T) {
	d := &Daemon{}
	fs := newFakeHostFS()
	execer := &fakeRSSExecutor{
		drivers: map[string]string{
			"ge-0-0-1": mlx5Driver,
			"ge-0-0-3": "virtio_net",
		},
		ethtoolC: map[string][]byte{"ge-0-0-1": []byte(mlx5CoalesceProbePreXpfd)},
	}

	d.applyStep0TunablesWith(
		true, false, "", 0,
		false, false, 8, 8,
		[]string{"ge-0-0-1", "ge-0-0-3", "lo"},
		fs, execer,
	)

	if _, ok := d.priorTunables.rssOwned["ge-0-0-1"]; !ok {
		t.Errorf("#6801: the mlx5 member must be claimed, got %v", d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.rssOwned["ge-0-0-3"]; !ok {
		t.Errorf("#15253: a non-mlx5 allowlist member MUST be claimed (capability-probed "+
			"apply set), got %v", d.priorTunables.rssOwned)
	}
	if _, ok := d.priorTunables.rssOwned["lo"]; ok {
		t.Errorf("#6801: lo must never be claimed, got %v", d.priorTunables.rssOwned)
	}
}

// TestReleasedNICTunableOwners_UnionsBothRecords_6801 pins the set
// algebra directly, including the case the two records disagree on: an
// `ethtool -c` probe that fails leaves an RSS claim with no coalescence
// capture, and that interface must still be released.
func TestReleasedNICTunableOwners_UnionsBothRecords_6801(t *testing.T) {
	prior := newPriorHostTunables()
	prior.claimRSSOwnership("rss-only")
	prior.claimRSSOwnership("both")
	prior.claimRSSOwnership("kept")
	prior.captureMlx5Coalesce("both", mlx5CoalesceState{rxUsecs: 42})
	prior.captureMlx5Coalesce("coalesce-only", mlx5CoalesceState{rxUsecs: 42})
	prior.captureMlx5Coalesce("kept", mlx5CoalesceState{rxUsecs: 42})

	got := releasedNICTunableOwners(prior, []string{"kept"})
	want := []string{"both", "coalesce-only", "rss-only"}
	if len(got) != len(want) {
		t.Fatalf("released set: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("released set must be deduplicated and sorted: want %v, got %v", want, got)
		}
	}
	if len(releasedNICTunableOwners(nil, nil)) != 0 {
		t.Error("a nil capture struct must yield no released interfaces")
	}
}
