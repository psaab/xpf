// Released-NIC RSS ownership must cover non-mlx5 interfaces (#15253, A80-02).
//
// Since #9040 the RSS reshape is capability-probed (`ethtool -x`), not
// gated on mlx5_core, so an i40e/ice NIC in the allowlist can carry a
// table xpfd concentrated. The #6801 claim/release set was still mlx5-
// gated: such a NIC was never claimed, and if it had been, the release
// path dropped its ownership without restoring. Both legs are pinned
// here; the coalescence leg (genuinely mlx5-only) is the control.
package daemon

import "testing"

func TestClaimNICTunableOwnershipCoversNonMlx515253(t *testing.T) {
	prior := newPriorHostTunables()
	execer := &fakeRSSExecutor{drivers: map[string]string{
		"ge-0-0-1": "i40e",
		"ge-0-0-2": mlx5Driver,
		"ge-0-0-3": "ice",
	}}
	claimNICTunableOwnership(prior, []string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-3", "lo"}, execer)
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-3"} {
		if _, ok := prior.rssOwned[iface]; !ok {
			t.Errorf("#15253: %s must be claimed as RSS-owned (capability-probed "+
				"apply set, not mlx5-only), got %v", iface, prior.rssOwned)
		}
	}
	if _, ok := prior.rssOwned["lo"]; ok {
		t.Error("#15253 control: lo must never be claimed")
	}
}

func TestReleaseRestoresNonMlx5RSS15253(t *testing.T) {
	prior := newPriorHostTunables()
	prior.claimRSSOwnership("ge-0-0-1")
	execer := &fakeRSSExecutor{drivers: map[string]string{"ge-0-0-1": "i40e"}}
	// Interface has left the allowlist (empty current, userspace-dp off).
	releaseUnboundNICTunables(prior, nil, false, execer)
	if callIndex(execer.calls, "-X", "ge-0-0-1") < 0 {
		t.Fatalf("#15253: released i40e NIC must get `ethtool -X default` restore, calls=%v", execer.calls)
	}
	if _, ok := prior.rssOwned["ge-0-0-1"]; ok {
		t.Error("#15253: ownership must be dropped after a successful restore")
	}
}

func TestReleaseDropsCoalescenceOnlyForNonMlx515253(t *testing.T) {
	prior := newPriorHostTunables()
	prior.claimRSSOwnership("ge-0-0-1")
	prior.mlx5Adaptive["ge-0-0-1"] = mlx5CoalesceState{adaptiveRX: true, rxUsecs: 42, txUsecs: 43}
	execer := &fakeRSSExecutor{drivers: map[string]string{"ge-0-0-1": "ice"}}
	releaseUnboundNICTunables(prior, nil, false, execer)
	if _, ok := prior.mlx5Adaptive["ge-0-0-1"]; ok {
		t.Error("#15253 control: coalescence ownership must be dropped for a non-mlx5 netdev")
	}
	if _, ok := prior.rssOwned["ge-0-0-1"]; ok {
		t.Error("#15253: RSS ownership must be restored then dropped, not retained")
	}
	if callIndex(execer.calls, "-C", "ge-0-0-1") >= 0 {
		t.Errorf("#15253 control: no ethtool -C coalescence restore on a non-mlx5 netdev, calls=%v", execer.calls)
	}
	if callIndex(execer.calls, "-X", "ge-0-0-1") < 0 {
		t.Errorf("#15253: RSS restore must still run on the non-mlx5 netdev, calls=%v", execer.calls)
	}
}
