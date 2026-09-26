package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// postPromoCancelDP is a RuntimeDataPlane whose ApplyConfig fires a supplied
// cancel func as a side effect — simulating a daemon stop (`systemctl stop
// xpfd`) arriving DURING the dataplane apply, i.e. AFTER Store.Commit already
// promoted the config but BEFORE the nft/login tail runs. Production passes
// context.Background() to d.dp.ApplyConfig, so the cancel targets the apply ctx
// carried by applyConfigLocked, which is then observed at the #2926 C3 boundary
// (after the dataplane apply, before the FRR reload).
type postPromoCancelDP struct {
	runtimeOnlyApplyTestDP
	cancel  func()
	applied bool
}

func (d *postPromoCancelDP) ApplyConfig(_ context.Context, _ *config.Config) (*dataplane.ApplyResult, error) {
	d.applied = true
	if d.cancel != nil {
		d.cancel() // daemon-stop arrives mid-apply (post-promotion)
	}
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint16{}}, nil
}

// TestPostPromotionCancelRunsHostAuthorizationCloseout is the #5643 (M35)
// fail-on-revert guard. A config apply that is cancelled at the #2926 C3
// boundary AFTER the dataplane apply (post-promotion daemon stop) must STILL run
// the nft host-authorization tail, so the durable config and the kernel nft
// state do not skew — otherwise a committed host-inbound/lo0 tightening is
// silently deferred for the entire intentional-stop window.
//
// The harness drives the REAL applyConfigLocked (no applyBodyForTest seam) with
// a dp whose ApplyConfig cancels the apply ctx, then asserts:
//   - the apply returns context.Canceled (it did bail at a #2926 boundary),
//   - the dataplane apply ran (dp.applied) — proving the cancel is
//     POST-promotion (past C2, at C3), not a pre-apply C1/C2 bail, and
//   - nftApplyPayload was invoked despite the cancel — proving the nft
//     host-authorization closeout ran, closing the skew.
//
// Fail-on-revert: remove the applyHostAuthorizationCloseout call from
// applyConfigLocked's cancellation branch and nftApplyPayload is never invoked
// (nftCalls==0) — the tail is skipped and the test goes RED.
func TestPostPromotionCancelRunsHostAuthorizationCloseout(t *testing.T) {
	installFakeNetworkctl(t)

	// Hermetic nftables: count every kernel-touching op through the netlink
	// installer seam (#6387 PR-3: applyLo0Filter / applyHostInboundFilter route
	// their install + table-delete through nftInstaller) instead of shelling out.
	orig := nftInstaller
	nftCalls := 0
	nftInstaller = &countingNftInstaller{calls: &nftCalls}
	defer func() { nftInstaller = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dp := &postPromoCancelDP{cancel: cancel}
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	err := d.applyConfigLocked(ctx, &config.Config{})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyConfigLocked = %v, want context.Canceled (the apply must bail at the C3 boundary)", err)
	}
	if !dp.applied {
		t.Fatalf("dataplane apply did not run: the cancel was not POST-promotion (C3), so the test is not exercising M35")
	}
	if nftCalls == 0 {
		t.Fatalf("nft host-authorization closeout did NOT run after a post-promotion cancel " +
			"(#5643/M35 skew): durable config committed but kernel nft state left stale")
	}
}

// rootAuthCloseoutHash is a well-formed crypt(3) SHA-512 hash distinct from the
// staged shadow field, so applyRootAuth → reconcileUserPassword takes the apply
// branch and pipes `root:<hash>` to the (faked) chpasswd — a privilege-free
// observable that applyRootAuth ran (writing root's authorized_keys instead
// would need a root-only chown that unprivileged test runs cannot perform).
const rootAuthCloseoutHash = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/" //nolint:gosec // test-only non-secret

// rootAuthCloseoutCfg builds a config whose system root-authentication sets a
// root encrypted-password, so applyRootAuth (the SOLE manager of root's durable
// credentials) has observable work in the closeout.
func rootAuthCloseoutCfg(hash string) *config.Config {
	cfg := &config.Config{}
	cfg.System.RootAuthentication = &config.RootAuthConfig{EncryptedPassword: config.Secret(hash)}
	return cfg
}

// TestPostPromotionCancelReconcilesRootAuth is the #5643 Gap A fail-on-revert
// guard: the host-authorization closeout must run applyRootAuth (tail step 13),
// not stop at applySSHConfig (step 12). applySSHConfig only writes the sshd
// PermitRootLogin drop-in; applyRootAuth is the SOLE manager of root's
// /etc/shadow password and /root/.ssh/authorized_keys, so omitting it leaves a
// committed root-credential change unenforced for the whole stop window.
//
// The dp cancels the apply ctx during ApplyConfig (post-promotion, C3); the test
// asserts applyRootAuth ran by observing chpasswd invoked with the committed
// root password hash.
//
// Fail-on-revert: remove `d.applyRootAuth(cfg)` from applyHostAuthorizationCloseout
// and chpasswd is never invoked (empty sentinel) — RED.
func TestPostPromotionCancelReconcilesRootAuth(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	// Redirect /etc/shadow, /etc/passwd, the provenance-marker dir, and
	// /root/.ssh to a throwaway tree (installs a fake chpasswd on PATH that
	// records its stdin to `sentinel`). Seed an OLD root hash so the committed
	// new hash is a genuine change (apply branch → chpasswd).
	sentinel, _ := stageRootAuthEnv(t, "$6$old5643salt$oldroot")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dp := &postPromoCancelDP{cancel: cancel}
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	err := d.applyConfigLocked(ctx, rootAuthCloseoutCfg(rootAuthCloseoutHash))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyConfigLocked = %v, want context.Canceled", err)
	}
	if !dp.applied {
		t.Fatalf("dataplane apply did not run: cancel was not post-promotion (C3)")
	}
	assertRootAuthApplied(t, sentinel, "#5643 Gap A: root credentials omitted from closeout")
}

// TestC1PostPromotionCancelRunsHostAuthorizationCloseout is the #5643 Gap B
// fail-on-revert guard: the C1 boundary (inside applyVRFReconcile, before the
// netlink phase) is post-promotion too — Store.Commit promotes UPSTREAM of
// applyConfigLocked — so a daemon-stop cancel landing at C1 must ALSO run the
// host-authorization closeout, not return context.Canceled bare.
//
// A pre-canceled ctx makes applyVRFReconcile bail at C1 before the dataplane
// apply (dp.applyCalls stays 0, proving the C1 path, distinct from the C2/C3
// test). The closeout is observed via both the nft calls and applyRootAuth
// invoking chpasswd with the committed root password.
//
// Fail-on-revert: revert the C1 return to a bare `return err` and neither the
// nft closeout nor applyRootAuth runs — RED.
func TestC1PostPromotionCancelRunsHostAuthorizationCloseout(t *testing.T) {
	installFakeNetworkctl(t)

	orig := nftInstaller
	nftCalls := 0
	nftInstaller = &countingNftInstaller{calls: &nftCalls}
	defer func() { nftInstaller = orig }()

	sentinel, _ := stageRootAuthEnv(t, "$6$old5643salt$oldroot")

	dp := &runtimeOnlyApplyTestDP{}
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled: applyVRFReconcile bails at C1 before the dataplane apply

	err := d.applyConfigLocked(ctx, rootAuthCloseoutCfg(rootAuthCloseoutHash))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyConfigLocked = %v, want context.Canceled", err)
	}
	if dp.applyCalls != 0 {
		t.Fatalf("dataplane apply ran (applyCalls=%d): the cancel did not bail at C1", dp.applyCalls)
	}
	if nftCalls == 0 {
		t.Fatalf("nft host-authorization closeout did NOT run after a C1 cancel (#5643 Gap B)")
	}
	assertRootAuthApplied(t, sentinel, "#5643 Gap B: C1 boundary not funneled through closeout")
}

// assertRootAuthApplied fails unless the faked chpasswd captured the committed
// root password hash — the privilege-free proof that applyRootAuth ran in the
// closeout.
func assertRootAuthApplied(t *testing.T, sentinel, why string) {
	t.Helper()
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("applyRootAuth did NOT run in the closeout (%s): chpasswd never "+
			"invoked (sentinel read err=%v)", why, err)
	}
	if !strings.Contains(string(got), rootAuthCloseoutHash) {
		t.Fatalf("applyRootAuth did NOT apply the committed root password (%s): "+
			"chpasswd stdin=%q, want it to contain %q", why, strings.TrimSpace(string(got)), rootAuthCloseoutHash)
	}
}

// TestLiveApplyRunsHostAuthorizationTailOnce guards against a double-apply or a
// regression on the normal (uncancelled) path: a live apply must run the nft
// tail exactly through the ordinary applyTailReconciles path (not the #5643
// closeout), and must NOT skip or double-run it. The closeout only fires on the
// cancellation branch, so a healthy apply's nft-call count is driven solely by
// the tail.
func TestLiveApplyRunsHostAuthorizationTailOnce(t *testing.T) {
	installFakeNetworkctl(t)

	orig := nftInstaller
	nftCalls := 0
	nftInstaller = &countingNftInstaller{calls: &nftCalls}
	defer func() { nftInstaller = orig }()

	dp := &runtimeOnlyApplyTestDP{}
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	if err := d.applyConfigLocked(context.Background(), &config.Config{}); err != nil {
		t.Fatalf("applyConfigLocked(live ctx) = %v, want nil", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("dataplane apply ran %d times, want 1", dp.applyCalls)
	}
	if nftCalls == 0 {
		t.Fatalf("nft host-authorization tail did not run on a healthy apply (nftCalls=0)")
	}
}
