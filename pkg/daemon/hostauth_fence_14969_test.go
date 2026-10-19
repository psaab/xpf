package daemon

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// hostauth_fence_14969_test.go — #14969 (D31-01).
//
// runHostAuthCloseoutOwners abandons an owner goroutine when the shared
// closeout budget expires. Since #14356 the closeout also runs on LIVE
// post-promotion aborts: it returns, applySem is released, and the
// abandoned owner — still holding its captured (stale) config — keeps
// writing kernel/OS host-auth state (the xpf_lo0 / xpf_hostinbound nft
// loads and every credential phase the #12169 live-config fences do not
// cover), potentially after and over a later commit.
//
// The fence is generational and checked at the syscall boundary (never
// a gate — gating would deadlock against the #12169 applySem settlement
// and break its "a new commit returns while an old revocation is
// blocked" contract): the runner runs each owner under its launch
// generation; every host-mutation seam (the runCommand* exec seam, the
// owner entries) refuses once a newer host-auth authority (a later
// closeout or a normal apply tail) advances the generation.
//
// Fail-on-revert: drop the checkHostAuthSeam14969 guard from
// runCommandStdinTimeout (or an owner entry) and the stale owner's
// post-supersession mutation lands — the tests below go RED.

// wedgedOwner14969 blocks until released, then attempts a host mutation
// through the REAL exec seam and records whether it landed.
func wedgedOwner14969(release <-chan struct{}, landed *atomic.Bool, seamErr *atomic.Value) func(*config.Config) error {
	return func(*config.Config) error {
		<-release
		_, err := runCommandTimeout("true")
		if err != nil {
			seamErr.Store(err)
			return err
		}
		landed.Store(true)
		return nil
	}
}

// TestAbandonedOwnerFencedAfterNewerAuthority14969 is the primary
// RED/GREEN gate: an owner abandoned by a budget-expired closeout must
// NOT land its stale host mutation after a newer host-auth authority
// (here: a second closeout invocation, the same advance a normal apply
// tail performs) has begun; while it is still the newest authority its
// mutation must land (control).
func TestAbandonedOwnerFencedAfterNewerAuthority14969(t *testing.T) {
	release := make(chan struct{})
	var landed atomic.Bool
	var seamErr atomic.Value
	owners := []hostAuthOwner{{"wedged", wedgedOwner14969(release, &landed, &seamErr)}}

	outcomes := runHostAuthCloseoutOwners(&config.Config{}, 30*time.Millisecond, owners)
	if len(outcomes) != 1 || !outcomes[0].timedOut {
		t.Fatalf("premise: outcomes = %+v, want the wedged owner timed out (abandoned)", outcomes)
	}

	// Control leg: no newer authority yet — releasing now, the owner's
	// seam must still pass and its mutation land. (This leg runs the
	// owner to completion, so the stale leg below uses a fresh owner.)
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for !landed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !landed.Load() {
		t.Fatal("control: the still-current owner's host mutation did not land — the fence refuses legitimate owners")
	}
	if v := seamErr.Load(); v != nil {
		t.Fatalf("control: current owner seam error = %v, want nil", v)
	}

	// Stale leg: abandon a second owner, then begin a newer authority.
	release2 := make(chan struct{})
	var landed2 atomic.Bool
	var seamErr2 atomic.Value
	owners2 := []hostAuthOwner{{"wedged-2", wedgedOwner14969(release2, &landed2, &seamErr2)}}
	outcomes = runHostAuthCloseoutOwners(&config.Config{}, 30*time.Millisecond, owners2)
	if len(outcomes) != 1 || !outcomes[0].timedOut {
		t.Fatalf("premise: outcomes = %+v, want the second owner timed out", outcomes)
	}
	beginHostAuthAuthority14969() // a newer apply tail / closeout begins
	close(release2)
	deadline = time.Now().Add(5 * time.Second)
	for seamErr2.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if landed2.Load() {
		t.Fatal("stale abandoned owner's host mutation LANDED after a newer host-auth authority began — the #14969 overwrite")
	}
	err, _ := seamErr2.Load().(error)
	if err == nil || !errors.Is(err, errHostAuthStaleOwner14969) {
		t.Fatalf("stale owner seam error = %v, want errHostAuthStaleOwner14969", err)
	}
}

// TestAbandonedNFTOwnerAbstains14969 drives the two nft owners' entry
// fence through the real owner functions a closeout launches: after a
// newer authority begins, a superseded owner goroutine calling
// applyLo0Filter / applyHostInboundFilter (the exact
// hostAuthCloseoutOwners entries) must abstain with the stale error
// before any render or installer call.
func TestAbandonedNFTOwnerAbstains14969(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(*Daemon, *config.Config) error
	}{
		{"lo0-filter", func(d *Daemon, c *config.Config) error { return d.applyLo0Filter(c) }},
		{"host-inbound-filter", func(d *Daemon, c *config.Config) error { return d.applyHostInboundFilter(c) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{}
			gen := beginHostAuthAuthority14969()
			release := make(chan struct{})
			errCh := make(chan error, 1)
			go func() {
				errCh <- runWithHostAuthGeneration14969(gen, func() error {
					<-release
					return tc.fn(d, &config.Config{})
				})
			}()
			beginHostAuthAuthority14969() // newer authority supersedes the owner
			close(release)
			select {
			case err := <-errCh:
				if err == nil || !errors.Is(err, errHostAuthStaleOwner14969) {
					t.Fatalf("superseded %s owner = %v, want errHostAuthStaleOwner14969 (abstain before install)", tc.name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("owner goroutine did not return")
			}

			// Control: the same owner under the CURRENT generation is
			// not refused by the fence (it proceeds to its normal
			// render/install path; an empty config tears down cleanly
			// against the fake-free default installer seam — we only
			// assert the fence did not refuse it).
			genNow := hostAuthGeneration14969.Load()
			err := runWithHostAuthGeneration14969(genNow, func() error {
				return tc.fn(d, &config.Config{})
			})
			if errors.Is(err, errHostAuthStaleOwner14969) {
				t.Fatalf("current-generation %s owner was refused by the fence: %v", tc.name, err)
			}
		})
	}
}

// TestHostAuthSeamNeverStaleWithoutCapture14969 pins the stand-alone
// contract: goroutines with no runner capture (direct reconciler tests,
// the normal tail, every non-host-auth exec caller) are never refused,
// even after authorities advance.
func TestHostAuthSeamNeverStaleWithoutCapture14969(t *testing.T) {
	beginHostAuthAuthority14969()
	beginHostAuthAuthority14969()
	if err := checkHostAuthSeam14969(); err != nil {
		t.Fatalf("uncaptured goroutine refused: %v", err)
	}
	if _, err := runCommandTimeout("true"); err != nil {
		t.Fatalf("uncaptured exec seam refused: %v", err)
	}
	// Owner entries on an uncaptured goroutine likewise proceed (the
	// empty config is a clean no-op for these reconcilers).
	d := &Daemon{}
	if err := d.applySystemLogin(&config.Config{}); err != nil {
		t.Fatalf("uncaptured applySystemLogin = %v, want nil", err)
	}
	if err := d.reconcileSudoers(&config.Config{}); err != nil && !strings.Contains(err.Error(), "sudoers") {
		t.Fatalf("uncaptured reconcileSudoers = %v, want nil or a genuine reconcile error", err)
	}
}
