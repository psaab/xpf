package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #6871 round 6: the link-cycle lease is renewed once per RETH member.
//
// The lease's TTL used to have to cover the WHOLE of step 2.6's rethToPhys loop,
// and no constant can: only a member that actually cycles re-arms the lease
// (PrepareLinkCycle takes it), so the exposure is the tail of members visited
// after the last cycling one; `reth-count` is operator-settable to 128
// (pkg/config/schema_chassis.go); and the per-member `ethtool -K rxvlan off` has
// a 20s hard ceiling (externalCommandTimeout 15s + the 5s WaitDelay in
// exec_timeout.go). Four wedging members in that tail already exceed a 60s TTL.
// Because rethToPhys is a Go MAP, which members land in that tail differs
// between runs — so the same config passes or fails at random, which is the
// worst shape a defect can have and the one a larger constant hides.
//
// The renewal lives in programRethMemberMAC rather than inline in the loop for
// the reason that function exists at all (see its doc comment): inline, it was
// reachable only through applyDataplaneAndHACore, which needs a live cluster
// manager, a wired dataplane, a networkd writer and real netlink members — so
// the only available guard would have been a structural canary, and a structural
// canary is satisfied by an assignment that is unreachable, shadowed or jumped
// over. Here the renewal is driven against the same fake link seam and fake
// dataplane the rest of the #5103 suite uses, and reth_hook_wired_5103_test.go
// separately pins that step 2.6 reaches the wrapper through exactly one
// programRethMemberMAC call site — which together is what makes "once per
// member" true rather than asserted.

// TestRethMemberMACRenewsTheLinkCycleLease_6871 is the fail-on-revert guard.
//
// It walks every outcome a member can have, because the whole point is that the
// renewal is NOT conditional on this member cycling: the member that keeps the
// lease alive for the loop's tail is precisely the one that did nothing.
//
// RED-on-revert: delete the `rt.Link().RenewLinkCycle()` call from
// programRethMemberMAC and every subtest fails at "did not renew the link-cycle
// lease".
func TestRethMemberMACRenewsTheLinkCycleLease_6871(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ops        rethLinkOps
		prepareErr error
	}{
		{
			// The common case, and the one that matters most: this member's MAC
			// went in live, so it neither takes nor re-arms a lease — but an
			// EARLIER member may have taken one, and this member's `ethtool`
			// still burns up to 20s of it.
			name: "live_set_no_cycle",
			ops:  newRecordingRethOps(t, new([]string), curMAC5103, false),
		},
		{
			name: "cycle_completed",
			ops:  newRecordingRethOps(t, new([]string), curMAC5103, true),
		},
		{
			// The member is gone by the time programRethMAC looks it up. Warn-only,
			// and it never reaches the cycle path — but the loop still walks on to
			// the next member, so the lease still needs the time.
			name: "ordinary_lookup_failure",
			ops:  ordinaryFailureRethOps(),
		},
		{
			name:       "cycle_aborted_on_failed_hook",
			ops:        newRecordingRethOps(t, new([]string), curMAC5103, true),
			prepareErr: errors.New("stop_workers: helper did not respond"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withRethOps(t, tc.ops)
			d, lc := newAbortRecoveryDaemon(tc.prepareErr)

			d.programRethMemberMAC("ge-0-0-1", virtMAC5103, nil, false, false)

			if lc.renewCalls != 1 {
				t.Errorf("RenewLinkCycle calls = %d, want 1: this member did not renew the "+
					"link-cycle lease. Every member's turn must touch it, including the ones "+
					"that need no cycle — those are exactly the members whose `ethtool` (20s "+
					"hard ceiling) burns down a lease an EARLIER member took. Without the "+
					"renewal the 60s TTL has to cover the whole rethToPhys loop, which "+
					"`reth-count` lets an operator take to 128 members, and the loop is a Go "+
					"map range so the overrun is nondeterministic between runs (#6871)",
					lc.renewCalls)
			}
		})
	}
}

// TestRethMemberMACSkipsRenewWithNoDataplane_6871 is the over-reach guard for the
// nil check. A daemon with no dataplane wired has no lease and no Link()
// controller to reach; renewing there would panic on the nil deref, which is a
// crash introduced by a fix for a suppression race.
//
// It stays GREEN under the revert above (no call, no panic either way), so it is
// a control rather than a restatement.
func TestRethMemberMACSkipsRenewWithNoDataplane_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))
	d := &Daemon{} // no dataplane published (#6743 cell empty)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("programRethMemberMAC panicked with no dataplane wired: %v. The "+
				"renewal must be behind the same nil guard as the rest of the dataplane "+
				"work on this path", r)
		}
	}()
	got, needRecovery, _ := d.programRethMemberMAC("ge-0-0-1", virtMAC5103, errPriorCommit5103, false, false)
	if got != errPriorCommit5103 {
		t.Errorf("commit error = %v, want the prior error passed through unchanged: with no "+
			"dataplane the hook never runs, so this member cannot enter the fail-closed "+
			"escalation class", got)
	}
	// The link really was cycled — the hook is a no-op with no dataplane, but
	// programRethMAC still takes its DOWN/set/UP fallback — so the recovery gate
	// must report that honestly. Step 2.6b2 is separately gated on a published dataplane,
	// which is what keeps an armed gate from dereferencing a nil dataplane.
	if !needRecovery {
		t.Error("the link WAS cycled, so the recovery gate must be armed; suppressing it " +
			"here would hide a real cycle from a caller that later acquires a dataplane")
	}
}

// #6871 round 7: the per-member renewal above is NOT enough on its own, and the
// round-6 comment that said it made the TTL bound "the interval between two
// consecutive members" was wrong.
//
// programRethMemberMAC renews at the end of the MAC SET. Everything expensive in
// a member's turn happens AFTER that: the `ethtool -K <if> rxvlan off` with its
// 20s hard ceiling, the child-netdev loop (one netlink round trip per VLAN
// sub-interface, cardinality operator-controlled), and — after the LAST member —
// step 2.6b's VIP/link-local reconcile followed by NotifyLinkCycle's own 1s NIC
// settle. So the interval between two consecutive renewals actually spanned
// member N's whole tail plus member N+1's MAC set, and the final tail ran to the
// release with no renewal in it at all.
//
// The two cells below bind the renewals that close those spans. Both extracted
// functions exist to BE bindable, for the same reason programRethMemberMAC does:
// inline in applyDataplaneAndHACore they were reachable only with a live cluster
// manager, a wired dataplane, a networkd writer and real netlink members, so the
// only available guard would have been a structural canary — and a structural
// canary is satisfied by a statement that is unreachable, shadowed or jumped
// over.

// stubRethTailCommand replaces the external-command seam for the duration of the
// test so the tail's `ethtool` does not shell out. The tail is warn-only on
// failure, so err drives which branch of the log runs, not whether the renewal
// does — which is the point of the failing subtest below.
func stubRethTailCommand(t *testing.T, err error) {
	t.Helper()
	prev := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, err }
	t.Cleanup(func() { runCommandTimeout = prev })
}

// TestRethMemberLinkTailRenewsTheLease_6871 binds the renewal that covers the
// per-member TAIL — the 20s-ceiling ethtool and the child-netdev loop.
//
// RED-on-revert: delete the `d.renewLinkCycleLease()` call at the end of
// finishRethMemberLinkTail and both subtests fail at "the member tail did not
// renew".
//
// The failing-ethtool subtest is the load-bearing one. A wedged ethtool is
// exactly the scenario the renewal exists for, so a renewal placed on the
// success branch of that log — or skipped when the command errors — would leave
// the lease burning down through the very case that motivated it.
func TestRethMemberLinkTailRenewsTheLease_6871(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ethtoolErr error
	}{
		{name: "ethtool_ok"},
		{name: "ethtool_failed", ethtoolErr: errors.New("ethtool: operation timed out")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRethTailCommand(t, tc.ethtoolErr)
			d, lc := newAbortRecoveryDaemon(nil)

			// A deliberately absent interface: every netlink helper in the tail
			// returns early on a failed lookup, so the cell exercises the tail's
			// control flow without needing a real netdev or privileges.
			d.finishRethMemberLinkTail("xpf6871-absent0", virtMAC5103, &config.InterfaceConfig{})

			if lc.renewCalls != 1 {
				t.Errorf("RenewLinkCycle calls = %d, want 1: the member tail did not renew the "+
					"link-cycle lease. This span holds the `ethtool -K rxvlan off` (20s hard "+
					"ceiling: externalCommandTimeout 15s plus the 5s WaitDelay) and one netlink "+
					"round trip per VLAN sub-interface, and the renewal in programRethMemberMAC "+
					"lands BEFORE all of it — so without this call the 60s TTL has to cover a "+
					"member's whole tail plus the next member's MAC set (#6871)", lc.renewCalls)
			}
		})
	}
}

// TestReconcileAfterRethLinkCycleRenewsTheLease_6871 binds the LAST renewal —
// the one covering the span that used to run unrenewed all the way into
// NotifyLinkCycle, which is what releases the lease.
//
// RED-on-revert: delete the `d.renewLinkCycleLease()` call at the end of
// reconcileAfterRethLinkCycle and both subtests fail.
//
// Both polarities are driven on purpose. Gating the renewal on
// needLinkCycleRecovery would look harmless and would skip exactly the abort
// path: programRethMACWithWorkerJoin returns linkCycled=false for a cycle that
// took a lease and then failed, so the gate would be false precisely when a
// lease is outstanding. Renewing unconditionally is safe because RenewLinkCycle
// cannot create one.
func TestReconcileAfterRethLinkCycleRenewsTheLease_6871(t *testing.T) {
	for _, needLinkCycleRecovery := range []bool{true, false} {
		name := "cycled"
		if !needLinkCycleRecovery {
			name = "no_cycle"
		}
		t.Run(name, func(t *testing.T) {
			d, lc := newAbortRecoveryDaemon(nil)

			// No cluster manager and no VRRP manager, so neither reconcile branch
			// has work to do; the renewal is the observable.
			d.reconcileAfterRethLinkCycle(&config.Config{}, needLinkCycleRecovery)

			if lc.renewCalls != 1 {
				t.Errorf("RenewLinkCycle calls = %d, want 1: the post-cycle VIP/link-local "+
					"reconcile did not renew the link-cycle lease. What follows it is "+
					"NotifyLinkCycle, which RELEASES the lease — so without this call "+
					"everything from the last member's MAC set through the ethtool, the "+
					"child-netdev loop, the per-RG VIP reconcile and NotifyLinkCycle's own 1s "+
					"NIC settle had to fit inside one TTL with no renewal anywhere in it "+
					"(#6871)", lc.renewCalls)
			}
		})
	}
}

// TestRethLeaseRenewalIsNilDataplaneSafe_6871 is the over-reach guard shared by
// both new call sites: they route through Daemon.renewLinkCycleLease, whose nil
// check is the only thing standing between a daemon with no dataplane wired and
// a panic on rt.Link().
//
// It stays GREEN under either revert above (no call, no panic either way).
func TestRethLeaseRenewalIsNilDataplaneSafe_6871(t *testing.T) {
	stubRethTailCommand(t, nil)
	d := &Daemon{} // no dataplane published (#6743 cell empty)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a renewal panicked with no dataplane wired: %v. Both new call sites must "+
				"be behind the same nil guard as the rest of the dataplane work on this path", r)
		}
	}()
	d.finishRethMemberLinkTail("xpf6871-absent0", virtMAC5103, &config.InterfaceConfig{})
	d.reconcileAfterRethLinkCycle(&config.Config{}, true)
	d.renewLinkCycleLease()
}

// #6871 round 6: the RETH MAC live-set failure reason must reach the journal.
//
// programRethMAC attempts the live MAC set first and falls back to a link cycle
// on ANY error. Before the previous round the error was scoped to the `if`, so
// the fallback log spent its one diagnostic slot asserting a driver capability
// it had not observed ("driver does not support live change") while DISCARDING
// the actual reason — and the fallback swallows it, so the journal was the only
// place it could have survived.
//
// The fix hoisted the error to liveSetErr and attached it to the log. Nothing
// bound that: deleting the `"err", liveSetErr` attribute left both pkg/daemon
// and pkg/dataplane/userspace green, so the recovered reason could be lost again
// silently. This is that binding.

// captureRethSlog installs a text handler over slog's default logger for the
// duration of the test and returns the buffer. Restores the previous default.
func captureRethSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// errLiveSetRefused6871 is deliberately distinctive: the assertion below matches
// its text, so a log line that merely mentions "err" cannot satisfy it.
var errLiveSetRefused6871 = errors.New("EBUSY: device busy, resource in use by another consumer")

// TestRethMACFallbackLogsTheLiveSetError_6871 is the fail-on-revert guard.
//
// RED-on-revert: drop the `"err", liveSetErr` attribute from the
// "RETH MAC live set refused" slog.Info in daemon_reth.go and this fails at
// "the live-set failure reason never reached the journal".
func TestRethMACFallbackLogsTheLiveSetError_6871(t *testing.T) {
	buf := captureRethSlog(t)

	var events []string
	ops := newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */)
	// Substitute a rejection reason of our own, keeping the fixture's event
	// recording intact. The assertion is then about THIS error travelling to the
	// journal, not about any error being present — a log line that happened to
	// carry some other text could not satisfy it.
	inner := ops.setHardwareAddr
	ops.setHardwareAddr = func(l netlink.Link, mac net.HardwareAddr) error {
		if err := inner(l, mac); err != nil {
			return errLiveSetRefused6871
		}
		return nil
	}
	withRethOps(t, ops)

	linkCycled, err := programRethMAC("ge-0-0-1", virtMAC5103, nil)
	if err != nil || !linkCycled {
		t.Fatalf("programRethMAC = (%v, %v), want (true, nil): the fixture must take the "+
			"fallback and complete it, or the log line under test never runs",
			linkCycled, err)
	}

	out := buf.String()
	if !strings.Contains(out, "RETH MAC live set refused") {
		t.Fatalf("the fallback log line is missing entirely; got:\n%s", out)
	}
	if !strings.Contains(out, "resource in use by another consumer") {
		t.Errorf("the live-set failure reason never reached the journal. programRethMAC "+
			"SWALLOWS this error — it falls back and returns nil — so the log is the only "+
			"place it survives, and without it an operator sees only that a cycle happened "+
			"and not why. A busy mlx5 VF and a driver with no ndo_set_mac_address produce "+
			"the same line, which is the wrong diagnosis on the hardware this cluster runs "+
			"(#6871). Log was:\n%s", out)
	}
	if strings.Contains(out, "does not support live change") {
		t.Errorf("the log still asserts a driver capability it did not observe. "+
			"dev_set_mac_address refuses a live set for a busy or absent device and for a "+
			"notifier rejection just as readily as for a missing ndo_set_mac_address, so "+
			"this branch cannot conclude anything about IFF_LIVE_ADDR_CHANGE. Log was:\n%s",
			out)
	}
}
