package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16458: fresh install on a never-committed foreign host ran
// `systemctl enable --now xpf-input-closed.service` (global input DROP) and
// xpfd, in bootstrap, then swapped in the lifeline guard: only
// em0/fab0/fab1/fxp0 plus the default-route NIC admitted, every other NIC
// (second sshd, virbr0 dnsmasq, BGP/OSPF, wg0/tailscale0) drops new inbound
// connections persistently across reboots; `docs/log/15147.md` calls the
// transit fence the only remaining foreign-host exposure — false for input.
// The input twin of #15147's ownership gate must release that leaf on an
// unowned host and keep it when xpf owns the host.
//
// The decisive arms mirror the issue acceptance: the GUARD harness is the
// production bootstrap entry (`installBootstrapInputProtection`, invoked by
// initManagers): GUARD=1 without the appliance marker removes the
// boot-installed early-input barrier (host-input stays reachable):
// CONNECTED. GUARD=1 with the appliance marker swaps in the lifeline guard
// exactly once and never removes: BLOCKED (the owned-appliance fail-closed
// posture). RED pre-fix: `installBootstrapInputProtection` called
// `ensureEarlyInputBootstrapGuard` unconditionally, so the unowned arm
// installed the lifeline guard (`install-lifeline`) instead of removing.
//
// Funded by the existing #10733 ownership predicate: the upstream fail-closed
// fences install BEFORE this gate — an unresolved input DROP that would
// fence a data address keeps the barrier standing even with GUARD=1.

// guardCell16458 wires a daemon whose production bootstrap entry runs against
// the recording fake installer. It returns the daemon and installer.
func guardCell16458(t *testing.T, owned bool) (*Daemon, *fakeNftInstaller) {
	t.Helper()
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	_ = v4
	_ = v6
	withApplianceMarker10733(t, owned)
	withTransitOwnershipRecord14620(t)
	store, _ := seedForeignStore15147(t)
	fake := withBarrierRecorder(t)
	d := &Daemon{store: store}
	d.bootstrapMode.Store(true)
	return d, fake
}

func countEarlyInputCalls(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if c == want {
			n++
		}
	}
	return n
}

// GUARD=1, unowned (no appliance marker, never-committed store): the
// production bootstrap entry must REMOVE the boot-installed barrier rather
// than swap in the lifeline guard. Models a pre-seeded `input-barrier close`
// install from the pre-networkd unit / the postinst `enable --now`.
func TestForeignHostRemovesBootInputBarrier16458(t *testing.T) {
	d, fake := guardCell16458(t, false)
	fake.earlyInputBarrierCalls = append(fake.earlyInputBarrierCalls, "install")

	d.installBootstrapInputProtection(false)

	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "remove"); got != 1 {
		t.Fatalf("boot-installed input barrier on a foreign never-committed host: remove calls = %d, want 1 (calls: %v)", got, fake.earlyInputBarrierCalls)
	}
	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "install-lifeline"); got != 0 {
		t.Fatalf("lifeline guard swapped in on a foreign never-committed host (calls: %v)", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("release must not mark the handoff done (the barrier is gone, input reopens)")
	}
	if d.EarlyInputGuardSwapFailed() {
		t.Fatal("release must not latch a guard-swap failure")
	}
}

// GUARD=1, owned (appliance marker present): the host is xpf's appliance —
// the barrier is xpf's fence and the lifeline guard keeps non-lifeline
// data ingress closed until the first commit (BLOCKED). Pre-fix unchanged
// behavior: swap in exactly one lifeline guard, never remove.
func TestApplianceHostSwapsLifelineGuard16458(t *testing.T) {
	withFailClosedBootDetect(t, func() (string, bool, error) { return "fxp0", true, nil })
	d, fake := guardCell16458(t, true)

	d.installBootstrapInputProtection(false)

	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "install-lifeline"); got != 1 {
		t.Fatalf("appliance bootstrap: install-lifeline calls = %d, want 1 (calls: %v)", got, fake.earlyInputBarrierCalls)
	}
	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "remove"); got != 0 {
		t.Fatalf("appliance host input barrier was removed as unowned (calls: %v)", fake.earlyInputBarrierCalls)
	}
}

// GUARD=1, owned: a committed store (no marker) owns the input posture the
// same way it owns the transit gate; the bar stays.
func TestCommittedHostKeepsInputBarrier16458(t *testing.T) {
	withFailClosedBootDetect(t, func() (string, bool, error) { return "fxp0", true, nil })
	withApplianceMarker10733(t, false)
	withTransitOwnershipRecord14620(t)
	fake := withBarrierRecorder(t)
	d := &Daemon{store: seedCommittedStore15147(t)}
	d.bootstrapMode.Store(true)

	d.installBootstrapInputProtection(false)

	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "install-lifeline"); got != 1 {
		t.Fatalf("committed bootstrap: install-lifeline calls = %d, want 1 (calls: %v)", got, fake.earlyInputBarrierCalls)
	}
	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "remove"); got != 0 {
		t.Fatalf("committed host input barrier was removed as unowned (calls: %v)", fake.earlyInputBarrierCalls)
	}
}

// GUARD=1, owned: a removal failure is observable: the failing remove is
// logged via the error return; here we record that the call IS ATTEMPTED
// (never silently skipped) so an operator can see the persistent drop.
func TestForeignInputBarrierReleaseAttemptsRemoval16458(t *testing.T) {
	d, fake := guardCell16458(t, false)
	fake.earlyInputBarrierRemove = func() error { return os.ErrPermission }

	d.installBootstrapInputProtection(false)

	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "remove"); got != 1 {
		t.Fatalf("unowned bootstrap: remove calls = %d, want 1 attempt even when it fails (calls: %v)", got, fake.earlyInputBarrierCalls)
	}
	if got := countEarlyInputCalls(fake.earlyInputBarrierCalls, "install-lifeline"); got != 0 {
		t.Fatalf("fell back to installing a lifeline guard after a failed release (calls: %v)", fake.earlyInputBarrierCalls)
	}
}

// The postinst must not inject the live DROP into a fresh install on an
// unmarked host: the GUARD line is gated on the appliance marker file OR a
// committed-config subtree under /etc/xpf/.configdb, so services on any
// NIC survive until the first commit. RED pre-fix: the injection ran
// unconditionally.
func TestPostinstSkipsLifelineGuardOnUnmarkedHost16458(t *testing.T) {
	root := transitBarrierRepoRoot9852(t)
	postinst := transitBarrierReadFile9852(t, filepath.Join(root, "debian", "xpf.postinst"))

	for _, want := range []string{
		`[ -e /etc/xpf/appliance ]`,
		`/etc/xpf/.configdb`,
		`GUARD`,
	} {
		if !strings.Contains(postinst, want) {
			t.Errorf("debian/xpf.postinst is missing %q", want)
		}
	}
}
