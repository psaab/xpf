package dataplane

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #4960. pkg/dataplane.CompileConfig mutates live host state in Phase 2
// (ensureVLANSubInterface / reconcileInterfaceAddresses) and there is no undo
// log. Steps that run AFTER it — preflightCheckIfindexCaps and
// attachUserspaceShimXDP in CompileUserspaceShim — can still fail, and when
// they do the daemon returns before publishing, so the Rust dataplane keeps its
// PREVIOUS snapshot while the host has already moved.
//
// The apply transaction that would undo it is a redesign and is tracked
// separately. What these tests hold is that the split state is REPORTED rather
// than silent: an operator who reads "attach failed" as "nothing happened" will
// roll back the config on a box that keeps the new VLANs and addresses.

// TestHostMutationAnnotatesAbortError is the reject-side proof. The wrapped
// error must preserve the original (errors.Is) — a caller classifying the
// failure must still see it — while adding what moved.
func TestHostMutationAnnotatesAbortError(t *testing.T) {
	base := errors.New("attach userspace shim XDP: operation not supported")
	r := &CompileResult{}
	r.markHostMutated("created VLAN sub-interface")
	r.markHostMutated("reconciled interface addresses")

	got := annotateHostMutationOnAbort(r, base)
	if got == nil {
		t.Fatal("annotation swallowed the error")
	}
	if !errors.Is(got, base) {
		t.Error("the original error must remain unwrappable — callers classify on it")
	}
	msg := got.Error()
	for _, want := range []string{
		"operation not supported",        // the real cause survives
		"created VLAN sub-interface",     // what moved
		"reconciled interface addresses", // and the other class
		"PREVIOUS snapshot",              // and what did NOT move
		"#4960",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("annotated error must contain %q, got: %s", want, msg)
		}
	}
}

// TestHostMutationSummaryIsStable pins the ordering. The message is assembled
// from a map; without the sort the two classes would swap between runs and an
// operator diffing two apply failures would see a spurious difference.
func TestHostMutationSummaryIsStable(t *testing.T) {
	first := ""
	for i := 0; i < 20; i++ {
		r := &CompileResult{}
		r.markHostMutated("reconciled interface addresses")
		r.markHostMutated("created VLAN sub-interface")
		r.markHostMutated("reconciled VLAN sub-interface addresses")
		got := r.hostMutationSummary()
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("summary is not order-stable: %q vs %q", first, got)
		}
	}
	if !strings.HasPrefix(first, "created VLAN sub-interface") {
		t.Errorf("want a sorted summary, got %q", first)
	}
}

// TestHostMutationNotAnnotatedWhenNothingMoved is the control that stops the
// annotation from becoming noise. A converged re-apply changes nothing; if it
// then fails for an unrelated reason, decorating that error with a warning
// about host state that did not move would train the operator to ignore the
// warning entirely — which costs the case where it is true.
//
// RED-on-revert: drop the `!result.HostMutated()` guard and this fails.
func TestHostMutationNotAnnotatedWhenNothingMoved(t *testing.T) {
	base := errors.New("attach userspace shim XDP: operation not supported")

	if got := annotateHostMutationOnAbort(&CompileResult{}, base); got.Error() != base.Error() {
		t.Errorf("an abort with no host mutation must return the error unchanged, got: %s", got)
	}
	if got := annotateHostMutationOnAbort(nil, base); got.Error() != base.Error() {
		t.Errorf("a nil result must return the error unchanged, got: %s", got)
	}
	// Success is never annotated: on the success path the snapshot IS published,
	// so the host and the dataplane agree and the mutation is the intended
	// outcome rather than a split state.
	r := &CompileResult{}
	r.markHostMutated("created VLAN sub-interface")
	if got := annotateHostMutationOnAbort(r, nil); got != nil {
		t.Errorf("a successful apply must not be annotated, got: %v", got)
	}
}

// TestHostMutationFlagIsPerRealChange is the discriminator proof, and it is the
// reason the mutation helpers were given return values at all.
//
// A flag meaning "this apply configured a VLAN" would be true on essentially
// every apply of a VLAN config, so the annotation would appear on every failure
// and say nothing. The flag has to VARY: set when the host actually changed,
// clear when the apply found it already correct.
//
// RED-on-revert: make markHostMutated unconditional at the call sites (i.e.
// ignore the helpers' return values) and the not-mutated case below flips.
func TestHostMutationFlagIsPerRealChange(t *testing.T) {
	converged := &CompileResult{}
	if converged.HostMutated() {
		t.Error("a compile that changed nothing reports a host mutation")
	}
	moved := &CompileResult{}
	moved.markHostMutated("created VLAN sub-interface")
	if !moved.HostMutated() {
		t.Error("a compile that created a link reports no host mutation")
	}
}

// TestHostMutationMarkIsIdempotentPerAction keeps the message readable: N
// interfaces reconciled in one apply are one classification, not N repetitions
// of the same phrase.
func TestHostMutationMarkIsIdempotentPerAction(t *testing.T) {
	r := &CompileResult{}
	for i := 0; i < 5; i++ {
		r.markHostMutated("reconciled interface addresses")
	}
	if n := strings.Count(r.hostMutationSummary(), "reconciled interface addresses"); n != 1 {
		t.Errorf("action repeated %d times in the summary, want 1: %q", n, r.hostMutationSummary())
	}
}

// TestPostMutationStepsAnnotateBothAbortPaths binds the WIRING. The unit tests
// above call annotateHostMutationOnAbort directly and would all pass on a build
// where CompileUserspaceShim never invokes it — the annotation present in the
// package and absent from every real apply.
//
// Both steps must annotate, not just the first: the reachable failure in
// practice is the SECOND one (attachUserspaceShimXDP on a driver that rejects
// the attach), so a fix that only covered the preflight would miss the case
// that actually happens.
//
// RED-on-revert: drop the annotateHostMutationOnAbort call from
// runPostMutationSteps and both subtests fail while every other test in this
// file still passes.
func TestPostMutationStepsAnnotateBothAbortPaths(t *testing.T) {
	mutated := func() *CompileResult {
		r := &CompileResult{}
		r.markHostMutated("created VLAN sub-interface")
		return r
	}
	boom := errors.New("operation not supported")
	ok := func(*CompileResult) error { return nil }
	fail := func(*CompileResult) error { return boom }

	t.Run("first step (preflight) fails", func(t *testing.T) {
		err := runPostMutationSteps(mutated(), fail, ok)
		if err == nil {
			t.Fatal("a failing first step returned no error")
		}
		if !strings.Contains(err.Error(), "#4960") {
			t.Errorf("a preflight abort after the host moved was not annotated: %v", err)
		}
	})

	t.Run("second step (attach) fails", func(t *testing.T) {
		err := runPostMutationSteps(mutated(), ok, fail)
		if err == nil {
			t.Fatal("a failing second step returned no error")
		}
		if !strings.Contains(err.Error(), "#4960") {
			t.Errorf("an ATTACH abort after the host moved was not annotated — this is the "+
				"reachable one: %v", err)
		}
	})

	t.Run("all steps succeed", func(t *testing.T) {
		if err := runPostMutationSteps(mutated(), ok, ok); err != nil {
			t.Errorf("a successful apply must return nil, got: %v", err)
		}
	})

	t.Run("later steps do not run after a failure", func(t *testing.T) {
		ran := false
		mark := func(*CompileResult) error { ran = true; return nil }
		if err := runPostMutationSteps(mutated(), fail, mark); err == nil {
			t.Fatal("expected an error")
		}
		if ran {
			t.Error("a step ran after an earlier one failed; the original control flow " +
				"short-circuits and must be preserved")
		}
	})
}

// mkAddr builds a netlink.Addr for the plan tests without touching a host.
func mkAddr(t *testing.T, cidr string) netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", cidr, err)
	}
	return *a
}

// TestPlanAddressReconcileConvergedIsEmpty is the DISCRIMINATOR proof, and it
// is the reason planAddressReconcile was split out of the netlink calls at all.
//
// The host-mutation flag is only worth reporting if it VARIES. If "this apply
// reconciled addresses" were recorded unconditionally it would be true on every
// apply of an addressed interface, the annotation would appear on every failure,
// and an operator would learn to ignore it — which costs the case where the host
// really did move.
//
// An interface already carrying exactly the desired set must produce an EMPTY
// plan, so reconcileInterfaceAddresses returns false and nothing is marked.
func TestPlanAddressReconcileConvergedIsEmpty(t *testing.T) {
	existing := []netlink.Addr{
		mkAddr(t, "10.0.0.1/24"),
		mkAddr(t, "2001:db8::1/64"),
	}
	desired := []string{"10.0.0.1/24", "2001:db8::1/64"}

	del, add, _ := planAddressReconcile(existing, desired, "ge-0/0/0")
	if len(del) != 0 || len(add) != 0 {
		t.Fatalf("a converged interface must plan no change, got del=%d add=%d", len(del), len(add))
	}
}

// TestPlanAddressReconcileDivergentPlansChange is the positive half of the
// discriminator: the plan must be non-empty when the host really is wrong, or
// "converged is empty" would be satisfiable by a function that always returns
// nothing.
func TestPlanAddressReconcileDivergentPlansChange(t *testing.T) {
	t.Run("missing address is added", func(t *testing.T) {
		del, add, _ := planAddressReconcile(nil, []string{"10.0.0.1/24"}, "ge-0/0/0")
		if len(add) != 1 || len(del) != 0 {
			t.Fatalf("want one add and no delete, got del=%d add=%d", len(del), len(add))
		}
	})
	t.Run("stale address is deleted", func(t *testing.T) {
		existing := []netlink.Addr{mkAddr(t, "192.0.2.5/24")}
		del, add, _ := planAddressReconcile(existing, []string{"10.0.0.1/24"}, "ge-0/0/0")
		if len(del) != 1 || len(add) != 1 {
			t.Fatalf("want one delete and one add, got del=%d add=%d", len(del), len(add))
		}
		if got := del[0].IPNet.String(); got != "192.0.2.5/24" {
			t.Errorf("wrong address planned for deletion: %s", got)
		}
	})
}

func TestPlanAddressReconcileRepairsDADFailedDesiredIPv6(t *testing.T) {
	existing := []netlink.Addr{mkAddr(t, "2001:db8::1/64")}
	existing[0].Flags = unix.IFA_F_DADFAILED

	del, add, dadfailedCount := planAddressReconcile(existing, []string{"2001:db8::1/64"}, "ge-0/0/0")
	if dadfailedCount != 1 {
		t.Errorf("dadfailed count = %d, want 1", dadfailedCount)
	}
	if len(del) != 1 || len(add) != 1 {
		t.Fatalf("want one delete and one add, got del=%d add=%d", len(del), len(add))
	}
	if got := del[0].IPNet.String(); got != "2001:db8::1/64" {
		t.Errorf("delete address = %s, want configured global IPv6", got)
	}
	if got := add[0].IPNet.String(); got != "2001:db8::1/64" {
		t.Errorf("add address = %s, want configured global IPv6", got)
	}
	if add[0].Flags&unix.IFA_F_NODAD == 0 {
		t.Errorf("re-added address flags = %#x, want IFA_F_NODAD", add[0].Flags)
	}
}

func TestPlanAddressReconcileLeavesTentativeDesiredIPv6Alone(t *testing.T) {
	existing := []netlink.Addr{mkAddr(t, "2001:db8::1/64")}
	existing[0].Flags = unix.IFA_F_TENTATIVE

	del, add, dadfailedCount := planAddressReconcile(existing, []string{"2001:db8::1/64"}, "ge-0/0/0")
	if len(del) != 0 || len(add) != 0 || dadfailedCount != 0 {
		t.Fatalf("tentative IPv6 is left to finish DAD, got del=%d add=%d count=%d",
			len(del), len(add), dadfailedCount)
	}
}

func TestPlanAddressReconcileIgnoresDADFlagsOnIPv4(t *testing.T) {
	existing := []netlink.Addr{mkAddr(t, "192.0.2.1/24")}
	existing[0].Flags = unix.IFA_F_DADFAILED

	del, add, dadfailedCount := planAddressReconcile(existing, []string{"192.0.2.1/24"}, "ge-0/0/0")
	if len(del) != 0 || len(add) != 0 || dadfailedCount != 0 {
		t.Fatalf("IPv4 DAD flags must not trigger a repair, got del=%d add=%d count=%d",
			len(del), len(add), dadfailedCount)
	}
}

// TestPlanAddressReconcileSkipsLinkLocal keeps the kernel's own addresses out of
// the delete set. A config that never mentions fe80::/10 must not cause the
// apply to tear down link-local connectivity — that would be a real outage
// manufactured by a diff the operator did not ask for.
func TestPlanAddressReconcileSkipsLinkLocal(t *testing.T) {
	existing := []netlink.Addr{
		mkAddr(t, "fe80::1/64"),
		mkAddr(t, "10.0.0.1/24"),
	}
	del, add, _ := planAddressReconcile(existing, []string{"10.0.0.1/24"}, "ge-0/0/0")
	if len(del) != 0 || len(add) != 0 {
		t.Fatalf("link-local must be left alone and the v4 address is already correct, "+
			"so the plan must be empty; got del=%d add=%d", len(del), len(add))
	}
}

// TestPlanAddressReconcileIsDeterministic pins the call ORDER. The adds are
// built from a map, so without the authored-order replay the netlink sequence
// would vary between runs — which makes an apply failure irreproducible and a
// log diff meaningless.
func TestPlanAddressReconcileIsDeterministic(t *testing.T) {
	desired := []string{"10.0.0.1/24", "10.0.1.1/24", "10.0.2.1/24", "2001:db8::1/64"}
	first := ""
	for i := 0; i < 20; i++ {
		_, add, _ := planAddressReconcile(nil, desired, "ge-0/0/0")
		got := ""
		for _, a := range add {
			got += a.IPNet.String() + ";"
		}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("add order varies between runs: %q vs %q", first, got)
		}
	}
	if first != "10.0.0.1/24;10.0.1.1/24;10.0.2.1/24;2001:db8::1/64;" {
		t.Errorf("adds must follow the authored order, got %q", first)
	}
}

// TestCompileZonesRecordsNoMutationWhenConverged binds the CALL SITE, which
// none of the tests above reach. They all drive CompileResult or
// planAddressReconcile directly, so every one of them passes on a build where
// mapZoneInterface calls markHostMutated UNCONDITIONALLY — ignoring the helper
// return values that exist precisely to make the flag vary. Measured: with the
// mark made unconditional, every other test in this file stays green.
//
// Reaching the reconcile call site needs an interface that actually exists —
// mapZoneInterface returns early with "interface not found" otherwise — so this
// uses `lo` and, crucially, passes as the DESIRED set exactly the addresses `lo`
// ALREADY has, read from the kernel first. The reconcile plan is therefore
// EMPTY by construction and no AddrAdd/AddrDel can run: the test cannot modify
// the host it runs on, whatever that host's lo looks like.
//
// RED-on-revert: make the markHostMutated call in mapZoneInterface's address
// branch unconditional and this fails.
func TestCompileZonesRecordsNoMutationWhenConverged(t *testing.T) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skipf("no loopback interface to drive the reconcile call site: %v", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Skipf("cannot read lo addresses: %v", err)
	}
	// Exactly what is already there — including link-local, which the plan
	// ignores anyway. An empty plan is the point.
	desired := make([]string, 0, len(addrs))
	for i := range addrs {
		desired = append(desired, addrs[i].IPNet.String())
	}
	if len(desired) == 0 {
		t.Skip("lo carries no addresses; nothing to converge against")
	}

	// Prove the premise before relying on it: if this plan were non-empty the
	// test would be about to mutate the host, and a green result would mean the
	// opposite of what it claims.
	if del, add, _ := planAddressReconcile(addrs, desired, "lo"); len(del) != 0 || len(add) != 0 {
		t.Fatalf("premise broken: the converged plan is not empty (del=%d add=%d); "+
			"refusing to run a test that would modify this host", len(del), len(add))
	}

	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zone-lo-4960": {Name: "zone-lo-4960", Interfaces: []string{"lo.0"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"lo": {Name: "lo", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: desired},
		}},
	}

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	if err := compileZones(hostMutationTestDP{}, cfg, result); err != nil {
		t.Fatalf("compileZones: %v", err)
	}

	if result.HostMutated() {
		t.Fatalf("compileZones recorded a host mutation (%q) on a CONVERGED interface where "+
			"the reconcile plan was empty and no netlink write ran. The flag is being set "+
			"unconditionally, so it says only 'an apply ran' — and the #4960 abort "+
			"annotation would then fire on every failure regardless of whether the host moved",
			result.hostMutationSummary())
	}
}

// hostMutationTestDP is a permissive DataPlane covering exactly the methods
// compileZones calls. It is deliberately its own type rather than a reuse of
// another test's fake: those carry tripwires that abort the compile early, and
// this test needs compileZones to run to COMPLETION — an early abort would
// record no mutation for the wrong reason and the assertion would be vacuous.
type hostMutationTestDP struct{ DataPlane }

func (hostMutationTestDP) SetZoneConfig(uint16, ZoneConfig) error { return nil }
func (hostMutationTestDP) SetZone(int, uint16, uint16, uint32, uint8, uint8, uint32) error {
	return nil
}
func (hostMutationTestDP) AddTxPort(int) error                     { return nil }
func (hostMutationTestDP) SetVlanIfaceInfo(int, int, uint16) error { return nil }
func (hostMutationTestDP) SetScreenConfig(uint32, ScreenConfig) error {
	return nil
}
func (hostMutationTestDP) DeleteStaleIfaceZone(map[IfaceZoneKey]bool) {}
func (hostMutationTestDP) DeleteStaleVlanIface(map[uint32]bool)       {}
func (hostMutationTestDP) ZeroStaleScreenConfigs(uint32)              {}
