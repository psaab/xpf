package networkd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// activationTailIfaces extends debtTestIfaces() so that EVERY dimension of the
// activation tail's `networkctl reconfigure` argv is observable (#6914).
//
// The tail selects interfaces with `!Unmanaged && !Disable && BondMaster == ""`
// and accumulates their names in slice order. An argv assertion can only catch
// a regression along an axis the fixture actually VARIES, so a fixture with one
// eligible interface pins almost nothing: with `[reconfigure trust0]` as the
// expectation, replacing the accumulated list with the literal "trust0",
// deleting the Unmanaged predicate, deleting the Disable predicate, or
// reversing the accumulation all still produce exactly that argv. Each of those
// was proven to exit 0 against the old fixture.
//
// So this carries FIVE interfaces covering all four exclusion/inclusion arms:
//
//	trust0  managed, non-member          -> INCLUDED (first)
//	lag0m   bond MEMBER                  -> excluded (reconfigure can eject it
//	                                        from its bond; its Bond= directive
//	                                        is picked up by the reload instead)
//	ext0    Unmanaged                    -> excluded
//	off0    Disable                      -> excluded
//	dmz0    managed, non-member          -> INCLUDED (second)
//
// Two included interfaces on either side of the excluded ones make BOTH
// accumulation and ORDER observable, which one eligible interface never can.
//
// Kept local to this file so the reload-debt tests that share debtTestIfaces()
// are unaffected — that fixture is deliberately minimal for its own purpose.
func activationTailIfaces() []InterfaceConfig {
	return append(debtTestIfaces(),
		InterfaceConfig{
			Name:       "lag0m",
			MACAddress: "52:54:00:aa:bb:dd",
			BondMaster: "ae0",
		},
		InterfaceConfig{
			Name:       "ext0",
			MACAddress: "52:54:00:aa:bb:ee",
			Unmanaged:  true,
		},
		InterfaceConfig{
			Name:       "off0",
			MACAddress: "52:54:00:aa:bb:ef",
			Disable:    true,
		},
		InterfaceConfig{
			Name:       "dmz0",
			MACAddress: "52:54:00:aa:bb:f0",
			Addresses:  []string{"10.0.30.10/24"},
		},
	)
}

// wantActivationTailArgv is the expected `networkctl reconfigure` argv for
// activationTailIfaces(), SPELLED OUT rather than derived by filtering the
// fixture with the production predicate. Deriving it would make the assertion
// true by construction: the same predicate would decide both the expectation
// and the behaviour, so deleting an arm would change them together and the test
// could never red.
//
// #9885 inserted `--` after the verb. That is not part of what this expectation
// is about — the INTERFACE SET is — but it is spelled out here too, for the same
// reason the names are: an expectation derived from the production argv builder
// would be true by construction. `--` ends option parsing, so a name beginning
// with `-` reaches networkctl as an OPERAND rather than as an option; without it
// a name like `--help` exits 0 without acting and leaves the whole batch
// unapplied while Apply reads success.
var wantActivationTailArgv = []string{"reconfigure", "--", "trust0", "dmz0"}

// rpFilterFixture points procSysNetRoot at a temp tree with the slow-path TUN's
// rp_filter pre-set to networkd's post-reload default, and returns a reader for
// it. restoreSlowPathRPFilter writes "0"; anything else means it never ran.
func rpFilterFixture(t *testing.T) func() string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "conf", "xpf-usp0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "conf", "all"), 0o755); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "conf", "all", "rp_filter"), []byte("0\n"), 0o644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	path := filepath.Join(dir, "rp_filter")
	write := func(v string) {
		if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	write("2")
	prev := procSysNetRoot
	procSysNetRoot = root
	t.Cleanup(func() { procSysNetRoot = prev })

	return func() string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading rp_filter: %v", err)
		}
		return string(b)
	}
}

// TestApplyTailSurvivesExternalDebtDischarge_5718 is the #5718 fold r4
// BLOCKER 2 fail-on-revert.
//
// Making the reload debt process-scoped (fold F2) was right for the reload
// itself — `networkctl reload` acts on one systemd-networkd, and pkg/daemon
// runs it too. But Apply's activation pass has a TAIL that only Apply can
// perform: the per-interface `networkctl reconfigure` that applies bond/VLAN
// addresses, and restoreSlowPathRPFilter, which re-disables rp_filter on the
// userspace dataplane's slow-path TUN after networkd resets it. Both sit behind
// `needReload`, which was computed purely from `changed || globalDebt`.
//
// The interleaving that loses them:
//
//  1. Apply writes files; its reload FAILS. It returns early — before the
//     tail — so no reconfigure debt is recorded either.
//  2. pkg/daemon runs a successful `networkctl reload` of its own (linksetup
//     rename, device-map, bootstrap) and reports it, clearing the GLOBAL debt.
//  3. Apply runs again with byte-identical files: changed==false, no reload
//     debt, no reconfigure debt -> the whole block is skipped, nil returned.
//
// The kernel did re-read the directory, so the reload obligation really was
// discharged — but the addresses were never reconfigured and rp_filter is left
// at networkd's default, silently dropping locally-originated traffic via the
// TUN. An external owner discharged a postcondition it cannot perform.
func TestApplyTailSurvivesExternalDebtDischarge_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	readRPFilter := rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reloadCalls, reconfigureCalls int
	// #5718 fold r6: record the whole argv, not just a count keyed on args[0].
	// `networkctl reconfigure` NAMES the interfaces it acts on, so counting
	// calls asserts only that the tail ran — a regression that reconfigured the
	// WRONG interfaces (an inverted bond-member exclusion, a stale list, the
	// wrong field read for the name) makes exactly the same number of calls and
	// the guard cannot fire. The argument list is the part that carries the
	// behaviour.
	var reconfigureArgs [][]string
	reloadFails := true
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		switch {
		case len(args) > 0 && args[0] == "reload":
			reloadCalls++
			if reloadFails {
				return errors.New("simulated networkctl reload failure")
			}
		case len(args) > 0 && args[0] == "reconfigure":
			reconfigureCalls++
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := activationTailIfaces()

	// 1) Apply writes the files; its reload fails, so it returns early and
	//    never reaches the tail.
	if err := m.Apply(ifaces); err == nil {
		t.Fatal("setup: Apply must fail when its reload fails")
	}
	if reconfigureCalls != 0 {
		t.Fatalf("setup: a failed reload returns before the tail, got %d reconfigure call(s)", reconfigureCalls)
	}
	if got := readRPFilter(); got != "2" {
		t.Fatalf("setup: rp_filter should still be networkd's default, got %q", got)
	}

	// 2) An external reload owner (pkg/daemon) succeeds and reports it. The
	//    kernel HAS now re-read the directory, so the global debt is genuinely
	//    discharged.
	NoteReloadResult(BeginReload(), nil)
	if reloadDebtOutstanding() {
		t.Fatal("setup: the external success must discharge the global reload debt")
	}

	// 3) The next Apply sees unchanged files and no global debt. It must still
	//    run ITS tail, because nobody else can.
	reloadFails = false
	reloadCalls, reconfigureCalls, reconfigureArgs = 0, 0, nil
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply should succeed: %v", err)
	}

	// The tail must reconfigure the interfaces this Apply actually wrote files
	// for, and ONLY those. The fixture carries a bond MEMBER alongside the
	// managed interface precisely so the exclusion at networkd.go:461 is load
	// bearing here: `networkctl reconfigure` on a bond member can eject it from
	// its bond, so the member must not appear. With a single-interface fixture
	// this assertion could not tell an intact exclusion from a deleted one —
	// dropping the check would have produced the same one-element argv, and an
	// INVERTED predicate would have produced zero calls, which the old
	// count-only assertion already caught. The member is what distinguishes
	// them.
	//
	// Spelled out rather than derived — deriving it by filtering the fixture
	// with the production predicate would be circular. (Hardcoding is not the
	// only non-circular option; `[]string{"reconfigure", ifaces[0].Name}` would
	// also work. It is simply the clearest.)
	wantArgs := wantActivationTailArgv
	if len(reconfigureArgs) != 1 || !slices.Equal(reconfigureArgs[0], wantArgs) {
		t.Fatalf("the activation tail must run %v exactly once; got %v. An address "+
			"application that names the wrong interfaces leaves the real ones unapplied "+
			"while still making the call the count-only assertion was watching for",
			wantArgs, reconfigureArgs)
	}

	if reconfigureCalls == 0 {
		t.Fatal("Apply skipped `networkctl reconfigure` after an EXTERNAL owner discharged " +
			"the global reload debt. Apply's own reload had failed, so the tail never ran " +
			"and no reconfigure debt was recorded; the external reload cleared the only " +
			"remaining signal. Bond and VLAN addresses are never applied and Apply reports " +
			"success (#5718 fold r4 BLOCKER 2)")
	}
	if got := readRPFilter(); got != "0" {
		t.Fatalf("Apply left rp_filter on the slow-path TUN at %q, not \"0\". networkd's "+
			"reload resets it to the default, and restoreSlowPathRPFilter is the only thing "+
			"that puts it back — it sits behind the same gate the external discharge "+
			"skipped, so locally-originated traffic via the TUN stays dropped", got)
	}
}

// TestApplyTailNotRepeatedOnceComplete_5718 is the scope control: the
// Manager-scoped obligation must be discharged by its own completed pass, not
// become a latch that re-runs the tail on every subsequent Apply.
func TestApplyTailNotRepeatedOnceComplete_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reloadCalls, reconfigureCalls int
	var reconfigureArgs [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		switch {
		case len(args) > 0 && args[0] == "reload":
			reloadCalls++
		case len(args) > 0 && args[0] == "reconfigure":
			reconfigureCalls++
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := activationTailIfaces()

	// A clean first Apply completes its tail.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if reloadCalls != 1 || reconfigureCalls != 1 {
		t.Fatalf("first Apply should reload once and reconfigure once, got %d/%d",
			reloadCalls, reconfigureCalls)
	}
	// Same reasoning as TestApplyTailSurvivesExternalDebtDischarge_5718: this
	// test's subject is repetition, so the call COUNT is load-bearing here —
	// but a count alone still cannot see a tail that runs the right number of
	// times against the wrong interfaces.
	if want := wantActivationTailArgv; !slices.Equal(reconfigureArgs[0], want) {
		t.Fatalf("first Apply ran %v, want %v", reconfigureArgs[0], want)
	}

	// An identical Apply has nothing to do: files unchanged, no global debt,
	// no reconfigure debt, and the previous pass completed its tail.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply: %v", err)
	}
	if reloadCalls != 1 || reconfigureCalls != 1 {
		t.Fatalf("a completed activation pass must not leave the Manager owing its tail "+
			"forever; steady-state Apply re-ran networkctl (reload=%d reconfigure=%d, want 1/1)",
			reloadCalls, reconfigureCalls)
	}
}

// #5718 fold r7 BLOCKER 1 FAIL-ON-REVERT: the write/remove-error branch owes
// this Manager's activation tail, and before the fix it NEVER ARMED it — the
// sole `activationPending = true` assignment lived in the success path, which
// that branch returns before reaching. Not "skipped": never armed.
//
// The distinction is what makes it reachable. The branch DOES arm the GLOBAL
// reload debt, and the global debt can be discharged by any reload owner — a
// device-map teardown that removes the offending stale marker and reloads
// successfully (pkg/daemon/linksetup.go) clears it while performing neither
// tail operation. The byte-identical Apply that follows then sees no change, no
// global debt, no reconfigure debt and no activation debt, and returns SUCCESS
// having run neither `networkctl reconfigure` nor `restoreSlowPathRPFilter` —
// bond/VLAN addresses unapplied, and the slow-path TUN's rp_filter left at the
// reload default of 2, which silently drops locally-originated traffic.
//
// The sequence below is that production sequence, with the external reload
// modelled by the same NoteReloadResult(BeginReload(), nil) the daemon helper
// calls.
//
// RED on revert: remove the `m.activationPending = true` arm from the
// write/remove-error branch in Apply and this fails with
// `Manager-only activation tail was lost: reconfigure=0 rp_filter="2"`.
func TestApplyErrorBranchArmsActivationTail_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	readRPFilter := rpFilterFixture(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	// A non-empty directory at a stale path makes os.Remove fail while every
	// desired file still writes, which is what forces Apply's partial-write /
	// remove-error branch rather than an outright abort.
	stale := filepath.Join(dir, filePrefix+"retired.link")
	if err := os.Mkdir(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(stale, "busy")
	if err := os.WriteFile(child, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	reloadFails := true
	var reconfigureCalls int
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reload" && reloadFails {
			return errors.New("simulated reload failure")
		}
		if len(args) > 0 && args[0] == "reconfigure" {
			reconfigureCalls++
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := activationTailIfaces()
	if err := m.Apply(ifaces); err == nil {
		t.Fatal("setup: Apply must fail on the unremovable stale path, or this " +
			"test is not exercising the error branch at all")
	}
	if !reloadDebtOutstanding() {
		t.Fatal("setup: the failed reload must arm the global reload debt")
	}

	// The daemon's next pre-Apply teardown resolves the stale removal and
	// reloads the shared networkd instance successfully. That discharges the
	// GLOBAL debt without doing either Manager tail operation.
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stale); err != nil {
		t.Fatal(err)
	}
	NoteReloadResult(BeginReload(), nil)
	if reloadDebtOutstanding() {
		t.Fatal("setup: an external successful reload must discharge the global debt — " +
			"if it does not, the retry below is driven by the global debt and this " +
			"test passes without the Manager-local arm existing at all")
	}

	reloadFails = false
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if reconfigureCalls == 0 || readRPFilter() != "0" {
		t.Fatalf("Manager-only activation tail was lost: reconfigure=%d rp_filter=%q",
			reconfigureCalls, readRPFilter())
	}
}

// OVER-REACH GUARD for the arm above, GREEN under the revert: an Apply that
// SUCCEEDS must still leave no activation debt behind. Arming the flag in the
// error branch must not leak into the ordinary path — a Manager that ends every
// Apply owing a tail would re-run reload+reconfigure on every subsequent commit
// forever, which is the #4954 debt machinery inverted into a permanent cost.
func TestApplySuccessLeavesNoActivationDebt_5718(t *testing.T) {
	resetReloadDebtForTest(t)
	_ = rpFilterFixture(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	orig := runNetworkctl
	runNetworkctl = func(args ...string) error { return nil }
	t.Cleanup(func() { runNetworkctl = orig })

	if err := m.Apply(activationTailIfaces()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	m.mu.Lock()
	pending := m.activationPending
	m.mu.Unlock()
	if pending {
		t.Fatal("a fully successful Apply must clear activationPending — the error " +
			"branch's arm must not leak into the success path")
	}
	if reloadDebtOutstanding() {
		t.Fatal("a fully successful Apply must leave no global reload debt")
	}
}
