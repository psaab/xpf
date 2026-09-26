package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stubPositionalRenameSeams points the POSITIONAL rename path's injectable
// seams (NIC inventory, rename, reload) at test doubles. Two present NICs so
// index 0 becomes fxp0 and index 1 becomes ge-0-0-0 — both differ from the
// kernel names, so phase 2 always attempts a rename.
func stubPositionalRenameSeams(t *testing.T, renameErr, reloadErr error) (renameCalls *int) {
	t.Helper()
	withTempLinkDir(t)

	// #7205: the enumeration seam now MODELS the effect of a rename rather
	// than returning a constant. It used to return the same two kernel names
	// forever, so a "successful" pass left the fake box still wearing enp5s0 /
	// enp6s0 — a rename that reports success and does not take effect, which is
	// exactly the state verifyPositionalNames exists to catch. With a constant
	// enumeration the success control could never distinguish a converged pass
	// from an inert one.
	live := []pciNIC{
		{name: "enp5s0", busAddr: "0000:05:00.0"},
		{name: "enp6s0", busAddr: "0000:06:00.0"},
	}
	savedEnum := enumeratePCINICsFn
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		out := make([]pciNIC, len(live))
		copy(out, live)
		return out, nil
	}
	t.Cleanup(func() { enumeratePCINICsFn = savedEnum })

	var rc int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		rc++
		if renameErr != nil {
			return renameErr
		}
		for i := range live {
			if live[i].name == from {
				live[i].name = to
				break
			}
		}
		return nil
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return reloadErr }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	return &rc
}

// TestEnumerateAndRenameInterfaces_RenameFailurePropagates_5842 is the #5842
// fail-on-revert for the POSITIONAL path, mirroring
// TestEnumerateAndRenameMapped_RenameFailurePropagates_4956 for the mapped one.
//
// enumerateAndRenameInterfaces returned nil unconditionally: renamePositional
// returned only a `changed bool` and swallowed every rename error into a WARN,
// writeLinkFile returned `false` for BOTH "unchanged" and "write failed", and
// the networkctl reload error was logged and dropped. A boot on which no NIC
// was renamed at all was reported to the caller as a successful naming pass.
//
// RED-on-revert: restore the final `return nil` (drop the errors.Join) and the
// error assertion fails.
func TestEnumerateAndRenameInterfaces_RenameFailurePropagates_5842(t *testing.T) {
	renameCalls := stubPositionalRenameSeams(t, fmt.Errorf("simulated rename failure"), nil)

	err := enumerateAndRenameInterfaces(0, false, 4, false, nil)
	if err == nil {
		t.Fatal("enumerateAndRenameInterfaces must return an error when a positional rename " +
			"fails, not launder it to nil — the caller cannot tell a converged boot from a " +
			"boot on which no NIC was renamed")
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename attempt; the fixture never reached the failing code")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("the error must name the failing step so an operator can act on it: %v", err)
	}
}

// TestEnumerateAndRenameInterfaces_ReloadFailurePropagates_5842 covers the
// distinct third laundering site. A reload failure is its own state: the .link
// files on disk are correct and the RUNNING interface names are not, which is
// exactly what a caller must not mistake for convergence.
func TestEnumerateAndRenameInterfaces_ReloadFailurePropagates_5842(t *testing.T) {
	stubPositionalRenameSeams(t, nil, fmt.Errorf("simulated reload failure"))

	err := enumerateAndRenameInterfaces(0, false, 4, false, nil)
	if err == nil {
		t.Fatal("a networkctl reload failure must propagate: the .link set is correct on disk " +
			"and the running names are not")
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Errorf("the error must name the reload step: %v", err)
	}
}

// TestEnumerateAndRenameInterfaces_SuccessReturnsNil is the negative control,
// and it is what stops the fix from being "always return an error". Without it
// a build that failed every boot would pass the two tests above.
func TestEnumerateAndRenameInterfaces_SuccessReturnsNil(t *testing.T) {
	renameCalls := stubPositionalRenameSeams(t, nil, nil)

	if err := enumerateAndRenameInterfaces(0, false, 4, false, nil); err != nil {
		t.Fatalf("a clean positional naming pass must return nil, got %v", err)
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename attempt; the fixture never reached the code under test")
	}
}

// TestConfigArrivalNamingKeepsRetryMarkerOnPositionalFailure_5842 verifies the
// reachable standalone config-arrival retry path. A failed positional naming
// pass must preserve emptyHANamingPending so a later accepted standalone config
// can retry; clustered config arrival is rejected by the topology preflight.
//
// RED-on-revert: launder the error again and the marker is consumed after a
// failed standalone naming pass.
func TestConfigArrivalNamingKeepsRetryMarkerOnPositionalFailure_5842(t *testing.T) {
	stubPositionalRenameSeams(t, fmt.Errorf("simulated rename failure"), nil)

	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"ge-0/0/0": {Name: "ge-0/0/0"}}

	if d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Error("maybeReapplyConfigArrivalNaming reported success on a boot where every rename failed")
	}
	if !d.emptyHANamingPending.Load() {
		t.Error("the standalone config-arrival retry marker was consumed even though naming did not converge")
	}
}

// TestConfigArrivalNamingConsumesRetryMarkerOnSuccess_5842 is the control for
// the test above. The marker MUST be consumed when naming converges, or the
// re-naming pass re-runs on every subsequent commit forever — so the fix is not
// satisfiable by simply never consuming it.
func TestConfigArrivalNamingConsumesRetryMarkerOnSuccess_5842(t *testing.T) {
	stubPositionalRenameSeams(t, nil, nil)

	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"ge-0/0/0": {Name: "ge-0/0/0"}}

	if !d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("a clean naming pass must report success")
	}
	if d.emptyHANamingPending.Load() {
		t.Error("the one-shot marker survived a SUCCESSFUL naming pass; the re-naming pass will " +
			"now re-run on every later commit")
	}
}

// TestWriteLinkFileDistinguishesUnchangedFromFailure_5842 pins the primitive
// that made the laundering possible. `false` used to mean BOTH "already
// correct, nothing to do" and "the write failed" — opposite facts under one
// value, so no caller could have reported the second even if it wanted to.
func TestWriteLinkFileDistinguishesUnchangedFromFailure_5842(t *testing.T) {
	withTempLinkDir(t)

	wrote, err := writeLinkFile("ge-0-0-3", "enp9s0")
	if err != nil || !wrote {
		t.Fatalf("first write = (%v, %v), want (true, nil)", wrote, err)
	}
	wrote, err = writeLinkFile("ge-0-0-3", "enp9s0")
	if err != nil || wrote {
		t.Fatalf("identical rewrite = (%v, %v), want (false, nil) — unchanged is not a failure",
			wrote, err)
	}

	// A write that cannot land must report an error, and must NOT be
	// indistinguishable from the unchanged case above. Point linkDir at a path
	// that is not a directory so the atomic write fails.
	saved := linkDir
	linkDir = saved + "/nonexistent-subdir"
	t.Cleanup(func() { linkDir = saved })

	wrote, err = writeLinkFile("ge-0-0-4", "enp10s0")
	if err == nil {
		t.Error("a failed .link write reported no error; it is indistinguishable from 'unchanged', " +
			"so the NIC comes up under its kernel name on the next boot with no signal")
	}
	if wrote {
		t.Error("a failed write reported changed")
	}
}

// TestPositionalNamingVerifiesLiveNames_7205 is the #7205 item-1 fail-on-revert.
//
// THE SEAM LIES: it reports success and does not rename. That is the whole
// defect — renamePositional reports what it ATTEMPTED, and before this nothing
// read the live names back, so a networkctl reload that partially applied, a
// udev race, or a NIC that vanished mid-pass left the box running under names
// the configuration does not reference WITH A CLEAN RETURN VALUE.
//
// Note what this can and cannot see. Positional mode has no stable identity to
// verify against — the positional index IS the identity — so this proves the
// intended name is worn, not that the right NIC wears it. Device-map mode has
// the identity half (a PCI match with a differing permanent MAC is refused);
// there is no positional equivalent, and pretending otherwise would be worse
// than the bounded check.
func TestPositionalNamingVerifiesLiveNames_7205(t *testing.T) {
	withTempLinkDir(t)

	// A constant enumeration: whatever is renamed, the live names never change.
	savedEnum := enumeratePCINICsFn
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{
			{name: "enp5s0", busAddr: "0000:05:00.0"},
			{name: "enp6s0", busAddr: "0000:06:00.0"},
		}, nil
	}
	t.Cleanup(func() { enumeratePCINICsFn = savedEnum })

	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { return nil } // reports success, does nothing
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	err := enumerateAndRenameInterfaces(0, false, 0, false, nil)
	if err == nil {
		t.Fatal("a naming pass whose renames all reported success but took no effect " +
			"returned nil. The box is running under kernel names the configuration does " +
			"not reference, and the caller has no way to know — this is the state #7205 " +
			"item 1 exists to report")
	}
	if !strings.Contains(err.Error(), "positional naming intended") {
		t.Errorf("the error does not name the live-vs-intended mismatch, so a reader "+
			"cannot tell this from an ordinary rename failure: %v", err)
	}
	// It must name BOTH mismatched NICs, not just the first. A verification that
	// stops at the first divergence under-reports exactly when the pass went
	// most wrong.
	for _, want := range []string{"fxp0", "ge-0-0-0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention intended name %q; a partial report "+
				"understates how far naming diverged: %v", want, err)
		}
	}
}

// CONTROL. A pass whose renames actually take effect must still report success,
// or the verification above is satisfiable by always failing.
func TestPositionalNamingVerificationPassesWhenRenamesTakeEffect_7205(t *testing.T) {
	stubPositionalRenameSeams(t, nil, nil)
	if err := enumerateAndRenameInterfaces(0, false, 0, false, nil); err != nil {
		t.Fatalf("a pass whose renames took effect must report success, got: %v", err)
	}
}

// The readback failing is UNKNOWN convergence, not confirmed convergence.
func TestPositionalNamingReportsAnUnreadableInterfaceList_7205(t *testing.T) {
	withTempLinkDir(t)
	calls := 0
	savedEnum := enumeratePCINICsFn
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		calls++
		if calls == 1 {
			// The first call is the pass's own enumeration; let it succeed so
			// the failure below is unambiguously the READBACK.
			return []pciNIC{{name: "fxp0", busAddr: "0000:05:00.0"}}, nil
		}
		return nil, fmt.Errorf("simulated sysfs read failure")
	}
	t.Cleanup(func() { enumeratePCINICsFn = savedEnum })

	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })
	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	err := enumerateAndRenameInterfaces(0, false, 0, false, nil)
	if err == nil {
		t.Fatal("an unreadable interface list means convergence is UNKNOWN, not " +
			"confirmed; returning nil is the fail-open this verification removes")
	}
	if !strings.Contains(err.Error(), "re-enumerate NICs") {
		t.Errorf("the error does not identify the readback as the failing step: %v", err)
	}
}
