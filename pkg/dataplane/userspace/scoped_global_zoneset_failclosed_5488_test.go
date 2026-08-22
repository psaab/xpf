// #5488 (F7): the required-protocol gate's fail-closed action is to DISARM the
// helper. When that disarm itself FAILS the helper stays ARMED on its
// previous-good Rust snapshot — and on the publish paths whose classifier BPF
// maps were already mutated IN PLACE (Compile's samePlanRefresh,
// syncSnapshotLocked unconditionally) the XDP shim is then redirecting transit
// to XSK against maps a generation AHEAD of the snapshot the helper is
// enforcing. That is the same "fail-OPEN security/availability mismatch"
// failClosedUserspaceCtrlMapLocked was introduced for in #4959; before this fix
// nothing drove userspace_ctrl.Enabled to 0 on the gate's disarm-error branch.
//
// The #5488 protocol bump is what makes this reachable in practice: every
// helper built before this PR reports a pre-v4 ConfigSnapshotProtocolVersion,
// so a multi-zone scoped global commit takes the gate on all of them.
//
// FAIL-ON-REVERT: dropping the failClosedUserspaceCtrlMapLocked call from
// disarmSnapshotProtocolFailClosedLocked (i.e. returning `joined` in both
// branches) leaves ctrl at Enabled=1 after a failed disarm, so
// TestSnapshotProtocolDisarmFailureFailsClosed5488/maps_mutated_in_place_disables_ctrl
// goes RED on its "ctrl.Enabled must be 0" assertion.
package userspace

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
)

// injectClassifierMaps5488 injects the ingress-iface / local-address /
// interface-NAT classifier maps that applyHelperStatusLocked reconciles, so a
// SUCCESSFUL disarm really completes instead of erroring out on a missing map.
func injectClassifierMaps5488(t *testing.T, m *Manager) {
	t.Helper()
	v6KeySize := uint32(unsafe.Sizeof(userspaceLocalV6Key{}))
	for _, spec := range []struct {
		name    string
		keySize uint32
	}{
		{mapNameUserspaceIngressIfaces, 4},
		{mapNameUserspaceLocalV4, 4},
		{mapNameUserspaceLocalV6, v6KeySize},
		{mapNameUserspaceInterfaceNATv4, 4},
		{mapNameUserspaceInterfaceNATv6, v6KeySize},
	} {
		bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    spec.keySize,
			ValueSize:  1,
			MaxEntries: 64,
		})
		if err != nil {
			skipIfBPFMapUnavailable(t, "new "+spec.name+" map", err)
		}
		t.Cleanup(func() { bpfMap.Close() })
		injectShimMap(t, m.bpfShim, spec.name, bpfMap)
	}
}

// newProtocolGateFailClosedManager5488 builds a Manager wired to a control
// socket, with a real userspace_ctrl map seeded Enabled=1 — the post-same-plan-
// refresh state: classifier maps already mutated in place, ctrl left enabled.
func newProtocolGateFailClosedManager5488(t *testing.T) (*Manager, *ebpf.Map, *ConfigSnapshot, string) {
	t.Helper()
	// A SHORT temp-dir prefix (not t.TempDir(), whose long sub-test name would
	// push the AF_UNIX path past the 108-byte sun_path limit -> "bind: invalid
	// argument"). Honors TMPDIR (run with TMPDIR=/tmp).
	dir, err := os.MkdirTemp("", "x5488")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	// A pre-v4 helper: the #5488 gate fires for a multi-zone scoped global.
	m.lastStatus.ConfigSnapshotProtocolVersion = preV4SnapshotProtocolVersion

	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	// applyHelperStatusLocked (run by a SUCCESSFUL disarm) reconciles the whole
	// classifier map set. Inject all of them, or the "successful disarm" branch
	// would fail its status sync and take the FAILED-disarm path instead —
	// silently turning that sub-test into a duplicate of the first one.
	injectClassifierMaps5488(t, m)

	enabled := userspaceCtrlValue{
		Enabled:         1,
		MetadataVersion: userspaceMetadataVersion,
		Workers:         4,
		QueueCount:      4,
	}
	if err := ctrlMap.Update(uint32(0), enabled, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl Enabled=1: %v", err)
	}

	cfg := multiZoneScopedGlobalDenyConfig()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return m, ctrlMap, snap, controlSock
}

// gateErr5488 returns the real gate error for a multi-zone scoped global against
// the manager's (pre-v4) helper, so the test drives the production predicate
// rather than a hand-rolled stand-in.
func gateErr5488(t *testing.T, m *Manager) error {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, multiZoneScopedGlobalDenyConfig()))
	if !errors.Is(err, ErrScopedGlobalZoneSetProtocolIncompatible) {
		t.Fatalf("precondition: gate error = %v, want ErrScopedGlobalZoneSetProtocolIncompatible", err)
	}
	return err
}

func TestSnapshotProtocolDisarmFailureFailsClosed5488(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	// Core contract: gate fires + disarm FAILS + maps were mutated in place
	// => ctrl must be driven to 0, and the commit must still abort.
	t.Run("maps_mutated_in_place_disables_ctrl", func(t *testing.T) {
		m, ctrlMap, snap, controlSock := newProtocolGateFailClosedManager5488(t)
		gateErr := gateErr5488(t, m)
		// The helper answers the set_forwarding_state disarm with OK:false, so
		// disarmSnapshotProtocolFailureLocked returns an error and the helper
		// stays ARMED on its previous-good snapshot.
		startArmControlServerReject(t, controlSock, 1)

		if got := readCtrlEnabled4959(t, ctrlMap); got != 1 {
			t.Fatalf("precondition: ctrl.Enabled = %d, want 1 (running enabled firewall)", got)
		}

		m.mu.Lock()
		err := m.disarmSnapshotProtocolFailClosedLocked(snap, gateErr, true /*mapsMutatedInPlace*/)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("disarmSnapshotProtocolFailClosedLocked must return an error when the disarm fails")
		}
		if got := readCtrlEnabled4959(t, ctrlMap); got != 0 {
			t.Fatalf("ctrl.Enabled = %d after a FAILED protocol-gate disarm, want 0 (fail closed); "+
				"the helper is still armed on its previous-good snapshot while the classifier maps "+
				"were mutated in place to the new plan, so a still-enabled shim redirects transit "+
				"to XSK against maps a generation ahead of the applied snapshot (#5488 F7 / #4959 "+
				"fail-open)", got)
		}
		// The fail-closed wrap must NOT swallow the sentinel: a commit that hits
		// a required-protocol gate must ABORT, never be promoted (#2138).
		if !IsRequiredProtocolGateError(err) {
			t.Fatalf("IsRequiredProtocolGateError(%v) = false, want true — the ctrl fail-closed wrap "+
				"must preserve the gate sentinel so the commit still aborts", err)
		}
	})

	// Scope control: the bootstrap path already programmed ctrl.Enabled=0
	// before the publish, so mapsMutatedInPlace=false must NOT run the
	// classifier fail-closed. Assert it leaves the (artificially still-enabled)
	// ctrl untouched, proving the action is specific to the in-place path.
	t.Run("bootstrap_path_does_not_failclose", func(t *testing.T) {
		m, ctrlMap, snap, controlSock := newProtocolGateFailClosedManager5488(t)
		gateErr := gateErr5488(t, m)
		startArmControlServerReject(t, controlSock, 1)

		m.mu.Lock()
		err := m.disarmSnapshotProtocolFailClosedLocked(snap, gateErr, false /*mapsMutatedInPlace*/)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("disarmSnapshotProtocolFailClosedLocked must return an error on the bootstrap path too")
		}
		if got := readCtrlEnabled4959(t, ctrlMap); got != 1 {
			t.Fatalf("ctrl.Enabled = %d, want 1 unchanged; the bootstrap path already set "+
				"ctrl.Enabled=0 before publish and must not run the in-place classifier fail-closed", got)
		}
		if !IsRequiredProtocolGateError(err) {
			t.Fatalf("IsRequiredProtocolGateError(%v) = false, want true", err)
		}
	})

	// Branch control: a SUCCESSFUL disarm must return the gate error UNCHANGED —
	// taking neither the errors.Join branch nor the ctrl fail-closed branch. The
	// identity comparison is the discriminating assertion: errors.Is would also
	// hold for a joined error, so it cannot tell the branches apart.
	//
	// Note this sub-test deliberately does NOT assert ctrl stays Enabled=1. On a
	// successful disarm the helper answers with a not-Enabled status and
	// disarmSnapshotProtocolFailureLocked feeds it to applyHelperStatusLocked,
	// which independently programs ctrl.Enabled=0. That is the ORDINARY
	// fail-closed outcome of a disarm, reached through the status sync rather
	// than through the F7 path — so a ctrl assertion here would pass whether or
	// not the F7 fix exists and would prove nothing.
	t.Run("successful_disarm_returns_bare_gate_error", func(t *testing.T) {
		m, _, snap, controlSock := newProtocolGateFailClosedManager5488(t)
		gateErr := gateErr5488(t, m)
		startArmControlServer(t, controlSock, 1) // responds OK:true

		m.mu.Lock()
		err := m.disarmSnapshotProtocolFailClosedLocked(snap, gateErr, true /*mapsMutatedInPlace*/)
		m.mu.Unlock()
		if err != gateErr { //nolint:errorlint // identity IS the assertion
			t.Fatalf("error = %v (%T), want the SAME error value as the gate returned; a "+
				"successful disarm must not join or re-wrap it", err, err)
		}
		if !IsRequiredProtocolGateError(err) {
			t.Fatalf("IsRequiredProtocolGateError(%v) = false, want true", err)
		}
	})
}

// TestProtocolGateSitesRouteThroughFailClosedHelper5488 is a source-level guard
// so a revert cannot re-inline the bare disarm at either publish site and slip
// past the behavioral test above (which drives the extracted helper directly).
//
// The two sites are exactly the two callers of publishSnapshotFailClosedLocked —
// the codebase's oracle for "the classifier maps are ahead of the applied
// snapshot" — and each must pass the SAME mapsMutatedInPlace value to both
// calls, or the fail-closed action and the publish would disagree about whether
// the maps were mutated.
func TestProtocolGateSitesRouteThroughFailClosedHelper5488(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file      string
		fn        string
		wantGate  string
		wantPub   string
		whyInPlce string
	}{
		{
			// #5485 split Compile at the m.mu boundary; the publish site is now
			// applyCompiledSnapshot. Retargeted, not relaxed — both asserted
			// substrings are unchanged.
			file:      "manager_compile.go",
			fn:        "applyCompiledSnapshot",
			wantGate:  "m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)",
			wantPub:   "publishSnapshotFailClosedLocked(&publishSnap, &status, samePlanRefresh)",
			whyInPlce: "samePlanRefresh mutates the classifier maps in place before the publish",
		},
		{
			file:      "process_status.go",
			fn:        "syncSnapshotLocked",
			wantGate:  "m.disarmSnapshotProtocolFailClosedLocked(&publishSnap, err, true)",
			wantPub:   "publishSnapshotFailClosedLocked(&publishSnap, &status, true)",
			whyInPlce: "its only producer of an unpublished lastSnapshot is Compile's pendingXSKStartup branch, which always mutates the maps in place",
		},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			src := goFunctionSource(t, tc.file, tc.fn)
			if !strings.Contains(src, tc.wantGate) {
				t.Errorf("%s must route the required-protocol gate hit through "+
					"%s so a FAILED disarm drives ctrl to 0 (#5488 F7) — %s; got:\n%s",
					tc.fn, tc.wantGate, tc.whyInPlce, src)
			}
			if !strings.Contains(src, tc.wantPub) {
				t.Errorf("%s must publish via %s; the gate fail-closed and the publish "+
					"fail-closed have to agree on mapsMutatedInPlace", tc.fn, tc.wantPub)
			}
		})
	}
}
