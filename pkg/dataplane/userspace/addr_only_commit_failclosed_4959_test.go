// #4959: an address-only commit takes the samePlanRefresh path, which mutates
// the ingress/local/interface-NAT classifier BPF maps IN PLACE while the XDP
// shim's ctrl gate is still enabled, then publishes the snapshot to the running
// Rust helper. Before this fix a REJECTED apply_snapshot returned the error but
// left the classifier maps on the NEW plan with ctrl STILL ENABLED — the shim
// then read maps a generation ahead of the applied (previous-good) Rust
// snapshot, making kernel-pass-vs-XSK-redirect and local-vs-interface-NAT
// ownership decisions against a plan the helper never accepted (fail OPEN).
//
// The fix makes the in-place map refresh + helper publish one fail-closed
// transaction: on a same-plan publish rejection ctrl is disabled (Enabled=0),
// dropping transit to the kernel-only fail-closed posture until a subsequent
// good commit re-publishes and re-enables it.
//
// FAIL-ON-REVERT: neutralizing publishSnapshotFailClosedLocked back to
// `return result, fmt.Errorf("publish userspace snapshot: %w", err)` (i.e.
// dropping the failClosedUserspaceCtrlMapLocked call on the mapsMutatedInPlace
// path) leaves ctrl at Enabled=1 after the rejected publish, so
// TestAddressOnlyCommitRejectedPublishFailsClosed4959 goes RED on its
// "ctrl.Enabled must be 0" assertion.
package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
)

// startArmControlServerReject stands up a unix control socket that decodes the
// next `n` requests and REJECTS each with OK:false (a helper-side validation
// failure). This models a running helper that refuses the apply_snapshot while
// keeping the previous-good snapshot enforced.
func startArmControlServerReject(t *testing.T, controlSock string, n int) {
	t.Helper()
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for i := 0; i < n; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK:    false,
					Error: "injected apply_snapshot rejection",
				})
			}()
		}
	}()
}

// readCtrlEnabled4959 reads the userspace_ctrl row at key 0 and returns its
// Enabled field.
func readCtrlEnabled4959(t *testing.T, ctrlMap *ebpf.Map) uint32 {
	t.Helper()
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(uint32(0), &ctrl); err != nil {
		t.Fatalf("read userspace_ctrl: %v", err)
	}
	return ctrl.Enabled
}

// newFailClosedManager4959 builds a Manager wired to a control socket under the
// short-path directory, with a real userspace_ctrl map seeded Enabled=1 (a
// running, enabled firewall). Returns the manager, its ctrl map, and a built
// publish snapshot.
func newFailClosedManager4959(t *testing.T) (*Manager, *ebpf.Map, ConfigSnapshot, string) {
	t.Helper()
	// A SHORT temp-dir prefix (not t.TempDir(), whose long sub-test name would
	// push the AF_UNIX path past the 108-byte sun_path limit -> "bind: invalid
	// argument"). Honors TMPDIR (run with TMPDIR=/tmp).
	dir, err := os.MkdirTemp("", "x4959")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock

	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	// Seed ctrl as a running, ENABLED firewall (post-same-plan-refresh state:
	// maps already mutated in place, ctrl left enabled).
	enabled := userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 4, QueueCount: 4}
	if err := ctrlMap.Update(uint32(0), enabled, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl Enabled=1: %v", err)
	}

	cfg := &config.Config{}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return m, ctrlMap, *snap, controlSock
}

func TestAddressOnlyCommitRejectedPublishFailsClosed4959(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	// Core contract: same-plan refresh (maps mutated in place) + a REJECTED
	// apply_snapshot must fail closed — ctrl disabled — not fail open.
	t.Run("rejected_publish_disables_ctrl", func(t *testing.T) {
		m, ctrlMap, snap, controlSock := newFailClosedManager4959(t)
		// Helper accepts the connection and REJECTS the apply_snapshot (helper-
		// side validation failure) — the exact fail-open trigger from #4959.
		startArmControlServerReject(t, controlSock, 1)

		if got := readCtrlEnabled4959(t, ctrlMap); got != 1 {
			t.Fatalf("precondition: ctrl.Enabled = %d, want 1 (running enabled firewall)", got)
		}

		var status ProcessStatus
		m.mu.Lock()
		err := m.publishSnapshotFailClosedLocked(&snap, &status, true /*mapsMutatedInPlace*/)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("publishSnapshotFailClosedLocked must return the rejection error")
		}
		if got := readCtrlEnabled4959(t, ctrlMap); got != 0 {
			t.Fatalf("ctrl.Enabled = %d after a rejected same-plan publish, want 0 (fail closed); "+
				"maps were mutated in place and the helper kept the previous-good snapshot, "+
				"so a still-enabled shim runs classifier maps a generation ahead of the applied "+
				"snapshot (#4959 fail-open)", got)
		}
	})

	// Control: a SUCCESSFUL same-plan publish must leave ctrl untouched (this
	// method does not manage the enable side — applyHelperStatusLocked does that
	// downstream). The fix must not turn healthy address commits into a disable.
	t.Run("successful_publish_keeps_ctrl_enabled", func(t *testing.T) {
		m, ctrlMap, snap, controlSock := newFailClosedManager4959(t)
		startArmControlServer(t, controlSock, 1) // responds OK:true

		var status ProcessStatus
		m.mu.Lock()
		err := m.publishSnapshotFailClosedLocked(&snap, &status, true /*mapsMutatedInPlace*/)
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("publishSnapshotFailClosedLocked on the success path returned %v, want nil", err)
		}
		if got := readCtrlEnabled4959(t, ctrlMap); got != 1 {
			t.Fatalf("ctrl.Enabled = %d after a successful publish, want 1 (unchanged)", got)
		}
	})

	// Bootstrap path (mapsMutatedInPlace=false): the caller already programmed
	// ctrl.Enabled=0 before the publish, so this method must NOT run the
	// classifier fail-closed — it just returns the error. Assert it leaves the
	// (artificially still-enabled) ctrl untouched so the gate is proven specific
	// to the in-place refresh path.
	t.Run("bootstrap_path_does_not_failclose", func(t *testing.T) {
		m, ctrlMap, snap, controlSock := newFailClosedManager4959(t)
		startArmControlServerReject(t, controlSock, 1)

		var status ProcessStatus
		m.mu.Lock()
		err := m.publishSnapshotFailClosedLocked(&snap, &status, false /*mapsMutatedInPlace*/)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("publishSnapshotFailClosedLocked must return the rejection error on the bootstrap path too")
		}
		if got := readCtrlEnabled4959(t, ctrlMap); got != 1 {
			t.Fatalf("ctrl.Enabled = %d, want 1 unchanged; the bootstrap-path publish must not "+
				"run the in-place classifier fail-closed", got)
		}
	})
}

// TestCompileRoutesPublishThroughFailClosedHelper4959 is a source-level guard so
// a revert cannot re-inline a bare requestLocked(apply_snapshot) at the Compile
// publish site and slip past the behavioral test above (which drives the
// extracted helper directly). Compile's classifier-map publish MUST route
// through publishSnapshotFailClosedLocked with the samePlanRefresh flag.
//
// #5485 split Compile at the m.mu boundary: the publish now lives in
// applyCompiledSnapshot, which is everything Compile does once the shim is
// attached and the snapshot is built. Retargeted, not relaxed — the asserted
// substring is unchanged.
func TestCompileRoutesPublishThroughFailClosedHelper4959(t *testing.T) {
	t.Parallel()
	src := goFunctionSource(t, "manager_compile.go", "applyCompiledSnapshot")
	if !strings.Contains(src, "publishSnapshotFailClosedLocked(&publishSnap, &status, samePlanRefresh)") {
		t.Fatalf("applyCompiledSnapshot must publish the classifier-map snapshot via "+
			"publishSnapshotFailClosedLocked(..., samePlanRefresh) so a rejected "+
			"same-plan apply_snapshot fails closed (#4959); got:\n%s", src)
	}
}

// #4959 (folded review finding): syncSnapshotLocked is the SECOND apply_snapshot
// site — the status-loop deferred-publish resume path. An address-only commit
// landing during the XSK-startup liveness-probe window takes the pendingXSKStartup
// branch of Compile, which mutates the ingress/local/interface-NAT classifier BPF
// maps IN PLACE (syncUserspaceClassifierMapsFailClosedLocked, ctrl still Enabled=1
// to probe) then DEFERS the publish. When the status loop later publishes via
// syncSnapshotLocked, a REJECTED apply_snapshot must fail closed (ctrl Enabled=0),
// otherwise the shim runs classifier maps a generation ahead of the applied Rust
// snapshot — the exact #4959 fail-open, as a residual on this second site.
//
// FAIL-ON-REVERT: neutralizing the syncSnapshotLocked publish back to a bare
// `m.requestLocked(ControlRequest{Type: "apply_snapshot", ...}, &status)` (i.e.
// dropping the publishSnapshotFailClosedLocked(..., true) wrap) leaves ctrl at
// Enabled=1 after the rejected deferred publish, so
// TestDeferredPublishRejectedFailsClosed4959/rejected_deferred_publish_disables_ctrl
// goes RED on its "ctrl.Enabled must be 0" assertion.
func TestDeferredPublishRejectedFailsClosed4959(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	// seedDeferredPublishState models the manager after an address-only commit
	// was deferred during XSK startup: an initial snapshot is published
	// (publishedSnapshot != 0, same binding plan) and XSK liveness is still being
	// probed (neither proven nor failed), with a newer same-plan snapshot pending
	// whose classifier maps were already mutated in place. syncSnapshotLocked must
	// therefore reach the deferred apply_snapshot publish for this snapshot.
	seedDeferredPublishState := func(m *Manager, snap *ConfigSnapshot) {
		m.lastSnapshot = snap
		m.publishedSnapshot = 1
		m.publishedPlanKey = snapshotBindingPlanKey(snap)
		m.xskLivenessProven = false
		m.xskLivenessFailed = false
	}

	// Core residual contract: a REJECTED deferred publish must fail closed.
	t.Run("rejected_deferred_publish_disables_ctrl", func(t *testing.T) {
		m, ctrlMap, snap, controlSock := newFailClosedManager4959(t)
		snapCopy := snap
		m.mu.Lock()
		seedDeferredPublishState(m, &snapCopy)
		m.mu.Unlock()
		// The status loop's deferred publish is rejected (helper-side validation
		// failure) — the exact fail-open trigger, on the second apply site.
		startArmControlServerReject(t, controlSock, 1)

		if got := readCtrlEnabled4959(t, ctrlMap); got != 1 {
			t.Fatalf("precondition: ctrl.Enabled = %d, want 1 (running enabled firewall)", got)
		}

		m.mu.Lock()
		err := m.syncSnapshotLocked()
		m.mu.Unlock()
		if err == nil {
			t.Fatal("syncSnapshotLocked must return the rejection error")
		}
		if got := readCtrlEnabled4959(t, ctrlMap); got != 0 {
			t.Fatalf("ctrl.Enabled = %d after a rejected deferred publish, want 0 (fail closed); "+
				"the pendingXSKStartup branch mutated the classifier maps in place and the helper "+
				"kept the previous-good snapshot, so a still-enabled shim runs classifier maps a "+
				"generation ahead of the applied snapshot (#4959 fail-open residual)", got)
		}
	})

	// No-regression: a SUCCESSFUL deferred publish must land, proving the
	// fail-closed wrap is transparent on success. The wrap only disables ctrl /
	// surfaces a publish-rejection error when requestLocked fails; on OK:true it
	// calls requestLocked exactly as the pre-fix bare publish did and returns
	// nil. syncSnapshotLocked advances publishedSnapshot immediately after the
	// successful publish and BEFORE the downstream applyHelperStatusLocked, so a
	// landed publish (publishedSnapshot == the new generation) proves the wrap
	// did not reject or short-circuit. applyHelperStatusLocked then touches BPF
	// maps not injected in this unit harness and may return a "sync helper
	// status: ... map not loaded" error AFTER the publish already landed; that is
	// tolerated here exactly as the sibling applyHelperStatusLocked unit tests
	// do — it is not a publish rejection. (The "success never disables ctrl via
	// the wrap" guarantee is proven directly by
	// TestAddressOnlyCommitRejectedPublishFailsClosed4959/successful_publish_keeps_ctrl_enabled,
	// which drives the same shared helper with mapsMutatedInPlace=true.)
	t.Run("successful_deferred_publish_lands", func(t *testing.T) {
		m, _, snap, controlSock := newFailClosedManager4959(t)
		snapCopy := snap
		m.mu.Lock()
		seedDeferredPublishState(m, &snapCopy)
		m.mu.Unlock()
		startArmControlServer(t, controlSock, 1) // responds OK:true

		m.mu.Lock()
		err := m.syncSnapshotLocked()
		published := m.publishedSnapshot
		m.mu.Unlock()
		if published != snapCopy.Generation {
			t.Fatalf("publishedSnapshot = %d after a successful deferred publish, want %d "+
				"(the publish must land; the fail-closed wrap must be transparent on success)",
				published, snapCopy.Generation)
		}
		if err != nil && strings.Contains(err.Error(), "publish userspace snapshot") {
			t.Fatalf("a successful deferred publish must not surface a publish-rejection error: %v", err)
		}
	})
}

// TestSyncSnapshotRoutesPublishThroughFailClosedHelper4959 is a source-level
// guard binding the SECOND apply_snapshot site. A revert cannot re-inline a bare
// requestLocked(apply_snapshot) at the syncSnapshotLocked deferred-publish site
// and slip past the behavioral test above. The deferred-publish path only ever
// publishes a snapshot whose classifier maps the pendingXSKStartup branch already
// mutated in place, so it MUST route through publishSnapshotFailClosedLocked with
// mapsMutatedInPlace hard-coded true.
func TestSyncSnapshotRoutesPublishThroughFailClosedHelper4959(t *testing.T) {
	t.Parallel()
	src := goFunctionSource(t, "process_status.go", "syncSnapshotLocked")
	if !strings.Contains(src, "publishSnapshotFailClosedLocked(&publishSnap, &status, true)") {
		t.Fatalf("syncSnapshotLocked must publish the deferred snapshot via "+
			"publishSnapshotFailClosedLocked(..., true) so a rejected deferred "+
			"apply_snapshot fails closed (#4959 residual); got:\n%s", src)
	}
}
