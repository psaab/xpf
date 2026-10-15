// #6827: a `set system host-name` commit must REACH the stale-management-TLS-
// certificate diagnostic, and the diagnostic must observe the NEW kernel host
// name.
//
// Neither held before this guard. warnStaleLoadedCert runs only while a
// certificate is being loaded (pkg/api generateSelfSignedCertAt), and the
// management reconciler rebuilds the HTTPS leg only when the TLS flag or the
// HTTPS bind address changes — so a plain rename on an unchanged endpoint
// reloaded nothing and said nothing. And because reconcileWebManagement runs
// EARLY in applyConfigLocked (before the dataplane apply, so a credential
// revocation survives an aborting commit) while applyHostname runs in the apply
// tail, even a commit that DID move the HTTPS bind would have diagnosed the OLD
// kernel name.
package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// seedDurableCert writes a cert/key pair into dir under the names
// SetTLSCertDirForTest hands the loader, minted for dnsName plus the loopback
// SANs and mgmtIP — i.e. the exact shape pkg/api's own mint path produces for a
// box named dnsName with its HTTPS listener on mgmtIP. The HTTPS leg then LOADS
// it as-is (the #1916 D6 durable contract), which is what makes the cert stale
// after a rename.
func seedDurableCert(t *testing.T, dir, dnsName, mgmtIP string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6827),
		Subject:      pkix.Name{CommonName: dnsName, Organization: []string{"xpf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", dnsName},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.ParseIP(mgmtIP)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWarnStaleMgmtCertForHostNameWithoutServer_6827 pins the nil paths: a
// daemon with the API disabled (no reconciler) and a reconciler whose server
// never bound must both be no-ops rather than a panic on the apply path.
func TestWarnStaleMgmtCertForHostNameWithoutServer_6827(t *testing.T) {
	noteRename(t, &Daemon{}, "new-fw-6827")
	(&Daemon{}).deliverStaleMgmtCertDiagnosis()

	reg := newFakeReg()
	d := &Daemon{}
	d.mgmt.Store(newManagementReconciler(d, api.Config{ListenFunc: reg.listen}))
	noteRename(t, d, "new-fw-6827")
	d.deliverStaleMgmtCertDiagnosis()
}

// noteRename drives the production sequence a `set system host-name` commit runs
// once applyHostname's guards have passed: the FENCED rename — kernel seam
// stubbed to a no-op so an unprivileged test can run it — followed by the
// delivery attempt applyHostname makes as its last act (#6827 round 7).
//
// It is the successor to the bare noteStaleMgmtCertHostName() call these cells
// used. Recording a debt is no longer separable from renaming: the syscall and
// the ledger write are one critical section, so a test that wants a debt has to
// go through the rename, exactly as production does.
//
// It deliberately does NOT touch osHostname. The delivery-time kernel read is a
// different seam (stubHostname) and several cells drive the two independently —
// including one that calls this from INSIDE an osHostname stub, to land a
// competing rename in a delivery's unlocked window.
func noteRename(t *testing.T, d *Daemon, name string) {
	t.Helper()
	restore := sethostname
	t.Cleanup(func() { sethostname = restore })
	sethostname = func([]byte) error { return nil }
	if err := d.renameHostNotingStaleMgmtCert(name); err != nil {
		t.Fatalf("fenced rename to %q: %v", name, err)
	}
	d.deliverStaleMgmtCertDiagnosis()
}

// stubHostname points the delivery-time kernel-name read at a fixed value.
func stubHostname(t *testing.T, name string) {
	t.Helper()
	restore := osHostname
	t.Cleanup(func() { osHostname = restore })
	osHostname = func() (string, error) { return name, nil }
}

// TestBootHostNameReachesTheDiagnostic_6827 is a FAIL-ON-REVERT guard for the
// BOOT ordering of the hook itself.
//
// The first config apply runs in startup phase 4 while startHTTPServer
// constructs d.mgmt much later in Run, so a `system host-name` applied at boot
// reaches a nil reconciler. Skipping on nil would reproduce the silence this
// diagnostic exists to remove, and the load path is not a fallback that covers
// it: it runs only while a certificate is being LOADED, which on an unchanged
// endpoint next happens at a restart or an HTTPS rebind — so the operator hears
// nothing for the remaining life of the process. (The worked shape here,
// `old-fw-6827` → `new-fw-6827`, is shape-PRESERVING, so the load path's
// INFERRED heuristic would accept it whenever it finally runs; it is a
// CROSS-shape rename that the heuristic declines outright, and for that one the
// parked debt is the only diagnosis there will ever be. #6827 round 6: the
// original comment here claimed the heuristic "declines precisely this shape",
// which is the opposite of what hostNameLikelyAccessIdentity does with two
// unqualified names.)
//
// SCOPE: these subtests drive deliverStaleMgmtCertDiagnosis DIRECTLY, so they
// bind the MECHANISM — a debt parked against a nil reconciler survives, and
// settles once something is serving a certificate. They say nothing about
// WHERE production calls that delivery from; the two deferred call sites are
// bound separately, at their own call site, by
// TestDeferredDeliveryIsWiredAtItsRetryPoints_6827.
//
// RED on revert: make deliverStaleMgmtCertDiagnosis return early when d.mgmt is
// nil WITHOUT parking the debt, and boot_rename_is_diagnosed_once_mgmt_is_up
// logs nothing.
func TestBootHostNameReachesTheDiagnostic_6827(t *testing.T) {
	t.Run("boot_rename_is_diagnosed_once_mgmt_is_up", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath := sethostname, hostnamePath
		t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
		hostnamePath = filepath.Join(t.TempDir(), "hostname")

		// STATEFUL stub (#6827 r3). The earlier fixture had the kernel already
		// reporting "new-fw-6827" while asking applyHostname to rename TO it —
		// a state production cannot reach, because the early return at
		// daemon_system.go fires first and sethostname is never called. It only
		// ran because that guard read os.Hostname directly while the rest of
		// the function read the seam; completing the seam reds it.
		//
		// So model the real sequence: the kernel reports the PRE-rename name,
		// and the fake sethostname advances it.
		current := "old-fw-6827"
		restoreHost := osHostname
		t.Cleanup(func() { osHostname = restoreHost })
		osHostname = func() (string, error) { return current, nil }
		var applied []string
		sethostname = func(b []byte) error {
			applied = append(applied, string(b))
			current = string(b)
			return nil
		}

		bootOut := captureDaemonWarn(t, func() {
			cfg := &config.Config{}
			cfg.System.HostName = "new-fw-6827"
			d.applyHostname(cfg)
		})
		if len(applied) != 1 || applied[0] != "new-fw-6827" {
			t.Fatalf("boot apply did not set the kernel name: %v", applied)
		}
		if strings.Contains(bootOut, "does not cover the current host-name") {
			t.Fatalf("nothing is serving a certificate yet; the boot apply must not warn: %q", bootOut)
		}

		m := serveStaleCert(t, d, "old-fw-6827")
		_ = m
		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a host name applied before the management server existed must still be "+
				"diagnosed once it comes up; got %q", out)
		}
		if !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("the deferred diagnostic must name the host name that was applied; got %q", out)
		}

		// The debt is settled: a second delivery says nothing.
		if again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() }); again != "" {
			t.Fatalf("a delivered diagnosis must not repeat; got %q", again)
		}
	})

	// #6827 r3: bind applyHostname's already-applied early return.
	//
	// It was innocuous before this PR and is LOAD-BEARING after it, because the
	// fenced rename and its delivery are reachable only past it. Deleting the guard
	// left the whole pkg/daemon + pkg/api suite GREEN, so nothing noticed —
	// while in production every commit carrying an unchanged `system host-name`
	// would re-fire the debt and its delivery, and a box with a genuinely stale
	// durable cert would emit the "does not cover the current host-name" WARN on
	// EVERY commit. Muting a real diagnostic by repeating it is exactly what
	// hostNameLikelyAccessIdentity's design avoids on the load path.
	t.Run("an_unchanged_host_name_is_a_no_op", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath := sethostname, hostnamePath
		t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
		hostnamePath = filepath.Join(t.TempDir(), "hostname")

		restoreHost := osHostname
		t.Cleanup(func() { osHostname = restoreHost })
		osHostname = func() (string, error) { return "steady-fw-6827", nil }
		var applied []string
		sethostname = func(b []byte) error { applied = append(applied, string(b)); return nil }

		// A cert that does NOT cover the name, so a delivery would be loud if
		// the debt were ever armed — the assertion below is not true for free.
		serveStaleCert(t, d, "other-fw-6827")

		out := captureDaemonWarn(t, func() {
			cfg := &config.Config{}
			cfg.System.HostName = "steady-fw-6827"
			d.applyHostname(cfg)
			d.deliverStaleMgmtCertDiagnosis()
		})
		if len(applied) != 0 {
			t.Fatalf("a commit whose host-name already matches the kernel must not call "+
				"sethostname; got %v", applied)
		}
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("an unchanged host-name must not arm the stale-cert debt — otherwise a box "+
				"with a stale durable cert warns on EVERY commit and operators learn to ignore "+
				"it; got %q", out)
		}
	})

	t.Run("debt_survives_a_delivery_that_reached_nothing", func(t *testing.T) {
		// MAJOR 1: the old code cleared the parked name whenever the drain RAN,
		// even if nothing was serving. With HTTPS off (or its bind failed) that
		// lost the diagnosis PERMANENTLY — the next boot's applyHostname sees
		// the name already applied and returns early, and the load path's
		// inferred heuristic declines cross-shape drift by design. The
		// certificate is durable on disk, so the staleness outlives the
		// listener and the debt must too.
		reg := newFakeReg()
		d := &Daemon{}
		m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
		d.mgmt.Store(m)
		stubHostname(t, "new-fw-6827")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		// HTTP only: no HTTPS leg, so no certificate is served.
		if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
			t.Fatalf("start HTTP leg: %v", err)
		}

		if out := captureDaemonWarn(t, func() { noteRename(t, d, "new-fw-6827") }); out != "" {
			t.Fatalf("with no certificate served there is nothing to diagnose yet; got %q", out)
		}
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("a delivery that reached no certificate must NOT clear the debt (#6827 MAJOR 1)")
		}

		// HTTPS comes up later carrying the stale durable pair: the debt settles.
		dir := t.TempDir()
		seedDurableCert(t, dir, "old-fw-6827", "10.0.0.1")
		m.srv.SetTLSCertDirForTest(dir)
		out := captureDaemonWarn(t, func() {
			if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
				t.Fatalf("enable HTTPS: %v", err)
			}
			d.deliverStaleMgmtCertDiagnosis()
		})
		if !strings.Contains(out, "does not cover the current host-name") || !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("a later HTTPS enable must settle the outstanding diagnosis; got %q", out)
		}
	})

	t.Run("delivery_reports_the_current_kernel_name", func(t *testing.T) {
		// MAJOR 2's consequence is removed at the root: the name is read from
		// the kernel at DELIVERY, never stored at rename time, so a deferred
		// diagnosis cannot describe a name the box no longer has.
		d := &Daemon{}
		stubHostname(t, "interim-fw-6827")
		noteRename(t, d, "interim-fw-6827")
		stubHostname(t, "final-fw-6827")
		serveStaleCert(t, d, "old-fw-6827")
		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !strings.Contains(out, "final-fw-6827") {
			t.Fatalf("the diagnosis must describe the CURRENT kernel name; got %q", out)
		}
		if strings.Contains(out, "interim-fw-6827") {
			t.Fatalf("the diagnosis must not replay an intermediate name; got %q", out)
		}
	})

	t.Run("rename_onto_the_certified_name_is_silent", func(t *testing.T) {
		d := &Daemon{}
		stubHostname(t, "still-fw-6827")
		serveStaleCert(t, d, "still-fw-6827")
		out := captureDaemonWarn(t, func() { noteRename(t, d, "still-fw-6827") })
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a covered host name must not warn; got %q", out)
		}
	})

	t.Run("failed_sethostname_is_not_diagnosed", func(t *testing.T) {
		d := &Daemon{}
		stubHostname(t, "old-fw-6827")
		// The cert covers NEITHER name (#6827 round 6). The earlier fixture
		// minted for "old-fw-6827" — the name the kernel still has after the
		// rejected rename — so a spurious note WOULD have been silent: the
		// delivery reads the kernel name, finds it covered, and says nothing
		// while quietly clearing the debt. Deleting applyHostname's error return,
		// or writing the ledger before the syscall inside the fence, left this
		// subtest GREEN. With a certificate that covers neither name, a note that
		// should not have happened is loud.
		serveStaleCert(t, d, "cert-fw-6827")
		restore := sethostname
		t.Cleanup(func() { sethostname = restore })
		sethostname = func([]byte) error { return os.ErrPermission }
		restorePath := hostnamePath
		t.Cleanup(func() { hostnamePath = restorePath })
		hostnamePath = filepath.Join(t.TempDir(), "hostname")
		out := captureDaemonWarn(t, func() {
			cfg := &config.Config{}
			cfg.System.HostName = "new-fw-6827"
			d.applyHostname(cfg)
		})
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a rename the kernel rejected must not be diagnosed; got %q", out)
		}
		// And assert the LEDGER directly, not only the log. `pending` alone
		// cannot see a spurious note — the delivery inside it reaches this live
		// leg and clears the flag straight back to false — but the generation
		// only ever advances, so it witnesses the note whatever the certificate
		// covers.
		d.staleCertMu.Lock()
		gen, pending := d.staleCertGen, d.staleCertPending
		d.staleCertMu.Unlock()
		if gen != 0 || pending {
			t.Fatalf("a rename the kernel REJECTED must leave the stale-cert ledger untouched; "+
				"got generation %d pending %v", gen, pending)
		}
	})
}

// serveStaleCert stands a management server on d with a live HTTPS leg serving a
// durable certificate minted for certName.
func serveStaleCert(t *testing.T, d *Daemon, certName string) *managementReconciler {
	t.Helper()
	reg := newFakeReg()
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("start HTTP leg: %v", err)
	}
	dir := t.TempDir()
	seedDurableCert(t, dir, certName, "10.0.0.1")
	m.srv.SetTLSCertDirForTest(dir)
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("enable HTTPS: %v", err)
	}
	if m.srv.HTTPSCertForTest() == nil {
		t.Fatal("HTTPS leg is not serving a certificate")
	}
	return m
}

// captureDaemonWarn runs fn with slog redirected to a buffer and returns what
// was logged at WARN or above.
func captureDaemonWarn(t *testing.T, fn func()) string {
	t.Helper()
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	fn()
	slog.SetDefault(restore)
	return buf.String()
}

// TestRenameIsNotedOnlyAfterSethostname_6827 binds the ORDERING that Fix 2's
// whole mechanism rests on: the diagnosis is attempted only AFTER the kernel
// name has actually moved.
//
// Hoisting the delivery above the rename previously left every test green, so
// the ordering was unproven — and ordering is the point. The stub records the
// kernel name observed at the moment the delivery reads it.
//
// RED on revert: move applyHostname's deliverStaleMgmtCertDiagnosis call above
// renameHostNotingStaleMgmtCert and the observed name is the PRE-rename one.
// (Deleting that call outright reds this too — the capture comes back empty.)
//
// The sibling ordering INSIDE the fence — the ledger write must not precede the
// syscall — is bound by failed_sethostname_is_not_diagnosed, which asserts the
// ledger is untouched when the kernel rejects the rename. Moving the write above
// the syscall dirties it there.
func TestRenameIsNotedOnlyAfterSethostname_6827(t *testing.T) {
	d := &Daemon{}
	restoreSet, restorePath := sethostname, hostnamePath
	t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
	hostnamePath = filepath.Join(t.TempDir(), "hostname")

	current := "old-fw-6827"
	restoreHost := osHostname
	t.Cleanup(func() { osHostname = restoreHost })
	osHostname = func() (string, error) { return current, nil }
	sethostname = func(b []byte) error { current = string(b); return nil }

	serveStaleCert(t, d, "old-fw-6827")
	out := captureDaemonWarn(t, func() {
		cfg := &config.Config{}
		cfg.System.HostName = "new-fw-6827"
		d.applyHostname(cfg)
	})
	if !strings.Contains(out, "new-fw-6827") {
		t.Fatalf("the diagnosis must observe the POST-rename kernel name — noting before "+
			"Sethostname would report %q; got %q", "old-fw-6827", out)
	}
}

// TestRenameAndGenerationBumpAreOneCriticalSection_6827 binds the #6827-round-7
// FENCE: staleCertMu is held ACROSS the Sethostname and the generation bump, so
// no observer can ever see a kernel name that has moved with a generation that
// has not.
//
// That interval is the whole of what rounds 5 and 6 declared unclosable. Their
// argument was that the syscall moves the name before the ledger records it, so
// a delivery in its unlocked window could re-validate against an unmoved
// generation and warn under the name the box had just left. It is closable, and
// this is the property that closes it — the generation exists before the window
// can open.
//
// It is asserted from INSIDE the syscall seam because that is the only instant
// at which the two can disagree, and it asserts with a SYNCHRONOUS
// sync.Mutex.TryLock (#6827 round 8). An earlier version spawned an observer
// goroutine and waited 100ms for it — which was probabilistic in the direction
// that matters: nothing guarantees the observer is scheduled inside the window,
// so a run could pass by never having looked. The round-7 comment here claimed
// the passing direction "cannot be produced by slowness", and that was wrong.
// TryLock removes the scheduler from the question entirely: it runs on this
// goroutine, at the instant the kernel name moves, and its answer is the state
// of the mutex — false while the fence holds, true the moment it does not.
//
// It is a TRADE, not a closure (#6827 round 9). What it proves is that the
// mutex is held WHILE sethostname runs. What it cannot see is whether the hold
// is UNINTERRUPTED from there to the bump: a shape that releases after the
// syscall and re-takes for the ledger write passes this cell — TryLock observes
// the first hold, and the closing read observes generation 1 — which is exactly
// the B2c mutant recorded GREEN in _Log.md. The probabilistic gap the goroutine
// version had is gone; this gap is deterministic and is covered structurally
// instead, by the single deferred unlock over a body with no intermediate
// release.
//
// RED on revert: take staleCertMu only for the ledger write and leave the
// syscall outside it — the exact pre-round-7 shape, where applyHostname called
// Sethostname and the generation moved afterwards. The observer then acquires
// the mutex mid-rename and reads generation 0 for a box that has already been
// renamed (measured: reds this cell and nothing else in pkg/daemon).
//
// What it does NOT distinguish, stated because it was measured rather than
// assumed: a shape that holds the mutex across the syscall, releases it, and
// re-takes it for the bump stays GREEN. That shape is still defective — the gap
// between the two holds is a window in which the name has moved and the
// generation has not.
//
// Why no probe caught it, stated at the right strength (#6827 round 9 corrected
// round 8, which asserted a mechanical impossibility): the first Unlock happens
// while the mutex is in NORMAL mode, where a woken waiter COMPETES with the
// re-acquiring goroutine rather than being handed ownership — and the
// re-acquirer, already running, usually wins. Usually is not never: sync.Mutex
// switches to STARVATION mode after a waiter has been blocked ~1ms and then
// hands ownership directly to that waiter. So the window is improbable to
// observe, not impossible, and B2c's GREEN is "did not observe it", not "cannot
// be observed". The guard against that shape is structural instead: the fenced
// function holds the mutex with a
// single `defer`ed unlock over a body with no intermediate release, which is
// visible on inspection in a way an interleaving is not. The two ORDERINGS
// inside the hold are bound behaviourally — ledger-after-syscall by
// failed_sethostname_is_not_diagnosed, generation-actually-moves by
// a_real_rename_mid_delivery_advances_the_generation.
func TestRenameAndGenerationBumpAreOneCriticalSection_6827(t *testing.T) {
	d := &Daemon{}
	restoreSet := sethostname
	t.Cleanup(func() { sethostname = restoreSet })

	var renamed string
	var free bool
	var genWhileFree uint64
	sethostname = func(b []byte) error {
		renamed = string(b) // the KERNEL name moves here
		// TryLock is NOT reentrant-friendly and that is exactly the point: this
		// goroutine already holds staleCertMu if the fence is doing its job, so
		// a successful acquisition here means the mutex was FREE while the kernel
		// name was moving — the window a concurrent delivery re-validates in.
		if d.staleCertMu.TryLock() {
			free = true
			genWhileFree = d.staleCertGen
			d.staleCertMu.Unlock()
		}
		// RECORD here, assert after the rename returns: a t.Fatal inside the seam
		// would unwind through production's deferred unlock and report a second,
		// false symptom on the way out.
		return nil
	}

	if err := d.renameHostNotingStaleMgmtCert("new-fw-6827"); err != nil {
		t.Fatalf("fenced rename: %v", err)
	}
	if renamed != "new-fw-6827" {
		t.Fatalf("fixture: the kernel seam was never called, so nothing was fenced; renamed = %q", renamed)
	}
	if free {
		t.Fatalf("staleCertMu was FREE while the kernel name was moving: it read generation %d "+
			"for a box already renamed to %q, which is exactly the window a concurrent delivery "+
			"re-validates in (#6827 round 7)", genWhileFree, renamed)
	}

	// And the generation the fence recorded is visible the moment it is released.
	d.staleCertMu.Lock()
	gen := d.staleCertGen
	d.staleCertMu.Unlock()
	if gen != 1 {
		t.Fatalf("the rename must have recorded exactly one generation under the fence; got %d", gen)
	}
}

// newMgmtDeliveryDaemon builds the Daemon the two DEFERRED delivery call sites
// need: a real configstore carrying setLines as the ACTIVE (committed)
// configuration.
//
// The store is what made both sites hard to bind, and it is load-bearing in a
// different way at each. reconcileWebManagement reaches the retry through
// managementReconciler.reconcile → committedDesired, which re-derives the WHOLE
// desired state from store.ActiveConfig() (#5561 round 14): with no store that
// derivation falls back to a bare &Daemon{}'s empty bind, so the reconcile
// DISABLES the live HTTPS leg and the delivery then correctly reports nothing
// served — a green test that proves nothing. startHTTPServer reaches its
// delivery through managementReconciler.start, which dereferences
// d.store.ActiveConfig() unconditionally.
func newMgmtDeliveryDaemon(t *testing.T, setLines ...string) *Daemon {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range setLines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return &Daemon{store: s}
}

// TestDeferredDeliveryIsWiredAtItsRetryPoints_6827 binds the two DEFERRED call
// sites. The delivery applyHostname makes inline with the rename is already
// bound by the subtests above; these two are what make the debt ledger a RETRY
// mechanism instead of "diagnose synchronously at the rename or never":
//
//   - startHTTPServer (daemon_run_servers.go): the boot management start. The
//     phase-4 boot config apply runs BEFORE the reconciler is constructed, so a
//     `system host-name` applied at boot parks against a nil d.mgmt, and this is
//     the first delivery that can see a reconciler at all.
//   - reconcileWebManagement (management.go): every day-2 commit, so a debt
//     incurred while HTTPS was down settles on the commit that brings it up.
//
// Both were unbound: deleting either call — or both, leaving only the inline one
// — left the whole pkg/daemon suite green, so the entire justification for
// keeping the flag pending was unmeasured.
//
// RED on revert: delete d.deliverStaleMgmtCertDiagnosis() from startHTTPServer
// and the first subtest fails; delete it from reconcileWebManagement and the
// second fails. Neither deletion is visible to the other.
func TestDeferredDeliveryIsWiredAtItsRetryPoints_6827(t *testing.T) {
	t.Run("boot_start_delivers_a_debt_parked_before_the_reconciler_existed", func(t *testing.T) {
		// No web-management stanza, so the boot start binds only the plain
		// --api-addr HTTP leg on an ephemeral loopback port. That is deliberate:
		// startHTTPServer CONSTRUCTS the api.Server itself, and the only cert-dir
		// injection seam (Server.SetTLSCertDirForTest) exists after construction,
		// so an in-process boot start cannot be handed a serving HTTPS leg
		// without driving the production /etc/xpf/tls generator.
		//
		// WHAT THIS CELL PROVES, AND WHAT IT DOES NOT (#6827 round 6 — stated
		// rather than implied, because the earlier comment read as if it proved
		// the whole chain). It proves that startHTTPServer attempts the parked
		// delivery, and that the attempt happens AFTER the management server has
		// been constructed — the two facts that make the call site the right one.
		// It does NOT prove that the delivery reached a certificate, emitted a
		// warning, or discharged the debt: none of those are observable at boot
		// in-process, for the construction-order reason above. Those three are
		// bound at the OTHER retry point instead, where the seam does exist —
		// a_day2_reconcile_settles_a_debt_incurred_while_https_was_down (reach +
		// discharge, on the debt flag) and
		// TestADeadHTTPSLegIsRebuiltByTheNextReconcile_6827 (the same, end to end
		// from reconcileWebManagement).
		//
		// Known residual: replacing the production delivery with a bare
		// osHostname() call would also satisfy this cell. The read is the only
		// in-process trace a delivery leaves when nothing is served, so no
		// assertion here can tell those two apart; a genuinely stronger cell
		// needs a pre-construction certificate seam on api.Config, which is a
		// production knob added for one test and was declined.
		d := newMgmtDeliveryDaemon(t, "system host-name new-fw-6827")
		d.opts.APIAddr = "127.0.0.1:0"

		// The kernel-name read lives INSIDE deliverStaleMgmtCertDiagnosis, past
		// its `!pending || mgmt == nil` early return, and nothing else on this
		// path reads it (the only other osHostname caller in the package is
		// applyHostname's already-applied guard, daemon_system.go, which
		// startHTTPServer never reaches). So a read during startHTTPServer is a
		// direct observation of the delivery running — and of it running AFTER
		// d.mgmt is published, since an unpublished reconciler returns before the
		// read.
		var reads int
		var srvUpAtRead bool
		restore := osHostname
		t.Cleanup(func() { osHostname = restore })
		osHostname = func() (string, error) {
			reads++
			// Capture the ORDERING, not just the fact of the call: a delivery
			// hoisted above mgmt.start would still read the name (d.mgmt is
			// published first) but could never reach a certificate, because no
			// server exists yet.
			if m := d.mgmt.Load(); m != nil {
				m.mu.Lock()
				srvUpAtRead = m.srv != nil
				m.mu.Unlock()
			}
			return "new-fw-6827", nil
		}

		// Boot order: the rename lands while startHTTPServer has not run, so the
		// debt parks against a nil reconciler.
		noteRename(t, d, "new-fw-6827")
		if reads != 0 {
			t.Fatalf("with no reconciler the delivery must not even reach the kernel-name read, "+
				"so this subtest's later count is attributable to the boot start alone; reads = %d", reads)
		}

		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		t.Cleanup(func() { cancel(); wg.Wait() })
		captureDaemonWarn(t, func() { d.startHTTPServer(ctx, &wg, nil, nil) })

		if reads == 0 {
			t.Fatal("the boot management start did not attempt the parked diagnosis: the kernel " +
				"name was never read, so deliverStaleMgmtCertDiagnosis did not run past its nil-reconciler " +
				"guard. A host-name applied in the phase-4 boot apply is then never diagnosed, because " +
				"the next boot's applyHostname sees the name already applied and returns early (#6827)")
		}
		if !srvUpAtRead {
			t.Fatal("the boot delivery ran BEFORE the management server was constructed: it can " +
				"never reach a certificate from there, so the retry point is decorative (#6827)")
		}

		// Negative control: nothing served a certificate, so the debt must
		// SURVIVE the boot delivery. This is also why the WARN text cannot be the
		// observable here — there is no certificate at boot to judge.
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("the boot delivery reached no served certificate, so it must not settle the debt")
		}
	})

	t.Run("a_day2_reconcile_settles_a_debt_incurred_while_https_was_down", func(t *testing.T) {
		d := newMgmtDeliveryDaemon(t,
			"system services web-management http",
			"system services web-management https",
		)
		reg := newFakeReg()
		m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
		d.mgmt.Store(m)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// Start SHORT of the committed state: HTTP only. That is the state a
		// disabled-or-failed HTTPS bind leaves behind, and the state in which a
		// rename incurs a debt no delivery can settle.
		want := m.committedDesired(nil)
		if !want.TLS || want.HTTPSAddr == "" {
			t.Fatalf("fixture: the committed config must ask for HTTPS or the reconcile has "+
				"nothing to bring up; desired = %+v", endpointOf(want))
		}
		httpOnly := want
		httpOnly.TLS, httpOnly.HTTPSAddr = false, ""
		if err := m.startTo(ctx, httpOnly); err != nil {
			t.Fatalf("start HTTP leg: %v", err)
		}

		stubHostname(t, "new-fw-6827")
		if out := captureDaemonWarn(t, func() { noteRename(t, d, "new-fw-6827") }); strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("nothing is serving a certificate yet, so the rename cannot be diagnosed "+
				"at the rename itself; got %q", out)
		}
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("the fixture must leave a debt outstanding, otherwise the reconcile has " +
				"nothing to settle and this subtest proves nothing")
		}

		// The stale durable pair the HTTPS leg LOADS when this reconcile binds it
		// (#1916 D6).
		dir := t.TempDir()
		seedDurableCert(t, dir, "old-fw-6827", "127.0.0.1")
		m.srv.SetTLSCertDirForTest(dir)

		// applyConfigLocked's entry point, not reconcileTo: the wiring under test
		// is reconcileWebManagement's, and reaching past it would bind the
		// mechanism again rather than the call site.
		captureDaemonWarn(t, func() {
			if err := d.reconcileWebManagement(d.store.ActiveConfig()); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
		})
		if m.srv.HTTPSCertForTest() == nil {
			t.Fatal("the reconcile did not bring the HTTPS leg up, so there was no certificate " +
				"for a retried delivery to reach and this subtest proves nothing")
		}

		// The DEBT FLAG, not the warning text. Bringing HTTPS up makes the
		// certificate LOAD path emit the same "does not cover the current
		// host-name" message, so a text assertion here passes with the retry
		// DELETED. Only a delivery clears the flag.
		d.staleCertMu.Lock()
		pending = d.staleCertPending
		d.staleCertMu.Unlock()
		if pending {
			t.Fatal("a web-management reconcile that brought HTTPS up left the host-name " +
				"diagnosis still owed: nothing retried the delivery, so the debt survives every " +
				"later commit on an unchanged endpoint and is discharged only by another rename (#6827)")
		}
	})
}

// TestADeadHTTPSLegIsRebuiltByTheNextReconcile_6827 is the FAIL-ON-REVERT guard
// for the #6827-round-6 BLOCKER, driven end-to-end from the daemon's own commit
// entry point.
//
// An HTTPS serve loop that terminates unexpectedly leaves the leg INSTALLED with
// only `dead` set (api.listenerLeg — removing it there would need lifeMu, which
// deadlocks a shutdown racing the exit). Two independent things then treated
// that corpse as a converged listener:
//
//   - the reconciler's leg-changed test compared only the FINGERPRINT, which
//     still matched the committed endpoint, so ReconcileHTTPS was never called;
//   - and had it been called, the same-address arm returned nil on a non-nil
//     pointer, so it would have done nothing.
//
// Either one alone makes HTTPS unrecoverable on an UNCHANGED configuration for
// the life of the process, and takes the stale-cert debt with it: the debt
// clears only against a served certificate, so it can never be discharged and
// the restart that finally rebinds HTTPS also discards it.
//
// RED on revert: drop `|| (next.TLS && !m.srv.HTTPSServing())` from
// reconcileTo's HTTPS arm, OR restore `s.httpsLeg != nil && ...` in
// api.Server.ReconcileHTTPS — each on its own fails the "HTTPS is back" and
// "debt settled" assertions below.
func TestADeadHTTPSLegIsRebuiltByTheNextReconcile_6827(t *testing.T) {
	d := newMgmtDeliveryDaemon(t,
		"system services web-management http",
		"system services web-management https",
	)
	reg := newFakeReg()
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	want := m.committedDesired(nil)
	if !want.TLS || want.HTTPSAddr == "" {
		t.Fatalf("fixture: the committed config must ask for HTTPS; desired = %+v", endpointOf(want))
	}
	httpOnly := want
	httpOnly.TLS, httpOnly.HTTPSAddr = false, ""
	if err := m.startTo(ctx, httpOnly); err != nil {
		t.Fatalf("start HTTP leg: %v", err)
	}
	dir := t.TempDir()
	seedDurableCert(t, dir, "old-fw-6827", "127.0.0.1")
	m.srv.SetTLSCertDirForTest(dir)
	captureDaemonWarn(t, func() {
		if err := d.reconcileWebManagement(d.store.ActiveConfig()); err != nil {
			t.Fatalf("bring HTTPS up: %v", err)
		}
	})
	if !m.srv.HTTPSServing() {
		t.Fatal("fixture: the HTTPS leg must be serving before it can die")
	}

	// The serve loop terminates on its own: closing the listener under it makes
	// Accept fail, which is the production shape of an unexpected serve exit
	// (serveLegLocked's serveErr arm, not a requested retirement). The `dead`
	// flag is therefore set by production, not by this test.
	httpsLn := reg.get(want.HTTPSAddr)
	if httpsLn == nil {
		t.Fatalf("fixture: no listener recorded at %q", want.HTTPSAddr)
	}
	httpsLn.Close()
	// Wait on `drained`, NOT on HTTPSServing() (#6827 round 7). This server also
	// has a live HTTP leg, so Server.Wait cannot be the barrier here — it would
	// block until daemon shutdown — and the poll has to stay. But it must not
	// poll the flag this cell exists to bind: HTTPSServing() reads `dead`, so a
	// mutation that stops `dead` being stored made this loop run to its deadline
	// and the cell red HERE, at the setup, instead of at "a dead HTTPS leg must
	// be rebuilt by the next reconcile" below. `drained` is stored by the serve
	// goroutine's defer on every exit path, so it reports that the exit happened
	// without consulting anything under test.
	deadline := time.Now().Add(5 * time.Second)
	for !m.srv.HTTPSLegDrainedForTest() {
		if time.Now().After(deadline) {
			t.Fatal("the HTTPS serve goroutine did not observe its closed listener")
		}
		time.Sleep(time.Millisecond)
	}

	// A rename now incurs a debt nothing can settle: no certificate is served.
	stubHostname(t, "new-fw-6827")
	captureDaemonWarn(t, func() { noteRename(t, d, "new-fw-6827") })
	d.staleCertMu.Lock()
	pending := d.staleCertPending
	d.staleCertMu.Unlock()
	if !pending {
		t.Fatal("fixture: with the HTTPS leg dead nothing serves a certificate, so the " +
			"diagnosis must still be owed")
	}

	// The operator's next commit — on the SAME configuration they never touched.
	out := captureDaemonWarn(t, func() {
		if err := d.reconcileWebManagement(d.store.ActiveConfig()); err != nil {
			t.Fatalf("reconcile over a dead HTTPS leg: %v", err)
		}
	})
	if !m.srv.HTTPSServing() {
		t.Fatal("a commit on an unchanged configuration left the DEAD HTTPS leg in place: the " +
			"management TLS plane is down until the daemon restarts, and no configuration " +
			"change can bring it back (#6827 round 6)")
	}
	d.staleCertMu.Lock()
	pending = d.staleCertPending
	d.staleCertMu.Unlock()
	if pending {
		t.Fatalf("the rebuilt HTTPS leg serves a certificate again, so the outstanding host-name "+
			"diagnosis must be discharged — otherwise the debt is permanently undischargeable "+
			"and a restart drops it; log was %q", out)
	}
}

// TestDebtClearIsGenerationSafe_6827 pins the #6827-round-5 losing sequence,
// with the round-6 tightening: the kernel-name read runs UNLOCKED, so a rename
// committed after it must neither settle the debt with the older delivery's
// evidence NOR be reported under the name that delivery read.
//
// The race is reachable: applySem serializes commits with each other, but the
// boot delivery (daemon_run_servers.go, on the Run goroutine) runs OUTSIDE it,
// and cluster comms are already running by then — Daemon.Run starts them right
// after the mutating startup phases and well before startHTTPServer — so a peer
// SyncApply -> applyHostname can bump the generation while the boot delivery
// sits in its unlocked window.
//
// Every subtest drives the PRODUCTION comparison — an earlier version of this
// test re-implemented `d.staleCertGen == gen` in its own body and asserted on
// its own arithmetic, so the fence could be replaced by an unconditional clear
// with the whole suite still green.
//
// RED on revert: `if false && d.staleCertGen != gen` (never abandon) fails the
// first and third subtests; `if true || d.staleCertGen != gen` (always abandon)
// fails the second. Neither direction passes all three. Deleting
// `d.staleCertGen++` from renameHostNotingStaleMgmtCert fails the third only — the
// first two supply their own generation movement, which is exactly why the
// third exists.
func TestDebtClearIsGenerationSafe_6827(t *testing.T) {
	t.Run("a_rename_landing_mid_delivery_is_not_settled", func(t *testing.T) {
		d := &Daemon{}
		serveStaleCert(t, d, "old-fw-6827")

		// osHostname is read INSIDE the unlocked window, so stubbing it is the
		// seam that lands a rename exactly where the race is: after this delivery
		// sampled the generation, before it re-validates it. It fires ONCE, so the
		// surviving debt is deliverable on a later attempt.
		restore := osHostname
		t.Cleanup(func() { osHostname = restore })
		var raced bool
		osHostname = func() (string, error) {
			if !raced {
				raced = true
				d.staleCertMu.Lock()
				d.staleCertGen++ // a newer `set system host-name` commits mid-delivery
				d.staleCertMu.Unlock()
			}
			return "interim-fw-6827", nil
		}

		d.staleCertMu.Lock()
		d.staleCertPending, d.staleCertGen = true, 1
		d.staleCertMu.Unlock()

		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !raced {
			t.Fatal("the stub never fired, so no rename landed in the unlocked window and " +
				"this subtest proves nothing")
		}
		// Round 6: the superseded delivery must ABANDON, not warn. Round 5 checked
		// the generation only AFTER the warning was already emitted, so this
		// sequence logged a staleness diagnosis naming a host name the box had
		// already left — and the fence, which runs later, cannot retract a line
		// that is out.
		if out != "" {
			t.Fatalf("a delivery whose generation was superseded must emit NOTHING — the name it "+
				"read is no longer the one the debt is about, and the clear-side fence cannot "+
				"retract an emitted line; got %q", out)
		}
		d.staleCertMu.Lock()
		pending, gen := d.staleCertPending, d.staleCertGen
		d.staleCertMu.Unlock()
		if gen != 2 {
			t.Fatalf("generation = %d, want the mid-delivery bump to 2", gen)
		}
		if !pending {
			t.Fatal("an older delivery settled a rename that landed AFTER it sampled the " +
				"generation — the newer debt is lost permanently (#6827 round 5)")
		}

		// The surviving debt is still deliverable (the fence defers it, not drops
		// it), and the delivery that DOES speak names the current kernel identity.
		if again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() }); !strings.Contains(again, "interim-fw-6827") {
			t.Fatalf("the outstanding newer debt must still be deliverable; got %q", again)
		}
	})

	t.Run("a_real_rename_mid_delivery_advances_the_generation", func(t *testing.T) {
		// The two subtests around this one move the generation THEMSELVES, so
		// both stay green with the production `d.staleCertGen++` deleted: they
		// prove the fence reacts to a moving generation, not that anything moves
		// it (#6827 round 6). This one drives the rename through
		// the production fenced rename and never touches staleCertGen.
		//
		// The shape is the one where the increment is load-bearing in production:
		// the NEWER rename's own delivery reaches nothing (HTTPS is still down),
		// and the commit carrying it then brings HTTPS up — so the OLDER delivery
		// is the one that finds a certificate. Without a generation to tell them
		// apart it settles the newer rename's debt with its own older evidence,
		// and that diagnosis is gone for the life of the process.
		d := newMgmtDeliveryDaemon(t,
			"system services web-management http",
			"system services web-management https",
		)
		reg := newFakeReg()
		m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
		d.mgmt.Store(m)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// #7039: bind the management plane to a ROUTABLE address.
		//
		// This subtest is about GENERATION SAFETY, and it uses the stale-cert
		// WARN as its observable for "the outstanding debt settled". That
		// diagnostic is now correctly SILENT on a loopback-only listener — no
		// remote client exists there to verify by host name — and
		// `web-management https` with no `interface` resolves to 127.0.0.1:443,
		// so this fixture was measuring the generation property THROUGH the very
		// defect #7039 fixes. A routable bind restores the observable without
		// weakening what the cell asserts.
		want := cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)
		httpOnly := cfgFor(reg, "10.0.0.1:8080", false, "", nil)
		if err := m.startTo(ctx, httpOnly); err != nil {
			t.Fatalf("start HTTP leg: %v", err)
		}
		dir := t.TempDir()
		seedDurableCert(t, dir, "old-fw-6827", "10.0.0.1")
		m.srv.SetTLSCertDirForTest(dir)

		// Debt #1, incurred while nothing serves a certificate.
		stubHostname(t, "first-fw-6827")
		noteRename(t, d, "first-fw-6827")
		d.staleCertMu.Lock()
		pending, firstGen := d.staleCertPending, d.staleCertGen
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("fixture: nothing served a certificate, so the debt must still stand")
		}

		restore := osHostname
		t.Cleanup(func() { osHostname = restore })
		var raced bool
		osHostname = func() (string, error) {
			if !raced {
				raced = true
				// A second `set system host-name` commits while this delivery is
				// in its unlocked window — through PRODUCTION, so the generation
				// moves only if renameHostNotingStaleMgmtCert moves it. Its own
				// delivery reaches nothing: HTTPS is still down at this instant.
				noteRename(t, d, "second-fw-6827")
				// ...and the same commit brings HTTPS up, so the OLDER delivery
				// below is the first one to find a served certificate.
				if err := m.reconcileTo(want); err != nil {
					t.Errorf("enable HTTPS mid-delivery: %v", err)
				}
			}
			return "second-fw-6827", nil
		}

		captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !raced {
			t.Fatal("the stub never fired, so no second rename landed and this subtest proves nothing")
		}
		if m.srv.HTTPSCertForTest() == nil {
			t.Fatal("fixture: HTTPS did not come up mid-delivery, so the older delivery reached " +
				"no certificate and could not have cleared anything either way")
		}
		d.staleCertMu.Lock()
		pending, gen := d.staleCertPending, d.staleCertGen
		d.staleCertMu.Unlock()
		if gen == firstGen {
			t.Fatalf("a real `set system host-name` must ADVANCE the generation: it is still %d, "+
				"so no delivery can tell the two renames apart", gen)
		}
		if !pending {
			t.Fatal("the older delivery settled the SECOND rename's debt with its own evidence — " +
				"that diagnosis is now lost for the life of the process (#6827 round 6)")
		}
		// And the surviving debt is genuinely deliverable now that HTTPS is up.
		again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !strings.Contains(again, "second-fw-6827") {
			t.Fatalf("the outstanding debt must settle on the next retry, naming the current "+
				"kernel identity; got %q", again)
		}
	})

	t.Run("an_unreadable_kernel_name_settles_nothing", func(t *testing.T) {
		// The read guard (#6827 round 6). An empty or failed os.Hostname leaves no
		// identity to judge the certificate against — but the delivery would still
		// REACH one, and warnStaleCertForHostName reports "answered" whenever it
		// does, so the debt would clear on the strength of nothing. The operator
		// gets silence (warnStaleHostName declines an empty name) and no retry.
		for _, c := range []struct {
			name string
			read func() (string, error)
		}{
			{"read_failed", func() (string, error) { return "", os.ErrPermission }},
			{"empty_name", func() (string, error) { return "", nil }},
			// A failed read that still returns a name is the same case: the value
			// is not trustworthy, so it must not be used to settle anything.
			{"error_with_a_name", func() (string, error) { return "new-fw-6827", os.ErrPermission }},
		} {
			t.Run(c.name, func(t *testing.T) {
				d := &Daemon{}
				serveStaleCert(t, d, "old-fw-6827")
				d.staleCertMu.Lock()
				d.staleCertPending, d.staleCertGen = true, 1
				d.staleCertMu.Unlock()

				restore := osHostname
				t.Cleanup(func() { osHostname = restore })
				osHostname = c.read

				out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
				if out != "" {
					t.Fatalf("with no usable kernel name there is nothing to diagnose; got %q", out)
				}
				d.staleCertMu.Lock()
				pending := d.staleCertPending
				d.staleCertMu.Unlock()
				if !pending {
					t.Fatal("a delivery that could not read the kernel name cleared the debt " +
						"anyway: the diagnosis is discharged with no identity behind it and is " +
						"never retried (#6827 round 6)")
				}
			})
		}
	})

	t.Run("an_unraced_delivery_settles_the_debt", func(t *testing.T) {
		// OVER-REACH GUARD (negative control): the fence must NARROW the clear to
		// the generation the delivery claimed, not suppress clearing. Stays GREEN
		// under the unconditional-clear mutation and RED under a never-clear one,
		// so the pair distinguishes the fence from both neighbours.
		d := &Daemon{}
		stubHostname(t, "new-fw-6827")
		serveStaleCert(t, d, "old-fw-6827")

		out := captureDaemonWarn(t, func() { noteRename(t, d, "new-fw-6827") })
		if !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("the rename must be diagnosed; got %q", out)
		}
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if pending {
			t.Fatal("a delivery that reached a served certificate with NO concurrent rename " +
				"must settle the debt — the generation fence must not suppress the clear")
		}
		if again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() }); again != "" {
			t.Fatalf("a settled debt must not re-warn; got %q", again)
		}
	})

	t.Run("a_sibling_that_already_settled_the_same_generation_silences_this_one", func(t *testing.T) {
		// #6827 round 7. TWO deliveries for ONE rename: the boot delivery from
		// startHTTPServer racing the rename's own attempt, or a reconcile retry
		// racing either. Both sample pending=true at the SAME generation, so a
		// re-validation that tests only the generation passes for both — the
		// first warns and clears, the second finds the generation unmoved and
		// warns again. One rename, two identical lines at the operator.
		//
		// The subtest above cannot see it: its second delivery starts AFTER the
		// clear, so it returns at the `!pending` early return without ever
		// reaching the re-validation. The overlap is what makes the case, and the
		// kernel-name read is the seam that produces it deterministically.
		//
		// RED on revert: drop `if !d.staleCertPending` from the re-validation in
		// deliverStaleMgmtCertDiagnosis and the outer delivery duplicates the
		// diagnosis the sibling has already delivered.
		d := &Daemon{}
		serveStaleCert(t, d, "old-fw-6827")
		d.staleCertMu.Lock()
		d.staleCertPending, d.staleCertGen = true, 1
		d.staleCertMu.Unlock()

		restore := osHostname
		t.Cleanup(func() { osHostname = restore })
		var siblingOut string
		var fired bool
		osHostname = func() (string, error) {
			if !fired {
				fired = true
				// The sibling runs to completion inside the outer delivery's
				// unlocked window: same generation, reaches the certificate,
				// warns, and clears the debt.
				siblingOut = captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
			}
			return "new-fw-6827", nil
		}

		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !fired {
			t.Fatal("the stub never fired, so the two deliveries never overlapped and this " +
				"subtest proves nothing")
		}
		if !strings.Contains(siblingOut, "new-fw-6827") {
			t.Fatalf("fixture: the SIBLING must be the one that delivered the diagnosis, "+
				"otherwise there is no settled debt for the outer delivery to re-warn; got %q", siblingOut)
		}
		if out != "" {
			t.Fatalf("the debt was already settled at this generation, so the second delivery "+
				"must stay silent rather than duplicate the line; got %q", out)
		}
	})
}
