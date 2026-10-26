package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFloorFor10848(t *testing.T, path, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setCurrentGenerationPackageVersion10848(t *testing.T, r *Runner, version string) {
	t.Helper()
	genid, err := r.stagedGenConfig().ResolveCurrent()
	if err != nil {
		t.Fatalf("resolve current generation: %v", err)
	}
	if genid == "" {
		t.Fatal("current generation is absent")
	}
	if err := writeStagedPackageVersion(filepath.Join(r.cfg.StagedGenDir, genid), version); err != nil {
		t.Fatalf("record staged package version: %v", err)
	}
}

func assertNoBinaryStop10848(t *testing.T, fs *fakeSystem) {
	t.Helper()
	for _, call := range fs.calls {
		if call == "stop" {
			t.Fatalf("anti-rollback refusal stopped the unit: calls=%v", fs.calls)
		}
	}
	if !fs.unitRunning {
		t.Fatal("anti-rollback refusal left the unit stopped")
	}
}

func TestRun_BinaryFloorRefusesReplayBeforeStop10848(t *testing.T) {
	for _, tc := range []struct {
		name           string
		packageVersion string
		want           string
	}{
		{name: "lower signed package", packageVersion: "0.0.200+g0123456789ab", want: "0.0.200+g0123456789ab"},
		{name: "generation without package identity", packageVersion: "", want: "no Debian package version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			seedInitialCurrent(t, r, cfg, "3.0.0")
			writeFloorFor10848(t, cfg.BinaryFloorPath, "0.0.300+gabcdef012345")
			if tc.packageVersion != "" {
				setCurrentGenerationPackageVersion10848(t, r, tc.packageVersion)
			}

			err := r.Run(Options{LockAlreadyHeld: true})
			if err == nil {
				t.Fatal("forward cut below the persisted high-water floor succeeded")
			}
			for _, want := range []string{"refuse-before-STOP", tc.want, "0.0.300+gabcdef012345"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name %q", err, want)
				}
			}
			assertNoBinaryStop10848(t, fs)
		})
	}
}

func TestRun_CorruptBinaryFloorFailsClosedBeforeStop10848(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	setCurrentGenerationPackageVersion10848(t, r, "0.0.400+g0123456789ab")
	if err := os.WriteFile(cfg.BinaryFloorPath, []byte("not-a-debian-version\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{LockAlreadyHeld: true})
	if err == nil || !strings.Contains(err.Error(), "anti-rollback floor") {
		t.Fatalf("corrupt floor accepted: %v", err)
	}
	assertNoBinaryStop10848(t, fs)
}

func TestRun_BinaryFloorAdvancesOnlyAfterHealthyCommit10848(t *testing.T) {
	t.Run("verified commit", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		setCurrentGenerationPackageVersion10848(t, r, "0.0.401+g0123456789ab")

		if err := r.Run(Options{LockAlreadyHeld: true}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		data, err := os.ReadFile(cfg.BinaryFloorPath)
		if err != nil {
			t.Fatalf("read committed floor: %v", err)
		}
		if got := strings.TrimSpace(string(data)); got != "0.0.401+g0123456789ab" {
			t.Fatalf("floor = %q, want committed package version", got)
		}
	})

	t.Run("health abort", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		fs.healthFailVersions["2.0.0"] = true
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		setCurrentGenerationPackageVersion10848(t, r, "0.0.402+g0123456789ab")

		if err := r.Run(Options{LockAlreadyHeld: true}); err == nil {
			t.Fatal("Run succeeded despite post-start health rejection")
		}
		if _, err := os.Lstat(cfg.BinaryFloorPath); !os.IsNotExist(err) {
			t.Fatalf("health-aborted cut advanced floor (lstat err=%v)", err)
		}
	})
}

func TestRollbackTo_BelowBinaryFloorRemainsNamedOverride10848(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	writeFloorFor10848(t, fx.cfg.BinaryFloorPath, "0.0.500+gabcdef012345")

	if err := fx.r.RollbackTo("1.0.0", RollbackOptions{LockAlreadyHeld: true}); err != nil {
		t.Fatalf("named RollbackTo below the high-water floor: %v", err)
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Fatalf("current -> %q after named rollback, want 1.0.0", got)
	}
	data, err := os.ReadFile(fx.cfg.BinaryFloorPath)
	if err != nil {
		t.Fatalf("read floor after named rollback: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "0.0.500+gabcdef012345" {
		t.Fatalf("named rollback lowered floor to %q", got)
	}
}

func TestKernelArm_KernelFloorRefusesReplayBeforeApt10848(t *testing.T) {
	f := newFakeKernelSystem()
	f.candidatePackageVersion = "0.0.200+g0123456789ab"
	r := newKernelRunner(t, f)
	writeFloorFor10848(t, r.cfg.KernelFloorPath, "0.0.300+gabcdef012345")

	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatal("kernel Arm below the persisted high-water floor succeeded")
	}
	for _, want := range []string{"refuse-before-apt", "0.0.200+g0123456789ab", "0.0.300+gabcdef012345"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "install:") || call == "reboot" {
			t.Fatalf("kernel replay reached apt/arm mutation: calls=%v", f.calls)
		}
	}
}

func TestKernelFloorAdvancesOnlyAfterPromotion10848(t *testing.T) {
	t.Run("promoted", func(t *testing.T) {
		f := newFakeKernelSystem()
		f.candidatePackageVersion = "0.0.401+g0123456789ab"
		r := newKernelRunner(t, f)
		if err := r.Arm("6.18.5-12-generic"); err != nil {
			t.Fatalf("Arm: %v", err)
		}
		if _, err := os.Lstat(r.cfg.KernelFloorPath); !os.IsNotExist(err) {
			t.Fatalf("Arm advanced floor before promotion (lstat err=%v)", err)
		}
		f.running = "6.18.5-12-generic"
		f.bootCurrent = "0004"
		f.verifyPass, f.beaconPass = true, true
		if _, err := r.Promote(); err != nil {
			t.Fatalf("Promote: %v", err)
		}
		data, err := os.ReadFile(r.cfg.KernelFloorPath)
		if err != nil {
			t.Fatalf("read promoted kernel floor: %v", err)
		}
		if got := strings.TrimSpace(string(data)); got != f.candidatePackageVersion {
			t.Fatalf("kernel floor = %q, want %q", got, f.candidatePackageVersion)
		}
	})

	t.Run("reverted", func(t *testing.T) {
		f := newFakeKernelSystem()
		f.candidatePackageVersion = "0.0.402+g0123456789ab"
		f.verifyPass = false
		r := newKernelRunner(t, f)
		if err := r.Arm("6.18.5-12-generic"); err != nil {
			t.Fatalf("Arm: %v", err)
		}
		f.running = "6.18.5-12-generic"
		f.bootCurrent = "0004"
		if _, err := r.Promote(); err == nil {
			t.Fatal("Promote succeeded despite dataplane rejection")
		}
		if _, err := os.Lstat(r.cfg.KernelFloorPath); !os.IsNotExist(err) {
			t.Fatalf("reverted kernel advanced floor (lstat err=%v)", err)
		}
	})
}

func TestParseAptCandidatePackageVersion10848(t *testing.T) {
	got, err := parseAptCandidatePackageVersion("linux-image-6.18.5-12-generic:\n  Candidate: 0.0.420+g0123456789ab\n")
	if err != nil {
		t.Fatalf("parse candidate: %v", err)
	}
	if got != "0.0.420+g0123456789ab" {
		t.Fatalf("candidate version = %q", got)
	}
	for _, output := range []string{
		"linux-image-6.18.5-12-generic:\n  Candidate: (none)\n",
		"linux-image-6.18.5-12-generic:\n  Installed: (none)\n",
	} {
		if _, err := parseAptCandidatePackageVersion(output); err == nil {
			t.Errorf("accepted missing candidate in %q", output)
		}
	}
}

// #10848 (B1): the publish-time check refuses a replayed old package
// before any generation is published.
func TestCheckBinaryFloorAtRefusesReplay10848(t *testing.T) {
	dir := t.TempDir()
	floorPath := filepath.Join(dir, "binary-floor")
	// Unenrolled: anything publishes (first install cannot be refused).
	if err := CheckBinaryFloorAt(floorPath, "0.0.100"); err != nil {
		t.Fatalf("unenrolled floor must allow publish: %v", err)
	}
	f := highWaterFloor{Path: floorPath}
	if err := f.advance("1.2.3"); err != nil {
		t.Fatalf("enroll floor: %v", err)
	}
	if err := CheckBinaryFloorAt(floorPath, "1.2.2"); err == nil ||
		!strings.Contains(err.Error(), "BELOW") {
		t.Fatalf("below-floor publish must refuse naming both versions, got: %v", err)
	}
	if err := CheckBinaryFloorAt(floorPath, "1.2.3"); err != nil {
		t.Fatalf("at-floor publish must allow: %v", err)
	}
	if err := CheckBinaryFloorAt(floorPath, "9.9.9"); err != nil {
		t.Fatalf("above-floor publish must allow: %v", err)
	}
}
