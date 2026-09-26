package upgrade

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_ForwardEnvelopeReaderGateRefusesBeforeStop10847(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{name: "standalone"},
		{name: "HA rolling", opts: Options{ClusterCoordinated: true, SkipStartHealthRollback: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			fs.readerVersion = 1
			r, cfg := testEnv(t, fs)
			mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"),
				"#xpf-config-envelope v=1 writer=2.0.0 ast=1 min-reader=2 rollback-fmt=1 committed=1\n{}")

			tc.opts.AllowNoRollbackFirstCut = true
			err := r.Run(tc.opts)
			if err == nil || !strings.Contains(err.Error(), "refuse-before-PREFLIGHT") ||
				!strings.Contains(err.Error(), "min-reader=2") || !strings.Contains(err.Error(), "reader v=1") {
				t.Fatalf("Run error = %v, want preflight refusal for reader < minReader", err)
			}
			assertForwardEnvelopeRefusedBeforeStop(t, fs)
		})
	}
}

func TestRun_ForwardEnvelopeReaderGateRejectsMalformedHeader10847(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), "#xpf-config-envelope v=\n{}")

	err := r.Run(Options{AllowNoRollbackFirstCut: true})
	if err == nil || !strings.Contains(err.Error(), "malformed live config DB envelope") {
		t.Fatalf("Run error = %v, want malformed-envelope refusal", err)
	}
	assertForwardEnvelopeRefusedBeforeStop(t, fs)
}

func TestRun_ForwardEnvelopeReaderGateAllowsLegacyAndCompatibleDB10847(t *testing.T) {
	for _, tc := range []struct {
		name string
		db   string
	}{
		{name: "legacy non-enveloped", db: `{"legacy":true}`},
		{name: "compatible envelope", db: "#xpf-config-envelope v=2 writer=2.0.0 ast=1 min-reader=2 rollback-fmt=1 committed=1\n{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), tc.db)
			if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
				t.Fatalf("compatible Run: %v", err)
			}
			if got := currentTarget(t, cfg); got != "2.0.0" {
				t.Fatalf("current -> %q, want 2.0.0", got)
			}
		})
	}
}

func TestRun_ForwardEnvelopeReaderGateRechecksLiveDBBeforeStop10847(t *testing.T) {
	for _, mode := range []string{"DB changes after VERIFY", "resume at VERIFIED"} {
		t.Run(mode, func(t *testing.T) {
			fs := newFakeSystem(t, "1.0.0")
			r, cfg := testEnv(t, fs)
			if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
				t.Fatalf("first cut: %v", err)
			}
			active := filepath.Join(cfg.ConfigDBDir, "active.json")
			const compatible = "#xpf-config-envelope v=1 writer=1.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n{}"
			const incompatible = "#xpf-config-envelope v=1 writer=2.0.0 ast=1 min-reader=2 rollback-fmt=1 committed=1\n{}"
			mkfile(t, active, compatible)
			stageSecondCut(t, r, cfg, fs)
			fs.readerVersion = 1

			if mode == "resume at VERIFIED" {
				seedCrashState(t, r, cfg, fs, StateVerified)
				mkfile(t, active, incompatible)
			} else {
				fs.verifyHook = func() { mkfile(t, active, incompatible) }
			}
			fs.calls = nil

			err := r.Run(Options{})
			if err == nil || !strings.Contains(err.Error(), "refuse-before-STOP") ||
				!strings.Contains(err.Error(), "min-reader=2") {
				t.Fatalf("Run error = %v, want pre-STOP envelope refusal", err)
			}
			assertForwardEnvelopeRefusedBeforeStop(t, fs)
			if mode == "DB changes after VERIFY" && !containsCall(fs.calls, "verify") {
				t.Fatalf("verification was not reached before the live DB changed: calls=%v", fs.calls)
			}
		})
	}
}

func assertForwardEnvelopeRefusedBeforeStop(t *testing.T, fs *fakeSystem) {
	t.Helper()
	if !fs.unitRunning {
		t.Fatal("unit stopped after forward envelope refusal")
	}
	for _, call := range fs.calls {
		switch call {
		case "stop", "dropin", "daemon-reload", "start":
			t.Errorf("live cutover call %q ran before envelope refusal (calls=%v)", call, fs.calls)
		}
	}
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}
