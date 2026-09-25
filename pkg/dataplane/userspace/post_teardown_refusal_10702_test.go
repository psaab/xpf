package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var rustPostTeardownPrefixRe10702 = regexp.MustCompile(`SNAPSHOT_POST_TEARDOWN_PREFIX:\s*&str\s*=\s*"([^"]*)"\s*;`)

func TestPostTeardownRefusalPrefixMatchesHelper10702(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/protocol/control.rs")
	if err != nil {
		t.Fatalf("read helper control protocol: %v", err)
	}
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			stripped.WriteByte('\n')
			continue
		}
		stripped.WriteString(line)
		stripped.WriteByte('\n')
	}
	match := rustPostTeardownPrefixRe10702.FindStringSubmatch(stripped.String())
	if match == nil {
		t.Fatal("SNAPSHOT_POST_TEARDOWN_PREFIX not found in userspace-dp/src/protocol/control.rs")
	}
	if match[1] != snapshotPostTeardownPrefix {
		t.Fatalf("Rust post-teardown prefix %q disagrees with Go prefix %q", match[1], snapshotPostTeardownPrefix)
	}
}

func serveRefusal10702(t *testing.T, message string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		_ = json.NewEncoder(conn).Encode(ControlResponse{OK: false, Error: message})
	}()
	return sock
}

// Drive requestDetailedAtSocket against a fake helper, not newHelperRejection,
// so the wire decoder's distinction between a retained pre-teardown refusal
// and the destructive post-teardown kind is pinned too.
func TestFakeHelperPinsRetainedAndPostTeardownRefusalKinds10702(t *testing.T) {
	cases := []struct {
		name             string
		message          string
		wantRetained     bool
		wantPostTeardown bool
	}{
		{
			name:         "pre_teardown_integrity_refusal_retains_prior_state",
			message:      "snapshot integrity error: unknown zone",
			wantRetained: true,
		},
		{
			name:             "post_teardown_refusal_does_not_claim_retention",
			message:          snapshotPostTeardownPrefix + " worker spawn failed after teardown (spawn_worker_failed:0); dataplane down — snapshot not persisted",
			wantPostTeardown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			sock := serveRefusal10702(t, tc.message)
			_, err := m.requestDetailedAtSocket(ControlRequest{Type: "apply_snapshot"}, sock)
			if err == nil {
				t.Fatal("fake helper refusal returned nil")
			}
			if got := errors.Is(err, errHelperRejected); got != tc.wantRetained {
				t.Fatalf("errors.Is(err, errHelperRejected) = %v, want %v (err=%v)", got, tc.wantRetained, err)
			}
			if got := errors.Is(err, errHelperPostTeardown); got != tc.wantPostTeardown {
				t.Fatalf("errors.Is(err, errHelperPostTeardown) = %v, want %v (err=%v)", got, tc.wantPostTeardown, err)
			}
			if err.Error() != tc.message {
				t.Fatalf("error message = %q, want helper message verbatim %q", err, tc.message)
			}
		})
	}
}

func TestPostTeardownRefusalDisablesCtrlAndArmsRetryDebt10702(t *testing.T) {
	message := snapshotPostTeardownPrefix + " worker spawn failed after teardown (spawn_worker_failed:0); dataplane down — snapshot not persisted"
	m := New()
	m.cfg.ControlSocket = serveRefusal10702(t, message)
	retained := &ConfigSnapshot{Version: ProtocolVersion, Generation: 41}
	m.lastSnapshot = retained
	m.publishedSnapshot = retained.Generation
	m.generation = retained.Generation
	ctrl := &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1},
		haveStored: true,
	}
	m.failClosedCtrlMapHook = ctrl
	var classifierSyncs []*ConfigSnapshot
	m.syncClassifierMapsHook = func(snapshot *ConfigSnapshot) error {
		classifierSyncs = append(classifierSyncs, snapshot)
		return nil
	}
	attempted := &ConfigSnapshot{Version: ProtocolVersion, Generation: 42}

	m.mu.Lock()
	err := m.publishSnapshotFailClosedLocked(attempted, &ProcessStatus{}, true)
	m.mu.Unlock()
	if m.syncCancel == nil {
		t.Fatal("post-teardown refusal left no reconcile worker to consume retry debt")
	}
	if m.syncCancel != nil {
		defer m.syncCancel()
	}
	if err == nil {
		t.Fatal("post-teardown refusal returned nil")
	}
	if !errors.Is(err, errHelperPostTeardown) || errors.Is(err, errHelperRejected) {
		t.Fatalf("refusal kind lost or misclassified: err=%v post_teardown=%v retained=%v", err,
			errors.Is(err, errHelperPostTeardown), errors.Is(err, errHelperRejected))
	}
	if err.Error() != "publish userspace snapshot: "+message {
		t.Fatalf("publish error = %q, want verbatim helper message wrapped by publish path", err)
	}
	if ctrl.stored.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d, want 0 after post-teardown refusal", ctrl.stored.Enabled)
	}
	if len(classifierSyncs) != 0 {
		t.Fatalf("classifier maps were rolled back %d times; dead workers cannot retain the prior plan", len(classifierSyncs))
	}
	m.mu.Lock()
	debt := m.snapshotRetryDebtLocked()
	unknown := m.applySnapshotOutcomeUnknown
	adoptedGeneration := uint64(0)
	if m.lastSnapshot != nil {
		adoptedGeneration = m.lastSnapshot.Generation
	}
	published := m.publishedSnapshot
	m.mu.Unlock()
	if !unknown || !debt || adoptedGeneration != attempted.Generation || published >= adoptedGeneration {
		t.Fatalf("post-teardown refusal did not leave retry debt armed: unknown=%v debt=%v adopted=%d published=%d",
			unknown, debt, adoptedGeneration, published)
	}
}
