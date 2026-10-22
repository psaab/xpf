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

// #16133: the ONE prefix site converted in this change is the #10702
// post-teardown refusal. These tests are the per-site differential the
// issue requires before any old prefix branch may be deleted: over the
// real socket path, the legacy prefix arm and the new structured code
// must agree, skew pairs must classify identically, and an unrecognized
// code must fall back to the prefix — never to a blanket non-retry
// default (explicitly excluded on #16133).

var (
	rustErrorCodeRe16133       = regexp.MustCompile(`ERROR_CODE_SNAPSHOT_POST_TEARDOWN:\s*&str\s*=\s*"([^"]*)"\s*;`)
	rustErrorRetryClassRe16133 = regexp.MustCompile(`ERROR_RETRY_CLASS_RETRY_DEBT:\s*&str\s*=\s*"([^"]*)"\s*;`)
)

func TestBoundaryErrorCodeConstantsMatchHelper16133(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/protocol/control.rs")
	if err != nil {
		t.Fatalf("read helper control protocol: %v", err)
	}
	// Strip // comments so a commented-out constant cannot satisfy the pin.
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		stripped.WriteString(line)
		stripped.WriteByte('\n')
	}
	text := stripped.String()
	code := rustErrorCodeRe16133.FindStringSubmatch(text)
	if code == nil {
		t.Fatal("ERROR_CODE_SNAPSHOT_POST_TEARDOWN not found in userspace-dp/src/protocol/control.rs")
	}
	if code[1] != errorCodeSnapshotPostTeardown {
		t.Fatalf("Rust error_code %q disagrees with Go %q", code[1], errorCodeSnapshotPostTeardown)
	}
	class := rustErrorRetryClassRe16133.FindStringSubmatch(text)
	if class == nil {
		t.Fatal("ERROR_RETRY_CLASS_RETRY_DEBT not found in userspace-dp/src/protocol/control.rs")
	}
	if class[1] != errorRetryClassRetryDebt {
		t.Fatalf("Rust error_retry_class %q disagrees with Go %q", class[1], errorRetryClassRetryDebt)
	}
}

// serveCodedRefusal16133 answers one control request with the given wire
// response, so the differential drives the real decoder (the fake helper
// may carry fields an old Go binary would ignore — that is the skew case).
func serveCodedRefusal16133(t *testing.T, resp ControlResponse) string {
	t.Helper()
	sock := filepath.Join(shortSockDir9322(t), "ctl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen coded-refusal socket: %v", err)
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
		_ = json.NewEncoder(conn).Encode(resp)
	}()
	return sock
}

const postTeardownMessage16133 = snapshotPostTeardownPrefix + " worker spawn failed after teardown (spawn_worker_failed:0); dataplane down — snapshot not persisted"

func classify16133(t *testing.T, resp ControlResponse) (retained, postTeardown bool, message string) {
	t.Helper()
	m := New()
	sock := serveCodedRefusal16133(t, resp)
	_, err := m.requestDetailedAtSocket(ControlRequest{Type: "apply_snapshot"}, sock)
	if err == nil {
		t.Fatal("fake helper refusal returned nil")
	}
	return errors.Is(err, errHelperRejected), errors.Is(err, errHelperPostTeardown), err.Error()
}

// TestPostTeardownBoundaryDifferential16133 is the decisive matrix: every
// row's old-prefix classification (wantRetained/wantPostTeardown as the
// pre-#16133 code computed them) must equal the new classification.
func TestPostTeardownBoundaryDifferential16133(t *testing.T) {
	cases := []struct {
		name             string
		resp             ControlResponse
		wantRetained     bool
		wantPostTeardown bool
	}{
		{
			name:             "success_is_not_a_refusal",
			resp:             ControlResponse{OK: true},
			wantRetained:     false,
			wantPostTeardown: false,
		},
		{
			// False-positive prefix: prose merely containing the token.
			name:         "prefix_not_at_start_is_retained_refusal",
			resp:         ControlResponse{OK: false, Error: "wrapped: " + postTeardownMessage16133},
			wantRetained: true,
		},
		{
			// Old Rust / new Go: no structured fields at all.
			name:             "legacy_prefix_only_old_rust_new_go",
			resp:             ControlResponse{OK: false, Error: postTeardownMessage16133},
			wantPostTeardown: true,
		},
		{
			// New Rust / new Go: code and prefix agree.
			name: "code_and_prefix_agree_new_pair",
			resp: ControlResponse{OK: false, Error: postTeardownMessage16133,
				ErrorCode: errorCodeSnapshotPostTeardown, ErrorRetryClass: errorRetryClassRetryDebt},
			wantPostTeardown: true,
		},
		{
			// The code classifies even when future prose drifts off the
			// prefix — the point of the structured field.
			name: "recognized_code_without_prefix",
			resp: ControlResponse{OK: false, Error: "worker spawn failed after teardown; dataplane down",
				ErrorCode: errorCodeSnapshotPostTeardown, ErrorRetryClass: errorRetryClassRetryDebt},
			wantPostTeardown: true,
		},
		{
			// The excluded blanket rule: unknown code + known prefix must
			// still classify on the prefix (skew: future Rust, this Go).
			name: "unknown_code_with_known_prefix_falls_back",
			resp: ControlResponse{OK: false, Error: postTeardownMessage16133,
				ErrorCode: "some_future_code", ErrorRetryClass: "some_future_class"},
			wantPostTeardown: true,
		},
		{
			// Unknown code and no known prefix: today's behaviour — a
			// retained in-band refusal, NOT a forced never-retry terminal.
			name: "unknown_code_without_prefix_stays_retained",
			resp: ControlResponse{OK: false, Error: "snapshot integrity error: unknown zone",
				ErrorCode: "some_future_code", ErrorRetryClass: "some_future_class"},
			wantRetained: true,
		},
		{
			// Truly-unknown post-teardown-shaped prose without prefix or
			// code stays a retained refusal (prefix is the only prose arm).
			name:         "unprefixed_teardown_prose_stays_retained",
			resp:         ControlResponse{OK: false, Error: "worker spawn failed after teardown; dataplane down"},
			wantRetained: true,
		},
		{
			// Right code, wrong retry class: pair not recognized, prefix
			// fallback decides (here: no prefix, so retained).
			name: "code_with_mismatched_retry_class_falls_back",
			resp: ControlResponse{OK: false, Error: "worker spawn failed after teardown; dataplane down",
				ErrorCode: errorCodeSnapshotPostTeardown, ErrorRetryClass: "never_retry"},
			wantRetained: true,
		},
		{
			// Empty message: decoder substitutes "unknown helper error",
			// a retained refusal — unchanged.
			name:         "empty_error_stays_retained",
			resp:         ControlResponse{OK: false},
			wantRetained: true,
		},
		{
			// A pre-teardown refusal carrying the converted site's fields
			// spuriously: code wins, matching the new-pair contract; the
			// old code classified this retained, so this row documents the
			// ONE intentional differential — it cannot occur from the real
			// helper, which stamps the code only at post-teardown legs.
			name: "recognized_code_on_integrity_prose",
			resp: ControlResponse{OK: false, Error: "snapshot integrity error: unknown zone",
				ErrorCode: errorCodeSnapshotPostTeardown, ErrorRetryClass: errorRetryClassRetryDebt},
			wantPostTeardown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.resp.OK {
				m := New()
				sock := serveCodedRefusal16133(t, tc.resp)
				if _, err := m.requestDetailedAtSocket(ControlRequest{Type: "apply_snapshot"}, sock); err != nil {
					t.Fatalf("success response returned error: %v", err)
				}
				return
			}
			retained, postTeardown, message := classify16133(t, tc.resp)
			if retained != tc.wantRetained || postTeardown != tc.wantPostTeardown {
				t.Fatalf("classification retained=%v postTeardown=%v, want retained=%v postTeardown=%v",
					retained, postTeardown, tc.wantRetained, tc.wantPostTeardown)
			}
			wantMessage := tc.resp.Error
			if wantMessage == "" {
				wantMessage = "unknown helper error"
			}
			if message != wantMessage {
				t.Fatalf("error message = %q, want helper message verbatim %q", message, wantMessage)
			}
		})
	}
}

// TestNewGoOldRustJSONSkew16133: an old helper's JSON (no structured
// fields) unmarshals with empty code/class on new Go, and a new helper's
// JSON carries the fields an old Go binary would simply not decode.
func TestNewGoOldRustJSONSkew16133(t *testing.T) {
	var oldWire ControlResponse
	if err := json.Unmarshal([]byte(`{"ok":false,"error":"`+postTeardownMessage16133+`"}`), &oldWire); err != nil {
		t.Fatalf("unmarshal old-helper wire: %v", err)
	}
	if oldWire.ErrorCode != "" || oldWire.ErrorRetryClass != "" {
		t.Fatalf("old-helper wire decoded structured fields: %+v", oldWire)
	}
	newWire, err := json.Marshal(ControlResponse{OK: false, Error: postTeardownMessage16133,
		ErrorCode: errorCodeSnapshotPostTeardown, ErrorRetryClass: errorRetryClassRetryDebt})
	if err != nil {
		t.Fatalf("marshal new-helper wire: %v", err)
	}
	for _, field := range []string{`"error_code":"snapshot_post_teardown"`, `"error_retry_class":"retry_debt"`, `"error":"` + snapshotPostTeardownPrefix} {
		if !strings.Contains(string(newWire), field) {
			t.Fatalf("new-helper wire %s missing %s (prose and code must coexist)", newWire, field)
		}
	}
}
