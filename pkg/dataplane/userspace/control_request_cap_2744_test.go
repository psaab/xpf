package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// oldControlRequestCapBytes is the pre-#2744 control-socket ceiling. It is
// hard-coded (NOT derived from MaxControlRequestBytes) so the fail-on-revert
// assertions below go RED if the cap is reverted to 16 MiB.
const oldControlRequestCapBytes = 16 * 1024 * 1024

// TestControlRequestCapRaisedAbove16MiB is the #2744 fail-on-revert proof.
// A legitimate feed-heavy request between the old 16 MiB ceiling and the new
// 64 MiB cap must now be accepted (round-trip through the control socket); a
// request past the new cap must still be rejected by the pre-flight guard with
// an actionable, operator-facing diagnostic.
func TestControlRequestCapRaisedAbove16MiB(t *testing.T) {
	if MaxControlRequestBytes <= oldControlRequestCapBytes {
		t.Fatalf("cap must be raised above the old 16 MiB ceiling, got %d", MaxControlRequestBytes)
	}

	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	gotType := make(chan string, 1)
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
		gotType <- req.Type
		_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	// A body ~4 MiB above the old 16 MiB cap — over the OLD ceiling, under
	// the NEW one. Pad the Type string so the serialized request crosses
	// 16 MiB. This models a large-but-legitimate feed-backed apply_snapshot.
	padLen := oldControlRequestCapBytes + 4*1024*1024
	req := ControlRequest{Type: "x" + strings.Repeat("y", padLen)}
	body, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(body) <= oldControlRequestCapBytes {
		t.Fatalf("test body %d must exceed the old 16 MiB cap to prove the raise", len(body))
	}
	if len(body) > MaxControlRequestBytes {
		t.Fatalf("test body %d must stay within the raised cap %d", len(body), MaxControlRequestBytes)
	}

	m.mu.Lock()
	_, err = m.requestDetailedLocked(req)
	m.mu.Unlock()
	if err != nil {
		// Under the old 16 MiB cap the pre-flight would have rejected this
		// before dialing; under #2744 it must pass the gate and round-trip.
		t.Fatalf("legitimate feed-heavy request above old 16 MiB cap was rejected: %v", err)
	}
	select {
	case typ := <-gotType:
		if !strings.HasPrefix(typ, "xy") {
			t.Fatalf("server received unexpected request type prefix: %.8q", typ)
		}
	default:
		t.Fatalf("server never received the request — it did not round-trip")
	}
}

// TestControlRequestAboveNewCapStillRejected proves the DoS guard survives the
// raise: a request past the new cap is rejected by the Go pre-flight with an
// actionable error, before any control-socket dial.
func TestControlRequestAboveNewCapStillRejected(t *testing.T) {
	m := New()
	// No control socket configured: if the pre-flight did NOT fire first,
	// requestDetailedLocked would fail with "control socket not configured".
	// Instead it must fail with the size-limit diagnostic, proving the guard
	// runs before the dial.
	m.cfg.ControlSocket = "/tmp/xpf-2744-nonexistent.sock"

	padLen := MaxControlRequestBytes + 1024
	req := ControlRequest{Type: "x" + strings.Repeat("y", padLen)}

	m.mu.Lock()
	_, err := m.requestDetailedLocked(req)
	m.mu.Unlock()
	if err == nil {
		t.Fatal("a request past the new cap must be rejected")
	}
	if !strings.Contains(err.Error(), "exceeding the dataplane") {
		t.Fatalf("expected the size-limit diagnostic, got: %v", err)
	}
}

// TestControlRequestCapLockstepWithRust documents and pins the lockstep
// relationship between the Go request/response ceilings and the Rust
// MAX_CONTROL_REQUEST_BYTES/MAX_CONTROL_RESPONSE_BYTES. Each direction has a
// bounded body, so both pairs must be identical across the protocol boundary.
// If either ceiling changes, update the corresponding expected value here.
func TestControlRequestCapLockstepWithRust(t *testing.T) {
	const rustMaxControlRequestBytes = 64 * 1024 * 1024 // userspace-dp/src/protocol/control.rs
	if MaxControlRequestBytes != rustMaxControlRequestBytes {
		t.Fatalf("Go MaxControlRequestBytes=%d must equal Rust MAX_CONTROL_REQUEST_BYTES=%d "+
			"(lockstep, see userspace-dp/src/protocol/control.rs)",
			MaxControlRequestBytes, rustMaxControlRequestBytes)
	}
	const rustMaxControlResponseBytes = 64 * 1024 * 1024 // userspace-dp/src/protocol/control.rs
	if MaxControlResponseBytes != rustMaxControlResponseBytes {
		t.Fatalf("Go MaxControlResponseBytes=%d must equal Rust MAX_CONTROL_RESPONSE_BYTES=%d "+
			"(lockstep, see userspace-dp/src/protocol/control.rs)",
			MaxControlResponseBytes, rustMaxControlResponseBytes)
	}
}
