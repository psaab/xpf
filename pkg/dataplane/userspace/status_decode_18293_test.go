package userspace

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #18293 socket + statusLoop cells: the classification must be minted on the
// REAL decoder path, not only by noteStatusPollResultLocked unit feeds. A
// fake helper answers status requests over a real unix socket; the manager
// polls it through requestDetailedAtSocket / statusLoop exactly as in
// production (controlRequestHook bypasses the decoder, so it cannot prove
// this — see TestContentConflictIsClassifiedOnTheRealSocketPath9520).

// undecodableStatusPayload18293 is a status reply whose zone id is a string
// where Go expects a number — the #18207-class wire-width/shape drift shape:
// the helper answered, Go cannot decode it.
const undecodableStatusPayload18293 = `{"ok":true,"status":{"pid":"not-a-number","started_at":"2026-01-01T00:00:00Z","control_socket":"/tmp/x.sock"}}` + "\n"

// serveStatus18293 answers every status request with payload, forever.
func serveStatus18293(t *testing.T, payload string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "x18293")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var req ControlRequest
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				_, _ = c.Write([]byte(payload))
			}(conn)
		}
	}()
	return sock
}

// TestStatusPollDecodeClassifiedOnRealSocket18293: a status poll answered
// with undecodable bytes returns an errStatusDecode error carrying the
// decoder's message; a non-status verb answered the same way does NOT get
// the class (the tag is status-only).
func TestStatusPollDecodeClassifiedOnRealSocket18293(t *testing.T) {
	sock := serveStatus18293(t, undecodableStatusPayload18293)
	m := New()
	_, err := m.requestDetailedAtSocket(ControlRequest{Type: "status"}, sock)
	if err == nil {
		t.Fatal("undecodable status reply returned nil error")
	}
	if !errors.Is(err, errStatusDecode) {
		t.Fatalf("status poll error = %v, want errStatusDecode class", err)
	}
	if !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Fatalf("status poll error = %q, want the decoder's message preserved", err.Error())
	}
	// Same bytes, different verb: no decode class.
	_, err = m.requestDetailedAtSocket(ControlRequest{Type: "ping"}, sock)
	if err == nil {
		t.Fatal("undecodable ping reply returned nil error")
	}
	if errors.Is(err, errStatusDecode) {
		t.Fatalf("ping error = %v, must not carry the status-only decode class", err)
	}
}

// TestStatusCloseWithoutReplyIsSilence18293 is the negative control: a helper
// that accepts and closes without writing a byte (the #1961 EOF shape) is
// silence, not a decode failure — it must stay wedge-countable.
func TestStatusCloseWithoutReplyIsSilence18293(t *testing.T) {
	sock := serveStatus18293(t, "")
	// serveStatus18293 writes payload (empty) then closes: zero bytes read.
	m := New()
	_, err := m.requestDetailedAtSocket(ControlRequest{Type: "status"}, sock)
	if err == nil {
		t.Fatal("pre-reply close returned nil error")
	}
	if errors.Is(err, errStatusDecode) {
		t.Fatalf("pre-reply close = %v, misclassified as decode failure; EOF is silence", err)
	}
	if !strings.Contains(err.Error(), "closed with no response") {
		t.Fatalf("pre-reply close = %q, want the #1961 EOF sentence", err.Error())
	}
}

// TestStatusLoopUndecodableAnswersNoKill18293 drives the real statusLoop:
// >30 polls answered undecodable -> decode counter advances, wedge count
// stays zero, no kill. The manager's proc is the test process itself, so a
// wedge kill would SIGKILL the test runner — survival is part of the proof,
// and liveness state is asserted directly.
func TestStatusLoopUndecodableAnswersNoKill18293(t *testing.T) {
	sock := serveStatus18293(t, undecodableStatusPayload18293)
	old := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = old })

	m := New()
	m.cfg.ControlSocket = sock
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	m.proc = &exec.Cmd{Process: proc}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.statusLoop(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		dec := m.liveness.decodeErrors
		failures := m.liveness.failures
		kills := m.liveness.kills
		m.mu.Unlock()
		if dec >= uint64(helperWedgeFailedPolls+5) {
			if failures != 0 {
				t.Fatalf("wedge failures = %d after %d undecodable answers, want 0", failures, dec)
			}
			if kills != 0 {
				t.Fatalf("kills = %d, want 0", kills)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("decodeErrors = %d after 5s, want >= %d (loop not polling the undecodable helper?)", dec, helperWedgeFailedPolls+5)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
