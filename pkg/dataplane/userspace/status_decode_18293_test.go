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
	"sync"
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
// 35 polls answered undecodable -> decode counter advances, no silence is
// recorded, no kill. The manager's proc is the test process itself, so a
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
		m.mu.Unlock()
		// #18685: silence and kills live in the round-trip tracker.
		m.liveTrack.mu.Lock()
		failures := m.liveTrack.silentTrips
		m.liveTrack.mu.Unlock()
		kills := m.liveTrack.kills.Load()
		if dec >= uint64(35) {
			if failures != 0 {
				t.Fatalf("wedge failures = %d after %d undecodable answers, want 0", failures, dec)
			}
			if kills != 0 {
				t.Fatalf("kills = %d, want 0", kills)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("decodeErrors = %d after 5s, want >= 35 (loop not polling the undecodable helper?)", dec)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stallingStatusSocket18293 serves a unix socket whose per-connection
// behavior is scripted by handler. The handler receives the accepted
// conn after the request has been read; it decides what (if anything)
// to write. Returning holds the conn open only via the handler itself;
// handlers that stall block until the client deadline closes the conn.
func stallingStatusSocket18293(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "x18293stall")
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
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				var req ControlRequest
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				handler(c)
			}(conn)
		}
	}()
	return sock
}

// TestStatusStalledHelperIsSilence18293 is the Rev18296 blocker cell: a
// helper that accepts and then never writes (or writes a partial prefix
// and stalls) makes the status poll hit the read deadline. That is the
// canonical #9651 wedge shape and MUST stay untagged silence — not
// errStatusDecode — so statusLoop's wedge counter can advance and kill
// it. Each poll here costs one controlBaseDeadline (3s); the assertion
// is on classification and wedge-countability, not wall-clock speed.
func TestStatusStalledHelperIsSilence18293(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func(net.Conn)
	}{
		{"never_writes", func(c net.Conn) {
			// Hold the conn open without writing; block until the
			// client's deadline closes it (read returns an error).
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}},
		{"one_byte_then_stalls", func(c net.Conn) {
			_, _ = c.Write([]byte("{"))
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := stallingStatusSocket18293(t, tc.handler)
			m := New()
			_, err := m.requestDetailedAtSocket(ControlRequest{Type: "status"}, sock)
			if err == nil {
				t.Fatal("stalled helper returned nil error")
			}
			if errors.Is(err, errStatusDecode) {
				t.Fatalf("stalled helper = %v, misclassified as decode failure; a read timeout is silence and must stay wedge-countable", err)
			}
			if !isStatusReadTimeout(err) {
				t.Fatalf("stalled helper error = %v (%T), want a read-timeout in the chain", err, err)
			}
			// Wedge-countable through the real round-trip site (#18685):
			// the call itself recorded one silent round trip, and the
			// decode counter did not move.
			m.liveTrack.mu.Lock()
			silent, since := m.liveTrack.silentTrips, m.liveTrack.silentSince
			m.liveTrack.mu.Unlock()
			if silent != 1 || since.IsZero() {
				t.Fatalf("tracker after one stalled round trip: silentTrips=%d silentSince=%v, want 1 and set (timeout must count as silence)", silent, since)
			}
			if m.liveness.decodeErrors != 0 {
				t.Fatalf("stalled poll moved the decode counter: %d, want 0", m.liveness.decodeErrors)
			}
		})
	}
}

// TestStatusLoopSilentDecodeSilentSequence18293 is the loop-level mixed
// sequence: through the REAL statusLoop + real socket, silent (stall)
// polls advance the wedge streak, an interleaved undecodable answer
// neither advances nor resets it, and further silent polls keep
// advancing it. Each silent poll pays the base control deadline, so
// the test asserts streak STATE after a bounded number of ticks
// rather than a kill. The kill itself is pinned at the counter level
// by TestDecodeFailureNeitherAdvancesNorResetsSilence18293 and
// TestSilentHelperStillKilledOnSchedule18293; here m.proc is the test
// process, so reaching the kill threshold would SIGKILL the runner —
// the sequence deliberately stays below it.
func TestStatusLoopSilentDecodeSilentSequence18293(t *testing.T) {
	// Script per connection: stall, stall, undecodable, stall.
	// stall = write nothing and hold; undecodable = the drift payload.
	var mu sync.Mutex
	calls := 0
	sock := stallingStatusSocket18293(t, func(c net.Conn) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 3 {
			_, _ = c.Write([]byte(undecodableStatusPayload18293))
			return
		}
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // stall until client deadline closes
	})

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

	// Silent polls each take ~controlBaseDeadline; wait until the loop
	// has consumed at least the 4 scripted connections (2 silent +
	// 1 decode + 1 silent) and the streak reflects them: failures==3,
	// decodeErrors==1, kills==0.
	deadline := time.Now().Add(30 * time.Second)
	for {
		m.mu.Lock()
		dec := m.liveness.decodeErrors
		m.mu.Unlock()
		m.liveTrack.mu.Lock()
		failures := m.liveTrack.silentTrips
		m.liveTrack.mu.Unlock()
		kills := m.liveTrack.kills.Load()
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 4 && failures == 3 && dec == 1 {
			if kills != 0 {
				t.Fatalf("kills = %d, want 0", kills)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 30s: calls=%d failures=%d decodeErrors=%d kills=%d, want calls>=4 failures=3 decodeErrors=1 kills=0 (silent->decode->silent through statusLoop)", n, failures, dec, kills)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
