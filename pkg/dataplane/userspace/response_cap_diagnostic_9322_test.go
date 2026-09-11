package userspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #9322: a helper response larger than MaxControlResponseBytes was truncated by
// the bounded reader and reported to the operator as
//
//	"the helper rejected it before replying — check the helper log for a
//	 decode/handler error"
//
// which names the WRONG COMPONENT. The helper answered; the answer did not fit;
// there is nothing in the helper log to find. Per docs/engineering-style.md a
// wrong diagnostic is worse than a missing one, because it sends the next person
// to the wrong subsystem.
//
// The in-source justification for not discriminating the two cases rested on a
// premise that is FALSE for the one verb that can reach the cap:
// MaxControlRequestBytes bounds what can be ASKED, and
// `export_owner_rg_sessions` is asked with ~60 bytes and answered with the
// UNBOUNDED owner-RG session set.
//
// These cells assert the ERROR STRING, at all three `boundedResponseReader` call
// sites, each against a positive control in the same run: a genuine pre-reply
// close must still produce the #1961 sentence. Without that pairing a cell could
// pass by making EVERY failure say "cap", which is the same defect pointed the
// other way.

// fakeHelper9322 binds an AF_UNIX socket in THIS process — so the #9003
// peer-credential check sees its own uid/pid and admits the connection — and
// replies with whatever the test asks for.
type fakeHelper9322 struct {
	ln net.Listener
}

// startFakeHelper9322 serves one reply mode. `reply` receives the accepted
// connection after the request line has been read.
func startFakeHelper9322(t *testing.T, path string, reply func(net.Conn)) *fakeHelper9322 {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	h := &fakeHelper9322{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Drain the request line so the caller's write completes.
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = c.Read(buf)
				_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
				reply(c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return h
}

// oversizeReply streams a syntactically-open JSON object well past the cap, so
// the decoder is still mid-value when the budget runs out — the shape a real
// over-cap response has.
func oversizeReply9322(c net.Conn) {
	if _, err := c.Write([]byte(`{"ok":true,"session_deltas":[`)); err != nil {
		return
	}
	// One element, repeated in 256 KiB writes, until past the EFFECTIVE cap.
	// The socket cells shrink it (smallResponseCap9697), so this crosses in
	// milliseconds instead of streaming and decoding 64 MiB.
	elem := []byte(`{"session_id":1,"owner_rg":1,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2"},`)
	chunk := make([]byte, 0, 256<<10)
	for len(chunk) < 256<<10 {
		chunk = append(chunk, elem...)
	}
	for i := int64(0); i < controlResponseCapBytes/int64(len(chunk))+2; i++ {
		if _, err := c.Write(chunk); err != nil {
			return
		}
	}
}

// smallResponseCap9697 shrinks the response cap for one cell (#9697). Crossing
// the real 64 MiB cap takes long enough under load to outrun the socket's
// round-trip deadline (3 s for the session socket and a small control
// request), and then the cell reports the deadline, not the cap. It is what
// the cell asserts, not a timing test. The cells that call it are not
// parallel, so they finish before any t.Parallel test resumes.
func smallResponseCap9697(t *testing.T) {
	t.Helper()
	prev := controlResponseCapBytes
	controlResponseCapBytes = 1 << 20
	t.Cleanup(func() { controlResponseCapBytes = prev })
}

// preReplyClose is the POSITIVE CONTROL: the helper accepts, reads the request,
// and closes without writing a byte — the #1961 shape.
func preReplyClose9322(c net.Conn) {}

func shortSockDir9322(t *testing.T) string {
	t.Helper()
	// A short prefix: t.TempDir()'s long sub-test name pushes an AF_UNIX path
	// past the 108-byte sun_path limit.
	dir, err := os.MkdirTemp("", "x9322")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func managerOnSocket9322(t *testing.T, sock string) *Manager {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	return m
}

// --- SITE 1: the control socket (requestDetailedLocked). ---
//
// This is the site the issue measured, and `export_owner_rg_sessions` is the
// verb that reaches it, so the request the cell sends is that verb rather than
// a synthetic one.
//
// RED at master: the oversize arm produces the #1961 "helper rejected it before
// replying" sentence, identical to the control arm.
func TestControlSocketNamesTheResponseCap9322(t *testing.T) {
	smallResponseCap9697(t)
	oversize := func(t *testing.T) error {
		dir := shortSockDir9322(t)
		sock := filepath.Join(dir, "c.sock")
		startFakeHelper9322(t, sock, oversizeReply9322)
		m := managerOnSocket9322(t, sock)
		m.mu.Lock()
		defer m.mu.Unlock()
		_, err := m.requestDetailedLocked(ControlRequest{
			Type:          "export_owner_rg_sessions",
			SessionExport: &SessionExportRequest{OwnerRGs: []int{1}},
		})
		return err
	}
	control := func(t *testing.T) error {
		dir := shortSockDir9322(t)
		sock := filepath.Join(dir, "c.sock")
		startFakeHelper9322(t, sock, preReplyClose9322)
		m := managerOnSocket9322(t, sock)
		m.mu.Lock()
		defer m.mu.Unlock()
		_, err := m.requestDetailedLocked(ControlRequest{
			Type:          "export_owner_rg_sessions",
			SessionExport: &SessionExportRequest{OwnerRGs: []int{1}},
		})
		return err
	}
	assertCapVsPreReplyClose9322(t, oversize, control)
}

// --- SITE 2: the session socket (requestSessionSyncLocked). ---
//
// A truncation here latches takeover-readiness through
// errSessionHelperUnreachable (#5247). The CLASSIFICATION is deliberately not
// changed by #9322 — that would be a #6785-shaped decision with HA blast radius
// — so this cell asserts the wrapper is still errSessionHelperUnreachable AND
// that the cap is now named inside it.
func TestSessionSocketNamesTheResponseCap9322(t *testing.T) {
	smallResponseCap9697(t)
	run := func(t *testing.T, reply func(net.Conn)) error {
		dir := shortSockDir9322(t)
		// sessionSocketPath() derives the session socket from the control
		// socket's DIRECTORY, so the fake must bind that exact name.
		ctrl := filepath.Join(dir, "control.sock")
		m := managerOnSocket9322(t, ctrl)
		startFakeHelper9322(t, m.sessionSocketPath(), reply)
		m.sessionMu.Lock()
		defer m.sessionMu.Unlock()
		return m.requestSessionSyncLocked(ControlRequest{Type: "session_sync"})
	}
	oversize := func(t *testing.T) error { return run(t, oversizeReply9322) }
	control := func(t *testing.T) error { return run(t, preReplyClose9322) }

	capErr := assertCapVsPreReplyClose9322(t, oversize, control)
	if !errors.Is(capErr, errSessionHelperUnreachable) {
		t.Errorf("the truncation error lost its errSessionHelperUnreachable wrapper: %v.\n"+
			"#9322 names the cause; it does not reclassify a truncation as healthy — "+
			"that would un-gate takeover-readiness (#5247) and is a #6785-shaped "+
			"decision this change does not make", capErr)
	}
}

// --- SITE 3: the boot probe (ProbeStatus). ---
//
// It returns the error BARE, so before #9322 a truncation here surfaced as an
// unadorned "unexpected EOF" with nothing naming the cap at all.
func TestBootProbeNamesTheResponseCap9322(t *testing.T) {
	smallResponseCap9697(t)
	run := func(t *testing.T, reply func(net.Conn)) error {
		dir := shortSockDir9322(t)
		sock := filepath.Join(dir, "b.sock")
		startFakeHelper9322(t, sock, reply)
		_, err := ProbeStatus(sock, 30*time.Second)
		return err
	}
	oversize := func(t *testing.T) error { return run(t, oversizeReply9322) }
	control := func(t *testing.T) error { return run(t, preReplyClose9322) }
	assertCapVsPreReplyClose9322(t, oversize, control)
}

// assertCapVsPreReplyClose9322 is the shared verdict, and it is TOTAL on
// purpose: both arms must fail, the cap arm must name the cap, and the control
// arm must NOT. A cell that only checked the cap arm would pass for a change
// that put the cap sentence on every failure.
func assertCapVsPreReplyClose9322(t *testing.T, oversize, preReplyClose func(*testing.T) error) error {
	t.Helper()

	capErr := oversize(t)
	if capErr == nil {
		t.Fatalf("an over-cap response must fail; got nil")
	}
	closeErr := preReplyClose(t)
	if closeErr == nil {
		t.Fatalf("a pre-reply close must fail; got nil")
	}

	const capMarker = "control-response cap"
	const rejectMarker = "helper rejected it before replying"

	if !strings.Contains(capErr.Error(), capMarker) {
		t.Errorf("the over-cap error does not name the cap.\n got: %v\nwant a message containing %q",
			capErr, capMarker)
	}
	if !strings.Contains(capErr.Error(), fmt.Sprintf("%d", controlResponseCapBytes)) {
		t.Errorf("the over-cap error does not name the byte ceiling: %v", capErr)
	}
	if strings.Contains(capErr.Error(), rejectMarker) {
		t.Errorf("the over-cap error still claims the helper rejected the request — that is "+
			"the wrong component, and it is what sends the operator to a helper log "+
			"with nothing in it: %v", capErr)
	}

	// POSITIVE CONTROL: the #1961 sentence must survive for the case it was
	// written for.
	if !strings.Contains(closeErr.Error(), rejectMarker) &&
		!strings.Contains(closeErr.Error(), "EOF") {
		t.Errorf("a genuine pre-reply close lost its diagnostic: %v", closeErr)
	}
	if strings.Contains(closeErr.Error(), capMarker) {
		t.Errorf("a pre-reply close is now blamed on the response cap — the cap sentence "+
			"must not become the answer to every failure: %v", closeErr)
	}
	if capErr.Error() == closeErr.Error() {
		t.Errorf("the two cases still produce the IDENTICAL sentence (%v); that is the "+
			"conflation #9322 is about", capErr)
	}
	return capErr
}

// The reader's own contract, including the arm that keeps this from being the
// same wrong diagnostic pointed the other way: a body that ends EXACTLY at the
// cap is COMPLETE, and must not be reported as truncated.
func TestLimitedResponseReaderReportsOnlyRealTruncation9322(t *testing.T) {
	t.Run("under the cap", func(t *testing.T) {
		r := boundedResponseReader(strings.NewReader(`{"ok":true}`))
		var resp ControlResponse
		if err := json.NewDecoder(r).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.truncated {
			t.Errorf("a small complete response was reported as truncated")
		}
	})

	// THE READER'S OWN CONTRACT, exercised directly rather than through
	// json.Decoder.
	//
	// This sub-case exists because the decoder-level one below is VACUOUS for
	// the branch it is about, and the mutation matrix is how I know. Mutant S2
	// (set `truncated` unconditionally once the budget is spent) SURVIVED the
	// decoder-level cell: with a body of exactly the cap, json.Decoder already
	// holds the closing brace when the budget runs out and never calls Read
	// again, so the `remaining <= 0` arm — the whole subject of S2 — is never
	// entered. The property was real and the fixture could not reach it.
	//
	// Reading exactly the cap and then calling Read once more enters that arm
	// deterministically, on both sides of the boundary.
	t.Run("reader contract at the boundary", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			extra     string
			truncated bool
		}{
			{"body ends exactly at the cap", "", false},
			{"body is one byte longer", "x", true},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				body := strings.Repeat("y", MaxControlResponseBytes) + tc.extra
				r := boundedResponseReader(strings.NewReader(body))
				buf := make([]byte, 1<<16)
				var got int64
				for got < MaxControlResponseBytes {
					n, err := r.Read(buf[:min9322(len(buf), MaxControlResponseBytes-int(got))])
					got += int64(n)
					if err != nil {
						t.Fatalf("read %d/%d bytes then %v", got, int64(MaxControlResponseBytes), err)
					}
				}
				if r.truncated {
					t.Fatalf("truncated was set before the budget was even exhausted")
				}
				// The read that enters the budget-exhausted arm.
				n, err := r.Read(buf)
				if n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("read past the cap = (%d, %v), want (0, io.EOF)", n, err)
				}
				if r.truncated != tc.truncated {
					t.Errorf("truncated = %v, want %v. A body that ends EXACTLY at the cap "+
						"is COMPLETE; reporting it as truncated is the same class of "+
						"wrong diagnostic #9322 fixes, pointed the other way",
						r.truncated, tc.truncated)
				}
			})
		}
	})

	t.Run("exactly at the cap (through the decoder)", func(t *testing.T) {
		// A body of EXACTLY MaxControlResponseBytes that is valid JSON. Padding
		// goes in a string field so the length is controllable to the byte.
		head := `{"ok":true,"error":"`
		tail := `"}`
		pad := strings.Repeat("x", MaxControlResponseBytes-len(head)-len(tail))
		body := head + pad + tail
		if len(body) != MaxControlResponseBytes {
			t.Fatalf("fixture: body is %d bytes, want exactly %d", len(body), MaxControlResponseBytes)
		}
		r := boundedResponseReader(strings.NewReader(body))
		var resp ControlResponse
		if err := json.NewDecoder(r).Decode(&resp); err != nil {
			t.Fatalf("a response of exactly the cap must decode: %v", err)
		}
		if r.truncated {
			t.Errorf("a response of EXACTLY the cap was reported as truncated. It is complete: " +
				"reporting it as truncated is the same class of wrong diagnostic #9322 " +
				"fixes, pointed the other way")
		}
	})

	t.Run("one byte over the cap", func(t *testing.T) {
		head := `{"ok":true,"error":"`
		tail := `"}`
		pad := strings.Repeat("x", MaxControlResponseBytes-len(head)-len(tail)+1)
		r := boundedResponseReader(strings.NewReader(head + pad + tail))
		var resp ControlResponse
		if err := json.NewDecoder(r).Decode(&resp); err == nil {
			t.Fatalf("a response one byte past the cap must not decode")
		}
		if !r.truncated {
			t.Errorf("a response one byte past the cap was NOT reported as truncated")
		}
	})

	t.Run("still delivers at most the cap", func(t *testing.T) {
		// The #9003 property this must not trade away.
		r := boundedResponseReader(endlessReader{})
		n, err := ioCopyDiscard9322(r)
		if err != nil {
			t.Fatalf("copy: %v", err)
		}
		if n != MaxControlResponseBytes {
			t.Fatalf("bounded reader yielded %d bytes, want exactly the %d-byte cap",
				n, MaxControlResponseBytes)
		}
		if !r.truncated {
			t.Errorf("an endless stream must be reported as truncated")
		}
	})
}

func ioCopyDiscard9322(r *limitedResponseReader) (int64, error) {
	buf := make([]byte, 1<<16)
	var total int64
	for {
		n, err := r.Read(buf)
		total += int64(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func min9322(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestResponseCapSeamDefaultsToTheConst9697 pins what the #9697 seam must
// never change: outside a cell that shrinks it, the enforced cap and the named
// cap are MaxControlResponseBytes.
func TestResponseCapSeamDefaultsToTheConst9697(t *testing.T) {
	if controlResponseCapBytes != MaxControlResponseBytes {
		t.Fatalf("controlResponseCapBytes = %d, want MaxControlResponseBytes (%d)", controlResponseCapBytes, int64(MaxControlResponseBytes))
	}
	if got := boundedResponseReader(strings.NewReader("")).remaining; got != MaxControlResponseBytes {
		t.Fatalf("boundedResponseReader budget = %d, want MaxControlResponseBytes (%d)", got, int64(MaxControlResponseBytes))
	}
	if msg := responseCapError("status", io.EOF).Error(); !strings.Contains(msg, fmt.Sprintf("%d", int64(MaxControlResponseBytes))) {
		t.Fatalf("responseCapError does not name MaxControlResponseBytes: %s", msg)
	}
}
