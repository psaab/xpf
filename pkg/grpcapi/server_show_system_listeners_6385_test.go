// RED-on-revert net for #6385/#6401: the REMOTE gRPC `show system services`
// renderer (server_show_system.go showSystemServices) — the path the remote
// `cli` binary reaches, and the one the dropped #6384 A10-b2-F5 attempt left
// hardcoded — must report the EFFECTIVE management-listener STATE from the
// shared daemon-owned snapshot (Config.ListenersFn -> Daemon.effectiveListeners),
// not the fixed `127.0.0.1:50051 (always on)` / `127.0.0.1:8080 (always on)`
// defaults it used to print unconditionally.
//
// #6401 fold: the snapshot carries per-listener STATE (Listening/Failed/
// Disabled), so a CONFIGURED-but-FAILED bind is not misreported. This file also
// pins the gRPC server's own EffectiveListener state machine (bind failure and
// the pre-bind -> listening -> serve-exit lifecycle), the signal
// Daemon.effectiveListeners reads for the gRPC row.
package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/sysservices"
)

// newActiveConfigServer builds a Server whose store has a committed (non-nil)
// active config, so showSystemServices proceeds past its nil-config guard.
func newActiveConfigServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet("set system host-name xpf-test"); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &Server{store: store}
}

// TestShowSystemServicesEffectiveListenersGRPC pins that the gRPC renderer
// reports the effective listener snapshot: a relocated gRPC bind and a disabled
// HTTP REST listener, never the hardcoded requested defaults.
func TestShowSystemServicesEffectiveListenersGRPC(t *testing.T) {
	s := newActiveConfigServer(t)
	// A relocated gRPC bind (Listening) + a disabled HTTP REST listener — neither
	// of which the pre-#6385 hardcoded renderer could ever produce.
	s.listenersFn = func() sysservices.Listeners {
		return sysservices.Listeners{
			GRPC: sysservices.Listener{Addr: "127.0.0.1:50055", State: sysservices.StateListening},
			HTTP: sysservices.Listener{State: sysservices.StateDisabled},
		}
	}

	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()

	if !strings.Contains(out, "gRPC:           127.0.0.1:50055") {
		t.Errorf("gRPC listener not reported at its EFFECTIVE bind 127.0.0.1:50055:\n%s", out)
	}
	// An empty --api-addr disables the REST listener; it must render "disabled",
	// not the fixed `127.0.0.1:8080 (always on)`.
	if !strings.Contains(out, "HTTP REST:      disabled") {
		t.Errorf("disabled HTTP REST listener not reported as disabled:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:8080") {
		t.Errorf("renderer still emits the hardcoded 127.0.0.1:8080 default:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:50051") {
		t.Errorf("renderer still emits the hardcoded 127.0.0.1:50051 default:\n%s", out)
	}
	if strings.Contains(out, "always on") {
		t.Errorf("renderer still emits the stale (always on) suffix:\n%s", out)
	}
}

func TestShowSystemServicesAPIAuthCredentialCounts10826(t *testing.T) {
	tests := []struct {
		name     string
		commands []string
		want     string
	}{
		{
			name: "named key only",
			commands: []string{
				"set system services web-management api-auth expires 2099-01-01",
				"set system services web-management api-auth key automation secret automation-key-secret-012345",
			},
			want: "API auth:       0 user(s), 1 API key(s)",
		},
		{
			name: "mixed named and legacy credentials",
			commands: []string{
				"set system services web-management api-auth expires 2099-01-01",
				"set system services web-management api-auth user admin password very-long-password-10826",
				"set system services web-management api-auth api-key machine-generated-key-10826",
				"set system services web-management api-auth key automation secret automation-key-secret-012345",
			},
			want: "API auth:       1 user(s), 2 API key(s)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure(): %v", err)
			}
			commands := append([]string{"set system host-name xpf-test"}, tc.commands...)
			for _, command := range commands {
				if _, err := store.LoadSet(command); err != nil {
					t.Fatalf("LoadSet(%q): %v", command, err)
				}
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit(): %v", err)
			}
			s := &Server{store: store}
			var buf strings.Builder
			s.showSystemServices(&buf)
			if out := buf.String(); !strings.Contains(out, tc.want) {
				t.Fatalf("remote API-auth credential counts = %q, want %q:\n%s", out, tc.want, out)
			}
		})
	}
}

// TestShowSystemServicesFailedHTTPGRPC pins the #6401 fold on the remote path:
// a CONFIGURED-but-FAILED HTTP bind renders "(bind failed)", distinct from the
// "disabled" a genuinely-off listener renders.
func TestShowSystemServicesFailedHTTPGRPC(t *testing.T) {
	s := newActiveConfigServer(t)
	s.listenersFn = func() sysservices.Listeners {
		return sysservices.Listeners{
			GRPC: sysservices.Listener{Addr: "127.0.0.1:50051", State: sysservices.StateListening},
			HTTP: sysservices.Listener{Addr: "192.0.2.1:8080", State: sysservices.StateFailed},
		}
	}
	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()
	if !strings.Contains(out, "HTTP REST:      192.0.2.1:8080 (bind failed)") {
		t.Errorf("failed HTTP bind not reported as (bind failed):\n%s", out)
	}
	if strings.Contains(out, "HTTP REST:      disabled") {
		t.Errorf("failed HTTP bind misreported as disabled:\n%s", out)
	}
}

// TestShowSystemServicesListenersFnNilFallbackGRPC pins the no-daemon fallback:
// with no snapshot source wired (a bare Server / unit-test build), the renderer
// falls back to the documented loopback defaults so the output shape is
// preserved off-daemon.
func TestShowSystemServicesListenersFnNilFallbackGRPC(t *testing.T) {
	s := newActiveConfigServer(t) // listenersFn left nil
	var buf strings.Builder
	s.showSystemServices(&buf)
	out := buf.String()
	if !strings.Contains(out, "gRPC:           127.0.0.1:50051") {
		t.Errorf("nil-fn fallback dropped the default gRPC listener:\n%s", out)
	}
	if !strings.Contains(out, "HTTP REST:      127.0.0.1:8080") {
		t.Errorf("nil-fn fallback dropped the default HTTP REST listener:\n%s", out)
	}
}

// TestGRPCEffectiveListenerBindFailure drives the real Run path against an
// already-bound address so net.Listen fails, and asserts EffectiveListener
// reports StateFailed with the requested address — NOT the requested address as
// if it were serving (the pre-#6401 behavior, where the daemon fell back to the
// requested --grpc-addr on an empty EffectiveAddr and rendered a failed listener
// as Listening).
func TestGRPCEffectiveListenerBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy addr: %v", err)
	}
	defer occupied.Close()
	addr := occupied.Addr().String()

	s := NewServer(addr, Config{})

	// #7611: Run is now SUPERVISED — a bind failure is retried with bounded
	// backoff rather than returned, so Run blocks until ctx is done. The
	// property this cell exists for is unchanged and still asserted below: a
	// listener that failed to bind must report StateFailed with the REQUESTED
	// address, never the requested address rendered as if it were serving
	// (the pre-#6401 behaviour).
	//
	// The old shape asserted `Run` returned an error. That assertion cannot
	// survive supervision and is not what #6385/#6401 are about; keeping it by
	// giving Run a pre-cancelled context would assert the shutdown path, not
	// the bind-failure path.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	var ln sysservices.Listener
	for time.Now().Before(deadline) {
		if ln = s.EffectiveListener(); ln.State == sysservices.StateFailed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if ln.State != sysservices.StateFailed {
		t.Errorf("bind-failure state = %v, want StateFailed: %+v", ln.State, ln)
	}
	if ln.Addr != addr {
		t.Errorf("failed listener addr = %q, want requested %q", ln.Addr, addr)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel — the supervisor must exit on ctx done (#7611)")
	}
}

// TestGRPCEffectiveListenerLifecycle drives the real Run path and asserts the
// pre-bind -> Listening -> serve-exit transitions: Listening reports the ACTUAL
// bound address (an ephemeral :0 resolves to a concrete port), and once the
// serve loop exits the state clears to Failed so a stale bound address is not
// reported for a dead server.
func TestGRPCEffectiveListenerLifecycle(t *testing.T) {
	const requested = "127.0.0.1:0"
	s := NewServer(requested, Config{})

	// PRE-BIND: before Run, EffectiveListener reports the requested address as
	// Listening (gRPC always binds on loopback; the tiny pre-bind window is not
	// flagged as a failure).
	if pre := s.EffectiveListener(); pre.State != sysservices.StateListening || pre.Addr != requested {
		t.Fatalf("pre-bind listener = %+v, want {Addr:%q State:Listening}", pre, requested)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Wait for the BOUND Listening state (a concrete ephemeral port), not the
	// pre-bind Listening state — which reports the requested "127.0.0.1:0" until
	// Run's net.Listen resolves it.
	var ln sysservices.Listener
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ln = s.EffectiveListener()
		if ln.State == sysservices.StateListening && !strings.HasSuffix(ln.Addr, ":0") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ln.State != sysservices.StateListening || ln.Addr == "" || strings.HasSuffix(ln.Addr, ":0") {
		cancel()
		<-done
		t.Fatalf("gRPC never reached bound Listening with a concrete port: %+v", ln)
	}
	boundAddr := ln.Addr // the concrete ephemeral port, e.g. 127.0.0.1:45321

	// SERVE EXIT: after the serve loop returns, the state must clear to Failed
	// AND the reported address must NOT be the stale concrete bound address — a
	// regression that sets Failed but retains effAddr would still render the dead
	// server at its old bound port. The cleared Failed reports the requested addr.
	cancel()
	<-done
	got := s.EffectiveListener()
	if got.State != sysservices.StateFailed {
		t.Errorf("after serve exit, state = %v, want StateFailed: %+v", got.State, got)
	}
	if got.Addr == boundAddr {
		t.Errorf("after serve exit, addr = %q still the STALE bound address (not cleared)", got.Addr)
	}
	if got.Addr != requested {
		t.Errorf("after serve exit, addr = %q, want the cleared/requested %q", got.Addr, requested)
	}
}
