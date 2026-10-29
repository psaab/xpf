// RED-on-revert net for #6385 (local console surface): the local CLI
// `show system services` renderer (cli_show_system.go showSystemServices) must
// report the EFFECTIVE (post-clamp, post-bind) management-listener addresses
// from the shared daemon-owned snapshot (SetListenersFn ->
// Daemon.effectiveListeners), the SAME source the remote gRPC renderer reads,
// not the fixed `127.0.0.1:50051 (always on)` / `127.0.0.1:8080 (always on)`
// defaults it used to print unconditionally. Pairs with the gRPC-path net in
// pkg/grpcapi/server_show_system_listeners_6385_test.go so BOTH surfaces are
// covered — the local/remote divergence is exactly what dropped the #6384
// A10-b2-F5 attempt.
//
// Reverting the render substitution makes this go RED: the relocated gRPC bind
// and the "disabled" HTTP state vanish and the hardcoded defaults reappear.
package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/sysservices"
)

func newCLIActiveConfigStore(t *testing.T) *CLI {
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
	return &CLI{store: store, sshdStateFn: func() sysservices.SSHDState { return sysservices.SSHDRunning }}
}

// TestShowSystemServicesEffectiveListenersLocal pins the local console renderer
// to the effective listener snapshot: a relocated gRPC bind and a disabled HTTP
// REST listener, never the hardcoded requested defaults.
func TestShowSystemServicesEffectiveListenersLocal(t *testing.T) {
	c := newCLIActiveConfigStore(t)
	c.listenersFn = func() sysservices.Listeners {
		return sysservices.Listeners{
			GRPC: sysservices.Listener{Addr: "127.0.0.1:50055", State: sysservices.StateListening},
			HTTP: sysservices.Listener{State: sysservices.StateDisabled},
		}
	}

	out := captureStdout(t, func() {
		if err := c.showSystemServices(); err != nil {
			t.Fatalf("showSystemServices(): %v", err)
		}
	})

	if !strings.Contains(out, "gRPC:           127.0.0.1:50055") {
		t.Errorf("gRPC listener not reported at its EFFECTIVE bind 127.0.0.1:50055:\n%s", out)
	}
	if !strings.Contains(out, "HTTP REST:      disabled") {
		t.Errorf("disabled HTTP REST listener not reported as disabled:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:8080") {
		t.Errorf("renderer still emits the hardcoded 127.0.0.1:8080 default:\n%s", out)
	}
	if strings.Contains(out, "always on") {
		t.Errorf("renderer still emits the stale (always on) suffix:\n%s", out)
	}
}

// TestShowSystemServicesListenersFnNilFallbackLocal pins the offline / no-daemon
// fallback: with no snapshot source wired the renderer falls back to the
// documented loopback defaults so the output shape is preserved off-daemon.
func TestShowSystemServicesListenersFnNilFallbackLocal(t *testing.T) {
	c := newCLIActiveConfigStore(t) // listenersFn left nil
	out := captureStdout(t, func() {
		if err := c.showSystemServices(); err != nil {
			t.Fatalf("showSystemServices(): %v", err)
		}
	})
	if !strings.Contains(out, "gRPC:           127.0.0.1:50051") {
		t.Errorf("nil-fn fallback dropped the default gRPC listener:\n%s", out)
	}
	if !strings.Contains(out, "HTTP REST:      127.0.0.1:8080") {
		t.Errorf("nil-fn fallback dropped the default HTTP REST listener:\n%s", out)
	}
}
