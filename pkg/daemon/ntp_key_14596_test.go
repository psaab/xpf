package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14596 renderer half: renderChronySources must never emit chrony
// `key <n>` — xpf writes no keyfile, so chronyd would log "Key n is
// missing" and never poll the source. The compiler strips unenforceable
// keys into SystemConfig.NTPServerKeyIDs; this pins the renderer belt
// for leniently-loaded / peer-synced configs that still carry a Key in
// NTPServerOptions (the #4902 render-belt shape).
func TestRenderChronySourcesStripsKey14596(t *testing.T) {
	opts := map[string]config.NTPServerOption{
		"192.0.2.1": {Key: 5, Version: 4, Prefer: true},
		"192.0.2.2": {Key: 7},
	}
	got := renderChronySources([]string{"192.0.2.1", "192.0.2.2"}, opts)
	if strings.Contains(got, "key") {
		t.Fatalf("rendered chrony sources contain `key` with no keyfile "+
			"behind it, so chronyd never polls those sources (#14596):\n%s", got)
	}
	want := "server 192.0.2.1 iburst version 4 prefer\nserver 192.0.2.2 iburst\n"
	if got != want {
		t.Fatalf("renderChronySources() = %q, want %q (key stripped, other modifiers preserved)", got, want)
	}
}

// Control: keyless rendering is byte-identical to before.
func TestRenderChronySourcesKeylessUnchanged14596(t *testing.T) {
	got := renderChronySources([]string{"10.0.0.1", "pool.example.net"}, nil)
	want := "server 10.0.0.1 iburst\npool pool.example.net iburst\n"
	if got != want {
		t.Fatalf("renderChronySources() = %q, want %q", got, want)
	}
}
