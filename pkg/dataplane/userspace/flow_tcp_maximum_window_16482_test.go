package userspace

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16482: tcp_maximum_window is a Rust u32 wire field added after #1977
// (#15753) without a buildFlowSnapshot coercion. A value above u32::MAX
// arriving via a tolerant ingress path (Store.Load of a hand-edited DB,
// SyncApply from a peer with a wider range) made the helper's serde decode
// of the whole apply_snapshot fail, leaving it unconfigured. The overflow
// must be capped to the schema ceiling 1048576 with a warning; 65536 must
// pass unchanged, and the wire JSON must decode as u32.
func TestTCPMaximumWindowCoerced16482(t *testing.T) {
	// Overflow: 5,000,000,000 > u32::MAX (4294967295).
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{MaximumWindow: 5000000000}
	snap := buildFlowSnapshot(cfg)
	if snap.TCPMaximumWindow != maxTCPMaximumWindow {
		t.Fatalf("overflow TCPMaximumWindow = %d, want cap %d", snap.TCPMaximumWindow, maxTCPMaximumWindow)
	}
	if !strings.Contains(buf.String(), "tcp_maximum_window") {
		t.Fatalf("overflow coercion did not warn for tcp_maximum_window: %q", buf.String())
	}

	// Wire JSON must fit the Rust u32 field.
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		TCPMaximumWindow uint32 `json:"tcp_maximum_window"`
	}
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("wire tcp_maximum_window does not decode as u32: %v (wire %s)", err, wire)
	}
	if decoded.TCPMaximumWindow != maxTCPMaximumWindow {
		t.Fatalf("wire tcp_maximum_window = %d, want %d", decoded.TCPMaximumWindow, maxTCPMaximumWindow)
	}

	// In-range value passes unchanged.
	cfg2 := &config.Config{}
	cfg2.Security.Flow.TCPSession = &config.TCPSessionConfig{MaximumWindow: 65536}
	if got := buildFlowSnapshot(cfg2).TCPMaximumWindow; got != 65536 {
		t.Fatalf("in-range TCPMaximumWindow altered: %d, want 65536", got)
	}

	// Unset stays omitted (0 = Rust default 65535).
	if got := buildFlowSnapshot(&config.Config{}).TCPMaximumWindow; got != 0 {
		t.Fatalf("unset TCPMaximumWindow = %d, want 0", got)
	}
}
