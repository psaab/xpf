package logging

import (
	"io"
	"log/slog"
	"testing"
)

// #16767: SetClientsPreserving must not close a client that appears in
// both the old and next sets (SetClients closes every old client,
// including the preserved identity — the pre-fix behaviour).
func TestSetClientsPreservingKeepsSharedClient16767(t *testing.T) {
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	shared := &SyslogClient{}
	oldOnly := &SyslogClient{}
	fresh := &SyslogClient{}

	h.SetClients([]*SyslogClient{shared, oldOnly})
	h.SetClientsPreserving([]*SyslogClient{shared, fresh})

	if shared.closed.Load() {
		t.Fatal("#16767: preserved client was closed by SetClientsPreserving")
	}
	if !oldOnly.closed.Load() {
		t.Fatal("control: superseded-only client must be closed")
	}
	got := h.Clients()
	if len(got) != 2 || got[0] != shared || got[1] != fresh {
		t.Fatalf("installed = %v, want [shared fresh]", got)
	}

	// Control: plain SetClients DOES close the shared identity — the
	// asymmetry is the fix, so pin both sides.
	h2 := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	shared2 := &SyslogClient{}
	h2.SetClients([]*SyslogClient{shared2})
	h2.SetClients([]*SyslogClient{shared2})
	if !shared2.closed.Load() {
		t.Fatal("control: SetClients must close even an identical old client")
	}
}
