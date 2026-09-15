package logging

import (
	"io"
	"log/slog"
	"testing"
)

// #9916 F-056: derived handlers must observe client swaps.
//
// WithAttrs/WithGroup snapshot h.clients WITHOUT h.mu (a -race report) and never
// refresh, so every previously derived slog.With(...) logger keeps forwarding to
// CLOSED clients after a reconfigure. The fix shares the client set by pointer;
// this cell pins that a derived handler sees the post-reconfigure set.
func TestSyslogDerivedSeesReconfigure9916(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, nil)
	h := NewSyslogSlogHandler(base)

	a := &SyslogClient{}
	h.SetClients([]*SyslogClient{a})

	derivedAttrs := h.WithAttrs([]slog.Attr{slog.String("k", "v")}).(*SyslogSlogHandler)
	derivedGroup := h.WithGroup("g").(*SyslogSlogHandler)

	// Control: before the swap both derivatives see A.
	if got := derivedAttrs.Clients(); len(got) != 1 || got[0] != a {
		t.Fatalf("pre-swap derivedAttrs clients = %v, want [A]", got)
	}
	if got := derivedGroup.Clients(); len(got) != 1 || got[0] != a {
		t.Fatalf("pre-swap derivedGroup clients = %v, want [A]", got)
	}

	b := &SyslogClient{}
	h.SetClients([]*SyslogClient{b})

	// Post-swap both derivatives must see B, not the closed A.
	if got := derivedAttrs.Clients(); len(got) != 1 || got[0] != b {
		t.Fatalf("post-swap derivedAttrs clients = %v, want [B] — derived handler pins closed clients (#9916 F-056)", got)
	}
	if got := derivedGroup.Clients(); len(got) != 1 || got[0] != b {
		t.Fatalf("post-swap derivedGroup clients = %v, want [B] — derived handler pins closed clients (#9916 F-056)", got)
	}
	// Root sees B as well (sanity).
	if got := h.Clients(); len(got) != 1 || got[0] != b {
		t.Fatalf("post-swap root clients = %v, want [B]", got)
	}
}
