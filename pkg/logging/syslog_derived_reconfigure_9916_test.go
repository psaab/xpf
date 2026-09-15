package logging

import (
	"context"
	"io"
	"log/slog"
	"sync"
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

// #9916 F-056 (race half, parent-review follow-up): the sequential cell above
// checks Clients(), not forwarding, and never runs the race gate. WithAttrs /
// WithGroup read h.clients without h.mu while SetClients writes under it — hammer
// reconfigure against derive + forward concurrently and run with -race. Clients
// are severity-none so Handle exercises the snapshot path without touching the
// network; the race is on the slice header, which this still covers.
func TestSyslogConcurrentReconfigureRaceFree9916(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, nil)
	h := NewSyslogSlogHandler(base)
	h.SetClients([]*SyslogClient{{MinSeverity: SeverityNone}})

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 200 {
				switch (g + i) % 4 {
				case 0:
					h.SetClients([]*SyslogClient{{MinSeverity: SeverityNone}, {MinSeverity: SeverityNone}})
				case 1:
					_ = h.WithAttrs([]slog.Attr{slog.Int("i", i)})
				case 2:
					_ = h.WithGroup("g")
				case 3:
					_ = h.Handle(context.Background(), slog.Record{})
					_ = h.Clients()
				}
			}
		}(g)
	}
	wg.Wait()
}

// #9916 F-056 (SPARK-1): SetClients copies the caller's slice. The whole lineage
// now shares one set, so a caller-side mutation of the passed backing array would
// race every reader; the copy severs that alias.
func TestSyslogSetClientsCopiesSlice9916(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, nil)
	h := NewSyslogSlogHandler(base)

	a := &SyslogClient{}
	passed := []*SyslogClient{a}
	h.SetClients(passed)
	derived := h.WithAttrs([]slog.Attr{slog.String("k", "v")}).(*SyslogSlogHandler)

	// Caller mutates after the call; neither root nor derived may observe it.
	passed[0] = &SyslogClient{}
	if got := h.Clients(); len(got) != 1 || got[0] != a {
		t.Fatalf("root observed caller-side slice mutation — SetClients must copy (#9916 F-056)")
	}
	if got := derived.Clients(); len(got) != 1 || got[0] != a {
		t.Fatalf("derived observed caller-side slice mutation — SetClients must copy (#9916 F-056)")
	}
}
