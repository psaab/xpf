package dataplane

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionCountContextCancelledBeforeWalk12609(t *testing.T) {
	m := newClearTestManager(t)
	for i := uint32(0); i < 3; i++ {
		if err := m.SetSessionV4(clearTestV4Key(i, false), SessionValue{}); err != nil {
			t.Fatalf("seed v4: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v4, v6, err := m.SessionCountContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if v4 != 0 || v6 != 0 {
		t.Fatalf("counts = (%d,%d), want zero partial counts", v4, v6)
	}
}

func TestSessionCountContextLiveParity12609(t *testing.T) {
	m := newClearTestManager(t)
	for i := uint32(0); i < 3; i++ {
		if err := m.SetSessionV4(clearTestV4Key(i, false), SessionValue{}); err != nil {
			t.Fatalf("seed v4: %v", err)
		}
	}
	if err := m.SetSessionV6(clearTestV6Key(1, false), SessionValueV6{}); err != nil {
		t.Fatalf("seed v6: %v", err)
	}
	want4, want6 := m.SessionCount()
	got4, got6, err := m.SessionCountContext(context.Background())
	if err != nil || got4 != want4 || got6 != want6 {
		t.Fatalf("counts=(%d,%d,%v), want (%d,%d,nil)", got4, got6, err, want4, want6)
	}
}

type cancelAtContextErr12609 struct {
	calls atomic.Int32
	at    int32
}

func (c *cancelAtContextErr12609) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAtContextErr12609) Done() <-chan struct{}       { return nil }
func (c *cancelAtContextErr12609) Value(any) any               { return nil }
func (c *cancelAtContextErr12609) Err() error {
	if c.calls.Add(1) >= c.at {
		return context.Canceled
	}
	return nil
}

func TestSessionCountContextCancelsDuringBothFamilies12609(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancelAt int32
	}{
		{name: "v4", cancelAt: 2},
		{name: "v6", cancelAt: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newClearTestManager(t)
			for i := uint32(0); i < 2048; i++ {
				if err := m.SetSessionV4(clearTestV4Key(i, false), SessionValue{}); err != nil {
					t.Fatalf("seed v4: %v", err)
				}
				if err := m.SetSessionV6(clearTestV6Key(i, false), SessionValueV6{}); err != nil {
					t.Fatalf("seed v6: %v", err)
				}
			}
			ctx := &cancelAtContextErr12609{at: tc.cancelAt}
			v4, v6, err := m.SessionCountContext(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
			if v4 != 0 || v6 != 0 {
				t.Fatalf("partial counts = (%d,%d), want zero", v4, v6)
			}
			if got := ctx.calls.Load(); got != tc.cancelAt {
				t.Fatalf("ctx.Err calls = %d, want %d (proves no v6 pass after v4 abort)", got, tc.cancelAt)
			}
		})
	}
}
