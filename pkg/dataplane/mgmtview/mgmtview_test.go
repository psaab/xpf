package mgmtview_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
)

// fakeBackend implements the optional caps under test.
type fakeBackend struct {
	stats   []dataplane.MapStats
	v4, v6  int
	ctxErr  error
	ctxSeen context.Context
}

func (b *fakeBackend) GetMapStats() []dataplane.MapStats { return b.stats }
func (b *fakeBackend) SessionCount() (int, int)          { return b.v4, b.v6 }
func (b *fakeBackend) SessionCountContext(ctx context.Context) (int, int, error) {
	b.ctxSeen = ctx
	return b.v4, b.v6, b.ctxErr
}

// bareBackend implements none of the optional caps.
type bareBackend struct{}

// indirection mimics pkg/daemon's liveDataPlane: its own method set
// is empty of optional caps, and Unwrap resolves the backend
// published at call time from a mutable cell.
type indirection struct{ cell *any }

func (i indirection) Unwrap() any { return *i.cell }

func TestProbeResolvesCurrentPublication(t *testing.T) {
	a := &fakeBackend{v4: 1}
	b := &fakeBackend{v4: 2}
	var cell any = a
	live := indirection{cell: &cell}

	if got := mgmtview.Probe(live); got != any(a) {
		t.Fatalf("Probe(live) = %T, want published backend A", got)
	}
	// Backend replacement: the next Probe must see B, not a cached A.
	cell = b
	if got := mgmtview.Probe(live); got != any(b) {
		t.Fatalf("Probe(live) after swap = %T, want published backend B (no caching across replacement)", got)
	}
	// Disowned: Probe fails closed to nil.
	cell = nil
	if got := mgmtview.Probe(live); got != nil {
		t.Fatalf("Probe(live) on disowned cell = %T, want nil", got)
	}
	// Plain backend is the identity; nil probes to nil.
	if got := mgmtview.Probe(a); got != any(a) {
		t.Fatalf("Probe(plain) = %T, want identity", got)
	}
	if got := mgmtview.Probe(nil); got != nil {
		t.Fatalf("Probe(nil) = %T, want nil", got)
	}
	if got := mgmtview.Unwrap(live); got != nil {
		t.Fatalf("Unwrap(live) on disowned cell = %T, want nil (same resolution as Probe)", got)
	}
	cell = a
	if got := mgmtview.Unwrap(live); got != any(a) {
		t.Fatalf("Unwrap(live) = %T, want published backend A", got)
	}
}

func TestMapStatsOnResolvedBackend(t *testing.T) {
	want := []dataplane.MapStats{{Name: "sessions", Type: "Hash", MaxEntries: 10, UsedCount: 3}}
	backend := &fakeBackend{stats: want}
	if got := mgmtview.MapStats(backend); !reflect.DeepEqual(got, want) {
		t.Fatalf("MapStats(backend) = %v, want %v", got, want)
	}
	if got := mgmtview.MapStats(bareBackend{}); got != nil {
		t.Fatalf("MapStats(bare) = %v, want nil", got)
	}
	if got := mgmtview.MapStats(nil); got != nil {
		t.Fatalf("MapStats(nil) = %v, want nil", got)
	}
	// An unresolved indirection has no GetMapStats of its own: the
	// helper must NOT unwrap it behind the caller's back, or a
	// render would take a second publication behind its single
	// Probe. This is the one-publication invariant (#6743 r7-F3).
	var cell any = backend
	if got := mgmtview.MapStats(indirection{cell: &cell}); got != nil {
		t.Fatalf("MapStats(indirection) = %v, want nil (no implicit Unwrap)", got)
	}
}

func TestSessionCountOnResolvedBackend(t *testing.T) {
	backend := &fakeBackend{v4: 4, v6: 6}
	if v4, v6 := mgmtview.SessionCount(backend); v4 != 4 || v6 != 6 {
		t.Fatalf("SessionCount(backend) = (%d,%d), want (4,6)", v4, v6)
	}
	if v4, v6 := mgmtview.SessionCount(bareBackend{}); v4 != 0 || v6 != 0 {
		t.Fatalf("SessionCount(bare) = (%d,%d), want (0,0)", v4, v6)
	}
	if v4, v6 := mgmtview.SessionCount(nil); v4 != 0 || v6 != 0 {
		t.Fatalf("SessionCount(nil) = (%d,%d), want (0,0)", v4, v6)
	}
	var cell any = backend
	if v4, v6 := mgmtview.SessionCount(indirection{cell: &cell}); v4 != 0 || v6 != 0 {
		t.Fatalf("SessionCount(indirection) = (%d,%d), want (0,0) (no implicit Unwrap)", v4, v6)
	}
}

func TestSessionCountContextShape(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{ k string }{"k"}, "v")
	backend := &fakeBackend{v4: 7, v6: 8}
	v4, v6, err, ok := mgmtview.SessionCountContext(ctx, backend)
	if !ok || err != nil || v4 != 7 || v6 != 8 {
		t.Fatalf("SessionCountContext(backend) = (%d,%d,%v,%v), want (7,8,nil,true)", v4, v6, err, ok)
	}
	if backend.ctxSeen != ctx {
		t.Fatal("SessionCountContext did not forward the caller's context")
	}

	sentinel := errors.New("count failed")
	failing := &fakeBackend{ctxErr: sentinel}
	if _, _, err, ok := mgmtview.SessionCountContext(ctx, failing); !ok || !errors.Is(err, sentinel) {
		t.Fatalf("SessionCountContext(failing) = (_,_,%v,%v), want (%v,true)", err, ok, sentinel)
	}

	if _, _, err, ok := mgmtview.SessionCountContext(ctx, bareBackend{}); ok || err != nil {
		t.Fatalf("SessionCountContext(bare) = (_,_,%v,%v), want (nil,false)", err, ok)
	}
	if _, _, err, ok := mgmtview.SessionCountContext(ctx, nil); ok || err != nil {
		t.Fatalf("SessionCountContext(nil) = (_,_,%v,%v), want (nil,false)", err, ok)
	}
}
