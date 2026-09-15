// #9902 F-096: a cancelled session walk must render its partial tally WITH a
// caveat, not as authoritative counts.
//
// walkSessionValues used to return nil on cancellation (walk.go) and
// noteSessionScanError only printed on err != nil (natshow.go), so a walk cut
// short by a hung-up client rendered exactly like a completed one. The walk now
// returns ErrSessionWalkCancelled when it stopped early with no scan error, and
// the note maps the sentinel to a "counts are partial" caveat. All three walking
// renderers inherit the caveat with zero call-site churn — they already route
// scanErr through noteSessionScanError and never branch on err == nil.
package natshow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// cancelCaveat9902 is the F-096 caveat: distinct from scanErrCaveat ("may be
// incomplete: <err>") because cancellation carries no error value to format.
const cancelCaveat9902 = "active session counts are partial (session walk cancelled)"

// fwdSession7315 builds the same forward SNAT+DNAT v4 row the #7315
// countingReader offers, so the mid-walk fixtures below tally identically.
func fwdSession7315(c *countingReader) dataplane.SessionValue {
	return dataplane.SessionValue{
		Flags:       dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		IngressZone: c.ingress, EgressZone: c.egres,
		NATSrcIP: natSrcIP7315(), NATSrcPort: 40000,
	}
}

// TestWalkSessionValuesCancelledReturnsSentinel9902 is the F-096 mechanism cell:
// a walk stopped by cancellation reports ErrSessionWalkCancelled, not nil.
func TestWalkSessionValuesCancelledReturnsSentinel9902(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dp := newCountingReader7315(7, 8)
	tallied := 0
	v := func(dataplane.SessionValue) { tallied++ }
	v6 := func(dataplane.SessionValueV6) { tallied++ }

	err := walkSessionValues(ctx, dp, v, v6)
	if !errors.Is(err, ErrSessionWalkCancelled) {
		t.Fatalf("cancelled walk err = %v, want ErrSessionWalkCancelled", err)
	}
	if dp.visited == 0 || dp.visited > 2 {
		t.Fatalf("cancelled walk visited %d rows, want 1-2 (one offered row per family)", dp.visited)
	}
	if tallied != 0 {
		t.Fatalf("cancelled walk tallied %d rows, want 0 (callback trips before visiting)", tallied)
	}
}

// TestWalkSessionValuesLiveWalkReturnsNil9902 pins the normal path: a completed
// walk still reports nil.
func TestWalkSessionValuesLiveWalkReturnsNil9902(t *testing.T) {
	dp := newCountingReader7315(7, 8)
	tallied := 0
	v := func(dataplane.SessionValue) { tallied++ }
	v6 := func(dataplane.SessionValueV6) { tallied++ }

	if err := walkSessionValues(context.Background(), dp, v, v6); err != nil {
		t.Fatalf("live walk err = %v, want nil", err)
	}
	if dp.visited != 2*walkRows7315 || tallied != 2*walkRows7315 {
		t.Fatalf("live walk visited %d tallied %d, want %d", dp.visited, tallied, 2*walkRows7315)
	}
}

// TestCancelledRenderersPinPartialCaveat9902 drives all three walking renderers
// with a cancelled context: the partial tally must print WITH the caveat, and a
// live render must not contain it (byte-identical healthy path).
func TestCancelledRenderersPinPartialCaveat9902(t *testing.T) {
	renderers := []struct {
		name            string
		ingress, egress uint16
		call            func(ctx context.Context, w *strings.Builder, dp *countingReader)
		telltale        string // rendered iff the (partial) tally still prints
	}{
		{"RenderPersistentDetail", 7, 8, func(ctx context.Context, w *strings.Builder, dp *countingReader) {
			RenderPersistentDetail(ctx, w, dp)
		}, "Total persistent NAT bindings: 1"},
		{"RenderSourceRuleDetail", 7, 8, func(ctx context.Context, w *strings.Builder, dp *countingReader) {
			RenderSourceRuleDetail(ctx, w, natFixtureConfig(), dp, applyResult7315)
		}, "source NAT rule: "},
		{"RenderDestRuleDetail", 8, 9, func(ctx context.Context, w *strings.Builder, dp *countingReader) {
			RenderDestRuleDetail(ctx, w, natFixtureConfig(), dp, applyResult7315)
		}, "destination NAT rule: "},
	}
	for _, r := range renderers {
		t.Run(r.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			dp := newCountingReader7315(r.ingress, r.egress)
			var b strings.Builder
			r.call(ctx, &b, dp)
			if !strings.Contains(b.String(), cancelCaveat9902) {
				t.Errorf("cancelled %s rendered no partial-tally caveat; got:\n%s", r.name, b.String())
			}
			if !strings.Contains(b.String(), r.telltale) {
				t.Errorf("cancelled %s aborted its render instead of printing the partial tally; got:\n%s", r.name, b.String())
			}
			live := newCountingReader7315(r.ingress, r.egress)
			var lb strings.Builder
			r.call(context.Background(), &lb, live)
			if strings.Contains(lb.String(), cancelCaveat9902) {
				t.Errorf("live %s rendered the cancel caveat on a completed walk; got:\n%s", r.name, lb.String())
			}
		})
	}
}

// midCancelReader9902 cancels ctx after offering `after` v4 rows: the walk stops
// mid-tally with a NONZERO partial count (v4 rows tallied so far, v6 untouched).
type midCancelReader9902 struct {
	*countingReader
	cancel  context.CancelFunc
	after   int
	offered int
}

func (r *midCancelReader9902) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < walkRows7315; i++ {
		r.visited++
		if r.offered == r.after {
			r.cancel()
		}
		r.offered++
		if !fn(dataplane.SessionKey{}, fwdSession7315(r.countingReader)) {
			return nil
		}
	}
	return nil
}

// TestCancelMidWalkPinsPartialCaveat9902: cancellation after a nonzero tally is
// still a partial tally, not an authoritative one.
func TestCancelMidWalkPinsPartialCaveat9902(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &midCancelReader9902{countingReader: newCountingReader7315(7, 8), cancel: cancel, after: 10}
	tallied := 0
	v := func(dataplane.SessionValue) { tallied++ }
	v6 := func(dataplane.SessionValueV6) { tallied++ }

	if err := walkSessionValues(ctx, dp, v, v6); !errors.Is(err, ErrSessionWalkCancelled) {
		t.Fatalf("mid-walk cancel err = %v, want ErrSessionWalkCancelled", err)
	}
	if tallied != 10 {
		t.Fatalf("mid-walk cancel tallied %d rows, want 10 (the rows offered before cancel)", tallied)
	}
	if dp.visited != 12 {
		t.Fatalf("mid-walk cancel visited %d rows, want 12 (11 v4 incl. the tripping row + 1 v6)", dp.visited)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	dp2 := &midCancelReader9902{countingReader: newCountingReader7315(7, 8), cancel: cancel2, after: 10}
	var b strings.Builder
	RenderPersistentDetail(ctx2, &b, dp2)
	if !strings.Contains(b.String(), cancelCaveat9902) {
		t.Errorf("mid-walk cancel rendered no caveat; got:\n%s", b.String())
	}
}

// v6CancelReader9902 lets v4 complete, then cancels as v6 iteration starts: the
// v4 tally is complete but the walk as a whole is partial.
type v6CancelReader9902 struct {
	*countingReader
	cancel context.CancelFunc
}

func (r *v6CancelReader9902) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	r.cancel()
	return r.countingReader.IterateSessionsV6(fn)
}

// TestV6CancelPinsPartialCaveat9902: a walk cancelled during the v6 family is
// partial even though every v4 row was visited.
func TestV6CancelPinsPartialCaveat9902(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &v6CancelReader9902{countingReader: newCountingReader7315(7, 8), cancel: cancel}
	tallied := 0
	v := func(dataplane.SessionValue) { tallied++ }
	v6 := func(dataplane.SessionValueV6) { tallied++ }

	if err := walkSessionValues(ctx, dp, v, v6); !errors.Is(err, ErrSessionWalkCancelled) {
		t.Fatalf("v6 cancel err = %v, want ErrSessionWalkCancelled", err)
	}
	if dp.visited != walkRows7315+1 || tallied != walkRows7315 {
		t.Fatalf("v6 cancel visited %d tallied %d, want visited %d tallied %d",
			dp.visited, tallied, walkRows7315+1, walkRows7315)
	}
}

// bothErrReader9902 trips the cancellation latch (it offers one row to a
// cancelled context) AND fails the scan: the real error must win.
type bothErrReader9902 struct {
	*countingReader
}

func (r *bothErrReader9902) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	r.visited++
	fn(dataplane.SessionKey{}, fwdSession7315(r.countingReader))
	return errors.New("9902 simultaneous scan failure")
}

// TestScanErrorBeatsCancel9902 pins precedence: when the scan both stopped early
// AND failed, the caller learns the error, not the sentinel.
func TestScanErrorBeatsCancel9902(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dp := &bothErrReader9902{countingReader: newCountingReader7315(7, 8)}

	err := walkSessionValues(ctx, dp, func(dataplane.SessionValue) {}, func(dataplane.SessionValueV6) {})
	if err == nil || !strings.Contains(err.Error(), "9902 simultaneous scan failure") {
		t.Fatalf("simultaneous error+cancel err = %v, want the scan error", err)
	}
	if errors.Is(err, ErrSessionWalkCancelled) {
		t.Fatalf("simultaneous error+cancel returned the sentinel, want scan-error precedence: %v", err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	var b strings.Builder
	RenderPersistentDetail(ctx2, &b, &bothErrReader9902{countingReader: newCountingReader7315(7, 8)})
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Errorf("simultaneous error+cancel rendered no scan-error caveat; got:\n%s", b.String())
	}
	if strings.Contains(b.String(), cancelCaveat9902) {
		t.Errorf("simultaneous error+cancel rendered the cancel caveat instead of the error; got:\n%s", b.String())
	}
}
