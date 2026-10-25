// #7315: the NAT detail renderers drove full v4+v6 conntrack walks that ran
// to completion after the client was gone.
//
// #6553 gave the four gRPC ShowText NAT topics ADMISSION but could not give
// them CANCELLATION: pkg/natshow's Render* helpers took no context and are
// shared with pkg/cli, so the lease could not reach the walk. Admission
// bounds CONCURRENCY; the lease bounds DURATION, and the two fail
// independently — a handler can hold its slot correctly and still walk the
// whole table for a client that has hung up. Because REST and gRPC alias ONE
// 4-slot diagcmd.SessionWalkLimiter, the slot such a walk keeps is a slot the
// REST surfaces that DO honour cancellation are queueing for.
//
// These probes count VISITED ROWS rather than asserting a rendered count,
// because the count is also 0 when the walk never ran: a visit count
// discriminates "stopped early" from "did not start", and the anti-vacuity
// assertion fails loudly on the latter. Each renderer is driven twice against
// the SAME fixture — cancelled, then live — so a green cannot come from a
// fixture that iterates nothing.
//
// FAIL-ON-REVERT: drop the ctx sampling from walkSessionValues (or restore a
// per-renderer hand-copied walk without it) and every cancelled cell below
// reports the full 2*walkRows7315 visits.
package natshow

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// walkRows7315 is per FAMILY, so a completed walk visits 2*walkRows7315. It is
// large enough that "stopped after the first offered row" and "ran to
// completion" cannot be confused for one another.
const walkRows7315 = 500

// countingReader offers walkRows7315 forward SNAT+DNAT sessions per family and
// counts every row it hands to the renderer's callback.
//
// Every session carries BOTH NAT flags and the fixture's zone ids, so the same
// fake feeds the source, destination and persistent-NAT renderers without any
// of them silently classifying every row away — a fake whose rows all fail the
// renderer's filter would still count visits, but it would stop the rendered
// tally from corroborating them.
type countingReader struct {
	visited        int
	ingress, egres uint16
	pnat           *dataplane.PersistentNATTable
}

func (c *countingReader) IsLoaded() bool { return true }

func (c *countingReader) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < walkRows7315; i++ {
		c.visited++
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{
			Flags:       dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
			IngressZone: c.ingress, EgressZone: c.egres,
			NATSrcIP: natSrcIP7315(), NATSrcPort: 40000,
		}) {
			return nil
		}
	}
	return nil
}

func (c *countingReader) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < walkRows7315; i++ {
		c.visited++
		if !fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{
			Flags:       dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
			IngressZone: c.ingress, EgressZone: c.egres,
		}) {
			return nil
		}
	}
	return nil
}

func (c *countingReader) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (c *countingReader) GetPersistentNAT() *dataplane.PersistentNATTable { return c.pnat }

// natSrcIP7315 is the fixture binding's NAT IP in the wire form
// SessionValue.NATSrcIP carries (native-endian word holding network-order
// bytes; CLAUDE.md "Byte Order"), so a v4 row tallies against the binding
// RenderPersistentDetail renders.
func natSrcIP7315() uint32 {
	var ip4 [4]byte
	copy(ip4[:], netip.MustParseAddr("203.0.113.1").AsSlice())
	return binary.NativeEndian.Uint32(ip4[:])
}

func newCountingReader7315(ingress, egress uint16) *countingReader {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
	})
	return &countingReader{ingress: ingress, egres: egress, pnat: pnat}
}

// applyResult7315 supplies the zone-id map the source/destination renderers
// require: both skip the walk entirely when the apply result is nil, which
// would make every assertion here vacuous.
//
// The three ids are DISTINCT. An earlier revision gave untrust and dmz the
// same id; the renderers invert this map to zoneByID, so the collision made
// one of the two rule-set keys unreachable and the rendered tally stopped
// depending on the walk at all — a fixture that would have scored the
// output-corroboration assertion as a real defect.
func applyResult7315() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 7, "untrust": 8, "dmz": 9}}
}

// TestNATRenderersStopOnCancelledContext7315 is the mechanism cell: each
// walking renderer must stop within one offered row per family.
func TestNATRenderersStopOnCancelledContext7315(t *testing.T) {
	renderers := []struct {
		name string
		// ingress/egress are the zone ids every fixture row carries, chosen
		// so the rows land in the rule-set the renderer prints a count for
		// (rs-src is trust->untrust, rs-dst is untrust->dmz).
		ingress, egress uint16
		call            func(ctx context.Context, w *strings.Builder, dp *countingReader)
	}{
		{"RenderPersistentDetail", 7, 8, func(ctx context.Context, w *strings.Builder, dp *countingReader) {
			RenderPersistentDetail(ctx, w, dp)
		}},
		{"RenderSourceRuleDetail", 7, 8, func(ctx context.Context, w *strings.Builder, dp *countingReader) {
			RenderSourceRuleDetail(ctx, w, natFixtureConfig(), dp, applyResult7315)
		}},
		{"RenderDestRuleDetail", 8, 9, func(ctx context.Context, w *strings.Builder, dp *countingReader) {
			RenderDestRuleDetail(ctx, w, natFixtureConfig(), dp, applyResult7315)
		}},
	}

	for _, r := range renderers {
		t.Run(r.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			dp := newCountingReader7315(r.ingress, r.egress)
			var b strings.Builder
			r.call(ctx, &b, dp)

			// One offered row per family before the guard trips: the
			// callback samples ctx on entry, so the iterator hands over
			// row 0 of v4 and row 0 of v6 and nothing further.
			if dp.visited > 2 {
				t.Errorf("cancelled %s visited %d of %d rows — the renderer is not "+
					"sampling ctx inside its session callbacks, so a disconnected "+
					"client's walk runs to completion holding a shared "+
					"diagcmd.SessionWalkLimiter slot", r.name, dp.visited, 2*walkRows7315)
			}
			if dp.visited == 0 {
				t.Fatalf("%s never started a walk, so this cell proves nothing about "+
					"cancellation — check the fixture still reaches the tally "+
					"(IsLoaded, a non-nil apply result, a non-empty binding table)",
					r.name)
			}

			// Control: the SAME fixture with a live context must walk
			// everything, so the assertion above is about cancellation and
			// not about a fake that stops on its own.
			live := newCountingReader7315(r.ingress, r.egress)
			var lb strings.Builder
			r.call(context.Background(), &lb, live)
			if live.visited != 2*walkRows7315 {
				t.Errorf("live %s visited %d rows, want %d — the fixture is not "+
					"iterating, which would make the cancelled cell vacuous",
					r.name, live.visited, 2*walkRows7315)
			}

			// The rendered tally corroborates the visit count: a cancelled
			// walk must report zero sessions where a live one reports every
			// row. This is what ties the counter to operator-visible output
			// rather than to the fake alone.
			if lb.String() == b.String() {
				t.Errorf("%s rendered byte-identical output for a cancelled and a "+
					"live walk — the tally it prints does not depend on the walk "+
					"that was cut short", r.name)
			}
		})
	}
}

// TestRenderPersistentDrivesNoWalk7315 pins the premise correction #7315
// carries: RenderPersistent is NOT one of the walking renderers, so it takes
// no context. The issue listed it among the four, citing persistent.go:85 and
// :102 — both of which are inside RenderPersistentDetail. Its only dataplane
// read is PersistentNATTable.All(), an in-process snapshot copy.
//
// The cell fires the day someone adds a session walk here: it would visit rows
// with no context to stop it, which is exactly the defect #7315 closes for its
// three siblings.
func TestRenderPersistentDrivesNoWalk7315(t *testing.T) {
	dp := newCountingReader7315(7, 8)
	var b strings.Builder
	RenderPersistent(&b, dp)

	if dp.visited != 0 {
		t.Errorf("RenderPersistent visited %d conntrack rows — it now drives a "+
			"session walk and must take a context.Context like the other three "+
			"walking renderers (#7315)", dp.visited)
	}
	if !strings.Contains(b.String(), "Total persistent NAT bindings: 1") {
		t.Fatalf("RenderPersistent rendered no bindings, so the zero-visit "+
			"assertion above is vacuous:\n%s", b.String())
	}
}

// TestWalkSessionValuesNotLoaded7315 covers the guard the three renderers gave
// up when the dp != nil / IsLoaded() checks moved into walkSessionValues: a
// nil or unloaded Reader must walk nothing and report no scan error.
func TestWalkSessionValuesNotLoaded7315(t *testing.T) {
	visits := 0
	v4 := func(dataplane.SessionValue) { visits++ }
	v6 := func(dataplane.SessionValueV6) { visits++ }

	if err := walkSessionValues(context.Background(), nil, v4, v6); err != nil {
		t.Errorf("nil Reader: err = %v, want nil", err)
	}
	if err := walkSessionValues(context.Background(), &unloadedReader7315{}, v4, v6); err != nil {
		t.Errorf("unloaded Reader: err = %v, want nil", err)
	}
	if visits != 0 {
		t.Errorf("walked %d rows with no loaded dataplane, want 0", visits)
	}
}

// unloadedReader7315 reports IsLoaded()==false and PANICS if walked, so a
// regression that drops the loaded check is a loud failure rather than a
// silently-zero count.
type unloadedReader7315 struct{}

func (unloadedReader7315) IsLoaded() bool { return false }
func (unloadedReader7315) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	panic("walked a dataplane that reports IsLoaded()==false")
}
func (unloadedReader7315) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	panic("walked a dataplane that reports IsLoaded()==false")
}
func (unloadedReader7315) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}
func (unloadedReader7315) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }

// compile-time: the fixture config the source/destination cells render must
// keep the rule-sets those renderers guard on.
var _ = func() *config.Config { return natFixtureConfig() }
