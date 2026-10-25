package natshow

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// unarmedReader is a dataplane that has been PUBLISHED but not armed:
// IsLoaded() is false, yet a counter read still succeeds and returns zero.
//
// That combination is the whole of #7423 row 3 and no existing fixture had it.
// `dataplane.Manager.ReadNATRuleCounter` is a map read with NO error path — it
// returns `(zero, nil)` when the helper has never reported — so the `err == nil`
// guard cannot fire and the caller rendered a confident `Translation hits: 0`.
// The guard is not dead code, which is why reading it was not enough to see the
// defect: it is live for other implementations of the interface and simply
// unreachable for the one in production.
type unarmedReader struct{ reads int }

func (u *unarmedReader) IsLoaded() bool { return false }
func (u *unarmedReader) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}
func (u *unarmedReader) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}
func (u *unarmedReader) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	u.reads++
	return dataplane.CounterValue{}, nil
}
func (u *unarmedReader) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }

// #7423 row 3: on a published-but-UNARMED dataplane the hits row must not
// render a number, and must say why.
//
// The `cr` is deliberately non-nil and carries a real NATCounterID — that is
// what makes this reach the block at all. The pre-existing "unloaded" goldens
// pass `crFn == nil`, so they skip the hits block on `cr != nil` and could
// never have seen this.
func TestTranslationHitsAreNotRenderedUnarmed_7423(t *testing.T) {
	for _, tc := range []struct {
		name    string
		render  func(context.Context, io.Writer, *config.Config, Reader, func() *dataplane.ApplyResult)
		ruleSet string
		key     string
	}{
		{"source", RenderSourceRuleDetail, "rs-src",
			dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "rs-src", "r1")},
		{"dest", RenderDestRuleDetail, "rs-dst",
			dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "rs-dst", "d1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &unarmedReader{}
			cr := &dataplane.ApplyResult{
				ZoneIDs:       map[string]uint32{"trust": 7, "untrust": 8, "dmz": 9},
				NATCounterIDs: map[string]uint32{tc.key: 5},
			}
			var b strings.Builder
			tc.render(context.Background(), &b, natFixtureConfig(), dp, func() *dataplane.ApplyResult { return cr })
			out := b.String()

			if strings.Contains(out, "Translation hits:        0 packets") {
				t.Errorf("unarmed dataplane rendered a measured-looking zero:\n%s", out)
			}
			if !strings.Contains(out, "Translation hits:        "+natCounterUnarmed) {
				t.Errorf("unarmed hits row must say why it has no number:\n%s", out)
			}
			// The counter must not be read at all. Without this the row could
			// render n/a while still touching a dataplane that is not armed —
			// honest output over an unsound read.
			if dp.reads != 0 {
				t.Errorf("read the NAT counter %d times on an unarmed dataplane", dp.reads)
			}
		})
	}
}

// #7423 row 4: the session count is a ZONE-PAIR aggregate, so it must appear
// ONCE per rule-set, not once per rule.
//
// The fixture has TWO rules in one rule-set, which is the smallest shape where
// the defect changes an outcome: with one rule the old and new renderings are
// indistinguishable. The assertion is on the COUNT of occurrences, because the
// defect was never a wrong number — it was the right number printed N times, so
// summing the column gave N x the truth.
func TestZonePairSessionCountAppearsOncePerRuleSet_7423(t *testing.T) {
	cfg := natFixtureConfig()
	rs := cfg.Security.NAT.Source[0]
	second := *rs.Rules[0]
	second.Name = "r2"
	rs.Rules = append(rs.Rules, &second)

	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
			{IsReverse: 0, Flags: dataplane.SessFlagSNAT, IngressZone: 7, EgressZone: 8},
		},
	}
	cr := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 7, "untrust": 8}}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	out := b.String()

	// Liveness: both rules really did render, or "printed once" is trivially
	// true because only one rule exists.
	for _, rule := range []string{"source NAT rule: r1", "source NAT rule: r2"} {
		if !strings.Contains(out, rule) {
			t.Fatalf("fixture did not render %q; the count assertion below is vacuous:\n%s", rule, out)
		}
	}
	if n := strings.Count(out, "sessions for this zone pair"); n != 1 {
		t.Errorf("the zone-pair aggregate appeared %d times for a 2-rule rule-set; "+
			"summing the column gives %dx the truth:\n%s", n, n, out)
	}
	if !strings.Contains(out, "sessions for this zone pair: 2") {
		t.Errorf("the aggregate lost its value:\n%s", out)
	}
	// And it must not be attributed to a rule — the old label claimed a
	// per-rule number the dataplane cannot produce, since a session carries
	// zone ids and no rule identity.
	if strings.Contains(out, "Number of sessions:") {
		t.Errorf("the per-rule `Number of sessions` label is back:\n%s", out)
	}
}

// #7423 row 4, second half: an unarmed dataplane renders no session number
// either. The scan is gated, so `rsSessions` is empty and the old code printed
// a bare `0` — indistinguishable from a genuinely idle rule set.
func TestZonePairSessionCountIsNotZeroWhenUnarmed_7423(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, natFixtureConfig(), &unarmedReader{},
		func() *dataplane.ApplyResult { return &dataplane.ApplyResult{} })
	out := b.String()
	if strings.Contains(out, "sessions for this zone pair: 0") {
		t.Errorf("unarmed dataplane rendered a session count of 0, which reads as "+
			"'no sessions' rather than 'not measured':\n%s", out)
	}
	if !strings.Contains(out, "sessions for this zone pair: "+natCounterUnarmed) {
		t.Errorf("unarmed session row must say why it has no number:\n%s", out)
	}
}

// TestZonePairSessionCountAppearsOncePerRuleSetDest_7423 is the destination-NAT
// half of row 4.
//
// dest.go received the identical fix, and the mutation cells confirm the
// pre-existing goldens do catch a revert there. But a golden reds on ANY output
// change and says nothing about which property broke; it is coverage, not a
// statement of intent. This makes the dest guard say the same thing its source
// sibling says, so a future edit that legitimately reshuffles the golden cannot
// quietly take the invariant with it.
func TestZonePairSessionCountAppearsOncePerRuleSetDest_7423(t *testing.T) {
	cfg := natFixtureConfig()
	rs := cfg.Security.NAT.Destination.RuleSets[0]
	second := *rs.Rules[0]
	second.Name = "d2"
	rs.Rules = append(rs.Rules, &second)

	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{IsReverse: 0, Flags: dataplane.SessFlagDNAT, IngressZone: 8, EgressZone: 9},
			{IsReverse: 0, Flags: dataplane.SessFlagDNAT, IngressZone: 8, EgressZone: 9},
			{IsReverse: 0, Flags: dataplane.SessFlagDNAT, IngressZone: 8, EgressZone: 9},
		},
	}
	cr := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"untrust": 8, "dmz": 9}}
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	out := b.String()

	// Liveness: with one rule "printed once" is trivially true.
	for _, rule := range []string{"d1", "d2"} {
		if !strings.Contains(out, rule) {
			t.Fatalf("fixture did not render rule %q; the count below is vacuous:\n%s", rule, out)
		}
	}
	if n := strings.Count(out, "sessions for this zone pair"); n != 1 {
		t.Errorf("the zone-pair aggregate appeared %d times for a 2-rule rule-set; "+
			"summing the column gives %dx the truth:\n%s", n, n, out)
	}
	if !strings.Contains(out, "sessions for this zone pair: 3") {
		t.Errorf("the aggregate lost its value:\n%s", out)
	}
	if strings.Contains(out, "Number of sessions:") {
		t.Errorf("the per-rule `Number of sessions` label is back:\n%s", out)
	}
}
