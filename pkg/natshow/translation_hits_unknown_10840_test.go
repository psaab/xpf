package natshow

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// counterErrReader is an ARMED Reader whose counter read fails, so the NAT
// detail renderers exercise their translation-hits error path (#10840). The
// production Manager never errors here — it is a map read returning
// (zero, nil) when the helper has never reported — so this arm is reachable
// only through other implementations of the interface, exactly like the
// `err == nil` guard #7423 documents.
type counterErrReader struct {
	fakeReader
	err error
}

func (r *counterErrReader) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, r.err
}

// #10840: an ARMED rule whose counter ID is missing (post-commit window before
// IDs are assigned, helper restart losing the counter map, mixed-version
// apply) must render its Translation hits as unknown — not omit the line.
// Both failure arms used to print nothing, so the rule read as "never hit"
// while the zone-pair session line below still printed a confident count.
func TestTranslationHitsUnknownWhenCounterIDMissing_10840(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(context.Context, io.Writer, *config.Config, Reader, func() *dataplane.ApplyResult)
	}{
		{"source", RenderSourceRuleDetail},
		{"dest", RenderDestRuleDetail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ids := range []struct {
				name string
				m    map[string]uint32
			}{
				{"empty map", map[string]uint32{}},
				{"nil map", nil},
			} {
				t.Run(ids.name, func(t *testing.T) {
					dp := &fakeReader{}
					cr := &dataplane.ApplyResult{
						ZoneIDs:       map[string]uint16{"trust": 7, "untrust": 8, "dmz": 9},
						NATCounterIDs: ids.m,
					}
					var b strings.Builder
					tc.render(context.Background(), &b, natFixtureConfig(), dp, func() *dataplane.ApplyResult { return cr })
					out := b.String()
					if !strings.Contains(out, "Translation hits:        unknown (no counter assigned)") {
						t.Errorf("armed rule with missing counter ID omits its hits state:\n%s", out)
					}
					if strings.Contains(out, "Translation hits:        0 packets") {
						t.Errorf("missing counter ID rendered a measured-looking zero:\n%s", out)
					}
				})
			}
		})
	}
}

// #10840, read-error arm: a counter read failure must surface a warning
// (mirroring noteSessionScanError), never silence.
func TestTranslationHitsWarnWhenCounterReadFails_10840(t *testing.T) {
	for _, tc := range []struct {
		name    string
		render  func(context.Context, io.Writer, *config.Config, Reader, func() *dataplane.ApplyResult)
		ruleKey string
	}{
		{"source", RenderSourceRuleDetail,
			dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "rs-src", "r1")},
		{"dest", RenderDestRuleDetail,
			dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "rs-dst", "d1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &counterErrReader{err: errors.New("helper restart: counter map closed")}
			cr := &dataplane.ApplyResult{
				ZoneIDs:       map[string]uint16{"trust": 7, "untrust": 8, "dmz": 9},
				NATCounterIDs: map[string]uint32{tc.ruleKey: 5},
			}
			var b strings.Builder
			tc.render(context.Background(), &b, natFixtureConfig(), dp, func() *dataplane.ApplyResult { return cr })
			out := b.String()
			if !strings.Contains(out, "Warning: translation hits could not be read: helper restart: counter map closed") {
				t.Errorf("counter read failure surfaces no warning:\n%s", out)
			}
		})
	}
}
