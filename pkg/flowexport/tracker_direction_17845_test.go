package flowexport

import (
	"testing"
	"time"
)

// #17845: a caller-preset ingress Direction (0) must not be overwritten
// at drain. Pre-fix collectDueExports used Direction==0 as the "unset"
// sentinel, so an explicitly-set ingress 0 on an egress-sampled flow
// (config derives 1) was silently flipped to 1. Only Direction 1 could
// ever survive the drain, so the TrackFlowOpenWithMeta "preset kept"
// contract held for exactly half the value space.
//
// RED pre-fix: the preset-0 interim below drains as Direction 1.
// GREEN post-fix: preset 0 stays 0, while a template that never set
// Direction still derives 1 from the exporter config (the #16754
// production path), and preset 1 keeps surviving.

func TestTrackerPresetIngressDirectionPreserved17845(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key, tmpl := trackerTestTemplate()
	// trackerTestTemplate is egress-sampled: FlowDirectionIface(1,3)==1.

	cases := []struct {
		name  string
		setup func(e *Exporter, tmpl *FlowRecord)
		want  uint8
	}{
		{"preset ingress 0 via WithMeta stays 0", func(e *Exporter, tmpl *FlowRecord) {
			tmpl.Direction = 0
			e.TrackFlowOpenWithMeta(key, start, *tmpl)
		}, 0},
		{"preset ingress 0 via Record stays 0", func(e *Exporter, tmpl *FlowRecord) {
			tmpl.Direction = 0
			tmpl.DirectionSet = true
			e.TrackFlowOpenRecord(key, start, *tmpl)
		}, 0},
		{"unset template derives egress 1", func(e *Exporter, tmpl *FlowRecord) {
			// Production daemon shape: TrackFlowOpenRecord, no Direction.
			e.TrackFlowOpenRecord(key, start, *tmpl)
		}, 1},
		{"preset egress 1 stays 1", func(e *Exporter, tmpl *FlowRecord) {
			tmpl.Direction = 1
			e.TrackFlowOpenWithMeta(key, start, *tmpl)
		}, 1},
		{"preset egress 1 stays 1 when config derives 0", func(e *Exporter, tmpl *FlowRecord) {
			tmpl.InZone, tmpl.OutZone = 3, 2 // config derives 0
			tmpl.Direction = 1
			e.TrackFlowOpenWithMeta(key, start, *tmpl)
		}, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewExporter(trackerTestConfig())
			if err != nil {
				t.Fatalf("NewExporter: %v", err)
			}
			e.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)
			tmpl := tmpl
			tc.setup(e, &tmpl)
			e.TouchFlow(key, start.Add(61*time.Second), 10, 1000)
			due := e.collectDueExports(start.Add(61 * time.Second))
			if len(due) != 1 {
				t.Fatalf("want 1 interim, got %v", due)
			}
			if due[0].Direction != tc.want {
				t.Fatalf("interim Direction = %d, want %d (preset must survive drain)", due[0].Direction, tc.want)
			}
			// Enrichment of the other fields is unaffected by the
			// presence bit: masks still resolve at drain.
			if due[0].SrcMask != testSrcMask || due[0].DstMask != testDstMask {
				t.Fatalf("interim masks = %d/%d, want %d/%d", due[0].SrcMask, due[0].DstMask, testSrcMask, testDstMask)
			}
			v4, _ := e.batch.drain()
			if len(v4) != 1 || v4[0].Direction != tc.want {
				t.Fatalf("batched interim = %+v, want Direction %d", v4, tc.want)
			}
		})
	}
}

// The inactive-timeout final carries the same preset: it is the other
// record shape collectDueExports emits, and it must not flip either.
func TestTrackerPresetIngressInactiveFinalPreserved17845(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key, tmpl := trackerTestTemplate()

	e, err := NewExporter(trackerTestConfig())
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.MaskResolver = maskResolverFor(tmpl.SrcIP, tmpl.DstIP)
	tmpl.Direction = 0 // explicit ingress preset on an egress-sampled flow
	e.TrackFlowOpenWithMeta(key, start, tmpl)
	e.TouchFlow(key, start.Add(30*time.Second), 100, 10000)
	final := e.collectDueExports(start.Add(50 * time.Second))
	if len(final) != 1 {
		t.Fatalf("want 1 inactive final, got %v", final)
	}
	if final[0].Direction != 0 {
		t.Fatalf("inactive final Direction = %d, want 0 (preset ingress preserved)", final[0].Direction)
	}
}
