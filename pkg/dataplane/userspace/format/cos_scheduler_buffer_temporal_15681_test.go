package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15681: formatSchedulerBuffer ignored BufferSizeTemporalUS, so a scheduler
// configured with `buffer-size temporal 50000` rendered "Buffer: -" in
// `show class-of-service scheduler-map`, hiding the configured sizing.
//
// FAIL-ON-REVERT: dropping the temporal arm makes the temporal row render
// "-" again and this test goes RED.
func TestFormatSchedulerBufferTemporal15681(t *testing.T) {
	if got := formatSchedulerBuffer(&config.CoSScheduler{BufferSizeTemporalUS: 50000}); got != "50000us" {
		t.Fatalf("temporal buffer = %q, want %q", got, "50000us")
	}
	// Controls: other forms and unset keep their established rendering.
	if got := formatSchedulerBuffer(&config.CoSScheduler{BufferSizePercent: 50}); got != "50%" {
		t.Fatalf("percent buffer = %q, want 50%%", got)
	}
	if got := formatSchedulerBuffer(&config.CoSScheduler{}); got != "-" {
		t.Fatalf("unset buffer = %q, want -", got)
	}
	if got := formatSchedulerBuffer(nil); got != "-" {
		t.Fatalf("nil scheduler buffer = %q, want -", got)
	}

	// End-to-end through the scheduler-map surface.
	cfg := &config.Config{ClassOfService: &config.ClassOfServiceConfig{
		ForwardingClasses: map[string]*config.CoSForwardingClass{
			"BE": {Name: "BE", Queue: 0},
		},
		Schedulers: map[string]*config.CoSScheduler{
			"S": {Name: "S", BufferSizeTemporalUS: 50000},
		},
		SchedulerMaps: map[string]*config.CoSSchedulerMap{
			"M": {Name: "M", Entries: map[string]*config.CoSSchedulerMapEntry{
				"BE": {ForwardingClass: "BE", Scheduler: "S"},
			}},
		},
	}}
	out := FormatCoSSchedulerMaps(cfg, "")
	if !strings.Contains(out, "50000us") {
		t.Fatalf("scheduler-map output missing temporal buffer 50000us:\n%s", out)
	}
}
