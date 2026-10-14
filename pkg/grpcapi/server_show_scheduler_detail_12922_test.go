package grpcapi

// #12922 on the gRPC ShowText surface: showSchedulers must carry the daily
// exclude/all-day qualifiers and the per-weekday override arms. On master it
// printed only start/stop + "Recurrence: daily", so a daily-exclude
// scheduler rendered like an ordinary active window (RED on master).

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowSchedulersRendersRecurrenceDetail12922(t *testing.T) {
	cfg := &config.Config{}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"excluded": {Name: "excluded", Daily: true, DailyExclude: true,
			StartTime: "09:00:00", StopTime: "17:00:00",
			Days: map[string]*config.SchedulerDayWindow{
				"monday": {Exclude: true},
				"sunday": {AllDay: true},
			}},
		// Named to sort AFTER `excluded`, so the weekday arms below can be
		// pinned inside the excluded block.
		"zz-always": {Name: "zz-always", Daily: true, AllDay: true},
	}
	var buf strings.Builder
	renderNoPanic(t, func() { (&Server{}).showSchedulers(cfg, &buf) })
	out := buf.String()

	for _, line := range []string{
		"  Recurrence: daily exclude",
		"  Recurrence: daily all-day",
		"  monday:    exclude",
		"  sunday:    all-day",
	} {
		if !schedulerLine12922(out, line) {
			t.Fatalf("line %q missing from gRPC show schedulers:\n%s", line, out)
		}
	}
	// The weekday arms belong to the excluded scheduler's block, between
	// its header and the next scheduler's header.
	exclIdx := strings.Index(out, "Scheduler: excluded")
	armIdx := strings.Index(out, "  monday:")
	nextIdx := strings.Index(out, "Scheduler: zz-always")
	if exclIdx < 0 || armIdx < exclIdx || nextIdx < armIdx {
		t.Fatalf("weekday arm rendered outside its scheduler block:\n%s", out)
	}
}

func schedulerLine12922(out, line string) bool {
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
