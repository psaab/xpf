package cli

// #12922 on the local CLI: `show schedulers` must carry the daily
// exclude/all-day qualifiers and the per-weekday override arms. On master
// the CLI printed only start/stop + "Recurrence: daily" (and ranged over
// the scheduler map unsorted), so a daily-exclude scheduler rendered like
// an ordinary active window (RED on master).

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestCLIShowSchedulersRecurrenceDetail12922(t *testing.T) {
	st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := st.LoadSet(strings.Join([]string{
		"set schedulers scheduler excluded daily exclude",
		"set schedulers scheduler excluded daily start-time 09:00:00",
		"set schedulers scheduler excluded daily stop-time 17:00:00",
		"set schedulers scheduler mixed daily start-time 08:00:00",
		"set schedulers scheduler mixed daily stop-time 16:00:00",
		"set schedulers scheduler mixed monday exclude",
		"set schedulers scheduler mixed sunday all-day",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := New(st, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	// PREMISE, asserted rather than assumed.
	cfg := st.ActiveConfig()
	if cfg == nil || cfg.Schedulers["excluded"] == nil || !cfg.Schedulers["excluded"].DailyExclude {
		t.Fatalf("fixture missing daily-exclude scheduler: %+v", cfg.Schedulers)
	}

	var runErr error
	out := captureStdout(t, func() { runErr = c.showSchedulers() })
	if runErr != nil {
		t.Fatalf("showSchedulers: %v", runErr)
	}
	for _, line := range []string{
		"  Recurrence: daily exclude",
		"  monday:    exclude",
		"  sunday:    all-day",
	} {
		if !cliSchedulerLine12922(out, line) {
			t.Fatalf("line %q missing from CLI show schedulers:\n%s", line, out)
		}
	}
	// Narrowness: the plain daily window of `mixed` keeps its recurrence line.
	if !cliSchedulerLine12922(out, "  Recurrence: daily") {
		t.Fatalf("plain daily recurrence line regressed:\n%s", out)
	}
}

func cliSchedulerLine12922(out, line string) bool {
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
