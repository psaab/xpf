package rpm

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14370: runProbeLoop's "RPM probe started" slog line interpolated
// test.Target verbatim, writing a live http-get credential URL to the
// daemon log. It must go through config.RedactURL like the JSON surface.

func TestRunProbeLoopStartedLogRedactsTarget14370(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	m := New()
	probe := &config.RPMProbe{Name: "p1"}
	test := &config.RPMTest{
		Name:         "t1",
		ProbeType:    "http-get",
		Target:       target14370,
		TestInterval: 3600,
		ProbeCount:   1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	// runProbeLoop logs before ticking; cancel immediately after entry by
	// running it synchronously with a pre-cancelled context still logs
	// first (the slog call precedes any ctx check), then returns on tick.
	// Use a short-lived run: cancel from a goroutine is racy, so instead
	// rely on the fact that the first statement is the log line and the
	// ticker select returns on ctx.Done.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	m.runProbeLoop(ctx, probe, test, "p1/t1", false)

	out := buf.String()
	if !strings.Contains(out, "RPM probe started") {
		t.Fatalf("expected probe-started log line, got:\n%s", out)
	}
	assertRedacted14370(t, "RPM probe started log", out)
}
