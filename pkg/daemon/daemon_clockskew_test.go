package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/clockskew"
)

var errClockSkewTest10025 = errors.New("simulated clock command failure")

// seedClockSkewStore10025 commits a config with the given cluster/NTP shape
// and returns a Daemon holding it.
func seedClockSkewStore10025(t *testing.T, cluster, ntp bool) *Daemon {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{"system host-name skewtest"}
	if cluster {
		lines = append(lines,
			"chassis cluster cluster-id 1",
			"chassis cluster authentication-key test-only-clockskew-01",
		)
	}
	if ntp {
		lines = append(lines, "system ntp server 10.0.0.1")
	}
	for _, l := range lines {
		if err := s.SetFromInput(l); err != nil {
			t.Fatalf("SetFromInput(%q): %v", l, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{store: s}
}

const clockSkewSyncedTracking10025 = `Reference ID    : 0A000001 (ntp1.example.net)
Stratum         : 3
Ref time (UTC)  : Thu Jul 10 12:34:56 2026
System time     : 0.000123456 seconds slow of NTP time
Leap status     : Normal
`

const clockSkewUnsyncTracking10025 = `Reference ID    : 00000000 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan 01 00:00:00 1970
System time     : 0.000000000 seconds fast of NTP time
Leap status     : Not synchronised
`

// stubClockSkewExec10025 replaces clockSkewRunCmd with a scripted stub and
// records every invocation. Mirrors service_reload_debt_6800_test.go.
func stubClockSkewExec10025(t *testing.T, chronyOut []byte, chronyErr error, timedateOut []byte, timedateErr error) *[]string {
	t.Helper()
	orig := clockSkewRunCmd
	t.Cleanup(func() { clockSkewRunCmd = orig })
	var seen []string
	clockSkewRunCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		seen = append(seen, name+" "+strings.Join(args, " "))
		if name == "chronyc" {
			return chronyOut, chronyErr
		}
		return timedateOut, timedateErr
	}
	return &seen
}

// TestClockSkewSampler10025 drives the daemon sampler — the production
// injected Sampler — against scripted chrony/timedatectl output. No real exec,
// no machine clock.
func TestClockSkewSampler10025(t *testing.T) {
	t.Run("healthy_clustered_node", func(t *testing.T) {
		d := seedClockSkewStore10025(t, true, true)
		seen := stubClockSkewExec10025(t, []byte(clockSkewSyncedTracking10025), nil, nil, nil)
		s := d.clockSkewAlarmSampler()(context.Background())
		want := clockskew.Sample{Available: true, Cluster: true, NTPConfigured: true,
			ReferenceKnown: true, Synced: true, HaveOffset: true, OffsetSecs: -0.000123456}
		if s != want {
			t.Fatalf("sample = %+v, want %+v", s, want)
		}
		if len(*seen) != 1 || !strings.HasPrefix((*seen)[0], "chronyc tracking") {
			t.Fatalf("healthy path must run exactly [chronyc tracking], ran %v", *seen)
		}
	})

	t.Run("no_ntp_configured_needs_no_exec", func(t *testing.T) {
		d := seedClockSkewStore10025(t, true, false)
		seen := stubClockSkewExec10025(t, nil, nil, nil, nil)
		s := d.clockSkewAlarmSampler()(context.Background())
		if !s.Available || !s.Cluster || s.NTPConfigured {
			t.Fatalf("no-source sample = %+v, want Available+Cluster without NTPConfigured", s)
		}
		if len(*seen) != 0 {
			t.Fatalf("the no-source arm needs no reference reading, but exec ran %v", *seen)
		}
	})

	t.Run("standalone_needs_no_exec", func(t *testing.T) {
		d := seedClockSkewStore10025(t, false, true)
		seen := stubClockSkewExec10025(t, nil, nil, nil, nil)
		s := d.clockSkewAlarmSampler()(context.Background())
		if !s.Available || s.Cluster {
			t.Fatalf("standalone sample = %+v, want Available without Cluster", s)
		}
		if len(*seen) != 0 {
			t.Fatalf("a standalone node has no fabric to protect; sampler must not fork, ran %v", *seen)
		}
	})

	t.Run("unsynchronized_reference", func(t *testing.T) {
		d := seedClockSkewStore10025(t, true, true)
		stubClockSkewExec10025(t, []byte(clockSkewUnsyncTracking10025), nil, nil, nil)
		s := d.clockSkewAlarmSampler()(context.Background())
		if !s.ReferenceKnown || s.Synced || s.HaveOffset {
			t.Fatalf("unsync sample = %+v, want Known without Synced/Offset", s)
		}
	})

	t.Run("chronyc_failure_falls_back_to_timedatectl", func(t *testing.T) {
		d := seedClockSkewStore10025(t, true, true)
		seen := stubClockSkewExec10025(t, nil, errClockSkewTest10025, []byte("yes\n"), nil)
		s := d.clockSkewAlarmSampler()(context.Background())
		if !s.ReferenceKnown || !s.Synced || s.HaveOffset {
			t.Fatalf("fallback sample = %+v, want Known+Synced without Offset", s)
		}
		if len(*seen) != 2 {
			t.Fatalf("fallback must try chronyc then timedatectl, ran %v", *seen)
		}
	})

	t.Run("total_exec_failure_is_unknown", func(t *testing.T) {
		d := seedClockSkewStore10025(t, true, true)
		stubClockSkewExec10025(t, nil, errClockSkewTest10025, nil, errClockSkewTest10025)
		s := d.clockSkewAlarmSampler()(context.Background())
		if !s.Available || s.ReferenceKnown {
			t.Fatalf("failed sample = %+v, want Available without ReferenceKnown (monitor HOLDs)", s)
		}
	})

	t.Run("nil_store_holds", func(t *testing.T) {
		d := &Daemon{}
		seen := stubClockSkewExec10025(t, nil, nil, nil, nil)
		s := d.clockSkewAlarmSampler()(context.Background())
		if s.Available {
			t.Fatalf("nil-store sample = %+v, want Available=false (monitor HOLDs)", s)
		}
		if len(*seen) != 0 {
			t.Fatalf("nil store must not fork, ran %v", *seen)
		}
	})
}

// TestClockSkewLifecycle10025: the monitor starts idempotently, the accessor
// is nil-safe, and discard clears the pointer (mirrors the #2114 shape).
func TestClockSkewLifecycle10025(t *testing.T) {
	var nilD *Daemon
	if alarms := nilD.clockSkewAlarms(); alarms != nil {
		t.Fatalf("nil daemon accessor = %+v, want nil", alarms)
	}
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
	if alarms := d.clockSkewAlarms(); alarms != nil {
		t.Fatalf("unstarted accessor = %+v, want nil", alarms)
	}
	d.maybeStartClockSkewAlarm()
	first := d.clockSkewAlarm.Load()
	if first == nil {
		t.Fatal("maybeStart must construct the monitor (no dataplane gate: the sampler reads config+chrony)")
	}
	d.maybeStartClockSkewAlarm()
	if second := d.clockSkewAlarm.Load(); second != first {
		t.Fatal("maybeStart must be idempotent")
	}
	// An empty store is standalone-shaped: the prompt evaluation clears/raises
	// nothing either way, so the accessor is deterministically empty.
	if alarms := d.clockSkewAlarms(); len(alarms) != 0 {
		t.Fatalf("empty-store accessor = %+v, want empty", alarms)
	}
	d.stopAndDiscardClockSkewAlarm()
	if d.clockSkewAlarm.Load() != nil {
		t.Fatal("stopAndDiscard must clear the pointer")
	}
	d.stopAndDiscardClockSkewAlarm() // idempotent
}

// TestClockSkewWiring10025 pins the daemonube wiring by source: the monitor
// must be started at boot, stopped at shutdown, and surfaced to both the
// in-process CLI and the gRPC server. No test crosses those call sites, so a
// deleted line would otherwise stay green (the #9443/#9452 rationale).
func TestClockSkewWiring10025(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	if src := read("daemon_run.go"); !strings.Contains(src, "d.maybeStartClockSkewAlarm()") {
		t.Error("daemon_run.go must start the clock-skew monitor at boot")
	}
	if src := read("daemon_run.go"); !strings.Contains(src, "shell.SetClockSkewAlarmsFn(d.clockSkewAlarms)") {
		t.Error("daemon_run.go must wire the monitor into the in-process CLI (`show system alarms`)")
	}
	if src := read("daemon_run_shutdown.go"); !strings.Contains(src, "d.stopAndDiscardClockSkewAlarm()") {
		t.Error("daemon_run_shutdown.go must stop the clock-skew monitor")
	}
	if src := read("daemon_run_servers.go"); !strings.Contains(src, "ClockSkewAlarmsFn: d.clockSkewAlarms,") {
		t.Error("daemon_run_servers.go must bind ClockSkewAlarmsFn into the gRPC server")
	}
}
