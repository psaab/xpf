package daemon

import (
	"context"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/clockskew"
)

// clockSkewRunCmd is the bounded command seam for the clock monitor. It is
// separate from chronyRunCmd (the config-reload seam) so a test of reload debt
// cannot race a monitor sample or accidentally change its result.
var clockSkewRunCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// clockSkewAlarmSampler returns the daemon-resident reference sampler. It
// reads the active config and then asks chrony for the local wall-clock offset;
// no peer RPC is involved, so the alarm remains useful precisely when fabric
// authentication is already failing. One shared sample deadline covers both
// the primary and fallback commands.
func (d *Daemon) clockSkewAlarmSampler() clockskew.Sampler {
	return func(parent context.Context) clockskew.Sample {
		if d == nil || d.store == nil {
			return clockskew.Sample{}
		}
		if parent == nil {
			parent = context.Background()
		}
		if parent.Err() != nil {
			return clockskew.Sample{}
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			return clockskew.Sample{}
		}
		sample := clockskew.Sample{Available: true, Cluster: cfg.Chassis.Cluster != nil}
		if !sample.Cluster {
			// A standalone node has no cross-node fabric RPC to protect and
			// should not fork a clock tool on every tick.
			return sample
		}
		sample.NTPConfigured = len(cfg.System.NTPServers) > 0
		if !sample.NTPConfigured {
			// No source is itself the actionable condition. Avoid a command
			// fork that cannot add information.
			return sample
		}

		// Share one deadline across chronyc and the qualitative fallback. This
		// keeps a pair of unavailable commands from serially consuming two
		// command timeouts during ordered daemon shutdown.
		ctx, cancel := context.WithTimeout(parent, clockskew.CommandTimeout)
		defer cancel()
		out, err := clockSkewRunCmd(ctx, "chronyc", "tracking")
		if err == nil {
			tracking, ok := clockskew.ParseChronyTracking(string(out))
			if ok {
				sample.ReferenceKnown = true
				sample.Synced = tracking.Synced
				sample.HaveOffset = tracking.HaveOffset
				sample.OffsetSecs = tracking.OffsetSecs
				return sample
			}
		}

		// `timedatectl` is a fixed-property fallback: it can still tell us
		// whether synchronization is established, but it cannot provide the
		// numeric offset, so a synced/yes result HOLDs the offset alarm rather
		// than inventing a value.
		out, err = clockSkewRunCmd(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
		if err == nil {
			if synced, ok := clockskew.ParseTimedatectlSync(string(out)); ok {
				sample.ReferenceKnown = true
				sample.Synced = synced
				return sample
			}
		}
		// Both commands failed or produced unusable text. Available remains
		// true (the daemon and config exist), while ReferenceKnown=false makes
		// the monitor HOLD an existing alarm and avoid a false clear.
		return sample
	}
}

// clockSkewAlarms returns the active reference-clock alarms for the local CLI
// and gRPC read surfaces. Atomic publication mirrors natpoolalarm's lifecycle
// contract: readers see either a complete monitor or nil during bootstrap and
// shutdown.
func (d *Daemon) clockSkewAlarms() []clockskew.ActiveAlarm {
	if d == nil {
		return nil
	}
	m := d.clockSkewAlarm.Load()
	if m == nil {
		return nil
	}
	return m.ActiveAlarms()
}

// clockSkewAlarmEmitter forwards one raise/clear transition to configured
// syslog streams. A monitor can still start in NoDataplane mode; the nil guard
// keeps alarm state available to the read surfaces even when no event reader is
// present.
func (d *Daemon) clockSkewAlarmEmitter() clockskew.Emitter {
	return func(severity int, msg string) {
		if d == nil || d.eventReader == nil {
			return
		}
		d.eventReader.ForwardLogMsg(severity, msg)
	}
}

// maybeStartClockSkewAlarm starts the monitor once the daemon has a config
// store. Unlike dataplane alarms, this monitor has a local chrony reference and
// therefore is useful even when the dataplane is disabled. It is safe to call
// repeatedly; the active pointer is immutable until stop/discard.
func (d *Daemon) maybeStartClockSkewAlarm() {
	if d == nil || d.store == nil {
		return
	}
	if d.clockSkewAlarm.Load() != nil {
		return
	}
	m := clockskew.New(d.clockSkewAlarmSampler(), d.clockSkewAlarmEmitter())
	if d.clockSkewAlarmTestTick > 0 {
		m.SetTickForTest(d.clockSkewAlarmTestTick)
	}
	d.clockSkewAlarm.Store(m)
	m.Start()
}

// stopAndDiscardClockSkewAlarm stops the loop and clears its pointer so a
// later bootstrap re-arm builds a fresh monitor. Safe and idempotent.
func (d *Daemon) stopAndDiscardClockSkewAlarm() {
	if d == nil {
		return
	}
	if m := d.clockSkewAlarm.Swap(nil); m != nil {
		m.Stop()
	}
}
