package daemon

import (
	"context"
	"fmt"
	"math"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/clockskew"
	"github.com/psaab/xpf/pkg/config"
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
		return d.clockSkewAlarmSample(parent, d.store.ActiveConfig())
	}
}

func (d *Daemon) clockSkewAlarmSample(parent context.Context, cfg *config.Config) clockskew.Sample {
	if d == nil || cfg == nil {
		return clockskew.Sample{}
	}
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
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

// confirmRecoveryClockSkewActive samples the just-loaded config while
// configstore is recovering confirm.json. Load holds the Store lock, so this
// path intentionally uses cfg directly instead of calling ActiveConfig.
func (d *Daemon) confirmRecoveryClockSkewActive(cfg *config.Config) bool {
	sample := d.clockSkewAlarmSample(context.Background(), cfg)
	if !sample.Available || !sample.Cluster {
		return false
	}
	if !sample.NTPConfigured {
		return true
	}
	if !sample.ReferenceKnown {
		return false
	}
	if !sample.Synced {
		return true
	}
	return sample.HaveOffset && !math.IsNaN(sample.OffsetSecs) &&
		!math.IsInf(sample.OffsetSecs, 0) &&
		math.Abs(sample.OffsetSecs) >= clockskew.RaiseAtSecs
}

// clockSkewAlarms returns the active reference-clock alarms for the local CLI
// and gRPC read surfaces. Atomic publication mirrors natpoolalarm's lifecycle
// contract: readers see either a complete monitor or nil during bootstrap and
// shutdown.
func (d *Daemon) clockSkewAlarms() []clockskew.ActiveAlarm {
	if d == nil {
		return nil
	}
	var out []clockskew.ActiveAlarm
	if m := d.clockSkewAlarm.Load(); m != nil {
		out = m.ActiveAlarms()
	}
	// #18585: the inter-node alarm, measured over admitted heartbeats by the
	// cluster manager. Merged here so it reaches every surface the local
	// reference alarm does (show system alarms, show security alarms detail,
	// show chassis cluster status).
	if d.cluster != nil {
		if offset, raisedAt, raised := d.cluster.PeerClockSkewAlarm(); raised {
			out = append(out, clockskew.ActiveAlarm{
				Kind:       clockskew.KindPeerOffset,
				OffsetSecs: offset.Seconds(),
				FirstSeen:  raisedAt,
			})
		}
	}
	return out
}

// peerClockAlarmSyslog forwards one #18585 peer-offset alarm transition to the
// same syslog streams as the local reference alarm.
func (d *Daemon) peerClockAlarmSyslog(raised bool, offset time.Duration) {
	severity, msg := clockskew.PeerOffsetSyslogLine(raised, offset.Seconds())
	d.clockSkewAlarmEmitter()(severity, msg)
}

// unkeyedAuthorityGraceAlarmSyslog forwards each #16016 notice rung and
// posture transition to the same RT_SYSTEM syslog streams as clock-skew alarms.
func (d *Daemon) unkeyedAuthorityGraceAlarmSyslog(rung string, raised bool, expiry time.Time) {
	severity := clockskew.SeverityRaise
	transition := "UNKEYED_AUTHORITY_GRACE_NOTICE"
	if !raised {
		severity = clockskew.SeverityClear
		transition = "UNKEYED_AUTHORITY_GRACE_CLEARED"
	} else {
		switch rung {
		case "stamped":
			transition = "UNKEYED_AUTHORITY_GRACE_STAMPED"
		case "t-24h":
			transition = "UNKEYED_AUTHORITY_GRACE_T_MINUS_24H"
		case "t-1h":
			transition = "UNKEYED_AUTHORITY_GRACE_T_MINUS_1H"
		case "expired":
			transition = "UNKEYED_AUTHORITY_GRACE_EXPIRED"
		case "daily-expired":
			transition = "UNKEYED_AUTHORITY_GRACE_EXPIRED_REMINDER"
		}
	}
	detail := "unkeyed control authority remains accepted; key the cluster before expiry"
	if rung == "expired" || rung == "daily-expired" {
		detail = "expired unkeyed control authority; a clock step can cause this — re-arm deliberately or key the cluster"
		if !expiry.IsZero() {
			detail = fmt.Sprintf("%s; expired_at=%s", detail, expiry.UTC().Format(time.RFC3339))
		}
	} else if !expiry.IsZero() {
		detail = fmt.Sprintf("%s; expires=%s", detail, expiry.UTC().Format(time.RFC3339))
	}
	d.clockSkewAlarmEmitter()(severity, fmt.Sprintf("RT_SYSTEM - %s rung=%q detail=%q", transition, rung, detail))
}

// unkeyedAuthorityRecoveryAuditSyslog records the local operator's explicit
// break-glass ownership choice in the RT_SYSTEM stream.
func (d *Daemon) unkeyedAuthorityRecoveryAuditSyslog(action, operator string, rgID, nodeID int, at time.Time, reason string) {
	rg := ""
	if rgID >= 0 {
		rg = fmt.Sprintf(" rg=%d", rgID)
	}
	msg := fmt.Sprintf("RT_SYSTEM - UNKEYED_AUTHORITY_RECOVERY action=%q operator=%q%s node=%d at=%s reason=%q",
		action, operator, rg, nodeID, at.UTC().Format(time.RFC3339Nano), reason)
	d.clockSkewAlarmEmitter()(clockskew.SeverityRaise, msg)
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
