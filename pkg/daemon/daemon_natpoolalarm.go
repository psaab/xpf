package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/natpoolalarm"
)

// natPoolAlarmSampler returns a natpoolalarm.Sampler that reads the
// userspace helper's last-applied, generation-coherent NAT pool view from
// the manager's cached state (#2079). It performs NO control-socket I/O: the
// manager's AppliedNATView reads m.lastStatus (refreshed by the 1 Hz status
// loop) and m.appliedSnapshot (captured at each successful apply_snapshot).
//
// When the published dataplane is not the userspace adapter (e.g. NoDataplane), the sampler
// reports Available:false so the monitor HOLDs (makes no decision).
func (d *Daemon) natPoolAlarmSampler() natpoolalarm.Sampler {
	return func() natpoolalarm.View {
		if d == nil {
			return natpoolalarm.View{Available: false}
		}
		// #2114: one dataplane snapshot per sampler tick (plan §5.3
		// rule 1) — the monitor goroutine runs concurrently with the
		// bootstrap-exit writer.
		rt := d.dataplane()
		if rt == nil {
			return natpoolalarm.View{Available: false}
		}
		adapter, ok := rt.(interface {
			Manager() *dpuserspace.Manager
		})
		if !ok {
			return natpoolalarm.View{Available: false}
		}
		mgr := adapter.Manager()
		if mgr == nil {
			return natpoolalarm.View{Available: false}
		}
		return projectNATPoolView(mgr.AppliedNATView())
	}
}

// projectNATPoolView maps the manager's applied NAT view onto the monitor's
// dataplane-free View. Pure function of its argument (all fields exported)
// so the field copy is unit-testable: dropping a field here silently
// starves the monitor, and the test pins every copied field.
func projectNATPoolView(v dpuserspace.AppliedNATView) natpoolalarm.View {
	if !v.Available {
		return natpoolalarm.View{Available: false}
	}
	pools := make(map[string]natpoolalarm.PoolStatus, len(v.Pools))
	for name, p := range v.Pools {
		pools[name] = natpoolalarm.PoolStatus{
			PoolName:        p.PoolName,
			AddressCount:    p.AddressCount,
			PortLow:         p.PortLow,
			PortHigh:        p.PortHigh,
			UsedPorts:       p.UsedPorts,
			ExhaustionTotal: p.ExhaustionTotal,
			AllocatorID:     p.AllocatorID,
			LiveFlows:       p.LiveFlows,
			MaxTrackedFlows: p.MaxTrackedFlows,
		}
	}
	return natpoolalarm.View{
		Config:         v.Config,
		Pools:          pools,
		HelperCoherent: v.HelperCoherent,
		Available:      true,
		StatusSequence: v.StatusSequence,
		ProcGen:        v.ProcGen,
	}
}

// natPoolAlarmEmitter returns a natpoolalarm.Emitter that forwards one
// pre-formatted structured RT_NAT line to all configured syslog streams and
// local writers via the daemon's EventReader (#2079). It is gated entirely
// behind a raise/clear transition by the monitor, so it fires at most a
// couple of lines per pool per utilization excursion — never per tick.
func (d *Daemon) natPoolAlarmEmitter() natpoolalarm.Emitter {
	return func(severity int, msg string) {
		if d == nil || d.eventReader == nil {
			return
		}
		d.eventReader.ForwardLogMsg(severity, msg)
	}
}

// natPoolAlarms returns the active NAT pool-utilization alarms for the
// `show security alarms` render sites (#2079). Returns nil when the monitor
// is not running (NoDataplane, bootstrap mode, or a torn-down dataplane).
//
// #2114: reads the monitor pointer atomically. This runs on gRPC/CLI
// request goroutines concurrently with the runtime start (bootstrap exit)
// and stop+discard (bootstrap rollback / shutdown) of the monitor. The
// atomic Load yields either a valid *Monitor (ActiveAlarms() is itself
// mutex-guarded inside the monitor) or nil — never a torn pointer.
func (d *Daemon) natPoolAlarms() []natpoolalarm.ActiveAlarm {
	if d == nil {
		return nil
	}
	m := d.natPoolAlarm.Load()
	if m == nil {
		return nil
	}
	return m.ActiveAlarms()
}

// natPoolExhaustionAlarms returns the active NAT pool-exhaustion alarms for
// the `show security alarms` render sites (#9902 F-026). Returns nil when
// the monitor is not running. Same #2114 atomic-read contract as
// natPoolAlarms.
func (d *Daemon) natPoolExhaustionAlarms() []natpoolalarm.ActiveExhaustionAlarm {
	if d == nil {
		return nil
	}
	m := d.natPoolAlarm.Load()
	if m == nil {
		return nil
	}
	return m.ActiveExhaustionAlarms()
}

// maybeStartNATPoolAlarm constructs and starts the NAT pool-alarm monitor
// daemon (#2114). It is idempotent: a non-nil stored monitor short-circuits.
//
// Called from the normal-boot background-services block (daemon_run.go) and
// from runBootstrapExitStartup's successful-arm branch. Both call sites run
// before the control plane serves requests (boot) or under d.applySem
// (bootstrap exit), so two concurrent constructions cannot interleave; the
// Load()!=nil short-circuit plus the atomic Store are belt-and-suspenders.
//
// The unpublished-dataplane guard keeps the helper self-contained: bootstrap suppresses
// the start, and a torn-down/never-armed dataplane has nothing to sample.
func (d *Daemon) maybeStartNATPoolAlarm() {
	if d.opts.NoDataplane || d.inBootstrap() || d.dataplane() == nil {
		return
	}
	if d.natPoolAlarm.Load() != nil {
		return // already started
	}
	m := natpoolalarm.New(d.natPoolAlarmSampler(), d.natPoolAlarmEmitter())
	// Test seam: drive the sampler at a fast tick so the #2114 race tests can
	// exercise the sampler-vs-dataplane-cell overlap deterministically. Zero in
	// production (default 10s cadence). Must be applied before Start().
	if d.natPoolAlarmTestTick > 0 {
		m.SetTickForTest(d.natPoolAlarmTestTick)
	}
	d.natPoolAlarm.Store(m)
	m.Start()
}

// stopAndDiscardNATPoolAlarm stops the monitor (Stop joins its goroutine)
// and CLEARS the pointer so a later re-arm builds a fresh monitor — the
// natpoolalarm.Monitor is not restartable after Stop() (#2114). Safe when no
// monitor is running (Swap returns nil). Called from bootstrap rollback
// (enterBootstrapMode) and shutdown. The atomic Swap(nil) is the single
// read-and-clear point, so a concurrent natPoolAlarms() reader sees either
// the old monitor or nil, never a torn pointer.
func (d *Daemon) stopAndDiscardNATPoolAlarm() {
	if m := d.natPoolAlarm.Swap(nil); m != nil {
		m.Stop()
	}
}
