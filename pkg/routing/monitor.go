package routing

import (
	"log/slog"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/linkstate"
	"github.com/vishvananda/netlink"
)

// InterfaceMonitorStatus tracks the link state of a monitored interface.
type InterfaceMonitorStatus struct {
	Interface string
	Weight    int
	Up        bool // true if link is operationally up
	// ConfiguredWeight / Clamped carry the #6589 clamp signal to the display.
	// Weight is what the election APPLIES; these say whether that differs from
	// what the operator wrote. Zero values mean "not clamped", so a producer
	// that does not set them renders exactly as before.
	ConfiguredWeight int
	Clamped          bool
}

// monitorManager is a DISPLAY-ONLY sample of interface-monitor link state
// for `show chassis cluster interfaces` (#17132). It is NOT an election
// producer: pkg/cluster.Monitor is the only producer of interface-monitor
// debt. This sample never feeds SetMonitorWeight. The mu field replaces
// the former shared Manager.mu.
type monitorManager struct {
	ops linkOps

	mu            sync.Mutex
	monitorStatus map[int][]InterfaceMonitorStatus // redundancy-group ID -> monitor states
}

// Apply checks link state for monitored interfaces in each redundancy
// group and stores the results for display.
func (mm *monitorManager) Apply(groups []*config.RedundancyGroup) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// #8073: keep the prior pass's statuses reachable. A transient netlink
	// failure must not erase what we already knew about a monitored link --
	// see the lookup branch below.
	prev := mm.monitorStatus
	mm.monitorStatus = make(map[int][]InterfaceMonitorStatus)
	for _, rg := range groups {
		var statuses []InterfaceMonitorStatus
		for _, mon := range rg.InterfaceMonitors {
			// #6549: bound the configured weight to the [0,255] heartbeat
			// weight domain so `show chassis cluster interfaces` renders
			// the weight the election applies, not a raw out-of-range one.
			// (Display only since #17132; the election's own clamp lives in
			// pkg/cluster.) The strict commit path rejects an out-of-range
			// weight; the tolerant load / peer-sync path only warns
			// (#1960 no-brick), so one can still reach here.
			weight, weightClamped := config.ClampInterfaceMonitorWeight(mon.Weight)

			// Translate Junos name (ge-0/0/0) to Linux name (ge-0-0-0).
			linuxName := config.LinuxIfName(mon.Interface)
			link, err := mm.ops.LinkByName(linuxName)
			if err != nil {
				// #8073: separate genuine absence from a transient lookup
				// failure. The original comment was right about the INTENDED
				// case -- a `chassis cluster interface-monitor` entry naming an
				// interface that lives on the peer node really is absent here,
				// and dropping it is correct. But `err != nil` also catches
				// ENOBUFS under load, EINTR, and a busy or truncated netlink
				// socket, and those took the same silent branch.
				//
				// (#17132: display only — the election reads the dampened
				// pkg/cluster Monitor, not this sample.)
				//
				// isLinkNotFound (vrf.go) is the predicate the sibling bond and
				// tunnel managers already use for this exact conflation, and
				// both RETAIN on the transient arm rather than treating the
				// error as absence. The faithful mirror of that here is to carry
				// the previous pass's status forward: it keeps the interface
				// visible in `show` with the last value actually observed.
				//
				// Deliberately NOT synthesizing Up=false: demoting a redundancy
				// group because a netlink lookup hiccuped would be a worse
				// failure than reporting slightly stale state.
				if !isLinkNotFound(err) {
					if carried, ok := findPrevMonitorStatus(prev, rg.ID, mon.Interface); ok {
						slog.Warn("interface monitor: link lookup failed, "+
							"carrying forward the previous status",
							"redundancy_group", rg.ID,
							"interface", mon.Interface,
							"linux_name", linuxName,
							"carried_up", carried.Up,
							"err", err)
						// Re-clamp: the weight comes from the CURRENT config,
						// not from the stale entry, so a weight change in this
						// commit is still honored while the link state is not
						// re-observed.
						carried.Weight = weight
						carried.ConfiguredWeight = mon.Weight
						carried.Clamped = weightClamped
						statuses = append(statuses, carried)
						continue
					}
					// No prior observation to carry -- the first pass, or the
					// interface is newly monitored. Nothing honest to report,
					// so it is still dropped, but no longer silently.
					slog.Warn("interface monitor: link lookup failed and no "+
						"previous status to carry, omitting from monitor state",
						"redundancy_group", rg.ID,
						"interface", mon.Interface,
						"linux_name", linuxName,
						"err", err)
				}
				continue
			}
			up := linkAttrsUp(link.Attrs())
			statuses = append(statuses, InterfaceMonitorStatus{
				Interface: mon.Interface,
				Weight:    weight,
				Up:        up,
				// #6589: carry the clamp signal to the display. This is the
				// LIVE path both `show chassis cluster interfaces` renderers
				// take; annotating only the config-only fallback would leave
				// the common case silent.
				ConfiguredWeight: mon.Weight,
				Clamped:          weightClamped,
			})
			if !up {
				slog.Warn("interface monitor: link down",
					"redundancy_group", rg.ID,
					"interface", mon.Interface,
					"weight", weight)
			}
		}
		if len(statuses) > 0 {
			mm.monitorStatus[rg.ID] = statuses
		}
	}
}

// linkAttrsUp is an alias of linkstate.Up (#17132: one predicate repo-wide;
// see pkg/linkstate for the carrier rule, #2070).
func linkAttrsUp(attrs *netlink.LinkAttrs) bool { return linkstate.Up(attrs) }

// findPrevMonitorStatus returns the previous pass's status for one monitored
// interface in one redundancy group.
//
// #8073: extracted rather than inlined so the carry-forward decision is
// directly testable. The slice is per-RG and short (one entry per configured
// interface-monitor), so a linear scan is the right shape.
func findPrevMonitorStatus(prev map[int][]InterfaceMonitorStatus, rgID int, iface string) (InterfaceMonitorStatus, bool) {
	for _, st := range prev[rgID] {
		if st.Interface == iface {
			return st, true
		}
	}
	return InterfaceMonitorStatus{}, false
}

// Statuses returns the current monitor state for all redundancy groups.
// Returns nil if no monitors are configured.
func (mm *monitorManager) Statuses() map[int][]InterfaceMonitorStatus {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if len(mm.monitorStatus) == 0 {
		return nil
	}
	// Return a copy
	result := make(map[int][]InterfaceMonitorStatus, len(mm.monitorStatus))
	for k, v := range mm.monitorStatus {
		cp := make([]InterfaceMonitorStatus, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}
