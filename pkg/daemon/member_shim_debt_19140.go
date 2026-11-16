package daemon

import (
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #19140: a primary whose RETH data member positively lost its XDP shim gives
// the RG to a healthy peer.
//
// #19110 makes such a member a takeover-readiness reason, which stops a
// STANDBY from taking the RG. It does nothing for the current PRIMARY: the
// link is up, so the interface monitor charges no weight, and readiness gates
// only promotion. Meanwhile the #10302 fence drops that member's kernel-path
// transit and AF_XDP never sees it, so a primary at full weight black-holes the
// RG's traffic on that RETH until a commit or a link event re-attaches (#19110
// removed the background re-attach).
//
// This producer runs on the transit-gate tick (1 s, reassertTransitGate). It
// charges cluster.RethMemberShimMonitorIface, at the arm floor (weight 1, never
// 0), to every RG that owns a RETH whose local member has been POSITIVELY
// missing for memberShimDebtGrace. The #12164 floor-debt yield then hands the
// RG to a peer that is heavier, wins the scaled ordering, holds a live echo
// lease and passes its own readiness gate (which, by #19110, refuses a peer
// whose member is shim-less too). A lone owner keeps the RG at weight 1 with an
// ERROR. A standby is charged too, so two equally broken nodes tie at the
// floor and nothing moves; a healthy primary never yields to a charged
// standby, because the yield needs the PEER to be heavier.
//
// Evidence rules (#19110's readiness classification, read lock-free through
// DataMemberShimVerdict):
//   - only MISSING (absent, not attached, a foreign program) starts or
//     extends an episode;
//   - ATTACHED ends it, and NOT-REQUIRED (administratively disabled, or
//     non-Ethernet framing for this config and device) never accrues debt;
//   - UNVERIFIED changes nothing: an episode's start is held, never advanced
//     or reset, and debt is neither installed nor cleared on it. A stale
//     snapshot (older than memberShimVerdictMaxAge), or none, counts as
//     unverified for every member. A primary is never demoted on the ABSENCE
//     of evidence.
//
// Debt clears only after every member of the RG has been attached (or not
// required) for memberShimClearHold, so a missing/attached flutter keeps it.
// A member, RETH or RG that leaves the configuration takes its debt with it.

const (
	// memberShimDebtGrace is how long a member must be continuously
	// POSITIVELY missing before its RG is charged. It absorbs a refused
	// refresh attach that a later link event fixes, and the VF re-probe
	// window. Coordinator decision 2026-11-16: a constant, no knob.
	memberShimDebtGrace = 10 * time.Second
	// memberShimClearHold is how long every member of a charged RG must be
	// attached (or not required) before the debt clears.
	memberShimClearHold = 10 * time.Second
	// memberShimVerdictMaxAge bounds the age of the snapshot's earliest
	// observation, the same bound #19110's readiness uses.
	memberShimVerdictMaxAge = 3 * time.Second
)

// memberShimVerdictSource is the userspace dataplane's lock-free #19140
// classification (the adapter in production).
type memberShimVerdictSource interface {
	DataMemberShimVerdict() (dpuserspace.DataMemberShimVerdict, bool)
}

// memberShimTracker is the producer's episode state. Guarded by
// Daemon.transitGateMu (reassertTransitGate holds it).
type memberShimTracker struct {
	// missingSince is when a member's current run of positive missing
	// evidence began; held across unverified ticks.
	missingSince map[string]time.Time
	// healthySince is when a member's current run of attached or
	// not-required evidence began; held across unverified ticks.
	healthySince map[string]time.Time
	// lastStatus is each member's last non-unverified classification and
	// detail, for the log.
	lastStatus map[string]dpuserspace.DataMemberShimState
	// debt is the RGs this producer charged.
	debt map[int]bool
}

// memberShimNow is the producer's clock. A seam for the cells.
var memberShimNow = time.Now

// applyMemberShimDebt is one producer pass. Caller holds d.transitGateMu.
func (d *Daemon) applyMemberShimDebt() {
	if d == nil || d.cluster == nil {
		return
	}
	src, ok := d.dataplane().(memberShimVerdictSource)
	if !ok {
		return
	}
	v, ok := src.DataMemberShimVerdict()
	if !ok {
		return // nothing published yet: no evidence, change nothing
	}
	now := memberShimNow()
	t := &d.memberShim
	if t.missingSince == nil {
		t.missingSince = map[string]time.Time{}
		t.healthySince = map[string]time.Time{}
		t.lastStatus = map[string]dpuserspace.DataMemberShimState{}
		t.debt = map[int]bool{}
	}

	// The RGs each configured member's RETH belongs to, from the config the
	// verdict was classified against.
	memberRGs := memberShimRGs(v.Config)
	if len(memberRGs) == 0 {
		// No configured RETH member: every episode and every debt goes.
		t.missingSince = map[string]time.Time{}
		t.healthySince = map[string]time.Time{}
		t.lastStatus = map[string]dpuserspace.DataMemberShimState{}
		for rg := range t.debt {
			d.setMemberShimDebt(rg, false, "no RETH data member is configured any more", nil, now)
		}
		return
	}
	fresh := v.Checked && !v.At.IsZero() && now.Sub(v.At) <= memberShimVerdictMaxAge
	if !v.Checked {
		// No shim program loaded: a distinct state, blocked elsewhere. No
		// evidence about the members: change nothing.
		return
	}
	// current is each member's classification THIS tick (unverified for
	// every member of a stale snapshot). Debt is installed only on a member
	// that is missing NOW, and cleared only when every member is healthy NOW:
	// an unverified member freezes its RG's debt state, whatever its held
	// episode says.
	current := map[string]dpuserspace.DataMemberShimStatus{}
	if fresh {
		seen := map[string]bool{}
		for _, mem := range v.Members {
			seen[mem.LinuxName] = true
			current[mem.LinuxName] = mem.Status
			switch mem.Status {
			case dpuserspace.DataMemberShimMissing:
				if t.missingSince[mem.LinuxName].IsZero() {
					t.missingSince[mem.LinuxName] = now
				}
				delete(t.healthySince, mem.LinuxName)
				t.lastStatus[mem.LinuxName] = mem
			case dpuserspace.DataMemberShimAttached, dpuserspace.DataMemberShimNotRequired:
				delete(t.missingSince, mem.LinuxName)
				if t.healthySince[mem.LinuxName].IsZero() {
					t.healthySince[mem.LinuxName] = now
				}
				t.lastStatus[mem.LinuxName] = mem
			default: // unverified: hold both episodes exactly as they are
			}
		}
		for name := range t.missingSince {
			if !seen[name] {
				delete(t.missingSince, name)
			}
		}
		for name := range t.healthySince {
			if !seen[name] {
				delete(t.healthySince, name)
			}
		}
	}

	// Per RG: which members, and whether the RG still exists in config.
	rgMembers := map[int][]string{}
	for name, rgs := range memberRGs {
		for _, rg := range rgs {
			rgMembers[rg] = append(rgMembers[rg], name)
		}
	}
	// An RG this producer charged whose RETH members all left the config.
	for rg := range t.debt {
		if _, ok := rgMembers[rg]; !ok {
			d.setMemberShimDebt(rg, false, "the RG has no configured RETH data member any more", nil, now)
		}
	}
	if !fresh {
		return // unverified for every member: install nothing, clear nothing
	}
	for _, rg := range sortedRGs(rgMembers) {
		names := rgMembers[rg]
		sort.Strings(names)
		if !t.debt[rg] {
			for _, name := range names {
				since := t.missingSince[name]
				if current[name] == dpuserspace.DataMemberShimMissing &&
					!since.IsZero() && now.Sub(since) >= memberShimDebtGrace {
					st := t.lastStatus[name]
					d.setMemberShimDebt(rg, true, "", &st, since)
					break
				}
			}
			continue
		}
		healthy := true
		for _, name := range names {
			st, known := current[name]
			since := t.healthySince[name]
			if !known || (st != dpuserspace.DataMemberShimAttached && st != dpuserspace.DataMemberShimNotRequired) ||
				since.IsZero() || now.Sub(since) < memberShimClearHold {
				healthy = false
				break
			}
		}
		if healthy {
			d.setMemberShimDebt(rg, false, "every RETH data member of the RG has its XDP shim again", nil, now)
		}
	}
}

// setMemberShimDebt installs or clears one RG's member-shim debt, on change
// only, and logs the edge. RG0 is never charged.
func (d *Daemon) setMemberShimDebt(rg int, on bool, why string, st *dpuserspace.DataMemberShimState, since time.Time) {
	t := &d.memberShim
	if rg <= 0 || t.debt[rg] == on {
		if !on {
			delete(t.debt, rg)
		}
		return
	}
	d.cluster.SetMonitorWeight(rg, cluster.RethMemberShimMonitorIface, on, cluster.RethMemberShimMonitorCost)
	if on {
		t.debt[rg] = true
		member, detail := "", ""
		if st != nil {
			member, detail = st.LinuxName, st.Detail
		}
		slog.Error("cluster: a RETH data member of this redundancy group has no XDP shim; charging the RG "+
			"member-shim election debt (weight 1): the RG yields to a healthy, takeover-ready peer if there is "+
			"one, and a lone owner keeps it",
			"rg", rg, "member", member, "detail", detail,
			"missing_for", memberShimNow().Sub(since).Round(time.Second), "issue", "#19140")
		return
	}
	delete(t.debt, rg)
	slog.Info("cluster: RETH member-shim election debt cleared", "rg", rg, "why", why, "issue", "#19140")
}

// memberShimRGs maps each configured local RETH data member (Linux name) to the
// RGs of the RETHs it serves. RG0 never appears.
func memberShimRGs(cfg *config.Config) map[string][]int {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	owners := cfg.RethRGOwners()
	out := map[string][]int{}
	for reth, phys := range cfg.RethToPhysical() {
		rg := owners[reth]
		if rg <= 0 {
			continue
		}
		name := config.LinuxIfName(phys)
		out[name] = append(out[name], rg)
	}
	return out
}

func sortedRGs(m map[int][]string) []int {
	out := make([]int, 0, len(m))
	for rg := range m {
		out = append(out, rg)
	}
	sort.Ints(out)
	return out
}
