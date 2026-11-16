package userspace

import (
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #19140: the #19110 readiness classification, structured and published
// lock-free for the daemon's member-shim election debt.
//
// #19110 stops a STANDBY whose RETH data member has no XDP shim from taking an
// RG (a takeover-readiness reason). It does nothing for the current PRIMARY,
// whose link is still up, so it keeps full weight and black-holes that member's
// transit indefinitely. #19140's daemon tick charges such a primary an
// election debt at the arm floor. It needs the same per-member verdict that
// readiness uses, without waiting on m.mu (which the HA cutover holds across
// helper round trips, #18711).
//
// So the classification lives in ONE function, classifyDataMembersLocked,
// which readiness formats into its reasons and the publisher snapshots. The
// snapshot is republished under m.mu whenever an input changes: an observation
// pass (observeDataMembers), a link-generation bump (a link event for a
// member), and a compile (a new membership authority). A reader therefore sees
// what readiness would say at the last such point. It still judges the
// snapshot's age itself (At, the verdict's earliest observation), because a
// stalled tick loop publishes nothing new.

// DataMemberShimStatus is one member's classification.
type DataMemberShimStatus int

const (
	// DataMemberShimAttached: POSITIVE evidence, the shim's program on the
	// member's current ifindex.
	DataMemberShimAttached DataMemberShimStatus = iota
	// DataMemberShimMissing: POSITIVELY missing: the netdev is absent, has
	// no XDP, or carries a foreign program.
	DataMemberShimMissing
	// DataMemberShimUnverified: no usable evidence either way (a failed
	// lookup, an unidentified program, a stale verdict or one made against
	// another config or program, a member not observed yet, or a
	// non-Ethernet exclusion whose device has changed since).
	DataMemberShimUnverified
	// DataMemberShimNotRequired: not a required attachment: administratively
	// disabled, or non-Ethernet framing for this config and this device.
	DataMemberShimNotRequired
)

func (s DataMemberShimStatus) String() string {
	switch s {
	case DataMemberShimAttached:
		return "attached"
	case DataMemberShimMissing:
		return "missing"
	case DataMemberShimUnverified:
		return "unverified"
	case DataMemberShimNotRequired:
		return "not-required"
	}
	return "unknown"
}

// DataMemberShimState is one configured local RETH data member.
type DataMemberShimState struct {
	LinuxName  string
	ConfigName string
	Status     DataMemberShimStatus
	Detail     string
}

// DataMemberShimVerdict is one published classification. It is immutable once
// published.
type DataMemberShimVerdict struct {
	// Config is the membership authority it was classified against.
	Config *config.Config
	// At is the underlying verdict's EARLIEST observation; zero when there is
	// none. A reader treats a snapshot older than its freshness bound as
	// unverified for every member.
	At time.Time
	// Checked is false when no check applies: no configured member, or no
	// shim program loaded (a distinct state, blocked elsewhere).
	Checked bool
	Members []DataMemberShimState
}

// classifyDataMembersLocked classifies every configured local RETH data member
// against the last tick's verdict and the CURRENT config, program and link
// generations. It makes no syscall. checked is false when no check applies.
// Caller holds m.mu.
func (m *Manager) classifyDataMembersLocked() (members []DataMemberShimState, checked bool) {
	cfg := m.genericDataMemberCfg
	configured := localDataMembers(cfg)
	if len(configured) == 0 {
		return nil, false
	}
	prog := m.entryProgramLocked()
	if prog == nil {
		return nil, false // no shim program loaded: a distinct state, already blocked elsewhere
	}
	v := m.memberVerdict
	stale := ""
	switch {
	case v.cfg != cfg:
		stale = "unverified: not yet observed against the current configuration"
	case v.prog != prog:
		stale = "unverified: not yet observed against the loaded shim program"
	case v.progErr != "":
		stale = "unverified: the loaded shim program could not be identified: " + v.progErr
	case v.oldest.IsZero() || memberNow().Sub(v.oldest) > memberVerdictMaxAge:
		stale = "unverified: no observation in the last " + memberVerdictMaxAge.String()
	}
	out := make([]DataMemberShimState, 0, len(configured))
	for _, mem := range configured {
		st := DataMemberShimState{LinuxName: mem.linuxName, ConfigName: mem.cfgName}
		o, observed := v.obs[mem.linuxName]
		switch {
		case mem.disabled:
			// Not required: pure config, under any verdict.
			st.Status, st.Detail = DataMemberShimNotRequired, "excluded: administratively disabled"
		case observed && v.cfg == cfg && o.kind == "excluded:non-ethernet":
			if o.linkGen == m.memberLink[mem.linuxName].gen {
				// Not required: framing, for this config and this device,
				// under any verdict age.
				st.Status, st.Detail = DataMemberShimNotRequired, o.detail
			} else {
				st.Status = DataMemberShimUnverified
				st.Detail = "unverified: the member's device changed after it was observed as non-Ethernet"
			}
		case stale != "":
			st.Status, st.Detail = DataMemberShimUnverified, stale
		case !observed:
			st.Status, st.Detail = DataMemberShimUnverified, "unverified: not observed yet"
		case o.kind == "":
			st.Status = DataMemberShimAttached
		case strings.HasPrefix(o.kind, "excluded"):
			st.Status, st.Detail = DataMemberShimNotRequired, o.detail
		case o.kind == "unverified":
			st.Status, st.Detail = DataMemberShimUnverified, o.detail
		default: // absent, not-attached, foreign-program
			st.Status, st.Detail = DataMemberShimMissing, o.detail
		}
		out = append(out, st)
	}
	return out, true
}

// publishMemberShimVerdictLocked republishes the classification. Caller holds
// m.mu, so it is ordered against every input change.
func (m *Manager) publishMemberShimVerdictLocked() {
	members, checked := m.classifyDataMembersLocked()
	m.memberShimVerdict.Store(&DataMemberShimVerdict{
		Config:  m.genericDataMemberCfg,
		At:      m.memberVerdict.oldest,
		Checked: checked,
		Members: members,
	})
}

// DataMemberShimVerdict returns the last published classification, lock-free.
// ok is false before the first publication. The Members slice is a copy.
func (m *Manager) DataMemberShimVerdict() (DataMemberShimVerdict, bool) {
	if m == nil {
		return DataMemberShimVerdict{}, false
	}
	p := m.memberShimVerdict.Load()
	if p == nil {
		return DataMemberShimVerdict{}, false
	}
	out := *p
	out.Members = append([]DataMemberShimState(nil), p.Members...)
	return out, true
}
