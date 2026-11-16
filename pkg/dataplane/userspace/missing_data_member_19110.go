package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #19110: a configured RETH data member with NO XDP shim attached is a
// takeover-readiness reason, from LIVE kernel state. Fail-closed.
//
// The refresh path never waits (zero refresh budgets), so a refused or failed
// attach of a recreated member leaves it with no XDP, and the #10302 fence
// drops its transit. NOTHING retries that attach automatically. Two earlier
// designs did: a record of failed attaches, then a background per-name attach
// worker. Review found the record could be erased by a partial pass and the
// worker could attach a reused index, escape config, program and Close
// fencing, and bypass structural admission (codex-e, codex-f). The user chose
// to remove both. Recovery is the next compile (an operator commit) or a later
// link-refresh event for the member. This file only makes the state visible.
//
// The observation runs on the STATUS TICK, OFF m.mu. Readiness
// (takeoverReadyLocked) runs under m.mu, which UpdateRGActive (the HA cutover)
// also needs. Its callers are the daemon's RG reconcile loop (reconcileRGState:
// every 2 s and on every triggered pass, once per RG; the result reaches the
// election through SetRGReady) and the metrics scrape. So:
//   - Once per tick, after the tick releases m.mu, observeDataMembers reads
//     the shim's entry program ID (a syscall, cached per loaded program and
//     made only on the tick) and looks up each configured local RETH data
//     member by NAME on a netlink handle with a 250 ms socket timeout. Every
//     observation carries its OWN timestamp, taken before its lookup.
//   - It publishes ONE verdict per pass. The verdict records the config
//     authority and the program it was made against, and it is aged from its
//     EARLIEST observation. Old evidence is never re-stamped at publish time.
//   - Readiness SERVES that verdict and makes no syscall. The member is
//     "unverified" (NOT ready) when the verdict was made against another config
//     or another program, when the loaded program could not be identified,
//     when its earliest observation is older than memberVerdictMaxAge, or when
//     it lacks this member.
//   - Positive evidence: XDP attached to the member's CURRENT ifindex with the
//     shim's own program ID. Absent, not attached, a foreign program or a
//     failed lookup is the reason "<name> has no XDP shim attached (<kind>)",
//     blocker xdp_missing_data_member. Its scope is F4's: with the peer alive
//     it blocks; a lone owner gets the ERROR log and the peer-alive-form metric.
//   - "Attachment REQUIRED?" is classified separately from attachment
//     freshness. Not required, and so never a blocker:
//       - a member whose base row is administratively disabled
//         (baseRowAdminDisabled: its own `disable`, or a disabled unit 0 on the
//         same netdev). This is pure config, so it holds under any verdict;
//       - a member with known non-Ethernet framing (dataplane.ShimAttachRefused),
//         classified from every lookup, whether or not the program could be
//         identified. Framing is a property of the DEVICE, not of attachment,
//         so the exclusion is kept across verdict staleness, but only while
//         the verdict was made against the CURRENT config AND the member's
//         device is the one observed. Device identity is the member's LINK
//         GENERATION (memberLinkState, user decision after codex-h): the
//         link-refresh path bumps it on any device change for the member
//         (noteDataMemberLinksLocked), and every observation is stamped with
//         the generation read at pass start, BEFORE its lookup. Readiness
//         keeps the exclusion only while the stamp equals the current
//         generation, a plain comparison with no I/O. A replaced member
//         becomes a blocker at once, within the freshness window too, and
//         stays one with the tick loop stalled. An observation that races a
//         replacement carries the OLD generation, so it cannot publish an
//         exemption for the new device.
//     These are the refresh path's structural attach exclusions
//     (refreshStructuralAttachAdmission).
//   - NO shim program loaded is its own state: the check is skipped, because
//     other reasons already block. A loaded program that cannot be identified
//     is NOT that state: its members are "unverified".
//
// Cost: per tick, one netlink lookup per configured member, plus one program
// info query when the loaded program changed. All of it runs off m.mu, and
// each lookup is bounded by its socket timeout. The tick logs on change only,
// keyed on a stable kind.

// missingDataMemberReasonMarker is the substring MapHATakeoverBlocker keys on.
const missingDataMemberReasonMarker = "has no XDP shim attached"

const (
	memberXDPQueryTimeout = 250 * time.Millisecond
	// memberVerdictMaxAge bounds the age of a verdict's EARLIEST observation:
	// one 1 s status tick plus the pass's own lookups and scheduling slack.
	memberVerdictMaxAge = 3 * time.Second
)

// errMemberAbsent: the member's netdev does not exist (yet) in this netns.
var errMemberAbsent = errors.New("data member netdev absent")

// memberXDPState is the kernel's view of one member, read by NAME.
type memberXDPState struct {
	Ifindex  int
	Attached bool
	ProgID   uint32
	// NotAttachable: known non-Ethernet framing; the shim never attaches it.
	NotAttachable bool
}

// memberXDPStateFn reads the member's current ifindex, framing and IFLA_XDP by
// name. It is a seam for the cells.
var memberXDPStateFn = func(name string) (memberXDPState, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return memberXDPState{}, err
	}
	defer h.Close()
	if err := h.SetSocketTimeout(memberXDPQueryTimeout); err != nil {
		return memberXDPState{}, err
	}
	l, err := h.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return memberXDPState{}, errMemberAbsent
		}
		return memberXDPState{}, err
	}
	a := l.Attrs()
	st := memberXDPState{Ifindex: a.Index, NotAttachable: dataplane.ShimAttachRefused(l, nil)}
	if a.Xdp != nil && a.Xdp.Attached {
		st.Attached, st.ProgID = true, a.Xdp.ProgId
	}
	return st, nil
}

// programIDFn reads a loaded program's kernel ID: BPF_OBJ_GET_INFO_BY_FD plus
// /proc/self/fdinfo. Only the status tick calls it, off m.mu. A seam.
var programIDFn = func(p *ebpf.Program) (uint32, error) {
	info, err := p.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("program info carries no ID")
	}
	return uint32(id), nil
}

// dataMember is one configured local RETH data member.
type dataMember struct {
	cfgName, linuxName string
	disabled           bool // baseRowAdminDisabled: the snapshot's AdminDisabled for its base row
}

// localDataMembers is the config's local RETH data members, sorted by Linux name.
func localDataMembers(cfg *config.Config) []dataMember {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	seen := map[string]dataMember{}
	for _, phys := range cfg.RethToPhysical() {
		mem := dataMember{cfgName: phys, linuxName: config.LinuxIfName(phys)}
		if ifc := cfg.Interfaces.Interfaces[phys]; ifc != nil {
			mem.disabled = baseRowAdminDisabled(cfg, phys, ifc, snapshotLinuxName(cfg, phys, ifc, nil))
		}
		seen[mem.linuxName] = mem
	}
	out := make([]dataMember, 0, len(seen))
	for _, mem := range seen {
		out = append(out, mem)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].linuxName < out[j].linuxName })
	return out
}

// localDataMemberNames is localDataMembers' Linux names.
func localDataMemberNames(cfg *config.Config) []string {
	members := localDataMembers(cfg)
	if members == nil {
		return nil
	}
	names := make([]string, len(members))
	for i, mem := range members {
		names[i] = mem.linuxName
	}
	return names
}

// entryProgramLocked is the shim's loaded entry program, nil when none is
// loaded. It goes through EntryProgramIdentity, which has no side effect: no
// syscall, no obsolete-registry log or count. Caller holds m.mu (lock order:
// the userspace m.mu, then the shim's).
func (m *Manager) entryProgramLocked() *ebpf.Program {
	if m.entryProgramHook != nil {
		return m.entryProgramHook()
	}
	if m.bpfShim == nil {
		return nil
	}
	return m.bpfShim.EntryProgramIdentity()
}

// shimProgIDCache is the tick's identification of one loaded program.
type shimProgIDCache struct {
	prog *ebpf.Program
	id   uint32
	err  error
}

// memberObservation is one member's observation, with its own timestamp.
type memberObservation struct {
	at      time.Time
	kind    string // "" positive evidence; "excluded:*" not required; else missing
	detail  string
	linkGen uint64 // the member's link generation when the pass STARTED, before the lookup
}

// memberLinkState is one data member's device lifecycle as the attach paths
// last resolved it (#19110). gen counts device changes; ifindex is the last
// resolved index (0: absent or unresolved). Guarded by m.mu.
type memberLinkState struct {
	gen     uint64
	ifindex int
}

// noteDataMemberLinksLocked bumps the link generation of every configured data
// member whose device changed. resolved maps each member's Linux name to its
// ifindex as just resolved by name (absent: 0). A member's generation moves
// when the link event names it (a re-create that kept its ifindex, or any
// other change to that device), and when its ifindex differs from the last
// one recorded (add, remove, re-create). The daemon coalesces RTNL events to
// the newest name, so the ifindex comparison is what catches a member whose
// own event was coalesced away. eventName is "" for the compile, which records
// the baseline from the ifindexes it already resolved. Generations only grow,
// and names that leave the configuration keep theirs: a verdict made against
// another config is never served anyway. Caller holds m.mu.
func (m *Manager) noteDataMemberLinksLocked(resolved map[string]int, eventName string) {
	if len(resolved) == 0 {
		return
	}
	if m.memberLink == nil {
		m.memberLink = map[string]memberLinkState{}
	}
	for name, ifindex := range resolved {
		st := m.memberLink[name]
		if name == eventName || ifindex != st.ifindex {
			st.gen++
		}
		st.ifindex = ifindex
		m.memberLink[name] = st
	}
}

// resolveDataMemberIfindexes resolves each configured data member by name;
// an unresolvable member is 0. It takes no Manager lock.
func resolveDataMemberIfindexes(cfg *config.Config) map[string]int {
	names := localDataMemberNames(cfg)
	if names == nil {
		return nil
	}
	out := make(map[string]int, len(names))
	for _, name := range names {
		ifindex, err := ifindexByNameFn(name)
		if err != nil {
			ifindex = 0
		}
		out[name] = ifindex
	}
	return out
}

// memberXDPVerdict is one pass's verdict. Guarded by m.mu.
type memberXDPVerdict struct {
	cfg     *config.Config // the config authority it was made against
	prog    *ebpf.Program  // the loaded program it was made against
	progErr string         // identifying that loaded program failed
	obs     map[string]memberObservation
	oldest  time.Time // its EARLIEST observation
}

// memberNow is the observation and readiness clock. A seam for the cells.
var memberNow = time.Now

// classifyMember turns one lookup into a kind ("" = positive evidence). The
// framing exclusion is decided from the lookup alone; only the attachment
// check needs the program's identity (progErr non-empty: it failed).
func classifyMember(st memberXDPState, err error, progID uint32, progErr string) (kind, detail string) {
	switch {
	case errors.Is(err, errMemberAbsent):
		return "absent", "absent"
	case err != nil:
		return "unverified", "unverified: lookup failed: " + err.Error()
	case st.NotAttachable:
		return "excluded:non-ethernet", fmt.Sprintf("excluded: non-Ethernet framing, ifindex %d", st.Ifindex)
	case progErr != "":
		return "unverified", "unverified: the loaded shim program could not be identified: " + progErr
	case !st.Attached:
		kind = "not-attached"
	case st.ProgID != progID:
		kind = "foreign-program"
	default:
		return "", ""
	}
	return kind, fmt.Sprintf("%s, ifindex %d", kind, st.Ifindex)
}

// observeDataMembers is the status tick's observation pass. The status loop
// calls it after the tick releases m.mu. It takes m.mu only to read its inputs
// and to publish; every syscall runs off it.
func (m *Manager) observeDataMembers() {
	m.mu.Lock()
	cfg := m.genericDataMemberCfg
	prog := m.entryProgramLocked()
	cache := m.shimProgID
	// Each member's link generation, read BEFORE any lookup: an observation
	// that races a device replacement carries the old generation, so it can
	// never publish an exemption for the new device.
	gens := make(map[string]uint64, len(m.memberLink))
	for name, st := range m.memberLink {
		gens[name] = st.gen
	}
	m.mu.Unlock()
	members := localDataMembers(cfg)
	v := memberXDPVerdict{cfg: cfg, prog: prog, obs: map[string]memberObservation{}}
	if len(members) > 0 && prog != nil {
		// One info query per loaded program; a FAILED query is retried on the
		// next tick, never cached as the program's identity.
		if cache.prog != prog || cache.err != nil {
			id, err := programIDFn(prog)
			cache = shimProgIDCache{prog: prog, id: id, err: err}
		}
		if cache.err != nil {
			v.progErr = cache.err.Error()
		}
		for _, mem := range members {
			at := memberNow() // before the lookup: the evidence is at least this old
			o := memberObservation{at: at, linkGen: gens[mem.linuxName]}
			if mem.disabled {
				o.kind, o.detail = "excluded:admin-disabled", "excluded: administratively disabled"
			} else {
				st, err := memberXDPStateFn(mem.linuxName)
				o.kind, o.detail = classifyMember(st, err, cache.id, v.progErr)
			}
			v.obs[mem.linuxName] = o
			if v.oldest.IsZero() || at.Before(v.oldest) {
				v.oldest = at
			}
		}
	}
	m.mu.Lock()
	if prog != nil && cache.prog == prog {
		m.shimProgID = cache
	}
	m.memberVerdict = v
	m.publishMemberShimVerdictLocked() // #19140
	logs := m.memberLogChangesLocked(v)
	m.mu.Unlock()
	for _, l := range logs {
		l()
	}
}

// memberLogChangesLocked returns the log lines owed by v, on change only, keyed
// on each member's stable kind. Caller holds m.mu; the caller logs after
// releasing it.
func (m *Manager) memberLogChangesLocked(v memberXDPVerdict) []func() {
	if m.memberLogged == nil {
		m.memberLogged = map[string]string{}
	}
	var out []func()
	for name := range m.memberLogged {
		if _, ok := v.obs[name]; !ok && v.prog != nil {
			delete(m.memberLogged, name)
		}
	}
	for _, name := range sortedObsNames(v.obs) {
		o := v.obs[name]
		prev, seen := m.memberLogged[name]
		if seen && prev == o.kind {
			continue
		}
		m.memberLogged[name] = o.kind
		kind, detail := o.kind, o.detail
		switch {
		case kind == "":
			if seen {
				out = append(out, func() {
					slog.Info("RETH data member has its XDP shim again; it no longer blocks takeover readiness",
						"member", name, "issue", "#19110")
				})
			}
		case strings.HasPrefix(kind, "excluded"):
			out = append(out, func() {
				slog.Info("RETH data member is not a required XDP attachment; it does not block takeover readiness",
					"member", name, "why", detail, "issue", "#19110")
			})
		case kind == "unverified":
			out = append(out, func() {
				slog.Warn("RETH data member's XDP attachment could not be verified; it blocks takeover readiness "+
					"while a peer is alive", "member", name, "detail", detail, "issue", "#19110")
			})
		default:
			out = append(out, func() {
				slog.Error("RETH data member has no XDP shim attached: this node is not takeover-ready while a "+
					"peer is alive, and as the owner it drops that member's transit. It is NOT retried "+
					"automatically: recovery is the next compile (an operator commit) or a link-refresh event "+
					"for the member", "member", name, "kind", kind, "detail", detail, "issue", "#19110")
			})
		}
	}
	return out
}

func sortedObsNames(obs map[string]memberObservation) []string {
	out := make([]string, 0, len(obs))
	for name := range obs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// missingDataMemberReasonsLocked is the readiness half. It serves the last
// tick's verdict and makes no syscall: every member classified missing or
// unverified by classifyDataMembersLocked is a reason. Caller holds m.mu.
func (m *Manager) missingDataMemberReasonsLocked(peerAlive bool) []string {
	if !peerAlive {
		return nil
	}
	members, checked := m.classifyDataMembersLocked()
	if !checked {
		return nil
	}
	var reasons []string
	for _, mem := range members {
		if mem.Status != DataMemberShimMissing && mem.Status != DataMemberShimUnverified {
			continue
		}
		reasons = append(reasons, fmt.Sprintf("userspace data interface %s %s (%s); not retried automatically: "+
			"recovery is the next compile or a link-refresh event", mem.LinuxName, missingDataMemberReasonMarker,
			mem.Detail))
	}
	return reasons
}
