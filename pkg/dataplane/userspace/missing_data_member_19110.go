package userspace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #19110: a configured RETH data member with NO XDP shim attached, from LIVE
// kernel state.
//
// The refresh path never waits (zero refresh budgets), so a refused or failed
// attach of a recreated member leaves it with no XDP and its transit dropped
// by the #10302 fence. Two earlier designs kept a record of the failed
// attaches ("debt"). Review showed that record could be ERASED by a pass that
// merely skipped the member (admission refusal, a stale snapshot, the netdev
// briefly absent) and could point at a dead or REUSED ifindex after a second
// recreate (codex-e P2-1, P2-2). So there is no record. Instead:
//
// The kernel is read on the STATUS TICK, never at readiness time. Readiness is
// called under m.mu, which UpdateRGActive (the HA cutover) also needs, by the
// daemon's RG reconcile loop (every 2 s and on every triggered pass, once per
// RG; its result feeds the election through SetRGReady) and by the metrics
// scrape. A netlink stall there would stall the cutover. So:
//   - Once per status tick (1 s), OFF m.mu, each configured local RETH data
//     member (RethToPhysical of the compile's config authority) is looked up
//     by NAME on a netlink handle with a 250 ms socket timeout. The positive
//     evidence is XDP attached to that member's CURRENT ifindex with the
//     shim's own entry program ID. The tick stores the verdict, built from
//     scratch with its timestamp: a failed lookup is "unverified" (NOT ready),
//     never the previous answer carried forward.
//   - Readiness serves that verdict: map reads under m.mu, no lookup (the
//     shim program's ID is read once per loaded program, then cached). A
//     verdict older than memberVerdictMaxAge, or one that does not cover a
//     configured member yet, also counts as "unverified". In steady state the
//     served verdict is at most one tick old.
//   - A member without positive evidence is the reason "<name> has no XDP shim
//     attached (<kind>)", blocker xdp_missing_data_member. Its scope is F4's:
//     with the peer alive it blocks; a lone owner gets the ERROR log and the
//     peer-alive-form metric instead. With no shim program loaded, the check
//     is skipped; other reasons already block readiness then.
//
// The retry is keyed by member NAME and runs OFF m.mu. After each status tick
// releases m.mu, a single-flight goroutine walks the members. A member with
// positive evidence clears its retry state. A member without it is attempted
// when due (1 s after the first attempt, doubling to 30 s): the name is
// resolved to an ifindex immediately before the attach, the attach goes to
// that freshly resolved index only (never a remembered one), and the kernel
// is read again as the evidence. An absent netdev or an admission refusal
// keeps the obligation and advances the backoff. Retry state is dropped only
// on positive evidence or when the name leaves the configured members.
//
// Logs are on change, keyed on a stable failure kind (errno, refusal,
// admission reason, absent, foreign program), never on Error(), which embeds
// elapsed time. The retry's attach passes Quiet, so the shim's own reclaim and
// fallback lines are DEBUG.
//
// Cost of one attempt, all OFF m.mu: two netlink RTM_GETLINKs (each bounded by
// memberXDPQueryTimeout), the admission's ethtool subprocess(es) (bounded by
// the ethtool wrapper's 15 s timeout plus 5 s WaitDelay), one pin reclaim, and
// one BPF_LINK_CREATE, which takes rtnl. The goroutine is single-flight, so a
// slow attempt delays only the next retry, never a status tick. Readiness
// itself does no lookup: it reads the stored verdict.

// missingDataMemberReasonMarker is the substring MapHATakeoverBlocker keys on.
const missingDataMemberReasonMarker = "has no XDP shim attached"

const (
	memberRetryMin        = time.Second
	memberRetryMax        = 30 * time.Second
	memberXDPQueryTimeout = 250 * time.Millisecond
	// memberVerdictMaxAge bounds how old a served verdict may be: one 1 s
	// status tick plus the pass's own lookups and scheduling slack. Only a
	// stalled loop or a slow attempt ages it past this.
	memberVerdictMaxAge = 3 * time.Second
)

// memberXDPVerdict is one tick's live verdict. Guarded by m.mu.
type memberXDPVerdict struct {
	at      time.Time
	names   []string          // the members this verdict covers
	missing map[string]string // name -> detail; a covered name not here has positive evidence
}

// memberLookup is one live read of a member.
type memberLookup struct {
	st   memberXDPState
	err  error
	kind string // memberMissingKind
}

func (l memberLookup) detail() string {
	if l.st.Ifindex > 0 {
		return fmt.Sprintf("%s, ifindex %d", l.kind, l.st.Ifindex)
	}
	return l.kind
}

func buildMemberVerdict(at time.Time, names []string, looked map[string]memberLookup) memberXDPVerdict {
	v := memberXDPVerdict{at: at, names: names, missing: map[string]string{}}
	for _, name := range names {
		if l, ok := looked[name]; !ok {
			v.missing[name] = "unverified"
		} else if l.kind != "" {
			v.missing[name] = l.detail()
		}
	}
	return v
}

// errMemberAbsent: the member's netdev does not exist (yet) in this netns.
var errMemberAbsent = errors.New("data member netdev absent")

// memberXDPState is the kernel's view of one member, read by NAME.
type memberXDPState struct {
	Ifindex  int
	Attached bool
	ProgID   uint32
}

// memberXDPStateFn reads the member's current ifindex and IFLA_XDP by name. It
// is a seam for the cells.
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
	st := memberXDPState{Ifindex: a.Index}
	if a.Xdp != nil && a.Xdp.Attached {
		st.Attached, st.ProgID = true, a.Xdp.ProgId
	}
	return st, nil
}

// memberMissingKind is "" when the kernel shows the shim attached to the
// member's current ifindex, else a STABLE kind.
func memberMissingKind(st memberXDPState, err error, progID uint32) string {
	switch {
	case errors.Is(err, errMemberAbsent):
		return "absent"
	case err != nil:
		return "unverified"
	case !st.Attached:
		return "not-attached"
	case st.ProgID != progID:
		return "foreign-program"
	}
	return ""
}

// localDataMemberNames is the config's local RETH data members, by Linux name.
func localDataMemberNames(cfg *config.Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	set := map[string]bool{}
	for _, phys := range cfg.RethToPhysical() {
		set[config.LinuxIfName(phys)] = true
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// shimProgIDCache remembers the kernel ID of one loaded entry program.
type shimProgIDCache struct {
	prog *ebpf.Program
	id   uint32
}

// shimEntryProgramIDLocked is the kernel ID of the shim's XDP entry program,
// the program every shim link attaches. It is read once per loaded program.
// ok is false before the shim is loaded. Caller holds m.mu (lock order: the
// userspace m.mu, then the shim manager's own mutex).
func (m *Manager) shimEntryProgramIDLocked() (uint32, bool) {
	if m.shimProgIDHook != nil {
		return m.shimProgIDHook()
	}
	if m.bpfShim == nil {
		return 0, false
	}
	prog := m.bpfShim.Program(m.bpfShim.XDPEntryProgram())
	if prog == nil {
		return 0, false
	}
	if prog == m.shimProgID.prog {
		return m.shimProgID.id, true
	}
	info, err := prog.Info()
	if err != nil {
		return 0, false
	}
	id, ok := info.ID()
	if !ok {
		return 0, false
	}
	m.shimProgID = shimProgIDCache{prog: prog, id: uint32(id)}
	return uint32(id), true
}

// missingDataMemberReasonsLocked is the readiness half. It serves the last
// tick's verdict and does no lookup. Caller holds m.mu.
func (m *Manager) missingDataMemberReasonsLocked(peerAlive bool) []string {
	if !peerAlive {
		return nil
	}
	names := localDataMemberNames(m.genericDataMemberCfg)
	if len(names) == 0 {
		return nil
	}
	if _, ok := m.shimEntryProgramIDLocked(); !ok {
		return nil
	}
	v := m.memberVerdict
	fresh := !v.at.IsZero() && time.Since(v.at) <= memberVerdictMaxAge
	var reasons []string
	for _, name := range names {
		detail, missing := v.missing[name]
		switch {
		case !fresh:
			detail = "unverified: no live verdict in the last " + memberVerdictMaxAge.String()
		case !slices.Contains(v.names, name):
			detail = "unverified: not checked yet"
		case !missing:
			continue
		}
		reasons = append(reasons, fmt.Sprintf("userspace data interface %s %s (%s); retried by name on a "+
			"later status tick", name, missingDataMemberReasonMarker, detail))
	}
	return reasons
}

// memberAttachRetry is one member name's retry state. Guarded by m.mu.
type memberAttachRetry struct {
	backoff time.Duration
	due     time.Time
	kind    string
}

type memberRetryOutcome struct {
	attached, attempted bool
	kind                string
	after               *memberLookup // the kernel re-read after an attach
}

// startMissingDataMemberRetry runs one retry pass in the background unless one
// is already running, and reports whether it started one. The status loop
// calls it after a tick releases m.mu.
func (m *Manager) startMissingDataMemberRetry(ctx context.Context, now time.Time) bool {
	m.mu.Lock()
	configured := m.genericDataMemberCfg != nil
	m.mu.Unlock()
	if !configured || !m.memberRetryInFlight.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer m.memberRetryInFlight.Store(false)
		m.retryMissingDataMembersOnce(ctx, now)
	}()
	return true
}

// retryMissingDataMembersOnce is one pass: the live verdict, then the due
// attempts. It takes m.mu only to read its inputs and to store the verdict and
// the outcomes; every syscall and subprocess runs off it.
func (m *Manager) retryMissingDataMembersOnce(ctx context.Context, now time.Time) {
	m.mu.Lock()
	cfg := m.genericDataMemberCfg
	names := localDataMemberNames(cfg)
	progID, havePID := m.shimEntryProgramIDLocked()
	var attach func([]dataplane.ShimXDPAttachRequest) map[int]error
	if m.bpfShim != nil {
		attach = m.bpfShim.AttachShimXDPInterfaces
	}
	check := m.rxVlanPreconditionCheck
	quarantined := maps.Clone(m.rxVlanQuarantinedParents)
	prev := make(map[string]memberAttachRetry, len(m.memberAttachRetry))
	for name, r := range m.memberAttachRetry {
		prev[name] = *r
	}
	m.mu.Unlock()
	if check == nil {
		check = dataplane.EnsureRxVlanParsePreconditions
	}
	if !havePID {
		return
	}
	// The verdict first, from lookups alone, so readiness is fresh even while
	// a slow attempt runs below. Built from scratch every pass.
	looked := make(map[string]memberLookup, len(names))
	for _, name := range names {
		st, err := memberXDPStateFn(name)
		looked[name] = memberLookup{st: st, err: err, kind: memberMissingKind(st, err, progID)}
	}
	m.mu.Lock()
	m.memberVerdict = buildMemberVerdict(time.Now(), names, looked)
	m.mu.Unlock()
	outcomes := map[string]memberRetryOutcome{}
	if attach != nil {
		for _, name := range names {
			if ctx.Err() != nil {
				return
			}
			p, owed := prev[name]
			o := retryOneMember(now, name, cfg, progID, looked[name], p, owed, attach, check, quarantined)
			if o.attempted && o.after != nil {
				looked[name] = *o.after
			}
			outcomes[name] = o
		}
	}
	m.mu.Lock()
	m.memberVerdict = buildMemberVerdict(time.Now(), names, looked)
	m.applyMemberRetryOutcomesLocked(names, outcomes, now)
	m.mu.Unlock()
}

// retryOneMember takes this pass's lookup of one member and, when the member is
// missing and due, attempts it. It never holds m.mu.
func retryOneMember(now time.Time, name string, cfg *config.Config, progID uint32, l memberLookup,
	prev memberAttachRetry, owed bool, attach func([]dataplane.ShimXDPAttachRequest) map[int]error,
	check func(string) (error, error), quarantined map[string]bool) memberRetryOutcome {
	st, err, kind := l.st, l.err, l.kind
	if kind == "" {
		return memberRetryOutcome{attached: true}
	}
	if owed && now.Before(prev.due) {
		return memberRetryOutcome{kind: kind}
	}
	if err != nil {
		// Absent or unverifiable: nothing to attach to. The obligation stays and
		// the backoff advances.
		return memberRetryOutcome{kind: kind, attempted: true}
	}
	if adm := memberAttachAdmission(name, cfg, quarantined, check); adm != "" {
		return memberRetryOutcome{kind: "admission:" + adm, attempted: true}
	}
	// The ifindex was resolved from the name just above: never a remembered one.
	res := attach([]dataplane.ShimXDPAttachRequest{{Ifindex: st.Ifindex, Quiet: true}})[st.Ifindex]
	st2, err2 := memberXDPStateFn(name)
	re := &memberLookup{st: st2, err: err2, kind: memberMissingKind(st2, err2, progID)}
	if re.kind == "" && st2.Ifindex == st.Ifindex {
		return memberRetryOutcome{attached: true, attempted: true, after: re}
	}
	if k := attachFailureKind(res); k != "" {
		return memberRetryOutcome{kind: k, attempted: true, after: re}
	}
	after := re.kind
	if after == "" {
		after = "recreated-during-attach"
	}
	return memberRetryOutcome{kind: "unverified-after-attach:" + after, attempted: true, after: re}
}

// memberAttachAdmission is the refresh path's RX-VLAN admission, by NAME and
// against the config authority, so no snapshot ifindex is involved.
func memberAttachAdmission(name string, cfg *config.Config, quarantined map[string]bool,
	check func(string) (error, error)) string {
	if quarantined[name] {
		return "rx-vlan-quarantined"
	}
	rxvlanErr, stagErr := check(name)
	if stagErr != nil {
		return "s-tag-precondition"
	}
	if rxvlanErr != nil && configHasRxVlanChildForParent(cfg, name) {
		return "c-tag-precondition"
	}
	return ""
}

// attachFailureKind is a stable identity for a failed attach: the refusal or
// the errno, never the error text.
func attachFailureKind(err error) string {
	if err == nil || attachErrIsAlreadyAttached(err) {
		return ""
	}
	prefix := "error"
	if errors.Is(err, dataplane.ErrXDPOccupied) {
		prefix = "refused"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return prefix + ":" + unix.ErrnoName(errno)
	}
	return prefix
}

// applyMemberRetryOutcomesLocked records one pass. Caller holds m.mu.
func (m *Manager) applyMemberRetryOutcomesLocked(names []string, outcomes map[string]memberRetryOutcome,
	now time.Time) {
	configured := make(map[string]bool, len(names))
	for _, name := range names {
		configured[name] = true
	}
	for name := range m.memberAttachRetry {
		if !configured[name] {
			delete(m.memberAttachRetry, name)
			slog.Info("RETH data member no longer configured; its XDP attach retry is dropped",
				"member", name, "issue", "#19110")
		}
	}
	for _, name := range names {
		o, ok := outcomes[name]
		if !ok {
			continue
		}
		r := m.memberAttachRetry[name]
		switch {
		case o.attached:
			if r != nil {
				delete(m.memberAttachRetry, name)
				how := "attached by another path"
				if o.attempted {
					how = "attached on retry"
				}
				slog.Info("RETH data member has its XDP shim again; the takeover-readiness obligation is cleared",
					"member", name, "how", how, "issue", "#19110")
			}
		case !o.attempted:
			// Not due yet: the obligation and its backoff stand.
		default:
			if r == nil {
				if m.memberAttachRetry == nil {
					m.memberAttachRetry = map[string]*memberAttachRetry{}
				}
				r = &memberAttachRetry{backoff: memberRetryMin}
				m.memberAttachRetry[name] = r
			} else {
				r.backoff = min(2*r.backoff, memberRetryMax)
			}
			r.due = now.Add(r.backoff)
			if r.kind != o.kind {
				slog.Error("RETH data member has no XDP shim attached: this node is not takeover-ready while a "+
					"peer is alive, and as the owner it drops that member's transit; retrying by name",
					"member", name, "kind", o.kind, "next_retry_in", r.backoff, "issue", "#19110")
			} else {
				slog.Debug("RETH data member still has no XDP shim attached; retry owed",
					"member", name, "kind", o.kind, "next_retry_in", r.backoff, "issue", "#19110")
			}
			r.kind = o.kind
		}
	}
}
