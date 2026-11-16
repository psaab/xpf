package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #19110: an XDP attach the kernel REFUSES (EBUSY/EEXIST) is not an interface
// that lacks native XDP.
//
// After an unclean exit the dead process's links are still attached when the
// restarted daemon attaches. The per-interface reclaim (shim_pins.go) detaches
// them synchronously, but a refusal can still come from somewhere else:
//   - a reclaim that could not detach (load or detach failure);
//   - a foreign program;
//   - an upper device carrying XDP;
//   - tcp-data-split or a memory provider (net/core/dev.c dev_xdp_install).
//
// The kernel makes those checks in generic mode too, so falling back to generic
// can only fail with EEXIST, or, if the occupant leaves in between, land a
// native-capable interface in skb mode. So a refusal is retried within one
// shared deadline for the whole attach pass. Every result is reclassified, and
// the pass ends in ErrXDPOccupied, never in a generic fallback.

// ErrXDPOccupied reports an XDP attach the kernel kept refusing (EBUSY/EEXIST)
// until the attach pass's occupancy budget ran out.
var ErrXDPOccupied = errors.New("XDP attach refused: interface occupied or busy")

// xdpOccupancyBudget is the ONE deadline every interface in an attach pass
// shares for refused attaches. It is not per interface, so N refused interfaces
// cannot add up to N budgets. It starts at the pass's FIRST refusal, not at the
// pass start: productive work (synchronous detaches, successful attaches, an
// EINVAL->generic fallback) never eats it (R23 P3-2). A var so cells can
// shorten it.
var xdpOccupancyBudget = 5 * time.Second

// SetXDPOccupancyBudgetForTest shortens the refusal and diagnostic budgets and
// returns a restore func. It is for tests only.
// It sets the compile pass's budgets and the refresh reconciliation's alike.
func SetXDPOccupancyBudgetForTest(budget, diag time.Duration) (restore func()) {
	ob, od := xdpOccupancyBudget, xdpOccupancyDiagBudget
	rb, rd := xdpRefreshOccupancyBudget, xdpRefreshDiagBudget
	xdpOccupancyBudget, xdpOccupancyDiagBudget = budget, diag
	xdpRefreshOccupancyBudget, xdpRefreshDiagBudget = budget, diag
	return func() {
		xdpOccupancyBudget, xdpOccupancyDiagBudget = ob, od
		xdpRefreshOccupancyBudget, xdpRefreshDiagBudget = rb, rd
	}
}

// xdpOccupancyDiagBudget bounds the WHOLE diagnostic probing of one pass. The
// netlink socket timeout bounds only each operation, not a multipart dump or a
// series of upper-device reads.
var xdpOccupancyDiagBudget = time.Second

// xdpOccupancyProbeTimeout is the per-operation netlink socket timeout of the
// diagnostic handle. The library default is 60 s.
const xdpOccupancyProbeTimeout = 250 * time.Millisecond

// xdpProbeInFlight bounds outstanding occupant probes to one (see diagnose).
var xdpProbeInFlight atomic.Bool

// xdpOccupantProbeFn describes what holds ifindex (its own XDP program, or an
// upper device's) for the give-up diagnostic only. It never changes the
// classification. It is a seam for the probe-error and upper-device cells.
var xdpOccupantProbeFn = probeXDPOccupant

// XDPOccupiedError is the give-up record. errors.Is matches ErrXDPOccupied AND
// the kernel's last errno, so an operator or caller can still tell EBUSY from
// EEXIST.
type XDPOccupiedError struct {
	Ifindex  int
	Generic  bool
	Attempts int
	Elapsed  time.Duration
	// Occupant is the diagnostic, or "unknown (...)" when nothing was found or
	// the probe failed or ran out of budget.
	Occupant string
	// Reclaim describes a stale-pin reclaim that did not fully succeed for this
	// ifindex, if any.
	Reclaim string
	Err     error
}

func (e *XDPOccupiedError) Error() string {
	mode := "native"
	if e.Generic {
		mode = "generic"
	}
	msg := fmt.Sprintf("attach userspace XDP shim %s to ifindex %d refused %d time(s) over %s: %v; occupant: %s",
		mode, e.Ifindex, e.Attempts, e.Elapsed.Round(time.Millisecond), e.Err, e.Occupant)
	if e.Reclaim != "" {
		msg += "; stale pin reclaim: " + e.Reclaim
	}
	return msg
}

func (e *XDPOccupiedError) Unwrap() []error { return []error{ErrXDPOccupied, e.Err} }

// isXDPRefusal reports a kernel refusal: something occupies the device or a
// device constraint holds. It is a refusal, not proof of an occupant.
func isXDPRefusal(err error) bool {
	return errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST)
}

// xdpNativeUnsupportedByDriver reports the one native refusal that means the
// driver has no native XDP at all: dev_xdp_attach returns EOPNOTSUPP when the
// device has no ndo_bpf ("Underlying driver does not support XDP in native
// mode"). A generic fallback after it is the supported deployment (iavf). Any
// other native error that ends in generic is an UNINTENDED generic (#19110 F4).
//
// FAIL-OPEN, deliberately: EOPNOTSUPP does not PROVE "no ndo_bpf". A driver
// with ndo_bpf can return it for a configuration refusal; virtio-net does,
// while the host implements GRO_HW/CSUM. Such a generic member is exempt from
// the F4 guard, as every generic member was before #19110. Telling the two
// apart would need the extack string, which this path does not see.
func xdpNativeUnsupportedByDriver(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP)
}

// xdpRefreshOccupancyBudget and xdpRefreshDiagBudget are the budgets of a
// #14133 refresh reconciliation (AttachShimXDPInterfaces). Both are ZERO: the
// refresh path never waits (Codex delta P2-1, R23 NEW-1).
//   - A refresh runs under the userspace Manager's mutex, which RG activation
//     (UpdateRGActive), takeover readiness, session installs and the 1 Hz status
//     poll also need. A refusal wait there would stall an HA cutover on a
//     healthy node.
//   - A refresh never has a dead process's stale link to wait out (the boot
//     race the compile budget exists for). A refusal there is the persistent
//     kind: an upper device, tcp-data-split, a memory provider. Waiting would
//     not clear it.
//
// So each interface gets ONE attempt per mode. A refusal returns ErrXDPOccupied
// with no generic attempt and no occupant probe. The interface stays
// fail-closed. The userspace Manager covers a configured RETH data member from
// live kernel state: a readiness reason and a per-name retry on a later status
// tick (pkg/dataplane/userspace missing_data_member_19110.go).
// They are vars so the batch cells can give the pass a non-zero budget.
var (
	xdpRefreshOccupancyBudget time.Duration
	xdpRefreshDiagBudget      time.Duration
)

// xdpAttachPass carries one attach pass's shared deadlines: the refusal
// deadline, armed at the pass's FIRST refusal, and the aggregate diagnostic
// deadline, armed at its FIRST give-up.
type xdpAttachPass struct {
	budget, diagBudget     time.Duration
	deadline, diagDeadline time.Time
	// reclaim records what the per-interface reclaim did, for the give-up
	// message.
	reclaim map[int]string
}

func newXDPAttachPass() *xdpAttachPass {
	return newXDPAttachPassWithBudget(xdpOccupancyBudget, xdpOccupancyDiagBudget)
}

func newXDPAttachPassWithBudget(budget, diag time.Duration) *xdpAttachPass {
	return &xdpAttachPass{budget: budget, diagBudget: diag, reclaim: map[int]string{}}
}

// refusalDeadline arms the pass's refusal deadline at its first refusal and
// returns it. It is wall-clock from then on: work done AFTER the first refusal
// counts against it, but work done before it does not.
func (p *xdpAttachPass) refusalDeadline() time.Time {
	if p.deadline.IsZero() {
		p.deadline = time.Now().Add(p.budget)
	}
	return p.deadline
}

// attachWithin attaches ifindex in the requested mode. A refusal is retried with
// backoff until the pass's shared deadline, and every result is reclassified, so
// an EEXIST that turns into EINVAL is returned as that EINVAL. Only a refusal
// that outlives the deadline becomes an *XDPOccupiedError.
func (m *Manager) attachWithin(pass *xdpAttachPass, ifindex int, generic bool) error {
	started := time.Now()
	backoff := 25 * time.Millisecond
	attempts := 0
	for {
		attempts++
		err := m.AttachXDP(ifindex, generic)
		if err == nil || !isXDPRefusal(err) {
			if err == nil && attempts > 1 {
				slog.Info("XDP attach succeeded after the kernel refused it",
					"ifindex", ifindex, "generic", generic, "attempts", attempts,
					"waited_ms", time.Since(started).Milliseconds(), "issue", "#19110")
			}
			return err
		}
		if time.Now().Add(backoff).After(pass.refusalDeadline()) {
			return &XDPOccupiedError{
				Ifindex:  ifindex,
				Generic:  generic,
				Attempts: attempts,
				Elapsed:  time.Since(started),
				Occupant: pass.diagnose(ifindex),
				Reclaim:  pass.reclaim[ifindex],
				Err:      err,
			}
		}
		time.Sleep(backoff)
		if backoff < 200*time.Millisecond {
			backoff *= 2
		}
	}
}

// reclaimAfterCheckHook is a test seam: it runs between the registration check
// and the reclaim, inside the ownership lease.
var reclaimAfterCheckHook func(ifindex int)

// reclaimBeforeAttach reclaims ifindex's stale pin (a previous process's link)
// immediately before this process's first attach of it. A link this process
// already registered is never reclaimed.
//
// The registration check and the reclaim run under the XDP ownership WRITE
// lease (Codex P1-1). AttachXDP holds the same lease across its attach, pin
// and registration, and this process has a second attacher outside the
// daemon's applySem: the userspace status loop's revalidation
// (statusLoop -> syncSnapshotLocked -> consumeRevalidateAttachLocked -> the
// #14133 reconcile). Without the lease, that attacher could attach, pin and
// register the interface between our check and our reclaim. We would then
// load THIS process's fresh pin and detach it, and the registry would still
// say "attached".
func (m *Manager) reclaimBeforeAttach(pass *xdpAttachPass, ifindex int, quiet bool) {
	m.xdpOwnershipMu.Lock()
	defer m.xdpOwnershipMu.Unlock()
	if _, registered := m.xdpLinkFor(ifindex); registered {
		return
	}
	if h := reclaimAfterCheckHook; h != nil {
		h(ifindex)
	}
	r := reclaimStaleXDPLinkPin(filepath.Join(linkPinPath, fmt.Sprintf("xdp_%d", ifindex)))
	r.log(ifindex, quiet)
	if !r.clean() {
		pass.reclaim[ifindex] = r.String()
	}
}

func isAlreadyAttached(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already attached")
}

// ShimXDPAttachRequest is one interface for AttachShimXDPInterfaces.
type ShimXDPAttachRequest struct {
	Ifindex      int
	ForceGeneric bool
	// Quiet demotes this attach's own reclaim and fallback logs to DEBUG. The
	// userspace per-member retry sets it: it repeats on a backoff and logs on
	// change itself, keyed on a stable failure kind (#19110, codex-e).
	Quiet bool
}

// AttachShimXDPInterfaces attaches the shim to interfaces outside a compile
// pass: the #14133 interface-link refresh and the status loop's revalidation
// (a recreated or re-probed netdev). It applies the compile pass's #19110
// rules, so neither path is a bypass (R23 P2-2, Codex P1-2):
//   - the stale pin is reclaimed first;
//   - a refusal (EBUSY/EEXIST) is retried and never falls back to generic;
//   - an unsupported native attach falls back to generic, and a fallback for
//     any reason other than EOPNOTSUPP is recorded for the F4 guard.
//
// The caller holds the userspace Manager's mutex across this call, so the
// refresh budgets are ZERO (Codex delta P2-1, R23 NEW-1): every interface gets
// one attempt per mode, and a refusal gives up at once with no occupant probe.
// The whole batch is still ONE pass, so if those budgets were ever non-zero, N
// refusing interfaces would share one budget instead of waiting N.
// Results are per ifindex; a nil entry means attached or already attached.
func (m *Manager) AttachShimXDPInterfaces(reqs []ShimXDPAttachRequest) map[int]error {
	pass := newXDPAttachPassWithBudget(xdpRefreshOccupancyBudget, xdpRefreshDiagBudget)
	out := make(map[int]error, len(reqs))
	for _, r := range reqs {
		out[r.Ifindex] = m.attachShimOne(pass, r)
	}
	return out
}

// attachShimOne is one interface's whole sequence within a pass.
func (m *Manager) attachShimOne(pass *xdpAttachPass, r ShimXDPAttachRequest) error {
	ifindex := r.Ifindex
	m.reclaimBeforeAttach(pass, ifindex, r.Quiet)
	if r.ForceGeneric {
		err := m.attachWithin(pass, ifindex, true)
		if isAlreadyAttached(err) {
			return nil
		}
		return err
	}
	nerr := m.attachWithin(pass, ifindex, false)
	if nerr == nil || isAlreadyAttached(nerr) {
		return nil
	}
	if errors.Is(nerr, ErrXDPOccupied) {
		return nerr
	}
	if m.settleFailedNativeAttach(ifindex) {
		return nil // another attacher registered it meanwhile; leave its link alone
	}
	logAt := slog.Warn
	if r.Quiet {
		logAt = slog.Debug
	}
	logAt("native XDP unavailable for userspace shim; falling back to generic (skb-mode)",
		"ifindex", ifindex, "err", nerr, "path", "interface-link refresh",
		"impact", "higher CPU, ~6 Gbps cap; fix driver/firmware to restore driver-mode XDP")
	if err := m.attachWithin(pass, ifindex, true); err != nil {
		if isAlreadyAttached(err) {
			return nil // not THIS call's generic link: nothing to record
		}
		return err
	}
	m.recordGenericFallback(ifindex, nerr)
	return nil
}

// settleFailedNativeAttach runs between a failed native attach and the generic
// fallback, on both attach paths (R23 NEW-2). It replaces a DetachXDP call.
//
// A failed fresh native attach registered nothing. So the only link DetachXDP
// could find here was one ANOTHER attacher registered in between: the compile
// pass and the userspace status loop's revalidation reconcile both attach, and
// only the compile holds applySem. Detaching that link, and then failing the
// generic attach, would leave the interface with no XDP after the compile had
// already published its arm proof.
//
// It reports whether a link is registered now. If one is, it changes nothing,
// and the caller neither falls back nor records a fallback. Otherwise it does
// what DetachXDP did for an absent link (discard the unobservable detach debt)
// and clears the native-XDP flags, both under the ownership lease, so no
// attacher can register between the check and the clear.
func (m *Manager) settleFailedNativeAttach(ifindex int) (registered bool) {
	m.xdpOwnershipMu.Lock()
	defer m.xdpOwnershipMu.Unlock()
	if _, ok := m.xdpLinkFor(ifindex); ok {
		return true
	}
	m.ReconcileDetachDebt([]int{ifindex})
	m.clearNativeXDPFlagsForIfindexes([]int{ifindex})
	return false
}

// diagnose runs the occupant probe within what is left of the pass's aggregate
// diagnostic budget. The probe runs in a goroutine whose wait is abandoned at
// the budget: a netlink dump cannot be cancelled, but this pass no longer waits
// for it.
func (p *xdpAttachPass) diagnose(ifindex int) string {
	if p.diagBudget <= 0 {
		// The refresh path: no probe, and no goroutine left behind.
		return "unknown (not probed: this attach path holds the userspace Manager mutex and never waits)"
	}
	if p.diagDeadline.IsZero() {
		p.diagDeadline = time.Now().Add(p.diagBudget)
	}
	remaining := time.Until(p.diagDeadline)
	if remaining <= 0 {
		return "unknown (diagnostic budget spent)"
	}
	type res struct {
		s   string
		err error
	}
	// At most ONE probe in flight, process-wide (Codex note). A probe abandoned
	// at its budget keeps running until its netlink operations time out; it is
	// not cancelled. A later pass must not stack another behind it.
	if !xdpProbeInFlight.CompareAndSwap(false, true) {
		return "unknown (a previous occupant probe is still running)"
	}
	ch := make(chan res, 1)
	// Read the probe here, not in the goroutine: an abandoned probe goroutine
	// can outlive this pass, and must not race a later reassignment of the seam.
	probe := xdpOccupantProbeFn
	go func() {
		defer xdpProbeInFlight.Store(false)
		s, err := probe(ifindex)
		ch <- res{s, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return fmt.Sprintf("unknown (probe failed: %v; EBUSY can also mean tcp-data-split or a memory provider)", r.err)
		}
		if r.s == "" {
			return "unknown (no XDP program found on the interface or its uppers; EBUSY can also mean " +
				"tcp-data-split or a memory provider)"
		}
		return r.s
	case <-time.After(remaining):
		return "unknown (diagnostic budget spent)"
	}
}

// probeXDPOccupant reads the target's IFLA_XDP, then every link whose parent
// (IFLA_LINK) is the target or which is the target's master, and names
// whichever carries XDP. It uses a dedicated handle with a short socket timeout.
func probeXDPOccupant(ifindex int) (string, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return "", err
	}
	defer h.Close()
	if err := h.SetSocketTimeout(xdpOccupancyProbeTimeout); err != nil {
		return "", err
	}
	self, err := h.LinkByIndex(ifindex)
	if err != nil {
		return "", fmt.Errorf("read ifindex %d: %w", ifindex, err)
	}
	var found []string
	if x := self.Attrs().Xdp; x != nil && x.Attached {
		found = append(found, fmt.Sprintf("%s XDP program %d on %s (ifindex %d)",
			xdpModeName(x.AttachMode), x.ProgId, self.Attrs().Name, ifindex))
	}
	links, err := h.LinkList()
	if err != nil {
		return strings.Join(found, "; "), fmt.Errorf("list links: %w", err)
	}
	master := self.Attrs().MasterIndex
	for _, l := range links {
		a := l.Attrs()
		if a.Index == ifindex || (a.ParentIndex != ifindex && a.Index != master) {
			continue
		}
		if x := a.Xdp; x != nil && x.Attached {
			found = append(found, fmt.Sprintf("upper %s (ifindex %d) carries %s XDP program %d",
				a.Name, a.Index, xdpModeName(x.AttachMode), x.ProgId))
		}
	}
	return strings.Join(found, "; "), nil
}

func xdpModeName(mode uint32) string {
	switch mode {
	case xdpAttachedDrv:
		return "native"
	case xdpAttachedSKB:
		return "generic"
	case xdpAttachedHW:
		return "offloaded"
	default:
		return "attached"
	}
}

// recordGenericFallback remembers why ifindex runs generic: the native error
// that sent it there. Only a detach (DetachXDP) or Teardown clears it. A
// re-commit cannot: the registered generic link short-circuits AttachXDP
// ("already attached"), so no native attempt is made until the link is gone,
// which in practice means an xpfd restart (R23 P2-3). The userspace Manager reads it to keep a RETH data
// member in unintended generic out of takeover readiness (#19110 F4).
func (m *Manager) recordGenericFallback(ifindex int, nativeErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.genericFallback == nil {
		m.genericFallback = map[int]error{}
	}
	m.genericFallback[ifindex] = nativeErr
}

func (m *Manager) clearGenericFallback(ifindex int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.genericFallback, ifindex)
}

// UnintendedGenericXDP returns, by ifindex, the native error of every interface
// this process attached generic after a native refusal OTHER than the
// driver-has-no-native-XDP EOPNOTSUPP. Such a generic is not the supported
// deployment: mlx5 with LRO/HW-GRO (EINVAL), a resource failure, and so on.
func (m *Manager) UnintendedGenericXDP() map[int]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int]string{}
	for ifindex, err := range m.genericFallback {
		if err != nil && !xdpNativeUnsupportedByDriver(err) {
			out[ifindex] = nativeRefusalText(err)
		}
	}
	return out
}

// nativeRefusalText is the errno's text when there is one ("invalid
// argument"), otherwise the whole error.
func nativeRefusalText(err error) string {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}
