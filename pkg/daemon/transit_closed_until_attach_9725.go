package daemon

import "log/slog"

// #9725: kernel transit is open only while the dataplane is armed AND a shim XDP
// program is attached.
//
// THE HOLE. The #5275 gate declared the node armed at rt.Start
// (LoadUserspaceShim) and opened kernel transit there: markDataplaneArmed wrote
// ip_forward and conf.all.forwarding to 1 and removed the #7191 barrier. Boot had
// raised both sysctls even earlier, and so does the sysctl.d that images baked
// before #9725 carry. But the per-interface attach runs later, inside the first
// ApplyConfig. In between, networkd and FRR are up, so static non-VIP addresses
// and FRR routes forwarded transit through the kernel with no XDP program and no
// barrier. Once a program is attached, the shim drops transit on a missing or
// stale helper heartbeat (userspace-xdp/src/lib.rs), so the window ends at the
// attach.
//
// THE RULE. Kernel transit is open only while both of these hold (transitOpen):
//   - the dataplane Started in this daemon's lifetime (dataplaneArmed);
//   - the runtime holds at least one attached shim XDP link now
//     (AttachedXDPLinkCount).
//
// THE SIGNAL is a live read of the dataplane's link map, not an event. Neither
// alternative is right:
//   - ApplyConfig's result: an apply can succeed with nothing attached, and can
//     fail after its attach;
//   - a record of an attach pass: a pass can skip interfaces it was handed, and
//     the #5485 reconcile that follows the snapshot publish can detach links the
//     pass attached.
//
// The link map holds exactly the links a successful attach created and no detach
// has removed. The gate re-reads it after every ApplyConfig, whatever that
// returned, and at the apply tail. It is not latched: an apply that leaves no
// link attached closes transit again.
//
// WHAT THE COUNT IS. The links are bpf_links (link.AttachXDP). While one is
// attached, the kernel refuses a netlink XDP detach or replace on that device, so
// the program goes away only when its link is closed or detached. xpfd does that
// through DetachXDP, which also drops the map entry. Two cases fall outside the
// map, both deliberately:
//   - a privileged actor that detaches or updates a link through its pin bypasses
//     the map. That actor could as well write the forwarding sysctls, so the gate
//     does not try to defend against it;
//   - a link pinned by an earlier run is not in a new Manager's map, so after a
//     restart the gate stays closed until this process attaches.
//
// The count asks the kernel, too: a link whose device was unregistered (NIC
// removal, VF re-creation, a driver reload) keeps its handle and map entry, but
// the kernel detached its program and reports ifindex 0, so it is not counted.
// The count is read at applies only, never on a link event; NOT CHANGED HERE
// states what that leaves open.
//
// WHAT IT DOES NOT PROVE. One attached link opens ip_forward for every interface,
// including one that no program covers. Per-surface coverage is the #7191
// arm-coverage proof's job, and the published runtime does not run that proof yet
// (#9804).
//
// HOW THE PIECES FIT.
//   - Bring-up closes transit explicitly (closeTransitUntilAttached). An older
//     image's sysctl.d and a restart after an armed run both leave the sysctls at
//     1. Neither the image nor the test VMs persist the transit knobs in sysctl.d:
//     systemd-sysctl re-applies such a file whenever it runs and would fight the
//     gate under a running xpfd, in whichever direction it was written. Both
//     default to 0, and the postinst scrubs an older image's persisted values.
//   - The package also ships xpf-transit-closed.service, a boot-only oneshot that
//     writes 0 after systemd-sysctl and before networkd, FRR and xpfd. It closes
//     the kernel from boot until xpfd starts, whatever an older image's sysctl.d
//     says. It is not a sysctl.d file, because systemd-sysctl re-applies every
//     sysctl.d file whenever it runs, which would close transit under a running,
//     attached xpfd.
//   - markDataplaneArmed records the Start and re-evaluates the gate. It opens if
//     a live link is already attached; otherwise a later re-evaluation that finds
//     one opens it.
//   - reassertTransitGate re-reads the state and drives both legs to it.
//   - markDataplaneArmFailed and markDataplaneNotArmed close transit, as before.
//     They cover a Start failure, bootstrap, --no-dataplane, the bootstrap
//     rollback and the #9686 stop.
//   - Every state change and both gate legs run under transitGateMu. An apply that
//     outlives the shutdown drain cannot reopen transit after the stop closed it:
//     it re-reads the state under the lock and finds the dataplane unarmed.
//
// NOT CHANGED HERE.
//   - The #7178 RG arm track still follows the arm alone, so a restarting node
//     regains full weight at Start, before anything is attached (#9842).
//   - Nothing re-reads the count when a device goes away. If every XDP-bearing
//     device is unregistered between applies, transit stays open until the next
//     apply, with no program adjudicating it. The daemon has no always-on link
//     subscription to re-read from, and master kept transit open for the whole
//     armed run, attached or not (#9848).
//   - The boot oneshot closes routed transit only. Bridged frames ignore
//     ip_forward, and networkd recreates persisted bridge domains before xpfd
//     starts, so a bridge domain forwards with no barrier until
//     closeTransitUntilAttached installs it at bring-up. On master that window
//     ran on until an attached shim adjudicated the ports (#9852).
//
// WHAT WAITING COSTS. The armed AF_XDP fast path never needed ip_forward
// (docs/image-validation.md). The paths that XDP_PASS to the kernel wait for an
// attach after a start or restart: route-based IPsec plaintext off an xfrm
// interface, SNAT'd frames and the #7409 slow-path reinject. So does a node with
// nothing attached, which has no program to adjudicate transit with.

// transitGateAcquireHook, when set, runs just before a gate function takes
// transitGateMu, with that function's name. It is a test seam: a race cell waits
// for a stop to reach the lock before it checks that the stop is blocked. Never
// set in production.
var transitGateAcquireHook func(caller string)

// lockTransitGate takes transitGateMu on behalf of caller.
func (d *Daemon) lockTransitGate(caller string) {
	if transitGateAcquireHook != nil {
		transitGateAcquireHook(caller)
	}
	d.transitGateMu.Lock()
}

// attachedLinksSource is the optional runtime capability the gate reads. It is a
// type assertion, as armCoverageSource is, so the broad runtime interface and its
// fakes stay unchanged. Production publishes LegacyDataPlaneAdapter, which
// forwards it. A test pins that, because #9804 is what a missing forwarder costs.
type attachedLinksSource interface {
	AttachedXDPLinkCount() int
}

// attachedXDPLinks reads how many interfaces carry a shim XDP program now. It is
// 0 when no runtime is published or the runtime does not report it.
func (d *Daemon) attachedXDPLinks() int {
	src, ok := d.dataplane().(attachedLinksSource)
	if !ok {
		return 0
	}
	return src.AttachedXDPLinkCount()
}

// attachedLinksNotifier is the optional runtime capability that REPORTS link
// changes, the other half of attachedLinksSource. The daemon registers on the
// runtime it publishes and clears the one it unpublishes, so the observer's
// lifetime is the runtime's: package-level state would let one daemon's detach
// drive another daemon's gate when two exist in a process.
type attachedLinksNotifier interface {
	SetAttachedLinksObserver(func(int))
}

// registerAttachedLinksObserver arms the gate on the currently published runtime.
func (d *Daemon) registerAttachedLinksObserver() {
	if src, ok := d.dataplane().(attachedLinksNotifier); ok {
		src.SetAttachedLinksObserver(d.onAttachedLinksChanged)
	}
}

// clearAttachedLinksObserver disarms the currently published runtime, before it
// is replaced or dropped.
func (d *Daemon) clearAttachedLinksObserver() {
	if src, ok := d.dataplane().(attachedLinksNotifier); ok {
		src.SetAttachedLinksObserver(nil)
	}
}

// onAttachedLinksChanged drives the gate from the count a writer REPORTS. It
// does not read the count back: the report can arrive while the writer holds a
// lock the read would need, and after Close no handle can answer at all, so a
// read-back would say zero even for a hitless upgrade whose pinned programs are
// still forwarding.
func (d *Daemon) onAttachedLinksChanged(n int) {
	d.lockTransitGate("attachedLinksObserver")
	defer d.transitGateMu.Unlock()
	d.writeTransitGateForCountLocked("attached-links", n)
}

// transitOpen is the predicate every kernel-transit write follows, read against
// the LIVE attached-link count.
func (d *Daemon) transitOpen() bool {
	return d.transitOpenForCount(d.attachedXDPLinks())
}

// transitOpenForCount is that same predicate against a GIVEN count, which is
// what an observer report carries. Both forms go through here, so the rule has
// one statement: re-deriving it at the count-taking call site left transitOpen
// bypassed on the path the gate actually uses.
func (d *Daemon) transitOpenForCount(attached int) bool {
	return d.dataplaneArmed.Load() && attached > 0
}

// writeTransitGateLocked drives both legs of the gate, the two sysctls and the
// #7191 barrier, to transitOpen, and returns it. Opening writes the sysctls first
// and removes the barrier last; closing installs the barrier first. Either leg
// alone keeps ROUTED transit closed; bridged frames ignore the sysctls and rely
// on the barrier alone. So the order only decides how early a change is
// complete. A change of state is logged once. Caller holds transitGateMu.
func (d *Daemon) writeTransitGateLocked(stage string) (open, verified bool) {
	return d.writeTransitGateForCountLocked(stage, d.attachedXDPLinks())
}

// writeTransitGateForCountLocked is writeTransitGateLocked against a GIVEN
// attached-link count, which is what an observer report carries. Caller holds
// transitGateMu.
func (d *Daemon) writeTransitGateForCountLocked(stage string, attached int) (open, verified bool) {
	open = d.transitOpenForCount(attached)
	var sysctlsOK, barrierOK bool
	if open {
		sysctlsOK = writeTransitForwardSysctls(true)
		barrierOK = d.applyTransitBarrier(true)
	} else {
		barrierOK = d.applyTransitBarrier(false)
		sysctlsOK = writeTransitForwardSysctls(false)
	}
	verified = sysctlsOK && barrierOK
	// The transition logs name the gate's state. A leg that fails to actuate is
	// logged where it fails: writeTransitForwardSysctls and the barrier episodes.
	if open != d.transitWasOpen {
		d.transitWasOpen = open
		if open {
			slog.Info("transit gate open: the dataplane is armed and a shim XDP program is attached",
				// #9725: the REPORTED count, not a re-read. Re-reading here would
				// re-enter the Manager from inside the observer, while both
				// linkReportMu and transitGateMu are held — the very thing the
				// observer's contract says it does not do — and it would log a
				// number different from the one the gate just acted on.
				"stage", stage, "attached_links", attached,
				"sysctls_verified", sysctlsOK, "barrier_verified", barrierOK)
		} else {
			slog.Info("transit gate closed: the dataplane is unarmed or no shim XDP program is attached",
				"stage", stage, "dataplane_armed", d.dataplaneArmed.Load(),
				"sysctls_verified", sysctlsOK, "barrier_verified", barrierOK)
		}
	}
	return open, verified
}

// reassertTransitGate re-reads the arm and the attached links and drives both
// legs to them. It runs after every ApplyConfig, whatever that returned, and at
// the apply tail.
func (d *Daemon) reassertTransitGate(stage string) {
	d.lockTransitGate("reassertTransitGate")
	defer d.transitGateMu.Unlock()
	d.writeTransitGateLocked(stage)
}

// closeTransitUntilAttached closes kernel transit at bring-up, before the
// dataplane arms. Unlike markDataplaneNotArmed, it records nothing about the arm
// and leaves the #7178 RG arm track alone.
func (d *Daemon) closeTransitUntilAttached(stage string) {
	d.lockTransitGate("closeTransitUntilAttached")
	defer d.transitGateMu.Unlock()
	barrierOK := d.applyTransitBarrier(false)
	sysctlsOK := writeTransitForwardSysctls(false)
	d.transitWasOpen = false
	slog.Info("transit gate closed at bring-up; it opens when the dataplane is armed and a shim XDP link is attached",
		"stage", stage, "sysctls_verified", sysctlsOK, "barrier_verified", barrierOK)
}
