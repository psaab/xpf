package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
)

// VRFSpec describes a single VRF by its logical name (no "vrf-"
// prefix) and its kernel routing table ID.
type VRFSpec struct {
	Name    string
	TableID int
}

// VRFInterfaceMember is a link currently enslaved to a named routing-instance
// VRF device.
type VRFInterfaceMember struct {
	InterfaceName string
	InstanceName  string
}

// vrfOps is the minimal netlink surface the VRF domain needs.
// Satisfied by *netlink.Handle in production; tests substitute a fake.
type vrfOps interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetUp(netlink.Link) error
	LinkSetMaster(netlink.Link, netlink.Link) error
	// #11060: detach a quarantined member back to the default routing
	// context (UnbindInterfaceFromVRF). *netlink.Handle already provides
	// this; fakes add a no-op or recording stub.
	LinkSetNoMaster(netlink.Link) error
	// #847: enumerate kernel devices to find orphan VRFs (left
	// over from a routing-instance rename across a daemon restart).
	LinkList() ([]netlink.Link, error)
}

// vrfManager owns VRF device lifecycle and interface-to-VRF binding.
// It holds its own mutex (formerly Manager.vrfsMu) and the tracked
// VRF device set, and depends only on the narrow vrfOps surface.
type vrfManager struct {
	ops vrfOps

	// term installs and removes the #9819 VRF miss terminator
	// (vrf_miss_terminator_9819.go). New wires the production ops. Only the
	// link-only test constructors leave it nil, and the real-kernel cell drives
	// a Manager built by New, so the production wiring is exercised.
	term vrfMissTerminatorOps

	// mu serializes all reads and writes of vrfs, and is held for the
	// full duration of Reconcile/Create including the netlink
	// operations. Callers must not assume Reconcile is re-entrant. See
	// docs/pr/844-vrf-idempotent/plan.md.
	mu   sync.Mutex
	vrfs []string // currently managed VRF device names
	// termRequired is the manager's desired presence state for the miss
	// terminator, set before link operations so a failed create cannot lose
	// install intent; it is not a second config snapshot.
	// termRemovePending records a failed removal separately: the desired state
	// is empty, but the stale kernel rules still need a retry.
	termRequired      bool
	termRemovePending bool
}

// Create creates a Linux VRF device and assigns it a routing table.
func (v *vrfManager) Create(name string, tableID int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	// #9819: the miss terminator first, as in Reconcile.
	if v.term != nil {
		v.termRequired = true
		if err := setVRFMissTerminator(v.term, true); err != nil {
			return errors.Join(err, v.createLocked(name, tableID))
		}
	}
	return v.createLocked(name, tableID)
}

// createLocked creates a VRF and appends it to v.vrfs. Caller must
// hold mu. If the named VRF already exists in the kernel, createLocked
// leaves it alone and does NOT adopt it into v.vrfs (this single-VRF
// helper is a fast path; Reconcile is the adoption / orphan-reap entry
// point per the namespace-claim policy).
func (v *vrfManager) createLocked(name string, tableID int) error {
	vrfName := "vrf-" + name
	if existing, err := v.ops.LinkByName(vrfName); err == nil {
		if err := v.ops.LinkSetUp(existing); err != nil {
			slog.Debug("failed to set existing VRF up", "name", vrfName, "err", err)
		}
		slog.Debug("VRF already exists", "name", vrfName, "table", tableID)
		return nil
	}
	added, err := createLinkedVRF(v.ops, vrfName, tableID)
	if added {
		v.vrfs = append(v.vrfs, vrfName)
	}
	return err
}

// IsManaged reports whether the given logical VRF name (e.g. "mgmt",
// "sfmix") is currently in the manager's tracked set.
func (v *vrfManager) IsManaged(name string) bool {
	vrfName := "vrf-" + name
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, n := range v.vrfs {
		if n == vrfName {
			return true
		}
	}
	return false
}

// Reconcile brings the manager's owned-VRF set to match desired.
//
// Ownership rules — xpfd manages VRFs in the "vrf-*" kernel namespace.
// The link type is still authoritative: a desired name occupied by a
// non-VRF device is foreign and causes reconcile to fail closed without
// deleting it. Operators MUST NOT pre-create VRF devices outside xpfd config.
//   - Desired VRF, present in kernel with matching table: no-op
//     (preserve ifindex). Adopted into v.vrfs if not already there.
//   - Desired VRF, present in kernel with mismatching table:
//     LinkDel + LinkAdd (recreate). Adopted into v.vrfs.
//   - Desired VRF name occupied by a non-VRF device: return an error,
//     leave the link untouched, and do not adopt it.
//   - Desired VRF, absent from kernel: LinkAdd, adopted into v.vrfs.
//   - Managed VRF in v.vrfs not in desired: LinkDel if the link is a
//     VRF, removed from v.vrfs; a same-name non-VRF is foreign and
//     left alone (skipped, not deleted).
//   - #847 orphan: vrf-<X> in kernel but NOT in desired AND NOT in
//     v.vrfs (e.g. left over from a routing-instance rename across
//     a daemon restart, where v.vrfs was empty after the restart):
//     LinkDel only if the link is a VRF; non-VRF links are left alone.
//
// Holds mu for the full body including netlink operations. VRF
// reconcile is low-frequency; lock contention is not a concern and
// serialized reconciles avoid TOCTOU between concurrent callers.
//
// #9819: when any VRF is desired, Reconcile installs the VRF miss terminator
// BEFORE it creates a device, so no VRF is ever live with its misses falling
// through to main. When nothing is desired and nothing is still owned, it
// removes the terminator afterwards. A terminator failure is returned beside
// the link reconcile's error and never skips the link reconcile.
func (v *vrfManager) Reconcile(desired []VRFSpec) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	var termErr error
	if v.term != nil && len(desired) > 0 {
		v.termRequired = true
		v.termRemovePending = false
		termErr = setVRFMissTerminator(v.term, true)
	}
	newVrfs, err := reconcileVRFs(v.ops, v.vrfs, desired)
	v.vrfs = newVrfs
	// A VRF whose delete failed stays tracked and is still in the kernel, so
	// its misses still need ending: remove only once nothing is owned.
	if v.term != nil && len(desired) == 0 && len(newVrfs) == 0 {
		termErr = setVRFMissTerminator(v.term, false)
		if termErr == nil {
			v.termRequired = false
			v.termRemovePending = false
		} else {
			v.termRequired = false
			v.termRemovePending = true
		}
	} else if len(newVrfs) > 0 {
		v.termRequired = true
		v.termRemovePending = false
	}
	switch {
	case termErr == nil:
		return err
	case err == nil:
		return termErr
	}
	return errors.Join(err, termErr)
}

// ReassertMissTerminator restores the managed pref-2000 l3mdev unreachable
// rules, or retries a failed removal, without reconciling links or changing
// ownership. The apply pipeline calls this after networkd activation on every
// commit; the manager's ownership state keeps empty configurations from
// installing a global rule while retaining removal debt.
func (v *vrfManager) ReassertMissTerminator() error {

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.term == nil {
		return nil
	}
	if v.termRequired || len(v.vrfs) > 0 {
		v.termRemovePending = false
		return setVRFMissTerminator(v.term, true)
	}
	if !v.termRemovePending {
		return nil
	}
	if err := setVRFMissTerminator(v.term, false); err != nil {
		return err
	}
	v.termRemovePending = false
	return nil

}

// MissTerminatorNeedsReconcile reports whether the manager still owns a VRF
// miss terminator state that the apply boundary must restore or remove.
func (v *vrfManager) MissTerminatorNeedsReconcile() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.term != nil && (v.termRequired || v.termRemovePending)
}

// BindInterfaceToVRF binds a network interface to a VRF device.
//
// A VRF link is type-asserted before binding: reconcile's name-based
// reclamation can be separated from this call by other netlink activity.
// The type check and LinkSetMaster are separate syscalls, so out-of-band
// replacement between them remains outside the daemon's applySem guarantee.
func (v *vrfManager) BindInterfaceToVRF(ifaceName, instanceName string) error {
	vrfName := "vrf-" + instanceName

	iface, err := v.ops.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	vrf, err := v.ops.LinkByName(vrfName)
	if err != nil {
		return fmt.Errorf("VRF %s not found: %w", vrfName, err)
	}
	vrfLink, ok := vrf.(*netlink.Vrf)
	if !ok || vrfLink == nil || vrfLink.Attrs() == nil {
		return fmt.Errorf("VRF %s is not a VRF device", vrfName)
	}
	if err := v.ops.LinkSetMaster(iface, vrfLink); err != nil {
		return fmt.Errorf("bind %s to VRF %s: %w", ifaceName, vrfName, err)
	}
	slog.Info("interface bound to VRF", "interface", ifaceName, "vrf", vrfName)
	return nil
}

// UnbindInterfaceFromVRFs detaches ifaceName only when its current master is
// one of the named VRF devices. It deliberately leaves unrelated masters
// untouched so a stale quarantine cannot detach a link owned by another
// subsystem. It takes no manager lock and returns whether it detached a link.
func (v *vrfManager) UnbindInterfaceFromVRFs(ifaceName string, instanceNames []string) (bool, error) {
	if v == nil || v.ops == nil || ifaceName == "" {
		return false, nil
	}
	iface, err := v.ops.LinkByName(ifaceName)
	if err != nil {
		if isLinkNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("interface %s lookup: %w", ifaceName, err)
	}
	if iface == nil || iface.Attrs() == nil || iface.Attrs().MasterIndex == 0 {
		return false, nil
	}
	// The observed master index and subsequent LinkSetNoMaster are not atomic
	// against arbitrary netlink writers. Daemon apply and periodic reassert
	// serialize callers through applySem; concurrent out-of-band `ip link` or
	// network-manager master changes are outside this guarantee.
	masterIndex := iface.Attrs().MasterIndex
	var lookupErrs []error
	for _, instanceName := range instanceNames {
		if instanceName == "" {
			continue
		}
		vrf, err := v.ops.LinkByName("vrf-" + instanceName)
		if err != nil {
			if !isLinkNotFound(err) {
				lookupErrs = append(lookupErrs, fmt.Errorf("VRF %s lookup: %w", instanceName, err))
			}
			continue
		}
		masterVRF, ok := vrf.(*netlink.Vrf)
		if !ok || masterVRF.Attrs() == nil || masterVRF.Attrs().Index != masterIndex {
			continue
		}
		if err := v.ops.LinkSetNoMaster(iface); err != nil {
			return false, fmt.Errorf("unbind %s from VRF %s: %w", ifaceName, instanceName, err)
		}
		return true, nil
	}
	if len(lookupErrs) > 0 {
		return false, errors.Join(lookupErrs...)
	}
	return false, nil
}

// InterfaceMembers returns links currently enslaved to the named VRF devices.
// Matching uses the live VRF type and ifindex so a same-name foreign master is
// never treated as a routing-instance membership.
func (v *vrfManager) InterfaceMembers(instanceNames []string) ([]VRFInterfaceMember, error) {
	if v == nil || v.ops == nil || len(instanceNames) == 0 {
		return nil, nil
	}
	links, err := v.ops.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links for routing-instance VRF members: %w", err)
	}

	instanceByMasterIndex := make(map[int]string, len(instanceNames))
	var lookupErrs []error
	for _, instanceName := range instanceNames {
		if instanceName == "" {
			continue
		}
		link, err := v.ops.LinkByName("vrf-" + instanceName)
		if err != nil {
			if !isLinkNotFound(err) {
				lookupErrs = append(lookupErrs, fmt.Errorf("lookup VRF vrf-%s for members: %w", instanceName, err))
			}
			continue
		}
		vrf, ok := link.(*netlink.Vrf)
		if !ok || vrf.Attrs() == nil || vrf.Attrs().Index <= 0 {
			continue
		}
		instanceByMasterIndex[vrf.Attrs().Index] = instanceName
	}

	members := make([]VRFInterfaceMember, 0)
	for _, link := range links {
		if link == nil || link.Attrs() == nil || link.Attrs().Name == "" ||
			link.Attrs().MasterIndex <= 0 {
			continue
		}
		if _, isVRF := link.(*netlink.Vrf); isVRF {
			continue
		}
		if instanceName, ok := instanceByMasterIndex[link.Attrs().MasterIndex]; ok {
			members = append(members, VRFInterfaceMember{
				InterfaceName: link.Attrs().Name,
				InstanceName:  instanceName,
			})
		}
	}
	return members, errors.Join(lookupErrs...)
}

// errLinkNotFound is an internal sentinel wrapper used when the
// manager generates its own "not found" errors (e.g. from fakes in
// tests, or from any path not going through the netlink library).
// netlink.LinkNotFoundError cannot be constructed outside the
// netlink package because its embedded error field is unexported.
type errLinkNotFound struct{ error }

// isLinkNotFound reports whether err is a "link not found" error
// from either the netlink library or the internal sentinel. Other
// errors (EINVAL, EBUSY, transport failure) must NOT be treated as
// absence.
func isLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nlNotFound netlink.LinkNotFoundError
	if errors.As(err, &nlNotFound) {
		return true
	}
	var internal errLinkNotFound
	return errors.As(err, &internal)
}

// reconcileVRFs is the pure core of Reconcile, parameterised on a
// vrfOps so tests can inject a fake. Returns the new tracked set and
// the first error encountered (others are logged).
//
// Ownership semantics: xpfd manages VRF devices by name, but the link
// TYPE is authoritative (#12062). A *netlink.Vrf whose logical name
// appears in desired is ADOPTED into v.vrfs (handles the post-restart
// case). A same-name non-VRF link (bridge, dummy, …) is FOREIGN: it is
// never adopted, brought up, or deleted — reconcile refuses with an
// error until its owner removes it. #847 orphan reap: any kernel VRF
// device NOT in desired AND NOT in v.vrfs is deleted; non-VRF
// vrf-* names are skipped. Operators must NOT pre-create vrf-<name>
// outside xpfd config.
//
// Partial-failure contract: if LinkAdd succeeds but a follow-up
// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
// tracked set. Similarly, LinkDel failures retain ownership. This
// ensures a future reconcile can retry.
func reconcileVRFs(ops vrfOps, tracked []string, desired []VRFSpec) ([]string, error) {
	desiredByName := make(map[string]int, len(desired))
	for _, spec := range desired {
		desiredByName["vrf-"+spec.Name] = spec.TableID
	}
	managed := make(map[string]bool, len(tracked))
	for _, name := range tracked {
		managed[name] = true
	}

	var firstErr error
	recordErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	newTracked := make([]string, 0, len(desired))

	for _, spec := range desired {
		vrfName := "vrf-" + spec.Name
		link, kerErr := ops.LinkByName(vrfName)

		if kerErr != nil {
			if !isLinkNotFound(kerErr) {
				// Transient netlink error — don't assume the VRF is
				// absent and don't attempt to create it. Next
				// reconcile will retry. CRUCIALLY: if this name was
				// already in v.vrfs, retain ownership — otherwise a
				// transient blip would silently drop us from the
				// managed set and IsManaged would start lying.
				if managed[vrfName] {
					newTracked = append(newTracked, vrfName)
				}
				recordErr(fmt.Errorf("lookup VRF %s: %w", vrfName, kerErr))
				continue
			}
			// Genuinely not in kernel — create it.
			added, err := createLinkedVRF(ops, vrfName, spec.TableID)
			if added {
				newTracked = append(newTracked, vrfName)
			}
			recordErr(err)
			continue
		}

		// A same-name non-VRF is foreign, not a stale VRF. Fail closed
		// rather than deleting an operator-created device.
		if _, ok := link.(*netlink.Vrf); !ok {
			// recordErr keeps only the first error: warn here so every
			// foreign occupant reaches the journal, not just the first
			// per reconcile.
			slog.Warn("refusing to reconcile desired-name foreign non-VRF link",
				"name", vrfName, "type", link.Type())
			recordErr(fmt.Errorf("refusing to reconcile VRF %s: existing link is %s, not a VRF",
				vrfName, link.Type()))
			continue
		}

		// Present in kernel and type-asserted above: bind the VRF and
		// read its table directly.
		vrf := link.(*netlink.Vrf)
		if vrf.Table == uint32(spec.TableID) {
			if err := ops.LinkSetUp(link); err != nil {
				slog.Debug("VRF set-up failed (non-fatal)", "name", vrfName, "err", err)
			}
			newTracked = append(newTracked, vrfName)
			continue
		}

		// Table mismatch — recreate with desired table.
		slog.Warn("VRF table ID mismatches desired, recreating",
			"name", vrfName, "old_table", vrf.Table, "new_table", spec.TableID)
		if err := ops.LinkDel(link); err != nil {
			// Delete failed — VRF still exists with wrong table.
			// Retain ownership so a future reconcile can retry.
			newTracked = append(newTracked, vrfName)
			recordErr(fmt.Errorf("delete stale VRF %s: %w", vrfName, err))
			continue
		}
		added, err := createLinkedVRF(ops, vrfName, spec.TableID)
		if added {
			newTracked = append(newTracked, vrfName)
		}
		recordErr(err)
	}

	// Delete managed VRFs no longer in desired.
	for _, existing := range tracked {
		if _, stillDesired := desiredByName[existing]; stillDesired {
			continue
		}
		link, err := ops.LinkByName(existing)
		if err != nil {
			if !isLinkNotFound(err) {
				// Transient — retain ownership; don't drop silently.
				newTracked = append(newTracked, existing)
				recordErr(fmt.Errorf("lookup VRF %s for delete: %w", existing, err))
			}
			// Not found: already gone; nothing to do.
			continue
		}
		if _, ok := link.(*netlink.Vrf); !ok {
			// Tracked name swapped out-of-band for a non-VRF (and
			// removed from config in the same interval): the link is
			// foreign, not our stale VRF. Refuse deletion (#12062).
			slog.Warn("refusing to delete tracked-not-desired non-VRF link",
				"name", existing, "type", link.Type())
			continue
		}
		if err := ops.LinkDel(link); err != nil {
			// Delete failed — VRF still exists. Retain in tracked so
			// next reconcile retries instead of losing ownership.
			newTracked = append(newTracked, existing)
			recordErr(fmt.Errorf("delete VRF %s: %w", existing, err))
			continue
		}
		slog.Info("VRF removed", "name", existing)
	}

	// #847: orphan reap. After a routing-instance rename across a
	// daemon restart, the old vrf-<oldname> persists in the kernel
	// while v.vrfs is empty (state lost on exit). The "delete
	// managed VRFs no longer desired" loop above can't catch it
	// (oldname isn't in tracked). Walk the kernel `vrf-*` namespace
	// and delete any VRF that is neither in `desired` nor in
	// `tracked` (already handled).
	//
	// xpfd manages VRF devices by name, but the link type stays
	// authoritative (#12062): only *netlink.Vrf links are deleted
	// here; same-name non-VRF links are foreign and left alone. This
	// is stricter than the original #844 plan (which preserved
	// "external" VRFs); the godoc on Reconcile is the authoritative
	// contract.
	links, err := ops.LinkList()
	if err != nil {
		// Best-effort: log and continue. The desired/tracked sets
		// already reflect what we can manage authoritatively.
		slog.Debug("VRF orphan reap: LinkList failed (non-fatal)", "err", err)
		return newTracked, firstErr
	}
	for _, link := range links {
		name := link.Attrs().Name
		if !strings.HasPrefix(name, "vrf-") {
			continue
		}
		if _, ok := link.(*netlink.Vrf); !ok {
			// Misnamed non-VRF interface (operator-created bridge
			// named "vrf-foo" or similar). Don't delete.
			continue
		}
		if _, stillDesired := desiredByName[name]; stillDesired {
			continue
		}
		if managed[name] {
			// Already handled by the tracked-but-not-desired loop above.
			continue
		}
		if err := ops.LinkDel(link); err != nil {
			slog.Warn("VRF orphan reap: LinkDel failed",
				"name", name, "err", err)
			continue
		}
		slog.Info("VRF orphan reaped", "name", name)
	}

	return newTracked, firstErr
}

// createLinkedVRF creates a VRF. Returns (added, err) where added is
// true if LinkAdd succeeded (even if a follow-up step failed). This
// lets callers record ownership of partially-created VRFs so a future
// reconcile can clean them up. Does not append to any tracked list —
// caller owns tracked-set updates.
func createLinkedVRF(ops vrfOps, vrfName string, tableID int) (bool, error) {
	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: vrfName},
		Table:     uint32(tableID),
	}
	if err := ops.LinkAdd(vrf); err != nil {
		return false, fmt.Errorf("create VRF %s: %w", vrfName, err)
	}
	link, err := ops.LinkByName(vrfName)
	if err != nil {
		return true, fmt.Errorf("find VRF %s after add: %w", vrfName, err)
	}
	// #6396: re-assert the post-create readback is the VRF we just created,
	// carrying the desired table, before bringing it up. LinkAdd and this
	// LinkByName are two syscalls; a concurrent external actor that deleted the
	// fresh device and substituted a same-name foreign link (or a VRF with a
	// different table) in that window would otherwise be brought up and the
	// name recorded as satisfied while no VRF with the desired table exists —
	// the routes leaked into it silently blackhole. LinkAdd succeeded, so
	// added=true (the caller records the partial create for reconcile), but
	// surface the error so the commit fails closed. A non-VRF occupant will be
	// rejected by reconcile until it is removed by its owner.
	if vrf, ok := link.(*netlink.Vrf); !ok || vrf.Table != uint32(tableID) {
		have := "non-VRF type " + link.Type()
		if ok {
			have = fmt.Sprintf("table %d", vrf.Table)
		}
		slog.Warn("VRF readback after create is not the intended interface",
			"name", vrfName, "want_table", tableID, "have", have)
		return true, fmt.Errorf(
			"VRF %s readback after create mismatch (want table %d, have %s)",
			vrfName, tableID, have)
	}
	if err := ops.LinkSetUp(link); err != nil {
		return true, fmt.Errorf("set VRF %s up: %w", vrfName, err)
	}
	slog.Info("VRF created", "name", vrfName, "table", tableID)
	return true, nil
}
