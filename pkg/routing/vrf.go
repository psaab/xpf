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

// vrfOps is the minimal netlink surface the VRF domain needs.
// Satisfied by *netlink.Handle in production; tests substitute a fake.
type vrfOps interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetUp(netlink.Link) error
	LinkSetMaster(netlink.Link, netlink.Link) error
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
}

// Create creates a Linux VRF device and assigns it a routing table.
func (v *vrfManager) Create(name string, tableID int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	// #9819: the miss terminator first, as in Reconcile.
	if v.term != nil {
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
// Ownership rules — xpfd is authoritative for the ENTIRE "vrf-*"
// kernel namespace. Any VRF whose name starts with "vrf-" is
// considered ours; operators MUST NOT pre-create vrf-<name> devices
// outside xpfd config.
//   - Desired VRF, present in kernel with matching table: no-op
//     (preserve ifindex). Adopted into v.vrfs if not already there.
//   - Desired VRF, present in kernel with mismatching table:
//     LinkDel + LinkAdd (recreate). Adopted into v.vrfs.
//   - Desired VRF, absent from kernel: LinkAdd, adopted into v.vrfs.
//   - Managed VRF in v.vrfs not in desired: LinkDel, removed from v.vrfs.
//   - #847 orphan: vrf-<X> in kernel but NOT in desired AND NOT in
//     v.vrfs (e.g. left over from a routing-instance rename across
//     a daemon restart, where v.vrfs was empty after the restart):
//     LinkDel via the namespace-claim sweep. xpfd reaps the entire
//     vrf-* namespace; if an operator created a vrf-<X> for their
//     own purposes, it WILL be deleted on next apply.
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
		termErr = setVRFMissTerminator(v.term, true)
	}
	newVrfs, err := reconcileVRFs(v.ops, v.vrfs, desired)
	v.vrfs = newVrfs
	// A VRF whose delete failed stays tracked and is still in the kernel, so
	// its misses still need ending: remove only once nothing is owned.
	if v.term != nil && len(desired) == 0 && len(newVrfs) == 0 {
		termErr = setVRFMissTerminator(v.term, false)
	}
	switch {
	case termErr == nil:
		return err
	case err == nil:
		return termErr
	}
	return errors.Join(err, termErr)
}

// BindInterfaceToVRF binds a network interface to a VRF device.
//
// This method takes NO lock — it is a pure netlink operation
// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
// lock-free property is what makes it safe for the tunnel domain to
// call while holding its own lock (see tunnel.go), with no lock
// ordering cycle.
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
	if err := v.ops.LinkSetMaster(iface, vrf); err != nil {
		return fmt.Errorf("bind %s to VRF %s: %w", ifaceName, vrfName, err)
	}
	slog.Info("interface bound to VRF", "interface", ifaceName, "vrf", vrfName)
	return nil
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
// Ownership semantics: xpfd is authoritative for the ENTIRE "vrf-*"
// kernel namespace. A VRF is "ours" by virtue of name prefix; if its
// logical name appears in desired, reconcileVRFs ADOPTS it into
// v.vrfs (handles the post-restart case). #847 orphan reap: any
// kernel "vrf-*" device NOT in desired AND NOT in v.vrfs is also
// deleted, so operators must NOT pre-create vrf-<name> outside
// xpfd config.
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

		// Present in kernel. Adopt it — the vrf-<desired-name>
		// namespace is ours, regardless of who created the device.
		currentTable := vrfTable(link)
		if currentTable == uint32(spec.TableID) {
			if err := ops.LinkSetUp(link); err != nil {
				slog.Debug("VRF set-up failed (non-fatal)", "name", vrfName, "err", err)
			}
			newTracked = append(newTracked, vrfName)
			continue
		}

		// Table mismatch — recreate with desired table.
		slog.Warn("VRF table ID mismatches desired, recreating",
			"name", vrfName, "old_table", currentTable, "new_table", spec.TableID)
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
	// xpfd claims the ENTIRE `vrf-*` kernel namespace — operators
	// must not pre-create vrf-<X> outside config. This is a
	// stricter policy than the original #844 plan (which preserved
	// "external" VRFs); the godoc on Reconcile is the
	// authoritative contract.
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
	// added=true (the caller records ownership so a later reconcile can clean
	// up), but surface the error so the commit fails closed; the reconcile
	// adopt path (vrfTable → recreate on table mismatch) reclaims it next cycle.
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

// vrfTable returns the routing table of a VRF link, or 0 if the link
// is not a VRF (which indicates a namespace collision with a
// non-VRF device of the same name).
func vrfTable(link netlink.Link) uint32 {
	if v, ok := link.(*netlink.Vrf); ok {
		return v.Table
	}
	return 0
}
