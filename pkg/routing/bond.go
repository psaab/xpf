package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// bondManager owns Linux bond device lifecycle for interfaces with
// fabric-options member-interfaces. The mu field replaces the bonds
// slice of the former shared Manager.ifaceMu.
type bondManager struct {
	ops linkOps

	mu sync.Mutex
	// bonds tracks the currently created bond devices by name, each mapped
	// to the signature (mode, MTU, resolved member set) it was realized
	// with. The signature lets Apply detect an UNCHANGED bond and leave it
	// untouched instead of tearing it down and rebuilding it on every
	// commit (#5119).
	bonds map[string]bondSig
}

// bondSig captures the parts of a fabric/ae bond's desired config that
// determine its kernel realization: the bond mode, the interface-level
// MTU, and the resolved (Linux-named) member set. Two bonds with an
// identical signature realize the same kernel device, so an unchanged
// signature means the bond must NOT be LinkDel'd and rebuilt on an
// unrelated commit — doing so re-enslaves members and forces LACP to
// re-converge, flapping the LAG (#5119). bondSig is a comparable struct
// (the member set is pre-sorted and joined into a single string) so a
// plain == is the whole diff.
type bondSig struct {
	mode    string // normalized: "active-backup" or "802.3ad"
	mtu     int    // interface-level MTU (0 = kernel default, not set)
	members string // sorted, comma-joined resolved Linux member names
}

// bondSigOf derives the signature of the bond an interface config would
// realize. The mode is normalized the same way Apply programs it (any
// non-"active-backup" mode is 802.3ad), and members are resolved to their
// Linux names and sorted so member-order or Junos-vs-Linux spelling never
// registers as a spurious change.
func bondSigOf(ifc *config.InterfaceConfig) bondSig {
	mode := "802.3ad"
	if ifc.BondMode == "active-backup" {
		mode = "active-backup"
	}
	members := make([]string, 0, len(ifc.FabricMembers))
	for _, m := range ifc.FabricMembers {
		members = append(members, config.LinuxIfName(m))
	}
	sort.Strings(members)
	return bondSig{
		mode:    mode,
		mtu:     ifc.MTU,
		members: strings.Join(members, ","),
	}
}

// Apply reconciles the Linux bond devices for interfaces with
// fabric-options member-interfaces against the currently tracked set.
// The bond mode comes from InterfaceConfig.BondMode (active-backup for
// fabric bonds, 802.3ad for ae interfaces).
//
// Apply is invoked on EVERY config commit, not only when the bond/fabric
// config changes (daemon_apply.go always calls ApplyBonds so bonds for
// deleted fabric interfaces are torn down). It therefore reconciles the
// desired bond set differentially rather than clearing and rebuilding —
// the fix for #5119, mirroring the #2546 XFRM reconcile:
//
//   - KEEP a bond untouched when it is still desired with an identical
//     signature (mode, MTU, member set) AND its kernel device is still
//     present — no LinkDel/LinkAdd/LinkSetMaster, so an unrelated policy-only
//     commit no longer flaps the LAG (LinkDel→LinkAdd→re-enslave→LACP
//     re-converge). This was the non-idempotent anti-pattern #2546 fixed for
//     XFRM but not bonds. If a tracked, still-desired bond has VANISHED from
//     the kernel (deleted out from under the daemon), the KEEP is NOT taken:
//     the bond is RECREATED rather than reported as falsely converged
//     (#5703 / codex-review-182 M29).
//   - CREATE a bond that is newly desired (also adopts a kernel bond that
//     outlived in-memory tracking, e.g. across a daemon restart). Both the
//     create and adopt paths verify the bond's ACTUAL enslaved member set and
//     track the REALIZED signature, not the full desired one: a member absent
//     at realization time (a #4823 soft error) yields a PARTIAL sig, never a
//     full one recorded as satisfied (#5261). A fully-realized adopt tracks
//     the full desired sig and never flaps (#5259).
//   - COMPLETE a still-desired bond whose realized member set is a strict
//     SUBSET of the desired set (same mode/MTU, just missing members) IN
//     PLACE — the missing members are enslaved via the adopt branch with no
//     LinkDel/LinkAdd, so a live (degraded) fabric/RETH bond is never flapped
//     on an unrelated commit. This is the self-heal path for a partial
//     realization once the absent member appears (#5261).
//   - RECREATE (delete+create) a bond whose identity changed — a genuine
//     config change that is NOT a pure member addition (member removed, mode
//     or MTU changed). The bond mode and existing enslavement cannot be
//     changed in place while members are attached, so such a change is a
//     delete+rebuild.
//   - DELETE a bond that is no longer desired (its fabric interface was
//     removed).
//
// A no-op commit (identical desired bond set) issues zero LinkDel, zero
// LinkAdd, and zero LinkSetMaster calls.
//
// Link-creation/enslavement/bring-up failures (LinkAdd, LinkSetMaster,
// LinkSetUp) are accumulated with errors.Join and returned instead of
// silently swallowed (#4823): before that fix, every one of these netlink
// failures was logged and skipped, and Apply ALWAYS returned nil — so a
// commit whose fabric/ae bond could not be realized in the kernel still
// reported success. LinkSetDown (best-effort pre-enslave step) and a
// not-yet-present member link (LinkByName on a FabricMembers entry —
// routine during interface enumeration ordering) remain log-only.
func (b *bondManager) Apply(interfaces []*config.InterfaceConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.bonds == nil {
		b.bonds = map[string]bondSig{}
	}

	// Build the desired name -> signature set. Skip interfaces with no
	// fabric members and vSRX single-local-member fabric-options mode
	// (LocalFabricMember resolved via .link rename — no bond device).
	desired := make(map[string]bondSig, len(interfaces))
	order := make([]string, 0, len(interfaces))
	ifcByName := make(map[string]*config.InterfaceConfig, len(interfaces))
	for _, ifc := range interfaces {
		if len(ifc.FabricMembers) == 0 || ifc.LocalFabricMember != "" {
			continue
		}
		if _, dup := desired[ifc.Name]; dup {
			continue
		}
		desired[ifc.Name] = bondSigOf(ifc)
		order = append(order, ifc.Name)
		ifcByName[ifc.Name] = ifc
	}

	var errs []error

	// Delete pass: remove bonds that are no longer desired OR whose identity
	// changed. A KEPT bond is left untouched — no destructive link op — so an
	// unrelated commit does not flap the LAG (#5119). A bond is KEPT when it
	// is still desired AND either:
	//   - its signature is identical (unchanged), or
	//   - it needs only a PARTIAL COMPLETION: same mode/MTU, and the tracked
	//     (realized) member set is a strict subset of the desired set. Such a
	//     bond is completed in place in the create pass (enslave the missing
	//     members, no LinkDel/LinkAdd) instead of being delete+recreated —
	//     never flap a live (degraded) fabric/RETH bond to add a member
	//     (#5261).
	// Everything else (no longer desired, or a genuine identity change: member
	// removed, mode/MTU changed) is deleted. #4901: a failed LinkDel retains
	// tracking so the next reconcile retries; a changed bond whose delete
	// failed keeps its OLD signature, so it is NOT recreated this cycle (its
	// stale kernel device is still present) and the next reconcile retries the
	// delete first.
	for name, trackedSig := range b.bonds {
		if wantSig, want := desired[name]; want &&
			(wantSig == trackedSig || isPartialCompletion(trackedSig, wantSig)) {
			continue // keep — unchanged or an in-place partial completion
		}
		if err := b.deleteLocked(name); err != nil {
			errs = append(errs, err)
		}
	}

	// Create/reconcile pass: build bonds that are newly desired or were just
	// deleted because their identity changed, and complete partial bonds in
	// place.
	for _, name := range order {
		sig := desired[name]
		if trackedSig, kept := b.bonds[name]; kept {
			// Survived the delete pass.
			if trackedSig == sig {
				// Unchanged in the desired config. Verify the kernel device is
				// actually PRESENT *and is a bond* before declaring convergence.
				// If a real bond is still there, bring it up idempotently (a
				// no-op on an already-up bond, matching the XFRM keep path);
				// zero LinkDel/LinkAdd/LinkSetMaster, so no flap.
				//
				// #6402: the type re-assertion is REQUIRED here, symmetric with
				// the createLocked adopt gate. LinkByName resolves the NAME, not
				// the type, so this KEEP fast-path must NOT bring up + `continue`
				// on whatever wears the name — that would re-open the silent
				// LAG-absence bug the adopt gate closes, on two reachable
				// transitions:
				//   1. A tracked bond (b.bonds[name]==sig) is replaced by a
				//      same-name FOREIGN (non-bond) link. The KEEP path would
				//      bring the foreign link up and report convergence while the
				//      LAG is gone.
				//   2. The delete-fail loop: createLocked found a foreign link,
				//      deleteLocked FAILED (fail-closed for that reconcile) but
				//      tracking only clears after a SUCCESSFUL LinkDel, so
				//      b.bonds[name] is still == sig. Without this gate the next
				//      reconcile's KEEP path would bring the foreign link up and
				//      `continue`, never re-entering createLocked, never retrying
				//      the delete — false convergence forever.
				// So a non-bond link falls through to the recreate path below,
				// which re-enters createLocked; its #6402 adopt gate reclaims the
				// foreign link (delete+recreate) or fails closed again on a delete
				// error, so b.bonds[name] is never left == sig with a foreign link
				// presented as satisfied.
				if link, err := b.ops.LinkByName(name); err == nil {
					if _, isBond := link.(*netlink.Bond); isBond {
						// #9872: the bond owner converges the live MTU. The
						// dataplane no longer plans a fabric bond's MTU from a
						// tagged ref, and the signature carries no units — so a
						// unit-MTU override written while an untagged unit
						// existed would otherwise stick forever once the unit
						// is removed (same sig → KEEP, no correction anywhere).
						if err := b.reconcileBondMTU(name, link, sig); err != nil {
							errs = append(errs, err)
						}
						if err := b.ops.LinkSetUp(link); err != nil {
							slog.Warn("failed to bring up existing bond", "name", name, "err", err)
							errs = append(errs, fmt.Errorf("bond %s: bring up existing: %w", name, err))
						}
						continue
					}
					// A same-name foreign link wears the bond's name — do NOT
					// bring it up or `continue`. Fall through to the recreate
					// path below.
				}
				// The tracked bond has VANISHED from the kernel (deleted out
				// from under the daemon — an operator `ip link del`, a driver
				// reset, or a transient kernel failure) OR has been REPLACED by
				// a same-name foreign link (#6402), yet is still desired with an
				// identical signature. Treating either as "unchanged" is false
				// convergence: the reconciler reports success while no bond
				// carries the fabric/RETH members (#5703 / codex-review-182 M29,
				// extended to the foreign-replacement case in #6402). RECREATE
				// via createLocked: on a VANISHED bond it finds no kernel device
				// (LinkByName miss) and takes the create+enslave path; on a
				// foreign replacement its adopt gate reclaims the link
				// (delete+recreate) or fails closed on a delete error. Either way
				// it tracks the ACTUAL realized member set (a still-absent member
				// yields a partial sig for a later in-place completion, #5261). A
				// create/delete failure is aggregated, not swallowed.
				slog.Warn("tracked bond missing or replaced by a foreign link; recreating", "name", name)
				if err := b.createLocked(name, ifcByName[name], sig); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if isPartialCompletion(trackedSig, sig) {
				// Same bond, missing members. Complete the enslavement IN
				// PLACE via the adopt branch of createLocked (the kernel bond
				// still exists — it was NOT deleted above), which enslaves the
				// still-missing members and re-tracks the realized member set.
				// No LinkDel/LinkAdd — the degraded bond is not flapped (#5261).
				if err := b.createLocked(name, ifcByName[name], sig); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			// A genuine identity change whose LinkDel failed above (OLD sig
			// retained). Skip recreation this cycle to avoid an EEXIST LinkAdd;
			// the next reconcile retries the delete first.
			continue
		}
		if err := b.createLocked(name, ifcByName[name], sig); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// createLocked realizes a single desired bond in the kernel: it adopts an
// already-present kernel device of that name without tearing it down (one
// that outlived in-memory tracking across a daemon restart, or whose prior
// LinkDel failed), or else creates the bond, enslaves its members, and
// brings everything up. On success the bond is tracked under the signature
// of its ACTUAL realized member set (which equals sig once fully enslaved).
// Netlink failures are aggregated and returned (#4823) rather than
// swallowed; a LinkAdd / find-after-create failure leaves the bond
// UNTRACKED so the next reconcile retries. Caller must hold mu.
func (b *bondManager) createLocked(name string, ifc *config.InterfaceConfig, sig bondSig) error {
	// Adopt an existing kernel device without a destructive rebuild — but
	// verify the actual enslaved member set before accepting the KEEP.
	//
	// The adopt path is the common daemon-restart case: the bond outlived
	// in-memory tracking and must NOT be flapped (LinkDel→LinkAdd→re-enslave
	// →LACP re-converge). Tracking the FULL desired sig unconditionally,
	// however, is wrong when the bond was realized with a PARTIAL member set
	// (a member absent at realization time is a #4823 soft error — routine
	// during interface enumeration ordering). If a restart then adopts that
	// partial bond and records the full desired sig, every future reconcile
	// sees tracked == desired and KEEPs the partial bond forever, never
	// completing the missing enslavement (#5261).
	//
	// So compare the observed kernel member set to the desired set:
	//   - COMPLETE (observed covers desired) → track the full desired sig and
	//     only bring the bond up. Zero enslave/LinkDel/LinkAdd — no flap of a
	//     good bond (#5259 preserved exactly).
	//   - PARTIAL → attempt to enslave the still-missing members now (the
	//     member may have appeared since the bond was first realized — e.g. a
	//     restart that resolved the enumeration race); members still absent
	//     stay a #4823 soft error. Then track a sig derived from the ACTUAL
	//     realized member set. If completion filled the set the tracked sig
	//     equals the desired sig; otherwise it is a PARTIAL sig != desired, so
	//     the NEXT reconcile re-enters this branch (Apply routes a pure
	//     partial through the KEEP path, never the delete pass) and completes
	//     the missing enslavement IN PLACE once the member appears, instead of
	//     KEEP-ing a partial bond forever.
	// No LinkDel/LinkAdd is issued on the adopt path — the same code path
	// serves both a restart adoption and an in-place partial completion.
	//
	// #6402: the adopt path must FIRST re-assert the found link is actually a
	// bond before adopting it. LinkByName resolves the NAME, not the type: a
	// same-name FOREIGN link (an external actor's device, or a leftover of a
	// different type after a name collision) would otherwise be brought up and
	// tracked as a satisfied bond while NO bond device carries the fabric/RETH
	// members — the LAG silently does not exist yet the reconcile reports
	// success. This is the last member of the post-create/adopt readback
	// identity-assertion family: the #6396 create readback re-asserts
	// *netlink.Bond, xfrm/VRF gate both create and adopt, and this closes the
	// bond adopt gap. Reclaim the name via delete+recreate (mirroring the xfrm
	// #5523 adopt gate and the vrfTable→recreate adopt path) rather than
	// adopting the foreign link. If the delete fails the kernel link is still
	// present, so a LinkAdd below would EEXIST — surface the delete failure so
	// the commit fails closed and the next reconcile retries the delete first,
	// exactly like the #5119 changed-signature and xfrm #5310 recreate paths.
	if existing, err := b.ops.LinkByName(name); err == nil {
		if _, isBond := existing.(*netlink.Bond); isBond {
			var errs []error
			trackSig := sig
			observed, ok := b.observedMembers(existing)
			if ok && !membersCoverDesired(ifc, observed) {
				enslaved, memberErrs := b.enslaveMembers(name, existing, ifc.FabricMembers, observed)
				errs = append(errs, memberErrs...)
				for _, m := range enslaved {
					observed[m] = true
				}
				trackSig = sigWithMembers(sig, observed)
			}
			b.bonds[name] = trackSig
			slog.Debug("bond already exists", "name", name, "complete", trackSig == sig)
			// #9872: same MTU handoff as the KEEP path — an adopted bond
			// outlived tracking, so its live MTU is whatever the last writer
			// (possibly a since-removed unit override) left behind.
			if err := b.reconcileBondMTU(name, existing, sig); err != nil {
				errs = append(errs, err)
			}
			if err := b.ops.LinkSetUp(existing); err != nil {
				slog.Warn("failed to bring up existing bond", "name", name, "err", err)
				errs = append(errs, fmt.Errorf("bond %s: bring up existing: %w", name, err))
			}
			return errors.Join(errs...)
		}
		// A same-name FOREIGN (non-bond) link wears the bond's name. Do NOT
		// adopt it: reclaim the name via delete+recreate and fall through to
		// the create path below. On a delete failure the kernel link is still
		// present, so a LinkAdd below would EEXIST — return the delete error so
		// the commit fails closed and the next reconcile retries the delete.
		slog.Info("link with bond name is not a bond interface, recreating",
			"name", name, "type", existing.Type())
		if err := b.deleteLocked(name); err != nil {
			return err
		}
	}

	bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: name})
	if sig.mode == "active-backup" {
		bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
	} else {
		bond.Mode = netlink.BOND_MODE_802_3AD
	}
	if ifc.MTU > 0 {
		bond.LinkAttrs.MTU = ifc.MTU
	}
	if err := b.ops.LinkAdd(bond); err != nil {
		slog.Warn("failed to create bond", "name", name, "err", err)
		return fmt.Errorf("bond %s: create: %w", name, err)
	}

	// Enslave member interfaces.
	bondLink, err := b.ops.LinkByName(name)
	if err != nil {
		slog.Warn("failed to find created bond", "name", name, "err", err)
		return fmt.Errorf("bond %s: find after create: %w", name, err)
	}

	// #6396: re-assert the post-create readback is the bond we just created
	// before enslaving members and bringing it up. A same-name foreign link
	// substituted in the add→readback window is only caught by enslaveMembers
	// (via a real-netlink LinkSetMaster failure) when at least one member is
	// actually enslavable; a bond whose configured members are all currently
	// absent (the #4823 soft-error enumeration case) enslaves nothing, so no
	// LinkSetMaster fires and the foreign link would be brought up and tracked
	// as a satisfied bond. The explicit type re-assertion closes that hole for
	// every member state. Fail the commit closed on the mismatch; the bond is
	// left untracked so the next reconcile retries.
	if _, ok := bondLink.(*netlink.Bond); !ok {
		slog.Warn("bond readback after create is not a bond interface",
			"name", name, "type", bondLink.Type())
		return fmt.Errorf("bond %s: readback after create is %s, not a bond",
			name, bondLink.Type())
	}

	enslaved, errs := b.enslaveMembers(name, bondLink, ifc.FabricMembers, nil)
	if err := b.ops.LinkSetUp(bondLink); err != nil {
		slog.Warn("failed to bring up bond", "name", name, "err", err)
		errs = append(errs, fmt.Errorf("bond %s: bring up: %w", name, err))
	}
	// Track the ACTUAL realized member set, not the full desired set. A member
	// absent at creation (a #4823 soft error) yields a PARTIAL sig, so a later
	// reconcile completes the enslavement IN PLACE when the member appears
	// (the Apply partial-completion path) instead of KEEP-ing the bond partial
	// forever (#5261). Fully enslaved → realized == desired → this equals sig.
	realized := make(map[string]bool, len(enslaved))
	for _, m := range enslaved {
		realized[m] = true
	}
	b.bonds[name] = sigWithMembers(sig, realized)
	slog.Info("bond created", "name", name, "mode", sig.mode, "members", ifc.FabricMembers)
	return errors.Join(errs...)
}

// reconcileBondMTU converges a KEPT or ADOPTED bond's live MTU to the
// interface-level MTU in sig (#9872). The bond signature carries no units,
// and the dataplane plans no MTU for a bond-mode fabric ref, so without this
// a unit-MTU override written while an untagged unit existed would stick
// forever once the unit is removed: same sig → KEEP, and nothing else writes
// the bond's MTU. Compare-then-write, so a converged bond sees zero netlink
// churn on unrelated commits (#5119); a zero sig MTU means kernel default,
// unmanaged here exactly as on the create path. A set failure is a hard
// #4823 error (like LinkSetUp on these paths): the bond stays tracked, so
// the next reconcile retries. Caller must hold mu.
func (b *bondManager) reconcileBondMTU(name string, link netlink.Link, sig bondSig) error {
	if sig.mtu <= 0 {
		return nil
	}
	if cur := link.Attrs().MTU; cur == sig.mtu {
		return nil
	}
	if err := b.ops.LinkSetMTU(link, sig.mtu); err != nil {
		slog.Warn("failed to converge bond MTU", "name", name, "mtu", sig.mtu, "err", err)
		return fmt.Errorf("bond %s: set MTU %d: %w", name, sig.mtu, err)
	}
	return nil
}

// enslaveMembers enslaves the given fabric members (Junos names) into
// bondLink, skipping any whose resolved Linux name is already present in
// `already` (an already-enslaved member must NOT be flapped). It returns the
// Linux names it SUCCESSFULLY enslaved and the accumulated hard errors.
//
// A member not yet visible in the kernel (LinkByName miss) is a #4823 soft
// error: logged and skipped, the bond is still realized with the members
// that ARE present, and the caller tracks a partial sig so a later reconcile
// completes it. A LinkSetMaster failure on a member that IS present is a hard
// error, accumulated and returned. Caller must hold mu.
func (b *bondManager) enslaveMembers(name string, bondLink netlink.Link, members []string, already map[string]bool) ([]string, []error) {
	var (
		enslaved []string
		errs     []error
	)
	for _, member := range members {
		linuxName := config.LinuxIfName(member)
		if already[linuxName] {
			continue // already enslaved — leave it in place, do not flap
		}
		memberLink, err := b.ops.LinkByName(linuxName)
		if err != nil {
			slog.Warn("bond member not found",
				"bond", name, "member", member, "linux", linuxName, "err", err)
			continue
		}
		// Member must be down before enslaving.
		b.ops.LinkSetDown(memberLink)
		if err := b.ops.LinkSetMaster(memberLink, bondLink); err != nil {
			slog.Warn("failed to enslave member",
				"bond", name, "member", member, "err", err)
			errs = append(errs, fmt.Errorf("bond %s: enslave member %s: %w", name, member, err))
			continue
		}
		b.ops.LinkSetUp(memberLink)
		enslaved = append(enslaved, linuxName)
		slog.Info("bond member added", "bond", name, "member", member)
	}
	return enslaved, errs
}

// observedMembers returns the set of Linux interface names currently
// enslaved to bondLink (their MasterIndex equals the bond's index). The
// second return is false when the member set cannot be determined — a
// LinkList failure, or a bond whose index is 0 (a real kernel bond never has
// index 0; the fallback keeps the adopt path bit-identical to the prior
// track-full-desired behavior rather than misclassifying the bond as
// partial). Caller must hold mu.
func (b *bondManager) observedMembers(bondLink netlink.Link) (map[string]bool, bool) {
	idx := bondLink.Attrs().Index
	if idx == 0 {
		return nil, false
	}
	links, err := b.ops.LinkList()
	if err != nil {
		slog.Warn("bond adopt: LinkList failed; cannot verify member set", "err", err)
		return nil, false
	}
	members := map[string]bool{}
	for _, l := range links {
		if l.Attrs().MasterIndex == idx {
			members[l.Attrs().Name] = true
		}
	}
	return members, true
}

// membersCoverDesired reports whether every desired fabric member (resolved
// to its Linux name) is present in the observed enslaved-member set.
func membersCoverDesired(ifc *config.InterfaceConfig, observed map[string]bool) bool {
	for _, m := range ifc.FabricMembers {
		if !observed[config.LinuxIfName(m)] {
			return false
		}
	}
	return true
}

// isPartialCompletion reports whether a tracked bond differs from its desired
// signature ONLY by missing members — same mode and MTU, and the tracked
// (realized) member set is a strict subset of the desired set. Such a bond is
// completed IN PLACE (the missing members are enslaved via createLocked's
// adopt branch) rather than delete+recreated, so a live (degraded) fabric/RETH
// bond is never flapped on an unrelated commit (#5261). A member removal, a
// mode change, or an MTU change is NOT a partial completion — it changes the
// bond identity and takes the delete+recreate path.
func isPartialCompletion(tracked, want bondSig) bool {
	if tracked.mode != want.mode || tracked.mtu != want.mtu {
		return false
	}
	if tracked.members == want.members {
		return false
	}
	return membersSubset(tracked.members, want.members)
}

// membersSubset reports whether every member in sub is present in super (both
// are sorted, comma-joined member strings). An empty sub is a subset of
// anything (a bond realized with zero members yet is a partial of any desired
// member set).
func membersSubset(sub, super string) bool {
	if sub == "" {
		return true
	}
	set := make(map[string]bool)
	for _, m := range strings.Split(super, ",") {
		set[m] = true
	}
	for _, m := range strings.Split(sub, ",") {
		if !set[m] {
			return false
		}
	}
	return true
}

// sigWithMembers returns a copy of base whose member set is the sorted,
// comma-joined names in realized. When realized equals the desired member
// set the result equals base, so a completed adopt tracks the full desired
// sig; a still-partial adopt tracks a sig that differs from desired and thus
// triggers a follow-up reconcile (#5261).
func sigWithMembers(base bondSig, realized map[string]bool) bondSig {
	names := make([]string, 0, len(realized))
	for n := range realized {
		names = append(names, n)
	}
	sort.Strings(names)
	base.members = strings.Join(names, ",")
	return base
}

// Clear removes all previously created bond devices.
func (b *bondManager) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clearLocked()
}

// clearLocked deletes every tracked bond. Caller must hold mu. Used by
// Clear (shutdown / full teardown). Apply no longer calls this — it
// reconciles differentially instead (#5119).
func (b *bondManager) clearLocked() error {
	var errs []error
	for name := range b.bonds {
		if err := b.deleteLocked(name); err != nil {
			errs = append(errs, err)
		}
	}
	// #4901: deleteLocked drops each successfully-removed name and RETAINS
	// the ones whose LinkDel failed so the next reconcile retries — do NOT
	// blanket-nil the map here, which would forget an orphaned bond and lose
	// ownership while reporting a clean teardown. Only clear once every
	// device is actually gone.
	if len(b.bonds) == 0 {
		b.bonds = nil
	}
	return errors.Join(errs...)
}

// deleteLocked removes a single tracked bond by name and drops it from
// tracking. Caller must hold mu. A link already gone from the kernel is
// treated as success (the entry is still untracked). It returns a non-nil
// error when the netlink LinkDel fails, in which case the name is RETAINED
// in tracking (#4901) so the next reconcile retries instead of orphaning
// the bond (and its enslaved members).
func (b *bondManager) deleteLocked(name string) error {
	link, err := b.ops.LinkByName(name)
	if err != nil {
		// #7529: only a POSITIVE not-found answer releases ownership. This
		// treated EVERY LinkByName failure as "already gone" — it dropped the
		// name from tracking AND returned nil, so a transient netlink error
		// (a busy or truncated socket, ENOBUFS under load, EINTR) made xpf
		// report a successful delete for a bond that is still in the kernel,
		// still enslaving its members, and no longer tracked. Nothing retries
		// it, because the reconcile diff keys off b.bonds.
		//
		// That is the exact failure #4901 fixed for the LinkDel leg below, one
		// call earlier: a failed delete retains the name so the next reconcile
		// retries. The lookup leg kept the old behaviour and undid it, since a
		// lookup that fails transiently discards the entry before LinkDel is
		// ever reached.
		//
		// isLinkNotFound (vrf.go) is the same predicate the sibling VRF and
		// XFRM paths already use — the fix shape was in-tree.
		if isLinkNotFound(err) {
			delete(b.bonds, name)
			return nil // genuinely gone
		}
		slog.Warn("bond delete: link lookup failed, retaining ownership for retry",
			"name", name, "err", err)
		return fmt.Errorf("lookup bond %s: %w", name, err)
	}
	if err := b.ops.LinkDel(link); err != nil {
		slog.Warn("failed to delete bond", "name", name, "err", err)
		return fmt.Errorf("delete bond %s: %w", name, err)
	}
	slog.Info("bond removed", "name", name)
	delete(b.bonds, name)
	return nil
}
