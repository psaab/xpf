// Package daemon — #1956 bare-metal device-map resolver and mapped-rename.
//
// This file owns device-map MODE: when the active config carries a non-empty
// `chassis device-map`, the daemon renames ONLY the mapped NICs (by stable
// identity — PCI bus address with permanent-MAC fallback) instead of the
// positional enumerate-and-rename path, and leaves every other NIC alone
// (unmapped-interface-policy leave-alone, the bare-metal default).
//
// None of this is hot-path: it runs at daemon start and on bootstrap-exit.
package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
	"github.com/vishvananda/netlink"
)

// renameInterfaceFn / networkctlReloadFn are injectable seams for the
// device-map rename orchestration so the rename/reload error-propagation path
// (#4956) is unit-testable without a live netlink stack. Production leaves them
// pointing at the real link-rename + networkctl-reload helpers.
var (
	renameInterfaceFn  = renameInterface
	networkctlReloadFn = networkctlReload
	// teardownRestoreTargetFn resolves the rename-back target for the
	// managed->unmapped teardown (#5309): given an xpf logical name, it reports
	// whether a LIVE device currently wears that name and, if so, the
	// host-predictable name to restore it to. Injectable so the fail-closed
	// retain-on-failure path is unit-testable without a live netlink/sysfs
	// stack (the existing teardown tests never reach the netlink block because
	// every on-disk name is still desired or protected).
	teardownRestoreTargetFn = teardownRestoreTarget
)

// The pure identity resolver, present-NIC model, and host enumeration live in
// pkg/devicemap so the daemon (rename + pre-flight) and the CLI
// (`show chassis device-map`) share ONE resolution discipline. The daemon
// keeps only the rename / teardown / pre-flight glue below.

// presentNIC is the daemon-local alias for the shared inventory type.
type presentNIC = devicemap.PresentNIC

var (
	enumerateAndRenameMappedFn     = enumerateAndRenameMapped
	enumerateAndRenameInterfacesFn = enumerateAndRenameInterfaces
	// enumeratePresentNICsFn is the seam every strand-management preflight
	// reads the live NIC inventory through (#4183), so the commit / day-0
	// bootstrap / check-config strand checks are unit-testable without a
	// live VM. Production leaves it pointing at the real sysfs+netlink scan.
	enumeratePresentNICsFn = enumeratePresentNICs
)

// enumeratePresentNICs reads the live host NIC inventory (sysfs + netlink).
func enumeratePresentNICs() ([]presentNIC, error) {
	return devicemap.EnumeratePresentNICs()
}

// resolveDeviceMap resolves entries against present NICs (see devicemap.Resolve).
func resolveDeviceMap(entries []config.DeviceMapEntry, nics []presentNIC, rethMembers map[string]bool) []devicemap.Binding {
	return devicemap.Resolve(entries, nics, rethMembers)
}

// rethMembersFromConfig returns the RETH-member logical-name set.
func rethMembersFromConfig(cfg *config.Config) map[string]bool {
	return devicemap.RethMembersFromConfig(cfg)
}

// deviceMapNamingActive is the single predicate every startup naming site uses
// to choose the device-map branch over the positional enumerate-and-rename.
// It returns true only for a non-nil config carrying a non-empty
// `chassis device-map` (DeviceMapConfig.Active). Extracted as a named seam so
// the startup decision is unit-testable WITHOUT a live VM (#1956): the original
// tests exercised enumerateAndRenameMapped in isolation, so the branch
// selection itself — the thing that actually drives boot behavior — was never
// covered. A regression that drops or inverts this branch is now caught by
// TestDeviceMapNamingActiveStartupDecision.
//
// The caller at the normal-boot site sources cfg from d.store.ActiveConfig(),
// which Store.Load (DB boot) and Store.Commit (bootstrap-from-file boot) both
// populate SYNCHRONOUSLY before the naming decision runs — so a committed or
// preseeded device-map is visible here on every boot path. The bootstrap-exit
// site passes the freshly-committed config parameter. Neither is a deferred /
// not-yet-promoted read.
func deviceMapNamingActive(cfg *config.Config) bool {
	return cfg != nil && cfg.Chassis.DeviceMap.Active()
}

// applyStartupNamingPolicy owns the ACTUAL startup naming branch used by both
// normal boot and bootstrap exit. Centralizing it here keeps the decision
// single-source and lets the regression test pin the real mapped-vs-positional
// call instead of only the pure predicate. Nil / inactive config falls back to
// positional naming to preserve the pre-#1956 default.
func applyStartupNamingPolicy(cfg *config.Config, nodeID int, clusterMode bool,
	userspaceWorkers int, rssEnabled bool, rssAllowed []string,
	protected map[string]bool) error {
	if deviceMapNamingActive(cfg) {
		return enumerateAndRenameMappedFn(cfg.Chassis.DeviceMap, cfg, protected)
	}
	// #7205: positional naming has no strand refusal, and that is CORRECT --
	// it claims every present NIC by design, so "the lifeline moved" is the
	// normal case rather than an error. Device-map mode refuses a boot rename
	// that would strand management (deviceMapStrandsManagement) precisely
	// because it does NOT claim every NIC, so a stranded lifeline there means
	// an unmapped NIC nobody will name.
	//
	// What was wrong was accepting the parameter and dropping it in silence: a
	// reader of this function could not tell a deliberate non-use from an
	// oversight, and an operator who had configured a lifeline expectation had
	// no way to learn it does not apply on this branch. Say so, once, and only
	// when the combination is actually surprising (a non-empty protected set
	// reaching the branch that will not honour it).
	notePositionalIgnoresProtected(protected)
	return enumerateAndRenameInterfacesFn(nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed)
}

// notePositionalIgnoresProtected records that a management/lifeline protected
// set reached the positional branch, which does not refuse renames (#7205).
//
// Deliberately an INFO and not a WARN: this is the designed behaviour of
// positional mode, not a fault. It is emitted only for a NON-EMPTY set, so a
// normal boot stays silent and the line appears exactly when an operator might
// otherwise assume the protection applied.
func notePositionalIgnoresProtected(protected map[string]bool) {
	if len(protected) == 0 {
		return
	}
	names := make([]string, 0, len(protected))
	for n := range protected {
		names = append(names, n)
	}
	sort.Strings(names)
	slog.Info("linksetup: positional naming claims every present NIC, so the "+
		"management/lifeline protected set is NOT a rename refusal on this branch "+
		"(it is one only in device-map mode, where unmapped NICs exist)",
		"protected", strings.Join(names, ","))
}

// deviceMapOriginalNameFor computes the OriginalName= to record in a mapped
// NIC's .link, given the NIC's CURRENT kernel name and its FINAL logical name.
//   - If an existing .link already records the original (recoverOriginalName
//     returns something other than the current name), use that.
//   - Else, when the NIC already wears its FINAL logical name (current ==
//     logical) and no .link exists (a second+ boot whose .link was lost),
//     derive the true pre-rename kernel name from sysfs — the logical name is
//     not something udev will ever present (Copilot SWE fallback).
//   - Else (current != logical and no .link), the current name IS the real
//     pre-rename kernel name (e.g. ens3 on a fresh first map). Keep it; do NOT
//     synthesize an enpXsY name, which would not match udev on next boot
//     (AGY r3 MAJOR).
//
// The bool reports whether a udev-matchable name was found. It is FALSE only
// in the recovery branch when the derivation comes back empty (#6678): there
// the NIC already wears its logical name, and the logical name is precisely
// what udev will never present. Returning it — as this did — writes a .link
// whose OriginalName= cannot match, so boot-time persistence fails SILENTLY:
// the file exists, the name looks plausible, and nothing matches. Every other
// consumer of an empty derivation treats it as a clean skip
// (ensureRethLinkOriginalName returns without rewriting), and this was the one
// place that converted "I could not derive a name" into "here is a name".
//
// The caller must not write a .link for a NIC this reports false for. Leaving
// the NIC under its kernel name is a state the rest of the daemon understands;
// a .link that silently never matches is not.
func deviceMapOriginalNameFor(currentNIC, logical string) (string, bool) {
	orig := recoverOriginalName(currentNIC)
	if orig != currentNIC {
		return orig, true // an existing .link chain recorded the true original
	}
	if currentNIC == logical {
		dk := deriveKernelNameFn(currentNIC)
		if dk == "" {
			return "", false
		}
		return dk, true
	}
	return currentNIC, true
}

// deviceMapOriginalUnknown marks, inside originalByCurrent, a bound NIC whose
// true pre-rename kernel name could not be derived (#6678).
//
// It is carried as a VALUE rather than in a separate set because
// breakNameCollisions re-keys originalByCurrent across the temp rename and
// only rewrites KEYS — a sentinel value survives that untouched, so this needs
// no signature change to a helper the positional rename path shares. The NUL
// prefix makes it unrepresentable as an interface name, so it can never be
// confused with one or silently written into a .link.
const deviceMapOriginalUnknown = "\x00xpf-original-unknown"

// enumerateAndRenameMapped is the device-map-mode replacement for
// enumerateAndRenameInterfaces. It renames ONLY mapped NICs to their bound
// logical names, writes .link files for ONLY those, scrubs stale xpf .link
// files for names no longer mapped, and (under leave-alone, the default)
// leaves every unmapped NIC entirely alone. It implements the collision-safe
// multi-pass rename (V-2) so a stale-udev misrename does not deadlock on
// EEXIST, and renames any temp-stranded unmapped NIC back to a host-
// predictable name in the SAME pass (OQ-15.3).
//
// It does NOT run the D3 RSS indirection (that is driven from the caller, as
// in the positional path) — the caller invokes applyStep0Tunables after.
//
// protected is the #1922 protected set (management lifeline / fxp0 / mgmt
// leaf). Protected names are treated as implicitly desired: their .link is
// NOT scrubbed (so the management NIC keeps its managed name across reboots
// even when the operator left it out of the device-map — AGY r2 CRITICAL).
//
// #4956: a rename (phase 2), stranded-restore (phase 3), or `networkctl
// reload` (phase 4) failure used to only slog.Warn and then `return nil`
// unconditionally — laundering the failure to success. The caller chain
// (applyStartupNamingForConfig → maybeReapplyConfigArrivalNaming) consumes the
// one-shot #4182 retry marker (emptyHANamingPending) on a nil return, so a
// mapped NIC that never got its logical name was reported as converged and the
// single retry was burned, wiring the config onto nonexistent/wrong interface
// names. Every phase now still runs best-effort (so partial progress + full
// logging happen), but the accumulated error is RETURNED so the retry marker
// is preserved and the boot/bootstrap sites surface it loudly.
func enumerateAndRenameMapped(dm *config.DeviceMapConfig, cfg *config.Config, protected map[string]bool) error {
	if !dm.Active() {
		return nil
	}
	nics, err := enumeratePresentNICsFn()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	// #5490 boot-time re-check: re-run the strand-management detector against
	// the now-readable hardware BEFORE performing ANY mapped rename. This closes
	// the "already-committed candidate strands at next boot" gap — a candidate
	// accepted at commit time (committed before this fix, or accepted under the
	// old fail-open commit path when commit-time enumeration transiently failed)
	// would otherwise perform its now-readable UNSAFE binding here without any
	// re-validation, causing a durable management lockout that the #1922 lifeline
	// does not veto (it does not block an explicit mapped rename in phase 2).
	// If the map would strand management, FAIL CLOSED: retain the current
	// interface naming (management stays reachable under its present name) and
	// return an error so the one-shot retry marker is preserved and boot/config-
	// arrival sites surface it loudly. The rename never runs, so no .link is
	// written and no NIC is moved. The check is skipped only when there is no
	// protected set to strand (len==0 — non-production; every real boot passes a
	// non-empty set from resolveProtectedInterfaces), which keeps the strand
	// detector's "empty protected == nothing to protect" contract intact.
	if len(protected) > 0 {
		lifelineName, _ := resolveLifelineCurrentName()
		if reason := deviceMapStrandsManagement(cfg, nics, protected, lifelineName); reason != "" {
			slog.Error("device-map: REFUSING to apply mapped interface renames at boot — the active "+
				"device-map would strand management on next boot. Retaining the current interface "+
				"naming so management stays reachable; fix the device-map and re-commit.",
				"reason", reason)
			return fmt.Errorf("device-map boot rename refused (fail-closed, #5490): %s", reason)
		}
	}
	// renameErrs accumulates every phase-2/3 rename and phase-4 reload failure
	// so the function fails (not launders) while still completing every phase.
	var renameErrs []error
	rethMembers := rethMembersFromConfig(cfg)
	bindings := resolveDeviceMap(dm.Entries, nics, rethMembers)

	// Desired final name -> the NIC currently holding the identity.
	desiredByCurrent := make(map[string]string) // currentName -> finalName
	desiredNames := make(map[string]bool)       // set of final logical names
	// originalByCurrent records the TRUE pre-rename kernel name for each
	// bound NIC, captured BEFORE any temp rename, so the .link OriginalName=
	// is the real udev-matchable name (a transient xpf-tmp-* name must never
	// be recorded as OriginalName — it would not match on next boot).
	originalByCurrent := make(map[string]string) // currentName -> OriginalName
	for _, b := range bindings {
		switch {
		case b.Status.Bound():
			desiredByCurrent[b.CurrentNIC] = b.Logical
			if orig, ok := deviceMapOriginalNameFor(b.CurrentNIC, b.Logical); ok {
				originalByCurrent[b.CurrentNIC] = orig
			} else {
				originalByCurrent[b.CurrentNIC] = deviceMapOriginalUnknown
			}
			desiredNames[b.Logical] = true
			slog.Info("device-map: resolved binding",
				"logical", b.Entry.LogicalName, "current", b.CurrentNIC, "status", b.Status.String())
		case b.Status == devicemap.BindUnbound:
			slog.Warn("device-map: entry UNBOUND — no present NIC matches its identity; "+
				"logical name left unassigned",
				"logical", b.Entry.LogicalName, "pci", b.Entry.PCIAddr, "mac", b.Entry.MAC)
		case b.Status == devicemap.BindRefusedAmbig:
			slog.Error("device-map: entry REFUSED — a different card is present at this identity "+
				"(topology changed). Refusing to bind to avoid hijacking the wrong NIC; re-pin "+
				"the device-map.",
				"logical", b.Entry.LogicalName, "pci", b.Entry.PCIAddr, "mac", b.Entry.MAC)
		case b.Status == devicemap.BindRefusedIdentityUnknown:
			// #6786: distinct from the topology-change refusal above — the card
			// may be entirely correct; its identity just could not be read, so
			// the pinned MAC could not be verified against it.
			slog.Error("device-map: entry REFUSED — the NIC at this identity could not be read, so "+
				"its permanent MAC is UNKNOWN and the pinned MAC cannot be verified. Refusing to "+
				"bind an unverified NIC into a pinned logical name; retry once the interface is "+
				"readable.",
				"logical", b.Entry.LogicalName, "pci", b.Entry.PCIAddr, "mac", b.Entry.MAC)
		case b.Status == devicemap.BindRefusedDupName:
			// #6546: more than one entry claims this logical name. Binding
			// either one would rename a nondeterministically-chosen NIC to it
			// and persist that choice in a .link file, so BOTH are refused.
			slog.Error("device-map: entry REFUSED — more than one device-map entry claims this "+
				"logical name, so binding either would rename an arbitrary NIC to it. Refusing "+
				"both; remove the duplicate entry.",
				"logical", b.Entry.LogicalName, "pci", b.Entry.PCIAddr, "mac", b.Entry.MAC)
		}
	}

	// Phase 1: break name collisions via the shared collision-safe primitive
	// (#4178 — the SAME discipline the positional path now uses). Any present
	// NIC whose CURRENT name equals a desired final name, but which is NOT the
	// NIC we want there (a stale-udev misrename, or the intended NIC is
	// elsewhere), is moved to a unique xpf-tmp-N first (V-2). breakNameCollisions
	// seeds its temp-name allocator from every present NIC name, so a leftover
	// xpf-tmp-N from a prior crashed run does not cause an EEXIST temp rename
	// (AGY MEDIUM-3), and re-keys desiredByCurrent/originalByCurrent across the
	// temp rename so phase 2 writes the correct OriginalName= (not xpf-tmp-N).
	nicByName := make(map[string]presentNIC, len(nics))
	currentNames := make([]string, len(nics))
	for i := range nics {
		nicByName[nics[i].Name] = nics[i]
		currentNames[i] = nics[i].Name
	}
	strandedTmp, unfreed, changed := breakNameCollisions("device-map", currentNames, desiredNames,
		desiredByCurrent, originalByCurrent, renameInterfaceFn)
	// A temp-stranded UNMAPPED NIC (not a desired source) is carried into phase
	// 3 keyed by its temp name; the presentNIC keeps its ORIGINAL (pre-temp)
	// name for the predictable-name lookup, matching the pre-#4178 behavior.
	tempStranded := make(map[string]presentNIC, len(strandedTmp))
	for tmp, origName := range strandedTmp {
		tempStranded[tmp] = nicByName[origName]
	}

	// Phase 2: rename each mapped NIC to its final logical name.
	for current, final := range desiredByCurrent {
		// #7205: phase 1 could not free this final name, so every rename onto
		// it below would EEXIST. Report the real cause once, here, rather than
		// letting each attempt surface a misleading EEXIST.
		if current != final && unfreed[final] {
			slog.Warn("device-map: skipping rename onto a name the collision "+
				"break could not free", "from", current, "to", final)
			renameErrs = append(renameErrs, unfreedNameErr("device-map", current, final))
			continue
		}
		// The OriginalName= is the TRUE pre-rename kernel name captured
		// before any temp rename; fall back to recovering it if absent.
		original := originalByCurrent[current]
		if original == "" {
			original = recoverOriginalName(current)
		}
		if original == deviceMapOriginalUnknown {
			// #6678: no udev-matchable pre-rename name exists for this NIC.
			// Writing a .link anyway would record an OriginalName= udev never
			// presents, so the file would silently never match and this NIC
			// would come up unnamed on the next boot with nothing to point at.
			// Decline to write it and report on the SAME channel as a .link
			// that failed to land (#5842) — the next-boot consequence is
			// identical, and it must be loud now rather than discovered on a
			// machine nobody is watching.
			slog.Error("device-map: cannot determine the pre-rename kernel name for a "+
				"bound NIC; refusing to write a .link whose OriginalName= could never "+
				"match. This NIC will come up under its kernel name on the next boot.",
				"current", current, "logical", final)
			renameErrs = append(renameErrs,
				fmt.Errorf("device-map: no udev-matchable OriginalName for %s (logical %s); "+
					"boot-time persistence not established", current, final))
			if current == final {
				continue
			}
			if err := renameInterfaceFn(current, final); err != nil {
				slog.Warn("device-map: rename failed", "from", current, "to", final, "err", err)
				renameErrs = append(renameErrs,
					fmt.Errorf("rename %s -> %s: %w", current, final, err))
			} else {
				slog.Info("device-map: renamed interface (no .link written)",
					"from", current, "to", final)
				changed = true
			}
			continue
		}
		if current == final {
			// Ensure a .link exists for boot persistence even when the name
			// already matches (idempotent — writeDeviceMapLinkFile skips
			// unchanged files).
			wroteLink, werr := writeDeviceMapLinkFile(final, original, rethMembers, dm.Entries)
			if werr != nil {
				// #5842: a .link that did not land means this NIC comes up
				// under its kernel name on the NEXT boot, unzoned — the same
				// unconverged state a failed rename leaves, so it joins the
				// same error channel.
				renameErrs = append(renameErrs, werr)
			}
			if wroteLink {
				changed = true
			}
			continue
		}
		// Write the .link FIRST so next boot's udev is correct, then rename.
		wroteLink, werr := writeDeviceMapLinkFile(final, original, rethMembers, dm.Entries)
		if werr != nil {
			renameErrs = append(renameErrs, werr)
		}
		if wroteLink {
			changed = true
		}
		if err := renameInterfaceFn(current, final); err != nil {
			slog.Warn("device-map: rename failed", "from", current, "to", final, "err", err)
			renameErrs = append(renameErrs,
				fmt.Errorf("rename %s -> %s: %w", current, final, err))
		} else {
			slog.Info("device-map: renamed interface", "from", current, "to", final)
			changed = true
		}
	}

	// Phase 3: any temp-stranded UNMAPPED NIC is renamed back to a
	// host-predictable name (OQ-15.3) so it is never left as xpf-tmp-* and
	// never re-matched as "managed".
	for tmp, nic := range tempStranded {
		predictable := predictableName(nic)
		if predictable == "" || predictable == tmp {
			slog.Warn("device-map: could not determine a predictable name for a stranded NIC; "+
				"leaving it under its temp name (xpf does not manage it)",
				"temp", tmp, "pci", nic.PCIAddr)
			continue
		}
		if err := renameInterfaceFn(tmp, predictable); err != nil {
			slog.Warn("device-map: restore stranded NIC to predictable name failed",
				"from", tmp, "to", predictable, "err", err)
			renameErrs = append(renameErrs,
				fmt.Errorf("restore stranded %s -> %s: %w", tmp, predictable, err))
		} else {
			slog.Info("device-map: restored unmapped NIC to predictable name",
				"from", tmp, "to", predictable)
			changed = true
		}
	}

	// Phase 4: scrub stale xpf .link files whose target name is no longer a
	// desired binding (a NIC dropped from the map). This keeps next boot's
	// udev rule set exactly equal to the resolved bindings (R-2). Protected
	// names (the management lifeline) are kept as implicitly-desired so the
	// mgmt NIC retains its managed name across reboots even if it is not in
	// the device-map (AGY r2 CRITICAL).
	keepLinks := make(map[string]bool, len(desiredNames)+len(protected))
	for n := range desiredNames {
		keepLinks[n] = true
	}
	for n := range protected {
		if n != "" {
			keepLinks[n] = true
		}
	}
	if scrubStaleDeviceMapLinks(keepLinks) {
		changed = true
	}

	// fxp0 bootstrap DHCP .network is NOT auto-created in device-map mode
	// (§9.6: console is the lifeline; no fabricated fxp0). It is written
	// only if the operator explicitly mapped a NIC to fxp0.
	if desiredNames["fxp0"] {
		wroteFxp0, err := writeBootstrapFxp0Network()
		if err != nil {
			// #5842: previously a bool, so a failed write was indistinguishable
			// from "already exists" and the device-map path launders it too.
			renameErrs = append(renameErrs, err)
		}
		if wroteFxp0 {
			changed = true
		}
	}

	if changed {
		if err := networkctlReloadFn(); err != nil {
			slog.Warn("device-map: networkctl reload failed", "err", err)
			renameErrs = append(renameErrs, fmt.Errorf("networkctl reload: %w", err))
		}
		slog.Info("device-map: interface naming updated")
	} else {
		slog.Info("device-map: interface naming unchanged")
	}
	// #4956: surface any phase-2/3 rename or phase-4 reload failure so the
	// caller's retry marker (emptyHANamingPending) is NOT consumed on an
	// unconverged rename and the reconcile does not proceed on mis-named NICs.
	if len(renameErrs) > 0 {
		return fmt.Errorf("device-map: %d interface rename/reload step(s) failed: %w",
			len(renameErrs), errors.Join(renameErrs...))
	}
	return nil
}

// writeDeviceMapLinkFile writes the .link for a mapped NIC. RETH members
// match by OriginalName= (their MAC alternates — R-6); the file content is
// identical to the positional path's writeLinkFile, so the two share a format.
// Returns (changed, err) — see writeLinkFile for why the two are separate
// (#5842).
func writeDeviceMapLinkFile(target, originalName string, rethMembers map[string]bool, entries []config.DeviceMapEntry) (bool, error) {
	// All device-map .link files match by OriginalName= (the current kernel
	// name at rename time). This is correct for RETH members (mandatory) and
	// is also stable for plain NICs because device-map mode resolves the
	// identity to the kernel name at rename time and rewrites the .link set
	// every boot (scrub-then-rewrite, R-2). Keeping one match discipline
	// avoids the MAC-vs-OriginalName drift the positional path carries.
	return writeLinkFile(target, originalName)
}

// deviceMapStrandsManagement reports whether applying cfg's device-map would,
// on next boot, leave the #1922 management/lifeline NIC unbound or rebound to
// a different port — i.e. strand the operator. Returns a non-empty reason when
// it would strand, "" when safe. A nil/empty device-map is always safe (the
// #1922 protected set is the independent backstop; positional mode unchanged).
//
// protected is the set of protected LOGICAL names (mgmt leaf / fxp0 +
// lifeline). lifelineCurrentName is the CURRENT kernel name of the lifeline
// NIC resolved by its persisted IDENTITY ("" if none) — load-bearing because
// on first boot the live mgmt NIC still carries its kernel name (enp5s0), not
// the protected target name (fxp0), so a name-only check would miss a steal
// (Codex HIGH-2). Pure given the inputs, so it is unit testable.
func deviceMapStrandsManagement(cfg *config.Config, nics []presentNIC, protected map[string]bool, lifelineCurrentName string) string {
	if cfg == nil {
		return ""
	}
	dm := cfg.Chassis.DeviceMap
	if !dm.Active() {
		return ""
	}
	bindings := resolveDeviceMap(dm.Entries, nics, rethMembersFromConfig(cfg))

	finalByCurrent := make(map[string]string)
	for _, b := range bindings {
		// A REFUSED binding on ANY entry is a hard stop: the operator's intent
		// cannot be realized, so refuse while they are still connected. The
		// two refusal reasons carry OPPOSITE remedies, so each gets its own
		// message — telling an operator who typed a duplicate name to "re-pin
		// the entry" sends them to a fix that changes nothing (#6546). Tested
		// through Status.Refused() rather than a single sentinel so a future
		// refusal reason cannot slip past this hard stop as a clean result.
		if b.Status == devicemap.BindRefusedDupName {
			return fmt.Sprintf("device-map entry %q refuses to bind: more than one entry claims "+
				"this logical name, so binding either would rename an arbitrary NIC to it. "+
				"Remove the duplicate entry before committing.", b.Entry.LogicalName)
		}
		// #6786: an UNREADABLE identity is not a topology change. Nothing is
		// known to be wrong with the card — the permanent MAC simply could not
		// be read, so the pinned MAC could not be verified. Telling this
		// operator to "re-pin the entry" sends them to a fix that changes
		// nothing (the same wrong-remedy trap #6546 named), and would have them
		// re-pin against a MAC they cannot currently read.
		if b.Status == devicemap.BindRefusedIdentityUnknown {
			return fmt.Sprintf("device-map entry %q refuses to bind: the NIC at its pinned identity "+
				"could not be read, so its permanent MAC is UNKNOWN and the pinned MAC cannot be "+
				"verified. Binding it would rename a NIC whose identity was never checked. Retry "+
				"once the interface is readable; do NOT re-pin against an unreadable MAC.",
				b.Entry.LogicalName)
		}
		if b.Status.Refused() {
			return fmt.Sprintf("device-map entry %q refuses to bind: a different card is present "+
				"at its pinned identity (topology changed). Re-pin the entry before committing.",
				b.Entry.LogicalName)
		}
		if b.CurrentNIC != "" {
			finalByCurrent[b.CurrentNIC] = b.Logical
		}
	}

	// The live management NIC's CURRENT kernel name(s). Prefer the
	// identity-resolved lifeline name (correct even before the rename); also
	// include any present NIC literally named like a protected target (the
	// already-renamed steady state).
	liveMgmt := map[string]bool{}
	if lifelineCurrentName != "" {
		liveMgmt[lifelineCurrentName] = true
	}
	present := make(map[string]bool, len(nics))
	for i := range nics {
		present[nics[i].Name] = true
		if protected[nics[i].Name] {
			liveMgmt[nics[i].Name] = true
		}
	}

	// Compute the NAME each present NIC will carry AFTER the map is applied:
	// its mapped logical name if mapped, else its current name (an unmapped
	// NIC keeps its name — protected ones are preserved by teardown/scrub).
	finalNameOf := func(current string) string {
		if f, ok := finalByCurrent[current]; ok {
			return f
		}
		return current
	}

	// Invariant 1 — management stays reachable: after apply, at least one
	// present NIC must carry a protected name. This is true if any NIC is
	// mapped to a protected name (incl. the live mgmt NIC mapped to itself —
	// Codex r2 HIGH-A) OR an unmapped live mgmt NIC keeps its protected name
	// (AGY r2). A deliberate port swap (old mgmt -> non-mgmt name, new NIC ->
	// fxp0) satisfies this via the new NIC (AGY r4). Only a map that leaves
	// ZERO present NICs with a protected name strands management.
	mgmtReachable := false
	for i := range nics {
		if protected[finalNameOf(nics[i].Name)] {
			mgmtReachable = true
			break
		}
	}
	if !mgmtReachable {
		// Identify a live mgmt NIC being moved off for a precise message.
		for lm := range liveMgmt {
			if f, ok := finalByCurrent[lm]; ok && !protected[f] {
				return fmt.Sprintf("device-map would rename the live management NIC %q to %q (a "+
					"non-management name) on next boot with no other NIC taking a management name "+
					"— management would be unreachable. Map a NIC to its management name before "+
					"committing.", lm, f)
			}
		}
		return "device-map would leave no interface carrying a management name on next boot — " +
			"management would be unreachable. Map a NIC to its management name before committing."
	}

	// Invariant 2 — no udev rename collision on a protected name: two present
	// NICs must not both end up carrying the same protected name on next boot.
	// This catches both a steal (a non-mgmt NIC grabbing a name the live mgmt
	// NIC keeps — Codex HIGH-2) and the unmapped-current-holder collision (AGY
	// r3 B.1). A deliberate swap is fine because the vacating NIC's final name
	// differs (AGY r4).
	for prot := range protected {
		if prot == "" {
			continue
		}
		holders := make([]string, 0, 2)
		for i := range nics {
			if finalNameOf(nics[i].Name) == prot {
				holders = append(holders, nics[i].Name)
			}
		}
		if len(holders) > 1 {
			return fmt.Sprintf("device-map would assign the management name %q to more than one "+
				"interface on next boot (%v) — a rename collision that can strand management. "+
				"Re-pin the device-map so exactly one NIC carries %q.", prot, holders, prot)
		}
	}
	return ""
}

// deviceMapCommitPreflight is the #1956 R-8/V-3 node-local commit pre-flight.
// It resolves the candidate's LOCAL device-map (and, for commit-confirmed,
// the rollback target) against present hardware and rejects a commit that
// would strand management on next boot — converting a latent reboot-time
// lockout into a commit-time error while the operator is still connected.
// rollbackTarget is the config that would be restored on a confirmed-commit
// timeout (the currently-active config); pass nil for a plain commit.
func (d *Daemon) deviceMapCommitPreflight(candidate, rollbackTarget *config.Config) error {
	// Fast path: neither config engages device-map mode — nothing to check.
	candActive := candidate != nil && candidate.Chassis.DeviceMap.Active()
	rbActive := rollbackTarget != nil && rollbackTarget.Chassis.DeviceMap.Active()
	if !candActive && !rbActive {
		return nil
	}
	nics, err := enumeratePresentNICsFn()
	if err != nil {
		// #5490 FAIL CLOSED. A transient sysfs/netlink enumeration error means
		// the strand-management safety check CANNOT run. The old behavior
		// (slog.Warn + return nil) laundered an unvalidated device-map to a
		// SUCCESSFUL commit: a candidate that moves the live management NIC to a
		// non-management name (without assigning another NIC a protected name)
		// was accepted here and then applied VERBATIM at next boot by
		// enumerateAndRenameMapped — a durable management lockout that even a
		// confirmed-commit rollback could not undo (its rollback target was
		// never validated either). The #1922 lifeline guards the LIVE mgmt NIC
		// but does NOT veto an explicit mapped rename in phase 2, so it is not a
		// substitute for this check. Reject the commit while the operator is
		// still connected rather than risk the lockout. Enumeration is a
		// cold-path scan (no forwarding cost), so failing closed here is cheap.
		return fmt.Errorf("device-map commit rejected: cannot read the present NIC inventory "+
			"to validate that the device-map will not strand management on next boot (%w); "+
			"refusing the commit rather than risk a durable management lockout — retry once the "+
			"hardware inventory is readable", err)
	}
	// The lifeline NIC's CURRENT kernel name, resolved by its persisted
	// IDENTITY — correct even before the rename (Codex HIGH-2).
	lifelineName, _ := resolveLifelineCurrentName()
	// AGY HIGH-2: resolve the protected set from EACH config's OWN
	// management-interface leaf (not the active config's), so a commit that
	// repoints `system management-interface` is validated against the
	// intent it is establishing — neither a silent lockout (using the stale
	// active leaf) nor a false rejection of a legitimate mgmt migration. The
	// lifeline record stays config-independent in both.
	if reason := deviceMapStrandsManagement(candidate, nics, protectedForConfig(candidate), lifelineName); reason != "" {
		return fmt.Errorf("device-map commit rejected: %s", reason)
	}
	// V-3(a): validate the rollback target too, so a confirmed-commit
	// timeout reverts to a KNOWN-safe config and can be applied
	// unconditionally (OQ-15.2 — no rollback-time abort, no split-brain).
	if rollbackTarget != nil {
		if reason := deviceMapStrandsManagement(rollbackTarget, nics, protectedForConfig(rollbackTarget), lifelineName); reason != "" {
			return fmt.Errorf("commit confirmed rejected: the rollback target (current active "+
				"config, restored on timeout) would strand management: %s", reason)
		}
	}
	return nil
}

// CheckDeviceMapStrandsManagement runs the #1956 device-map strand-management
// preflight against the LIVE host NIC inventory for a config that has NOT been
// committed — the day-0 `xpfd check-config` gate (#4183). It is the daemon-free
// analogue of deviceMapCommitPreflight: cmd/xpfd's check-config subcommand has
// no *Daemon, so this package-level helper enumerates present NICs, resolves
// the lifeline + protected set from the candidate config itself, and reports
// whether the map would strand management on next boot.
//
// Returns:
//   - reason != ""            -> the map WOULD strand management (hard-FAIL).
//   - reason == "", off==true -> SKIPPED: none of the mapped identities are
//     present, the OFF-TARGET signal (see below). Not a strand — the on-target
//     first-boot preflight is the real gate; the caller warns, never fails.
//   - reason == "", off==false -> checked and safe (or device-map inactive).
//   - err != nil              -> NIC enumeration failed (transient/environmental).
//
// Off-target guard (#4191 review, MAJOR): `xpfd check-config` is invoked OFF
// the target hardware by the standard day-0 pipeline — the config-drive is
// built on the BUILD host (scripts/image/make_config_drive.py) and installed
// from the DEPLOY host (scripts/deploy/xpf-deploy.py). There
// enumeratePresentNICs SUCCEEDS but returns the BUILD host's NICs, NONE at the
// target's mapped PCI/MAC identities, so every entry lands BindUnbound and a
// naive strand check would false-reject a PERFECTLY VALID bare-metal map. When
// NO mapped identity resolves to any present NIC (every binding is BindUnbound;
// a bound OR refused entry means the slot IS populated, so that is on-target),
// skip the check. This keeps the on-target genuine-strand rejection (mapped
// NICs present but management lost) and the on-target card-swap refusal intact.
func CheckDeviceMapStrandsManagement(cfg *config.Config) (reason string, offTarget bool, err error) {
	return checkDeviceMapStrandsManagement(cfg, true)
}

// CheckDeviceMapStrandsManagementOnTarget checks a day-0 config against the
// hardware it will be imported on. Unlike build/deploy-host check-config,
// every-unbound identities are not evidence of an off-target invocation here:
// the import preflight must assess the actual present NICs and fail closed.
func CheckDeviceMapStrandsManagementOnTarget(cfg *config.Config) (reason string, offTarget bool, err error) {
	return checkDeviceMapStrandsManagement(cfg, false)
}

func checkDeviceMapStrandsManagement(cfg *config.Config, allowOffTarget bool) (reason string, offTarget bool, err error) {
	if cfg == nil || !cfg.Chassis.DeviceMap.Active() {
		return "", false, nil
	}
	nics, err := enumeratePresentNICsFn()
	if err != nil {
		return "", false, err
	}
	if allowOffTarget && !anyMappedIdentityPresent(cfg, nics) {
		return "", true, nil
	}
	lifelineName, _ := resolveLifelineCurrentName()
	return deviceMapStrandsManagement(cfg, nics, protectedForConfig(cfg), lifelineName), false, nil
}

// anyMappedIdentityPresent reports whether ANY device-map entry resolves to a
// present NIC by identity — i.e. at least one binding is Decisive (bound OR
// refused: a refused entry means the pinned PCI slot IS populated, just with a
// swapped card). All-BindUnbound means none of the target's identities are on
// this host — the off-target signal used by CheckDeviceMapStrandsManagement.
func anyMappedIdentityPresent(cfg *config.Config, nics []presentNIC) bool {
	dm := cfg.Chassis.DeviceMap
	for _, b := range resolveDeviceMap(dm.Entries, nics, rethMembersFromConfig(cfg)) {
		if b.Status.Decisive() {
			return true
		}
	}
	return false
}

// protectedForConfig resolves the #1922 protected set using the SPECIFIC
// config's management-interface leaf (plus the config-independent lifeline
// record), rather than the currently-active config. The pre-flight uses this
// so a commit that repoints `system management-interface` is validated
// against the mgmt NIC it is ESTABLISHING.
func protectedForConfig(cfg *config.Config) map[string]bool {
	mgmtLeaf := ""
	if cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	return protectedInterfaces(mgmtLeaf)
}

// teardownUnmappedManaged is the #1956 V-4 managed->unmapped teardown,
// ordered to run BEFORE networkd.Apply on the live apply path. It is the
// single authority for the leave-alone transition: a NIC that xpf PREVIOUSLY
// managed (has a 10-xpf-<name>.link on disk) but whose name is no longer a
// desired binding is renamed back to its host-predictable name and its xpf
// .link/.network removed — so by the time networkd.Apply's stale-file sweep
// runs, that interface is already absent from BOTH the desired set and the
// on-disk xpf set and Apply has nothing to half-clean (which would otherwise
// un-rename it).
//
// The "previously managed" source of truth is the 10-xpf-*.link glob (the
// durable record of what xpf renamed), NOT the now-absent config. It runs
// only in device-map mode with leave-alone; manage-down keeps today's
// claim-all teardown via the compiler reconcile. It is no-op idempotent:
// when nothing transitioned, it touches nothing (operator priority #1 —
// zero churn on an unrelated commit).
//
// Fail-closed (#5309): the teardown RETURNS an error and RETAINS the durable
// markers on a genuine failure. When the rename-back of a live device fails
// (EBUSY / name collision) or no predictable name can be resolved for a device
// still wearing the xpf name, the `10-xpf-<name>.link` marker and its matching
// `.network` are KEPT — deleting them would drop xpf management AND leave the
// live interface under the wrong name (stale host routing ownership) while
// destroying the retry debt (the durable markers are the only record that the
// next commit must retry the teardown). The markers are reclaimed ONLY when the
// rename-back SUCCEEDED, or when no live device wears the name (already torn
// down / never present — an idempotent no-op that reclaims any leftover files
// without error). Rename-back and networkctl-reload failures are aggregated via
// errors.Join and surfaced so the caller (daemon_apply) fails the commit closed,
// mirroring the #4956 startup aggregation and the #4901 retain-on-failed-delete
// discipline.
func teardownUnmappedManaged(dm *config.DeviceMapConfig, protected map[string]bool) error {
	if !dm.Active() || dm.EffectiveUnmappedPolicy() != config.DeviceMapPolicyLeaveAlone {
		return nil
	}
	desiredNames := make(map[string]bool)
	for _, e := range dm.Entries {
		desiredNames[config.LinuxIfName(e.LogicalName)] = true
	}

	entries, err := os.ReadDir(linkDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no link dir → nothing was ever managed → no-op
		}
		return fmt.Errorf("device-map teardown: read link dir: %w", err)
	}
	reloaded := false
	var teardownErrs []error
	for _, fe := range entries {
		fname := fe.Name()
		if !strings.HasPrefix(fname, linkPrefix) || !strings.HasSuffix(fname, ".link") {
			continue
		}
		target := strings.TrimSuffix(strings.TrimPrefix(fname, linkPrefix), ".link")
		if desiredNames[target] {
			continue // still managed — leave it
		}
		// AGY r2 CRITICAL: NEVER tear down a #1922-protected interface (the
		// management lifeline / fxp0 / mgmt leaf), even when it is absent from
		// the device-map. Renaming it back to its predictable name and
		// deleting its .network here would cause an immediate management
		// lockout at commit time. The protected set is the config-independent
		// backstop; leaving the unmapped-but-protected NIC managed under its
		// xpf name keeps mgmt reachable. (The commit pre-flight separately
		// warns the operator to add it to the map — deviceMapStrandsManagement
		// Case C.)
		if protected[target] {
			slog.Info("device-map teardown: skipping #1922-protected interface left unmapped "+
				"(kept managed to preserve the management lifeline)", "name", target)
			continue
		}
		// A previously-managed NIC is no longer mapped. If a live device is
		// still wearing this xpf name, restore it to its predictable host name
		// FIRST — and only reclaim the durable markers when that succeeds.
		predictable, live := teardownRestoreTargetFn(target)
		renameOK := true // no live device to rename → safe to reclaim files
		switch {
		case !live:
			// Already renamed back / never present. Nothing to restore; fall
			// through to the (idempotent) marker reclaim below.
		case predictable == "" || predictable == target:
			// A live device still wears the xpf name but no distinct
			// predictable name is resolvable. Dropping management now would
			// strand the device under the wrong name AND destroy the retry
			// debt. RETAIN the markers and fail closed (#5309).
			renameOK = false
			slog.Warn("device-map teardown: no predictable name to restore unmapped NIC; "+
				"retaining durable state for retry (fail-closed)", "name", target)
			teardownErrs = append(teardownErrs,
				fmt.Errorf("no predictable name to restore unmapped NIC %q", target))
		default:
			if err := renameInterfaceFn(target, predictable); err != nil {
				renameOK = false
				slog.Warn("device-map teardown: rename-back failed; retaining durable state "+
					"for retry (fail-closed)", "name", target, "to", predictable, "err", err)
				teardownErrs = append(teardownErrs,
					fmt.Errorf("rename-back %s -> %s: %w", target, predictable, err))
			} else {
				slog.Info("device-map teardown: restored unmapped NIC to predictable name",
					"from", target, "to", predictable)
				reloaded = true
			}
		}
		// #5309: reclaim the durable markers ONLY when the rename-back
		// succeeded (or there was no live device to rename). On failure, RETAIN
		// both files so the next commit retries — never destroy the retry debt.
		if !renameOK {
			continue
		}
		if err := os.Remove(filepath.Join(linkDir, fname)); err == nil {
			reloaded = true
			slog.Info("device-map teardown: removed stale .link", "file", fname)
		}
		netFile := linkPrefix + target + ".network"
		if err := os.Remove(filepath.Join(linkDir, netFile)); err == nil {
			reloaded = true
			slog.Info("device-map teardown: removed stale .network", "file", netFile)
		}
	}
	if reloaded {
		if err := networkctlReloadFn(); err != nil {
			slog.Warn("device-map teardown: networkctl reload failed (fail-closed)", "err", err)
			teardownErrs = append(teardownErrs, fmt.Errorf("networkctl reload: %w", err))
		}
	}
	if len(teardownErrs) > 0 {
		return fmt.Errorf("device-map teardown: %d step(s) failed: %w",
			len(teardownErrs), errors.Join(teardownErrs...))
	}
	return nil
}

// teardownRestoreTarget resolves the rename-back target for the
// managed->unmapped teardown. It returns (predictable, true) when a LIVE device
// currently wears the xpf logical name `target` — `predictable` is the
// host-predictable name to restore it to (empty when none is resolvable). It
// returns ("", false) when no live device wears the name (already torn down or
// never present), in which case the teardown reclaims any leftover durable
// markers as an idempotent no-op. Split out as an injectable seam so the
// fail-closed retain-on-failure path (#5309) is testable without live
// netlink/sysfs.
func teardownRestoreTarget(target string) (predictable string, live bool) {
	if _, err := netlink.LinkByName(target); err != nil {
		return "", false // no live device wears this xpf name
	}
	nic := presentNIC{Name: target}
	if devReal, err := filepath.EvalSymlinks(
		filepath.Join("/sys/class/net", target, "device")); err == nil {
		nic.PCIAddr = devicemap.ExtractPCIAddr(devReal)
	}
	return predictableName(nic), true
}

// predictableNameLookup is the udev predictable-name resolver, injectable
// for tests (the real one shells out to `udevadm`, unavailable in the unit
// sandbox). It maps a present NIC (currently wearing a temp name) to the
// host's own predictable name. Empty result => caller leaves it under the
// temp name (never guesses a name that could collide — V-6).
var predictableNameLookup = udevPredictableName

// deriveKernelNameFn is the sysfs-based PCI→kernel-name resolver, injectable
// for tests (the real deriveKernelName in daemon_reth.go reads /sys/class/net
// which is unavailable in the unit sandbox).
var deriveKernelNameFn = deriveKernelName

// predictableName resolves the host-predictable name for a stranded NIC via
// the udev database, using the PUBLIC `udevadm info` interface rather than
// parsing /run/udev/data directly (Codex r3 MEDIUM — that couples to internal
// systemd storage layout). It prefers the most stable of ONBOARD > SLOT >
// PATH, mirroring systemd's own net-naming priority.
func predictableName(nic presentNIC) string {
	return predictableNameLookup(nic)
}

func udevPredictableName(nic presentNIC) string {
	// Query by the temp name's sysfs node — the kernel name has changed but
	// the device node and its ID_NET_NAME_* properties have not.
	out, err := execCommand("udevadm", "info", "--query=property",
		"--path=/sys/class/net/"+nic.Name)
	if err != nil {
		return ""
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			props[k] = v
		}
	}
	for _, key := range []string{"ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH"} {
		if v := props[key]; v != "" {
			return v
		}
	}
	return ""
}

// scrubStaleDeviceMapLinks removes 10-xpf-*.link files whose target name is
// not in the desired set, so a NIC dropped from the device-map does not keep
// a stale udev rename rule (R-2). The bootstrap .network and any non-.link
// file are left untouched. Returns true if anything was removed.
func scrubStaleDeviceMapLinks(desiredNames map[string]bool) bool {
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return false
	}
	removed := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, linkPrefix) || !strings.HasSuffix(name, ".link") {
			continue
		}
		target := strings.TrimSuffix(strings.TrimPrefix(name, linkPrefix), ".link")
		if desiredNames[target] {
			continue
		}
		if err := os.Remove(filepath.Join(linkDir, name)); err == nil {
			removed = true
			slog.Info("device-map: removed stale .link for unmapped name", "file", name, "target", target)
		}
	}
	return removed
}
