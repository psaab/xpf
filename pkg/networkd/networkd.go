// Package networkd generates systemd-networkd .link and .network files
// for interfaces managed by xpfd.
package networkd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/rendersafe"
)

// networkctlTimeout bounds every networkctl shell-out. Apply runs on
// the config-apply path under applyConfigLocked's applySem
// (daemon_apply.go d.networkd.Apply), so a hung networkctl (dbus stall,
// wedged systemd-networkd) would otherwise block every commit
// indefinitely. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const networkctlTimeout = 15 * time.Second

// runNetworkctl runs `networkctl <args...>` under networkctlTimeout. It is a
// package var so tests can stub the shell-out (the unit sandbox has no
// systemd-networkd) and assert Apply's success/error contract without
// depending on a real networkctl.
var runNetworkctl = func(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), networkctlTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "networkctl", args...).Run()
}

const (
	// DefaultNetworkDir is the systemd-networkd configuration directory.
	DefaultNetworkDir = "/etc/systemd/network"
	// filePrefix distinguishes xpf-managed files from manually created ones.
	filePrefix = "10-xpf-"
)

// InterfaceConfig describes a single interface for networkd generation.
type InterfaceConfig struct {
	Name             string   // interface name (trust0, untrust0, wan0, etc.)
	MACAddress       string   // hardware MAC address (from kernel)
	OriginalName     string   // kernel name before rename (for .link OriginalName= match)
	Addresses        []string // CIDR addresses (10.0.1.10/24, 2001:db8::1/64, etc.)
	PrimaryAddress   string   // address marked as primary (listed first for source selection)
	PreferredAddress string   // address marked as preferred (gets PreferredLifetime=forever)
	IsVLANParent     bool     // true = don't assign addresses (they go on sub-interface)
	DHCPv4           bool     // true = daemon runs DHCPv4 client (don't set static addr)
	DHCPv6           bool     // true = daemon runs DHCPv6 client
	Unmanaged        bool     // true = not in config; keep down with no addresses
	Disable          bool     // true = administratively disabled (keep down)
	DADDisable       bool     // true = disable IPv6 Duplicate Address Detection
	Speed            string   // link speed: "10M", "100M", "1G", "10G", etc.
	Duplex           string   // "full", "half"
	MTU              int      // interface MTU (0 = default)
	Description      string   // interface description (maps to .network [Network] Description)
	BondMaster       string   // LAG parent: bind this interface to a bond master (ae0, etc.)
	IsBond           bool     // true = this is a bond/LAG device (needs .netdev file)
	BondMode         string   // bond mode: "802.3ad" (default for ae interfaces)
	LACPRate         string   // LACP transmit rate: "fast" or "slow" (default)
	MinLinks         int      // minimum active member links (0 = no minimum)
	KeepAddresses    bool     // true = KeepConfiguration=static (preserve external addresses across reload)
	VRFName          string   // VRF device name (e.g. "vrf-mgmt") — emits [Network] VRF= so networkctl reconfigure preserves binding
	BridgeMaster     string   // bridge device name to join (e.g. "br-bd0")
	IsBridge         bool     // true = this is a bridge device (needs .netdev file)

	// VLANParentAddresses are addresses a VLAN parent carries ITSELF. Addresses
	// is ignored for a VLAN parent, so a sub-interface's addresses cannot leak
	// onto it; this field is the explicit exception. Its one producer is the
	// VRRP advert source of a VRRP-backed RETH whose untagged unit binds its
	// instance to the parent device (#9721).
	VLANParentAddresses []string
}

// Manager handles systemd-networkd .link and .network file generation.
type Manager struct {
	networkDir string
	// protectedResolver returns the #1922 management protected set (logical
	// names). Files for these interfaces (10-xpf-<name>.{link,network}) are
	// NEVER swept by Apply even when the interface is absent from the
	// compiled config — sweeping them would delete the live management NIC's
	// rename + addressing and lock the operator out (#1956 AGY r3 CRITICAL,
	// also the #1922 lifeline invariant). nil => no exemption (legacy).
	protectedResolver func() map[string]bool

	// mu guards the activation-debt fields below. Apply runs serialized under
	// the daemon's applySem today, but the debt is process-durable state that
	// outlives a single call, so it is locked defensively.
	//
	// The `networkctl reload` debt itself is NOT here — it is process-scoped
	// (see the reloadDebt holder below). Only the per-interface reconfigure
	// debt is Manager state, because `networkctl reconfigure <ifaces>` names
	// the interfaces this Manager generated files for; no other reload owner
	// in the process issues one.
	mu sync.Mutex
	// reconfigurePending mirrors the reload debt for the per-interface
	// `networkctl reconfigure` address-application follow-up (bonds / VLANs),
	// which was warn-only and likewise never retried. It holds the logical
	// interface names that still owe a reconfigure; the next activation pass
	// retries them and clears the set on success.
	reconfigurePending map[string]bool
	// activationPending records that THIS Manager began an activation pass and
	// did not finish it. It is deliberately NOT the process-wide reload debt.
	//
	// #5718 fold r4 BLOCKER 2: making the reload debt process-scoped collapsed
	// two different obligations into one flag. "The kernel re-read the
	// directory" is genuinely global — any owner's successful `networkctl
	// reload` discharges it. But Apply's activation pass has a TAIL that only
	// Apply can run: the per-interface `networkctl reconfigure` that applies
	// bond/VLAN addresses, and restoreSlowPathRPFilter, which re-disables
	// rp_filter on the userspace dataplane's slow-path TUN after networkd
	// resets it. Both sit behind `needReload`.
	//
	// So when Apply's own reload FAILED (it returns early, before the tail, and
	// therefore never records reconfigure debt) and pkg/daemon then ran a
	// SUCCESSFUL reload of its own, the global debt cleared — and the next
	// Apply with byte-identical files saw changed==false, no reload debt and no
	// reconfigure debt, skipped the whole block, and returned nil. The kernel
	// had re-read the files, but the addresses were never reconfigured and
	// rp_filter was left at networkd's default, silently dropping
	// locally-originated traffic via the TUN. An external owner discharged a
	// postcondition it had no way to perform.
	//
	// This flag is set when Apply enters its activation pass and cleared only
	// once that pass completes its tail, so no other owner can discharge it.
	activationPending bool
}

// reloadDebt is the #4954 `networkctl reload` activation debt: a reload that
// FAILED after generated files were already written to (or removed from) disk.
// Because the files are already on disk, a later Apply with byte-identical
// content sees no change (writeIfChanged → changed=false) and would otherwise
// SKIP the reload and return nil — masking a config the kernel never activated
// as a green commit (route leak / stranded NIC / management lockout persists).
// The debt forces the next activation pass to re-run the idempotent reload
// even with unchanged files, and is cleared only once a reload succeeds.
//
// #5718 fold F2 — ONE holder, EVERY owner. The debt is PROCESS-scoped, not
// Manager-scoped, because `networkctl reload` acts on the single
// systemd-networkd instance for the whole host and this Manager is not its
// only owner. pkg/daemon shells out to `networkctl reload` directly through
// its own networkctlReload helper from FIVE production call sites —
// linksetup's post-rename reload (warn-only, linksetup.go), the device-map
// rename and teardown reloads (device_map.go, via networkctlReloadFn), and the
// bootstrap teardown and lifeline reloads (bootstrap.go) — all writing or
// removing the same 10-xpf-* files this package generates. With a per-Manager bool those
// owners could disagree with the Manager, and the disagreement resolves in the
// dangerous direction: a daemon-side reload that fails leaves the files on
// disk unactivated while the Manager's flag stays false, so the next Apply
// takes the `changed==false && !reloadDebt` branch, skips the reload, and
// reports the very #4954 false success the debt exists to prevent. Every
// reload owner in the process now records into this holder — pkg/networkd via
// noteReloadFailed / noteReloadSucceeded, pkg/daemon via the exported
// BeginReload / NoteReloadResult pair.
//
// #5718 fold F4 — the clear is EPOCH-GUARDED, never a blind store. `epoch`
// increments every time debt is RECORDED, and a successful reload may only
// discharge the debt state it observed before it started. Without the guard a
// concurrent owner's failure is silently lost:
//
//	owner B calls reload; the syscall returns success
//	owner A writes new generated files
//	owner A calls reload; it FAILS; A records the debt
//	owner B resumes and blind-stores pending=false  ← A's debt is gone
//
// B's reload re-read the directory BEFORE A's files existed, so it cannot have
// activated them, yet the operator is told the next identical Apply succeeded.
// A debt cleared whose work never ran is a silent skip of a reload the system
// believes it performed. With the guard, B's epoch snapshot no longer matches
// and its clear is refused, so A's debt survives to force the retry.
var reloadDebt struct {
	mu      sync.Mutex
	pending bool
	epoch   uint64
	// tailPending records that a reload run by an EXTERNAL owner SUCCEEDED
	// (#6912). The kernel really did re-read the directory, so the reload
	// obligation is genuinely discharged and `pending` is correctly false —
	// but the activation TAIL was not run, and only Apply can run it. Without
	// this the next unchanged Apply sees changed==false, no reload debt, no
	// reconfigure debt and no activationPending, skips the whole block, and
	// returns nil having silently left addresses unreconfigured and the
	// slow-path TUN's rp_filter at networkd's default.
	//
	// Process-scoped for the same reason `pending` is: pkg/daemon runs
	// `networkctl reload` from several sites of its own, and a Manager-scoped
	// flag could not record what they did.
	tailPending bool
}

// reloadDebtEpoch snapshots the debt epoch. Callers take it immediately BEFORE
// running `networkctl reload` and hand it back to noteReloadSucceeded.
func reloadDebtEpoch() uint64 {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	return reloadDebt.epoch
}

// reloadDebtOutstanding reports whether an activation is still owed.
func reloadDebtOutstanding() bool {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	return reloadDebt.pending
}

// noteExternalReloadRanWithoutTail records that an external owner's reload
// succeeded, so the activation tail is owed even though no reload is (#6912).
func noteExternalReloadRanWithoutTail() {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	reloadDebt.tailPending = true
}

// externalTailOutstanding reports whether an external reload has discharged a
// reload obligation without the activation tail having run since.
func externalTailOutstanding() bool {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	return reloadDebt.tailPending
}

// clearExternalTailDebt is called only after the tail has actually completed.
func clearExternalTailDebt() {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	reloadDebt.tailPending = false
}

// noteReloadFailed records the activation debt and advances the epoch so any
// reload already in flight cannot clear it.
func noteReloadFailed() {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	reloadDebt.pending = true
	reloadDebt.epoch++
}

// noteReloadSucceeded discharges the debt observed at epoch. If another owner
// recorded debt while this reload was in flight the epoch has moved, and this
// reload provably cannot have activated that owner's files — so the clear is
// refused and the debt survives for the next activation pass.
func noteReloadSucceeded(epoch uint64) {
	reloadDebt.mu.Lock()
	defer reloadDebt.mu.Unlock()
	if reloadDebt.epoch != epoch {
		return
	}
	reloadDebt.pending = false
}

// BeginReload snapshots the #4954 activation-debt epoch before a `networkctl
// reload` that this package does not run itself. Pair every call with
// NoteReloadResult; see the reloadDebt holder for why the debt is
// process-scoped rather than owned by a Manager.
func BeginReload() uint64 { return reloadDebtEpoch() }

// NoteReloadResult records the outcome of a `networkctl reload` executed
// outside this package (pkg/daemon's linksetup, device-map and bootstrap
// paths). epoch must come from the BeginReload that preceded the reload.
func NoteReloadResult(epoch uint64, err error) {
	if err != nil {
		noteReloadFailed()
		return
	}
	noteReloadSucceeded(epoch)
	// #6912: a SUCCESSFUL external reload discharges the reload obligation but
	// performs none of the activation tail — the per-interface `networkctl
	// reconfigure` that applies bond/VLAN addresses, and restoreSlowPathRPFilter.
	// An external owner cannot run those, so record that they are owed.
	//
	// Armed at this EXTERNAL entry point (BeginReload/NoteReloadResult exist
	// for reloads this package does not run itself) rather than in the shared
	// noteReloadSucceeded. That choice is about keeping the flag's meaning true
	// to its name, NOT about preventing a defect: arming on the shared path was
	// measured equivalent, because Apply's own reload runs the tail in the same
	// pass and clears the flag before returning. It would simply add a pointless
	// write on every Apply.
	//
	// Likewise the failure branch above does not arm it, and does not need to:
	// noteReloadFailed sets the reload debt, so debtOwed already forces the next
	// Apply through the tail. Measured — arming there as well changes nothing.
	noteExternalReloadRanWithoutTail()
}

// ReloadDebtOutstanding reports whether a `networkctl reload` activation is
// still owed process-wide. It exists so the other reload owners can assert the
// POSTCONDITION of their reporting — a failure is carried forward, a success
// discharges — rather than the proxy of whether the debt epoch happened to
// move, which is unchanged both when a success is reported correctly and when
// reporting it is omitted entirely.
//
// It does NOT report a Manager's own activation debt: `networkctl reconfigure`
// and the slow-path rp_filter restore are Manager-scoped obligations no
// external reload owner performs. See Manager.activationPending.
func ReloadDebtOutstanding() bool { return reloadDebtOutstanding() }

// SetProtectedResolver registers the management protected-set provider so
// Apply can exempt the lifeline's files from the stale-file sweep. Called once
// at daemon init alongside the dataplane protected resolver.
func (m *Manager) SetProtectedResolver(fn func() map[string]bool) {
	m.protectedResolver = fn
}

// New creates a new networkd manager.
func New() *Manager {
	return NewInDir(DefaultNetworkDir)
}

// NewInDir creates a networkd manager rooted at networkDir. Production callers
// use New(); tests and offline renderers use this to avoid touching /etc.
func NewInDir(networkDir string) *Manager {
	if networkDir == "" {
		networkDir = DefaultNetworkDir
	}
	return &Manager{
		networkDir: networkDir,
	}
}

// Apply writes .link and .network files for all interfaces,
// then calls networkctl reload if any files changed.
// Interfaces with existing non-xpf networkd configs (e.g. management
// interface) are skipped to avoid conflicts.
func (m *Manager) Apply(interfaces []InterfaceConfig) error {
	// An empty desired set is NOT a no-op (#2988): if the last xpf-managed
	// interface is removed, the stale `10-xpf-*` sweep below must still run
	// so old .network/.link/.netdev snippets do not resurrect addresses,
	// bonds, bridges, or renames on the next reload. The expected set ends up
	// holding only the protected-resolver's lifeline files, so everything
	// else xpf owns is swept and a reload is requested.

	// Discover interfaces with existing non-xpf networkd .network files.
	// Only skip unmanaged interfaces that have external configs (e.g.
	// management interface). Configured interfaces always get xpf files
	// even if old external files exist — xpf takes ownership.
	external := m.findExternallyManaged()

	var filtered []InterfaceConfig
	for _, ifc := range interfaces {
		if ifc.Unmanaged && external[ifc.Name] {
			slog.Debug("skipping externally managed interface", "name", ifc.Name)
			continue
		}
		filtered = append(filtered, ifc)
	}
	interfaces = filtered

	// Build set of expected filenames.
	// .link files are only for managed physical interfaces (have MAC address,
	// not unmanaged). Unmanaged interfaces are named by the daemon at startup.
	// .netdev files are for bond (LAG) and bridge devices.
	// VLAN sub-interfaces (wan0.50) only get .network files.
	expected := make(map[string]bool)
	for _, ifc := range interfaces {
		if ifc.MACAddress != "" && !ifc.Unmanaged {
			expected[filePrefix+ifc.Name+".link"] = true
		}
		if ifc.IsBond || ifc.IsBridge {
			expected[filePrefix+ifc.Name+".netdev"] = true
		}
		expected[filePrefix+ifc.Name+".network"] = true
	}

	// #1956 AGY r3 CRITICAL: never sweep the management protected set's files.
	// A protected interface (the lifeline / fxp0 / mgmt leaf) is exempt from
	// the unmanaged bring-down and is therefore absent from `interfaces`, so
	// the stale-file sweep below would otherwise delete its 10-xpf-*.link and
	// .network — instantly stripping the live mgmt NIC's rename + addressing
	// on reload. Add its files to `expected` so the sweep preserves them.
	if m.protectedResolver != nil {
		for name := range m.protectedResolver() {
			if name == "" {
				continue
			}
			expected[filePrefix+name+".link"] = true
			expected[filePrefix+name+".network"] = true
		}
	}

	changed := false

	// Remove stale xpf-managed files. #4900: a remove FAILURE is aggregated
	// (mirroring the #2987 write-failure handling) and fails the commit —
	// best-effort still attempts every delete, but a stale 10-xpf-* unit that
	// cannot be removed (read-only /etc, immutable bit, EACCES) must NOT survive
	// a "successful" commit and silently re-apply the removed address / VRF /
	// bond / bridge / rename on the next reload or reboot. The prior warn-only
	// path let such a file survive with no error and, if no other file changed,
	// no reload either.
	var removeErrs []error
	matches, _ := filepath.Glob(filepath.Join(m.networkDir, filePrefix+"*"))
	for _, path := range matches {
		base := filepath.Base(path)
		if !expected[base] {
			if err := os.Remove(path); err != nil {
				slog.Warn("failed to remove stale networkd file", "path", path, "err", err)
				removeErrs = append(removeErrs, fmt.Errorf("remove stale %s: %w", base, err))
			} else {
				slog.Info("removed stale networkd file", "path", path)
				changed = true
			}
		}
	}

	// Write .netdev, .link, and .network files. Write failures are
	// aggregated (#2987): we still attempt every generated file so a single
	// blocked path does not silently skip the rest, then fail the Apply at
	// the end so the commit cannot succeed against stale kernel state.
	var writeErrs []error
	write := func(path, content string) {
		ch, err := writeIfChanged(path, content)
		if err != nil {
			writeErrs = append(writeErrs, err)
			return
		}
		if ch {
			changed = true
		}
	}
	for _, ifc := range interfaces {
		// #9494: ifc.Name becomes a path component under m.networkDir, and
		// filepath.Join Cleans, so a name carrying a separator would write
		// outside the managed directory as root while Apply reported success.
		// Refuse it as a write failure: the Apply fails and nothing is written
		// for that interface. This is the belt behind the schema gate, for
		// names that reach Apply through a tolerant load, peer sync or rollback.
		if err := confinedInterfaceName(ifc.Name); err != nil {
			writeErrs = append(writeErrs, err)
			continue
		}
		// .netdev file: for bond/LAG devices and bridge devices
		if ifc.IsBond {
			netdevPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".netdev")
			write(netdevPath, m.generateNetdev(ifc))
		}
		if ifc.IsBridge {
			netdevPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".netdev")
			write(netdevPath, m.generateBridgeNetdev(ifc))
		}

		// .link file: only for managed physical interfaces with a MAC address.
		// Skip unmanaged interfaces — the daemon's linksetup handles their
		// naming at startup. Writing .link files for unmanaged interfaces would
		// override the FPC-aware naming (e.g. ge-7-0-X on node1).
		if ifc.MACAddress != "" && !ifc.Unmanaged {
			linkPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".link")
			write(linkPath, m.generateLink(ifc))
		}

		// .network file: for all interfaces
		networkPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".network")
		write(networkPath, m.generateNetwork(ifc))
	}

	if len(writeErrs) > 0 || len(removeErrs) > 0 {
		// Fail the commit (#2987 write failures, #4900 stale-remove failures).
		// Still reload if some files changed so the kernel reflects whatever did
		// get written/removed, but surface the error so the operator is not told
		// a config was committed while a stale unit survives on disk.
		nWrite, nRemove := len(writeErrs), len(removeErrs)
		// #5718 fold r7 BLOCKER 1: this branch owes the Manager tail and never
		// armed it. `activationPending` had exactly one assignment — in the
		// success path below — so an Apply that failed a write or a stale
		// removal returned from here with the tail NEVER ARMED, not merely
		// skipped. The reload attempted just below is not the tail: the
		// per-interface `networkctl reconfigure` and (on a failed reload)
		// `restoreSlowPathRPFilter` are Manager-only work that no other reload
		// owner performs.
		//
		// That matters because the GLOBAL debt this branch arms is discharged
		// by ANY reload owner. A device-map teardown that removes the offending
		// stale marker and reloads successfully (daemon/linksetup.go) clears the
		// global debt while doing neither tail operation; the byte-identical
		// Apply that follows then sees no change, no global debt, no
		// reconfigure debt and no activation debt, and returns success having
		// skipped the tail entirely — bond/VLAN addresses unapplied and
		// `xpf-usp0`'s rp_filter left at 2, silently dropping slow-path traffic.
		//
		// Armed BEFORE the reload, like the success path, so an early return
		// still records the obligation. Deliberately NOT cleared when the reload
		// below succeeds: that reload is only the first half, and the
		// reconfigure half has still not run.
		m.mu.Lock()
		m.activationPending = true
		m.mu.Unlock()
		if changed {
			epoch := reloadDebtEpoch()
			if err := runNetworkctl("reload"); err != nil {
				// #4954: a failed reload here also owes activation debt so a
				// later identical retry re-attempts it rather than reporting a
				// false success.
				noteReloadFailed()
				writeErrs = append(writeErrs, fmt.Errorf("networkctl reload: %w", err))
			} else {
				noteReloadSucceeded(epoch)
				restoreSlowPathRPFilter()
			}
		}
		allErrs := append(append([]error{}, removeErrs...), writeErrs...)
		return fmt.Errorf("networkd: %d generated file(s) failed to write, %d stale file(s) failed to remove: %w",
			nWrite, nRemove, errors.Join(allErrs...))
	}

	// #4954: an Apply must (re)activate whenever files changed this call OR a
	// prior Apply left reload/reconfigure debt. Because the generated files are
	// already on disk, an identical retry after a failed activation sees no
	// change (changed==false) yet the kernel still runs the pre-failure config;
	// without the debt the retry would skip the networkctl commands and return
	// a false success. The debt is cleared only when the idempotent command
	// finally succeeds.
	debtOwed := reloadDebtOutstanding()
	m.mu.Lock()
	reconfDebt := len(m.reconfigurePending) > 0
	activationOwed := m.activationPending
	m.mu.Unlock()

	needReload := changed || debtOwed
	// #5718 fold r4 BLOCKER 2: activationOwed keeps this Manager's own tail —
	// the per-interface reconfigure and restoreSlowPathRPFilter — reachable
	// even when another reload owner discharged the global debt on our behalf.
	// Without it, an external successful reload turns the next unchanged Apply
	// into a no-op that skips postconditions only Apply can perform.
	// #6912: externalTailOutstanding() covers the case none of the others can —
	// a successful EXTERNAL reload, no failed Apply anywhere, and byte-identical
	// files. changed is false, the reload debt was correctly discharged, no
	// reconfigure failed and this Manager never started a pass, so every other
	// term is false while the tail has still never run.
	if needReload || reconfDebt || activationOwed || externalTailOutstanding() {
		// Mark the pass in flight BEFORE the reload can fail out, so an early
		// return leaves the obligation recorded.
		m.mu.Lock()
		m.activationPending = true
		m.mu.Unlock()
		if needReload {
			if changed {
				slog.Info("networkd config updated, reloading", "interfaces", len(interfaces))
			} else {
				slog.Info("networkd re-running deferred reload after a prior failed reload",
					"interfaces", len(interfaces))
			}
			epoch := reloadDebtEpoch()
			if err := runNetworkctl("reload"); err != nil {
				noteReloadFailed()
				return fmt.Errorf("networkctl reload: %w", err)
			}
			noteReloadSucceeded(epoch)
		}
		// Dynamically created interfaces (bonds, VLANs) may not get their
		// addresses applied by reload alone. Reconfigure all managed
		// interfaces to ensure addresses are applied.
		// Skip bond member interfaces — reconfigure can eject them from
		// their bond. Their Bond= directive is picked up by reload.
		var reconf []string
		for _, ifc := range interfaces {
			if !ifc.Unmanaged && !ifc.Disable && ifc.BondMaster == "" {
				reconf = append(reconf, ifc.Name)
			}
		}
		if len(reconf) > 0 {
			args := append([]string{"reconfigure"}, reconf...)
			// Best-effort (reload above already applied the files), but the
			// failure is no longer silent AND no longer forgotten: record the
			// debt so the next Apply retries even with unchanged files (#4954).
			if err := runNetworkctl(args...); err != nil {
				m.setReconfigurePending(reconf)
				slog.Warn("networkctl reconfigure failed",
					"interfaces", len(reconf), "err", err)
			} else {
				m.setReconfigurePending(nil)
			}
		} else {
			// Nothing managed to reconfigure — clear any stale debt.
			m.setReconfigurePending(nil)
		}
		restoreSlowPathRPFilter()
		// The tail completed, so this Manager owes nothing further. Cleared
		// LAST and only here: every early return above leaves it set.
		m.mu.Lock()
		m.activationPending = false
		m.mu.Unlock()
		// #6912: and the tail an external reload left owed has now been paid.
		// Cleared at the same point and for the same reason — only a completed
		// tail discharges it, so every early return above preserves it.
		clearExternalTailDebt()
	}

	return nil
}

// setReconfigurePending records the set of interface names that still owe a
// `networkctl reconfigure` (#4954), or clears the debt when names is empty.
func (m *Manager) setReconfigurePending(names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(names) == 0 {
		m.reconfigurePending = nil
		return
	}
	m.reconfigurePending = make(map[string]bool, len(names))
	for _, n := range names {
		m.reconfigurePending[n] = true
	}
}

// procSysNetRoot is the root of the IPv4 sysctl tree. It is a package var
// (not a const) so tests can point the slow-path rp_filter handling at a
// temp-file fixture instead of the live /proc.
var procSysNetRoot = "/proc/sys/net/ipv4"

// restoreSlowPathRPFilter re-disables rp_filter on the userspace dataplane's
// slow-path TUN device after a networkctl reload. networkd resets sysctls to
// defaults (rp_filter=2) on all interfaces during reload, which breaks
// locally-originated traffic delivery via the TUN (the kernel drops packets
// whose source route doesn't point at the TUN interface).
//
// The kernel computes the effective rp_filter for a packet as
// max(conf/all/rp_filter, conf/<dev>/rp_filter), so the per-device 0 we write
// here is ignored if conf/all/rp_filter is non-zero (a common Debian/Ubuntu
// default). We do NOT mutate the host-global conf/all knob — instead, when it
// is non-zero, we emit a one-time operator-visible warning that slow-path
// reinjection will be dropped until it is lowered (#2378). This runs only on
// the reload/clear path, never per-packet.
func restoreSlowPathRPFilter() {
	const tunName = "xpf-usp0"
	path := fmt.Sprintf("%s/conf/%s/rp_filter", procSysNetRoot, tunName)
	// BestEffortKernelKnob (#1894): procfs has no rename, so the
	// fsatomic writers are impossible here by construction — the direct
	// write is correct, not an oversight.
	if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
		if os.IsNotExist(err) {
			// TUN may not exist (userspace DP not active) — not an error.
			return
		}
		slog.Warn("failed to restore rp_filter on slow-path TUN", "path", path, "err", err)
	}
	warnIfAllRPFilterOverrides(tunName)
}

// warnIfAllRPFilterOverrides emits a loud warning when net.ipv4.conf.all.rp_filter
// is non-zero. The kernel uses max(conf/all/rp_filter, conf/<dev>/rp_filter), so
// a non-zero conf/all knob silently drops slow-path reinjected IPv4 packets
// regardless of the per-device value (#2378). The message states the hazard from
// the all-knob directly and does NOT assert that the per-device write above
// succeeded — so it stays accurate when the per-device write failed (in which
// case the drop hazard is in fact MORE acute, and suppressing the warning would
// hide a still-relevant signal). A missing or unparsable conf/all/rp_filter is
// treated as "cannot determine" and stays quiet so a read failure never produces
// a spurious warning.
func warnIfAllRPFilterOverrides(tunName string) {
	allPath := fmt.Sprintf("%s/conf/all/rp_filter", procSysNetRoot)
	raw, err := os.ReadFile(allPath)
	if err != nil {
		return
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || val == 0 {
		return
	}
	slog.Warn("net.ipv4.conf.all.rp_filter is non-zero; kernel uses max(all,dev) "+
		"so slow-path reinjected IPv4 packets will be SILENTLY DROPPED until "+
		"'sysctl -w net.ipv4.conf.all.rp_filter=0' is set",
		"tun", tunName, "all_rp_filter", val, "issue", 2378)
}

func FindExternallyManaged(dir string) map[string]bool {
	result := make(map[string]bool)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, ".network") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Name=") {
				ifName := strings.TrimSpace(strings.TrimPrefix(line, "Name="))
				if ifName != "" {
					result[ifName] = true
				}
			}
		}
	}
	return result
}

func (m *Manager) findExternallyManaged() map[string]bool {
	return FindExternallyManaged(m.networkDir)
}

// sanitizeUnitValue replaces every ASCII control byte (C0, 0x00-0x1F, which
// includes newline, plus DEL 0x7F) with a SPACE before the value is interpolated
// into a generated systemd unit line. Render-side belt for #1798: a description
// like "lan\nDHCP=ipv4" must not be able to inject extra directives into a
// .network/.netdev/.link unit even if the commit-time validation layer were
// bypassed (e.g. an old persisted value reaching the renderer ahead of the
// load-time sanitizer).
//
// # The consuming grammar, and why a space is the right substitute here (#6833)
//
// A systemd unit file is `Key=Value` one per line. The load-bearing byte for an
// interpolated value is therefore the NEWLINE, which ends the directive and lets
// the remainder be read as a new one. That is the byte #1798 named and it is
// genuinely the live one here.
//
// A space is safe because this belt is applied to `Description=` and ONLY to
// `Description=`, which systemd treats as free text. That is not incidental — it
// is what makes the substitution correct, and it is pinned by
// TestUnitValueSanitizerIsAppliedOnlyToDescription_6833.
//
// It would NOT be safe on several `[Match]` keys, which are WHITESPACE-SEPARATED
// LISTS: `OriginalName=` accepts a list of patterns, so a space inside one value
// would make a single .link file match several kernel interfaces — the
// substitution manufacturing the very delimiter the belt exists to prevent (the
// #6829 shape, where the space and not the newline was the live byte). Any future
// call site on such a key must re-derive the substitute rather than reuse this
// function; the inventory test above is what forces that.
func sanitizeUnitValue(s string) string {
	return rendersafe.ReplaceControlBytes(s, ' ')
}

func (m *Manager) generateNetdev(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[NetDev]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)
	b.WriteString("Kind=bond\n")
	if ifc.Description != "" {
		fmt.Fprintf(&b, "Description=%s\n", sanitizeUnitValue(ifc.Description))
	}
	if ifc.MTU > 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", ifc.MTU)
	}
	b.WriteString("\n[Bond]\n")
	mode := ifc.BondMode
	if mode == "" {
		mode = "802.3ad"
	}
	fmt.Fprintf(&b, "Mode=%s\n", mode)
	if mode == "active-backup" {
		// Active-backup uses MII monitoring, no LACP
		b.WriteString("MIIMonitorSec=100ms\n")
	} else {
		// LACP modes (802.3ad, balance-xor, etc.)
		rate := ifc.LACPRate
		if rate == "" {
			rate = "fast"
		}
		fmt.Fprintf(&b, "LACPTransmitRate=%s\n", rate)
		b.WriteString("TransmitHashPolicy=layer3+4\n")
	}
	if ifc.MinLinks > 0 {
		fmt.Fprintf(&b, "MinLinks=%d\n", ifc.MinLinks)
	}
	return b.String()
}

func (m *Manager) generateBridgeNetdev(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[NetDev]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)
	b.WriteString("Kind=bridge\n")
	if ifc.Description != "" {
		fmt.Fprintf(&b, "Description=%s\n", sanitizeUnitValue(ifc.Description))
	}
	if ifc.MTU > 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", ifc.MTU)
	}
	return b.String()
}

func (m *Manager) generateLink(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[Match]\n")
	if ifc.OriginalName != "" {
		// RETH members: match by kernel name (PCI-based, stable across
		// reboots) because the MAC alternates between physical and virtual.
		fmt.Fprintf(&b, "OriginalName=%s\n", ifc.OriginalName)
	} else {
		fmt.Fprintf(&b, "MACAddress=%s\n", ifc.MACAddress)
	}
	b.WriteString("\n[Link]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)
	if ifc.MTU > 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", ifc.MTU)
	}
	if ifc.Speed != "" {
		fmt.Fprintf(&b, "BitsPerSecond=%s\n", junosSpeedToNetworkd(ifc.Speed))
	}
	if ifc.Duplex != "" {
		fmt.Fprintf(&b, "Duplex=%s\n", ifc.Duplex)
	}
	if ifc.Description != "" {
		fmt.Fprintf(&b, "Description=%s\n", sanitizeUnitValue(ifc.Description))
	}
	return b.String()
}

func (m *Manager) generateNetwork(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[Match]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)

	if ifc.Unmanaged || ifc.Disable {
		b.WriteString("\n[Link]\n")
		b.WriteString("ActivationPolicy=always-down\n")
		b.WriteString("RequiredForOnline=no\n")
		b.WriteString("\n[Network]\n")
		b.WriteString("DHCP=no\n")
		b.WriteString("IPv6AcceptRA=no\n")
		b.WriteString("LinkLocalAddressing=no\n")
		return b.String()
	}

	if ifc.IsVLANParent {
		b.WriteString("\n[Link]\n")
		b.WriteString("RequiredForOnline=no\n")
	}

	b.WriteString("\n[Network]\n")
	b.WriteString("IPv6AcceptRA=no\n")

	if ifc.IsVLANParent {
		b.WriteString("DHCP=no\n")
	}

	// Preserve externally-added addresses (e.g. VRRP VIPs) across networkctl reload.
	if ifc.KeepAddresses {
		b.WriteString("KeepConfiguration=static\n")
	}

	b.WriteString("LinkLocalAddressing=ipv6\n")

	// VRF membership — ensures networkctl reconfigure preserves the binding
	if ifc.VRFName != "" {
		fmt.Fprintf(&b, "VRF=%s\n", ifc.VRFName)
	}

	// Bond member: bind to bond master
	if ifc.BondMaster != "" {
		fmt.Fprintf(&b, "Bond=%s\n", ifc.BondMaster)
	}

	// Bridge member: bind to bridge device
	if ifc.BridgeMaster != "" {
		fmt.Fprintf(&b, "Bridge=%s\n", ifc.BridgeMaster)
	}

	// Disable IPv6 Duplicate Address Detection if configured
	if ifc.DADDisable {
		b.WriteString("IPv6DuplicateAddressDetection=0\n")
	}

	// Write static Address= lines for VLAN-parent-exempt interfaces, gating
	// each family independently on its own DHCP flag (#2986). DHCP is a
	// per-family property on the wire (DHCPv4 vs DHCPv6/PD), so a static
	// address must be suppressed ONLY for the family whose DHCP client owns
	// it — not the opposite family. The common WAN shape DHCPv4 + static
	// IPv6 (and the mirror static IPv4 + DHCPv6) previously dropped the
	// static address of the non-DHCP family because the gate keyed on
	// whole-interface (!DHCPv4 && !DHCPv6).
	if !ifc.IsVLANParent {
		ordered := orderAddresses(ifc.Addresses, ifc.PrimaryAddress)
		addrs := make([]string, 0, len(ordered))
		for _, addr := range ordered {
			if addressIsIPv6(addr) {
				if ifc.DHCPv6 {
					continue
				}
			} else if ifc.DHCPv4 {
				continue
			}
			addrs = append(addrs, addr)
		}
		if ifc.PreferredAddress != "" {
			// Use [Address] sections so we can set PreferredLifetime
			for _, addr := range addrs {
				b.WriteString("\n[Address]\n")
				fmt.Fprintf(&b, "Address=%s\n", addr)
				if addr == ifc.PreferredAddress {
					b.WriteString("PreferredLifetime=forever\n")
				}
			}
		} else {
			for _, addr := range addrs {
				fmt.Fprintf(&b, "Address=%s\n", addr)
			}
		}
	}

	// #9721: a VLAN parent's OWN addresses, the VRRP advert source of a
	// VRRP-backed RETH whose untagged unit binds its instance to this device.
	// Addresses stays ignored above for a VLAN parent; only this explicit
	// field renders on one.
	if ifc.IsVLANParent {
		for _, addr := range ifc.VLANParentAddresses {
			fmt.Fprintf(&b, "Address=%s\n", addr)
		}
	}

	return b.String()
}

// junosSpeedToNetworkd converts Junos speed notation to systemd-networkd BitsPerSecond.
// Junos uses "10m", "100m", "1g", "10g", "25g", "40g", "100g", "auto".
// networkd expects numeric bps value (e.g. "1000000000" for 1G).
func junosSpeedToNetworkd(speed string) string {
	s := strings.ToLower(strings.TrimSpace(speed))
	switch s {
	case "10m":
		return "10000000"
	case "100m":
		return "100000000"
	case "1g":
		return "1000000000"
	case "2.5g":
		return "2500000000"
	case "5g":
		return "5000000000"
	case "10g":
		return "10000000000"
	case "25g":
		return "25000000000"
	case "40g":
		return "40000000000"
	case "100g":
		return "100000000000"
	default:
		return speed // pass through as-is
	}
}

// addressIsIPv6 reports whether a CIDR address string (e.g.
// "2001:db8::1/64" or "10.0.1.10/24") is IPv6. An IPv6 literal always
// contains a colon and an IPv4 literal never does, so a colon test
// classifies the family without a full netip parse — keeping the static
// render allocation-free and tolerant of zone-id suffixes.
func addressIsIPv6(addr string) bool {
	return strings.Contains(addr, ":")
}

// orderAddresses returns a copy of addrs with primaryAddr first (if set and present).
func orderAddresses(addrs []string, primaryAddr string) []string {
	if primaryAddr == "" || len(addrs) <= 1 {
		return addrs
	}
	ordered := make([]string, 0, len(addrs))
	found := false
	for _, a := range addrs {
		if a == primaryAddr {
			found = true
		} else {
			ordered = append(ordered, a)
		}
	}
	if found {
		ordered = append([]string{primaryAddr}, ordered...)
	}
	return ordered
}

// writeIfChanged writes content to path only if the content differs from
// the existing file. It returns (changed, err): changed is true when the
// file was actually written, and err is non-nil when the write failed.
//
// A write failure (read-only /etc, full disk, EACCES, blocked path) MUST
// propagate so Apply can fail the commit (#2987) — fail-closed posture.
// Previously the error was logged and swallowed as changed=false, which a
// caller could not distinguish from "nothing changed", so the commit
// succeeded while the kernel kept stale link/address/VRF state.
func writeIfChanged(path, content string) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false, nil
	}

	// AtomicGeneratedConfig (#1894): .link/.network snippets are
	// regenerated on boot/apply — keep them un-torn for networkd, but
	// never pay an fsync on this hot apply path (many small files per
	// reconcile).
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to write networkd file", "path", path, "err", err)
		return false, fmt.Errorf("write %s: %w", path, err)
	}

	slog.Info("wrote networkd file", "path", path)
	return true, nil
}

// confinedInterfaceName reports whether name can stand as a single file-name
// component under the managed networkd directory (#9494). An empty name, or one
// containing a path separator or NUL, cannot.
func confinedInterfaceName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("networkd: refusing interface name %q: it cannot be a file name inside the managed directory (#9494)", name)
	}
	return nil
}
