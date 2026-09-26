// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/rendersafe"
	"github.com/vishvananda/netlink"
)

const linkPrefix = "10-xpf-"

// linkDir is the systemd-networkd config directory. A var (not const) so
// tests can redirect it to a temp dir; production never reassigns it.
var linkDir = "/etc/systemd/network"

// netlink link operations used by renameInterface, indirected through
// package vars so tests can inject failures (e.g. a LinkSetUp error) and
// record the exact call sequence. They default to the real
// vishvananda/netlink functions; production never reassigns them. This
// mirrors the package's existing function-var seam idiom (deriveKernelNameFn
// in device_map.go) and the testLink/mockLinkByName scaffold in
// vip_readiness_test.go. Tests that swap these vars MUST restore them via
// t.Cleanup and MUST NOT call t.Parallel() — the vars are package-global
// mutable state.
var (
	nlLinkByName  = netlink.LinkByName
	nlLinkSetDown = netlink.LinkSetDown
	nlLinkSetName = netlink.LinkSetName
	nlLinkSetUp   = netlink.LinkSetUp
)

// pciNIC holds enumeration data for one physical NIC.
type pciNIC struct {
	sortKey int    // 0 = virtio, 1 = hardware
	busAddr string // PCI bus address (e.g. "0000:05:00.0")
	name    string // current kernel name (e.g. "enp5s0")
}

// enumerateAndRenameInterfaces assigns vSRX-style names to all PCI NICs.
//
// Standalone (clusterMode=false):
//
//	idx 0 → fxp0, idx 1+ → ge-0-0-{idx-1}
//
// Cluster (clusterMode=true):
//
//	idx 0 → fxp0, idx 1 → em0, idx 2+ → ge-{FPC}-0-{idx-2}
//	FPC = 0 for node 0, FPC = 7 for node 1
//
// userspaceWorkers is the userspace-dp worker count from the active
// config (0 if userspace dataplane is not configured). Used by D3 RSS
// indirection to constrain mlx5 RSS to queues 0..workers-1 before any
// AF_XDP socket binds.
// rssEnabled is the operator kill switch for D3 (#797 review feedback);
// false skips D3 entirely even when userspace-dp has multiple workers.
// rssAllowedInterfaces is the authoritative set of Linux interface
// names that userspace-dp will bind AF_XDP on; D3 only touches
// interfaces in that set (Codex H1 — prevents ethtool from reshaping
// sibling mlx5 PFs or non-userspace-dp netdevs).
func enumerateAndRenameInterfaces(nodeID int, clusterMode bool, userspaceWorkers int, rssEnabled bool, rssAllowedInterfaces []string) error {
	// #5842: through the injectable seam (shared with the device-map path) so
	// the positional error channel is testable end to end, not only per-helper.
	nics, err := enumeratePCINICsFn()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	if len(nics) == 0 {
		slog.Info("linksetup: no PCI network interfaces found")
		return nil
	}

	fpc := 0
	if clusterMode && nodeID == 1 {
		fpc = 7
	}

	// #4178: collision-safe two-pass rename. Capturing every OriginalName
	// BEFORE any write, then breaking target-name collisions with temp
	// names, keeps an enumeration shift (a NIC added/removed/reordered
	// changes the positional index→name map) from corrupting the .link
	// OriginalName= chain or EEXIST-stranding a rename — the discipline
	// device-map mode already had and positional mode previously lacked.
	changed, nameErrs := renamePositional(nics, fpc, clusterMode, renameInterfaceFn)

	// Ensure fxp0 has a bootstrap DHCP .network file (needed before
	// the daemon writes its own networkd configs).
	wrote, err := writeBootstrapFxp0Network()
	if err != nil {
		nameErrs = append(nameErrs, err)
	}
	if wrote {
		changed = true
	}

	if changed {
		if err := networkctlReloadFn(); err != nil {
			slog.Warn("linksetup: networkctl reload failed", "err", err)
			// #5842: a reload failure means the .link set on disk is correct
			// and the RUNNING names are not — precisely the state a caller
			// must not mistake for convergence.
			nameErrs = append(nameErrs, fmt.Errorf("networkctl reload: %w", err))
		}
		slog.Info("linksetup: interface naming updated")
	} else {
		slog.Info("linksetup: interface naming unchanged")
	}

	// #7205: READ THE LIVE NAMES BACK. Everything above reports what was
	// ATTEMPTED; only this reports what took effect. It runs AFTER the reload
	// so a reload that partially applied is visible, and its findings join the
	// same #5842 error channel as a failed rename -- the next-boot and
	// this-boot consequences are identical, so they must not be reported on
	// different channels.
	nameErrs = append(nameErrs, verifyPositionalNames(fpc, clusterMode)...)

	// D3 (#785): constrain mlx5 RSS indirection to queues 0..workers-1
	// on every mlx5_core interface that userspace-dp will bind on.
	// Must run strictly before any AF_XDP bind — that ordering is
	// structurally guaranteed because the dataplane is loaded later in
	// daemon.Run(). The allowlist was derived from the compiled
	// userspace-dp binding plan (Codex H1) so we never touch sibling
	// mlx5 PFs that xpf is not driving.
	applyRSSIndirection(rssEnabled, userspaceWorkers, rssAllowedInterfaces, realRSSExecutor{})

	// #5842: surface any rename / .link-write / reload failure, mirroring the
	// device-map path (#4956). This preserves maybeReapplyConfigArrivalNaming's
	// one-shot emptyHANamingPending marker after a failed accepted standalone
	// config apply, so another accepted standalone config can retry naming.
	// Before #5842 positional mode always returned nil and consumed the marker on
	// failure, leaving no config-arrival retry owner for standalone naming.
	//
	// RSS indirection runs first and unconditionally: it is best-effort tuning
	// keyed on interface names that either did or did not change, and skipping
	// it on a naming error would turn a naming fault into a throughput fault.
	if len(nameErrs) > 0 {
		return fmt.Errorf("linksetup: %d interface rename/write/reload step(s) failed: %w",
			len(nameErrs), errors.Join(nameErrs...))
	}
	return nil
}

// reapplyRSSIndirection re-runs D3 on an already-renamed firewall. Called
// from the daemon reconcile path on every applyConfig, so worker-count
// changes and the enable/disable knob both take effect without a restart.
// Safe to invoke repeatedly: applyRSSIndirection is idempotent (matching
// tables skip the write) and per-interface driver-filtered.
// allowedInterfaces is the userspace-dp binding allowlist; see
// applyRSSIndirection for semantics.
func reapplyRSSIndirection(rssEnabled bool, userspaceWorkers int, allowedInterfaces []string) {
	reapplyRSSIndirectionWith(rssEnabled, userspaceWorkers, allowedInterfaces, realRSSExecutor{})
}

// reapplyRSSIndirectionWith is the injectable variant used by tests so
// the end-to-end commit→reapply→ethtool pipeline can be asserted without
// touching real sysfs.
func reapplyRSSIndirectionWith(rssEnabled bool, userspaceWorkers int, allowedInterfaces []string, execer rssExecutor) {
	applyRSSIndirection(rssEnabled, userspaceWorkers, allowedInterfaces, execer)
}

// enumeratePCINICs discovers all PCI network interfaces via sysfs, sorted
// by driver type (virtio first) then PCI bus address.
func enumeratePCINICs() ([]pciNIC, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}

	var nics []pciNIC
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}

		devicePath := filepath.Join("/sys/class/net", name, "device")
		if _, err := os.Stat(devicePath); err != nil {
			continue // not a PCI device
		}

		// Read driver name.
		driverLink, err := os.Readlink(filepath.Join(devicePath, "driver"))
		if err != nil {
			continue
		}
		driver := filepath.Base(driverLink)

		// Extract PCI bus address from the device symlink target.
		devReal, err := filepath.EvalSymlinks(devicePath)
		if err != nil {
			continue
		}
		busAddr := extractPCIAddr(devReal)
		if busAddr == "" {
			continue
		}

		sk := 1 // hardware
		if driver == "virtio_net" {
			sk = 0
		}
		nics = append(nics, pciNIC{sortKey: sk, busAddr: busAddr, name: name})
	}

	// Sort: virtio first, then by PCI bus address (lexicographic on
	// bus address is equivalent to numeric for same-width addresses).
	sort.Slice(nics, func(i, j int) bool {
		if nics[i].sortKey != nics[j].sortKey {
			return nics[i].sortKey < nics[j].sortKey
		}
		return nics[i].busAddr < nics[j].busAddr
	})

	return nics, nil
}

// extractPCIAddr extracts the last PCI address (DDDD:BB:DD.F) from a sysfs path.
func extractPCIAddr(path string) string {
	// Walk path components and find the last one matching PCI format.
	parts := strings.Split(path, "/")
	var last string
	for _, p := range parts {
		// A PCI address is DDDD:BB:DD.F (>= 12 chars). The length guard must
		// admit index 10 (the '.'), so require >= 11 — a bare >= 10 lets a
		// 10-char component with ':' at 4 and 7 index p[10] out of bounds
		// (AGY r2 Low, hardened now that the bootstrap lifeline path calls
		// extractPCIAddr on arbitrary sysfs components).
		if len(p) >= 11 && p[4] == ':' && p[7] == ':' && p[10] == '.' {
			last = p
		}
	}
	return last
}

// assignName returns the vSRX target name for a given enumeration index.
func assignName(idx, fpc int, clusterMode bool) string {
	if idx == 0 {
		return "fxp0"
	}
	if clusterMode {
		if idx == 1 {
			return "em0"
		}
		return fmt.Sprintf("ge-%d-0-%d", fpc, idx-2)
	}
	return fmt.Sprintf("ge-0-0-%d", idx-1)
}

// renamePositional performs the collision-safe two-pass positional rename
// (#4178). It captures every NIC's OriginalName from the EXISTING .link set
// BEFORE writing any file (so a mid-pass overwrite can never feed a corrupted
// OriginalName into a later NIC's recovery), breaks target-name collisions via
// temp names (so an enumeration shift does not EEXIST-strand a rename), then
// writes each .link with the pre-captured OriginalName and renames to the
// final name. renameFn is injected so production passes renameInterface and
// tests can model EEXIST semantics. Returns true if any .link changed or any
// rename ran.
func renamePositional(nics []pciNIC, fpc int, clusterMode bool, renameFn func(from, to string) error) (bool, []error) {
	// Phase 0: snapshot targets and capture EVERY OriginalName up-front, from
	// the .link set as it exists BEFORE this pass writes anything. This is the
	// core of the #4178 fix: the previous single-pass loop wrote .link file idx
	// then let idx+1's recoverOriginalName read that just-overwritten file, so
	// an enumeration shift corrupted the OriginalName chain.
	desiredByCurrent := make(map[string]string, len(nics))
	originalByCurrent := make(map[string]string, len(nics))
	desiredNames := make(map[string]bool, len(nics))
	currentNames := make([]string, len(nics))
	for idx, nic := range nics {
		target := assignName(idx, fpc, clusterMode)
		desiredByCurrent[nic.name] = target
		originalByCurrent[nic.name] = recoverOriginalName(nic.name)
		desiredNames[target] = true
		currentNames[idx] = nic.name
	}

	// Phase 1: break target-name collisions (shared with the device-map path).
	// After this every desired final name is free. The positional path names
	// every present NIC, so there are no unmapped stranded NICs — the stranded
	// set is empty and ignored.
	_, unfreed, changed := breakNameCollisions("linksetup", currentNames, desiredNames,
		desiredByCurrent, originalByCurrent, renameFn)

	// Phase 2: write each .link with its pre-captured OriginalName and rename
	// to the final name. Collisions are already broken, so no EEXIST here.
	//
	// #5842: errs accumulates every failure so the pass still COMPLETES —
	// abandoning it midway would leave the NIC set half-renamed, which is
	// worse than finishing and reporting — while the caller learns naming did
	// not converge. Mirrors the device-map path's renameErrs (#4956).
	var errs []error
	for current, final := range desiredByCurrent {
		original := originalByCurrent[current]
		if original == "" {
			original = recoverOriginalName(current)
		}
		wrote, err := writeLinkFile(final, original)
		if err != nil {
			errs = append(errs, err)
		}
		if wrote {
			changed = true
		}
		if current != final {
			// #7205: phase 1 could not free this name, so the rename below
			// would EEXIST. Report the real cause instead.
			if unfreed[final] {
				slog.Warn("linksetup: skipping rename onto a name the collision "+
					"break could not free", "from", current, "to", final)
				errs = append(errs, unfreedNameErr("linksetup", current, final))
				continue
			}
			if err := renameFn(current, final); err != nil {
				slog.Warn("linksetup: rename failed",
					"from", current, "to", final, "err", err)
				errs = append(errs, fmt.Errorf("rename %s->%s: %w", current, final, err))
			} else {
				slog.Info("linksetup: renamed interface",
					"from", current, "to", final)
				changed = true
			}
		}
	}
	return changed, errs
}

// breakNameCollisions is the shared phase-1 collision break used by BOTH the
// positional (renamePositional) and device-map (enumerateAndRenameMapped)
// rename paths (#4178). A single-pass rename that renames in enumeration order
// deadlocks when NIC A must take the final name NIC B still holds (a stale-udev
// misrename, or a positional enumeration shift): the rename EEXISTs and is
// dropped. This moves every present NIC that currently wears a DESIRED final
// name — but is not that name's intended final occupant — to a unique
// xpf-tmp-N name first, so the subsequent rename-to-final pass always finds its
// target free.
//
// It mutates desiredByCurrent/originalByCurrent in place: when a NIC that is
// itself a desired SOURCE is temp-renamed, its entry is re-keyed to the temp
// name, carrying the TRUE OriginalName across the temp rename (a transient
// xpf-tmp-N name must never be recorded as OriginalName= — it would not match
// udev on next boot). A temp-stranded NIC that is NOT a desired source is
// returned in stranded (tempName → its pre-temp current name) so the caller can
// restore it to a host-predictable name; the positional caller has no unmapped
// NICs, so it receives an empty map.
//
// currentNames MUST list every present NIC name — it is used both to decide
// occupancy and to pick an xpf-tmp-N that is not already in use (a leftover
// temp name from a prior crashed run must not cause an EEXIST temp rename).
// renameFn is injected so both callers reuse renameInterface (and tests can
// model EEXIST semantics). logPrefix ("linksetup" or "device-map") tags the
// temp-rename logs so they match the surrounding mode's log lines (an operator
// / log-based alerting reading a device-map collision sees "device-map:", not
// a misleading "linksetup:").
func breakNameCollisions(
	logPrefix string,
	currentNames []string,
	desiredNames map[string]bool,
	desiredByCurrent map[string]string,
	originalByCurrent map[string]string,
	renameFn func(from, to string) error,
) (stranded map[string]string, unfreed map[string]bool, changed bool) {
	inUse := make(map[string]bool, len(currentNames))
	for _, name := range currentNames {
		inUse[name] = true
	}
	freeTempName := func() string {
		for k := 0; ; k++ {
			cand := fmt.Sprintf("xpf-tmp-%d", k)
			if !inUse[cand] {
				inUse[cand] = true
				return cand
			}
		}
	}
	stranded = make(map[string]string)
	unfreed = make(map[string]bool)
	for _, name := range currentNames {
		if !desiredNames[name] {
			continue // this NIC's current name is not wanted by anyone
		}
		if final, ok := desiredByCurrent[name]; ok && final == name {
			continue // already correctly named — leave it
		}
		tmp := freeTempName()
		if err := renameFn(name, tmp); err != nil {
			// #7205: this NIC still occupies a DESIRED final name, so phase 2's
			// stated premise -- "collisions are already broken, so no EEXIST
			// here" -- is false for THIS name. Report it rather than letting
			// phase 2 attempt a rename that is guaranteed to EEXIST: the
			// resulting error names the wrong cause and sends the reader at the
			// rename rather than at the collision break that did not happen.
			slog.Warn(logPrefix+": temp-rename to break collision failed; the "+
				"desired name it occupies cannot be claimed this pass",
				"from", name, "to", tmp, "occupies", name, "err", err)
			unfreed[name] = true
			continue
		}
		slog.Info(logPrefix+": temp-renamed conflicting interface", "from", name, "to", tmp)
		changed = true
		if final, ok := desiredByCurrent[name]; ok {
			// This NIC is itself a desired source — carry its mapping and its
			// TRUE OriginalName across the temp rename.
			delete(desiredByCurrent, name)
			desiredByCurrent[tmp] = final
			if orig, ok := originalByCurrent[name]; ok {
				delete(originalByCurrent, name)
				originalByCurrent[tmp] = orig
			}
		} else {
			stranded[tmp] = name
		}
	}
	return stranded, unfreed, changed
}

// unfreedNameErr is the error both rename paths report when phase 1 could not
// free a desired final name (#7205).
//
// Phase 2's premise is "collisions are already broken, so no EEXIST here". A
// failed temp rename in breakNameCollisions falsifies that premise for exactly
// one name, and before this the paths went ahead and attempted the rename
// anyway. The resulting EEXIST is reported -- #7203 gave both paths an error
// channel -- but it names the WRONG cause: it points at the rename, and the
// reader goes looking at udev or the .link file instead of at the collision
// break that did not happen. Refusing the doomed rename and saying why is the
// difference between an error that is loud and one that is useful.
//
// This is deliberately NOT a rollback. Rolling the collision break back would
// mean un-renaming NICs that were successfully moved, which leaves the box in a
// third state that neither phase understands; finishing the pass and reporting
// per-name is the same discipline #5842 chose for phase 2 itself.
func unfreedNameErr(logPrefix, current, final string) error {
	return fmt.Errorf("%s: cannot rename %s -> %s: the collision break could not free "+
		"%q (its current occupant failed to temp-rename), so this rename would EEXIST "+
		"and phase 2's no-collision premise does not hold for this name (#7205)",
		logPrefix, current, final, final)
}

// verifyPositionalNames reads the LIVE interface list back and reports any NIC
// not wearing the name positional naming intended for it (#7205).
//
// renamePositional reports what it ATTEMPTED. It cannot report what took
// effect: a networkctl reload that partially applied, a udev race, or a NIC
// that vanished mid-pass all leave the box running under names the config does
// not reference, with a clean return value. #7203 gave this path an error
// channel; this is what fills it with the thing that actually matters.
//
// Device-map mode has the identity half of this -- enumerateAndRenameMapped
// refuses a binding whose PCI address matches but whose permanent MAC differs,
// so a swapped card is never silently hijacked. Positional mode has no stable
// identity to verify against, because the positional INDEX is the identity. A
// live-name readback is the available substitute: it cannot tell you the right
// NIC got the name, but it can tell you the name is worn at all.
//
// Re-enumeration is sound here because enumeratePCINICs sorts by (sortKey,
// busAddr) -- both PCI-derived and independent of the interface NAME -- so
// index i addresses the same NIC before and after a rename pass. If that sort
// ever became name-dependent this check would silently compare a NIC against
// another NIC's intended name, which is why the ordering is stated here rather
// than assumed.
func verifyPositionalNames(fpc int, clusterMode bool) []error {
	nics, err := enumeratePCINICsFn()
	if err != nil {
		// The readback itself failed, so convergence is UNKNOWN rather than
		// confirmed. Reporting it is the point: silently treating an
		// unreadable interface list as "names are fine" is the fail-open this
		// function exists to remove.
		return []error{fmt.Errorf("verify interface names: re-enumerate NICs: %w", err)}
	}
	var errs []error
	for idx, nic := range nics {
		want := assignName(idx, fpc, clusterMode)
		if nic.name != want {
			slog.Error("linksetup: interface is not wearing its intended name after "+
				"the naming pass", "index", idx, "bus", nic.busAddr,
				"live_name", nic.name, "intended", want)
			errs = append(errs, fmt.Errorf(
				"interface at PCI %s (positional index %d) is named %q but positional "+
					"naming intended %q: the rename did not take effect, so the box is "+
					"running under names the configuration does not reference (#7205)",
				nic.busAddr, idx, nic.name, want))
		}
	}
	return errs
}

// recoverOriginalName returns the OriginalName from an existing .link file
// if the interface was previously renamed, otherwise returns the current name.
func recoverOriginalName(currentName string) string {
	// Search existing .link files for one that renames TO this name.
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return currentName
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), linkPrefix) || !strings.HasSuffix(e.Name(), ".link") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(linkDir, e.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		// Check if this .link file has Name=<currentName>.
		if !containsLine(content, "Name="+currentName) {
			continue
		}
		// Extract OriginalName= value.
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OriginalName=") {
				orig := strings.TrimPrefix(line, "OriginalName=")
				if orig != "" {
					return orig
				}
			}
		}
	}
	return currentName
}

// containsLine checks if the text contains an exact line matching s.
func containsLine(text, s string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == s {
			return true
		}
	}
	return false
}

// writeLinkFile writes a systemd .link file for the given target name.
// Returns (changed, err): changed is true when the file was created or
// rewritten, err is non-nil when the write failed.
//
// #5842: the two were one `bool` before, and `false` meant BOTH "already
// correct, nothing to do" and "the write failed" — opposite facts under one
// value. A caller could not distinguish a converged boot from one where the
// .link set never landed, so a failed write left the NIC un-renamed on the
// next boot with the only trace a WARN nobody polls. The rename path is the
// one that matters: a .link that did not land is a NIC that comes up with its
// kernel name and no zone.
func writeLinkFile(target, originalName string) (bool, error) {
	// #9886: refuse a render-unsafe name BEFORE any mutation — before the
	// path is even built, so a slash/control name cannot escape the managed
	// directory or land on disk in any form. Both slots interpolate raw:
	// target into [Link] Name= (and the file name), originalName into
	// [Match] OriginalName= — itself a whitespace-separated match list, so a
	// multi-pattern original claims devices other than the intended NIC.
	// #10089 adds the separate literal-pattern refusal for glob
	// metacharacters in that [Match] OriginalName= slot; [Link] Name= is
	// non-match syntax and remains literal.
	// Callers surface the error on their existing fail-closed channels
	// (#5842 positional errs, #4956 device-map renameErrs); the rename still
	// proceeds without a .link rather than stranding the NIC mid-pass.
	if !rendersafe.SafeInterfaceName(target) {
		return false, fmt.Errorf("linksetup: refusing .link target name %q: it is not exactly one pattern, carries control bytes, or ends in a line-continuation backslash — no file written (#9886/#10718)", target)
	}
	if !rendersafe.SafeInterfaceName(originalName) {
		return false, fmt.Errorf("linksetup: refusing .link OriginalName %q for target %q: it is not exactly one [Match] OriginalName= pattern, carries control bytes, or ends in a line-continuation backslash — no file written (#9886/#10718)", originalName, target)
	}
	if glob := rendersafe.FirstGlobMetacharacter(originalName); glob != "" {
		return false, fmt.Errorf("linksetup: refusing .link OriginalName %q for target %q: glob metacharacter %q in [Match] OriginalName= would claim every matching interface — no file written (#10089)", originalName, target, glob)
	}
	path := filepath.Join(linkDir, linkPrefix+target+".link")
	content := fmt.Sprintf(`# Managed by xpfd — do not edit
[Match]
OriginalName=%s

[Link]
Name=%s`, originalName, target)

	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false, nil // unchanged
	}

	// AtomicGeneratedConfig: regenerated at daemon start; a torn file is
	// unacceptable but a power-cut loss is re-derived next boot.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("linksetup: failed to write .link file",
			"path", path, "err", err)
		return false, fmt.Errorf("write .link %s: %w", path, err)
	}
	slog.Info("linksetup: wrote .link file",
		"original", originalName, "target", target)
	return true, nil
}

// writeBootstrapFxp0Network writes a bootstrap DHCP .network file for fxp0
// if one doesn't already exist (needed during provisioning before the daemon
// writes its own networkd configs). Returns (changed, err) for the same #5842
// reason as writeLinkFile — a missing bootstrap DHCP file on the management
// NIC is the difference between a reachable box and a console-only one.
func writeBootstrapFxp0Network() (bool, error) {
	path := filepath.Join(linkDir, linkPrefix+"fxp0.network")
	if _, err := os.Stat(path); err == nil {
		return false, nil // already exists
	}

	content := `# Managed by xpfd — bootstrap DHCP for provisioning
[Match]
Name=fxp0

[Network]
DHCP=yes

[DHCPv4]
UseDNS=yes
UseRoutes=yes`

	// AtomicGeneratedConfig: bootstrap provisioning file, re-created if
	// missing on next boot.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("linksetup: failed to write fxp0 .network file",
			"path", path, "err", err)
		return false, fmt.Errorf("write fxp0 .network %s: %w", path, err)
	}
	slog.Info("linksetup: created fxp0 DHCP .network file")
	return true, nil
}

// renameInterface brings the interface down, renames it, and brings it back up.
//
// Failure recovery is asymmetric by design:
//
//   - LinkSetDown failure: the interface is untouched; return immediately.
//   - LinkSetName failure: the rename did NOT happen, so bring the link back
//     up under its original name and return.
//   - LinkSetUp failure (final step): the rename DID happen — the link is now
//     correctly named but DOWN. We must NOT rename it back: doing so would
//     re-create collisions that callers such as the device-map phase-1 path
//     (device_map.go) deliberately broke. Instead retry the bring-up once on
//     the same handle (netlink set operations act on the cached, stable
//     ifindex — not the name — so the handle remains valid across the rename;
//     this holds because LinkByName populates a non-zero Index, making
//     netlink's internal ensureIndex a no-op). On persistent failure return
//     an actionable error: the interface is left correctly named (never
//     stranded under the old name).
//
// Automatic recovery of the DOWN-but-correctly-named link depends on whether
// the interface is managed by systemd-networkd. A *managed* interface (a
// configured ge-*/em0/fxp0/mapped name) has a generated .network and is
// brought up at the next config reconcile (networkd.Apply) — note the
// immediate networkctl reload after the caller's rename loop only brings up
// links that already have a managed .network, so the first-boot ge-* case is
// recovered at the first config apply, not the immediate reload. An *unmanaged*
// interface (e.g. a device-map phase-1 squatter parked under xpf-tmp-N with no
// .network) is NOT brought up automatically — but that DOWN-at-temp-name state
// is the intended/harmless outcome there. The returned error therefore also
// points the operator at the explicit `ip link set <newName> up` recovery so
// the unmanaged case is actionable.
func renameInterface(oldName, newName string) error {
	link, err := nlLinkByName(oldName)
	if err != nil {
		return fmt.Errorf("link %s not found: %w", oldName, err)
	}

	if err := nlLinkSetDown(link); err != nil {
		return fmt.Errorf("link down %s: %w", oldName, err)
	}

	if err := nlLinkSetName(link, newName); err != nil {
		// Rename did not happen — bring the link back up under its
		// original name.
		_ = nlLinkSetUp(link)
		return fmt.Errorf("rename %s -> %s: %w", oldName, newName, err)
	}

	if err := nlLinkSetUp(link); err != nil {
		// The rename already succeeded; the link is correctly named but
		// DOWN. Retry the bring-up once (acts by ifindex; the handle is
		// still valid). Do NOT rename back — that would re-create
		// collisions the device-map collision-break path relies on having
		// broken.
		if retryErr := nlLinkSetUp(link); retryErr != nil {
			return fmt.Errorf(
				"renamed %s -> %s but could not bring it up; interface is "+
					"correctly named but DOWN — if it is managed the next "+
					"config reconcile will bring it up, otherwise run "+
					"`ip link set %s up`: %w",
				oldName, newName, newName, retryErr)
		}
	}

	return nil
}

// networkctlReload calls networkctl reload to apply .link/.network changes.
//
// This is the process's OTHER `networkctl reload` owner: all FIVE daemon-side
// reload sites go through here (the post-rename reload above, device-map's
// rename and teardown reloads via networkctlReloadFn, and bootstrap's teardown
// and lifeline reloads), and all of them write or remove the same 10-xpf-* files
// pkg/networkd generates. #5718 fold F2: report the outcome into networkd's
// process-scoped #4954 activation debt so the two owners cannot disagree. A
// failure here leaves those files on disk unactivated; without the report,
// networkd.Apply's debt would read false and the next Apply with unchanged
// content would skip the reload and return a false success — the exact #4954
// masking the debt exists to prevent, entered through this path instead. Note
// the linksetup call site above is warn-only, so this record is the ONLY thing
// that carries the failure forward.
func networkctlReload() error {
	epoch := networkd.BeginReload()
	out, err := execCommand("networkctl", "reload")
	networkd.NoteReloadResult(epoch, err)
	if err != nil {
		return fmt.Errorf("networkctl reload: %w (output: %s)", err, out)
	}
	return nil
}

// execCommand runs a command under the shared 15s apply-path timeout
// (#1794) and returns combined output. networkctlReload runs while
// applySem is held; an unbounded `networkctl reload` (dbus stall) would
// otherwise wedge every commit.
func execCommand(name string, args ...string) (string, error) {
	out, err := runCommandTimeout(name, args...)
	return string(out), err
}
