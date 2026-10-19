// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// netlink-backed retained MAC identity reader. Tests replace this cold-path
// seam to distinguish a verified match, mismatch, and unreadable observation.
var nicIdentityMACFn = readNICIdentityMAC

type retainedMACVerdict uint8

const (
	retainedMACAbsent retainedMACVerdict = iota
	retainedMACMatch
	retainedMACMismatch
	retainedMACUnreadable
)

// reason is the operator-facing wording for the two removal verdicts, shared
// by the positional and bootstrap paths so they cannot drift. Unreadable never
// says "mismatch": no comparison took place.
func (v retainedMACVerdict) reason() string {
	if v == retainedMACUnreadable {
		return "identity unreadable; comparison unavailable"
	}
	return "identity mismatch"
}

func readNICIdentityMAC(name string) (string, error) {
	link, err := nlLinkByName(name)
	if err != nil {
		return "", err
	}
	attrs := link.Attrs()
	if len(attrs.PermHWAddr) != 0 {
		return attrs.PermHWAddr.String(), nil
	}
	if len(attrs.HardwareAddr) != 0 {
		return attrs.HardwareAddr.String(), nil
	}
	return "", errors.New("link has neither permanent nor running MAC")
}

func verifyRetainedMACLink(currentName string) retainedMACVerdict {
	want := retainedMACAddress(currentName)
	if want == "" {
		return retainedMACAbsent
	}
	got, err := nicIdentityMACFn(currentName)
	if err != nil || strings.TrimSpace(got) == "" {
		return retainedMACUnreadable
	}
	wantMAC, wantErr := net.ParseMAC(strings.TrimSpace(want))
	gotMAC, gotErr := net.ParseMAC(strings.TrimSpace(got))
	if wantErr != nil || gotErr != nil {
		return retainedMACUnreadable
	}
	if !bytes.Equal(wantMAC, gotMAC) {
		return retainedMACMismatch
	}
	return retainedMACMatch
}

// retainedMACAddress returns the MACAddress= value from a name-only managed
// .link. Such a link is the only persistence shape whose identity needs this
// check; OriginalName= links and files without a MAC remain unchanged.
func retainedMACAddress(currentName string) string {
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return ""
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
		if !containsLine(content, "Name="+currentName) || strings.Contains(content, "OriginalName=") {
			continue
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "MACAddress=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "MACAddress="))
			}
		}
	}
	return ""
}

type pciNIC struct {
	sortKey      int    // 0 = virtio, 1 = hardware
	busAddr      string // PCI bus address (e.g. "0000:05:00.0")
	name         string // current kernel name (e.g. "enp5s0")
	devPort      int    // kernel dev_port; -1 when unavailable
	physPortName string // kernel phys_port_name; empty when unavailable
}

// sysClassNetRoot is package-global to let enumeration tests exercise the
// real sysfs walk against a synthetic tree. Production leaves it unchanged.
var sysClassNetRoot = "/sys/class/net"

// liveInterfaceNamesFn lists the live kernel interface names. It backs
// #15044's occupancy scan for live non-PCI NICs already wearing a
// positional name; production reads sysfs, tests inject a fixture list.
var liveInterfaceNamesFn = func() ([]string, error) {
	entries, err := os.ReadDir(sysClassNetRoot)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// isPositionalName reports whether name is one positional naming assigns
// (fxp0, cluster em0, ge-<fpc>-0-<n> for either FPC). Deliberately
// syntactic: any live netdev wearing such a name is a positional holder
// for #15044 occupancy purposes, whatever bus it sits on.
func isPositionalName(name string, clusterMode bool) bool {
	if name == "fxp0" {
		return true
	}
	if clusterMode && name == "em0" {
		return true
	}
	var fpc, idx int
	if n, err := fmt.Sscanf(name, "ge-%d-0-%d", &fpc, &idx); err != nil || n != 2 {
		return false
	}
	// Sscanf accepts trailing junk ("ge-0-0-1x"); require exact round-trip.
	return name == fmt.Sprintf("ge-%d-0-%d", fpc, idx) && (fpc == 0 || fpc == 7)
}

// livePositionalHolders returns the sorted live interface names that wear
// a positional name but are NOT among the enumerated PCI NICs. Under
// #14595 enumeratePCINICs skips every non-PCI netdev, so a USB NIC that
// a pre-#14595 build named fxp0 (the controller's BDF sorted ahead of the
// PCI NICs) is invisible to renamePositional: without this scan its slot
// is handed to a PCI NIC, 10-xpf-fxp0.link is rewritten to that NIC's
// kernel name before the rename EEXISTs (warn-only at the boot caller),
// and the next boot rebinds fxp0 onto the PCI cable (#15044). A scan
// error is returned so the caller fails closed instead of re-indexing
// blind.
func livePositionalHolders(nics []pciNIC, clusterMode bool) ([]string, error) {
	live, err := liveInterfaceNamesFn()
	if err != nil {
		return nil, err
	}
	enumerated := make(map[string]bool, len(nics))
	for _, nic := range nics {
		enumerated[nic.name] = true
	}
	var holders []string
	for _, name := range live {
		if enumerated[name] || !isPositionalName(name, clusterMode) {
			continue
		}
		holders = append(holders, name)
	}
	sort.Strings(holders)
	return holders, nil
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
// indirection to constrain RSS to queues 0..workers-1 on every
// capability-probed bound interface before any AF_XDP socket binds.
// rssEnabled is the operator kill switch for D3 (#797 review feedback);
// false skips D3 entirely even when userspace-dp has multiple workers.
// rssAllowedInterfaces is the authoritative set of Linux interface
// names that userspace-dp will bind AF_XDP on; D3 only touches
// interfaces in that set (Codex H1 — prevents ethtool from reshaping
// sibling PFs or non-userspace-dp netdevs).
func enumerateAndRenameInterfaces(nodeID int, clusterMode bool, userspaceWorkers int, rssEnabled bool, rssAllowedInterfaces []string) error {
	// #5842: through the injectable seam (shared with the device-map path) so
	// the positional error channel is testable end to end, not only per-helper.
	nics, err := enumeratePCINICsFn()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	// #15044: a live non-PCI NIC (e.g. a USB NIC a pre-#14595 build named
	// fxp0 via its xHCI controller's BDF) already wearing a positional
	// name is invisible to the PCI enumeration above. Re-indexing around
	// it would rewrite its 10-xpf-<name>.link onto a PCI NIC and rebind
	// the name to a different cable on the next boot. Refuse loudly
	// before any .link write or rename; the operator resolves it with a
	// chassis device-map or by removing the stale name. This runs even
	// when no PCI NICs exist: a lone USB holder must not be silently
	// ignored while its .link still claims the name. A scan failure is
	// likewise fatal — re-indexing blind is the fail-open being removed.
	holders, err := livePositionalHolders(nics, clusterMode)
	if err != nil {
		return fmt.Errorf("linksetup: cannot list live interfaces to check for "+
			"non-PCI positional name holders (#15044): %w", err)
	}
	if len(holders) > 0 {
		return fmt.Errorf("linksetup: refusing positional re-indexing: live "+
			"non-PCI interface(s) %s already wear positional name(s) that the "+
			"PCI enumeration cannot see (#15044); renaming would rewrite "+
			"their .link files onto PCI NICs and rebind the names on the "+
			"next boot — configure a chassis device-map for these NICs or "+
			"remove the stale positional names", strings.Join(holders, ", "))
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

	// D3 (#785): constrain RSS indirection to queues 0..workers-1 on
	// every capability-probed interface that userspace-dp will bind on
	// (#9040: eligibility is a readable indirection table, not mlx5_core).
	// Must run strictly before any AF_XDP bind — that ordering is
	// structurally guaranteed because the dataplane is loaded later in
	// daemon.Run(). The allowlist was derived from the compiled
	// userspace-dp binding plan (Codex H1) so we never touch sibling
	// PFs that xpf is not driving.
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
// by driver type (virtio first), PCI bus address, then hardware port identity.
func enumeratePCINICs() ([]pciNIC, error) {
	entries, err := os.ReadDir(sysClassNetRoot)
	if err != nil {
		return nil, err
	}

	var nics []pciNIC
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}

		netPath := filepath.Join(sysClassNetRoot, name)
		devicePath := filepath.Join(netPath, "device")
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
		devPort := -1
		if data, err := os.ReadFile(filepath.Join(netPath, "dev_port")); err == nil {
			if parsed, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && parsed >= 0 {
				devPort = parsed
			}
		}
		physPortName := ""
		if data, err := os.ReadFile(filepath.Join(netPath, "phys_port_name")); err == nil {
			physPortName = strings.TrimSpace(string(data))
		}
		nics = append(nics, pciNIC{
			sortKey: sk, busAddr: busAddr, name: name,
			devPort: devPort, physPortName: physPortName,
		})
	}

	sort.Slice(nics, func(i, j int) bool {
		a, b := nics[i], nics[j]
		if a.sortKey != b.sortKey {
			return a.sortKey < b.sortKey
		}
		if a.busAddr != b.busAddr {
			return a.busAddr < b.busAddr
		}
		// A known port number is a stronger hardware identity than a
		// representor label; unknown values sort after known ones.
		if (a.devPort >= 0) != (b.devPort >= 0) {
			return a.devPort >= 0
		}
		if a.devPort >= 0 && a.devPort != b.devPort {
			return a.devPort < b.devPort
		}
		if a.physPortName != b.physPortName {
			if a.physPortName == "" {
				return false
			}
			if b.physPortName == "" {
				return true
			}
			if lessPhysPortName(a.physPortName, b.physPortName) {
				return true
			}
			if lessPhysPortName(b.physPortName, a.physPortName) {
				return false
			}
		}
		return a.name < b.name
	})

	return nics, nil
}

// lessPhysPortName compares the digit runs numerically (for example,
// pf0vf2 before pf0vf10) and otherwise compares bytes. Empty/unparseable
// names still have deterministic ordering through the original text.
func lessPhysPortName(a, b string) bool {
	for len(a) > 0 && len(b) > 0 {
		if a[0] >= '0' && a[0] <= '9' && b[0] >= '0' && b[0] <= '9' {
			endA, endB := 0, 0
			for endA < len(a) && a[endA] >= '0' && a[endA] <= '9' {
				endA++
			}
			for endB < len(b) && b[endB] >= '0' && b[endB] <= '9' {
				endB++
			}
			numA, errA := strconv.ParseUint(a[:endA], 10, 64)
			numB, errB := strconv.ParseUint(b[:endB], 10, 64)
			if errA == nil && errB == nil && numA != numB {
				return numA < numB
			}
			if len(a[:endA]) != len(b[:endB]) {
				return len(a[:endA]) < len(b[:endB])
			}
			a, b = a[endA:], b[endB:]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

// extractPCIAddr extracts the PCI address (DDDD:BB:DD.F) from a sysfs
// device path. Every caller passes the resolved `device` symlink
// target. A PCI netdev's target ends in the device's own BDF (possibly
// below PCI bridges / a root port), so that BDF names this device; a
// virtio netdev's target ends in `virtioN` directly below its PCI
// function, which is a 1:1 channel to that function, so the parent
// BDF likewise names this device (enumeratePCINICs enumerates
// virtio_net under it, sorted first). Any other final component means
// the device sits on a NON-PCI bus below the last PCI ancestor, and
// that ancestor's BDF must NOT be reported as this device's address
// (#14595): on x86 a USB NIC hangs off an xHCI controller
// (…/0000:00:14.0/usb2/2-1/2-1:1.0), and reporting the controller's BDF
// gave every NIC behind one controller one shared "PCI address" in the
// device-map candidates. Returns "" for a non-PCI device;
// enumeratePCINICs then skips it (it has no PCI positional identity),
// while the device-map inventory keeps it via its permanent MAC
// (#4884). Mirrors devicemap.ExtractPCIAddr so the two enumerations
// cannot drift.
func extractPCIAddr(path string) string {
	// The length guard must admit index 10 (the '.'), so require
	// >= 11 — a bare >= 10 lets a 10-char component with ':' at 4 and
	// 7 index p[10] out of bounds (AGY r2 Low, hardened now that the
	// bootstrap lifeline path calls extractPCIAddr on arbitrary sysfs
	// components).
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	if len(last) >= 11 && last[4] == ':' && last[7] == ':' && last[10] == '.' {
		return last
	}
	if isVirtioComponent(last) {
		// virtioN directly below a PCI function: report that function.
		for i := len(parts) - 2; i >= 0; i-- {
			p := parts[i]
			if len(p) >= 11 && p[4] == ':' && p[7] == ':' && p[10] == '.' {
				return p
			}
		}
	}
	return ""
}

// isVirtioComponent reports whether a sysfs path component is a virtio
// device directory (`virtio0`, `virtio12`, …).
func isVirtioComponent(p string) bool {
	if !strings.HasPrefix(p, "virtio") || len(p) == len("virtio") {
		return false
	}
	for _, c := range p[len("virtio"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
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
// (#4178). It captures each verified OriginalName (or an unknown sentinel)
// from the EXISTING .link set BEFORE writing any file (so a mid-pass overwrite
// can never feed a corrupted OriginalName into a later NIC's recovery), breaks
// target-name collisions via temp names (so an enumeration shift does not
// EEXIST-strand a rename), then writes eligible .link files and renames to the
// target. On a target change it removes MAC-form claims only after confirming
// that their MAC belongs to this NIC; a foreign claim remains for its owner.
// renameFn is injected so production passes renameInterface and tests can
// model EEXIST semantics. Returns true if any .link changed or any rename ran.
func renamePositional(nics []pciNIC, fpc int, clusterMode bool, renameFn func(from, to string) error) (bool, []error) {
	// Phase 0: snapshot targets and capture each verified OriginalName or
	// unknown sentinel up-front, from the .link set as it exists BEFORE this
	// pass writes anything. This is the core of the #4178 fix: the previous
	// single-pass loop wrote .link file idx then let idx+1's recovery read that
	// just-overwritten file, so an enumeration shift corrupted the chain.
	desiredByCurrent := make(map[string]string, len(nics))
	originalByCurrent := make(map[string]string, len(nics))
	identityMACByCurrent := make(map[string]string, len(nics))
	identityErrByCurrent := make(map[string]error, len(nics))
	desiredNames := make(map[string]bool, len(nics))
	currentNames := make([]string, len(nics))
	for idx, nic := range nics {
		target := assignName(idx, fpc, clusterMode)
		desiredByCurrent[nic.name] = target
		if original, ok := positionalOriginalNameFor(nic.name, target); ok {
			originalByCurrent[nic.name] = original
		} else {
			// #12156: a 10-xpf .link assigns this current name without
			// recording its kernel original, or the NIC already wears its
			// target name without any original record. Carry "unknown" through
			// the shared collision-break re-keying without manufacturing
			// OriginalName=<logical name>.
			originalByCurrent[nic.name] = originalNameUnknown
			logUnknownOriginalLinkSkip("linksetup", nic.name, target)
		}
		if originalByCurrent[nic.name] == originalNameUnknown &&
			(linkMACAddressFromFile(linkPrefix+nic.name+".link") ||
				linkMACAddressFromFile(linkPrefix+target+".link")) {
			identityMACByCurrent[nic.name], identityErrByCurrent[nic.name] = nicIdentityMACFn(nic.name)
		}
		desiredNames[target] = true
		currentNames[idx] = nic.name
	}

	// Phase 1: break target-name collisions (shared with the device-map path).
	// After this every desired final name is free. The positional path names
	// every present NIC, so there are no unmapped stranded NICs — the stranded
	// set is empty and ignored.
	_, preTemp, unfreed, changed := breakNameCollisions("linksetup", currentNames, desiredNames,
		desiredByCurrent, originalByCurrent, renameFn)

	// Phase 2: write each .link with its pre-captured OriginalName and rename
	// to the final name. Collisions are already broken, so no EEXIST here.
	//
	// #5842: errs accumulates every failure so the pass still COMPLETES —
	// abandoning it midway would leave the NIC set half-renamed, which is
	// worse than finishing and reporting — while the caller learns naming did
	// not converge. Mirrors the device-map path's renameErrs (#4956).
	// MINOR-3: unknown NICs run BEFORE any known NIC writes (order within
	// each class is still map order). Every neutralize lands before the
	// known owner's writeLinkFile, so no map order can interleave a
	// neutralize between the owner's write and the end of the pass. A
	// failed owner write leaves NO claim behind (fail-closed: nothing was
	// spared) whether the unknown's own temp rename FAILED (unfreed
	// current, so its O.link is named by current) or SUCCEEDED (the
	// phase-2 key is xpf-tmp-N, so the O.link is removed under the
	// pre-temp name that breakNameCollisions returns in preTemp, #12557).
	// The ordering key must match the loop's unknown predicate, including
	// the collided-temp "" re-derivation below — hence the helper.
	var errs []error
	// resolvedOriginal is the loop's unknown predicate: the pre-captured
	// value, or the re-derivation for collided-temp currents whose capture
	// is "". The unknowns-first ordering MUST use it (not the raw map),
	// or a re-derived unknown would sort as known.
	resolvedOriginal := func(current, final string) string {
		if original := originalByCurrent[current]; original != "" {
			return original
		}
		if original, ok := positionalOriginalNameFor(current, final); ok {
			return original
		}
		return originalNameUnknown
	}
	orderedCurrents := make([]string, 0, len(desiredByCurrent))
	for current, final := range desiredByCurrent {
		if resolvedOriginal(current, final) == originalNameUnknown {
			orderedCurrents = append(orderedCurrents, current)
		}
	}
	for current, final := range desiredByCurrent {
		if resolvedOriginal(current, final) != originalNameUnknown {
			orderedCurrents = append(orderedCurrents, current)
		}
	}
	for _, current := range orderedCurrents {
		final := desiredByCurrent[current]
		original := resolvedOriginal(current, final)
		if original == originalNameUnknown {
			// #12156: no udev-matchable kernel original is known. On the
			// same-name path the .link write is skipped (a retained name-only
			// link stays; the phase-0 log tells that apart from the absence
			// of usable persistence). On the target-change path the
			// resurrectable claims are neutralized instead (MAJOR-1 below).
			if current == final {
				switch verdict := verifyRetainedMACLink(current); verdict {
				case retainedMACMismatch, retainedMACUnreadable:
					reason := verdict.reason()
					name := linkPrefix + current + ".link"
					if err := neutralizeResurrectableLink(name); err != nil {
						slog.Error("linksetup: retained MAC-form .link "+reason+
							"; could not remove the file, so it may still claim this name on a later boot",
							"interface", current, "file", name, "err", err)
						errs = append(errs, fmt.Errorf("linksetup: retained MAC-form .link for %s has %s; removal failed (#12550): %w", current, reason, err))
					} else {
						changed = true
						slog.Error("linksetup: retained MAC-form .link "+reason+
							"; removed the file so it cannot claim this name on a later boot",
							"interface", current)
						errs = append(errs, fmt.Errorf("linksetup: retained MAC-form .link for %s has %s; persistence removed (#12550)", current, reason))
					}
				}
				continue
			}
			// MAJOR-1: an unknown NIC changing target MUST NOT leave
			// resurrectable claims behind. Its own name-only O.link (whose
			// MAC still matches it) and any stale T.link (another NIC's
			// claim) would each re-apply at the next boot and put a NIC up
			// under ANOTHER NIC's logical name — fail-open. Remove claims
			// whose MAC is verified as this NIC's, preserve foreign claims,
			// and rename as required (stranding is worse).
			// Persistence loss is reported via the phase-2 ERROR log below,
			// not the #5842 errs channel (errs carries only failures: a
			// neutralize that fails, a failed rename, or the #7205 unfreed
			// error).
			// An unknown NIC that failed its own temp rename still wears
			// another NIC's final name. With the unknowns-first ordering
			// above, this neutralize runs BEFORE the known owner's
			// writeLinkFile(final, original) call in the else branch below,
			// so there is no map-order race: the owner always rewrites its
			// own name after every neutralize. A failed owner write leaves
			// no removable claim belonging to the unknown behind; foreign
			// MAC-form claims remain with their owner.
			// current may be xpf-tmp-N; use the pre-temp name and its
			// phase-0 MAC snapshot to verify the O.link claim (#12557).
			removeName := current
			if pre, ok := preTemp[current]; ok {
				removeName = pre
			}
			neutralized := true
			for _, name := range []string{linkPrefix + removeName + ".link", linkPrefix + final + ".link"} {
				removed, err := neutralizeResurrectableLinkForMAC(name,
					identityMACByCurrent[removeName], identityErrByCurrent[removeName])
				if err != nil {
					neutralized = false
					slog.Error("linksetup: failed to neutralize resurrectable .link",
						"file", name, "err", err)
					errs = append(errs, err)
				}
				if removed {
					changed = true
				}
			}
			if neutralized {
				slog.Error("linksetup: unknown-original NIC changed target without a "+
					"verifiable kernel name; neutralized retained .link claims (preserving "+
					"claims with a foreign or unverifiable MAC) so the next boot falls back to kernel names",
					"from", current, "to", final)
			}
		} else {
			wrote, err := writeLinkFile(final, original)
			if err != nil {
				errs = append(errs, err)
			}
			if wrote {
				changed = true
			}
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

// positionalOriginalNameFor determines whether positional naming has a
// udev-matchable OriginalName for this NIC. A previously recorded name is
// verified by the existing .link chain. With no recorded original and no
// name-only .link assigning the current name, a NIC whose current name
// differs from its assigned final name is ASSUMED under its kernel name
// (first rename). That assumption is FALSE for a NIC renamed in memory by
// an earlier pass of this same boot (shift-back writes OriginalName=<logical>
// there — MINOR-3, residual): without a kernel-name oracle the gate cannot
// tell, so that shape still emits a logical original. A 10-xpf .link that
// assigns the current name without an OriginalName= means the current name
// is logical and the kernel original is unknown whatever the final name is
// (#12156/F1).
func positionalOriginalNameFor(current, final string) (string, bool) {
	original, matchedNameOnly, _ := recoverOriginalName(current)
	if original != current {
		return original, true
	}
	if matchedNameOnly {
		return "", false
	}
	if current != final {
		return current, true
	}
	return "", false
}

// logUnknownOriginalLinkSkip distinguishes a matching name-only link from the
// absence of usable persistence. When the NIC is already at its final name
// the skip is benign (no target change, nothing to persist): MAC-form links
// log at Info, missing persistence at Warn. When the NIC must still rename
// (the F1 path), no persistence exists for the target and the retained file
// will be neutralized — that logs at ERROR like the device-map analogue
// (MINOR-4: Info-only there is fail-quiet on the F1 path itself).
func logUnknownOriginalLinkSkip(logPrefix, current, final string) {
	_, matchedNameOnly, matchedMAC := recoverOriginalName(current)
	if current != final {
		slog.Error(logPrefix+": unknown-original NIC must rename without a "+
			"verifiable kernel name; no persistence exists for the target",
			"current", current, "logical", final)
		return
	}
	if matchedNameOnly {
		if matchedMAC {
			slog.Info(logPrefix+": existing MAC-form .link found; skipping an "+
				"unmatchable OriginalName= write",
				"current", current, "logical", final)
		} else {
			slog.Info(logPrefix+": existing name-only .link found; skipping an "+
				"unmatchable OriginalName= write",
				"current", current, "logical", final)
		}
		return
	}
	slog.Warn(logPrefix+": cannot determine the pre-rename kernel name for "+
		"this NIC and no usable .link exists to retain; skipping the .link write "+
		"instead of persisting an unmatchable OriginalName=. Boot-time persistence "+
		"is NOT established.",
		"current", current, "logical", final)
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
// A temp-renamed desired source is returned in preTemp (tempName → its
// pre-temp current name), so the caller can still find the .link filed under
// the name the NIC wore before phase 1: both callers neutralize an
// unknown-original NIC's O.link under that name (#12557, #12718).
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
) (stranded map[string]string, preTemp map[string]string, unfreed map[string]bool, changed bool) {
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
	preTemp = make(map[string]string)
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
			// TRUE OriginalName across the temp rename and retain its original
			// link filename for the caller's cleanup.
			delete(desiredByCurrent, name)
			desiredByCurrent[tmp] = final
			preTemp[tmp] = name
			if orig, ok := originalByCurrent[name]; ok {
				delete(originalByCurrent, name)
				originalByCurrent[tmp] = orig
			}
		} else {
			stranded[tmp] = name
		}
	}
	return stranded, preTemp, unfreed, changed
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
// Re-enumeration is sound here because enumeratePCINICs sorts by
// (sortKey, busAddr, dev_port, phys_port_name, name). The port identity
// fields keep shared-function multiport NICs at the same index across
// interface renames; name is only a final fallback when sysfs has no
// distinguishing port metadata. Reordering sysfs metadata can otherwise
// compare a NIC against another NIC's intended name.
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

// recoverOriginalName returns the OriginalName from an existing 10-xpf .link
// that names currentName, plus whether a matching Name= has no recorded
// OriginalName= and whether that name-only link matches by MACAddress=. The
// distinction matters because Name=<current> without OriginalName= proves the
// NIC already wears a logical name, not its kernel name (#12156/F1).
func recoverOriginalName(currentName string) (original string, matchedNameOnly, matchedMAC bool) {
	// Search existing .link files for one that renames TO this name.
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return currentName, false, false
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
		var recordedOriginal string
		hasMACMatch := false
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OriginalName=") {
				recordedOriginal = strings.TrimPrefix(line, "OriginalName=")
			}
			if strings.HasPrefix(line, "MACAddress=") &&
				strings.TrimSpace(strings.TrimPrefix(line, "MACAddress=")) != "" {
				hasMACMatch = true
			}
		}
		if recordedOriginal != "" {
			return recordedOriginal, false, false
		}
		matchedNameOnly = true
		matchedMAC = matchedMAC || hasMACMatch
	}
	return currentName, matchedNameOnly, matchedMAC
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

// neutralizeResurrectableLink removes a managed .link file that udev could
// otherwise re-apply at the next boot. Missing files are not errors; only
// xpfd-managed names are ever removed.
func neutralizeResurrectableLink(name string) error {
	if !strings.HasPrefix(name, linkPrefix) || !strings.HasSuffix(name, ".link") {
		return fmt.Errorf("linksetup: refusing to remove unmanaged link file %q", name)
	}
	path := filepath.Join(linkDir, name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove resurrectable .link %s: %w", path, err)
	}
	return nil
}

func neutralizeResurrectableLinkForNIC(name, nicName string) (bool, error) {
	if !linkMACAddressFromFile(name) {
		return neutralizeResurrectableLinkForMAC(name, "", nil)
	}
	nicMAC, identityErr := nicIdentityMACFn(nicName)
	return neutralizeResurrectableLinkForMAC(name, nicMAC, identityErr)
}

// neutralizeResurrectableLinkForMAC verifies MAC ownership before deleting a
// managed link. Filename equality does not establish ownership: a mismatch
// or unreadable identity preserves the claim, while links without a MAC
// retain their prior cleanup behavior.
func neutralizeResurrectableLinkForMAC(name, nicMAC string, identityErr error) (bool, error) {
	if !strings.HasPrefix(name, linkPrefix) || !strings.HasSuffix(name, ".link") {
		return false, fmt.Errorf("linksetup: refusing to remove unmanaged link file %q", name)
	}
	path := filepath.Join(linkDir, name)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read resurrectable .link %s before removal: %w", path, err)
	}
	fileMAC, hasMAC := linkMACAddress(string(data))
	if hasMAC {
		if identityErr != nil || strings.TrimSpace(nicMAC) == "" {
			if identityErr == nil {
				identityErr = errors.New("NIC MAC is empty")
			}
			return false, fmt.Errorf("linksetup: cannot verify MAC ownership of %s; preserving claim: %w", path, identityErr)
		}
		wantMAC, wantErr := net.ParseMAC(strings.TrimSpace(nicMAC))
		fileMACParsed, fileErr := net.ParseMAC(strings.TrimSpace(fileMAC))
		if wantErr != nil || fileErr != nil {
			return false, fmt.Errorf("linksetup: cannot verify MAC ownership of %s; preserving claim: invalid MACAddress or NIC MAC", path)
		}
		if !bytes.Equal(wantMAC, fileMACParsed) {
			slog.Info("linksetup: preserving MAC-form .link owned by another NIC",
				"file", name)
			return false, nil
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove resurrectable .link %s: %w", path, err)
	}
	return true, nil
}

func linkMACAddressFromFile(name string) bool {
	data, err := os.ReadFile(filepath.Join(linkDir, name))
	if err != nil {
		return false
	}
	_, hasMAC := linkMACAddress(string(data))
	return hasMAC
}

func linkMACAddress(content string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MACAddress=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "MACAddress=")), true
		}
	}
	return "", false
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
	// metacharacters in that [Match] OriginalName= slot; #15079 adds the
	// same refusal for a leading '!', systemd's list-inversion prefix,
	// which would make the .link claim every device except the named one;
	// [Link] Name= is non-match syntax and remains literal on both counts.
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
	if rendersafe.IsNegatedMatchPattern(originalName) {
		return false, fmt.Errorf("linksetup: refusing .link OriginalName %q for target %q: a leading '!' in [Match] OriginalName= inverts the match list and would claim every interface except the named one — no file written (#15079)", originalName, target)
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
