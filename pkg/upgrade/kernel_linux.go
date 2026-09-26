package upgrade

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/fsatomic"
	"golang.org/x/sys/unix"
)

// efibootmgr can block indefinitely while firmware services NVRAM. Keep each
// operation well inside xpf-kernel-promote.service's 120-second start timeout,
// leaving time for Promote to persist a counted revert instead of letting
// systemd take its uncounted OnFailure reboot path.
var kernelNVRAMTimeout = 10 * time.Second

var (
	// An efibootmgr entry line is "BootXXXX*<sp>LABEL<TAB>loader-path"
	// (active entries have the '*', inactive do not). The LABEL is the field
	// between the id and the TAB that introduces the device/loader path —
	// capture ONLY the label, not the trailing tab+path (a `(.+)` greedy
	// capture would fold the whole path into the key — caught live, #1930).
	// Some entries have no loader path (no tab) — `[^\t]+` then tolerates EOL.
	bootEntryRE          = regexp.MustCompile(`^Boot([0-9A-F]{4})\*?\s+([^\t]+?)(?:\t.*)?$`)
	bootCurrentRE        = regexp.MustCompile(`^BootCurrent:\s*([0-9A-F]{4})`)
	bootNextRE           = regexp.MustCompile(`^BootNext:\s*([0-9A-F]{4})`)
	slotSelectorKernelRE = regexp.MustCompile(`xpf_slot_kernel="vmlinuz-([^"]+)"`)
)

// realKernelSystem is the production KernelSystem backed by UEFI, apt, GRUB,
// systemd, and the Linux watchdog device.
type realKernelSystem struct {
	// ProbeFunc is wired by the caller when a richer forward-health probe is
	// available (e.g. xpfd with its dataplane manager). When nil, ForwardBeacon
	// does a real reachability ping through the dataplane to BeaconTarget.
	ProbeFunc func(deadline time.Time) (bool, error)
	// BeaconTarget is the ForwardBeacon ping target; empty -> the IPv4 default
	// gateway. Set via XPF_KERNEL_BEACON_TARGET for a topology-specific peer.
	BeaconTarget string

	// UnitActive is Gate 4's precondition-A probe: is xpfd up at all. nil ->
	// unitActiveProbeCtx(ctx, DefaultUnit), the package's SINGLE is-active
	// primitive. Injectable for the same reason HelperHealthDeps.UnitActive is
	// (#5286/#5808): BOTH of Gate 4's preconditions have to be drivable from one
	// place, or a test can only ever reach whichever one the host it runs on
	// happens to satisfy.
	UnitActive func(ctx context.Context) (bool, error)
	// HelperStatus is Gate 4's dataplane-liveness probe (#6607): the
	// control-socket status query, adapted to the same primitive tuple the
	// binary channel's helper-readiness gate consumes (HelperStatusFunc). It is
	// wired by cmd/xpfd, which owns the dataplane package; pkg/upgrade
	// deliberately does not import pkg/dataplane/userspace (see helper_health.go).
	//
	// nil means NO dataplane probe is available to this caller, and ForwardBeacon
	// then falls back to the xpfd-liveness-plus-ping check alone — documented as
	// the weaker statement it is. Production always wires it.
	HelperStatus HelperStatusFunc
	// ControlSocket is the helper control-socket path HelperStatus queries,
	// resolved from the active config by the caller (honoring an operator
	// `system dataplane control-socket` override).
	ControlSocket string
	// StatusTimeout bounds a single control-socket status query (default 2s).
	StatusTimeout time.Duration

	// IsManagementIface classifies a KERNEL INTERFACE NAME as management
	// (out-of-band) rather than dataplane, for ForwardBeacon's #7157 target
	// eligibility check. Injected for the same reason HelperStatus is: the
	// answer belongs to config.IsManagementIfName — the #7515 SSOT already
	// shared by the daemon's vrf-mgmt binder, the networkd `VRF=` emitter and
	// the ip-monitoring next-hop validator — and pkg/upgrade deliberately does
	// not import pkg/config. Passing the SSOT rather than copying its three
	// prefixes is the point: #7515 records that a divergence between the
	// consumers of that rule is always a bug, and this is a fourth consumer.
	//
	// nil means this caller cannot classify interfaces, which is treated as "no
	// information" and NOT as ineligible — the same contract the nil-HelperStatus
	// branch documents below, and for the same reason (failing closed on a
	// missing seam reverts every embedder's promotion). Both production
	// constructors wire it, and that claim is bound by a test rather than left
	// to this comment.
	IsManagementIface func(iface string) bool

	// Test seams (#5076). All nil/"" in production; a test injects them to
	// drive the purge-failure path deterministically without shelling out to
	// apt/dpkg or touching the real /boot + /lib/modules.
	//
	//   aptGetFn       overrides the apt-get invocation (purge, install).
	//   pkgInstalledFn overrides the dpkg "is this package installed?" query.
	//                  It is TRI-STATE (installed, queryErr): a non-nil queryErr
	//                  means dpkg's status could not be determined and callers on
	//                  a destructive path must fail SAFE (#5428).
	//   fsRoot         prefixes the /boot + /lib/modules paths the prune sweep
	//                  and the slot selector touch, so a test can assert
	//                  against a temp-rooted filesystem.
	aptGetFn       func(args ...string) error
	pkgInstalledFn func(pkg string) (bool, error)
	fsRoot         string
}

// aptGetCmd runs apt-get through the injected seam when present, else the real
// apt-get helper.
func (s *realKernelSystem) aptGetCmd(args ...string) error {
	if s.aptGetFn != nil {
		return s.aptGetFn(args...)
	}
	return aptGet(args...)
}

// pkgInstalled reports whether a package is installed AND whether the dpkg
// query itself succeeded, through the injected seam when present, else a real
// dpkg-query. It is TRI-STATE (installed / not-installed / query-error): a
// non-nil error means the status could NOT be determined (dpkg-DB corruption,
// lock, missing binary). Callers on a path that then deletes package-owned
// files MUST treat a query error as POSSIBLY-INSTALLED and fail safe — never as
// "removed" (#5428).
func (s *realKernelSystem) pkgInstalled(pkg string) (bool, error) {
	if s.pkgInstalledFn != nil {
		return s.pkgInstalledFn(pkg)
	}
	return isPkgInstalled(pkg)
}

// rooted prefixes an absolute path with fsRoot (empty in production -> the path
// is returned unchanged). Lets tests confine package-owned file operations to a
// temp directory.
func (s *realKernelSystem) rooted(p string) string {
	if s.fsRoot == "" {
		return p
	}
	return filepath.Join(s.fsRoot, p)
}

var _ KernelSystem = (*realKernelSystem)(nil)

// NewKernelSystem returns the production KernelSystem implementation. The
// forward-beacon target may be pinned via XPF_KERNEL_BEACON_TARGET (else the
// IPv4 default gateway is used).
func NewKernelSystem() *realKernelSystem {
	return &realKernelSystem{BeaconTarget: os.Getenv("XPF_KERNEL_BEACON_TARGET")}
}

// NewKernelSystemWithHelperStatus returns the production KernelSystem with Gate
// 4's dataplane-liveness probe wired (#6607). It mirrors
// NewSystemWithHelperHealth, which does the same job for the BINARY channel's
// post-cut readiness gate: pkg/upgrade owns the gate logic, cmd/xpfd injects the
// dataplane primitives so this package need not import (and cannot cycle with)
// pkg/dataplane/userspace.
func NewKernelSystemWithHelperStatus(
	unitActive func(ctx context.Context) (bool, error),
	status HelperStatusFunc,
	controlSocket string,
	isManagementIface func(iface string) bool,
) *realKernelSystem {
	s := NewKernelSystem()
	s.UnitActive = unitActive
	s.HelperStatus = status
	s.ControlSocket = controlSocket
	s.IsManagementIface = isManagementIface
	return s
}

func (s *realKernelSystem) IsUEFI() bool {
	st, err := os.Stat("/sys/firmware/efi/efivars")
	return err == nil && st.IsDir()
}

func (s *realKernelSystem) EfibootmgrOK() bool {
	return runCmdTimeout(kernelNVRAMTimeout, "efibootmgr") == nil
}

func (s *realKernelSystem) BootEntries() (map[string]string, error) {
	out, err := captureCmdTimeout(kernelNVRAMTimeout, "efibootmgr")
	if err != nil {
		return nil, err
	}
	entries := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		m := bootEntryRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		entries[strings.TrimSpace(m[2])] = m[1]
	}
	return entries, nil
}

func (s *realKernelSystem) BootOrder() ([]string, error) {
	out, err := captureCmdTimeout(kernelNVRAMTimeout, "efibootmgr")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "BootOrder:")
		if !ok {
			continue
		}
		var order []string
		for _, part := range strings.Split(rest, ",") {
			id := strings.TrimSpace(part)
			if id != "" {
				order = append(order, id)
			}
		}
		return order, nil
	}
	return nil, fmt.Errorf("BootOrder not found in efibootmgr output")
}

func (s *realKernelSystem) GrubSubmenuDisabled() (bool, error) {
	hasDisable := false
	for _, path := range grubDefaultFiles() {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, fmt.Errorf("read %s: %w", path, err)
		}
		if strings.Contains(string(data), "GRUB_DISABLE_SUBMENU=y") {
			hasDisable = true
			break
		}
	}

	st, err := os.Stat("/etc/grub.d/09_xpf")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat /etc/grub.d/09_xpf: %w", err)
	}
	return hasDisable && st.Mode()&0111 != 0, nil
}

func (s *realKernelSystem) WatchdogStatus() (bool, bool) {
	_, wdErr := os.Stat("/dev/watchdog")
	_, persistentErr := os.Stat("/etc/xpf/kernel-channel/watchdog-persistent")
	return wdErr == nil, persistentErr == nil
}

func (s *realKernelSystem) FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	// Stat the nearest existing ancestor so a not-yet-created versions dir
	// still yields the backing filesystem's free space.
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if err := unix.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func (s *realKernelSystem) RunningKernel() (string, error) {
	out, err := captureCmd("uname", "-r")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// KernelHeld reports whether EVERY currently-installed linux-* package is held
// (r1 Codex High: a "any linux- is held" check false-passes a PARTIAL rehold).
func (s *realKernelSystem) KernelHeld() (bool, error) {
	out, err := captureCmd("apt-mark", "showhold")
	if err != nil {
		return false, err
	}
	held := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			held[p] = true
		}
	}
	installed := currentLinuxPackages()
	if len(installed) == 0 {
		// No linux-* installed at all — treat as "not held" so the caller
		// surfaces the anomaly rather than silently passing.
		return false, nil
	}
	for _, p := range installed {
		if !held[p] {
			return false, nil
		}
	}
	return true, nil
}

func (s *realKernelSystem) InstallCandidateKernel(version string) (string, error) {
	unholdLinuxPackages()
	reheld := false
	defer func() {
		// On ANY early return (install/initramfs/grub failure) the deferred
		// rehold restores the safety floor. A best-effort rehold here is
		// acceptable ONLY because the caller's KernelHeld() pre-arm re-assert
		// (kernel_run.go) verifies the FULL set is held and aborts the arm
		// otherwise (r1 Codex High); we log a failure so it is not silent.
		if !reheld {
			if err := holdLinuxPackages(); err != nil {
				fmt.Fprintf(os.Stderr, "kernel-upgrade: WARNING deferred rehold after failed install: %v\n", err)
			}
		}
	}()

	pkgs := []string{"linux-image-" + version, "linux-modules-" + version}
	// linux-modules-extra carries the mlx5/i40e (and other) NIC drivers the
	// appliance bake explicitly requires (bake.py asserts it). Omitting it
	// would boot a candidate that cannot drive the dataplane NICs — a failure
	// the virtio OVMF test would NOT surface (r1 Codex High). Include it when
	// available so the candidate has the same driver set as the running kernel.
	extraPkg := "linux-modules-extra-" + version
	if aptPackageAvailable(extraPkg) {
		pkgs = append(pkgs, extraPkg)
	}
	headersPkg := "linux-headers-" + version
	if aptPackageAvailable(headersPkg) {
		pkgs = append(pkgs, headersPkg)
	}
	// If any candidate package is already recorded installed by dpkg, its
	// on-disk payload is UNCERTAIN: a prior prune (or an interrupted roll)
	// could have removed /boot + /lib/modules while dpkg still thinks the
	// version is current. A plain `apt-get install <same-version>` would then
	// treat the package as satisfied and never restore the files. Force
	// --reinstall in that case so apt re-fetches and lays the payload back down
	// (#5076).
	anyInstalled := false
	for _, p := range pkgs {
		ok, qerr := s.pkgInstalled(p)
		// On a query error the on-disk payload is UNCERTAIN just as when the
		// package is recorded installed, so fail safe and force --reinstall:
		// apt then re-fetches and re-lays /boot + /lib/modules regardless
		// (harmless when the package turns out not to be installed — apt just
		// installs it fresh) (#5076/#5428).
		if qerr != nil || ok {
			anyInstalled = true
			break
		}
	}
	installArgs := buildInstallArgs(pkgs, anyInstalled)
	if err := s.aptGetCmd(installArgs...); err != nil {
		return "", err
	}
	if err := runCmd("update-initramfs", "-u", "-k", version); err != nil {
		return "", err
	}
	if err := runCmd("update-grub"); err != nil {
		return "", err
	}

	// Rehold is load-bearing (the candidate must not be apt-movable after this
	// window) — a failure here is FATAL to the install (r1 Codex High).
	if err := holdLinuxPackages(); err != nil {
		return "", fmt.Errorf("rehold linux-* after candidate install: %w", err)
	}
	reheld = true

	// The candidate's uname -r is the requested version when the standard
	// "<version>" naming holds; prefer the actual /lib/modules dir if present.
	if _, err := os.Stat(filepath.Join("/lib/modules", version)); err == nil {
		return version, nil
	}
	return version, nil
}

func (s *realKernelSystem) DefaultBootEntry() (string, error) {
	order, err := s.BootOrder()
	if err != nil {
		return "", err
	}
	if len(order) == 0 {
		return "", fmt.Errorf("BootOrder is empty")
	}
	return order[0], nil
}

// buildInstallArgs returns the apt-get argv for installing the candidate
// packages. When any target package is already installed the payload may be
// stale/missing, so --reinstall is required to make apt restore /boot +
// /lib/modules even though dpkg thinks the version is current (#5076).
func buildInstallArgs(pkgs []string, anyInstalled bool) []string {
	args := []string{"install", "-y"}
	if anyInstalled {
		args = append(args, "--reinstall")
	}
	return append(args, pkgs...)
}

func (s *realKernelSystem) WriteSlotSelector(slot, unameR string) error {
	// The uname string is embedded verbatim in a double-quoted GRUB directive
	// below (`set xpf_slot_kernel="vmlinuz-<unameR>"`). A `"`, backslash, or
	// newline in it would inject arbitrary GRUB commands and corrupt the boot
	// selector. Validate to the kernel-version charset and fail CLOSED — never
	// write a selector built from an unvalidated segment (#5452).
	if err := ValidateKernelSegment("kernel uname", unameR); err != nil {
		return fmt.Errorf("write slot selector: %w", err)
	}
	dir := s.rooted(filepath.Join("/boot/efi/EFI", slot))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create slot selector dir %s: %w", dir, err)
	}
	content := fmt.Sprintf("set xpf_slot_kernel=\"vmlinuz-%s\"\nset xpf_slot_initrd=\"initrd.img-%s\"\n", unameR, unameR)
	if err := fsatomic.WriteFileDurable(filepath.Join(dir, "xpf.selector"), []byte(content), 0644); err != nil {
		return fmt.Errorf("write slot selector: %w", err)
	}
	return nil
}

func (s *realKernelSystem) ReadSlotSelector(slot string) (string, error) {
	path := s.rooted(filepath.Join("/boot/efi/EFI", slot, "xpf.selector"))
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read slot selector %s: %w", path, err)
	}
	m := slotSelectorKernelRE.FindSubmatch(data)
	if len(m) != 2 {
		return "", nil
	}
	return string(m[1]), nil
}

func (s *realKernelSystem) SetBootNext(bootID string) error {
	return runCmdTimeout(kernelNVRAMTimeout, "efibootmgr", "--bootnext", bootID)
}

// ClearBootNext deletes the one-shot BootNext variable (#6758).
//
// efibootmgr treats deleting an absent BootNext as success, which is what the
// arm's failure path needs: it clears unconditionally rather than reading first,
// so there is no read-then-delete window and no special case for "the firmware
// silently dropped it already".
func (s *realKernelSystem) ClearBootNext() error {
	return runCmdTimeout(kernelNVRAMTimeout, "efibootmgr", "--delete-bootnext")
}

// GetBootNext parses the one-shot BootNext id out of efibootmgr's output (the
// "BootNext: XXXX" line), or returns "" if no one-shot is armed (#5847). The
// two-phase arm reads this back to POSITIVELY CONFIRM the firmware accepted the
// SetBootNext write before recording the verified ARMED journal. A missing
// BootNext line is NOT an error — it is the legitimate "no one-shot set" state.
func (s *realKernelSystem) GetBootNext() (string, error) {
	out, err := captureCmdTimeout(kernelNVRAMTimeout, "efibootmgr")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		m := bootNextRE.FindStringSubmatch(line)
		if len(m) == 2 {
			return m[1], nil
		}
	}
	return "", nil
}

// watchdogTimeoutSecs is the timeout armed before the candidate reboot. It must
// exceed the WORST-CASE time from this arm to the candidate boot petting/
// disarming the watchdog — which on physical servers includes a full UEFI POST
// + memory training (minutes), so a 60s default would reset the box mid-POST
// (r1 AGY). Default 600s; overridable via XPF_KERNEL_WATCHDOG_TIMEOUT_SECS.
func watchdogTimeoutSecs() int32 {
	if v := os.Getenv("XPF_KERNEL_WATCHDOG_TIMEOUT_SECS"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 600
}

// ArmWatchdog sets a generous timeout and pets once. NOTE: the watchdog is
// best-effort (Path Option D2): the firmware-cleared BootNext is what actually
// closes the boot-LOOP; the watchdog only converts an early-boot HANG into the
// reset that triggers that fallback. It is armed only right before the reboot.
func (s *realKernelSystem) ArmWatchdog() error {
	if _, err := os.Stat("/dev/watchdog"); err != nil {
		return fmt.Errorf("/dev/watchdog unavailable: %w", err)
	}
	fd, err := unix.Open("/dev/watchdog", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open /dev/watchdog: %w", err)
	}
	defer unix.Close(fd)

	timeout := watchdogTimeoutSecs()
	// Attempt to set a generous timeout, then pet. We ALWAYS attempt the
	// keepalive first so a driver that lacks WDIOC_SETTIMEOUT still gets a pet on
	// its default timeout (the D2 weak-arm). But a SETTIMEOUT failure means we
	// could NOT establish the generous timeout the roll relies on, so we must
	// SURFACE it rather than swallow it (#4872 B): a StrictWatchdog (D1)
	// deployment treats an arm failure as fatal and refuses to reboot with a
	// watchdog whose timeout we could not control. The caller (armCandidate)
	// decides strict-vs-best-effort; this method's job is to report the truth.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.WDIOC_SETTIMEOUT), uintptr(unsafe.Pointer(&timeout)))
	if err := writeWatchdogKeepalive(fd); err != nil {
		return err
	}
	if errno != 0 {
		return fmt.Errorf("watchdog WDIOC_SETTIMEOUT(%ds): %w", timeout, errno)
	}
	return nil
}

func (s *realKernelSystem) Reboot() error {
	return exec.Command("systemctl", "reboot").Run()
}

// promotionMarkerPath records the last promoted kernel uname -r (survives the
// journal clear) for the external HA orchestrator's post-reboot version-check.
const promotionMarkerPath = "/var/lib/xpf/kernel-promoted"

func (s *realKernelSystem) WritePromotionMarker(unameR string) error {
	if err := fsatomic.MkdirAllDurable(filepath.Dir(promotionMarkerPath), 0755); err != nil {
		return fmt.Errorf("create promotion marker dir: %w", err)
	}
	return fsatomic.WriteFileDurable(promotionMarkerPath, []byte(unameR+"\n"), 0644)
}

func (s *realKernelSystem) ReadPromotionMarker() (string, error) {
	data, err := os.ReadFile(promotionMarkerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read promotion marker: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *realKernelSystem) ClearPromotionMarker() error {
	if err := os.Remove(promotionMarkerPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear promotion marker: %w", err)
	}
	return nil
}

func (s *realKernelSystem) ClearRollLease() error {
	if err := os.Remove(DefaultKernelRollLeasePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear kernel-roll lease: %w", err)
	}
	return nil
}

func (s *realKernelSystem) BootCurrent() (string, error) {
	out, err := captureCmdTimeout(kernelNVRAMTimeout, "efibootmgr")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		m := bootCurrentRE.FindStringSubmatch(line)
		if len(m) == 2 {
			return m[1], nil
		}
	}
	return "", fmt.Errorf("BootCurrent not found in efibootmgr output")
}

// osExecutable is os.Executable, a package var so a test can drive the callers
// below deterministically (under `go test` the real os.Executable is the TEST
// binary, which is not an xpfd).
//
// THREE callers, across two files, and they do NOT want the same thing from it
// (#6601):
//
//   - resolveVerifyGateBin (here) — the SOLE source for the INNER hop's
//     verify-dataplane exec. It fails CLOSED: since #6620 there are no
//     configured-root fallbacks, because a leftover at a compiled-in default is
//     indistinguishable from a live install once a root has been relocated, and
//     a Gate-3 error routes to revert() — a correct terminal outcome.
//   - resolveArmingBinary (kernel_arm_record.go) — the AUTHORITY. The arming
//     process IS an xpfd, so this names the live binary by construction. It
//     fails CLOSED: an error refuses the arm, because arming is retryable and
//     an unverified candidate kernel is not.
//   - VerifyPromoteBinaryMatchesRecord (kernel_arm_record.go) — the promote-time
//     cross-check. It fails OPEN on an error, deliberately: this is a second
//     opinion whose authority (the sidecar) was already applied and validated by
//     the outer hop, so an indeterminate answer must not veto a promotion the
//     record already justified.
//
// That arm-closed / promote-open asymmetry is intentional. Change one of the
// three and check the other two: they are the same function var, not the same
// contract.
var osExecutable = os.Executable

// verifyGateBin is the basename of the daemon artifact the promotion gate
// execs. It matches the versions/<ver>/xpfd basename the cut writes (flip.go,
// cutover.go) and manifest's SSOT entry.
const verifyGateBin = "xpfd"

// resolveVerifyGateBin returns an EXPLICIT path to the xpfd artifact the kernel
// promotion gate execs for `verify-dataplane`. It NEVER PATH-resolves a bare
// name (#6541), and since #6620 it NEVER INFERS ONE FROM THE FILESYSTEM either.
//
// Why it matters here specifically: this gate runs as root on a candidate boot
// and its exit status decides promote-vs-rollback (KernelRunner.verifyAndPromote,
// Gate 3). A PATH entry ordered ahead of the real location would therefore get
// to author that decision — and even absent an attacker, a stale xpfd left in
// some other directory would verify the WRONG build against the candidate
// kernel. Every sibling xpfd invocation in this package already builds an
// explicit path (realSystem.VerifyDataplane / BinaryVersion take an explicit
// `bin`; cutover.go, flip.go, and runtime/seed.go all filepath.Join it out of
// the version dir); this was the one site that did not.
//
// THERE IS EXACTLY ONE SOURCE, AND NO FALLBACK: os.Executable().
//
// The gate IS an xpfd subcommand (`xpfd upgrade kernel promote`,
// cmd/xpfd/upgrade_kernel.go), so the running process is BY CONSTRUCTION the
// installed, live xpfd — an answer the kernel gives, not one inferred from
// ambient state. On Linux this reads /proc/self/exe, which resolves the
// /usr/local/sbin/xpfd -> versions/current -> versions/<ver>/xpfd chain down to
// the concrete versioned artifact, i.e. the same version-multiplexed path
// realSystem.VerifyDataplane is handed.
//
// Note it is a PATH, not the inode — an overwrite of that path (a #2176-shape
// raw deploy) would leave it stat'ing to a NEWER file while this process still
// runs the old one. The `upgrade kernel promote` lock (cmd/xpfd/upgrade_kernel.go)
// serializes this against a binary cut, and either way the exec target stays
// explicit, which is the property this function exists to guarantee.
//
// WHY THE TWO CONFIGURED-ROOT FALLBACKS ARE GONE (#6620). This used to fall
// through to <SbinDir>/xpfd and then <VersionsDir>/current/xpfd. That is the
// same defect class the OUTER hop (scripts/image/xpf-kernel-promote) eliminated
// in #6601 r5, and it is worth naming precisely rather than by analogy:
// `--sbin-dir` and `--versions-dir` relocate INDEPENDENTLY, and NEITHER
// relocation removes what it left behind, so a leftover at a compiled-in
// default is byte-for-byte indistinguishable from a healthy install —
//
//	BOTH roots relocated : the old default sbin symlink AND the old default
//	                       versions/current both survive, and that symlink
//	                       still points at that runtime, so the two
//	                       "candidates" are ONE INODE, exactly like a healthy
//	                       default layout. A same-inode test calls that
//	                       unambiguous; it is a STALE build.
//	ONE root relocated   : exactly one default survives, so "the only usable
//	                       default" IS the stale leftover.
//	NEITHER relocated    : healthy — and os.Executable answers, so no fallback
//	                       was ever needed here in the first place.
//
// The question a defaults fallback tries to answer — WHICH of these files is
// the live xpfd — is not answerable from the filesystem at all once a root has
// been relocated. The outer hop's authority order is now
// /proc/<MainPID>/exe -> strictly-parsed ExecStart -> loud refusal; this is the
// inner hop's counterpart, with one authority and the same refusal.
//
// The old ORDER argument (sbin before versions/current, because flip step 6b
// repoints <SbinDir>/<bin> on every cut) was a correct ranking of two guesses.
// A better-ranked guess is still a guess: on a both-roots-relocated box the
// surviving default sbin symlink resolves perfectly and names a stale runtime,
// so the ranking preferred the stale build with full confidence.
//
// FAILURE IS FAIL-CLOSED, NOT A PATH FALLBACK AND NOT A GUESS. If the running
// binary cannot be identified and validated (absolute, existing, regular,
// executable) this returns an error, VerifyDataplane propagates it, and the
// caller — KernelRunner.verifyAndPromote in kernel_run.go — turns any Gate-3
// error into revert(): restore the known-good BootOrder and reboot to the
// known-good slot. On an A/B kernel promote that is the SAFE direction, and it
// is strictly better than executing a stale verifier, whose PASS would
// authorize a permanent promotion of a kernel nothing actually validated.
//
// The cost of refusing is bounded and recoverable: the operator's candidate is
// not promoted and the box comes back on the kernel it was already running.
// The cost of guessing is a promotion justified by the wrong dataplane.
//
// Reachability: the error paths need os.Executable to fail (no /proc) or its
// path to no longer resolve. The latter is how an UNLINKED running binary lands
// here, and it is worth being precise about the mechanism: Go TRIMS the
// " (deleted)" suffix Readlink appends and returns the original path with a nil
// error (src/os/executable_procfs.go), so this is driven by os.Stat returning
// ENOENT on that path — never by inspecting a suffix. Code or tests keying on a
// "(deleted)" string would be testing an input the API cannot produce
// (TestOsExecutableTrimsDeletedSuffix pins that toolchain behaviour).
func resolveVerifyGateBin() (string, error) {
	self, err := osExecutable()
	if err != nil {
		return "", fmt.Errorf("cannot identify the running xpfd (os.Executable: %v); "+
			"refusing to infer one from <sbin-dir>/%s or <versions-dir>/%s/%s — a "+
			"leftover from a relocated runtime is indistinguishable from a live one "+
			"and would verify this candidate kernel against the wrong dataplane "+
			"(#6620) — and refusing to PATH-resolve a bare %q (#6541)",
			err, verifyGateBin, currentLink, verifyGateBin, verifyGateBin)
	}
	if verr := validateGateBin(self); verr != nil {
		return "", fmt.Errorf("the running xpfd %q is not usable as the promotion "+
			"gate's exec target (%v); refusing to infer a replacement from "+
			"<sbin-dir>/%s or <versions-dir>/%s/%s — a leftover from a relocated "+
			"runtime is indistinguishable from a live one and would verify this "+
			"candidate kernel against the wrong dataplane (#6620) — and refusing "+
			"to PATH-resolve a bare %q (#6541)",
			self, verr, verifyGateBin, currentLink, verifyGateBin, verifyGateBin)
	}
	return self, nil
}

// validateGateBin reports whether p is usable as the gate's exec target: an
// absolute path to an existing, regular, executable file. Rejecting a
// non-absolute path is what keeps a relative or bare name from reaching
// exec.Command, where it would be CWD- or PATH-resolved.
func validateGateBin(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("not an absolute path")
	}
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (mode %s)", st.Mode())
	}
	if st.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("not executable (mode %s)", st.Mode())
	}
	return nil
}

// verifyDataplaneCmd builds the Gate-3 command with an EXPLICIT, resolved xpfd
// path. Split out of VerifyDataplane so the #6541 regression test can assert on
// the resolved argv itself rather than on a side effect of running it.
func (s *realKernelSystem) verifyDataplaneCmd() (*exec.Cmd, error) {
	bin, err := resolveVerifyGateBin()
	if err != nil {
		return nil, fmt.Errorf("resolve verify-dataplane gate binary: %w", err)
	}
	return exec.Command(bin, "verify-dataplane"), nil
}

func (s *realKernelSystem) VerifyDataplane() (bool, error) {
	cmd, err := s.verifyDataplaneCmd()
	if err != nil {
		// Fail closed: the caller reverts (reboot to known-good).
		return false, err
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		// exit 3 = REJECT (verifier rejected the shim). main.go contract.
		if ee.ExitCode() == 3 {
			return false, nil
		}
	}
	return false, fmt.Errorf("verify-dataplane exec failed: %w (output: %s)", err, strings.TrimSpace(out.String()))
}

// ForwardBeacon proves the candidate kernel can actually FORWARD, not merely
// that a unit is active (r2 Codex Critical: `systemctl is-active` is not a
// forwarding proof).
//
// BeaconTarget guidance (r1 AGY): for a meaningful proof the operator SHOULD set
// XPF_KERNEL_BEACON_TARGET to a DATAPLANE-side target (e.g. the HA peer link or
// a known host reachable only through a dataplane interface). The default
// IPv4-gateway fallback is a WEAK best-effort: on a box whose default route is
// the out-of-band management interface it can false-PASS (ping succeeds over
// mgmt while the dataplane is broken), and on a transit/BGP router with no
// static default route it returns "" and fail-SAFE-reverts. Neither is a silent
// brick — a false-pass still required verify-dataplane (the #1864 kernel
// verifier, Gate 3) to PASS first, and the fail-safe revert is recoverable —
// but the strong gate is an operator-set dataplane BeaconTarget. A wired
// ProbeFunc (the richest probe, when the caller has the dataplane manager) takes
// precedence; otherwise this does a REAL reachability probe through the
// dataplane: xpfd must be active AND the dataplane helper must report
// enabled+forwarding-armed over its control socket (#6607) AND a ping to
// BeaconTarget (default: the IPv4 default gateway) must succeed within the
// deadline. A candidate kernel whose shim verified (Gate 3) but cannot forward
// fails the ping -> revert. The gateway is the most universally-available
// off-box target that exercises the forwarding path; an operator can override
// BeaconTarget for a topology-specific peer-link target.
func (s *realKernelSystem) ForwardBeacon(deadline time.Duration) (bool, error) {
	if s.ProbeFunc != nil {
		return s.ProbeFunc(time.Now().Add(deadline))
	}
	// Precondition A: xpfd must be up at all — a down daemon cannot forward
	// regardless of ping. Routed through unitActiveProbeCtx, the package's
	// SINGLE is-active primitive (#5808): ctx-bounded so a wedged DBus is killed
	// rather than blocking the gate past the rollback deadline, and exit-code
	// aware so "unit not found" is not silently read as "inactive".
	beaconCtx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	unitActive := s.UnitActive
	if unitActive == nil {
		unitActive = func(ctx context.Context) (bool, error) {
			return unitActiveProbeCtx(ctx, DefaultUnit)
		}
	}
	if active, err := unitActive(beaconCtx); err != nil || !active {
		return false, nil
	}
	// Precondition B: the DATAPLANE must actually be forwarding (#6607).
	//
	// This used to be `systemctl is-active xpfd-userspace-dp` — a unit that
	// exists nowhere in the repository and never has. The helper is a CHILD
	// PROCESS xpfd spawns, not a systemd unit, so that probe could never report
	// active; combined into an OR with the xpfd probe it could contribute
	// neither a pass nor a fail, and the guard silently degenerated to "xpfd is
	// active". That is exactly the pre-#5286 mistake: a Type=simple xpfd reports
	// active immediately while its helper is down, stale or crash-looping and
	// NOT forwarding — and a kernel change (AF_XDP shim vs a new kernel,
	// verifier, driver) is the single most likely cause of precisely that state,
	// which is what Gate 4 exists to catch. The fail direction of the old shape
	// was PERMISSIVE, so a bad kernel was more likely to be promoted than
	// rolled back.
	//
	// A nil probe means this caller has no dataplane to ask (a non-xpfd embedder
	// or a test). Fall back to A alone rather than failing closed: a missing
	// seam is "no information", not "unhealthy", and failing closed on it would
	// revert every such caller's promotion. Production always wires it.
	if s.HelperStatus != nil {
		timeout := s.StatusTimeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		enabled, armed, _, err := s.HelperStatus(s.ControlSocket, timeout)
		if err != nil || !enabled || !armed {
			return false, nil
		}
	}
	target := s.BeaconTarget
	if target == "" {
		target = beaconDefaultGateway()
	}
	if target == "" {
		// No reachable target to probe. Be HONEST: we cannot prove forwarding,
		// so do NOT promote on a "pass" we can't substantiate — return false so
		// the caller reverts (a conservative, fail-safe default; the operator
		// can set BeaconTarget to enable promotion on a box with no gateway).
		return false, fmt.Errorf("no forward-beacon target (no default gateway; set BeaconTarget)")
	}
	// #7157: the target must be one a probe can actually FAIL against. A ping
	// to the box's own address is answered by the local stack over `lo` in tens
	// of microseconds with the dataplane in any state (measured: `ip route get
	// 172.16.50.8` -> `local ... dev lo`, ping 0.055ms), so pointing
	// XPF_KERNEL_BEACON_TARGET at a local dataplane address — which the
	// guidance above actively invites — makes this gate pass UNCONDITIONALLY.
	// A target egressing the out-of-band management interface is the same
	// failure in the issue's original form. Refuse both, and refuse a target
	// with no route at all, naming which: the error reaches the operator through
	// KernelRunner.revert -> KernelRollOutcome.Reason, where "forward beacon
	// FAILED" alone would not tell them what to change.
	if err := beaconTargetEligible(target, s.IsManagementIface); err != nil {
		return false, err
	}
	secs := int(deadline.Seconds())
	if secs < 1 {
		secs = 1
	}
	// ping -c <n> -w <deadline>: a single reply within the window proves the
	// dataplane forwarded a packet off-box on the candidate kernel.
	if err := beaconPing(target, secs); err != nil {
		return false, nil
	}
	return true, nil
}

// beaconPing is ForwardBeacon's off-box reachability probe. Package var for the
// same reason as beaconDefaultGateway and unitActiveProbeCtx (#6607): without a
// seam, EVERY assertion about the gates upstream of it is decided by whether the
// test host can reach the target. That is not a convenience — a test that
// asserts "the beacon rejects an unhealthy dataplane" while the ping is also
// failing cannot tell the two rejections apart, so deleting the dataplane
// condition outright leaves it green. Forcing a SUCCESSFUL ping is what makes
// the dataplane condition the only thing left that can reject.
var beaconPing = func(target string, secs int) error {
	return runCmd("ping", "-c", "3", "-w", fmt.Sprintf("%d", secs), target)
}

// beaconDefaultGateway is ForwardBeacon's target-of-last-resort resolver. A
// package var for the same reason as unitActiveProbeCtx: it is the only other
// thing in the beacon that reaches outside the process, so without a seam every
// assertion about the code AFTER it depends on whether the machine running the
// test happens to have a default route (#6607). TestDefaultGatewayParseLogic
// covers the parsing; this covers the branch that consumes it.
var beaconDefaultGateway = defaultGateway

// defaultGateway returns the IPv4 default-route next hop, or "" if none.
//
// The parse itself lives in parseDefaultRoute (kernel_beacon_target_7157.go) so
// the test can call the PRODUCTION function instead of a copy of it written
// inside the test — which is what TestDefaultGatewayParseLogic used to do, and
// which would have stayed green through any change made here.
func defaultGateway() string {
	out, err := captureCmd("ip", "-4", "route", "show", "default")
	if err != nil {
		return ""
	}
	gw, _ := parseDefaultRoute(out)
	return gw
}

func (s *realKernelSystem) SetBootOrderFront(bootID string) error {
	order, err := s.BootOrder()
	if err != nil {
		return err
	}
	if len(order) > 0 && order[0] == bootID {
		return nil
	}
	next := []string{bootID}
	for _, id := range order {
		if id != bootID {
			next = append(next, id)
		}
	}
	return runCmdTimeout(kernelNVRAMTimeout, "efibootmgr", "--bootorder", strings.Join(next, ","))
}

func (s *realKernelSystem) DisarmWatchdog() error {
	// A genuinely-absent watchdog device is "nothing to disarm" — nil. But an
	// I/O failure while a device IS present (open/write/close) was previously
	// swallowed into nil, hiding a watchdog that is still armed and could bounce
	// the box (#4872 B). Surface those errors so the caller can log them (or, in
	// strict contexts, react) instead of assuming a clean disarm.
	if _, err := os.Stat("/dev/watchdog"); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat /dev/watchdog: %w", err)
	}
	fd, err := unix.Open("/dev/watchdog", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open /dev/watchdog for disarm: %w", err)
	}
	// The magic-close 'V' tells the driver to disable the watchdog on close
	// (WDIOF_MAGICCLOSE). Both the write and the close must succeed for the
	// disarm to actually take effect.
	if _, werr := unix.Write(fd, []byte{'V'}); werr != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("write watchdog magic-close: %w", werr)
	}
	if cerr := unix.Close(fd); cerr != nil {
		return fmt.Errorf("close /dev/watchdog: %w", cerr)
	}
	return nil
}

func (s *realKernelSystem) PruneInactiveSlot(slot, knownGoodUnameR, candidateVersion string) error {
	// Fail CLOSED on an unsafe candidate segment BEFORE any purge, glob, or
	// delete (#5452). candidateVersion feeds `apt-get purge linux-image-<ver>`
	// (a "*" would purge EVERY kernel package), filepath.Glob("/boot/*-"+ver)
	// whose matches are handed to os.RemoveAll (a "*" globs "/boot/*-*",
	// matching every dashed /boot file -> wipes all kernels/initrds/config),
	// and os.RemoveAll("/lib/modules/"+ver) (a ".." traverses to "/lib"). Never
	// run a filesystem delete keyed by an unvalidated version. knownGoodUnameR
	// is validated by WriteSlotSelector before it reaches the GRUB script.
	if err := ValidateKernelSegment("kernel candidate version", candidateVersion); err != nil {
		return fmt.Errorf("kernel-upgrade prune: %w", err)
	}
	// Restore the inactive slot's boot selector to the KNOWN-GOOD kernel FIRST.
	// This is the load-bearing safety step and it is independent of the package
	// cleanup below: whatever happens to the candidate's packages, the slot
	// selector never points at the (possibly half-removed) candidate. Doing it
	// before any package/file mutation guarantees a later failure cannot strand
	// the selector on the candidate (#5076).
	if err := s.WriteSlotSelector(slot, knownGoodUnameR); err != nil {
		return err
	}
	// The candidate kernel packages are HELD (InstallCandidateKernel re-holds
	// the full set), so `apt-get purge` must be allowed to change held packages
	// or it leaves the candidate installed-in-dpkg while we delete its files
	// (r2 Codex High). Include linux-modules-extra (the install adds it).
	candPkgs := []string{
		"linux-image-" + candidateVersion,
		"linux-modules-" + candidateVersion,
		"linux-modules-extra-" + candidateVersion,
		"linux-headers-" + candidateVersion,
	}
	// Only purge packages that are actually installed (avoid apt errors on a
	// never-installed optional pkg like headers/modules-extra). A dpkg-query
	// ERROR here (DB corruption, lock, missing binary) must NOT be misread as
	// "not installed": that false-negative would drop a still-owned package
	// from the set, skip the purge, and let the sweep below delete
	// package-owned /boot + /lib/modules files while dpkg still owns them (the
	// #5427 divergence class, reached via DB corruption instead of a
	// lock/maintainer-script failure). Fail SAFE: treat a query error as
	// POSSIBLY-INSTALLED and include the package, so a real purge is attempted
	// and the sweep stays gated behind the confirmed-absent re-query below
	// (#5428).
	var installed []string
	for _, p := range candPkgs {
		ok, qerr := s.pkgInstalled(p)
		if qerr != nil || ok {
			installed = append(installed, p)
		}
	}
	if len(installed) > 0 {
		args := append([]string{"purge", "-y", "--allow-change-held-packages"}, installed...)
		if err := s.aptGetCmd(args...); err != nil {
			// The purge FAILED (dpkg lock, held-package refusal, a
			// maintainer-script error, ...). dpkg still records these packages
			// as installed. Deleting their /boot + /lib/modules payload now
			// would leave the package database and the filesystem
			// inconsistent: a later `apt-get install <same-version>` WITHOUT
			// --reinstall sees the package current and never restores the
			// files, so the slot would hold a kernel with no modules/boot
			// files. LEAVE the package-owned files intact and surface the
			// failure so the caller logs it and the prune stays retryable. The
			// selector is already pointed at known-good (above), so the box is
			// safe regardless (#5076).
			return fmt.Errorf("purge un-promoted candidate %s: %w", candidateVersion, err)
		}
		// Re-query dpkg: manual deletion of package-owned files must ONLY
		// follow a CONFIRMED removal. If any package is still installed (a
		// partial purge), keep its files and surface the anomaly rather than
		// delete a still-owned payload (#5076). A query ERROR on the re-query
		// is NOT a confirmed removal either — fail SAFE and treat it as
		// still-installed so the sweep is skipped (#5428).
		var stillInstalled []string
		for _, p := range installed {
			ok, qerr := s.pkgInstalled(p)
			if qerr != nil || ok {
				stillInstalled = append(stillInstalled, p)
			}
		}
		if len(stillInstalled) > 0 {
			return fmt.Errorf("purge un-promoted candidate %s: still installed or unconfirmed-removed after purge: %s",
				candidateVersion, strings.Join(stillInstalled, ", "))
		}
	}
	// The candidate packages are confirmed ABSENT (none were installed, or the
	// purge removed them and the dpkg re-query confirms it). Any leftover
	// /lib/modules or /boot files are now truly orphaned, so sweeping them
	// cannot desync dpkg. This sweep is best-effort: an orphan-file removal
	// error must not block the revert (the firmware-cleared BootNext is the
	// safety floor), so it is logged, not returned.
	if err := os.RemoveAll(s.rooted(filepath.Join("/lib/modules", candidateVersion))); err != nil {
		fmt.Fprintf(os.Stderr, "kernel-upgrade: WARNING remove /lib/modules/%s: %v\n", candidateVersion, err)
	}
	if matches, err := filepath.Glob(s.rooted(filepath.Join("/boot", "*-"+candidateVersion))); err == nil {
		for _, match := range matches {
			if err := os.RemoveAll(match); err != nil {
				fmt.Fprintf(os.Stderr, "kernel-upgrade: WARNING remove %s: %v\n", match, err)
			}
		}
	}
	return nil
}

// isPkgInstalled reports whether a dpkg package is in the "installed" state and
// whether the query itself succeeded. It is TRI-STATE: (true, nil) installed,
// (false, nil) confirmed NOT installed, (false, err) status UNKNOWN.
//
// dpkg-query exits non-zero in TWO very different situations, and they must not
// be conflated (#5428):
//   - the package is genuinely unknown to dpkg ("no packages found matching") —
//     a never-installed optional pkg (e.g. linux-headers/-modules-extra), OR a
//     package dpkg fully purged (purge drops it from the DB entirely). This is a
//     legitimate confirmed-absent, returned as (false, nil). Treating it as an
//     error would push a never-installed pkg into the purge set and make
//     `apt-get purge` fail with "Unable to locate package" — a prune regression.
//   - a real query failure (DB corruption/parse error, permission, lock,
//     missing binary). The status is UNKNOWN; return the error so a destructive
//     caller fails SAFE (possibly-installed) rather than deleting owned files.
func isPkgInstalled(pkg string) (bool, error) {
	out, err := captureCmd("dpkg-query", "-W", "-f=${Status}", pkg)
	if err != nil {
		if dpkgQueryAbsent(err) {
			return false, nil
		}
		return false, err
	}
	return strings.Contains(out, "install ok installed"), nil
}

// dpkgQueryAbsent reports whether a dpkg-query error means the package is
// genuinely unknown to dpkg (a legitimate "not installed") rather than a real
// query failure that must fail SAFE (#5428). captureCmd folds dpkg-query's
// stderr into the returned error, so the "no packages found matching" marker is
// visible in err.Error().
func dpkgQueryAbsent(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no packages found matching")
}

func (s *realKernelSystem) Now() time.Time {
	return time.Now()
}

func grubDefaultFiles() []string {
	files := []string{"/etc/default/grub"}
	matches, err := filepath.Glob("/etc/default/grub.d/*.cfg")
	if err == nil {
		files = append(files, matches...)
	}
	return files
}

func captureCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	// Force the C locale so the parsed output (efibootmgr "BootCurrent:" /
	// "BootOrder:", uname, ip route, dpkg-query) is never localized/translated,
	// which would break the regex/field parses and trigger spurious reverts
	// (r1 AGY: locale-robust parsing). LC_ALL=C wins over LANG/LC_*.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func aptGet(args ...string) error {
	cmd := exec.Command("apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apt-get %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func aptPackageAvailable(pkg string) bool {
	if out, err := captureCmd("apt-cache", "show", pkg); err == nil && strings.TrimSpace(out) != "" {
		return true
	}
	if out, err := captureCmd("dpkg-query", "-W", "-f=${binary:Package}\n", pkg); err == nil && strings.TrimSpace(out) != "" {
		return true
	}
	return false
}

func unholdLinuxPackages() {
	linuxPackages := currentLinuxPackages()
	if len(linuxPackages) == 0 {
		return
	}
	// Unhold failure is non-fatal: at worst the candidate install fails (apt
	// refuses to touch a held pkg), which is itself surfaced as an error.
	_ = runCmd("apt-mark", append([]string{"unhold"}, linuxPackages...)...)
}

func holdLinuxPackages() error {
	linuxPackages := currentLinuxPackages()
	if len(linuxPackages) == 0 {
		return fmt.Errorf("no linux-* packages found to hold")
	}
	return runCmd("apt-mark", append([]string{"hold"}, linuxPackages...)...)
}

// kernelPkgPrefixes are the ACTUAL kernel image/module/header package families
// the channel holds. `linux-*` is too broad (r1 Copilot): it would pin
// linux-base, linux-libc-dev, linux-firmware, linux-tools-*, etc. — unrelated
// packages whose long-term hold blocks security updates and diverges from the
// bake's intent (which holds only the kernel set). We hold exactly the kernel
// families + the metapackages that pull them.
var kernelPkgPrefixes = []string{
	"linux-image-", "linux-modules-", "linux-modules-extra-",
	"linux-headers-", "linux-generic", "linux-image-generic",
	"linux-headers-generic", "linux-image-virtual", "linux-virtual",
}

func isKernelPkg(pkg string) bool {
	for _, p := range kernelPkgPrefixes {
		if pkg == p || strings.HasPrefix(pkg, p) {
			return true
		}
	}
	return false
}

func currentLinuxPackages() []string {
	out, err := captureCmd("dpkg-query", "-W", "-f=${binary:Package}\n", "linux-*")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		pkg := strings.TrimSpace(line)
		// Only the kernel image/module/header families + metas — NOT the broad
		// linux-* set (excludes linux-base / linux-libc-dev / firmware / tools).
		if pkg == "" || !isKernelPkg(pkg) || seen[pkg] {
			continue
		}
		seen[pkg] = true
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

func writeWatchdogKeepalive(fd int) error {
	n, err := unix.Write(fd, []byte{'K'})
	if err != nil {
		return fmt.Errorf("write watchdog keepalive: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("write watchdog keepalive: short write %d", n)
	}
	return nil
}
