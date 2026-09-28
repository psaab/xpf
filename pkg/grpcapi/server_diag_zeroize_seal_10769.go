package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/ipsec"
)

// The system-path seams mirror the image's SYSPREP_ENABLE_OPS and
// SYSPREP_PURGE_PATHS. Tests point them at a disposable tree; production values
// remain the image paths whose previous-tenant state must not survive reset.
var (
	zeroizeMachineIDPath       = "/etc/machine-id"
	zeroizeSSHHostKeyDir       = "/etc/ssh"
	zeroizeRootSSHUserDir      = "/root/.ssh"
	zeroizeRootBashHistory     = "/root/.bash_history"
	zeroizeSNMPEngineIDPath    = "/var/lib/xpf/snmp-engine-id"
	zeroizeSNMPEngineBootsPath = "/var/lib/xpf/snmp-engineboots"
	zeroizeSystemdRandomSeed   = "/var/lib/systemd/random-seed"
	zeroizeAptListsDir         = "/var/lib/apt/lists"
	zeroizeAptArchiveDir       = "/var/cache/apt/archives"
	zeroizeRunUtmpPath         = "/run/utmp"
	zeroizeDay0RejectedPath    = "/etc/xpf/.day0-config-rejected"
	zeroizeRootGrownPath       = "/etc/xpf/.root-grown"
	zeroizeDDNSLeaseStatePath  = ddns.DefaultLeaseStatePath()
	zeroizeDDNSSurfaceAPath    = ddns.DefaultSurfaceAStatePath()
	zeroizePasswdBackupPaths   = []string{"/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-"}
	zeroizeManagedHostKeysPath = "/etc/ssh/ssh_known_hosts"
	zeroizeManagedDropins      = []string{
		"/etc/ssh/sshd_config.d/00-xpf.conf",
		"/etc/ssh/sshd_config.d/xpf.conf",
		"/etc/chrony/sources.d/xpf.sources",
		"/etc/chrony/conf.d/xpf-threshold.conf",
		"/etc/systemd/resolved.conf.d/xpf.conf",
		"/etc/systemd/resolved.conf.d/bpfrx.conf",
	}
	zeroizeHostnamePath   = "/etc/hostname"
	zeroizeResolvConfPath = "/etc/resolv.conf"
	zeroizeIPsecStatePath = ipsec.DefaultConnStatePath
	zeroizeKeaLeasePaths  = []string{dhcpserver.DefaultKeaLeaseFile4Path, dhcpserver.DefaultKeaLeaseFile6Path}
	zeroizeStopKeaUnits   = stopKeaUnits
	zeroizeVerifyKeaStopped = verifyKeaUnitsStopped
	zeroizeVarBackupsDir    = "/var/backups"
)

var (
	errZeroizeDDNSOwnership = errors.New("zeroize refused to erase config while DDNS ownership is unresolved")
	errZeroizeIPsecOwnership = errors.New("zeroize refused to erase config while IPsec teardown is unresolved")
	errZeroizeKeaStop = errors.New("zeroize could not stop Kea before lease-file erasure")
)

const zeroizeManagedHostKeysHeader = "# Managed by xpfd — do not edit\n"

// zeroizeImageSealResidue removes the safely-regenerable members of the
// image's own factory seal set. It deliberately leaves files whose deletion
// would destroy live service state or lacks a regeneration/ownership proof;
// see the survivor decisions below.
func zeroizeImageSealResidue() error {
	var errs []error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}

	// machine-id is left present but empty so systemd regenerates it.
	fail(zeroizeTruncateFile(zeroizeMachineIDPath))

	// The image seals every ssh_host_* private/public/certificate file. The
	// first-boot xpf-day0-config unit runs ssh-keygen -A before ssh.service, so
	// deleting these here regenerates a fresh device identity on reboot.
	entries, err := os.ReadDir(zeroizeSSHHostKeyDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fail(fmt.Errorf("zeroize: read SSH host-key directory %s: %w", zeroizeSSHHostKeyDir, err))
	} else {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "ssh_host_") {
				fail(zeroizeRemovePath(filepath.Join(zeroizeSSHHostKeyDir, entry.Name())))
			}
		}
	}

	// The sysprep ssh-userdir and bash-history operations apply to root here.
	// Provisioned non-root homes have already been handled by the marker-aware
	// login teardown; unrelated operator accounts remain outside xpf ownership.
	fail(zeroizeRemovePath(zeroizeRootSSHUserDir))
	fail(zeroizeRemovePath(zeroizeRootBashHistory))

	// SNMP engine identity, monotonicity state, and systemd's persisted random
	// seed all regenerate on the next boot. Losing SNMP engineBoots alongside
	// its EngineID is safe because the engine ID itself is replaced.
	// Remove image-sealed caches plus the day-0 rejection and root-grow
	// markers. They are either disposable cache or first-boot state.
	for _, path := range []string{
		zeroizeSNMPEngineIDPath,
		zeroizeSNMPEngineBootsPath,
		zeroizeSystemdRandomSeed,
		zeroizeRunUtmpPath,
		zeroizeDay0RejectedPath,
		zeroizeRootGrownPath,
	} {
		fail(zeroizeRemovePath(path))
	}

	// NOTE: the passwd-/shadow-/group-/gshadow- backups are NOT erased here.
	// Shadow tools recreate them on every userdel/passwd invocation, and the
	// login-account teardown runs those commands after this function returns.
	// zeroizeEraseAccountBackups runs after that teardown instead.
	// Package lists and downloaded archives are caches and can be recreated
	// by apt. Temporary directories and generic /etc backup files are not
	// swept: unrelated live services may hold temp files open, and those
	// backups are not provably xpf-owned. This is an intentional survivor
	// decision rather than a silent claim that these image-seal legs ran.
	for _, dir := range []string{zeroizeAptListsDir, zeroizeAptArchiveDir} {
		fail(zeroizeClearDir(dir))
	}

	// Remove xpf-owned host-trust and service drop-ins. Host-trust is erased
	// only when its ownership header proves xpfd wrote it; a foreign file is
	// deliberately preserved.
	fail(zeroizeRemoveManagedHostKeys(zeroizeManagedHostKeysPath))
	for _, path := range zeroizeManagedDropins {
		fail(zeroizeRemovePath(path))
	}
	// /etc/resolv.conf is xpf-owned only when its generated header proves
	// ownership. Removing that file clears prior nameservers; boot repairs the
	// absent file to the safe header-only empty resolver state.
	fail(zeroizeRemoveManagedResolvConf(zeroizeResolvConfPath))

	// `logfiles` is part of SYSPREP_ENABLE_OPS. Empty /var/log while retaining
	// the directory for the still-running reset action; post-reset log entries
	// may be written before xpfd stops, but prior-tenant persisted entries are
	// unlinked. Volatile /run logs disappear at reboot.
	fail(zeroizeClearDir(zeroizeVarLogDir))
	if len(errs) == 0 {
		// Do not change the running device name until every earlier cleanup
		// leg has succeeded; reset is recoverable when residue remains.
		fail(zeroizeResetHostname(zeroizeHostnamePath))
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func zeroizeStopKeaAndEraseLeases() error {
	// Stop, verify, and unlink in one critical section with no intervening
	// wipe I/O: a Kea restart between stop and unlink would re-persist prior
	// leases under the erasure. No mask/disable: a mask persists across the
	// reboot into the next tenant and would break their DHCP; stop plus an
	// inactive verification plus immediate unlink closes the re-persist
	// window instead (a restart after the unlink creates fresh empty state,
	// not prior leases). Each systemctl invocation is bounded 15s+5s by the
	// shared exec helper; any stop/verify failure fails closed here, before
	// any lease byte is unlinked.
	if err := zeroizeStopKeaUnits(); err != nil {
		return fmt.Errorf("%w: %w", errZeroizeKeaStop, err)
	}
	if err := zeroizeVerifyKeaStopped(); err != nil {
		return fmt.Errorf("%w: %w", errZeroizeKeaStop, err)
	}
	var errs []error
	for _, current := range zeroizeKeaLeasePaths {
		// The full LFC set, not just the canonical CSV: Kea startup prefers
		// .completed over .2/.1, so unlinking only the current file leaves
		// prior leases loadable (and a crash can leave leases ONLY in
		// .completed).
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if err := zeroizeRemovePath(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	// Re-verify emptiness after the unlink: a writer racing the stop would
	// otherwise leave fresh prior-tenant rows behind a clean receipt.
	for _, current := range zeroizeKeaLeasePaths {
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("zeroize: Kea lease file %s reappeared during erasure", path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("zeroize: inspect Kea lease file %s: %w", path, err)
			}
		}
	}
	return nil
}

// zeroizeShadowBackupNames are the Debian shadow-tools backups in
// /var/backups, rewritten on every passwd/userdel invocation.
var zeroizeShadowBackupNames = []string{"passwd.bak", "group.bak", "shadow.bak", "gshadow.bak"}

// zeroizeEraseAccountBackups removes the account-database backups AFTER the
// login-account teardown that recreates them (#10769 d05-F6): the /etc
// passwd-/shadow-/group-/gshadow- files plus the /var/backups shadow set and
// any editor tilde-backup beside them. Running this in the early seal legs
// would let userdel/passwd re-create pre-modification backups afterwards.
func zeroizeEraseAccountBackups() error {
	var errs []error
	for _, path := range zeroizePasswdBackupPaths {
		if err := zeroizeRemovePath(path); err != nil {
			errs = append(errs, err)
		}
	}
	entries, err := os.ReadDir(zeroizeVarBackupsDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("zeroize: read backup directory %s: %w", zeroizeVarBackupsDir, err))
		}
		return errors.Join(errs...)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		shadow := false
		for _, want := range zeroizeShadowBackupNames {
			if name == want {
				shadow = true
				break
			}
		}
		if !shadow && !strings.HasSuffix(name, "~") {
			continue
		}
		if err := zeroizeRemovePath(filepath.Join(zeroizeVarBackupsDir, name)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// zeroizeCheckDDNSStateEmpty is the preflight used before beginZeroize writes
// any marker or the wipe removes any credentials. Both stores are durable
// authority to delete published records and must be trusted-empty first.
func zeroizeCheckDDNSStateEmpty() error {
	for _, path := range []string{zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath} {
		if err := ddns.CheckStateEmpty(path); err != nil {
			return err
		}
	}
	return nil
}

// zeroizeEraseDDNSState removes only stores the managers have emptied after
// successful backend-fingerprint-checked withdrawal. It runs before any other
// destructive wipe leg so an orphaned RR leaves the config and credentials
// available for an operator retry.
func zeroizeEraseDDNSState() error {
	if err := zeroizeCheckDDNSStateEmpty(); err != nil {
		return fmt.Errorf("%w: %w", errZeroizeDDNSOwnership, err)
	}
	var errs []error
	for _, path := range []string{zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath} {
		if err := ddns.EraseStateIfEmpty(path); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("%w: %w", errZeroizeDDNSOwnership, errors.Join(errs...))
	}
	return nil
}
func zeroizeCheckOwnershipStateEmpty() error {
	if err := zeroizeCheckDDNSStateEmpty(); err != nil {
		return err
	}
	return ipsec.CheckConnStateEmpty(zeroizeIPsecStatePath)
}

func zeroizeEraseIPsecState() error {
	if err := ipsec.CheckConnStateEmpty(zeroizeIPsecStatePath); err != nil {
		return fmt.Errorf("%w: %w", errZeroizeIPsecOwnership, err)
	}
	if err := ipsec.EraseConnStateIfEmpty(zeroizeIPsecStatePath); err != nil {
		return fmt.Errorf("%w: %w", errZeroizeIPsecOwnership, err)
	}
	return nil
}

func zeroizeTruncateFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to truncate non-regular file %s", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("zeroize: truncate %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("zeroize: sync truncated %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("zeroize: close truncated %s: %w", path, err)
	}
	return zeroizeSyncDir(filepath.Dir(path))
}

func zeroizeClearDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("zeroize: refusing to clear non-directory %s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("zeroize: read directory %s: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		if err := zeroizeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	if len(entries) != 0 {
		if err := zeroizeSyncDir(dir); err != nil {
			errs = append(errs, fmt.Errorf("zeroize: sync directory %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}

// zeroizeRemovePath unlinks path and syncs its parent directory so the removal
// is durable before the reset marker clears (#10769 d05-F6). Every seal-leg
// removal funnels through here, so durability holds structurally rather than
// depending on an audited sync inventory at the end of each leg. An absent
// path is the goal (no barrier needed); a sync failure is surfaced
// fail-closed so the reset is never reported clean on unpersisted unlinks.
func zeroizeRemovePath(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if sk, isLink := configstore.SymlinkTarget(path); isLink {
		return fmt.Errorf("zeroize: refusing to erase symlink %s -> %s", sk.Path, sk.Target)
	}
	hardlinks, herr := configstore.CollectHardlinkedFiles(path, "")
	if herr != nil {
		return fmt.Errorf("zeroize: inspect hard links for %s: %w", path, herr)
	}
	if removeErr := os.RemoveAll(path); removeErr != nil {
		return fmt.Errorf("zeroize: remove %s: %w", path, removeErr)
	}
	var errs []error
	if len(hardlinks) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: removed %s but hard-linked bytes survive at %v", path, hardlinks))
	}
	if err := zeroizeSyncDir(filepath.Dir(path)); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync parent of %s: %w", path, err))
	}
	return errors.Join(errs...)
}

func zeroizeRemoveManagedHostKeys(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect managed SSH host keys %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to erase non-regular managed SSH host keys %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("zeroize: read managed SSH host keys %s: %w", path, err)
	}
	if !strings.HasPrefix(string(data), zeroizeManagedHostKeysHeader) {
		slog.Info("zeroize: preserving foreign SSH known-hosts file", "path", path)
		return nil
	}
	return zeroizeRemovePath(path)
}

func zeroizeResetHostname(path string) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zeroize: inspect hostname %s: %w", path, err)
	}
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to replace non-regular hostname %s", path)
	}
	links, err := configstore.CollectHardlinkedFiles(path, "")
	if err != nil {
		return fmt.Errorf("zeroize: inspect hostname hard links %s: %w", path, err)
	}
	if len(links) != 0 {
		return fmt.Errorf("zeroize: hostname %s has hard-linked copies: %v", path, links)
	}
	if err := fsatomic.WriteFileDurable(path, []byte("xpf\n"), 0o644); err != nil {
		return fmt.Errorf("zeroize: reset hostname %s: %w", path, err)
	}
	return nil
}

const zeroizeManagedResolvConfHeader = "# Generated by xpfd — do not edit\n"

func zeroizeRemoveManagedResolvConf(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect managed resolver %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		slog.Info("zeroize: preserving foreign resolver symlink", "path", path)
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to erase non-regular resolver %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("zeroize: read managed resolver %s: %w", path, err)
	}
	if !strings.HasPrefix(string(data), zeroizeManagedResolvConfHeader) {
		slog.Info("zeroize: preserving foreign resolver file", "path", path)
		return nil
	}
	if err := zeroizeRemovePath(path); err != nil {
		return err
	}
	return zeroizeSyncDir(filepath.Dir(path))
}

// keaUnits are the Kea DHCP server units factory reset stops before erasing
// lease state.
var keaUnits = []string{"kea-dhcp4-server", "kea-dhcp6-server"}

// keaUnitActive reports whether a Kea unit is active. Exit 3/4 (inactive /
// unknown) is a definitive "not active"; any other query failure fails
// closed rather than assuming the unit is down.
func keaUnitActive(unit string) (bool, error) {
	out, err := combinedOutputTimeoutUnlimited(context.Background(), "systemctl", "is-active", "--quiet", unit)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && (exitErr.ExitCode() == 3 || exitErr.ExitCode() == 4) {
		return false, nil
	}
	return false, fmt.Errorf("query %s state: %w: %s", unit, err, strings.TrimSpace(string(out)))
}

func stopKeaUnits() error {
	var errs []error
	for _, unit := range keaUnits {
		active, err := keaUnitActive(unit)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !active {
			continue
		}
		out, err := combinedOutputTimeoutUnlimited(context.Background(), "systemctl", "stop", unit)
		if err != nil {
			errs = append(errs, fmt.Errorf("stop %s: %w: %s", unit, err, strings.TrimSpace(string(out))))
		}
	}
	return errors.Join(errs...)
}

// verifyKeaUnitsStopped fails closed unless every Kea unit is verifiably
// inactive. It runs after the stop and immediately before the lease unlink
// so a restart (or a stop that silently failed) cannot re-persist leases
// under the erasure.
func verifyKeaUnitsStopped() error {
	var errs []error
	for _, unit := range keaUnits {
		active, err := keaUnitActive(unit)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if active {
			errs = append(errs, fmt.Errorf("kea unit %s still active after stop", unit))
		}
	}
	return errors.Join(errs...)
}
