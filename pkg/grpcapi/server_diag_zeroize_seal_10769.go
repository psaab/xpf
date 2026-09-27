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

	for _, path := range zeroizeKeaLeasePaths {
		fail(zeroizeRemovePath(path))
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

	for _, path := range zeroizePasswdBackupPaths {
		fail(zeroizeRemovePath(path))
	}

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
	if st, err := os.Stat(zeroizeVarLogDir); err == nil && st.IsDir() {
		fail(zeroizeSyncDir(zeroizeVarLogDir))
	}
	if st, err := os.Stat(zeroizeSSHHostKeyDir); err == nil && st.IsDir() {
		fail(zeroizeSyncDir(zeroizeSSHHostKeyDir))
	}
	if st, err := os.Stat(filepath.Dir(zeroizeMachineIDPath)); err == nil && st.IsDir() {
		fail(zeroizeSyncDir(filepath.Dir(zeroizeMachineIDPath)))
	}
	for _, dir := range []string{
		filepath.Dir(zeroizeHostnamePath),
		filepath.Dir(zeroizeResolvConfPath),
		filepath.Dir(zeroizeKeaLeasePaths[0]),
		filepath.Dir(zeroizeKeaLeasePaths[1]),
	} {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			fail(zeroizeSyncDir(dir))
		}
	}
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

func zeroizeRemovePath(path string) error {
	if sk, isLink := configstore.SymlinkTarget(path); isLink {
		return fmt.Errorf("zeroize: refusing to erase symlink %s -> %s", sk.Path, sk.Target)
	}
	hardlinks, herr := configstore.CollectHardlinkedFiles(path, "")
	if herr != nil {
		return fmt.Errorf("zeroize: inspect hard links for %s: %w", path, herr)
	}
	removeErr := os.RemoveAll(path)
	if removeErr != nil {
		return fmt.Errorf("zeroize: remove %s: %w", path, removeErr)
	}
	if len(hardlinks) != 0 {
		return fmt.Errorf("zeroize: removed %s but hard-linked bytes survive at %v", path, hardlinks)
	}
	return nil
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

func stopKeaUnits() error {
	var errs []error
	for _, unit := range []string{"kea-dhcp4-server", "kea-dhcp6-server"} {
		out, err := combinedOutputTimeoutUnlimited(context.Background(), "systemctl", "is-active", "--quiet", unit)
		if err == nil {
			out, err = combinedOutputTimeoutUnlimited(context.Background(), "systemctl", "stop", unit)
			if err != nil {
				errs = append(errs, fmt.Errorf("stop %s: %w: %s", unit, err, strings.TrimSpace(string(out))))
			}
			continue
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || (exitErr.ExitCode() != 3 && exitErr.ExitCode() != 4) {
			errs = append(errs, fmt.Errorf("query %s state: %w: %s", unit, err, strings.TrimSpace(string(out))))
		}
	}
	return errors.Join(errs...)
}
