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
	"syscall"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/termsafe"
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
	zeroizeHostnamePath        = "/etc/hostname"
	zeroizeHostsPath           = "/etc/hosts"
	zeroizeResolvConfPath      = "/etc/resolv.conf"
	zeroizeDBusMachineIDPath   = "/var/lib/dbus/machine-id"
	zeroizeIPsecStatePath      = ipsec.DefaultConnStatePath
	zeroizeKeaLeasePaths       = []string{dhcpserver.DefaultKeaLeaseFile4Path, dhcpserver.DefaultKeaLeaseFile6Path}
	zeroizeStopKeaUnits        = stopKeaUnits
	zeroizeVerifyKeaStopped    = verifyKeaUnitsStopped
	zeroizeVarBackupsDir       = "/var/backups"
	zeroizeNetworkdLeaseDir    = "/var/lib/systemd/network"
	zeroizeNetifLeaseDir       = "/run/systemd/netif/leases"
	zeroizeNetifLinksDir       = "/run/systemd/netif/links"
	zeroizeNetifServerLeaseDir = "/run/systemd/netif/dhcp-server-lease"
	zeroizeNetifStatePath      = "/run/systemd/netif/state"
	zeroizeDHCPClientStateDirs = []string{"/var/lib/dhcp", "/var/lib/dhclient"}
	zeroizeTmpDirs             = []string{"/tmp", "/var/tmp"}
	zeroizeShmDir              = "/dev/shm"
	zeroizeEtcDir              = "/etc"
	zeroizeRunXPFDir           = "/run/xpf"
	zeroizeRunJournalDir       = "/run/log/journal"
)

var (
	errZeroizeDDNSOwnership  = errors.New("zeroize refused to erase config while DDNS ownership is unresolved")
	errZeroizeIPsecOwnership = errors.New("zeroize refused to erase config while IPsec teardown is unresolved")
	errZeroizeKeaStop        = errors.New("zeroize could not stop Kea before lease-file erasure")
)

const zeroizeManagedHostKeysHeader = "# Managed by xpfd — do not edit\n"

// zeroizeEraseSSHHostKeys removes the sealed ssh_host_* key files. The
// directory is synced unconditionally, even with zero matches: a prior
// attempt may have unlinked entries but failed this barrier, and a retry
// that skips it would let the marker complete over undurable unlinks.
func zeroizeEraseSSHHostKeys() error {
	entries, err := os.ReadDir(zeroizeSSHHostKeyDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var errs []error
	if err != nil {
		errs = append(errs, fmt.Errorf("zeroize: read SSH host-key directory %s: %w", zeroizeSSHHostKeyDir, err))
	} else {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "ssh_host_") {
				if rerr := zeroizeRemovePath(filepath.Join(zeroizeSSHHostKeyDir, entry.Name())); rerr != nil {
					errs = append(errs, rerr)
				}
			}
		}
	}
	if serr := zeroizeSyncDurable(zeroizeSSHHostKeyDir); serr != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync SSH host-key directory %s: %w", zeroizeSSHHostKeyDir, serr))
	}
	return errors.Join(errs...)
}

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

	// machine-id is left present but empty so systemd regenerates it. The
	// D-Bus alias copy is removed outright (D-Bus regenerates a missing one).
	fail(zeroizeTruncateFile(zeroizeMachineIDPath))
	fail(zeroizeRemovePath(zeroizeDBusMachineIDPath))

	// The image seals every ssh_host_* private/public/certificate file. The
	// first-boot xpf-day0-config unit runs ssh-keygen -A before ssh.service, so
	// deleting these here regenerates a fresh device identity on reboot.
	fail(zeroizeEraseSSHHostKeys())

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
	// by apt.
	for _, dir := range []string{zeroizeAptListsDir, zeroizeAptArchiveDir} {
		fail(zeroizeClearDir(dir))
	}

	// Temporary directories (seal tmp-files parity, #10769 d05-F6). /tmp and
	// /var/tmp are cleared of tenant data; /dev/shm is cleared of
	// xpf/DHCP-attributable entries only, since a full shm clear would pull
	// live segments from under still-running host services.
	for _, dir := range zeroizeTmpDirs {
		fail(zeroizeClearTmpDir(dir))
	}
	fail(zeroizeClearShmDir(zeroizeShmDir))

	// Editor backups (seal backup-files parity, #10769 d05-F6). /etc top
	// level is stem-gated to backups of the reset-owned identity files;
	// service directories are swept for backups of the exact basenames xpf
	// renders there (never a bare suffix match over shared dirs).
	fail(zeroizeSweepOwnedEtcBackups(zeroizeEtcDir))
	for _, target := range zeroizeServiceBackupSweepTargets() {
		fail(zeroizeSweepOwnedBackups(target.dir, target.owned))
	}

	// DHCP client identity (#10769 d05-F6), sourced from the image's exact
	// systemd generation (Debian 261.x; paths below verified against the
	// 261.2 source and the shipped 261 networkd binary, which the image
	// enables with DHCP clients on bootstrap fxp0):
	//   - Client leases live in memory (link->dhcp_lease/dhcp6_lease);
	//     v261 writes NO per-ifindex file under /run/systemd/netif/leases/
	//     (the directory is created at startup in networkd.c but has no
	//     writer left in the tree — the leases/<ifindex> shape is legacy).
	//     The leases dir is still cleared wholesale as defense.
	//   - The live client serialization IS per-link /run/systemd/netif/
	//     links/<ifindex> (link_save in networkd-state-file.c, embedding
	//     DHCP-derived DNS/NTP/domains plus DHCP6_CLIENT_IAID/DUID from
	//     link_serialize_dhcp6_client) and the aggregate
	//     /run/systemd/netif/state (manager_save). Both are cleared.
	//   - DUID is runtime-derived, never persisted: the default vendor
	//     DUID is EN 43793 + hashed machine-id (networkd.conf(5)
	//     DUIDType=vendor; sd-dhcp-duid.c performs no file I/O), so the
	//     machine-id truncation above rotates it. IAID defaults to a
	//     siphash of the persistent ifname/MAC (dhcp_identifier_set_iaid),
	//     i.e. hardware-derived, likewise unpersisted.
	//   - Persistent /var/lib/systemd/network/ holds only DHCP SERVER
	//     leases (dhcp-server-lease/<ifname>), which xpf never renders
	//     (no [DHCPServer] in 10-xpf-*; Kea serves DHCP), plus the
	//     runtime server mirror under netif/dhcp-server-lease/. Both are
	//     cleared wholesale regardless.
	// xpf's own per-interface DUIDs live in the config root (erased with
	// it); legacy dhclient state likewise. The running networkd (which the
	// wipe deliberately does not stop — SSH) can only re-serialize
	// prior-tenant bytes pre-reboot; the mandatory reboot gate clears
	// /run and restarts networkd, so post-reboot state derives from the
	// new config with a rotated machine-id/DUID. Entries are cleared with
	// their directories kept: networkd creates the subdirs at startup
	// only, while files are rewritten via temp+rename on every save.
	fail(zeroizeClearDir(zeroizeNetworkdLeaseDir))
	fail(zeroizeClearDir(zeroizeNetifLeaseDir))
	fail(zeroizeClearDir(zeroizeNetifLinksDir))
	fail(zeroizeClearDir(zeroizeNetifServerLeaseDir))
	fail(zeroizeRemovePath(zeroizeNetifStatePath))
	for _, dir := range zeroizeDHCPClientStateDirs {
		fail(zeroizeClearDir(dir))
	}

	// Prior-tenant host trust, resolver, and static host mappings do not
	// survive regardless of xpfd ownership headers: a prior root could strip
	// a header to preserve hostile trust or nameservers, and any pre-reset
	// value is the prior tenant's either way. Trust anchors are removed;
	// resolver and hosts are rewritten to their factory defaults.
	fail(zeroizeEraseKnownHosts(zeroizeManagedHostKeysPath))
	for _, path := range zeroizeManagedDropins {
		fail(zeroizeRemovePath(path))
	}
	fail(zeroizeResetResolvConf(zeroizeResolvConfPath))
	fail(zeroizeResetHosts(zeroizeHostsPath))

	// `logfiles` is part of SYSPREP_ENABLE_OPS. Empty /var/log while retaining
	// the directory for the still-running reset action; post-reset log entries
	// may be written before xpfd stops, but prior-tenant persisted entries are
	// unlinked.
	fail(zeroizeClearDir(zeroizeVarLogDir))
	// Volatile tenant state (#10769 d05-F6): reset is wipe-then-stop with no
	// reboot, so /run/xpf helper state and the volatile journal are cleared
	// in-wipe (services that need them are already stopped) rather than
	// left for a reboot that may never come.
	fail(zeroizeClearRunXPFDir(zeroizeRunXPFDir))
	fail(zeroizeClearDir(zeroizeRunJournalDir))
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

// zeroizeStopKeaAndEraseLeases is a package var (like performZeroizeWipe) so
// the final-verification regression can bypass the Kea leg and prove the
// pre-completion check catches what the bypassed leg missed.
var zeroizeStopKeaAndEraseLeases = func() error {
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

// zeroizeFinalEraseVerification re-proves the race-prone erase sets
// immediately before the pending markers clear: Kea lease files and
// DDNS/IPsec crash temps. Earlier legs erase and verify each of these, but
// later legs run in between; a fence-escaper write landing after an early
// check must fail the wipe here rather than slip under a clean receipt.
// The daemon post-verify remains as defense-in-depth behind it.
func zeroizeFinalEraseVerification() error {
	var errs []error
	for _, current := range zeroizeKeaLeasePaths {
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if _, err := os.Lstat(path); err == nil {
				errs = append(errs, fmt.Errorf("zeroize: Kea lease file %s present at final verification", path))
			} else if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("zeroize: inspect Kea lease file %s: %w", path, err))
			}
		}
	}
	ddnsPaths := []string{zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath}
	for _, path := range ddnsPaths {
		temps, err := ddns.ListCrashTemps(path)
		if err != nil {
			errs = append(errs, err)
		} else if len(temps) != 0 {
			errs = append(errs, fmt.Errorf("zeroize: DDNS crash temps present at final verification: %v", temps))
		}
	}
	if temps, err := ipsec.ListCrashTemps(zeroizeIPsecStatePath); err != nil {
		errs = append(errs, err)
	} else if len(temps) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: IPsec crash temps present at final verification: %v", temps))
	}
	return errors.Join(errs...)
}

// zeroizeShadowBackupNames are the Debian shadow-tools backups in
// /var/backups, rewritten on every passwd/userdel invocation.
var zeroizeShadowBackupNames = []string{"passwd.bak", "group.bak", "shadow.bak", "gshadow.bak"}

// zeroizeShadowTildeStems are the account-database basenames whose editor
// tilde-backups the sweep owns. A bare *~ match would take unrelated
// application/operator backups in the shared /var/backups directory.
var zeroizeShadowTildeStems = []string{"passwd", "shadow", "group", "gshadow"}

// zeroizeEraseAccountBackups removes the account-database backups AFTER the
// login-account teardown that recreates them (#10769 d05-F6): the /etc
// passwd-/shadow-/group-/gshadow- files plus the /var/backups shadow set and
// tilde-backups of the account-database basenames. Running this in the early
// seal legs would let userdel/passwd re-create pre-modification backups
// afterwards.
func zeroizeEraseAccountBackups() error {
	var errs []error
	for _, path := range zeroizePasswdBackupPaths {
		if err := zeroizeRemovePath(path); err != nil {
			errs = append(errs, err)
		}
	}
	entries, err := os.ReadDir(zeroizeVarBackupsDir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(errs...)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("zeroize: read backup directory %s: %w", zeroizeVarBackupsDir, err))
	} else {
		for _, entry := range entries {
			if entry.IsDir() || !isShadowBackupEntry(entry.Name()) {
				continue
			}
			if err := zeroizeRemovePath(filepath.Join(zeroizeVarBackupsDir, entry.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// Always sync, even with zero matches: a prior attempt may have unlinked
	// entries but failed this barrier (retry durability).
	if serr := zeroizeSyncDurable(zeroizeVarBackupsDir); serr != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync backup directory %s: %w", zeroizeVarBackupsDir, serr))
	}
	return errors.Join(errs...)
}

// isShadowBackupEntry reports whether a /var/backups entry is a shadow-tools
// account backup: one of the exact shadow names, or a tilde-backup of an
// account-database basename. Anything else in the shared directory (other
// applications' backups) is left alone.
func isShadowBackupEntry(name string) bool {
	for _, want := range zeroizeShadowBackupNames {
		if name == want {
			return true
		}
	}
	if !strings.HasSuffix(name, "~") {
		return false
	}
	stem, ok := editorBackupStem(name)
	if !ok {
		return false
	}
	for _, want := range zeroizeShadowTildeStems {
		if stem == want {
			return true
		}
	}
	return false
}

// zeroizeTmpPreservedPrefixes are tmp entries that belong to live service
// infrastructure rather than tenant data: systemd private-tmp mount points
// and snap's private tmp. Unlinking those would destabilize still-running
// host services for no tenant-clean gain (their contents are namespaced
// away from the host view anyway).
var zeroizeTmpPreservedPrefixes = []string{"systemd-private-", "snap-private-tmp-"}

// zeroizeClearTmpDir removes every entry in a tmp directory (#10769 d05-F6,
// seal tmp-files parity). Unlike zeroizeRemovePath it unlinks symlinks,
// sockets, fifos, and device nodes as names rather than refusing them: by
// the FHS tmp contract nothing here is persistent service state, factory
// reset is a decommissioning operation, and live file descriptors survive
// an unlink. Only the preserved service-infrastructure prefixes are kept.
func zeroizeClearTmpDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read tmp directory %s: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		preserved := false
		for _, prefix := range zeroizeTmpPreservedPrefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				preserved = true
				break
			}
		}
		if preserved {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			zeroizeWarnEscapingInteriorLinks(full)
		}
		// os.RemoveAll on a symlink removes the link, never the target.
		if err := os.RemoveAll(full); err != nil {
			errs = append(errs, fmt.Errorf("zeroize: remove tmp entry %s: %w", filepath.Join(dir, entry.Name()), err))
		}
	}
	// Always sync an existing directory, even when nothing was removed: a
	// prior attempt may have unlinked entries but failed this barrier.
	if err := zeroizeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync tmp directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// zeroizeIsShmResetEntry reports whether a /dev/shm entry is attributable to
// xpf/DHCP and therefore safe to unlink on reset. A full shm clear would
// pull live shared-memory segments out from under still-running host
// services; arbitrary prior-tenant shm outside these patterns is reboot-
// cleared tmpfs (documented residual for stop-without-reboot).
func zeroizeIsShmResetEntry(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"xpf", "kea", "dhcp"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "xpf") || strings.Contains(lower, "kea")
}

func zeroizeClearShmDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read shm directory %s: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || !zeroizeIsShmResetEntry(entry.Name()) {
			continue
		}
		if err := zeroizeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even with zero matches: retry
	// durability for a prior unlink whose barrier failed.
	if err := zeroizeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync shm directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// editorBackupStem strips an editor-backup suffix (~, .bak, .old, .orig)
// and reports the stem. Used to scope backup sweeps to backups OF owned
// files rather than every backup-suffixed name on the box.
func editorBackupStem(name string) (string, bool) {
	if strings.HasSuffix(name, "~") {
		return strings.TrimSuffix(name, "~"), true
	}
	for _, suffix := range []string{".bak", ".old", ".orig"} {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix), true
		}
	}
	return "", false
}

// zeroizeSweepOwnedBackups removes the editor backups inside dir whose stem
// the owned predicate accepts. A symlinked backup fails closed for operator
// inspection.
func zeroizeSweepOwnedBackups(dir string, owned func(stem string) bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read directory %s for backup sweep: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		stem, ok := editorBackupStem(entry.Name())
		if !ok || !owned(stem) {
			continue
		}
		if err := zeroizeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even with zero matches: retry
	// durability for a prior unlink whose barrier failed.
	if err := zeroizeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync backup directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// zeroizeOwnedEtcBackupStems are the /etc top-level files whose editor
// backups the reset owns: backups of the identity files it resets.
var zeroizeOwnedEtcBackupStems = []string{"hostname", "hosts", "resolv.conf", "passwd", "shadow", "group", "gshadow"}

// zeroizeSweepOwnedEtcBackups removes editor backups of the reset-owned
// /etc files (hostname.bak, hosts~, ...). /etc is a shared root, so unlike
// the service-dir sweep this one gates on the stem: a backup of any other
// file is left for the operator.
func zeroizeSweepOwnedEtcBackups(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read directory %s for backup sweep: %w", dir, err)
	}
	owned := make(map[string]bool, len(zeroizeOwnedEtcBackupStems))
	for _, stem := range zeroizeOwnedEtcBackupStems {
		owned[stem] = true
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		stem, ok := editorBackupStem(entry.Name())
		if !ok || !owned[stem] {
			continue
		}
		if err := zeroizeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even with zero matches: retry
	// durability for a prior unlink whose barrier failed.
	if err := zeroizeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync backup directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// zeroizeBackupSweepTarget pairs a directory with an ownership predicate
// over backup stems: only backups OF xpf-rendered basenames are erased.
// These directories are NOT xpf-exclusive (an operator's sshd_config.bak
// sits beside ssh_known_hosts), so a bare suffix sweep would take unowned
// files.
type zeroizeBackupSweepTarget struct {
	dir   string
	owned func(stem string) bool
}

// zeroizeServiceBackupSweepTargets returns the service directories whose
// backups-of-rendered-files the reset erases: the xpf drop-in dirs (gated
// on the drop-in basenames), the rendered-config dirs (gated on the
// rendered basenames), the SSH config dir (known_hosts only), and the
// rsyslog/networkd dirs (gated on the 10-xpf- ownership shape the wipe
// legs themselves use). Derived from the seamed path vars so tests
// relocate the whole inventory into a disposable tree.
func zeroizeServiceBackupSweepTargets() []zeroizeBackupSweepTarget {
	stemsByDir := make(map[string]map[string]bool)
	add := func(dir, stem string) {
		if stemsByDir[dir] == nil {
			stemsByDir[dir] = make(map[string]bool)
		}
		stemsByDir[dir][stem] = true
	}
	for _, dropin := range zeroizeManagedDropins {
		add(filepath.Dir(dropin), filepath.Base(dropin))
	}
	add(zeroizeSSHHostKeyDir, filepath.Base(zeroizeManagedHostKeysPath))
	add(filepath.Dir(zeroizeFRRConf), filepath.Base(zeroizeFRRConf))
	add(filepath.Dir(zeroizeSwanctlSnippet), filepath.Base(zeroizeSwanctlSnippet))
	add(filepath.Dir(zeroizeKea4Conf), filepath.Base(zeroizeKea4Conf))
	add(filepath.Dir(zeroizeKea6Conf), filepath.Base(zeroizeKea6Conf))
	var out []zeroizeBackupSweepTarget
	for dir, stems := range stemsByDir {
		out = append(out, zeroizeBackupSweepTarget{dir: dir, owned: func(stem string) bool {
			return stems[stem]
		}})
	}
	out = append(out,
		zeroizeBackupSweepTarget{dir: zeroizeRsyslogConfDir, owned: func(stem string) bool {
			return strings.HasPrefix(stem, "10-xpf-") && strings.HasSuffix(stem, ".conf")
		}},
		zeroizeBackupSweepTarget{dir: zeroizeNetworkdDir, owned: func(stem string) bool {
			return strings.HasPrefix(stem, "10-xpf-")
		}},
	)
	return out
}

// zeroizeRunXPFPreserved is the one /run/xpf entry the wipe must not
// unlink: the host-wide upgrade lock a later wipe leg acquires for mutual
// exclusion with a concurrent upgrade. Unlinking it would let the wipe
// lock a fresh inode while an upgrade holds the old one.
const zeroizeRunXPFPreserved = "upgrade.lock"

// zeroizeClearRunXPFDir removes xpf runtime state (#10769 d05-F6): helper
// sockets and state files carrying tenant flow/session data. Reset is
// wipe-then-stop with no reboot, so volatile state left here would be
// observable pre-reboot. Unlinking a live socket's name does not disturb
// its established connections; the upgrade lock is preserved.
func zeroizeClearRunXPFDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read run directory %s: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		if entry.Name() == zeroizeRunXPFPreserved {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			zeroizeWarnEscapingInteriorLinks(full)
		}
		// Names only: RemoveAll on a symlink removes the link, and live
		// socket fds survive their name's unlink.
		if err := os.RemoveAll(full); err != nil {
			errs = append(errs, fmt.Errorf("zeroize: remove run entry %s: %w", filepath.Join(dir, entry.Name()), err))
		}
	}
	// Always sync an existing directory, even when nothing was removed: a
	// prior attempt may have unlinked entries but failed this barrier.
	if err := zeroizeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync run directory %s: %w", dir, err))
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

// zeroizeSyncDurable syncs dir, or the nearest existing ancestor when dir
// itself is absent. Retry durability for removals: if an earlier attempt
// unlinked entries (or the directory) but failed its barrier, a retry that
// finds nothing must still sync the survivor — otherwise the marker can
// complete with the unlink undurable. Syncing the surviving ancestor makes
// the ancestor's removal durable too, closing the debt structurally.
func zeroizeSyncDurable(dir string) error {
	d := filepath.Clean(dir)
	for {
		if _, err := os.Lstat(d); err == nil {
			return zeroizeSyncDir(d)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("zeroize: inspect %s: %w", d, err)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return fmt.Errorf("zeroize: no existing ancestor for %s", dir)
		}
		d = parent
	}
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
	// Always sync an existing directory, even when it read empty: a prior
	// attempt may have unlinked its entries but failed this barrier, and a
	// retry that skips it would let the marker complete over undurable
	// unlinks. A never-existing directory carries no debt and returns nil
	// above.
	if err := zeroizeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// zeroizeRemovePath unlinks path and syncs its parent directory so the removal
// is durable before the reset marker clears (#10769 d05-F6). Every seal-leg
// removal funnels through here, so durability holds structurally rather than
// depending on an audited sync inventory at the end of each leg. An absent
// path still syncs the nearest surviving ancestor: an earlier attempt may
// have unlinked it (or its parent) but failed the barrier, and skipping the
// sync on retry would let a later attempt complete the marker with that
// unlink undurable. A sync failure is surfaced fail-closed so the reset is
// never reported clean on unpersisted unlinks.
func zeroizeRemovePath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Retry durability: the unlink may have landed on an attempt whose
		// barrier failed. Syncing the nearest surviving ancestor retires
		// that debt and also makes an ancestor's own removal durable.
		if err := zeroizeSyncDurable(filepath.Dir(path)); err != nil {
			return fmt.Errorf("zeroize: sync parent of %s: %w", path, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect %s: %w", path, err)
	}
	if sk, isLink := configstore.SymlinkTarget(path); isLink {
		return fmt.Errorf("zeroize: refusing to erase symlink %s -> %s", sk.Path, sk.Target)
	}
	if info.IsDir() {
		zeroizeWarnEscapingInteriorLinks(path)
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
	if err := zeroizeSyncDurable(filepath.Dir(path)); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync parent of %s: %w", path, err))
	}
	return errors.Join(errs...)
}

// zeroizeWarnEscapingInteriorLinks censuses symlinks inside a directory the
// wipe is about to remove wholesale. RemoveAll unlinks those links without
// following them, so a target outside the tree survives by design —
// following links out of the owned tree would itself violate ownership
// boundaries. Each escape is logged with link and target so a successful
// wipe never silently implies out-of-tree bytes were removed.
func zeroizeWarnEscapingInteriorLinks(root string) {
	interior, err := configstore.CollectInteriorSymlinks(root, "")
	if err != nil {
		slog.Warn("zeroize: interior symlink census incomplete", "dir", root, "err", err)
	}
	for _, sk := range interior {
		if zeroizeLinkTargetEscapes(root, sk.Path, sk.Target) {
			slog.Warn("zeroize: interior symlink target outside the erased tree survives (out of erase scope)",
				"link", sk.Path, "target", sk.Target)
		}
	}
}

// zeroizeLinkTargetEscapes reports whether a symlink's target resolves
// outside root. Lexical only (consistent with the pathname-walk census);
// an unresolvable target counts as escaping so it is logged, not missed.
func zeroizeLinkTargetEscapes(root, linkPath, target string) bool {
	abs := target
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(filepath.Dir(linkPath), target)
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(abs))
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// zeroizeEraseKnownHosts removes the system-wide SSH known-hosts file whether
// or not it carries the xpfd ownership header (#10769 d05-F6). The header is
// hygiene, not a security boundary against a prior-root tenant: prior root
// could strip the header to preserve hostile trust anchors across the reset,
// and any pre-reset trust is the prior tenant's either way. A symlink is
// unlinked (the link, never the target); any other non-regular file fails
// closed for operator inspection.
func zeroizeEraseKnownHosts(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Retry durability: a prior attempt may have unlinked the file
		// but failed its barrier; sync the surviving ancestor anyway.
		if serr := zeroizeSyncDurable(filepath.Dir(path)); serr != nil {
			return fmt.Errorf("zeroize: sync parent of absent known-hosts %s: %w", path, serr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect SSH known-hosts %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		slog.Info("zeroize: removing foreign SSH known-hosts symlink", "path", path)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("zeroize: remove known-hosts symlink %s: %w", path, err)
		}
		return zeroizeSyncDir(filepath.Dir(path))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to erase non-regular SSH known-hosts %s", path)
	}
	if data, err := os.ReadFile(path); err != nil {
		return fmt.Errorf("zeroize: read SSH known-hosts %s: %w", path, err)
	} else if !strings.HasPrefix(string(data), zeroizeManagedHostKeysHeader) {
		slog.Info("zeroize: removing foreign SSH known-hosts file (no xpfd header; prior-tenant trust does not survive reset)", "path", path)
	}
	return zeroizeRemovePath(path)
}

// zeroizeSethostname sets the live kernel hostname during reset. A package
// var (mirroring the daemon's sethostname seam) so tests observe the call
// without renaming the test host; production is syscall.Sethostname.
var zeroizeSethostname = syscall.Sethostname

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
	// Reset is wipe-then-stop with no reboot: the live kernel name must move
	// with the file or the prior-tenant transient hostname stays observable
	// pre-reboot. A failed sethostname fails the wipe (a failed reset
	// restores both via the daemon identity snapshot).
	if err := zeroizeSethostname([]byte("xpf")); err != nil {
		return fmt.Errorf("zeroize: set live hostname: %w", err)
	}
	return nil
}

const zeroizeManagedResolvConfHeader = "# Generated by xpfd — do not edit\n"

// zeroizeDefaultHosts is the factory /etc/hosts: loopback plus the reset
// hostname's 127.0.1.1 mapping (Debian convention), no tenant entries.
const zeroizeDefaultHosts = "127.0.0.1 localhost\n" +
	"::1 localhost ip6-localhost ip6-loopback\n" +
	"127.0.1.1 xpf\n" +
	"ff02::1 ip6-allnodes\n" +
	"ff02::2 ip6-allrouters\n"

// zeroizeWriteFileDurableOrInPlace writes path durably, falling back to an
// in-place write when path is a bind mount (EXDEV/EBUSY on rename, common
// for /etc/resolv.conf in containers — the daemon's DNS reconciler carries
// the same fallback). The in-place path truncates and syncs; it never
// follows a symlink (callers unlink links first).
func zeroizeWriteFileDurableOrInPlace(path string, data []byte, perm os.FileMode) error {
	if err := fsatomic.WriteFileDurable(path, data, perm); err == nil {
		return nil
	} else if !isZeroizeCrossDeviceOrBusy(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return fmt.Errorf("zeroize: in-place write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("zeroize: in-place write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("zeroize: sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("zeroize: close %s: %w", path, err)
	}
	return nil
}

func isZeroizeCrossDeviceOrBusy(err error) bool {
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EBUSY)
}

// zeroizeResetResolvConf replaces the resolver file with the header-only
// empty default whether or not it carries the xpfd header (#10769 d05-F6).
// Like the known-hosts header, it is hygiene, not a security boundary
// against prior root: a headerless file keeps prior nameservers across the
// reset otherwise. A symlink (e.g. the systemd stub link) is replaced by a
// regular file, matching the production ownership model (xpf owns
// /etc/resolv.conf directly, resolved masked). Only the prior nameserver
// count is logged, never their addresses.
func zeroizeResetResolvConf(path string) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zeroize: inspect resolver %s: %w", path, err)
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			slog.Info("zeroize: replacing foreign resolver symlink with the reset default", "path", path)
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("zeroize: remove resolver symlink %s: %w", path, err)
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("zeroize: refusing to replace non-regular resolver %s", path)
		} else if data, rerr := os.ReadFile(path); rerr != nil {
			return fmt.Errorf("zeroize: read resolver %s: %w", path, rerr)
		} else if !strings.HasPrefix(string(data), zeroizeManagedResolvConfHeader) {
			slog.Info("zeroize: resetting foreign resolver file to the empty default", "path", path)
		}
	}
	if links, err := configstore.CollectHardlinkedFiles(path, ""); err != nil {
		return fmt.Errorf("zeroize: inspect resolver hard links %s: %w", path, err)
	} else if len(links) != 0 {
		return fmt.Errorf("zeroize: resolver %s has hard-linked copies: %v", path, links)
	}
	if err := zeroizeWriteFileDurableOrInPlace(path, []byte(zeroizeManagedResolvConfHeader), 0o644); err != nil {
		return fmt.Errorf("zeroize: reset resolver %s: %w", path, err)
	}
	// Redundant with the durable write above, but routed through the test
	// seam so the barrier inventory stays observable.
	return zeroizeSyncDir(filepath.Dir(path))
}

// zeroizeResetHosts replaces /etc/hosts with the factory default: prior
// static mappings (tenant hostnames, MITM entries a prior root could have
// planted) must not survive. A symlink is replaced, never followed.
func zeroizeResetHosts(path string) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zeroize: inspect hosts %s: %w", path, err)
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			slog.Info("zeroize: replacing hosts symlink with the reset default", "path", path)
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("zeroize: remove hosts symlink %s: %w", path, err)
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("zeroize: refusing to replace non-regular hosts %s", path)
		}
	}
	if links, err := configstore.CollectHardlinkedFiles(path, ""); err != nil {
		return fmt.Errorf("zeroize: inspect hosts hard links %s: %w", path, err)
	} else if len(links) != 0 {
		return fmt.Errorf("zeroize: hosts %s has hard-linked copies: %v", path, links)
	}
	if err := zeroizeWriteFileDurableOrInPlace(path, []byte(zeroizeDefaultHosts), 0o644); err != nil {
		return fmt.Errorf("zeroize: reset hosts %s: %w", path, err)
	}
	// Redundant with the durable write above, but routed through the test
	// seam so the barrier inventory stays observable.
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
	return false, fmt.Errorf("query %s state: %w: %s", unit, err, termsafe.SanitizeForDisplay(strings.TrimSpace(string(out))))
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
			errs = append(errs, fmt.Errorf("stop %s: %w: %s", unit, err, termsafe.SanitizeForDisplay(strings.TrimSpace(string(out)))))
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
