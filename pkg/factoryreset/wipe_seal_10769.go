package factoryreset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/termsafe"
)

// The system-path seams mirror the image's SYSPREP_ENABLE_OPS and
// SYSPREP_PURGE_PATHS. wipeSealMapping below binds every member of those
// tuples to its zeroize leg or survivor reason, and seal_parity_test.go
// parses the tuples from scripts/image/bake.py so drift reds (#17085).
// Tests point them at a disposable tree; production values
// remain the image paths whose previous-tenant state must not survive reset.
var (
	wipeMachineIDPath         = "/etc/machine-id"
	wipeApplianceMarkerPath   = "/etc/xpf/appliance"
	wipeSSHHostKeyDir         = "/etc/ssh"
	wipeRootSSHUserDir        = "/root/.ssh"
	wipeRootBashHistory       = "/root/.bash_history"
	wipeSNMPEngineIDPath           = "/var/lib/xpf/snmp-engine-id"
	wipeSNMPEngineBootsPath        = "/var/lib/xpf/snmp-engineboots"
	wipeUEFIStatePath              = "/var/lib/xpf/uefi-bootorder-front"
	wipeFeedShrinkHistoryPath      = configstore.FeedShrinkHistoryPath
	wipeEthtoolForcedRegistryPath  = configstore.EthtoolForcedRegistryPath
	wipeSystemdRandomSeed          = "/var/lib/systemd/random-seed"
	wipeAptListsDir                = "/var/lib/apt/lists"
	wipeAptArchiveDir         = "/var/cache/apt/archives"
	wipeRunUtmpPath           = "/run/utmp"
	wipeDay0RejectedPath      = "/etc/xpf/.day0-config-rejected"
	wipeRootGrownPath         = "/etc/xpf/.root-grown"
	wipeDDNSLeaseStatePath    = ddns.DefaultLeaseStatePath()
	wipeDDNSSurfaceAPath      = ddns.DefaultSurfaceAStatePath()
	wipePasswdBackupPaths     = []string{"/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-"}
	wipeManagedHostKeysPath   = "/etc/ssh/ssh_known_hosts"
	wipeManagedDropins        = []string{
		"/etc/ssh/sshd_config.d/00-xpf.conf",
		"/etc/ssh/sshd_config.d/xpf.conf",
		"/etc/chrony/sources.d/xpf.sources",
		"/etc/chrony/conf.d/xpf-threshold.conf",
		"/etc/systemd/resolved.conf.d/xpf.conf",
		"/etc/systemd/resolved.conf.d/bpfrx.conf",
	}
	wipeHostnamePath        = "/etc/hostname"
	wipeHostsPath           = "/etc/hosts"
	wipeResolvConfPath      = "/etc/resolv.conf"
	wipeDBusMachineIDPath   = "/var/lib/dbus/machine-id"
	wipeIPsecStatePath      = ipsec.DefaultConnStatePath
	wipeKeaLeasePaths       = []string{dhcpserver.DefaultKeaLeaseFile4Path, dhcpserver.DefaultKeaLeaseFile6Path}
	wipeStopKeaUnits        = stopKeaUnits
	wipeVerifyKeaStopped    = verifyKeaUnitsStopped
	wipeVarBackupsDir       = "/var/backups"
	wipeNetworkdLeaseDir    = "/var/lib/systemd/network"
	wipeNetifLeaseDir       = "/run/systemd/netif/leases"
	wipeNetifLinksDir       = "/run/systemd/netif/links"
	wipeNetifServerLeaseDir = "/run/systemd/netif/dhcp-server-lease"
	wipeNetifStatePath      = "/run/systemd/netif/state"
	wipeDHCPClientStateDirs = []string{"/var/lib/dhcp", "/var/lib/dhclient"}
	wipeTmpDirs             = []string{"/tmp", "/var/tmp"}
	wipeShmDir              = "/dev/shm"
	wipeEtcDir              = "/etc"
	wipeRunXPFDir           = "/run/xpf"
	wipeRunJournalDir       = "/run/log/journal"
)

var (
	errWipeDDNSOwnership  = errors.New("zeroize refused to erase config while DDNS ownership is unresolved")
	errWipeIPsecOwnership = errors.New("zeroize refused to erase config while IPsec teardown is unresolved")
	errWipeKeaStop        = errors.New("zeroize could not stop Kea before lease-file erasure")
)

// wipeSealDisposition is the zeroize disposition of one image-seal member:
// exactly one of leg (the member is erased by the production wipe the parity
// test drives end-to-end) or survivor (a reason the member deliberately
// survives the wipe legs, with its narrowing).
// The leg field is an honest marker, not a callable: production posture
// gates (appliance-only legs, #16448) and the configured config root live
// inside performWipe / wipeImageSealResidue, so no per-member closure here
// could be production-identical without re-implementing them. The parity
// test therefore drives PerformZeroizeWipe once against the redirected
// tree and asserts every leg member's planted path is gone.
type wipeSealDisposition struct {
	leg      bool
	survivor string
}

// wipeSealMapping binds every member of bake.py's SYSPREP_ENABLE_OPS and
// SYSPREP_PURGE_PATHS (#17085, R4-Q46-01) to its zeroize disposition. It is
// the single source the parity test (seal_parity_test.go) checks: the test
// parses both tuples from scripts/image/bake.py, so a new seal member with
// no row here — or a deleted row — reds there. Keys are the tuple members
// verbatim (virt-sysprep op names for ENABLE, absolute paths for PURGE).
// A leg:true row asserts the production wipe (performWipe, driven by the
// parity test via PerformZeroizeWipe) erases the member under its real
// posture gates; it does not name a function to call.
var wipeSealMapping = map[string]wipeSealDisposition{
	// SYSPREP_ENABLE_OPS.
	// machine-id: rotated (fresh random bytes) by the appliance-only leg in
	// wipeImageSealResidue; on a foreign host the operator host keeps its id.
	"machine-id": {leg: true},
	// ssh-hostkeys: erased by wipeEraseSSHHostKeys, appliance-only.
	"ssh-hostkeys": {leg: true},
	// ssh-userdir: root's .ssh, erased appliance-only (foreign-host root
	// material is owned by the marker-aware login teardown, #16448).
	"ssh-userdir": {leg: true},
	// logfiles: /var/log cleared appliance-only; on a foreign host only the
	// xpf-owned firewall logs are erased (wipeFirewallLogs).
	"logfiles": {leg: true},
	// tmp-files: /tmp and /var/tmp cleared appliance-only.
	"tmp-files": {leg: true},
	// bash-history: root's .bash_history, erased appliance-only.
	"bash-history": {leg: true},
	// package-manager-cache: apt lists/archives cleared appliance-only.
	"package-manager-cache": {leg: true},
	// backup-files: editor backups swept on every host, stem-gated to
	// backups of reset-owned files (wipeSweepOwnedEtcBackups and
	// wipeServiceBackupSweepTargets), never a bare suffix sweep.
	"backup-files": {leg: true},
	// passwd-backups: wipeEraseAccountBackups, run after the login-account
	// teardown that recreates them (every host).
	"passwd-backups": {leg: true},
	// utmp: /run/utmp removed appliance-only.
	"utmp": {leg: true},
	// SYSPREP_PURGE_PATHS.
	// .configdb and xpf.conf: erased by wipeConfigDir against the
	// CONFIGURED config root handed to PerformZeroizeWipe (wipe.go: the
	// configured root, not the hardcoded /etc/xpf default), every host.
	"/etc/xpf/.configdb": {leg: true},
	"/etc/xpf/xpf.conf":  {leg: true},
	"/etc/xpf/.day0-config-applied": {
		survivor: "overwritten by beginZeroize with the prefixed zeroize-pending record (a metadata record holding ConfigDir/ConfigBase/ArchiveDir and log-file basenames, not tenant secrets), preserved by the config leg while the pending prefix is present, and removed only by completeZeroize after every wipe leg and final verification succeed; on failure it stays as the fail-closed loader gate",
	},
	"/etc/xpf/.day0-config-rejected":    {leg: true},
	"/etc/xpf/.root-grown":              {leg: true},
	"/var/lib/xpf/snmp-engine-id":       {leg: true},
	"/var/lib/xpf/snmp-engineboots":     {leg: true},
	"/var/lib/xpf/uefi-bootorder-front": {leg: true},
	// random-seed: removed appliance-only (host state on a foreign host).
	"/var/lib/systemd/random-seed": {leg: true},
	// apt lists glob: the lists dir is cleared appliance-only.
	"/var/lib/apt/lists/*": {leg: true},
}

const wipeManagedHostKeysHeader = "# Managed by xpfd — do not edit\n"

// wipeEraseSSHHostKeys removes the sealed ssh_host_* key files. The
// directory is synced unconditionally, even with zero matches: a prior
// attempt may have unlinked entries but failed this barrier, and a retry
// that skips it would let the marker complete over undurable unlinks.
func wipeEraseSSHHostKeys() error {
	entries, err := os.ReadDir(wipeSSHHostKeyDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var errs []error
	if err != nil {
		errs = append(errs, fmt.Errorf("zeroize: read SSH host-key directory %s: %w", wipeSSHHostKeyDir, err))
	} else {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "ssh_host_") {
				if rerr := wipeRemovePath(filepath.Join(wipeSSHHostKeyDir, entry.Name())); rerr != nil {
					errs = append(errs, rerr)
				}
			}
		}
	}
	if serr := wipeSyncDurable(wipeSSHHostKeyDir); serr != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync SSH host-key directory %s: %w", wipeSSHHostKeyDir, serr))
	}
	return errors.Join(errs...)
}

// wipeIsApplianceHost reports whether the bake-written appliance marker
// (/etc/xpf/appliance, docs/install-images.md #7114) is present. Only an
// appliance host is wholly xpf-owned: a foreign-host .deb install is a
// guest on an operator-managed host, so the image-seal legs that erase
// host-owned state must not run there (#16448). A probe error other than
// absence fails closed (not appliance): skipping a destructive leg is
// recoverable, deleting host data is not.
func wipeIsApplianceHost() bool {
	_, err := os.Stat(wipeApplianceMarkerPath)
	return err == nil
}

// wipeImageSealResidue removes the safely-regenerable members of the
// image's own factory seal set. It deliberately leaves files whose deletion
// would destroy live service state or lacks a regeneration/ownership proof;
// see the survivor decisions below.
//
// Host-owned legs — machine-id rotation, SSH host keys, root's .ssh and
// shell history, apt caches, /tmp//var/tmp, /var/log, /etc/hosts,
// /etc/hostname and the volatile journal — run ONLY on an appliance host
// (wipeIsApplianceHost, #16448). On a foreign host they would irreversibly
// delete data xpf does not own (root's unmarked SSH material, the host's
// audit trail and scratch data); the ownership-aware legs below and the
// marker-aware login teardown in performWipe own the foreign-host reset.
// /etc/resolv.conf is the exception: xpfd owns it as a plain file on every
// host (pkg/daemon masks systemd-resolved at startup), so resetting it
// stays within xpf ownership on both postures. xpf-owned state (SNMP/feed/
// day-0 state, xpf drop-ins, DHCP client serialization, editor backups of
// xpf-rendered files, /run/xpf) is erased on both postures.
func wipeImageSealResidue() error {
	appliance := wipeIsApplianceHost()
	var errs []error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}

	// Appliance-only: rotating the host's machine-id (and its D-Bus alias)
	// re-identifies an operator-managed foreign host (#16448).
	if appliance {
		// machine-id is replaced with fresh random bytes (deliberately NOT
		// the seal's truncate: v261 regenerates an empty id from the stable
		// SMBIOS UUID on VMs, reproducing the prior DUID-EN). The D-Bus
		// alias copy is removed in either shape it ships (symlink or file).
		fail(wipeRotateMachineID(wipeMachineIDPath))
		fail(wipeEraseDBusMachineID(wipeDBusMachineIDPath))

		// The image seals every ssh_host_* private/public/certificate file. The
		// dedicated xpf-ssh-hostkeys unit runs ssh-keygen -A before ssh.service
		// whenever the keys are absent (#16445), so deleting these here
		// regenerates a fresh device identity on reboot — including after an
		// interrupted reset, whose pending marker still gates the day-0 loader.
		fail(wipeEraseSSHHostKeys())

		// The sysprep ssh-userdir and bash-history operations apply to root here.
		// Provisioned non-root homes have already been handled by the marker-aware
		// login teardown; unrelated operator accounts remain outside xpf ownership.
		// On a foreign host root's unmarked .ssh is the operator's own SSH
		// material: the marker-aware wipeRootLoginAccount owns root revocation
		// there and preserves unmarked keys (#16448).
		fail(wipeRemovePath(wipeRootSSHUserDir))
		fail(wipeRemovePath(wipeRootBashHistory))
	}

	// xpf-owned identity/state on every host: SNMP engine identity (the
	// daemon regenerates it), forced-NIC state and name-keyed feed-shrink
	// history (tenant state that must not cross a reset), and the day-0
	// rejection / root-grow first-boot markers under /etc/xpf.
	for _, path := range []string{
		wipeSNMPEngineIDPath,
		wipeSNMPEngineBootsPath,
		wipeUEFIStatePath,
		wipeEthtoolForcedRegistryPath,
		wipeFeedShrinkHistoryPath,
		wipeDay0RejectedPath,
		wipeRootGrownPath,
	} {
		fail(wipeRemovePath(path))
	}
	fail(wipeEthtoolForcedRegistryCrashTemps(wipeEthtoolForcedRegistryPath))
	fail(feeds.EraseShrinkHistoryCrashTemps(wipeFeedShrinkHistoryPath))

	// Appliance-only: systemd's persisted random seed and /run/utmp are
	// host state the seal rotates/clears; apt lists and archives are the
	// host's package caches. None is xpf-owned on a foreign host (#16448).
	if appliance {
		fail(wipeRemovePath(wipeSystemdRandomSeed))
		fail(wipeRemovePath(wipeRunUtmpPath))
		// NOTE: the passwd-/shadow-/group-/gshadow- backups are NOT erased here.
		// Shadow tools recreate them on every userdel/passwd invocation, and the
		// login-account teardown runs those commands after this function returns.
		// wipeEraseAccountBackups runs after that teardown instead.
		// Package lists and downloaded archives are caches and can be recreated
		// by apt.
		for _, dir := range []string{wipeAptListsDir, wipeAptArchiveDir} {
			fail(wipeClearDir(dir))
		}
	}

	// Appliance-only: /tmp and /var/tmp hold the host's scratch data on a
	// foreign host (#16448). /dev/shm stays gated to xpf/DHCP-attributable
	// entries on every host (wipeClearShmDir already scopes it).
	if appliance {
		// Temporary directories (seal tmp-files parity, #10769 d05-F6). /tmp and
		// /var/tmp are cleared of tenant data.
		for _, dir := range wipeTmpDirs {
			fail(wipeClearTmpDir(dir))
		}
	}
	fail(wipeClearShmDir(wipeShmDir))

	// Editor backups (seal backup-files parity, #10769 d05-F6). /etc top
	// level is stem-gated to backups of the reset-owned identity files;
	// service directories are swept for backups of the exact basenames xpf
	// renders there (never a bare suffix match over shared dirs).
	fail(wipeSweepOwnedEtcBackups(wipeEtcDir))
	for _, target := range wipeServiceBackupSweepTargets() {
		fail(wipeSweepOwnedBackups(target.dir, target.owned))
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
	//     DUIDType=vendor; sd-dhcp-duid.c performs no file I/O), so on an
	//     appliance the fresh machine-id installed above rotates it on every
	//     target (truncate alone would regenerate the same firmware UUID on
	//     VMs). IAID defaults to a siphash of the persistent ifname/MAC
	//     (dhcp_identifier_set_iaid): stable-by-design hardware identity,
	//     not tenant-secret residue, likewise unpersisted.
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
	if appliance {
		fail(wipeClearDir(wipeNetworkdLeaseDir))
		fail(wipeClearDir(wipeNetifLeaseDir))
		fail(wipeClearDir(wipeNetifLinksDir))
		fail(wipeClearDir(wipeNetifServerLeaseDir))
		fail(wipeRemovePath(wipeNetifStatePath))
		for _, dir := range wipeDHCPClientStateDirs {
			fail(wipeClearDir(dir))
		}
	}

	// xpf-rendered drop-ins are xpf-owned on every host.
	for _, path := range wipeManagedDropins {
		fail(wipeRemovePath(path))
	}
	// /etc/resolv.conf is xpf-owned on every host (see the function doc):
	// resetting it to the header-only default stays within xpf ownership.
	fail(wipeResetResolvConf(wipeResolvConfPath))

	if appliance {
		// Prior-tenant host trust and static host mappings do not
		// survive regardless of xpfd ownership headers: a prior root could strip
		// a header to preserve hostile trust, and any pre-reset
		// value is the prior tenant's either way. Trust anchors are removed;
		// hosts is rewritten to its factory default. On a foreign host the
		// system-wide known-hosts file and /etc/hosts are the operator's own
		// trust/mappings, not xpf's (#16448).
		fail(wipeEraseKnownHosts(wipeManagedHostKeysPath))
		fail(wipeResetHosts(wipeHostsPath))

		// `logfiles` is part of SYSPREP_ENABLE_OPS. Empty /var/log while retaining
		// the directory for the still-running reset action; post-reset log entries
		// may be written before xpfd stops, but prior-tenant persisted entries are
		// unlinked. On a foreign host /var/log is the host's audit trail; only
		// the xpf-owned firewall logs (wipeFirewallLogs) are erased there.
		fail(wipeClearDir(wipeVarLogDir))
		// The volatile journal is host log state on a foreign host too.
		fail(wipeClearDir(wipeRunJournalDir))
	}
	// Volatile tenant state (#10769 d05-F6): reset is wipe-then-stop with no
	// reboot, so /run/xpf helper state is cleared in-wipe (services that need
	// it are already stopped) rather than left for a reboot that may never come.
	fail(wipeClearRunXPFDir(wipeRunXPFDir))
	if appliance && len(errs) == 0 {
		// Do not change the running device name until every earlier cleanup
		// leg has succeeded; reset is recoverable when residue remains.
		// Appliance-only: /etc/hostname and the live kernel name are the
		// host's identity on a foreign host (#16448).
		fail(wipeResetHostname(wipeHostnamePath))
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func listEthtoolForcedRegistryCrashTemps(path string) ([]string, error) {
	dir := filepath.Dir(path)
	prefix := "." + filepath.Base(path) + ".tmp-"
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("zeroize: inspect forced-interface registry directory for %s: %w", path, err)
	}
	var temps []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			temps = append(temps, filepath.Join(dir, entry.Name()))
		}
	}
	return temps, nil
}

func wipeEthtoolForcedRegistryCrashTemps(path string) error {
	temps, err := listEthtoolForcedRegistryCrashTemps(path)
	if err != nil {
		return err
	}
	var errs []error
	for _, temp := range temps {
		if err := wipeRemovePath(temp); err != nil {
			errs = append(errs, err)
		}
	}
	remaining, err := listEthtoolForcedRegistryCrashTemps(path)
	if err != nil {
		errs = append(errs, err)
	} else if len(remaining) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: forced-interface registry crash temps reappeared after sweep: %v", remaining))
	}
	return errors.Join(errs...)
}

// wipeStopKeaAndEraseLeases is a package var (like performWipe) so
// the final-verification regression can bypass the Kea leg and prove the
// pre-completion check catches what the bypassed leg missed.
var wipeStopKeaAndEraseLeases = func() error {
	// Stop, verify, and unlink in one critical section with no intervening
	// wipe I/O: a Kea restart between stop and unlink would re-persist prior
	// leases under the erasure. No mask/disable: a mask persists across the
	// reboot into the next tenant and would break their DHCP; stop plus an
	// inactive verification plus immediate unlink closes the re-persist
	// window instead (a restart after the unlink creates fresh empty state,
	// not prior leases). Each systemctl invocation is bounded 15s+5s by the
	// shared exec helper; any stop/verify failure fails closed here, before
	// any lease byte is unlinked.
	if err := wipeStopKeaUnits(); err != nil {
		return fmt.Errorf("%w: %w", errWipeKeaStop, err)
	}
	if err := wipeVerifyKeaStopped(); err != nil {
		return fmt.Errorf("%w: %w", errWipeKeaStop, err)
	}
	var errs []error
	for _, current := range wipeKeaLeasePaths {
		// The full LFC set, not just the canonical CSV: Kea startup prefers
		// .completed over .2/.1, so unlinking only the current file leaves
		// prior leases loadable (and a crash can leave leases ONLY in
		// .completed).
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if err := wipeRemovePath(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	// Re-verify emptiness after the unlink: a writer racing the stop would
	// otherwise leave fresh prior-tenant rows behind a clean receipt.
	for _, current := range wipeKeaLeasePaths {
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

// wipeEraseHelperState is the ungated-wipe spelling of the shared
// helper-state sweep (SweepHelperState, #17087): no daemon post-verify
// follows on this path, and the helper is not running in the offline
// contexts that take it. The reserved-alias recovery is UNGATED-SPECIFIC:
// this failure returns before completeZeroize, so factory-reset pending
// markers remain with NO handoff flag written (do not delete one — none
// exists). (Authoring a clean config via commit-confirmed first also
// converges, for operators who want a non-default helper path; the
// daemon restart/author/rerun leg proves that shape.) Callers pass a
// non-empty path only.
func wipeEraseHelperState(path string) error {
	return SweepHelperState(path, SweepOpts{
		ErrPrefix:        "zeroize: ",
		ReservedRecovery: "verify that file holds its correct contents with no helper temps beside it, restart xpfd if it is running, then rerun zeroize - this offline failure left factory-reset pending markers with no handoff flag, and the wiped config resolves the default helper path on retry, clearing the markers on success",
		SyncDir:          wipeSyncDir,
	})
}

// verifyHelperStateAtFinalVerification is VerifyHelperStateErased with
// the final-verification wording: a surviving canonical or temp set is
// reported as present AT FINAL VERIFICATION, while the reserved-alias
// failure keeps the shared cannot-be-verified sentence and the ungated
// recovery. It removes nothing.
func verifyHelperStateAtFinalVerification(path string) error {
	var errs []error
	if config.HelperStatePathTouchesReserved(path) {
		errs = append(errs, fmt.Errorf("zeroize: helper state path %s aliases reserved reset-gate/identity state: helper-state erasure cannot be verified (the reserved file is never unlinked); recovery: verify that file holds its correct contents with no helper temps beside it, restart xpfd if it is running, then rerun zeroize - this offline failure left factory-reset pending markers with no handoff flag, and the wiped config resolves the default helper path on retry, clearing the markers on success", path))
	} else if _, err := os.Lstat(path); err == nil {
		errs = append(errs, fmt.Errorf("zeroize: helper state %s present at final verification", path))
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("zeroize: inspect helper state %s: %w", path, err))
	}
	if dead, live, err := dpuserspace.ListStaleStateTempsIncludingLegacy(path); err != nil {
		errs = append(errs, err)
	} else if len(dead) != 0 || len(live) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: helper state temps present at final verification for %s: dead=%v live=%v", path, dead, live))
	}
	return errors.Join(errs...)
}

// wipeFinalEraseVerification re-proves the race-prone erase sets
// immediately before the pending markers clear: Kea lease files, the daemon's
// feed-shrink history canonical and crash temps, and DDNS/IPsec state files
// plus crash temps. Earlier legs erase and verify each of these, but later
// legs run in between; a fence-escaper write landing after an early check must
// fail this wipe rather than slip under a clean receipt. Canonicals are
// checked as well as temps: a writer that completed a full save leaves a
// canonical with no temp behind. The helper class is covered only for
// ungated completions with a known path: gated wipes skip it (the helper is
// live until the daemon stops it post-wipe, and the daemon sweep owns the
// path), legacy direct wipes name no path to check, and a reserved canonical
// FAILS (the sweep never unlinks gates or identity, so erasure is unprovable;
// temps still checked). The daemon post-verify remains as defense-in-depth
// behind it.
func wipeFinalEraseVerification(completion Completion) error {
	var errs []error
	for _, current := range wipeKeaLeasePaths {
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if _, err := os.Lstat(path); err == nil {
				errs = append(errs, fmt.Errorf("zeroize: Kea lease file %s present at final verification", path))
			} else if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("zeroize: inspect Kea lease file %s: %w", path, err))
			}
		}
	}
	for _, path := range []string{wipeDDNSLeaseStatePath, wipeDDNSSurfaceAPath, wipeIPsecStatePath} {
		if _, err := os.Lstat(path); err == nil {
			errs = append(errs, fmt.Errorf("zeroize: state file %s present at final verification", path))
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("zeroize: inspect state file %s: %w", path, err))
		}
	}
	if _, err := os.Lstat(wipeEthtoolForcedRegistryPath); err == nil {
		errs = append(errs, fmt.Errorf("zeroize: forced-interface registry %s present at final verification", wipeEthtoolForcedRegistryPath))
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("zeroize: inspect forced-interface registry %s: %w", wipeEthtoolForcedRegistryPath, err))
	}
	if temps, err := listEthtoolForcedRegistryCrashTemps(wipeEthtoolForcedRegistryPath); err != nil {
		errs = append(errs, err)
	} else if len(temps) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: forced-interface registry crash temps present at final verification: %v", temps))
	}
	if _, err := os.Lstat(wipeFeedShrinkHistoryPath); err == nil {
		errs = append(errs, fmt.Errorf("zeroize: feed shrink history %s present at final verification", wipeFeedShrinkHistoryPath))
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("zeroize: inspect feed shrink history %s: %w", wipeFeedShrinkHistoryPath, err))
	}
	if temps, err := feeds.ListShrinkHistoryCrashTemps(wipeFeedShrinkHistoryPath); err != nil {
		errs = append(errs, err)
	} else if len(temps) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: feed shrink history crash temps present at final verification: %v", temps))
	}
	ddnsPaths := []string{wipeDDNSLeaseStatePath, wipeDDNSSurfaceAPath}
	for _, path := range ddnsPaths {
		temps, err := ddns.ListCrashTemps(path)
		if err != nil {
			errs = append(errs, err)
		} else if len(temps) != 0 {
			errs = append(errs, fmt.Errorf("zeroize: DDNS crash temps present at final verification: %v", temps))
		}
	}
	if temps, err := ipsec.ListCrashTemps(wipeIPsecStatePath); err != nil {
		errs = append(errs, err)
	} else if len(temps) != 0 {
		errs = append(errs, fmt.Errorf("zeroize: IPsec crash temps present at final verification: %v", temps))
	}
	if !completion.pending && completion.helperPath != "" {
		// A reserved canonical FAILS via the shared verify: the sweep
		// never unlinks gates or identity, so helper-state erasure is
		// unprovable from this path. Temp siblings are still checked.
		if err := verifyHelperStateAtFinalVerification(completion.helperPath); err != nil {
			errs = append(errs, err)
		}
	}
	if !completion.pending {
		if err := wipeVerifyPersistentNatGenerationState(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// wipeShadowBackupNames are the Debian shadow-tools backups in
// /var/backups, rewritten on every passwd/userdel invocation.
var wipeShadowBackupNames = []string{"passwd.bak", "group.bak", "shadow.bak", "gshadow.bak"}

// wipeShadowTildeStems are the account-database basenames whose editor
// tilde-backups the sweep owns. A bare *~ match would take unrelated
// application/operator backups in the shared /var/backups directory.
var wipeShadowTildeStems = []string{"passwd", "shadow", "group", "gshadow"}

// wipeEraseAccountBackups removes the account-database backups AFTER the
// login-account teardown that recreates them (#10769 d05-F6): the /etc
// passwd-/shadow-/group-/gshadow- files plus the /var/backups shadow set and
// tilde-backups of the account-database basenames. Running this in the early
// seal legs would let userdel/passwd re-create pre-modification backups
// afterwards.
func wipeEraseAccountBackups() error {
	var errs []error
	for _, path := range wipePasswdBackupPaths {
		if err := wipeRemovePath(path); err != nil {
			errs = append(errs, err)
		}
	}
	entries, err := os.ReadDir(wipeVarBackupsDir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(errs...)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("zeroize: read backup directory %s: %w", wipeVarBackupsDir, err))
	} else {
		for _, entry := range entries {
			if entry.IsDir() || !isShadowBackupEntry(entry.Name()) {
				continue
			}
			if err := wipeRemovePath(filepath.Join(wipeVarBackupsDir, entry.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// Always sync, even with zero matches: a prior attempt may have unlinked
	// entries but failed this barrier (retry durability).
	if serr := wipeSyncDurable(wipeVarBackupsDir); serr != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync backup directory %s: %w", wipeVarBackupsDir, serr))
	}
	return errors.Join(errs...)
}

// isShadowBackupEntry reports whether a /var/backups entry is a shadow-tools
// account backup: one of the exact shadow names, or a tilde-backup of an
// account-database basename. Anything else in the shared directory (other
// applications' backups) is left alone.
func isShadowBackupEntry(name string) bool {
	for _, want := range wipeShadowBackupNames {
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
	for _, want := range wipeShadowTildeStems {
		if stem == want {
			return true
		}
	}
	return false
}

// wipeTmpPreservedPrefixes are tmp entries that belong to live service
// infrastructure rather than tenant data: systemd private-tmp mount points
// and snap's private tmp. Unlinking those would destabilize still-running
// host services for no tenant-clean gain (their contents are namespaced
// away from the host view anyway).
var wipeTmpPreservedPrefixes = []string{"systemd-private-", "snap-private-tmp-"}

// wipeClearTmpDir removes every entry in a tmp directory (#10769 d05-F6,
// seal tmp-files parity). Unlike wipeRemovePath it unlinks symlinks,
// sockets, fifos, and device nodes as names rather than refusing them: by
// the FHS tmp contract nothing here is persistent service state, factory
// reset is a decommissioning operation, and live file descriptors survive
// an unlink. Only the preserved service-infrastructure prefixes are kept.
// Hardlinked entries are refused before unlinking (FactoryResetHardlinkError
// with the inode scan): an external sibling would otherwise retain the
// bytes silently under a clean receipt.
func wipeClearTmpDir(dir string) error {
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
		for _, prefix := range wipeTmpPreservedPrefixes {
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
			wipeWarnEscapingInteriorLinks(full)
		}
		hardlinks, herr := configstore.CollectHardlinkedFiles(full, "")
		if herr != nil {
			errs = append(errs, fmt.Errorf("zeroize: inspect hard links for tmp entry %s: %w", full, herr))
			continue
		}
		if len(hardlinks) != 0 {
			errs = append(errs, fmt.Errorf("zeroize: refusing to erase hard-linked tmp entry %s: %w", full, &configstore.FactoryResetHardlinkError{Paths: hardlinks}))
			continue
		}
		// os.RemoveAll on a symlink removes the link, never the target.
		if err := os.RemoveAll(full); err != nil {
			errs = append(errs, fmt.Errorf("zeroize: remove tmp entry %s: %w", filepath.Join(dir, entry.Name()), err))
		}
	}
	// Always sync an existing directory, even when nothing was removed: a
	// prior attempt may have unlinked entries but failed this barrier.
	if err := wipeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync tmp directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// wipeIsShmResetEntry reports whether a /dev/shm entry is attributable to
// xpf/DHCP and therefore safe to unlink on reset. A full shm clear would
// pull live shared-memory segments out from under still-running host
// services; arbitrary prior-tenant shm outside these patterns is reboot-
// cleared tmpfs (documented residual for stop-without-reboot).
func wipeIsShmResetEntry(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"xpf", "kea", "dhcp"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "xpf") || strings.Contains(lower, "kea")
}

func wipeClearShmDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read shm directory %s: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || !wipeIsShmResetEntry(entry.Name()) {
			continue
		}
		if err := wipeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even with zero matches: retry
	// durability for a prior unlink whose barrier failed.
	if err := wipeSyncDir(dir); err != nil {
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

// wipeSweepOwnedBackups removes the editor backups inside dir whose stem
// the owned predicate accepts. A symlinked backup fails closed for operator
// inspection.
func wipeSweepOwnedBackups(dir string, owned func(stem string) bool) error {
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
		if err := wipeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even with zero matches: retry
	// durability for a prior unlink whose barrier failed.
	if err := wipeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync backup directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// wipeOwnedEtcBackupStems are the /etc top-level files whose editor
// backups the reset owns: backups of the identity files it resets.
var wipeOwnedEtcBackupStems = []string{"hostname", "hosts", "resolv.conf", "passwd", "shadow", "group", "gshadow"}

// wipeSweepOwnedEtcBackups removes editor backups of the reset-owned
// /etc files (hostname.bak, hosts~, ...). /etc is a shared root, so unlike
// the service-dir sweep this one gates on the stem: a backup of any other
// file is left for the operator.
func wipeSweepOwnedEtcBackups(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read directory %s for backup sweep: %w", dir, err)
	}
	owned := make(map[string]bool, len(wipeOwnedEtcBackupStems))
	for _, stem := range wipeOwnedEtcBackupStems {
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
		if err := wipeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even with zero matches: retry
	// durability for a prior unlink whose barrier failed.
	if err := wipeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync backup directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// wipeBackupSweepTarget pairs a directory with an ownership predicate
// over backup stems: only backups OF xpf-rendered basenames are erased.
// These directories are NOT xpf-exclusive (an operator's sshd_config.bak
// sits beside ssh_known_hosts), so a bare suffix sweep would take unowned
// files.
type wipeBackupSweepTarget struct {
	dir   string
	owned func(stem string) bool
}

// wipeServiceBackupSweepTargets returns the service directories whose
// backups-of-rendered-files the reset erases: the xpf drop-in dirs (gated
// on the drop-in basenames), the rendered-config dirs (gated on the
// rendered basenames), the SSH config dir (known_hosts only), and the
// rsyslog/networkd dirs (gated on the 10-xpf- ownership shape the wipe
// legs themselves use). Derived from the seamed path vars so tests
// relocate the whole inventory into a disposable tree.
func wipeServiceBackupSweepTargets() []wipeBackupSweepTarget {
	stemsByDir := make(map[string]map[string]bool)
	add := func(dir, stem string) {
		if stemsByDir[dir] == nil {
			stemsByDir[dir] = make(map[string]bool)
		}
		stemsByDir[dir][stem] = true
	}
	for _, dropin := range wipeManagedDropins {
		add(filepath.Dir(dropin), filepath.Base(dropin))
	}
	add(wipeSSHHostKeyDir, filepath.Base(wipeManagedHostKeysPath))
	add(filepath.Dir(wipeFRRConf), filepath.Base(wipeFRRConf))
	add(filepath.Dir(wipeSwanctlSnippet), filepath.Base(wipeSwanctlSnippet))
	// #16852: editor backups of the legacy pre-rename snippet (bpfrx.conf~ /
	// bpfrx.conf.bak, ...) carry the same cleartext PSKs; sweep them with
	// the xpf.conf backups in the same conf.d.
	add(filepath.Dir(wipeSwanctlSnippet), ipsec.LegacyBPFRXConfFile)
	add(filepath.Dir(wipeKea4Conf), filepath.Base(wipeKea4Conf))
	add(filepath.Dir(wipeKea6Conf), filepath.Base(wipeKea6Conf))
	var out []wipeBackupSweepTarget
	for dir, stems := range stemsByDir {
		out = append(out, wipeBackupSweepTarget{dir: dir, owned: func(stem string) bool {
			return stems[stem]
		}})
	}
	out = append(out,
		wipeBackupSweepTarget{dir: wipeRsyslogConfDir, owned: func(stem string) bool {
			return strings.HasPrefix(stem, "10-xpf-") && strings.HasSuffix(stem, ".conf")
		}},
		wipeBackupSweepTarget{dir: wipeNetworkdDir, owned: func(stem string) bool {
			return strings.HasPrefix(stem, "10-xpf-")
		}},
	)
	return out
}

// wipeRunXPFPreserved is the one /run/xpf entry the wipe must not
// unlink: the host-wide upgrade lock a later wipe leg acquires for mutual
// exclusion with a concurrent upgrade. Unlinking it would let the wipe
// lock a fresh inode while an upgrade holds the old one.
const wipeRunXPFPreserved = "upgrade.lock"

// wipeClearRunXPFDir removes xpf runtime state (#10769 d05-F6): helper
// sockets and state files carrying tenant flow/session data. Reset is
// wipe-then-stop with no reboot, so volatile state left here would be
// observable pre-reboot. Unlinking a live socket's name does not disturb
// its established connections; the upgrade lock is preserved. Hardlinked
// entries are refused before unlinking (FactoryResetHardlinkError with
// the inode scan): an external sibling would otherwise retain the bytes
// silently under a clean receipt.
func wipeClearRunXPFDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: read run directory %s: %w", dir, err)
	}
	var errs []error
	for _, entry := range entries {
		if entry.Name() == wipeRunXPFPreserved {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			wipeWarnEscapingInteriorLinks(full)
		}
		hardlinks, herr := configstore.CollectHardlinkedFiles(full, "")
		if herr != nil {
			errs = append(errs, fmt.Errorf("zeroize: inspect hard links for run entry %s: %w", full, herr))
			continue
		}
		if len(hardlinks) != 0 {
			errs = append(errs, fmt.Errorf("zeroize: refusing to erase hard-linked run entry %s: %w", full, &configstore.FactoryResetHardlinkError{Paths: hardlinks}))
			continue
		}
		// Names only: RemoveAll on a symlink removes the link, and live
		// socket fds survive their name's unlink.
		if err := os.RemoveAll(full); err != nil {
			errs = append(errs, fmt.Errorf("zeroize: remove run entry %s: %w", filepath.Join(dir, entry.Name()), err))
		}
	}
	// Always sync an existing directory, even when nothing was removed: a
	// prior attempt may have unlinked entries but failed this barrier.
	if err := wipeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync run directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// wipeCheckDDNSStateEmpty is the preflight used before beginZeroize writes
// any marker or the wipe removes any credentials. Both stores are durable
// authority to delete published records and must be trusted-empty first.
func wipeCheckDDNSStateEmpty() error {
	for _, path := range []string{wipeDDNSLeaseStatePath, wipeDDNSSurfaceAPath} {
		if err := ddns.CheckStateEmpty(path); err != nil {
			return err
		}
	}
	return nil
}

// wipeEraseDDNSState removes only stores the managers have emptied after
// successful backend-fingerprint-checked withdrawal. It runs before any other
// destructive wipe leg so an orphaned RR leaves the config and credentials
// available for an operator retry.
func wipeEraseDDNSState() error {
	if err := wipeCheckDDNSStateEmpty(); err != nil {
		return fmt.Errorf("%w: %w", errWipeDDNSOwnership, err)
	}
	var errs []error
	for _, path := range []string{wipeDDNSLeaseStatePath, wipeDDNSSurfaceAPath} {
		if err := ddns.EraseStateIfEmpty(path); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("%w: %w", errWipeDDNSOwnership, errors.Join(errs...))
	}
	return nil
}

func wipeEraseIPsecState() error {
	if err := ipsec.CheckConnStateEmpty(wipeIPsecStatePath); err != nil {
		return fmt.Errorf("%w: %w", errWipeIPsecOwnership, err)
	}
	if err := ipsec.EraseConnStateIfEmpty(wipeIPsecStatePath); err != nil {
		return fmt.Errorf("%w: %w", errWipeIPsecOwnership, err)
	}
	return nil
}

// wipeRotateMachineID installs a fresh random machine-id, replacing the
// prior-tenant identity. Truncation (the SYSPREP seal shape) is NOT enough:
// systemd v261.2 acquire_machine_id() regenerates an empty id from the
// stable SMBIOS firmware UUID on KVM/AMAZON/QEMU/XEN/BHYVE, which would
// reproduce the prior default vendor DUID-EN (EN 43793 + hashed
// machine-id). A present valid id is instead used verbatim by PID 1
// before any unit starts (machine_id_setup reads first, acquires only
// when invalid), so installing fresh random bytes means regeneration —
// firmware-derived or otherwise — never happens: the stable-UUID case
// needs no fixture because there is no regeneration input left to vary.
// networkd then reads the installed id at its post-reboot startup; the
// reboot gate holds N+1 until that reboot. The ssh host keys do not
// depend on first-boot detection: xpf-ssh-hostkeys regenerates on key
// absence alone (#16445). Format per machine-id(5): 32 lowercase hex +
// newline, world-readable.
func wipeRotateMachineID(path string) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zeroize: inspect %s: %w", path, err)
	}
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to replace non-regular file %s", path)
	}
	// Durable rename replaces the inode: a preexisting hardlink would
	// keep the OLD identity bytes alive at a sibling. Refuse like the
	// new #10769 seal removers (fail-before-unlink covers these sites
	// plus this rotation only; the master-owned archive/config-DB
	// collectors intentionally retain unlink-then-report).
	hardlinks, herr := configstore.CollectHardlinkedFiles(path, "")
	if herr != nil {
		return fmt.Errorf("zeroize: inspect hard links for %s: %w", path, herr)
	}
	if len(hardlinks) != 0 {
		return fmt.Errorf("zeroize: refusing to rotate hard-linked %s: %w", path, &configstore.FactoryResetHardlinkError{Paths: hardlinks})
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("zeroize: generate machine-id: %w", err)
	}
	body := hex.EncodeToString(id[:]) + "\n"
	if err := fsatomic.WriteFileDurable(path, []byte(body), 0o444); err != nil {
		return fmt.Errorf("zeroize: install machine-id %s: %w", path, err)
	}
	return nil
}

// wipeSyncDurable syncs dir, or the nearest existing ancestor when dir
// itself is absent. Retry durability for removals: if an earlier attempt
// unlinked entries (or the directory) but failed its barrier, a retry that
// finds nothing must still sync the survivor — otherwise the marker can
// complete with the unlink undurable. Syncing the surviving ancestor makes
// the ancestor's removal durable too, closing the debt structurally.
func wipeSyncDurable(dir string) error {
	d := filepath.Clean(dir)
	for {
		if _, err := os.Lstat(d); err == nil {
			return wipeSyncDir(d)
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

func wipeClearDir(dir string) error {
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
		if err := wipeRemovePath(filepath.Join(dir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	// Always sync an existing directory, even when it read empty: a prior
	// attempt may have unlinked its entries but failed this barrier, and a
	// retry that skips it would let the marker complete over undurable
	// unlinks. A never-existing directory carries no debt and returns nil
	// above.
	if err := wipeSyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync directory %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// wipeRemovePath unlinks path and syncs its parent directory so the removal
// is durable before the reset marker clears (#10769 d05-F6). Every seal-leg
// removal funnels through here, so durability holds structurally rather than
// depending on an audited sync inventory at the end of each leg. An absent
// path still syncs the nearest surviving ancestor: an earlier attempt may
// have unlinked it (or its parent) but failed the barrier, and skipping the
// sync on retry would let a later attempt complete the marker with that
// unlink undurable. A sync failure is surfaced fail-closed so the reset is
// never reported clean on unpersisted unlinks. A path with surviving hard
// links is refused BEFORE unlinking (FactoryResetHardlinkError with the
// inode scan): removing first would destroy the census evidence and let a
// retry succeed over bytes a sibling still holds.
func wipeRemovePath(path string) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode().IsRegular() {
		// Single regular file: the shared primitive (#17171) owns the
		// inspect -> refuse symlink -> refuse hardlink -> remove
		// sequence. Only the seal leg's parent-sync barrier stays here.
		// Historic seal spellings preserved verbatim (#17171 fold),
		// mapped from the typed/sentinel classes.
		if err := configstore.EraseFileForReset(path); err != nil {
			var linkErr *configstore.FactoryResetHardlinkError
			switch {
			case errors.As(err, &linkErr):
				return fmt.Errorf("zeroize: refusing to erase hard-linked %s: %w", path, linkErr)
			case errors.Is(err, configstore.ErrEraseInspectLinks):
				return fmt.Errorf("zeroize: inspect hard links for %s: %w", path, err)
			case errors.Is(err, configstore.ErrEraseInspect):
				return fmt.Errorf("zeroize: inspect %s: %w", path, err)
			case errors.Is(err, configstore.ErrEraseRemove):
				return fmt.Errorf("zeroize: remove %s: %w", path, err)
			default:
				return fmt.Errorf("zeroize: %w", err)
			}
		}
		if err := wipeSyncDurable(filepath.Dir(path)); err != nil {
			return fmt.Errorf("zeroize: sync parent of %s: %w", path, err)
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		// Retry durability: the unlink may have landed on an attempt whose
		// barrier failed. Syncing the nearest surviving ancestor retires
		// that debt and also makes an ancestor's own removal durable.
		if err := wipeSyncDurable(filepath.Dir(path)); err != nil {
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
		wipeWarnEscapingInteriorLinks(path)
	}
	hardlinks, herr := configstore.CollectHardlinkedFiles(path, "")
	if herr != nil {
		return fmt.Errorf("zeroize: inspect hard links for %s: %w", path, herr)
	}
	if len(hardlinks) != 0 {
		// Fail BEFORE unlinking: removing first would destroy the census
		// evidence (nlink on the managed name), letting a retry report
		// success while sibling links retain the bytes. Refusing keeps
		// the failure retry-persistent until the operator removes every
		// name (see the inode scan in the error).
		return fmt.Errorf("zeroize: refusing to erase hard-linked %s: %w", path, &configstore.FactoryResetHardlinkError{Paths: hardlinks})
	}
	if removeErr := os.RemoveAll(path); removeErr != nil {
		return fmt.Errorf("zeroize: remove %s: %w", path, removeErr)
	}
	var errs []error
	if err := wipeSyncDurable(filepath.Dir(path)); err != nil {
		errs = append(errs, fmt.Errorf("zeroize: sync parent of %s: %w", path, err))
	}
	return errors.Join(errs...)
}

// wipeWarnEscapingInteriorLinks censuses symlinks inside a directory the
// wipe is about to remove wholesale. RemoveAll unlinks those links without
// following them, so a target outside the tree survives by design —
// following links out of the owned tree would itself violate ownership
// boundaries. Each escape is logged with link and target so a successful
// wipe never silently implies out-of-tree bytes were removed.
func wipeWarnEscapingInteriorLinks(root string) {
	interior, err := configstore.CollectInteriorSymlinks(root, "")
	if err != nil {
		slog.Warn("zeroize: interior symlink census incomplete", "dir", root, "err", err)
	}
	for _, sk := range interior {
		if wipeLinkTargetEscapes(root, sk.Path, sk.Target) {
			slog.Warn("zeroize: interior symlink target outside the erased tree survives (out of erase scope)",
				"link", sk.Path, "target", sk.Target)
		}
	}
}

// wipeLinkTargetEscapes reports whether a symlink's target resolves
// outside root. Lexical only (consistent with the pathname-walk census);
// an unresolvable target counts as escaping so it is logged, not missed.
func wipeLinkTargetEscapes(root, linkPath, target string) bool {
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

// wipeEraseKnownHosts removes the system-wide SSH known-hosts file whether
// or not it carries the xpfd ownership header (#10769 d05-F6). The header is
// hygiene, not a security boundary against a prior-root tenant: prior root
// could strip the header to preserve hostile trust anchors across the reset,
// and any pre-reset trust is the prior tenant's either way. A symlink is
// unlinked (the link, never the target); any other non-regular file fails
// closed for operator inspection.
func wipeEraseKnownHosts(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Retry durability: a prior attempt may have unlinked the file
		// but failed its barrier; sync the surviving ancestor anyway.
		if serr := wipeSyncDurable(filepath.Dir(path)); serr != nil {
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
		return wipeSyncDir(filepath.Dir(path))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("zeroize: refusing to erase non-regular SSH known-hosts %s", path)
	}
	if data, err := os.ReadFile(path); err != nil {
		return fmt.Errorf("zeroize: read SSH known-hosts %s: %w", path, err)
	} else if !strings.HasPrefix(string(data), wipeManagedHostKeysHeader) {
		slog.Info("zeroize: removing foreign SSH known-hosts file (no xpfd header; prior-tenant trust does not survive reset)", "path", path)
	}
	return wipeRemovePath(path)
}

// wipeEraseDBusMachineID removes the D-Bus machine-id alias copy in
// whichever shape the image carries it: the tmpfiles L-line creates a
// symlink to /etc/machine-id when nothing stages the file (the sealed
// appliance runtime shape), while older/materialized installs carry a
// regular file. A symlink has only the LINK unlinked (never the target,
// so the freshly rotated /etc/machine-id is untouched); a regular file
// goes through the standard remover. Either way the alias regenerates
// from the rotated id.
func wipeEraseDBusMachineID(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if serr := wipeSyncDurable(filepath.Dir(path)); serr != nil {
			return fmt.Errorf("zeroize: sync parent of absent D-Bus machine-id %s: %w", path, serr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("zeroize: inspect D-Bus machine-id %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		slog.Info("zeroize: removing D-Bus machine-id symlink (link only; /etc/machine-id untouched)", "path", path)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("zeroize: remove D-Bus machine-id symlink %s: %w", path, err)
		}
		if err := wipeSyncDir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("zeroize: sync D-Bus machine-id directory %s: %w", filepath.Dir(path), err)
		}
		return nil
	}
	return wipeRemovePath(path)
}

// wipeSethostname sets the live kernel hostname during reset. A package
// var (mirroring the daemon's sethostname seam) so tests observe the call
// without renaming the test host; production is syscall.Sethostname.
var wipeSethostname = syscall.Sethostname

func wipeResetHostname(path string) error {
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
		return fmt.Errorf("zeroize: refusing to reset hard-linked hostname %s: %w", path, &configstore.FactoryResetHardlinkError{Paths: links})
	}
	if err := fsatomic.WriteFileDurable(path, []byte("xpf\n"), 0o644); err != nil {
		return fmt.Errorf("zeroize: reset hostname %s: %w", path, err)
	}
	// Reset is wipe-then-stop with no reboot: the live kernel name must move
	// with the file or the prior-tenant transient hostname stays observable
	// pre-reboot. A failed sethostname fails the wipe (a failed reset
	// restores both via the daemon identity snapshot).
	if err := wipeSethostname([]byte("xpf")); err != nil {
		return fmt.Errorf("zeroize: set live hostname: %w", err)
	}
	return nil
}

const wipeManagedResolvConfHeader = "# Generated by xpfd — do not edit\n"

// wipeDefaultHosts is the factory /etc/hosts: loopback plus the reset
// hostname's 127.0.1.1 mapping (Debian convention), no tenant entries.
const wipeDefaultHosts = "127.0.0.1 localhost\n" +
	"::1 localhost ip6-localhost ip6-loopback\n" +
	"127.0.1.1 xpf\n" +
	"ff02::1 ip6-allnodes\n" +
	"ff02::2 ip6-allrouters\n"

// wipeWriteFileDurableOrInPlace writes path durably, falling back to an
// in-place write when path is a bind mount (EXDEV/EBUSY on rename, common
// for /etc/resolv.conf in containers — the daemon's DNS reconciler carries
// the same fallback). The in-place path truncates and syncs; it never
// follows a symlink (callers unlink links first).
func wipeWriteFileDurableOrInPlace(path string, data []byte, perm os.FileMode) error {
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

// wipeResetResolvConf replaces the resolver file with the header-only
// empty default whether or not it carries the xpfd header (#10769 d05-F6).
// Like the known-hosts header, it is hygiene, not a security boundary
// against prior root: a headerless file keeps prior nameservers across the
// reset otherwise. A symlink (e.g. the systemd stub link) is replaced by a
// regular file, matching the production ownership model (xpf owns
// /etc/resolv.conf directly, resolved masked). Only the prior nameserver
// count is logged, never their addresses.
func wipeResetResolvConf(path string) error {
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
		} else if !strings.HasPrefix(string(data), wipeManagedResolvConfHeader) {
			slog.Info("zeroize: resetting foreign resolver file to the empty default", "path", path)
		}
	}
	if links, err := configstore.CollectHardlinkedFiles(path, ""); err != nil {
		return fmt.Errorf("zeroize: inspect resolver hard links %s: %w", path, err)
	} else if len(links) != 0 {
		return fmt.Errorf("zeroize: refusing to reset hard-linked resolver %s: %w", path, &configstore.FactoryResetHardlinkError{Paths: links})
	}
	if err := wipeWriteFileDurableOrInPlace(path, []byte(wipeManagedResolvConfHeader), 0o644); err != nil {
		return fmt.Errorf("zeroize: reset resolver %s: %w", path, err)
	}
	// Redundant with the durable write above, but routed through the test
	// seam so the barrier inventory stays observable.
	return wipeSyncDir(filepath.Dir(path))
}

// wipeResetHosts replaces /etc/hosts with the factory default: prior
// static mappings (tenant hostnames, MITM entries a prior root could have
// planted) must not survive. A symlink is replaced, never followed.
func wipeResetHosts(path string) error {
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
		return fmt.Errorf("zeroize: refusing to reset hard-linked hosts %s: %w", path, &configstore.FactoryResetHardlinkError{Paths: links})
	}
	if err := wipeWriteFileDurableOrInPlace(path, []byte(wipeDefaultHosts), 0o644); err != nil {
		return fmt.Errorf("zeroize: reset hosts %s: %w", path, err)
	}
	// Redundant with the durable write above, but routed through the test
	// seam so the barrier inventory stays observable.
	return wipeSyncDir(filepath.Dir(path))
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
