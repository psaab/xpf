package grpcapi

import (
	"path/filepath"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/upgrade/lock"
)

// RedirectZeroizeWipePathsForTesting redirects every filesystem path and
// command seam the factory-reset wipe touches into root, returning a
// restore func. It is the single source behind the grpcapi hermetic
// test helpers; cross-package recovery tests (which cannot reach the
// private vars) drive real wipes through it. Test-only: production
// never calls it.
func RedirectZeroizeWipePathsForTesting(root string) (restore func()) {
	oldMachine, oldSSH, oldRootSSHUser, oldHistory := zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory
	oldEngineID, oldBoots, oldSeed := zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed
	oldFeedShrinkHistoryPath := zeroizeFeedShrinkHistoryPath
	oldAptLists, oldAptArchive, oldUtmp := zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath
	oldDay0Reject, oldRootGrown := zeroizeDay0RejectedPath, zeroizeRootGrownPath
	oldDDNSLease, oldDDNSSurface := zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath
	oldPasswdBackups, oldHostKeys := zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath
	oldDropins := zeroizeManagedDropins
	oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec := zeroizeHostnamePath, zeroizeHostsPath, zeroizeResolvConfPath, zeroizeDBusMachineIDPath, zeroizeIPsecStatePath
	oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldNetifLinks, oldNetifServer, oldNetifState, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname := zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeNetifLeaseDir, zeroizeNetifLinksDir, zeroizeNetifServerLeaseDir, zeroizeNetifStatePath, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir, zeroizeRunXPFDir, zeroizeRunJournalDir, zeroizeSethostname
	oldFRR, oldSwan, oldK4, oldK6 := zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf
	oldBPF, oldND, oldVer := zeroizeBPFPinDir, zeroizeNetworkdDir, zeroizeVersionsDir
	oldLock := zeroizeAcquireUpgradeLock
	oldProv, oldSudoers, oldHome, oldPasswd, oldUserdel := zeroizeProvisionedUsersDir, zeroizeSudoersDir, zeroizeHomeBase, zeroizePasswdPath, zeroizeUserdel
	oldRootSSH, oldLockRoot := zeroizeRootSSHDir, zeroizeLockRootPassword
	oldVarLog, oldSecurityDir, oldFlowDir, oldRsyslogDir := zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir
	oldPendingPath := configstore.FactoryResetPendingPath
	oldHandoff := configstore.ResetHandoffPath
	oldHistHomes := zeroizeCLIHistoryHomesOverride

	zeroizeMachineIDPath = filepath.Join(root, "etc", "machine-id")
	zeroizeSSHHostKeyDir = filepath.Join(root, "etc", "ssh")
	zeroizeRootSSHUserDir = filepath.Join(root, "root", ".ssh")
	zeroizeRootBashHistory = filepath.Join(root, "root", ".bash_history")
	zeroizeSNMPEngineIDPath = filepath.Join(root, "var", "lib", "xpf", "snmp-engine-id")
	zeroizeSNMPEngineBootsPath = filepath.Join(root, "var", "lib", "xpf", "snmp-engineboots")
	zeroizeFeedShrinkHistoryPath = filepath.Join(root, "var", "lib", "xpf", "feed-shrink-history.json")
	zeroizeSystemdRandomSeed = filepath.Join(root, "var", "lib", "systemd", "random-seed")
	zeroizeAptListsDir = filepath.Join(root, "var", "lib", "apt", "lists")
	zeroizeAptArchiveDir = filepath.Join(root, "var", "cache", "apt", "archives")
	zeroizeRunUtmpPath = filepath.Join(root, "run", "utmp")
	zeroizeDay0RejectedPath = filepath.Join(root, "etc", "xpf", ".day0-config-rejected")
	zeroizeRootGrownPath = filepath.Join(root, "etc", "xpf", ".root-grown")
	zeroizeDDNSLeaseStatePath = filepath.Join(root, "var", "lib", "xpf", "dhcp-ddns-state.json")
	zeroizeDDNSSurfaceAPath = filepath.Join(root, "var", "lib", "xpf", "interface-ddns-state.json")
	zeroizePasswdBackupPaths = []string{
		filepath.Join(root, "etc", "passwd-"), filepath.Join(root, "etc", "shadow-"),
		filepath.Join(root, "etc", "group-"), filepath.Join(root, "etc", "gshadow-"),
	}
	zeroizeManagedHostKeysPath = filepath.Join(root, "etc", "ssh", "ssh_known_hosts")
	zeroizeManagedDropins = []string{
		filepath.Join(root, "etc", "ssh", "sshd_config.d", "00-xpf.conf"),
		filepath.Join(root, "etc", "ssh", "sshd_config.d", "xpf.conf"),
		filepath.Join(root, "etc", "chrony", "sources.d", "xpf.sources"),
		filepath.Join(root, "etc", "chrony", "conf.d", "xpf-threshold.conf"),
		filepath.Join(root, "etc", "systemd", "resolved.conf.d", "xpf.conf"),
		filepath.Join(root, "etc", "systemd", "resolved.conf.d", "bpfrx.conf"),
	}
	zeroizeHostnamePath = filepath.Join(root, "etc", "hostname")
	zeroizeHostsPath = filepath.Join(root, "etc", "hosts")
	zeroizeResolvConfPath = filepath.Join(root, "etc", "resolv.conf")
	zeroizeDBusMachineIDPath = filepath.Join(root, "var", "lib", "dbus", "machine-id")
	zeroizeIPsecStatePath = filepath.Join(root, "var", "lib", "xpf", "ipsec-conn-state.json")
	zeroizeKeaLeasePaths = []string{
		filepath.Join(root, "var", "lib", "kea", "kea-leases4.csv"),
		filepath.Join(root, "var", "lib", "kea", "kea-leases6.csv"),
	}
	zeroizeStopKeaUnits = func() error { return nil }
	zeroizeVerifyKeaStopped = func() error { return nil }
	zeroizeSethostname = func([]byte) error { return nil }
	zeroizeVarBackupsDir = filepath.Join(root, "var", "backups")
	zeroizeNetworkdLeaseDir = filepath.Join(root, "var", "lib", "systemd", "network")
	zeroizeNetifLeaseDir = filepath.Join(root, "run", "systemd", "netif", "leases")
	zeroizeNetifLinksDir = filepath.Join(root, "run", "systemd", "netif", "links")
	zeroizeNetifServerLeaseDir = filepath.Join(root, "run", "systemd", "netif", "dhcp-server-lease")
	zeroizeNetifStatePath = filepath.Join(root, "run", "systemd", "netif", "state")
	zeroizeDHCPClientStateDirs = []string{filepath.Join(root, "var", "lib", "dhcp"), filepath.Join(root, "var", "lib", "dhclient")}
	zeroizeTmpDirs = []string{filepath.Join(root, "tmp"), filepath.Join(root, "var", "tmp")}
	zeroizeShmDir = filepath.Join(root, "dev", "shm")
	zeroizeEtcDir = filepath.Join(root, "etc")
	zeroizeRunXPFDir = filepath.Join(root, "run", "xpf")
	zeroizeRunJournalDir = filepath.Join(root, "run", "log", "journal")
	zeroizeFRRConf = filepath.Join(root, "rendered", "frr", "frr.conf")
	zeroizeSwanctlSnippet = filepath.Join(root, "rendered", "swanctl", "xpf.conf")
	zeroizeKea4Conf = filepath.Join(root, "rendered", "kea", "kea-dhcp4.conf")
	zeroizeKea6Conf = filepath.Join(root, "rendered", "kea", "kea-dhcp6.conf")
	zeroizeBPFPinDir = filepath.Join(root, "bpf")
	zeroizeNetworkdDir = filepath.Join(root, "networkd")
	zeroizeVersionsDir = filepath.Join(root, "versions")
	lockPath := filepath.Join(root, "upgrade.lock")
	zeroizeAcquireUpgradeLock = func() (interface{ Release() error }, error) {
		return lock.AcquireAt(lockPath, "zeroize", "")
	}
	login := filepath.Join(root, "login")
	zeroizeProvisionedUsersDir = filepath.Join(login, "provisioned-users")
	zeroizeSudoersDir = filepath.Join(login, "sudoers.d")
	zeroizeHomeBase = filepath.Join(login, "home")
	zeroizePasswdPath = filepath.Join(login, "passwd")
	zeroizeCLIHistoryHomesOverride = []string{filepath.Join(root, "home-op")}
	zeroizeUserdel = func(string) ([]byte, error) { return nil, nil }
	zeroizeRootSSHDir = filepath.Join(login, "root-ssh")
	zeroizeLockRootPassword = func() ([]byte, error) { return nil, nil }
	zeroizeVarLogDir = filepath.Join(root, "var", "log")
	zeroizeSecurityLogDir = filepath.Join(root, "var", "log", "xpf")
	zeroizeFlowTraceDir = filepath.Join(root, "var", "log", "xpf-flow-trace")
	zeroizeRsyslogConfDir = filepath.Join(root, "etc", "rsyslog.d")
	configstore.FactoryResetPendingPath = filepath.Join(root, "etc", "xpf", configstore.Day0ConfigAppliedBase)
	configstore.ResetHandoffPath = filepath.Join(root, "etc", "xpf", ".reset-handoff")

	return func() {
		zeroizeMachineIDPath, zeroizeSSHHostKeyDir, zeroizeRootSSHUserDir, zeroizeRootBashHistory = oldMachine, oldSSH, oldRootSSHUser, oldHistory
		zeroizeSNMPEngineIDPath, zeroizeSNMPEngineBootsPath, zeroizeSystemdRandomSeed = oldEngineID, oldBoots, oldSeed
		zeroizeFeedShrinkHistoryPath = oldFeedShrinkHistoryPath
		zeroizeAptListsDir, zeroizeAptArchiveDir, zeroizeRunUtmpPath = oldAptLists, oldAptArchive, oldUtmp
		zeroizeDay0RejectedPath, zeroizeRootGrownPath = oldDay0Reject, oldRootGrown
		zeroizeDDNSLeaseStatePath, zeroizeDDNSSurfaceAPath = oldDDNSLease, oldDDNSSurface
		zeroizePasswdBackupPaths, zeroizeManagedHostKeysPath = oldPasswdBackups, oldHostKeys
		zeroizeManagedDropins = oldDropins
		zeroizeHostnamePath, zeroizeHostsPath, zeroizeResolvConfPath, zeroizeDBusMachineIDPath, zeroizeIPsecStatePath = oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec
		zeroizeKeaLeasePaths, zeroizeStopKeaUnits, zeroizeVerifyKeaStopped, zeroizeVarBackupsDir, zeroizeNetworkdLeaseDir, zeroizeNetifLeaseDir, zeroizeNetifLinksDir, zeroizeNetifServerLeaseDir, zeroizeNetifStatePath, zeroizeDHCPClientStateDirs, zeroizeTmpDirs, zeroizeShmDir, zeroizeEtcDir, zeroizeRunXPFDir, zeroizeRunJournalDir, zeroizeSethostname = oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldNetifLinks, oldNetifServer, oldNetifState, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname
		zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf = oldFRR, oldSwan, oldK4, oldK6
		zeroizeBPFPinDir, zeroizeNetworkdDir, zeroizeVersionsDir = oldBPF, oldND, oldVer
		zeroizeAcquireUpgradeLock = oldLock
		zeroizeProvisionedUsersDir, zeroizeSudoersDir, zeroizeHomeBase, zeroizePasswdPath, zeroizeUserdel = oldProv, oldSudoers, oldHome, oldPasswd, oldUserdel
		zeroizeRootSSHDir, zeroizeLockRootPassword = oldRootSSH, oldLockRoot
		zeroizeVarLogDir, zeroizeSecurityLogDir, zeroizeFlowTraceDir, zeroizeRsyslogConfDir = oldVarLog, oldSecurityDir, oldFlowDir, oldRsyslogDir
		configstore.FactoryResetPendingPath = oldPendingPath
		zeroizeCLIHistoryHomesOverride = oldHistHomes
		configstore.ResetHandoffPath = oldHandoff
	}
}
