package factoryreset

import (
	"path/filepath"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/upgrade/lock"
)

// RedirectZeroizeWipePathsForTesting redirects every filesystem path and
// command seam the factory-reset wipe touches into root, returning a
// restore func. It is the single source behind the factoryreset hermetic
// test helpers; cross-package recovery tests (which cannot reach the
// private vars) drive real wipes through it. Test-only: production
// never calls it.
func RedirectWipePathsForTesting(root string) (restore func()) {
	oldMachine, oldSSH, oldRootSSHUser, oldHistory := wipeMachineIDPath, wipeSSHHostKeyDir, wipeRootSSHUserDir, wipeRootBashHistory
	oldEngineID, oldBoots, oldSeed := wipeSNMPEngineIDPath, wipeSNMPEngineBootsPath, wipeSystemdRandomSeed
	oldFeedShrinkHistoryPath := wipeFeedShrinkHistoryPath
	oldAptLists, oldAptArchive, oldUtmp := wipeAptListsDir, wipeAptArchiveDir, wipeRunUtmpPath
	oldDay0Reject, oldRootGrown := wipeDay0RejectedPath, wipeRootGrownPath
	oldDDNSLease, oldDDNSSurface := wipeDDNSLeaseStatePath, wipeDDNSSurfaceAPath
	oldPasswdBackups, oldHostKeys := wipePasswdBackupPaths, wipeManagedHostKeysPath
	oldDropins := wipeManagedDropins
	oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec := wipeHostnamePath, wipeHostsPath, wipeResolvConfPath, wipeDBusMachineIDPath, wipeIPsecStatePath
	oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldNetifLinks, oldNetifServer, oldNetifState, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname := wipeKeaLeasePaths, wipeStopKeaUnits, wipeVerifyKeaStopped, wipeVarBackupsDir, wipeNetworkdLeaseDir, wipeNetifLeaseDir, wipeNetifLinksDir, wipeNetifServerLeaseDir, wipeNetifStatePath, wipeDHCPClientStateDirs, wipeTmpDirs, wipeShmDir, wipeEtcDir, wipeRunXPFDir, wipeRunJournalDir, wipeSethostname
	oldFRR, oldSwan, oldK4, oldK6 := wipeFRRConf, wipeSwanctlSnippet, wipeKea4Conf, wipeKea6Conf
	oldBPF, oldND, oldVer := wipeBPFPinDir, wipeNetworkdDir, wipeVersionsDir
	oldLock := wipeAcquireUpgradeLock
	oldProv, oldSudoers, oldHome, oldPasswd, oldUserdel := wipeProvisionedUsersDir, wipeSudoersDir, wipeHomeBase, wipePasswdPath, wipeUserdel
	oldBusy, oldKill := wipeAccountHasLiveProcesses, wipeKillAccountProcesses
	oldRootSSH, oldLockRoot := wipeRootSSHDir, wipeLockRootPassword
	oldVarLog, oldSecurityDir, oldFlowDir, oldRsyslogDir := wipeVarLogDir, wipeSecurityLogDir, wipeFlowTraceDir, wipeRsyslogConfDir
	oldPendingPath := configstore.FactoryResetPendingPath
	oldHandoff := configstore.ResetHandoffPath
	oldHistHomes := wipeCLIHistoryHomesOverride

	wipeMachineIDPath = filepath.Join(root, "etc", "machine-id")
	wipeSSHHostKeyDir = filepath.Join(root, "etc", "ssh")
	wipeRootSSHUserDir = filepath.Join(root, "root", ".ssh")
	wipeRootBashHistory = filepath.Join(root, "root", ".bash_history")
	wipeSNMPEngineIDPath = filepath.Join(root, "var", "lib", "xpf", "snmp-engine-id")
	wipeSNMPEngineBootsPath = filepath.Join(root, "var", "lib", "xpf", "snmp-engineboots")
	wipeFeedShrinkHistoryPath = filepath.Join(root, "var", "lib", "xpf", "feed-shrink-history.json")
	wipeSystemdRandomSeed = filepath.Join(root, "var", "lib", "systemd", "random-seed")
	wipeAptListsDir = filepath.Join(root, "var", "lib", "apt", "lists")
	wipeAptArchiveDir = filepath.Join(root, "var", "cache", "apt", "archives")
	wipeRunUtmpPath = filepath.Join(root, "run", "utmp")
	wipeDay0RejectedPath = filepath.Join(root, "etc", "xpf", ".day0-config-rejected")
	wipeRootGrownPath = filepath.Join(root, "etc", "xpf", ".root-grown")
	wipeDDNSLeaseStatePath = filepath.Join(root, "var", "lib", "xpf", "dhcp-ddns-state.json")
	wipeDDNSSurfaceAPath = filepath.Join(root, "var", "lib", "xpf", "interface-ddns-state.json")
	wipePasswdBackupPaths = []string{
		filepath.Join(root, "etc", "passwd-"), filepath.Join(root, "etc", "shadow-"),
		filepath.Join(root, "etc", "group-"), filepath.Join(root, "etc", "gshadow-"),
	}
	wipeManagedHostKeysPath = filepath.Join(root, "etc", "ssh", "ssh_known_hosts")
	wipeManagedDropins = []string{
		filepath.Join(root, "etc", "ssh", "sshd_config.d", "00-xpf.conf"),
		filepath.Join(root, "etc", "ssh", "sshd_config.d", "xpf.conf"),
		filepath.Join(root, "etc", "chrony", "sources.d", "xpf.sources"),
		filepath.Join(root, "etc", "chrony", "conf.d", "xpf-threshold.conf"),
		filepath.Join(root, "etc", "systemd", "resolved.conf.d", "xpf.conf"),
		filepath.Join(root, "etc", "systemd", "resolved.conf.d", "bpfrx.conf"),
	}
	wipeHostnamePath = filepath.Join(root, "etc", "hostname")
	wipeHostsPath = filepath.Join(root, "etc", "hosts")
	wipeResolvConfPath = filepath.Join(root, "etc", "resolv.conf")
	wipeDBusMachineIDPath = filepath.Join(root, "var", "lib", "dbus", "machine-id")
	wipeIPsecStatePath = filepath.Join(root, "var", "lib", "xpf", "ipsec-conn-state.json")
	wipeKeaLeasePaths = []string{
		filepath.Join(root, "var", "lib", "kea", "kea-leases4.csv"),
		filepath.Join(root, "var", "lib", "kea", "kea-leases6.csv"),
	}
	wipeStopKeaUnits = func() error { return nil }
	wipeVerifyKeaStopped = func() error { return nil }
	wipeSethostname = func([]byte) error { return nil }
	wipeVarBackupsDir = filepath.Join(root, "var", "backups")
	wipeNetworkdLeaseDir = filepath.Join(root, "var", "lib", "systemd", "network")
	wipeNetifLeaseDir = filepath.Join(root, "run", "systemd", "netif", "leases")
	wipeNetifLinksDir = filepath.Join(root, "run", "systemd", "netif", "links")
	wipeNetifServerLeaseDir = filepath.Join(root, "run", "systemd", "netif", "dhcp-server-lease")
	wipeNetifStatePath = filepath.Join(root, "run", "systemd", "netif", "state")
	wipeDHCPClientStateDirs = []string{filepath.Join(root, "var", "lib", "dhcp"), filepath.Join(root, "var", "lib", "dhclient")}
	wipeTmpDirs = []string{filepath.Join(root, "tmp"), filepath.Join(root, "var", "tmp")}
	wipeShmDir = filepath.Join(root, "dev", "shm")
	wipeEtcDir = filepath.Join(root, "etc")
	wipeRunXPFDir = filepath.Join(root, "run", "xpf")
	wipeRunJournalDir = filepath.Join(root, "run", "log", "journal")
	wipeFRRConf = filepath.Join(root, "rendered", "frr", "frr.conf")
	wipeSwanctlSnippet = filepath.Join(root, "rendered", "swanctl", "xpf.conf")
	wipeKea4Conf = filepath.Join(root, "rendered", "kea", "kea-dhcp4.conf")
	wipeKea6Conf = filepath.Join(root, "rendered", "kea", "kea-dhcp6.conf")
	wipeBPFPinDir = filepath.Join(root, "bpf")
	wipeNetworkdDir = filepath.Join(root, "networkd")
	wipeVersionsDir = filepath.Join(root, "versions")
	lockPath := filepath.Join(root, "upgrade.lock")
	wipeAcquireUpgradeLock = func() (interface{ Release() error }, error) {
		return lock.AcquireAt(lockPath, "zeroize", "")
	}
	login := filepath.Join(root, "login")
	wipeProvisionedUsersDir = filepath.Join(login, "provisioned-users")
	wipeSudoersDir = filepath.Join(login, "sudoers.d")
	wipeHomeBase = filepath.Join(login, "home")
	wipePasswdPath = filepath.Join(login, "passwd")
	wipeCLIHistoryHomesOverride = []string{filepath.Join(root, "home-op")}
	wipeUserdel = func(string) ([]byte, error) { return nil, nil }
	wipeAccountHasLiveProcesses = func(int) (bool, error) { return false, nil }
	wipeKillAccountProcesses = func(int) ([]byte, error) { return nil, nil }
	wipeRootSSHDir = filepath.Join(login, "root-ssh")
	wipeLockRootPassword = func() ([]byte, error) { return nil, nil }
	wipeVarLogDir = filepath.Join(root, "var", "log")
	wipeSecurityLogDir = filepath.Join(root, "var", "log", "xpf")
	wipeFlowTraceDir = filepath.Join(root, "var", "log", "xpf-flow-trace")
	wipeRsyslogConfDir = filepath.Join(root, "etc", "rsyslog.d")
	configstore.FactoryResetPendingPath = filepath.Join(root, "etc", "xpf", configstore.Day0ConfigAppliedBase)
	configstore.ResetHandoffPath = filepath.Join(root, "etc", "xpf", ".reset-handoff")

	return func() {
		wipeMachineIDPath, wipeSSHHostKeyDir, wipeRootSSHUserDir, wipeRootBashHistory = oldMachine, oldSSH, oldRootSSHUser, oldHistory
		wipeSNMPEngineIDPath, wipeSNMPEngineBootsPath, wipeSystemdRandomSeed = oldEngineID, oldBoots, oldSeed
		wipeFeedShrinkHistoryPath = oldFeedShrinkHistoryPath
		wipeAptListsDir, wipeAptArchiveDir, wipeRunUtmpPath = oldAptLists, oldAptArchive, oldUtmp
		wipeDay0RejectedPath, wipeRootGrownPath = oldDay0Reject, oldRootGrown
		wipeDDNSLeaseStatePath, wipeDDNSSurfaceAPath = oldDDNSLease, oldDDNSSurface
		wipePasswdBackupPaths, wipeManagedHostKeysPath = oldPasswdBackups, oldHostKeys
		wipeManagedDropins = oldDropins
		wipeHostnamePath, wipeHostsPath, wipeResolvConfPath, wipeDBusMachineIDPath, wipeIPsecStatePath = oldHostname, oldHosts, oldResolv, oldDBus, oldIPsec
		wipeKeaLeasePaths, wipeStopKeaUnits, wipeVerifyKeaStopped, wipeVarBackupsDir, wipeNetworkdLeaseDir, wipeNetifLeaseDir, wipeNetifLinksDir, wipeNetifServerLeaseDir, wipeNetifStatePath, wipeDHCPClientStateDirs, wipeTmpDirs, wipeShmDir, wipeEtcDir, wipeRunXPFDir, wipeRunJournalDir, wipeSethostname = oldKeaPaths, oldStopKea, oldVerifyKea, oldVarBackups, oldNetLease, oldNetifLease, oldNetifLinks, oldNetifServer, oldNetifState, oldDHCPClient, oldTmp, oldShm, oldEtc, oldRunXPF, oldRunJournal, oldSethostname
		wipeFRRConf, wipeSwanctlSnippet, wipeKea4Conf, wipeKea6Conf = oldFRR, oldSwan, oldK4, oldK6
		wipeBPFPinDir, wipeNetworkdDir, wipeVersionsDir = oldBPF, oldND, oldVer
		wipeAcquireUpgradeLock = oldLock
		wipeProvisionedUsersDir, wipeSudoersDir, wipeHomeBase, wipePasswdPath, wipeUserdel = oldProv, oldSudoers, oldHome, oldPasswd, oldUserdel
		wipeAccountHasLiveProcesses, wipeKillAccountProcesses = oldBusy, oldKill
		wipeRootSSHDir, wipeLockRootPassword = oldRootSSH, oldLockRoot
		wipeVarLogDir, wipeSecurityLogDir, wipeFlowTraceDir, wipeRsyslogConfDir = oldVarLog, oldSecurityDir, oldFlowDir, oldRsyslogDir
		configstore.FactoryResetPendingPath = oldPendingPath
		wipeCLIHistoryHomesOverride = oldHistHomes
		configstore.ResetHandoffPath = oldHandoff
	}
}
