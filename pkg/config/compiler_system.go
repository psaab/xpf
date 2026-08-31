package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const sharedUMEMPhase0ArtifactMaxBytes = 16 << 20

func compileSystem(node *Node, sys *SystemConfig, cfg *Config, opts compileOpts) error {
	dpType, err := compileSystemDataplaneType(node)
	if err != nil {
		return err
	}
	sys.DataplaneType = dpType

	// #6956: `system host-name fw1;` packs the value onto the `system` node's
	// OWN Keys — `Keys=["system","host-name","fw1"]` with ZERO children — so the
	// child walk below never runs and the host name compiled to "" with no
	// error and no warning. The nested spelling `system { host-name fw1; }`
	// works, and the flattened one is what `display set` output and vSRX
	// migration paths produce.
	//
	// Everything keyed on host name is affected: the management TLS
	// certificate's subject, syslog's origin field, the CLI prompt.
	//
	// Read here rather than through `packedBodyChildren` + a `packedTail` opt-in
	// (the #6821 mechanism) DELIBERATELY. That pairing exists because compiling
	// a packed tail the gate does not validate turns "not compiled" into
	// "compiled, unvalidated". It has nothing to bypass here: `host-name` is a
	// scalar leaf with NO validator, measured in both spellings — `system
	// host-name bad..name;` and `system { host-name bad..name; }` are both
	// accepted by SchemaValidate today. So the rule is satisfied vacuously, and
	// this stays narrowed to the leaf the issue names rather than teaching the
	// gate to validate every packed token on the `system` line, which would
	// newly reject configurations that commit cleanly now.
	if len(node.Keys) >= 3 && node.Keys[1] == "host-name" {
		sys.HostName = node.Keys[2]
	}

	// #6957/#6992: spans every `login` child of this `system` node. See the
	// `case "login"` arm.
	var loginUserByName map[string]*LoginUser

	for _, child := range node.Children {
		switch child.Name() {
		case "host-name":
			if len(child.Keys) >= 2 {
				sys.HostName = child.Keys[1]
			}
		case "dataplane-type":
			// Already resolved before child compilation so system dataplane
			// dispatch is independent of statement ordering.
		case "domain-name":
			if len(child.Keys) >= 2 {
				sys.DomainName = child.Keys[1]
			}
		case "domain-search":
			// Multi-value leaf (schema_system.go domain-search, multi:true).
			// Handles every AST shape via the #2545 multi-leaf SSOT helper:
			//   - bracket list  `domain-search [ a b ]` collapses every value
			//     onto child.Keys[1:] with no children (#2419);
			//   - hierarchical block `domain-search { a; b; }` carries one
			//     leaf child per value;
			//   - single `domain-search a`.
			// Reading only child.Keys[1] + children kept the first domain and
			// silently dropped the rest of a flat-set bracket list once #2419
			// collapsed it onto Keys (the orphan children this loop relied on
			// vanished) — a #2419 regression for flat-set domain-search.
			sys.DomainSearch = append(sys.DomainSearch, firewallMatchValues(child)...)
		case "time-zone":
			if len(child.Keys) >= 2 {
				sys.TimeZone = child.Keys[1]
			}
		case "no-redirects":
			sys.NoRedirects = true
		case "name-server":
			// Multi-value leaf (schema_system.go name-server, multi:true).
			// Same #2419 collapse as domain-search above: a flat-set bracket
			// list `name-server [ 8.8.8.8 9.9.9.9 ]` now lands every server on
			// child.Keys[1:] with no children, so reading only child.Keys[1] +
			// children dropped every server but the first (broken DNS config).
			// firewallMatchValues unifies bracket / hierarchical block / single
			// shapes.
			sys.NameServers = append(sys.NameServers, firewallMatchValues(child)...)
		case "ntp":
			// #6690: read EVERY server a `server` node carries, not just
			// Keys[1]. `system { ntp { server { a; b; } } }` puts one leaf
			// child per server and leaves the node itself with Keys=["server"]
			// only, so the old `len(Keys) >= 2` read compiled ZERO servers from
			// it — a green commit with no time sync at all. The bracketed
			// spelling `server [ a b ]` collapses onto Keys[1:] (#2419) and
			// kept only the first.
			//
			// This is NOT firewallMatchValues: a `server` node's trailing
			// tokens are ambiguous. `server 1.1.1.1 prefer;` and
			// `server [ 1.1.1.1 2.2.2.2 ];` are structurally identical after
			// the lexer strips the brackets, so the per-server OPTION keywords
			// have to be recognised by name or `prefer` would be compiled as a
			// second NTP server and rendered verbatim into a chrony directive
			// (#4902 types the value for exactly that reason).
			for _, ntpChild := range child.FindChildren("server") {
				ntpServers, ntpOpts := ntpServerValues(ntpChild)
				sys.NTPServers = append(sys.NTPServers, ntpServers...)
				for addr, opt := range ntpOpts {
					if sys.NTPServerOptions == nil {
						sys.NTPServerOptions = map[string]NTPServerOption{}
					}
					sys.NTPServerOptions[addr] = opt
				}
			}
			if thNode := child.FindChild("threshold"); thNode != nil {
				if v := nodeVal(thNode); v != "" {
					if n, ok := parseIntLeaf(&cfg.Warnings, "system ntp threshold", v); ok {
						sys.NTPThreshold = n
					}
				}
				// Check for inline: threshold 400 action accept;
				for i := 2; i < len(thNode.Keys)-1; i++ {
					if thNode.Keys[i] == "action" {
						sys.NTPThresholdAction = thNode.Keys[i+1]
					}
				}
				// Check for hierarchical: action { accept; }
				if actNode := thNode.FindChild("action"); actNode != nil {
					sys.NTPThresholdAction = nodeVal(actNode)
				}
			}
		case "login":
			// #6957: allocate ONCE. This arm runs per `login` child, and two
			// sibling `login { … }` blocks under one `system` are legal Junos —
			// a generated or concatenated config produces them routinely, and an
			// operator appending a second stanza to add an account is the
			// motivating case. Reallocating here discarded everything the
			// EARLIER block had contributed, so the compiled set reduced to the
			// last block and the first block's users vanished with no error.
			//
			// That is not merely absent-from-config: `reconcileAbsentLoginUsers`
			// treats the compiled set as authoritative and DEPROVISIONS
			// xpf-managed accounts missing from it, so the lost accounts were
			// removed from the box by a commit that reported success.
			//
			// Everything below this line already appends (`sys.Login.Classes`,
			// `sys.Login.Users`), so allocating once is the whole fix —
			// subsequent blocks accumulate into the same struct.
			//
			// Distinct root from #6956, which is fixed in the same change: that
			// one is a packed tail the walk never reads; this one is two
			// children the walk reads and then overwrites.
			if sys.Login == nil {
				sys.Login = &LoginConfig{}
			}
			// #6957 + #6992: the name->entry index must span blocks too, for the
			// same reason the allocation must. #6992 folds a user NAME authored
			// twice into ONE entry, but its index was declared inside this arm,
			// so it reset per block and could only ever fold WITHIN one. That
			// was invisible while the reallocation above discarded the earlier
			// block — the duplicate never coexisted, so the fold was never asked
			// to span anything and #6992's own cross-block cell passed for the
			// wrong reason. Fixing #6957 makes the duplicate real, which is what
			// surfaced it.
			if loginUserByName == nil {
				loginUserByName = map[string]*LoginUser{}
			}
			// #4304 S-2: parse custom `login class <name>` RBAC definitions so
			// a real vSRX config commits (the `user ... class` enum accepts
			// the defined names) and maps its Junos permission set onto xpf's
			// coarse permission model. Compiled BEFORE users so the class set
			// is complete regardless of stanza order.
			for _, classInst := range namedInstances(child.FindChildren("class")) {
				lc := &LoginClass{Name: classInst.name}
				for _, prop := range classInst.node.Children {
					// #5831: record RESTRICTIVE leaf PRESENCE from the
					// classification table (compiler_login_deny.go), NOT from
					// the case arms below. Presence, not value: a
					// quoted-empty or valueless deny-commands flattens to ""
					// and would be invisible to a value test, yet an empty
					// regex denies EVERY command in Junos. Driving it from the
					// table means a newly-classified restrictive leaf is gated
					// without also needing a `case` arm here — the missing-arm
					// fail-open the table exists to prevent. Both AST shapes
					// carry the leaf name in Keys[0], so prop.Name() is
					// dual-shape safe, exactly as the switch below relies on.
					if loginClassLeafRestrictive[prop.Name()] {
						lc.DenyLeavesPresent = append(lc.DenyLeavesPresent, prop.Name())
					}
					switch prop.Name() {
					case "permissions":
						lc.Permissions = append(lc.Permissions, firewallMatchValues(prop)...)
					case "idle-timeout":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								lc.IdleTimeout = n
							}
						}
					case "allow-commands":
						lc.AllowCommands = nodeVal(prop)
					case "deny-commands":
						// Value only. PRESENCE is recorded above, off
						// loginClassLeafRestrictive, because the value cannot
						// carry it: a quoted-empty or valueless deny-commands
						// flattens to "" yet denies EVERY command in Junos.
						lc.DenyCommands = nodeVal(prop)
					case "allow-configuration":
						lc.AllowConfiguration = nodeVal(prop)
					case "deny-configuration":
						lc.DenyConfiguration = nodeVal(prop)
					}
				}
				lc.MappedPermissions, _ = mapJunosPermissions(lc.Permissions)
				sys.Login.Classes = append(sys.Login.Classes, lc)
			}
			// #6992: a user NAME authored in two blocks folds into ONE entry.
			//
			// Without the fold both blocks survive in Login.Users and two
			// readers pick different ones: pkg/cli configuredClass returns the
			// FIRST block with a non-empty class, while pkg/daemon
			// applySystemLogin iterates every block in order, so the account
			// state that lands (password, authorized_keys) comes from the LAST.
			// Measured on a config that commits CLEAN at strict: with
			// `class admins` first and `class ops` second, the SSH key the
			// operator wrote under the VIEW-only block authenticates and the
			// CLI then grants super-user. The authorization decision and the
			// credential that reaches it come from different blocks.
			//
			// The fold is per-LEAF last-authored-wins because that is what the
			// FLAT spelling already produces — SetPath merges `set system login
			// user alice ...` written twice onto one node, replacing each leaf —
			// so folding makes the two AST shapes agree rather than inventing a
			// third answer. This is the #5180 dual-AST-equivalence property, and
			// the same reasoning as the #6838 cohort fold one stanza over: make
			// the outcome INDEPENDENT of which reader picks, rather than
			// teaching one reader the other's tie-break, which is a proxy that
			// rots the day the other reader changes. Here it is stronger than a
			// matched tie-break: after the fold there is no tie to break.
			//
			// Deliberately NOT applied to `class`: #6838 already made the class
			// cohort reader-independent by folding permissions across it, and a
			// merge here would fight that design.
			userByName := loginUserByName
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := userByName[userInst.name]
				if user == nil {
					user = &LoginUser{Name: userInst.name}
					userByName[userInst.name] = user
					sys.Login.Users = append(sys.Login.Users, user)
				}
				// A later block's `authentication` section replaces the earlier
				// block's key set wholesale rather than appending to it. That is
				// what the runtime already does — applySystemLogin rewrites
				// authorized_keys per entry with WriteFileDurable, so the last
				// entry's keys are the ones on disk — so the fold preserves the
				// provisioned key set exactly and removes only the divergence.
				authoredAuth := false
				for _, prop := range userInst.node.Children {
					if prop.Name() == "authentication" {
						authoredAuth = true
						break
					}
				}
				if authoredAuth {
					user.SSHKeys = nil
					user.EncryptedPassword = ""
				}
				for _, prop := range userInst.node.Children {
					switch prop.Name() {
					case "uid":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								user.UID = n
							}
						}
					case "class":
						user.Class = nodeVal(prop)
					case "authentication":
						// Children-only is CORRECT here, unlike the sibling
						// sites fixed for #6818/#6821/#6822. The compact
						// spelling `authentication encrypted-password "$6$..."`
						// is REJECTED at commit by the #6662 packed-login-body
						// gate, which names the rewrite; on the tolerant load /
						// peer-sync path it is a warning and the stanza stays
						// inert, deliberately, so a peer-synced config behaves
						// exactly as the older binary made it behave (#1960).
						// Compiling the value here would silently reverse that
						// decision and change RBAC on the HA sync path.
						for _, authChild := range prop.Children {
							switch authChild.Name() {
							case "encrypted-password":
								user.EncryptedPassword = Secret(nodeVal(authChild))
							case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
								if v := nodeVal(authChild); v != "" {
									user.SSHKeys = append(user.SSHKeys, v)
								}
							}
						}
					}
				}
			}
		case "backup-router":
			if len(child.Keys) >= 2 {
				sys.BackupRouter = child.Keys[1]
			}
			// destination keyword: backup-router 192.168.50.1 destination 192.168.0.0/16
			for i, k := range child.Keys {
				if k == "destination" && i+1 < len(child.Keys) {
					sys.BackupRouterDst = child.Keys[i+1]
				}
			}
			// Also check children for hierarchical format
			if dstNode := child.FindChild("destination"); dstNode != nil && len(dstNode.Keys) >= 2 {
				sys.BackupRouterDst = dstNode.Keys[1]
			}
		case "commit":
			for _, key := range child.Keys[1:] {
				if key == "persist-groups-inheritance" {
					sys.PersistGroupsInheritance = true
				}
			}
			if child.FindChild("persist-groups-inheritance") != nil {
				sys.PersistGroupsInheritance = true
			}
		case "root-authentication":
			sys.RootAuthentication = &RootAuthConfig{}
			for _, prop := range child.Children {
				switch prop.Name() {
				case "encrypted-password":
					sys.RootAuthentication.EncryptedPassword = Secret(nodeVal(prop))
				case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
					if v := nodeVal(prop); v != "" {
						sys.RootAuthentication.SSHKeys = append(sys.RootAuthentication.SSHKeys, v)
					}
				}
			}
		case "archival":
			sys.Archival = &ArchivalConfig{
				ArchiveDir:  "/var/lib/xpf/archive",
				MaxArchives: 10,
			}
			if cfgNode := child.FindChild("configuration"); cfgNode != nil {
				if cfgNode.FindChild("transfer-on-commit") != nil {
					sys.Archival.TransferOnCommit = true
				}
				if tiNode := cfgNode.FindChild("transfer-interval"); tiNode != nil {
					if v := nodeVal(tiNode); v != "" {
						if n, ok := parseIntLeaf(&cfg.Warnings, "system archival configuration transfer-interval", v); ok {
							sys.Archival.TransferInterval = n
						}
					}
				}
				for _, asNode := range cfgNode.FindChildren("archive-sites") {
					// #6692: archiveSiteEntries reads EVERY authored site
					// across all four AST shapes, so a bracketed list is no
					// longer truncated to its first member. The two things the
					// pre-#6692 warning in this spot demanded of a widening
					// reader are both satisfied here: the `password <secret>`
					// modifier is separated from the URL stream by
					// archiveSiteEntries (it is never promoted to a site), and
					// the #4589 leading-dash gate below now runs over EVERY
					// site rather than slot 1 alone — so widening the read
					// closes the gate escape instead of arming it.
					for _, site := range archiveSiteEntries(asNode) {
						// #4589 A7 F-02: reject a leading-dash archive-site at
						// commit. Runtime archival shells out to `scp <src> <dest>`;
						// a `-`-prefixed URL is never a valid scp destination and,
						// pre-`--`-separator, was parsed as an scp option (CWE-88).
						if strings.HasPrefix(site.url, "-") {
							return fmt.Errorf("system archival archive-sites %q: an archive-site URL must not begin with '-' (it is passed to scp as a destination, not an option)", site.url)
						}
						sys.Archival.ArchiveSites = append(sys.Archival.ArchiveSites, site.url)
						if site.hasPassword {
							sys.Archival.ArchiveSitesWithPassword = append(
								sys.Archival.ArchiveSitesWithPassword, site.url)
						}
					}
				}
			}
		case "master-password":
			if prfNode := child.FindChild("pseudorandom-function"); prfNode != nil {
				sys.MasterPassword = nodeVal(prfNode)
			}
		case "license":
			if auNode := child.FindChild("autoupdate"); auNode != nil {
				if urlNode := auNode.FindChild("url"); urlNode != nil {
					sys.LicenseAutoUpdate = nodeVal(urlNode)
				}
			}
		case "processes":
			for _, proc := range child.Children {
				if proc.FindChild("disable") != nil || nodeVal(proc) == "disable" {
					sys.DisabledProcesses = append(sys.DisabledProcesses, proc.Name())
				}
			}
		case "internet-options":
			sys.InternetOptions = &InternetOptionsConfig{}
			if child.FindChild("no-ipv6-reject-zero-hop-limit") != nil {
				sys.InternetOptions.NoIPv6RejectZeroHopLimit = true
			}
		case "dataplane":
			switch effectiveDataplaneType(sys.DataplaneType) {
			case dataplaneTypeUserspace:
				if sys.UserspaceDataplane == nil {
					sys.UserspaceDataplane = &UserspaceConfig{}
				}
				if err := compileUserspaceDataplane(child, sys.UserspaceDataplane, &cfg.Warnings); err != nil {
					return err
				}
			case dataplaneTypeEBPF:
				// The legacy eBPF dataplane has no system dataplane sub-stanza.
			case dataplaneTypeDPDK:
				// DPDK retired in #1525 / #1528. This branch is reachable
				// only from a direct CompileConfig call on a tree that still
				// carries a `dataplane-type dpdk` leaf — i.e., a commit-path
				// candidate. Store.Load and Store.SyncApply both call
				// rewriteRetiredDataplaneType before compile, which strips
				// the `dataplane-type dpdk` leaf so sys.DataplaneType == ""
				// (→ userspace) and this branch is never entered; the
				// sub-stanza children hit compileUserspaceDataplane instead
				// and are silently dropped there as unknown keys.
				//
				// For the direct-compile case the sub-stanza children
				// (cores, memory, socket-mem, rx-mode, ports) are silently
				// dropped here because the DPDKConfig type is deleted.
				// validateDataplaneTypeStrict in compileExpanded fires
				// immediately after compileSystem and returns
				// ErrDPDKDataplaneRetired, so the no-op here is inconsequential.
			}
		case "syslog":
			sys.Syslog = &SystemSyslogConfig{}
			for _, slInst := range namedInstances(child.FindChildren("host")) {
				host := &SyslogHostConfig{Address: slInst.name}
				// #6684: `host 10.0.0.1 any any;` packs the whole body onto the
				// host node's Keys, leaving Children empty — the host compiled
				// with ZERO facilities and shipped nothing, silently.
				for _, prop := range packedBodyChildren(slInst.node,
					schemaForPath("system", "syslog", "host")) {
					// #4303 S-1: switch on the KNOWN host sub-statements
					// before the facility/severity fallback. Without this
					// every non-`allow-duplicates` child (source-address,
					// port, match, structured-data, ...) was captured as a
					// bogus SyslogFacility{Facility:Keys[0], Severity:Keys[1]}
					// that polluted the facility filter — applySystemSyslog
					// reads Facilities[0].Facility, so a leading
					// `source-address` set the whole client's facility to
					// garbage.
					switch prop.Name() {
					case "allow-duplicates":
						host.AllowDuplicates = true
					case "source-address":
						host.SourceAddress = nodeVal(prop)
					case "port":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								host.Port = n
							}
						}
					case "match", "match-strings", "structured-data",
						"explicit-priority", "log-prefix", "facility-override",
						"routing-instance", "exclude-hostname":
						// Recognized Junos host modifiers that are NOT
						// facility/severity pairs. Accepted so a valid
						// config commits; not (yet) wired into the runtime
						// syslog client — see the S-5 advisory path.
					default:
						if fac, sev, ok := syslogFacilitySeverity(prop); ok {
							host.Facilities = append(host.Facilities, SyslogFacility{
								Facility: fac,
								Severity: sev,
							})
						}
					}
				}
				sys.Syslog.Hosts = append(sys.Syslog.Hosts, host)
			}
			for _, fileInst := range namedInstances(child.FindChildren("file")) {
				file := &SyslogFileConfig{Name: fileInst.name}
				archiveKnobs := map[string]bool{}
				for _, prop := range fileInst.node.Children {
					switch prop.Name() {
					case "archive":
						// #7146: the whole `archive` block (files, size,
						// start-time, transfer-interval, archive-sites,
						// world/no-world-readable) is modeled in setSchema
						// and implemented by NOTHING — #4303 folded it into
						// the recognized-modifier skip list below, so every
						// knob committed clean and vanished. Record the
						// container's presence and its sub-statement
						// KEYWORDS (never their values) so ValidateConfig can
						// tell the operator their logs are not being
						// archived. Recording is all this does; no runtime
						// consumer reads these fields.
						file.ArchiveConfigured = true
						for _, knob := range syslogArchiveKnobs(prop) {
							archiveKnobs[knob] = true
						}
					case "match", "match-strings", "structured-data",
						"explicit-priority", "allow-duplicates":
						// #4303 S-1: recognized file modifiers, not a
						// facility/severity pair — do not append as one.
					default:
						if fac, sev, ok := syslogFacilitySeverity(prop); ok {
							// #7187: APPEND. This assigned, so a file naming two
							// facilities kept only the last one parsed and the
							// earlier selectors vanished before any render.
							file.Selectors = append(file.Selectors,
								SyslogFacility{Facility: fac, Severity: sev})
						}
					}
				}
				if len(archiveKnobs) > 0 {
					file.ArchiveKnobs = make([]string, 0, len(archiveKnobs))
					for knob := range archiveKnobs {
						file.ArchiveKnobs = append(file.ArchiveKnobs, knob)
					}
					sort.Strings(file.ArchiveKnobs)
				}
				sys.Syslog.Files = append(sys.Syslog.Files, file)
			}
			// Parse user destinations: user * { any emergency; }
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := &SyslogUserConfig{User: userInst.name}
				for _, prop := range userInst.node.Children {
					switch prop.Name() {
					case "match", "match-strings", "structured-data",
						"explicit-priority", "allow-duplicates":
						// #4303 S-1: recognized user modifiers, not a pair.
					default:
						if fac, sev, ok := syslogFacilitySeverity(prop); ok {
							// #7187: APPEND, for the same reason as the file
							// sink above.
							user.Selectors = append(user.Selectors,
								SyslogFacility{Facility: fac, Severity: sev})
						}
					}
				}
				sys.Syslog.Users = append(sys.Syslog.Users, user)
			}
		}
	}

	svcNode := node.FindChild("services")
	if svcNode != nil {
		dhcpNode := svcNode.FindChild("dhcp-local-server")
		if dhcpNode != nil {
			if err := compileDHCPLocalServer(dhcpNode, &sys.DHCPServer, false); err != nil {
				return err
			}
		}
		dhcp6Node := svcNode.FindChild("dhcpv6-local-server")
		if dhcp6Node != nil {
			if err := compileDHCPLocalServer(dhcp6Node, &sys.DHCPServer, true); err != nil {
				return err
			}
		}
		// SSH service
		if sshNode := svcNode.FindChild("ssh"); sshNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.SSH = &SSHServiceConfig{}
			if rl := sshNode.FindChild("root-login"); rl != nil && len(rl.Keys) >= 2 {
				sys.Services.SSH.RootLogin = rl.Keys[1]
			}
			// #6692: key-exchange is `multi: true` and the operator lists
			// methods in PREFERENCE order, so a bracketed list truncated to
			// slot 0 pinned sshd to the FIRST (often the weaker legacy) method
			// and silently discarded the modern one the operator added — a
			// hardening change that appears applied and is not. Read every
			// value via firewallMatchValues, exactly as the ciphers/macs
			// siblings below already do. Widening is safe on the injection axis
			// because validateMultiValueLeaf (schema_walk.go) runs the leaf's
			// ValidateSSHAlgorithm over EVERY token of Keys[1:] and every
			// block-child, not just the first (#4902).
			for _, kx := range sshNode.FindChildren("key-exchange") {
				sys.Services.SSH.KeyExchange = append(sys.Services.SSH.KeyExchange, firewallMatchValues(kx)...)
			}
			// #4305 S-4: SSH hardening knobs. ciphers/macs are repeatable
			// (bracketed list or one-per-child); read every value via
			// firewallMatchValues so a `[ a b c ]` list is not truncated.
			for _, cn := range sshNode.FindChildren("ciphers") {
				sys.Services.SSH.Ciphers = append(sys.Services.SSH.Ciphers, firewallMatchValues(cn)...)
			}
			for _, mn := range sshNode.FindChildren("macs") {
				sys.Services.SSH.MACs = append(sys.Services.SSH.MACs, firewallMatchValues(mn)...)
			}
			if cl := sshNode.FindChild("connection-limit"); cl != nil {
				if n, err := strconv.Atoi(nodeVal(cl)); err == nil {
					sys.Services.SSH.ConnectionLimit = n
				}
			}
			if ci := sshNode.FindChild("client-alive-interval"); ci != nil {
				if n, err := strconv.Atoi(nodeVal(ci)); err == nil {
					sys.Services.SSH.ClientAliveInterval = n
					sys.Services.SSH.ClientAliveIntervalSet = true
				}
			}
			if cc := sshNode.FindChild("client-alive-count-max"); cc != nil {
				if n, err := strconv.Atoi(nodeVal(cc)); err == nil {
					sys.Services.SSH.ClientAliveCountMax = n
					sys.Services.SSH.ClientAliveCountMaxSet = true
				}
			}
			if pv := sshNode.FindChild("protocol-version"); pv != nil {
				sys.Services.SSH.ProtocolVersion = nodeVal(pv)
			}
		}
		// DNS service
		if dnsNode := svcNode.FindChild("dns"); dnsNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.DNSEnabled = true
			if hasDNSProxyChild(dnsNode) {
				sys.Services.DNSProxyConfigured = true
			}
		}
		// Web management
		if wmNode := svcNode.FindChild("web-management"); wmNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.WebManagement = &WebManagementConfig{}
			if httpNode := wmNode.FindChild("http"); httpNode != nil {
				sys.Services.WebManagement.HTTP = true
				if ifNode := httpNode.FindChild("interface"); ifNode != nil {
					sys.Services.WebManagement.HTTPInterface = nodeVal(ifNode)
				}
			}
			if httpsNode := wmNode.FindChild("https"); httpsNode != nil {
				sys.Services.WebManagement.HTTPS = true
				if httpsNode.FindChild("system-generated-certificate") != nil {
					sys.Services.WebManagement.SystemGeneratedCert = true
				}
				if ifNode := httpsNode.FindChild("interface"); ifNode != nil {
					sys.Services.WebManagement.HTTPSInterface = nodeVal(ifNode)
				}
			}
			if authNode := wmNode.FindChild("api-auth"); authNode != nil {
				auth := &APIAuthConfig{}
				for _, inst := range namedInstances(authNode.FindChildren("user")) {
					if pwNode := inst.node.FindChild("password"); pwNode != nil {
						auth.Users = append(auth.Users, &APIAuthUser{
							Username: inst.name,
							Password: Secret(nodeVal(pwNode)),
						})
					}
				}
				// #6692: api-key is `multi: true`, so a bracketed list
				// collapses onto ONE node's Keys and the pre-fix nodeVal read
				// kept slot 0 alone — a second provisioned key silently did not
				// authenticate, and key rotation (add new, then remove old)
				// silently failed to add the new key.
				//
				// multiLeafAuthoredValues rather than firewallMatchValues:
				// this leaf's EMPTY values are load-bearing. A quoted-empty
				// `api-key ""` must still reach APIKeys so
				// validateAPIAuthNoEmptySecretsStrict hard-rejects it and
				// apiAuthHasUsableCredential does not count it (#5636);
				// dropping empties here would turn that operator-visible
				// rejection into a silent disappearance. The
				// multiLeafAuthoredValues(n)[0] == nodeVal(n) invariant is what
				// makes slot 0 byte-identical to the pre-fix read.
				for _, ch := range authNode.FindChildren("api-key") {
					for _, key := range multiLeafAuthoredValues(ch) {
						auth.APIKeys = append(auth.APIKeys, Secret(key))
					}
				}
				sys.Services.WebManagement.APIAuth = auth
			}
		}
		// system services dynamic-dns — the Surface A provider catalog + engine
		// tunables (#2691 P2, plan §5.9). The per-interface `dynamic-dns`
		// bindings reference these named providers.
		if ddnsNode := svcNode.FindChild("dynamic-dns"); ddnsNode != nil {
			cat, ddnsWarnings, err := compileDDNSServices(ddnsNode, opts.lenientDDNSDuration)
			if err != nil {
				return err
			}
			if cfg != nil {
				cfg.Warnings = append(cfg.Warnings, ddnsWarnings...)
			}
			if cat != nil {
				if sys.Services == nil {
					sys.Services = &SystemServicesConfig{}
				}
				sys.Services.DynamicDNS = cat
			}
		}
	}

	snmpNode := node.FindChild("snmp")
	if snmpNode != nil {
		if err := compileSNMP(snmpNode, sys, cfg, opts.lenientSNMPTrapGroup); err != nil {
			return err
		}
	}

	// #4306 S-5: make the grouped `system` inert knobs (login banner/retry,
	// ntp boot-server/authentication-key/source-address, internet-options
	// extras, ssh rate-limit) loud instead of a silent no-op.
	if cfg != nil {
		cfg.Warnings = append(cfg.Warnings, systemInertKnobWarnings(node)...)
	}

	return nil
}

// ddnsProviderStringProps are the per-provider leaves that carry a string
// value, used by compileDDNSProvider's walker to recognize a "<leaf> <value>"
// pair at any AST depth (#2691 P2).
var ddnsProviderStringProps = map[string]bool{
	"backend":               true,
	"update-server":         true,
	"tsig-key":              true,
	"tsig-algorithm":        true,
	"tsig-secret":           true,
	"source-address":        true,
	"destination-interface": true,
	"routing-instance":      true,
	// HTTP-provider leaves (#2691 P3).
	"server":            true,
	"username":          true,
	"password":          true,
	"url-template":      true,
	"ok-response":       true,
	"api-token":         true,
	"zone":              true,
	"aws-access-key":    true,
	"aws-secret-key":    true,
	"aws-region":        true,
	"hosted-zone-id":    true,
	"checkip-url":       true,
	"checkip-allowlist": true,
}

// compileDDNSServices compiles the `system services dynamic-dns` block into a
// typed *DDNSServicesConfig: the named provider catalog + the engine tunables
// (forced-refresh / error-backoff-max). Returns a nil *DDNSServicesConfig for
// a truly empty block so a garbage/empty stanza does not materialize a
// catalog (#2691 P2, plan §5.9) — that can still happen alongside a non-nil
// warnings slice (an all-malformed block warns but has nothing to publish).
//
// #4837: forced-refresh / error-backoff-max accept a Go duration string
// ("24h") or a bare-seconds integer ("86400"), but a value that parses as
// NEITHER form (a typo like "24hh", or a non-positive value like "-5" — the
// downstream engine has no defined meaning for a non-positive interval) was
// previously silently discarded: the field was left unset, falling back to
// its downstream default, with no commit-time error or warning telling the
// operator their value was rejected. Strict (commit / commit-check):
// hard-reject on the first malformed leaf, naming it and its value. Lenient
// (load / peer-sync): downgrade to a warning, accumulated across both
// leaves, so an already-persisted config an older binary accepted still
// boots (#1960 fail-closed-on-load class) — the field stays unset either
// way, matching pre-#4837 runtime behavior exactly; only the warning is new.
func compileDDNSServices(node *Node, lenient bool) (*DDNSServicesConfig, []string, error) {
	cat := &DDNSServicesConfig{Providers: map[string]*DDNSProvider{}}
	var warnings []string
	for _, inst := range namedInstances(node.FindChildren("provider")) {
		p := compileDDNSProvider(inst.name, inst.node)
		if p == nil {
			continue
		}
		cat.Providers[p.Name] = p
		// TLS enforcement (#4861): a credentialed HTTP backend
		// (dyndns2/duckdns/cloudflare/route53/generic) must not carry its
		// update credential over a plaintext http:// endpoint. Strict
		// (commit / commit-check) hard-rejects; lenient (load / peer-sync)
		// downgrades to a warning so an already-persisted config an older
		// binary accepted still boots (#1960 fail-closed-on-load class). The
		// redirect-downgrade half (an https endpoint 30x'd to http) is blocked
		// at runtime by the shared client's CheckRedirect (pkg/ddns).
		if field, val, bad := ddnsPlaintextCredentialEndpoint(p); bad {
			msg := fmt.Sprintf("system services dynamic-dns provider %q (backend %s) "+
				"%s %q must be an https:// endpoint — a credentialed backend over a "+
				"plaintext http:// endpoint transmits the update credential in cleartext",
				p.Name, p.Backend, field, RedactURL(val))
			if !lenient {
				return nil, nil, fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg)
		}
	}
	// Engine tunables: a duration ("24h") or a bare-seconds integer. They may
	// appear as a child node OR packed into the block's Keys (flat-set).
	for _, leaf := range []string{"forced-refresh", "error-backoff-max"} {
		v := ddnsServicesScalar(node, leaf)
		if v == "" {
			continue
		}
		s := parseDurationSeconds(v)
		if s <= 0 {
			msg := fmt.Sprintf(
				"system services dynamic-dns %s %q: not a valid duration "+
					"(e.g. \"24h\") or a positive bare-seconds integer; "+
					"ignored — falls back to the built-in default", leaf, v)
			if !lenient {
				return nil, nil, fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg)
			continue
		}
		switch leaf {
		case "forced-refresh":
			cat.ForcedRefreshSeconds = s
		case "error-backoff-max":
			cat.ErrorBackoffMaxSeconds = s
		}
	}
	if len(cat.Providers) == 0 && cat.ForcedRefreshSeconds == 0 && cat.ErrorBackoffMaxSeconds == 0 {
		return nil, warnings, nil
	}
	return cat, warnings, nil
}

// ddnsServicesScalar finds a top-level scalar leaf value under the dynamic-dns
// block, tolerating both the hierarchical (child node `key value`) and flat-set
// (key+value packed into the block's Keys) AST shapes.
func ddnsServicesScalar(node *Node, key string) string {
	if c := node.FindChild(key); c != nil {
		if v := nodeVal(c); v != "" {
			return v
		}
	}
	for i := 0; i+1 < len(node.Keys); i++ {
		if node.Keys[i] == key {
			return node.Keys[i+1]
		}
	}
	return ""
}

// parseDurationSeconds parses a duration leaf as either a Go duration string
// ("24h", "30m", "1h30m") or a bare integer count of seconds ("86400"),
// returning whole seconds. Returns 0 for an unparseable value (the engine then
// uses its default).
func parseDurationSeconds(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	if d, err := time.ParseDuration(v); err == nil {
		return int(d.Seconds())
	}
	return 0
}

// compileDDNSProvider compiles one `provider <name> { ... }` entry. It walks
// the provider subtree (both AST shapes) for its string leaves. Returns nil for
// an empty provider block (just a name with no settings).
func compileDDNSProvider(name string, node *Node) *DDNSProvider {
	props := map[string]string{}
	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			// Skip the leading "provider" + "<name>" tokens. The named-instance
			// node's Keys begin with the value (name) when packed flat-set; be
			// conservative and skip until we are past the name.
			for start < len(n.Keys) && (n.Keys[start] == "provider" || n.Keys[start] == name) {
				start++
			}
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			if ddnsProviderStringProps[k] && i+1 < len(n.Keys) {
				if _, ok := props[k]; !ok {
					props[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, c := range n.Children {
			walk(c, false)
		}
	}
	walk(node, true)

	p := &DDNSProvider{
		Name:                 name,
		Backend:              props["backend"],
		UpdateServer:         props["update-server"],
		TSIGKeyName:          props["tsig-key"],
		TSIGAlgorithm:        props["tsig-algorithm"],
		TSIGSecret:           Secret(props["tsig-secret"]),
		SourceAddress:        props["source-address"],
		DestinationInterface: props["destination-interface"],
		RoutingInstance:      props["routing-instance"],
		Server:               props["server"],
		Username:             props["username"],
		Password:             Secret(props["password"]),
		URLTemplate:          props["url-template"],
		OKResponse:           props["ok-response"],
		APIToken:             Secret(props["api-token"]),
		Zone:                 props["zone"],
		AWSAccessKeyID:       props["aws-access-key"],
		AWSSecretAccessKey:   Secret(props["aws-secret-key"]),
		AWSRegion:            props["aws-region"],
		HostedZoneID:         props["hosted-zone-id"],
		CheckIPURL:           props["checkip-url"],
		CheckIPAllowlist:     props["checkip-allowlist"],
	}
	if p.Backend == "" && p.UpdateServer == "" && p.TSIGKeyName == "" &&
		p.TSIGAlgorithm == "" && p.TSIGSecret == "" && p.SourceAddress == "" &&
		p.DestinationInterface == "" && p.RoutingInstance == "" &&
		p.Server == "" && p.Username == "" && p.Password == "" &&
		p.URLTemplate == "" && p.OKResponse == "" && p.APIToken == "" &&
		p.Zone == "" && p.AWSAccessKeyID == "" && p.AWSSecretAccessKey == "" &&
		p.AWSRegion == "" && p.HostedZoneID == "" && p.CheckIPURL == "" &&
		p.CheckIPAllowlist == "" {
		return nil
	}
	return p
}

func compileSystemDataplaneType(node *Node) (string, error) {
	var dpType string
	for _, child := range node.Children {
		if child.Name() != "dataplane-type" || len(child.Keys) < 2 {
			continue
		}
		next := child.Keys[1]
		if !validDataplaneType(next) {
			return "", fmt.Errorf(
				"unknown dataplane-type %q; dataplane-type %q is invalid; "+
					"valid values are userspace or ebpf (deprecated); "+
					"dpdk parses for legacy-config compatibility but is "+
					"rejected at commit per #1525",
				next, next)
		}
		dpType = next
	}
	return dpType, nil
}

func hasDNSProxyChild(node *Node) bool {
	for _, child := range node.Children {
		if child.Name() == "dns-proxy" {
			return true
		}
	}
	return false
}

func compileUserspaceDataplane(node *Node, cfg *UserspaceConfig, warnings *[]string) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "userspace":
			// #903: `set system dataplane userspace ...` is a redundant
			// path — the operator wrote `userspace` again under a
			// dataplane block we are ALREADY processing as the userspace
			// dataplane (entered via `case "dataplane"` after
			// dataplane-type=userspace). Pre-fix this was a silent
			// no-op; we now strip the leading "userspace" key and
			// re-dispatch through this same switch so the inner setting
			// (`workers 4`, `poll-mode interrupt`, etc.) actually takes
			// effect. Backward-compatible: no commit-time hard error,
			// so stored pre-fix configs replay cleanly on upgrade AND
			// finally do what the operator intended.
			if len(child.Keys) >= 2 {
				synthetic := &Node{
					Keys:     child.Keys[1:],
					Children: child.Children,
					IsLeaf:   child.IsLeaf,
				}
				synthParent := &Node{Children: []*Node{synthetic}}
				if err := compileUserspaceDataplane(synthParent, cfg, warnings); err != nil {
					return err
				}
			}
		case "cores", "memory", "socket-mem", "rx-mode", "ports":
			// Retired DPDK-era knobs (#1525 deleted the consumer; #1892
			// documents the disposition). Accepted so stored configs keep
			// loading, but they configure nothing — record the knob name
			// so userspaceRetiredKnobWarnings surfaces a commit warning.
			cfg.RetiredKnobsSeen = append(cfg.RetiredKnobsSeen, child.Name())
		case "binary":
			cfg.Binary = nodeVal(child)
		case "control-socket":
			cfg.ControlSocket = nodeVal(child)
		case "state-file":
			cfg.StateFile = nodeVal(child)
		case "workers":
			if v := nodeVal(child); v != "" {
				if n, ok := parseIntLeaf(warnings, "system dataplane workers", v); ok {
					cfg.Workers = n
				}
			}
		case "ring-entries":
			if v := nodeVal(child); v != "" {
				if n, ok := parseIntLeaf(warnings, "system dataplane ring-entries", v); ok {
					cfg.RingEntries = n
				}
			}
		case "poll-mode":
			if v := nodeVal(child); v == "interrupt" || v == "busy-poll" {
				cfg.PollMode = v
			}
		case "shared-umem":
			cfg.SharedUMEM = compileSharedUMEMConfig(child)
		case "rss-indirection":
			// Defaults to enabled; only the string "disable" flips it off.
			// Anything else (including "enable" and empty) leaves the
			// default behaviour — D3 runs.
			if nodeVal(child) == "disable" {
				cfg.RSSIndirectionDisabled = true
			}
		case "claim-host-tunables":
			// #801 B1 opt-in gate. Defaults false. Only the literal
			// string "true" turns it on; anything else (including
			// "false", "enable", and empty) leaves the default-safe
			// behaviour in which xpfd never touches host-scope knobs.
			if nodeVal(child) == "true" {
				cfg.ClaimHostTunables = true
			}
		case "cpu-governor":
			// `performance` | `schedutil` | `default` (skip). Stored
			// verbatim; daemon maps `default` / "" → no write. Any
			// unrecognised governor is also passed through so bare-metal
			// operators can request `powersave` / `ondemand` if needed
			// without a config-schema change.
			cfg.CPUGovernor = nodeVal(child)
		case "netdev-budget":
			if v := nodeVal(child); v != "" {
				if n, ok := parseIntLeaf(warnings, "system dataplane netdev-budget", v); ok {
					cfg.NetdevBudget = n
				}
			}
		case "coalescence":
			// `coalescence adaptive enable|disable`, `coalescence
			// rx-usecs <n>`, `coalescence tx-usecs <n>`. All three keys
			// live under the same node to mirror the Junos shape
			// (`set system dataplane coalescence <knob> <val>`).
			for _, sub := range child.Children {
				switch sub.Name() {
				case "adaptive":
					// `enable` → operator opt-out of the "disable by
					// default" behaviour; `disable` (or any other value,
					// including "") → apply `ethtool -C adaptive-rx off
					// adaptive-tx off`. Explicit is set whenever the
					// knob was written so the daemon can distinguish
					// "omitted" from "explicitly enable" in logs.
					v := nodeVal(sub)
					cfg.CoalescenceAdaptiveExplicit = true
					if v == "enable" {
						cfg.CoalescenceAdaptiveDisabled = false
					} else {
						// Includes "disable", empty, and unknown values.
						cfg.CoalescenceAdaptiveDisabled = true
					}
				case "rx-usecs":
					if v := nodeVal(sub); v != "" {
						if n, ok := parseIntLeaf(warnings, "system dataplane coalescence rx-usecs", v); ok {
							cfg.CoalescenceRXUsecs = n
						}
					}
				case "tx-usecs":
					if v := nodeVal(sub); v != "" {
						if n, ok := parseIntLeaf(warnings, "system dataplane coalescence tx-usecs", v); ok {
							cfg.CoalescenceTXUsecs = n
						}
					}
				}
			}
		}
	}
	return nil
}

// syslogFacilitySeverity extracts the `<facility> <severity>` pair from a
// system-syslog destination child. The pair is normally flat
// (`daemon warning;` → Keys=["daemon","warning"]) but tolerates the
// hierarchical shape (`daemon { warning; }` → Keys=["daemon"], child
// Keys=["warning"]). Returns ok=false when the node carries no severity
// token, so a bare/garbage leaf is dropped rather than appended as a
// half-populated filter entry (#4303 S-1). Callers must pre-filter the
// known non-facility host/file/user modifiers by keyword.
func syslogFacilitySeverity(prop *Node) (facility, severity string, ok bool) {
	if prop == nil || len(prop.Keys) == 0 {
		return "", "", false
	}
	if len(prop.Keys) >= 2 {
		return prop.Keys[0], prop.Keys[1], true
	}
	for _, c := range prop.Children {
		if len(c.Keys) > 0 && c.Keys[0] != "" {
			return prop.Keys[0], c.Keys[0], true
		}
	}
	return "", "", false
}

// syslogArchiveKeywordArgs enumerates the `system syslog file <f> archive`
// sub-statements setSchema models (schema_system.go) and records, for each,
// whether it is followed by a value token. It is the keyword allowlist the
// token walker below uses to tell a KEYWORD apart from a VALUE in a flattened
// token stream, and the arity it uses to step over a value so an
// `archive-sites` URL that happens to equal a keyword is not mistaken for one
// (#7146).
var syslogArchiveKeywordArgs = map[string]bool{
	"size":              true,
	"files":             true,
	"start-time":        true,
	"transfer-interval": true,
	"archive-sites":     true,
	"world-readable":    false,
	"no-world-readable": false,
}

// syslogArchiveTokens flattens a syslog-file `archive` subtree into its tokens
// in source order, depth-first pre-order: a node contributes its own Keys,
// then each child's subtree. This is what makes ONE walker cover every shape
// the dual AST produces for the same stanza (#7146):
//
//	flat block      `set ... archive files 7` + `set ... archive size 1m`
//	                -> Keys=["archive"], children ["files","7"] ["size","1m"]
//	flat compact    `set ... archive size 1m files 5`
//	                -> Keys=["archive"] -> child ["size","1m"] -> GRANDchild
//	                   ["files","5"] (a nested chain, not siblings)
//	hierarchical    `archive { files 7; size 1m; }` -> same as flat block
//	hier. one-line  `archive size 1m files 5;`
//	                -> Keys=["archive","size","1m","files","5"], NO children
//
// A reader that only walked Children would miss the one-line form entirely;
// one that only read Keys would miss both block forms.
func syslogArchiveTokens(n *Node, out []string) []string {
	if n == nil {
		return out
	}
	out = append(out, n.Keys...)
	for _, c := range n.Children {
		out = syslogArchiveTokens(c, out)
	}
	return out
}

// syslogArchiveKnobs returns the sorted, deduplicated archive sub-statement
// KEYWORDS configured under a syslog-file `archive` node — never their values,
// because an `archive-sites` URL can carry credentials and the caller feeds
// this straight into an operator-visible commit advisory (#7146).
//
// Unrecognized tokens are skipped rather than reported: the schema already
// rejects an unknown leaf at commit, and echoing an arbitrary token here would
// reintroduce the value-leak this function exists to avoid.
func syslogArchiveKnobs(n *Node) []string {
	if n == nil {
		return nil
	}
	tokens := syslogArchiveTokens(n, nil)
	if len(tokens) > 0 {
		// Drop the leading "archive" keyword itself.
		tokens = tokens[1:]
	}
	seen := map[string]bool{}
	var knobs []string
	for i := 0; i < len(tokens); i++ {
		takesValue, isKeyword := syslogArchiveKeywordArgs[tokens[i]]
		if !isKeyword {
			continue
		}
		if !seen[tokens[i]] {
			seen[tokens[i]] = true
			knobs = append(knobs, tokens[i])
		}
		if takesValue {
			// Step over the value so `archive-sites "size"` records
			// archive-sites once, not archive-sites AND size.
			i++
		}
	}
	sort.Strings(knobs)
	return knobs
}

// loginClassPermName renders a coarse xpf permission for the advisory.
func loginClassPermName(p LoginClassPermission) string {
	switch p {
	case PermView:
		return "view"
	case PermClear:
		return "clear"
	case PermControl:
		return "control"
	case PermConfig:
		return "configure"
	case PermMaint:
		return "maintenance"
	case PermAll:
		return "super-user"
	default:
		return "unknown"
	}
}

// loginClassAdvisoryWarnings emits one accept-with-advisory warning per custom
// `system login class <name>` (#4304 S-2). The class is RECOGNIZED (a valid
// vSRX RBAC config commits instead of being hard-rejected), but xpf's coarse
// permission model cannot faithfully represent every Junos permission or the
// per-command ADDITIVE regexes (allow-commands / allow-configuration), so the
// advisory states exactly what maps and what is recognized-but-not-enforced.
// It says nothing about the RESTRICTIVE regexes: #5831 moved deny-commands /
// deny-configuration out of advisory territory entirely — strict rejects the
// commit, and the tolerant path folds the class and emits its own warning
// (compiler_login_deny.go). Deterministic order for stable output.
func loginClassAdvisoryWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) == 0 {
		return nil
	}
	var warnings []string
	for _, lc := range cfg.System.Login.Classes {
		_, folded := mapJunosPermissions(lc.Permissions)
		// Report the EFFECTIVE set (lc.MappedPermissions), not a fresh
		// mapJunosPermissions call (#5831). The two are identical for every
		// class the tolerant #5831 fold did not touch, so this changes no
		// existing output; for a folded class the fresh call would report the
		// pre-fold buckets and tell the operator the class still holds
		// permissions it no longer has.
		names := make([]string, 0, len(lc.MappedPermissions))
		for _, p := range lc.MappedPermissions {
			names = append(names, loginClassPermName(p))
		}
		mappedStr := "none"
		if len(names) > 0 {
			sort.Strings(names)
			mappedStr = strings.Join(names, ",")
		}
		msg := fmt.Sprintf("system login class %q: recognized (custom RBAC); Junos permissions [%s] mapped to xpf coarse permissions {%s}",
			lc.Name, strings.Join(lc.Permissions, " "), mappedStr)
		if len(folded) > 0 {
			sort.Strings(folded)
			msg += fmt.Sprintf("; fine-grained permissions [%s] folded to view-only (xpf has no finer bucket)", strings.Join(folded, " "))
		}
		// Neutral not-enforced knobs (allow-* is a whitelist EXTENSION and
		// idle-timeout is a session-lifetime knob; dropping them cannot make
		// the class more permissive than the source config).
		var inert []string
		if lc.AllowCommands != "" {
			inert = append(inert, "allow-commands")
		}
		if lc.AllowConfiguration != "" {
			inert = append(inert, "allow-configuration")
		}
		if lc.IdleTimeout > 0 {
			inert = append(inert, "idle-timeout")
		}
		if len(inert) > 0 {
			msg += fmt.Sprintf("; %s accepted but NOT enforced by xpf's coarse RBAC", strings.Join(inert, "/"))
		}
		// SECURITY: deny-commands / deny-configuration are BLACKLISTS, and the
		// #4304 "accepted but MORE PERMISSIVE" advisory that used to be
		// appended here is GONE (#5831) rather than reworded. Two reasons it
		// could not stay:
		//
		//  1. It is no longer reachable on the strict path at all —
		//     validateLoginClassDenyStrict rejects the commit outright.
		//  2. On the tolerant path it would now be misleading. That path folds
		//     the class to the repair floor before this runs, dropping every
		//     operational-verb bucket, so the class is MORE restrictive than
		//     the Junos config on the half deny-commands targets; repeating
		//     the old text would tell the operator the opposite of what
		//     happened. (Configuration is the one half where the restriction
		//     genuinely does not bind — the fold keeps `configure` so the
		//     statement can be deleted — and the fold's own warning says so
		//     precisely, which a blanket "MORE PERMISSIVE" cannot.)
		//
		// foldLoginClassDenyToRepairableFloor emits the accurate per-class
		// warning on that path, so this advisory stays out of the
		// restrictive-regex business entirely and describes only the
		// permission mapping.
		warnings = append(warnings, msg)
	}
	return warnings
}

// sshHardeningAdvisoryWarnings notes the SSH knobs xpf recognizes but does not
// (or cannot) render into the sshd drop-in (#4305 S-4). protocol-version is the
// main one: modern sshd is SSH-2 only, so `v2` is a silent no-op and any other
// value cannot be honored (SSH-1 is unsupported).
func sshHardeningAdvisoryWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		return nil
	}
	ssh := cfg.System.Services.SSH
	var warnings []string
	if ssh.ProtocolVersion != "" && ssh.ProtocolVersion != "v2" {
		warnings = append(warnings, fmt.Sprintf(
			"system services ssh protocol-version %q: sshd is SSH-2 only; SSH-1 is not supported, so this is accepted but NOT enforced",
			ssh.ProtocolVersion))
	}
	return warnings
}

// userspaceRetiredKnobWarnings turns each retired DPDK-era `system
// dataplane` knob recorded by compileUserspaceDataplane into a commit
// warning (#1892). The knobs (cores, memory, socket-mem, rx-mode, ports)
// lost their consumer in the #1525 DPDK retirement; they stay parseable
// so stored configs keep loading, but the operator must learn the stanza
// is inert. Deduplicated and ordered for stable output.
func userspaceRetiredKnobWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.UserspaceDataplane == nil {
		return nil
	}
	seen := cfg.System.UserspaceDataplane.RetiredKnobsSeen
	if len(seen) == 0 {
		return nil
	}
	uniq := make([]string, 0, len(seen))
	have := make(map[string]bool, len(seen))
	for _, k := range seen {
		if !have[k] {
			have[k] = true
			uniq = append(uniq, k)
		}
	}
	sort.Strings(uniq)
	warnings := make([]string, 0, len(uniq))
	for _, k := range uniq {
		warnings = append(warnings, fmt.Sprintf(
			"system dataplane %s: retired DPDK-era knob (#1525), accepted for config compatibility but ignored", k))
	}
	return warnings
}

// compileSharedUMEMConfig compiles the `system dataplane shared-umem` stanza
// into typed config. It is intentionally PURE (no file I/O): it records the
// mode, the participating-interface filter, and the operator-DECLARED
// phase0-artifact-file PATH only. The artifact's node-local contents are NEVER
// embedded here — that node-local read happens non-fatally in
// sharedUMEMAuditWarnings so the same committed tree compiles to the same typed
// config on any node (#5300 determinism).
func compileSharedUMEMConfig(node *Node) *SharedUMEMConfig {
	cfg := &SharedUMEMConfig{}
	for _, child := range node.Children {
		switch child.Name() {
		case "mode":
			cfg.Mode = nodeVal(child)
		case "interface":
			// #6692: `interface` is `multi: true` — a bracketed list
			// (`shared-umem { interface [ eth1 eth2 ]; }`) collapses onto ONE
			// node's Keys, so the pre-fix nodeVal read kept eth1 alone and the
			// dataplane's shared-UMEM memory topology differed from what the
			// operator authored. firewallMatchValues reads both sides of the
			// AST and skips empty tokens, matching the previous `v != ""`
			// guard.
			for _, v := range firewallMatchValues(child) {
				cfg.Interfaces = append(cfg.Interfaces, LinuxIfName(v))
			}
		case "phase0-artifact-file", "artifact-file":
			if path := nodeVal(child); path != "" {
				cfg.Phase0ArtifactFile = path
			}
		}
	}
	return cfg
}

// readSharedUMEMPhase0ArtifactForAudit reads and validates the operator-declared
// Phase 0 audit artifact for the AUDIT WARNING path only (#5300). It is
// non-blocking and bounded so it can never hang or OOM a commit:
//   - it stats first and refuses any non-regular file (directory, FIFO, socket,
//     device) — an os.Open on a FIFO/device can block indefinitely;
//   - it refuses an over-cap file by its stat size before opening;
//   - it opens O_RDONLY|O_NONBLOCK (a no-op on a regular file) so a stat->open
//     TOCTOU swap to a FIFO/device still cannot block; and
//   - it bounds the read with a LimitReader.
//
// The returned artifact is used ONLY to derive an operator-visible audit
// warning; it is never stored in the typed config, so it cannot affect
// same-tree->same-config determinism. Every error return here is non-fatal at
// the call site (sharedUMEMAuditWarnings turns it into a warning, not a compile
// error).
func readSharedUMEMPhase0ArtifactForAudit(path string) (map[string]interface{}, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read shared-umem artifact %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read shared-umem artifact %s: not a regular file (mode %s)", path, info.Mode().Type())
	}
	if info.Size() > sharedUMEMPhase0ArtifactMaxBytes {
		return nil, fmt.Errorf("read shared-umem artifact %s: exceeds %d bytes", path, sharedUMEMPhase0ArtifactMaxBytes)
	}

	// O_NONBLOCK guards a stat->open TOCTOU swap to a FIFO/device; on a regular
	// file it has no effect.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("read shared-umem artifact %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, sharedUMEMPhase0ArtifactMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read shared-umem artifact %s: %w", path, err)
	}
	if len(data) > sharedUMEMPhase0ArtifactMaxBytes {
		return nil, fmt.Errorf("read shared-umem artifact %s: exceeds %d bytes", path, sharedUMEMPhase0ArtifactMaxBytes)
	}

	var artifact map[string]interface{}
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, fmt.Errorf("decode shared-umem artifact %s: %w", path, err)
	}
	if artifact == nil {
		return nil, fmt.Errorf("decode shared-umem artifact %s: top-level value must be a JSON object", path)
	}
	if err := normalizeSharedUMEMArtifactInterfaces(artifact); err != nil {
		return nil, fmt.Errorf("decode shared-umem artifact %s: %w", path, err)
	}
	return artifact, nil
}

// sharedUMEMAuditWarnings performs the NON-BLOCKING, NON-GATING Phase 0 audit
// read for the operator-declared shared-umem artifact (#5300). Per
// docs/shared-umem-plan.md ("Phase 0: Repro and Audit Evidence") the artifact
// is audit evidence only: it does not gate runtime shared-UMEM selection, so a
// read failure must never fail the compile and must never change the typed
// config. Running it as a tail gate keeps the operator audit signal at commit /
// load while keeping the read off the typed-config path:
//
//   - unavailable / unreadable / non-regular / oversized / malformed -> one
//     commit WARNING (visible but non-blocking); the commit still succeeds.
//   - a machine-readable artifact whose "passed" field is explicitly false ->
//     a WARNING surfacing that recorded result.
//
// Because it only appends to cfg.Warnings (a host-local diagnostic) and never
// touches cfg.System.UserspaceDataplane.SharedUMEM, the same committed tree
// still compiles to the identical typed config on a peer / after restart.
func sharedUMEMAuditWarnings(cfg *Config) []string {
	if cfg == nil || cfg.System.UserspaceDataplane == nil ||
		cfg.System.UserspaceDataplane.SharedUMEM == nil {
		return nil
	}
	path := cfg.System.UserspaceDataplane.SharedUMEM.Phase0ArtifactFile
	if path == "" {
		return nil
	}
	artifact, err := readSharedUMEMPhase0ArtifactForAudit(path)
	if err != nil {
		return []string{fmt.Sprintf(
			"system dataplane shared-umem phase0-artifact-file %s: audit artifact unavailable (%v); non-blocking, does not gate the commit or change the compiled config", path, err)}
	}
	if passed, ok := artifact["passed"].(bool); ok && !passed {
		return []string{fmt.Sprintf(
			"system dataplane shared-umem phase0-artifact-file %s: audit artifact records passed=false; shared-UMEM selection is decided at runtime by live bind validation, not this artifact", path)}
	}
	return nil
}

func normalizeSharedUMEMArtifactInterfaces(artifact map[string]interface{}) error {
	for _, key := range []string{"selected_interfaces", "interfaces"} {
		if err := normalizeSharedUMEMArtifactInterfaceArray(artifact, key); err != nil {
			return err
		}
	}
	for _, key := range []string{
		"driver",
		"driver_name",
		"driver_version",
		"firmware",
		"firmware_version",
		"mtu",
		"nic_firmware_versions",
		"queue_topology",
	} {
		if err := normalizeSharedUMEMArtifactInterfaceMap(artifact, key); err != nil {
			return err
		}
	}
	return nil
}

func normalizeSharedUMEMArtifactInterfaceArray(artifact map[string]interface{}, key string) error {
	values, ok := artifact[key].([]interface{})
	if !ok {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		name, ok := value.(string)
		if !ok {
			continue
		}
		linuxName := LinuxIfName(name)
		if _, exists := seen[linuxName]; exists {
			return fmt.Errorf("duplicate %s entry after Linux interface-name normalization: %s", key, linuxName)
		}
		seen[linuxName] = struct{}{}
		values[i] = linuxName
	}
	return nil
}

func normalizeSharedUMEMArtifactInterfaceMap(artifact map[string]interface{}, key string) error {
	values, ok := artifact[key].(map[string]interface{})
	if !ok {
		return nil
	}
	normalized := make(map[string]interface{}, len(values))
	for ifname, value := range values {
		linuxName := LinuxIfName(ifname)
		if _, exists := normalized[linuxName]; exists {
			return fmt.Errorf("duplicate %s key after Linux interface-name normalization: %s", key, linuxName)
		}
		normalized[linuxName] = value
	}
	artifact[key] = normalized
	return nil
}

func compileSNMP(node *Node, sys *SystemConfig, cfg *Config, lenient bool) error {
	snmp := &SNMPConfig{
		Communities: make(map[string]*SNMPCommunity),
		TrapGroups:  make(map[string]*SNMPTrapGroup),
		V3Users:     make(map[string]*SNMPv3User),
	}

	// #5833: communities whose `clients` allowlist carried a malformed token on
	// the tolerant load / peer-sync path are quarantined to deny-all. Sticky
	// across same-name merge blocks (#5472): once a community is quarantined a
	// LATER well-formed block must NOT un-quarantine it (its policy is no longer
	// trustworthy). Empty on the strict path (a malformed token hard-rejects
	// before it can be recorded here).
	quarantinedComms := map[string]bool{}

	for _, child := range node.Children {
		switch child.Name() {
		case "location":
			snmp.Location = nodeVal(child)
		case "contact":
			snmp.Contact = nodeVal(child)
		case "description":
			snmp.Description = nodeVal(child)
		case "community":
			commName := nodeVal(child)
			if commName != "" {
				commChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					commChildren = child.Children[0].Children
				}
				// Parse THIS block's authorization + clients into locals first.
				// A same-name sibling block is then MERGED into any existing
				// entry rather than overwriting it (#5472), so a later block
				// cannot silently drop an earlier block's source-IP allowlist.
				var blockAuth string
				var blockClients []SNMPClient
				for _, prop := range commChildren {
					switch prop.Name() {
					case "authorization":
						blockAuth = nodeVal(prop)
					case "clients":
						// #4289: Junos `clients` source-IP allowlist.
						// parseSNMPClients handles both AST shapes and the
						// per-entry `restrict` modifier. Accumulate so a
						// clients block split across load-merge / flat-set
						// replays is not dropped.
						blockClients = append(blockClients, parseSNMPClients(prop)...)
					}
				}
				// Flat form: community public authorization read-only
				for i := 2; i < len(child.Keys)-1; i++ {
					if child.Keys[i] == "authorization" {
						blockAuth = child.Keys[i+1]
					}
				}
				// #4834: reject/warn on an unparseable `clients` entry before
				// it reaches compileClientNets. See validateSNMPClients for
				// why this matters beyond a plain prefix typo: it also
				// catches a mistyped "restrict" keyword, which otherwise
				// silently detaches from the preceding prefix and turns a
				// deny-except entry into an unrestricted allow (fail-open).
				// Validate only THIS block's new entries: on the merge path an
				// earlier block's entries were already validated (and, strict,
				// would have aborted), so re-validating the accumulated list
				// would double-report the same warning.
				clientWarnings, blockMalformed, err := validateSNMPClients(blockClients, lenient)
				if err != nil {
					return err
				}
				if cfg != nil {
					cfg.Warnings = append(cfg.Warnings, clientWarnings...)
				}
				// #5833: a malformed token on the lenient path quarantines the
				// community (strict already aborted above). Record it BEFORE the
				// clientNets build below so the deny-all override wins.
				if blockMalformed {
					quarantinedComms[commName] = true
				}
				// #5472: same-name `community` blocks MERGE into one entry
				// instead of a plain map overwrite. Junos treats two
				// `community public { ... }` siblings as a single configuration
				// node; the old `Communities[name] = comm` overwrite let a later
				// duplicate with NO `clients` replace an earlier block that had
				// an allowlist — and AllowsSource reads an empty allowlist as
				// allow-all, so the source-IP restriction was silently erased
				// (security fail-open: any source could then query the
				// community). Accumulating the allowlist keeps the restriction
				// on BOTH the strict commit and the lenient load / HA
				// config-sync paths (a warn-and-keep-last-writer gate would
				// still open the community on the lenient path).
				comm := snmp.Communities[commName]
				if comm == nil {
					comm = &SNMPCommunity{Name: commName}
					snmp.Communities[commName] = comm
				}
				comm.Clients = append(comm.Clients, blockClients...)
				// A later block updates the authorization only when it
				// explicitly states one; an omitted authorization must NOT
				// clear a value an earlier block established (do not let an
				// empty duplicate downgrade read-write back to the read-only
				// default).
				if blockAuth != "" {
					comm.Authorization = blockAuth
				}
				if comm.Authorization == "" {
					comm.Authorization = "read-only"
				}
				// #4711: (re)build the allocation-free client-prefix cache from
				// the now-merged Clients, so AllowsSource does an
				// allocation-free match per incoming v2c packet instead of
				// re-parsing every prefix on every packet. Runs here, before
				// the config is published to the SNMP agent, so the cache is
				// set with no concurrent readers.
				comm.clientNets = compileClientNets(comm.Clients)
				// #5833: fail CLOSED for a quarantined community. compileClientNets
				// above would drop the malformed token and leave the surviving
				// broad allow live (fail-open); override the enforcement cache with
				// an explicit deny-all so no source can query this community until
				// the operator fixes the typo. Sticky across merge blocks, so a
				// later well-formed block for the same community cannot reopen it.
				if quarantinedComms[commName] {
					comm.clientNets = snmpQuarantineClientNets()
				}
			}
		case "trap-group":
			tgName := nodeVal(child)
			if tgName != "" {
				tg := &SNMPTrapGroup{Name: tgName}
				tgChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					tgChildren = child.Children[0].Children
				}
				for _, prop := range tgChildren {
					switch prop.Name() {
					case "targets":
						// targets may carry multiple values: one per child
						// (hierarchical `targets { a; b; }`) and/or packed in
						// the leaf Keys (flat-set / bracketed list).
						tg.Targets = append(tg.Targets, firewallMatchValues(prop)...)
					case "version":
						// #3948: carry the trap-group SNMP version to the
						// emitter. Schema enum is v1|v2|all; an empty value
						// (unspecified) defaults to v2c in pkg/snmp/traps.go.
						// Without this the version was parsed but dropped, so a
						// `version v1` group silently emitted v2c traps that a
						// v1-only receiver drops.
						tg.Version = nodeVal(prop)
					case "categories":
						// #5522: retain the configured trap categories so the
						// runtime can enforce the filter. `categories` is a
						// schema `multi: true` leaf, so the bracketed/flat-set
						// list collapses onto the leaf Keys and/or its children
						// (the #2419 dual-shape) — read BOTH via
						// firewallMatchValues. A trap-group with NO categories
						// stanza leaves this nil, which pkg/snmp/traps.go treats
						// as "all categories" (the Junos default). Before this
						// the key was recognized but DISCARDED, so a group
						// scoped to exclude `link` still received every
						// linkUp/linkDown notification (filter bypass).
						tg.Categories = append(tg.Categories, firewallMatchValues(prop)...)
					default:
						// #2990: a typoed child key (e.g. `tragets`) would
						// otherwise be silently dropped, committing a trap
						// group with zero targets that sends nothing. Strict
						// (commit / commit-check): reject so the operator is
						// told about the typo instead of losing every
						// notification at runtime. Lenient (load / HA-sync):
						// downgrade to a warning so an already-persisted bad
						// config still boots — the runtime ignores the unknown
						// key, so it is inert (#1960 fail-closed-on-load).
						if !lenient {
							return fmt.Errorf("snmp trap-group %q: unknown statement %q (valid: targets, version, categories)", tgName, prop.Name())
						}
						if cfg != nil {
							cfg.Warnings = append(cfg.Warnings,
								fmt.Sprintf("snmp trap-group %q: unknown statement %q (downgraded to warning on tolerant path; ignored at runtime)", tgName, prop.Name()))
						}
					}
				}
				// #2990: a trap group with no targets sends nothing. Strict:
				// reject rather than presenting a configured-but-inert group
				// (this also catches a bare `set snmp trap-group g1` with no
				// children). Lenient: warn so an already-persisted zero-target
				// group still boots — sendLinkTraps skips a zero-target group,
				// so it is inert (#1960).
				if len(tg.Targets) == 0 {
					if !lenient {
						return fmt.Errorf("snmp trap-group %q: no targets configured (a trap group with zero targets sends no notifications)", tgName)
					}
					if cfg != nil {
						cfg.Warnings = append(cfg.Warnings,
							fmt.Sprintf("snmp trap-group %q: no targets configured (downgraded to warning on tolerant path; sends no notifications)", tgName))
					}
				}
				snmp.TrapGroups[tg.Name] = tg
			}
		case "v3":
			compileSNMPv3(child, snmp)
		}
	}

	sys.SNMP = snmp
	if cfg != nil {
		cfg.Warnings = append(cfg.Warnings, snmpInertKnobWarnings(node)...)
	}
	return nil
}

// snmpInertKnobWarnings emits accept-with-advisory notes for the top-level
// `snmp` knobs xpf recognizes but does not enforce (#4306 S-5). The
// security-relevant ones are called out explicitly: a MIB `view` (on a
// community or standalone) is NOT enforced, so a view-scoped community is
// silently promoted to full ifTable exposure; `trap-options source-address`
// is NOT bound, so traps leave from the default egress IP. Messages are built
// from the node IDENTITY (keywords) only — never the community NAME (an SNMP
// community string is a secret). Deterministic, deduplicated output.
func snmpInertKnobWarnings(node *Node) []string {
	if node == nil {
		return nil
	}
	seen := map[string]bool{}
	var warnings []string
	add := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
	}
	nodeHasSub := func(n *Node, keyword string) bool {
		if n == nil {
			return false
		}
		if n.FindChild(keyword) != nil {
			return true
		}
		for _, k := range n.Keys[1:] {
			if k == keyword {
				return true
			}
		}
		return false
	}
	for _, child := range node.Children {
		switch child.Name() {
		case "view":
			add("snmp view: MIB view scoping is accepted but NOT enforced by the SNMP agent (the full ifTable MIB is exposed regardless)")
		case "trap-options":
			if nodeHasSub(child, "source-address") {
				add("snmp trap-options source-address: accepted but NOT enforced (traps are sent from the default egress IP)")
			}
		case "health-monitor":
			add("snmp health-monitor: accepted but NOT implemented (no-op)")
		case "rmon":
			add("snmp rmon: accepted but NOT implemented (no-op)")
		case "community":
			// The community NAME is a secret — never echo it. Name only the
			// keyword. A view-scoped community answers the full ifTable.
			if nodeHasSub(child, "view") {
				add("snmp community view: per-community MIB view scoping is accepted but NOT enforced (the community answers the full ifTable)")
			}
		}
	}
	return warnings
}

// systemInertKnobWarnings emits accept-with-advisory notes for the grouped
// `system` knobs that commit clean but do nothing (#4306 S-5): login banners /
// retry-options, NTP boot-server / authentication-key / source-address, and
// `internet-options` leaves beyond the one xpf models. Messages name the
// keyword only — never a leaf value (the NTP authentication-key is a secret).
func systemInertKnobWarnings(sysNode *Node) []string {
	if sysNode == nil {
		return nil
	}
	seen := map[string]bool{}
	var warnings []string
	add := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
	}
	if login := sysNode.FindChild("login"); login != nil {
		if login.FindChild("message") != nil {
			add("system login message: pre-login banner accepted but NOT applied")
		}
		if login.FindChild("announcement") != nil {
			add("system login announcement: post-login announcement accepted but NOT applied")
		}
		if login.FindChild("retry-options") != nil {
			add("system login retry-options: login retry/lockout policy accepted but NOT enforced")
		}
	}
	if ntp := sysNode.FindChild("ntp"); ntp != nil {
		if ntp.FindChild("boot-server") != nil {
			add("system ntp boot-server: accepted but NOT enforced (no one-shot boot-time sync)")
		}
		if ntp.FindChild("authentication-key") != nil {
			// The key VALUE is a secret — name the keyword only.
			add("system ntp authentication-key: NTP authentication accepted but NOT enforced")
		}
		if ntp.FindChild("source-address") != nil {
			add("system ntp source-address: accepted but NOT bound (NTP uses the default source IP)")
		}
	}
	if io := sysNode.FindChild("internet-options"); io != nil {
		var extra []string
		for _, c := range io.Children {
			if c.Name() != "no-ipv6-reject-zero-hop-limit" {
				extra = append(extra, c.Name())
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			add(fmt.Sprintf("system internet-options [%s]: accepted but NOT implemented (xpf models only no-ipv6-reject-zero-hop-limit)", strings.Join(extra, " ")))
		}
	}
	if svc := sysNode.FindChild("services"); svc != nil {
		if ssh := svc.FindChild("ssh"); ssh != nil {
			if ssh.FindChild("rate-limit") != nil {
				add("system services ssh rate-limit: accepted but NOT enforced (sshd has no per-minute connection-rate limiter)")
			}
		}
	}
	return warnings
}

// compileSNMPv3 parses the v3 { usm { local-engine { user <name> { ... } } } } hierarchy.
func compileSNMPv3(node *Node, snmp *SNMPConfig) {
	// Flat form: Keys = ["v3", "usm", "local-engine", "user", "<name>", "authentication-sha", "authentication-password", "<pass>"]
	// Index:       0      1         2              3       4                5                         6                       7
	if len(node.Keys) >= 8 && node.Keys[1] == "usm" && node.Keys[2] == "local-engine" && node.Keys[3] == "user" {
		userName := node.Keys[4]
		user := snmp.V3Users[userName]
		if user == nil {
			user = &SNMPv3User{Name: userName}
		}
		parseSNMPv3UserKeys(node.Keys[5:], user)
		snmp.V3Users[userName] = user
		return
	}

	// Hierarchical form: v3 -> usm -> local-engine -> user <name> { ... }
	usmNode := node.FindChild("usm")
	if usmNode == nil {
		return
	}
	// #7653: `usm local-engine { user ... }` packs the intermediate container
	// onto the usm line, so local-engine sits in usmNode.Keys and this
	// FindChild returns nil -- and EVERY v3 user disappears. That is not a
	// credential downgrade but an SNMPv3 management outage from a config whose
	// text is correct. packedBodyChildren expands the tail schema-driven AND
	// (per #6818) attaches the nested block UNDER the packed node rather than
	// beside it, which is exactly the shape needed here: the users are
	// usmNode.Children and they belong under the synthesized local-engine.
	engineNode := usmNode.FindChild("local-engine")
	if engineNode == nil {
		for _, c := range packedBodyChildren(usmNode, schemaForPath("snmp", "v3", "usm")) {
			if c.Name() == "local-engine" {
				engineNode = c
				break
			}
		}
	}
	if engineNode == nil {
		return
	}
	for _, child := range engineNode.Children {
		if child.Name() != "user" {
			continue
		}
		userName := nodeVal(child)
		if userName == "" {
			continue
		}
		user := snmp.V3Users[userName]
		if user == nil {
			user = &SNMPv3User{Name: userName}
		}
		userChildren := child.Children
		if len(child.Keys) < 2 && len(child.Children) > 0 {
			userChildren = child.Children[0].Children
		}
		// #7653: the body may be PACKED onto the user's own instance line
		//   user ops authentication-sha256 authentication-password "s3cret";
		// leaving Children empty. The user was still REGISTERED -- with no
		// derived key -- and minimum-security enforcement keys on key
		// presence, so a noAuthNoPriv request naming this user bypasses the
		// authentication the operator authored. Route the trailing key run
		// through the same parseSNMPv3UserKeys the flat-set form uses above,
		// rather than a second copy of its table.
		if len(child.Keys) > 2 {
			parseSNMPv3UserKeys(child.Keys[2:], user)
		}
		for _, prop := range userChildren {
			// #6822: the compact spelling
			//   authentication-sha256 authentication-password "s3cret";
			// flattens the credential onto this node's own Keys, where the
			// FindChild reads below cannot see it. The result was NOT a skipped
			// user -- the protocol comes from the case label, so the user was
			// registered as requiring SHA-256 and AES-128 with EMPTY passwords.
			//
			// parseSNMPv3UserKeys already reads exactly this key shape for the
			// flat-set path. Route the compact block form through the same
			// function rather than duplicating its table: a second copy is a
			// second thing to keep in step, and a divergence here is a silent
			// credential loss either way.
			//
			// packedBodyChildren (compact_tail.go) is the general expander and
			// is used for the #6818/#6821 siblings. It is the wrong tool HERE:
			// the protocol is carried by the case LABEL rather than by a value,
			// so the reader below needs the whole key run, not a rebuilt child
			// tree -- and parseSNMPv3UserKeys already consumes exactly that run.
			if len(prop.Keys) >= 3 {
				// Route ONLY the exact credential shape, and do NOT skip the
				// switch below.
				//
				// `len(Keys) >= 3` alone is not a discriminator: extra container
				// keys survive schema walking, so
				//   authentication-sha256 ignored ignored { authentication-password "good"; }
				// matched it, parseSNMPv3UserKeys recognised SHA-256 but not
				// `ignored`, left the password empty, and an unconditional
				// `continue` then skipped the real password CHILD the switch
				// would have compiled. That registers the user as requiring
				// SHA-256 with an EMPTY credential -- which is the #6822 defect
				// itself, reintroduced on a different shape.
				//
				// Falling through also fixes the precedence: a node can carry a
				// packed tail AND a real child, and the child is the canonical
				// block spelling, so it must win.
				switch prop.Keys[1] {
				case "authentication-password", "privacy-password":
					parseSNMPv3UserKeys(prop.Keys, user)
				}
			}
			switch prop.Name() {
			case "authentication-md5":
				user.AuthProtocol = "md5"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = Secret(nodeVal(pw))
				}
			case "authentication-sha":
				user.AuthProtocol = "sha"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = Secret(nodeVal(pw))
				}
			case "authentication-sha256":
				user.AuthProtocol = "sha256"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = Secret(nodeVal(pw))
				}
			case "privacy-des":
				user.PrivProtocol = "des"
				if pw := prop.FindChild("privacy-password"); pw != nil {
					user.PrivPassword = Secret(nodeVal(pw))
				}
			case "privacy-aes128":
				user.PrivProtocol = "aes128"
				if pw := prop.FindChild("privacy-password"); pw != nil {
					user.PrivPassword = Secret(nodeVal(pw))
				}
			}
		}
		snmp.V3Users[userName] = user
	}
}

// parseSNMPv3UserKeys parses flat-form keys after the user name.
// Keys like: ["authentication-sha256", "authentication-password", "adminpass"]
func parseSNMPv3UserKeys(keys []string, user *SNMPv3User) {
	if len(keys) == 0 {
		return
	}
	switch keys[0] {
	case "authentication-md5":
		user.AuthProtocol = "md5"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = Secret(keys[2])
		}
	case "authentication-sha":
		user.AuthProtocol = "sha"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = Secret(keys[2])
		}
	case "authentication-sha256":
		user.AuthProtocol = "sha256"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = Secret(keys[2])
		}
	case "privacy-des":
		user.PrivProtocol = "des"
		if len(keys) >= 3 && keys[1] == "privacy-password" {
			user.PrivPassword = Secret(keys[2])
		}
	case "privacy-aes128":
		user.PrivProtocol = "aes128"
		if len(keys) >= 3 && keys[1] == "privacy-password" {
			user.PrivPassword = Secret(keys[2])
		}
	}
}

var schedulerWeekdays = map[string]struct{}{
	"monday": {}, "tuesday": {}, "wednesday": {}, "thursday": {},
	"friday": {}, "saturday": {}, "sunday": {},
}

func compileSchedulers(node *Node, cfg *Config) error {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*SchedulerConfig)
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
		// #5825: REUSE the existing map entry instead of allocating a fresh
		// SchedulerConfig per named AST instance. compileSchedulers runs once PER
		// top-level `schedulers` root (compiler_dispatch.go) and once per named
		// instance within a root; the pre-fix code built a fresh sched each time
		// then unconditionally `cfg.Schedulers[name] = sched`, so a later same-name
		// block/root REPLACED the first — every day/window authored earlier
		// vanished. A policy time-gated by the scheduler then became active/inactive
		// on the WRONG days with a clean commit. Flat `set` composes into ONE path,
		// so hierarchical diverged from flat. Reusing the persisted entry composes
		// every fragment: the weekday Days map (below) UNIONS distinct days across
		// blocks/roots (no window lost), and the daily/date scalars follow
		// flat-set / Junos load-merge last-wins (a repeated leaf replaces — no
		// "conflict" arises in flat-set, so hierarchical must match). Mirrors the
		// #5824 policy-statement block-merge.
		sched := cfg.Schedulers[inst.name]
		if sched == nil {
			sched = &SchedulerConfig{Name: inst.name}
			cfg.Schedulers[inst.name] = sched
		}

		for _, prop := range inst.node.Children {
			name := prop.Name()
			switch {
			case name == "start-time":
				// Legacy simplified shape: start-time/stop-time as direct
				// children of the scheduler (the daily window).
				sched.StartTime = nodeVal(prop)
			case name == "stop-time":
				sched.StopTime = nodeVal(prop)
			case name == "start-date":
				sched.StartDate = nodeVal(prop)
			case name == "stop-date":
				sched.StopDate = nodeVal(prop)
			case name == "daily":
				sched.Daily = true
				// Junos hierarchical shape:
				//   daily { start-time X; stop-time Y; }
				//   daily all-day;  /  daily { exclude; }
				// A bare `daily;` leaf carries no window and only flips the
				// recurrence flag. Descend to read the daily window (#3849 —
				// previously this branch ignored the block, leaving the
				// window empty so isWithinWindow fell open to always-active).
				if win, ok := schedulerWindowFromNode(prop); ok {
					if win.StartTime != "" {
						sched.StartTime = win.StartTime
					}
					if win.StopTime != "" {
						sched.StopTime = win.StopTime
					}
					sched.AllDay = win.AllDay
				}
			default:
				if _, ok := schedulerWeekdays[name]; ok {
					if win, ok := schedulerWindowFromNode(prop); ok {
						if sched.Days == nil {
							sched.Days = make(map[string]*SchedulerDayWindow)
						}
						w := win
						sched.Days[name] = &w
					}
				}
			}
		}
		// #5825: NO unconditional overwrite here — sched IS the shared map entry,
		// so this instance's fragments are already composed into any earlier
		// same-name block/root's days and scalars.
	}
	return nil
}

// schedulerWindowFromNode extracts a time window from a `daily` or weekday
// container node inside a scheduler. It handles both AST shapes and returns
// ok=false when the node is a bare flag with no recognized window statement
// (e.g. a plain `daily;`), so the caller can leave the window unset.
func schedulerWindowFromNode(n *Node) (SchedulerDayWindow, bool) {
	var win SchedulerDayWindow
	found := false

	// Flat leaf shape where the keyword rides on the node's own Keys, e.g.
	// hierarchical `daily all-day;` parses to Keys=["daily","all-day"].
	if len(n.Keys) >= 2 {
		switch n.Keys[1] {
		case "all-day":
			win.AllDay = true
			found = true
		case "exclude":
			win.Exclude = true
			found = true
		}
	}

	for _, c := range n.Children {
		switch c.Name() {
		case "start-time":
			win.StartTime = nodeVal(c)
			found = true
		case "stop-time":
			win.StopTime = nodeVal(c)
			found = true
		case "all-day":
			win.AllDay = true
			found = true
		case "exclude":
			win.Exclude = true
			found = true
		}
	}
	return win, found
}

func compileChassis(node *Node, ch *ChassisConfig) error {
	// #1956 R-7/V-7: the device-map subtree compiles INDEPENDENTLY of
	// cluster — a sibling `device-map` must not be dropped on a standalone
	// (no-cluster) box. Compile it first, then fall through to cluster.
	if dmNode := node.FindChild("device-map"); dmNode != nil {
		if dm := compileDeviceMap(dmNode); dm != nil {
			ch.DeviceMap = dm
		}
	}

	// #6672: resolve the cluster body across all four spellings. A body packed
	// onto the `cluster` line — or onto the `chassis` line above it — carries
	// its statements on Keys with NO children, so the FindChild reads below saw
	// an empty stanza and compiled nothing while the commit succeeded. The
	// container spelling returns the same node, untouched.
	clusterNode := normalizedClusterNode(node)
	if clusterNode == nil {
		return nil
	}

	ch.Cluster = &ClusterConfig{}

	if n := clusterNode.FindChild("cluster-id"); n != nil {
		if v := nodeVal(n); v != "" {
			if id, err := strconv.Atoi(v); err == nil {
				ch.Cluster.ClusterID = id
			}
		}
	}
	if n := clusterNode.FindChild("node"); n != nil {
		if v := nodeVal(n); v != "" {
			if id, err := strconv.Atoi(v); err == nil {
				ch.Cluster.NodeID = id
				// Mark the leaf as explicitly present so the node-identity
				// cross-check (#4185) can tell "node 0" from an absent leaf.
				ch.Cluster.NodeIDSet = true
			}
		}
	}
	if rcNode := clusterNode.FindChild("reth-count"); rcNode != nil {
		if v := nodeVal(rcNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ch.Cluster.RethCount = n
			}
		}
	}
	if n := clusterNode.FindChild("heartbeat-interval"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.HeartbeatInterval = ms
			}
		}
	}
	if n := clusterNode.FindChild("heartbeat-threshold"); n != nil {
		if v := nodeVal(n); v != "" {
			if cnt, err := strconv.Atoi(v); err == nil {
				ch.Cluster.HeartbeatThreshold = cnt
			}
		}
	}
	if clusterNode.FindChild("control-link-recovery") != nil {
		ch.Cluster.ControlLinkRecovery = true
	}
	// #7441: node-local strict session-auth posture. A bare flag leaf, like
	// control-link-recovery above; its runtime meaning is in pkg/cluster.
	if clusterNode.FindChild("strict-session-auth") != nil {
		ch.Cluster.StrictSessionAuth = true
	}
	// #4107: compile the cluster control-channel PSK into a Secret so it is
	// redacted on every render/log path (mirrors the IKE/interface/routing
	// Secret compile sites). nodeVal reads the raw leaf value; it is never
	// logged here.
	if n := clusterNode.FindChild("authentication-key"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlLinkAuthKey = Secret(v)
		}
	}
	// #6630: the additional ACCEPTED key that makes a rotation rolling. Same
	// Secret treatment; never signed with, only verified against.
	if n := clusterNode.FindChild("additional-authentication-key"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlLinkAuthKeyAlt = Secret(v)
		}
	}
	if n := clusterNode.FindChild("control-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlInterface = v
		}
	}
	if n := clusterNode.FindChild("peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.PeerAddress = v
		}
	}
	if n := clusterNode.FindChild("fabric-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.FabricInterface = v
		}
	}
	if n := clusterNode.FindChild("fabric-peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.FabricPeerAddress = v
		}
	}
	if n := clusterNode.FindChild("fabric1-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.Fabric1Interface = v
		}
	}
	if n := clusterNode.FindChild("fabric1-peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.Fabric1PeerAddress = v
		}
	}
	if clusterNode.FindChild("configuration-synchronize") != nil {
		ch.Cluster.ConfigSync = true
	}
	if clusterNode.FindChild("nat-state-synchronization") != nil {
		ch.Cluster.NATStateSync = true
	}
	if clusterNode.FindChild("ipsec-session-synchronization") != nil {
		ch.Cluster.IPsecSASync = true
	}
	if clusterNode.FindChild("dhcp-lease-synchronization") != nil {
		ch.Cluster.DHCPLeaseSync = true
	}
	if n := clusterNode.FindChild("reth-advertise-interval"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.RethAdvertiseInterval = ms
			}
		}
	}
	if clusterNode.FindChild("hitless-restart") != nil {
		ch.Cluster.HitlessRestart = true
	}
	if clusterNode.FindChild("no-reth-vrrp") != nil {
		ch.Cluster.NoRethVRRP = true
	}
	// Private RG election is the default — suppress RETH VRRP, elect over
	// control link only.  "no-private-rg-election" opts out (legacy VRRP).
	ch.Cluster.PrivateRGElection = true
	if clusterNode.FindChild("no-private-rg-election") != nil {
		ch.Cluster.PrivateRGElection = false
	}
	if n := clusterNode.FindChild("peer-fencing"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.PeerFencing = v
		}
	}
	if n := clusterNode.FindChild("takeover-hold-time"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.TakeoverHoldTime = ms
			}
		}
	}

	// #6543: redundancy-group instances are folded by CANONICAL id, not by
	// the spelling the operator wrote. `strconv.Atoi` maps `1`, `01`, `001`
	// and `+1` to the same int, and the AST keeps them as DISTINCT instances
	// (namedInstances yields one entry per node, and a repeated hierarchical
	// `redundancy-group 1 { ... }` block is two nodes as well). Appending one
	// record per instance therefore committed TWO *RedundancyGroup with
	// ID=1 — one carrying the operator's `node <n> priority <p>` map and one
	// with an EMPTY map.
	//
	// Everything downstream keys redundancy groups by the int id, so the
	// split was silently lossy: cluster.Manager.UpdateConfig's id-keyed
	// last-wins loop overwrote LocalPriority with the map-miss zero from
	// whichever record came second, so a node configured to win the election
	// at priority 200 ran RG 1 at priority 0. The #4880 priority-range gate
	// could not catch it either — it iterated the empty-map record and passed
	// vacuously, having nothing to range-check.
	//
	// Folding by canonical id yields exactly one record per id and replays
	// every instance's body into it through the same statement table, so the
	// merge is leaf-level last-wins — Junos `set` semantics — rather than a
	// whole record silently displacing another. First-appearance order of the
	// ids is preserved so the compiled slice stays deterministic.
	byID := make(map[int]*RedundancyGroup)
	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
		rgID := 0
		if n, err := strconv.Atoi(rgInst.name); err == nil {
			rgID = n
		}

		rg, ok := byID[rgID]
		if !ok {
			rg = &RedundancyGroup{
				ID:             rgID,
				NodePriorities: make(map[int]int),
			}
			byID[rgID] = rg
			ch.Cluster.RedundancyGroups = append(ch.Cluster.RedundancyGroups, rg)
		}

		// #6588: redundancyGroupBody, not .Children — the whole body may be
		// packed onto the instance's own Keys.
		// Dispatch through redundancyGroupStatements — the same table
		// isRedundancyGroupStatement is derived from, so the set of statements
		// compiled here and the set redundancyGroupBody splits a packed line at
		// are one thing rather than two that must be kept in step.
		for _, child := range redundancyGroupBody(rgInst.node) {
			if compile, ok := redundancyGroupStatements[child.Name()]; ok {
				compile(rg, child)
			}
		}
	}

	return nil
}

// monitorEntryNodes returns one node per MONITORED ENTRY carried by cfgNode —
// a redundancy-group `interface-monitor` statement or an ip-monitoring
// `inet` address list — across every spelling (#6588). `skip` is the number of
// leading Keys that name the statement itself rather than an entry.
//
// Two independent collapses have to be undone, and they compose:
//
//  1. PACKED statement. `interface-monitor ge-0/0/0 weight 255;` yields
//     Keys=["interface-monitor","ge-0/0/0","weight","255"] and NO children,
//     while `interface-monitor { ge-0/0/0 weight 255; }` yields
//     Keys=["interface-monitor"] with one child per entry. A flat `set` command
//     produces the CONTAINER shape. Reading only Children dropped the packed
//     spelling entirely — the original #6588 fail-open.
//
//     Tail and children are EITHER/OR here, not accumulated — the rule
//     namedInstances already applies. A tail means the statement IS one entry,
//     so its children are that entry's ATTRIBUTES:
//     `interface-monitor ge-0/0/0 { weight 255; }` must compile ONE monitor for
//     ge-0/0/0, not a second one named after its first attribute. (Accumulating
//     there mints a monitor for an interface literally called "weight".)
//
//  2. BRACKETED list. The lexer strips `[`/`]` (#2419), so
//     `interface-monitor [ ge-0/0/0 ge-0/0/1 ]` collapses N names onto ONE
//     node's Keys in EVERY spelling — packed, hierarchical container child, and
//     flat-set child alike. Taking only Keys[skip] compiled the FIRST name and
//     silently discarded the rest, which is the same failover fail-open one
//     monitor at a time. Each candidate's Keys are therefore SPLIT at entry
//     boundaries: a token that is not the `weight` keyword (or the value slot
//     reserved immediately after it) starts a new entry.
//
// The value slot reservation matters for the same reason it does in the #6524
// application walk: `weight` consumes exactly one following token even when
// that token spells something else, so a malformed `weight weight` cannot
// silently split into two entries. A malformed or duplicated weight is
// reported by validateMonitorWeightTokensAST, which derives its entries from
// THIS function so the gate and the compiler can never disagree.
//
// A candidate's children are attributes of every entry it produces. That is
// exact for the N==1 case (the only shape Junos renders) and lossless for the
// invented `[ a b ] { weight 255; }` — over-applying a weight adds demotion
// debt, the fail-SAFE direction, whereas dropping it silently is the failure
// mode this whole change exists to remove.
func monitorEntryNodes(cfgNode *Node, skip int) []*Node {
	var candidates []*Node
	if len(cfgNode.Keys) > skip {
		candidates = []*Node{{
			Keys:     cfgNode.Keys[skip:],
			Children: cfgNode.Children,
			IsLeaf:   cfgNode.IsLeaf,
			Line:     cfgNode.Line,
			Column:   cfgNode.Column,
		}}
	} else {
		candidates = cfgNode.Children
	}

	var entries []*Node
	for _, cand := range candidates {
		// Separate the entry NAMES from the `weight <n>` attribute tokens, then
		// give every name the candidate's full attribute run. The attributes are
		// candidate-scoped, NOT positional: a bracketed list with a trailing
		// inline weight applies that weight to every member, matching the
		// children-block spelling `[ a b ] { weight 255; }` and the fail-safe
		// rule documented above. Attaching it to the preceding name only (the
		// obvious reading, and what this function did when it was first written)
		// left `[ ge-0/0/0 ge-0/0/1 ] weight 255` with ge-0/0/0 at weight ZERO —
		// monitored but deducting nothing, so its link going down did not demote
		// the group. That was WORSE than master, which compiled one monitor at
		// 255 and dropped the rest.
		var names, attrs []string
		for i := 0; i < len(cand.Keys); {
			tok := cand.Keys[i]
			if tok == monitorWeightKeyword && len(names) > 0 {
				// Reserve the value slot: `weight` consumes exactly one
				// following token even when that token spells a name.
				attrs = append(attrs, tok)
				if i+1 < len(cand.Keys) {
					attrs = append(attrs, cand.Keys[i+1])
					i += 2
					continue
				}
				i++
				continue
			}
			names = append(names, tok)
			i++
		}
		for _, name := range names {
			keys := make([]string, 0, 1+len(attrs))
			keys = append(keys, name)
			keys = append(keys, attrs...)
			entries = append(entries, &Node{
				Keys:     keys,
				Children: cand.Children,
				IsLeaf:   cand.IsLeaf,
				Line:     cand.Line,
				Column:   cand.Column,
			})
		}
	}
	return entries
}

// monitorWeightKeyword is the only attribute a monitored entry carries. It is
// named so monitorEntryNodes and validateMonitorWeightTokensAST cannot drift
// apart from the compiler's reader.
const monitorWeightKeyword = "weight"

// monitorWeightTokens returns every `weight` VALUE an entry carries, across
// both locations the value can occupy (#6588):
//
//   - inline on the entry's own Keys — `ge-0/0/0 weight 255`
//   - as a child leaf              — `ge-0/0/0 { weight 255; }`
//
// Callers take the FIRST token, so the compiled weight is the same regardless
// of spelling. Before #6588 the two locations disagreed on which duplicate
// won: the inline scan overwrote (last wins) while FindChild returned the
// first, so `weight 100 weight 200` compiled to 200 inline but 100 in a block.
// Returning every token also lets the AST gate REJECT a duplicate rather than
// silently pick one, which is what makes the answer spelling-independent.
//
// A `weight` keyword with no following token yields an empty-string entry, so
// the gate reports it as malformed rather than the caller treating it as absent.
func monitorWeightTokens(entry *Node) []string {
	var out []string
	for i := 1; i < len(entry.Keys); i++ {
		if entry.Keys[i] != monitorWeightKeyword {
			continue
		}
		if i+1 < len(entry.Keys) {
			out = append(out, entry.Keys[i+1])
			i++
			continue
		}
		out = append(out, "")
	}
	for _, c := range entry.Children {
		if len(c.Keys) > 0 && c.Keys[0] == monitorWeightKeyword {
			out = append(out, nodeVal(c))
		}
	}
	return out
}

// packedStatementProps returns one node per PROPERTY carried by a statement
// whose body is a set of named properties rather than a list of monitored
// entries — `ip-monitoring` (#6588). `skip` names the statement itself and
// isProp reports whether a token opens a new property.
//
//	ip-monitoring { global-weight 255; family inet 10.0.1.1 weight 100; }
//	  -> Keys=["ip-monitoring"], one child per property (returned as-is)
//	ip-monitoring global-weight 255;
//	  -> Keys=["ip-monitoring","global-weight","255"], no children
//	     -> one synthetic property node ["global-weight","255"]
//
// This is deliberately NOT monitorEntryNodes: there every non-attribute token
// opens an entry, which would shred `global-weight 255` into two. Here the tail
// is split only at recognized property keywords, so a property's value tokens
// stay with it. Both a packed tail and real children are returned when both
// exist — properties are siblings, so nothing is lost either way (unlike a
// monitored entry, where children are that entry's attributes).
func packedStatementProps(cfgNode *Node, skip int, isProp func(string) bool) []*Node {
	return packedStatementPropsArity(cfgNode, skip, isProp, nil)
}

// packedStatementPropsArity is packedStatementProps with a VALUE-SLOT contract
// (#6665).
//
// THE DEFECT. The plain splitter applies isProp to every token in the tail with
// no positional state at all, so a registered keyword opens a new statement
// WHEREVER it appears — including where a value is expected. An interface whose
// name spells a statement keyword is therefore consumed as that statement:
//
//	packed:    redundancy-group 1 interface-monitor ip-monitoring weight 255;
//	             -> InterfaceMonitors=[]  IPMonitoring=&{}
//	container: redundancy-group 1 { interface-monitor ip-monitoring weight 255; }
//	             -> InterfaceMonitors=[{ip-monitoring 255}]  IPMonitoring=nil
//
// The monitor is dropped AND an unrelated statement is fabricated, and the two
// spellings of one config compile differently. `pkg/cluster` then ranges an
// empty InterfaceMonitors, so the redundancy group accrues no link-down debt and
// never demotes — the failure `assertSingleMonitor` exists to name.
//
// It is sticky: configstore persists the TREE and re-emits a packed leaf as the
// same packed line, so it survives `show configuration`, reboot and HA peer
// sync. Authored once, wrong forever.
//
// THE FIX IS #6658'S OWN SHAPE, one level up. monitorEntryNodes already reserves
// a value slot — "`weight` consumes exactly one following token even when that
// token spells a name" — for exactly this class. `arity` lifts that contract to
// the statement splitter: a keyword that takes an argument consumes the next
// token unconditionally, so the token in its value slot cannot re-arm the
// splitter.
//
// A nil arity is the pre-#6665 behaviour, kept for the ip-monitoring caller
// whose sub-keywords have no name-shaped value slot.
//
// WHAT IT DOES NOT RESOLVE, stated rather than implied: `interface-monitor` is
// variadic, so only its FIRST token is protected. `interface-monitor ge-0/0/0
// preempt;` still reads `preempt` as a statement — which is also what the
// container form does, so the two spellings agree, which is the property under
// repair. There is no local information that distinguishes "a second monitor
// named preempt" from "no more monitors, then preempt", and inventing one would
// break the multi-statement packing #6588 pins.
func packedStatementPropsArity(
	cfgNode *Node,
	skip int,
	isProp func(string) bool,
	arity func(string) int,
) []*Node {
	var props []*Node
	if len(cfgNode.Keys) > skip {
		var cur *Node
		pending := 0 // value tokens the open statement must still absorb
		for _, tok := range cfgNode.Keys[skip:] {
			if pending > 0 {
				pending--
				cur.Keys = append(cur.Keys, tok)
				continue
			}
			if cur == nil || isProp(tok) {
				cur = &Node{Keys: []string{tok}, Line: cfgNode.Line, Column: cfgNode.Column}
				props = append(props, cur)
				if arity != nil {
					pending = arity(tok)
				}
				continue
			}
			cur.Keys = append(cur.Keys, tok)
		}
	}
	return append(props, cfgNode.Children...)
}

// redundancyGroupStatementArity is how many tokens a redundancy-group statement
// consumes as its VALUE before the splitter may open another statement (#6665).
//
// Derived from the grammar the compilers actually read, and deliberately only
// for the statements whose value slot can hold a free-form identifier or a
// number. `preempt` and `strict-vip-ownership` take nothing, so the token after
// them genuinely does open a statement.
func redundancyGroupStatementArity(tok string) int {
	switch tok {
	case "interface-monitor":
		// `<ifname>` — the one free-form identifier slot in the whole stanza,
		// and therefore the only slot a keyword can be stolen out of.
		return 1
	case "node", "gratuitous-arp-count":
		// `<node-id>` / `<count>` — numeric, so a keyword here is already
		// rejected by the #5694 identity gate rather than silently stolen; the
		// reservation makes that a parse-time fact instead of a downstream one.
		return 1
	}
	return 0
}

// redundancyGroupBody returns the body statements of one `redundancy-group`
// instance across both spellings (#6588). It is the ONE-LEVEL-UP twin of the
// packing this file already undoes inside the body — and is itself one level
// BELOW the `chassis cluster` body, where the same shape dropped the entire
// cluster stanza (#6672, compiler_chassis_cluster_packed.go). The two splitters
// interact on exactly one token: `node` is both a cluster statement and a
// redundancy-group statement, so the cluster splitter must NOT re-arm on it
// inside a group's tail or this function never sees the priority it exists to
// preserve:
//
//	redundancy-group 1 { interface-monitor ge-0/0/0 weight 255; }
//	  -> Keys=["redundancy-group","1"], one child per statement
//	redundancy-group 1 interface-monitor ge-0/0/0 weight 255;
//	  -> Keys=["redundancy-group","1","interface-monitor","ge-0/0/0","weight","255"],
//	     NO children — the whole body is packed onto the instance's own Keys
//
// namedInstances resolves the instance NAME across both shapes (it reads
// Keys[1]), but hands back the node with the body still on Keys, so a caller
// that then walks `.Children` sees an EMPTY redundancy group. Every statement
// was silently dropped while `commit` succeeded: not just the monitors, but
// `node <id> priority <p>` — the election priority itself. The operator sets a
// priority, `show configuration` echoes it, and the cluster elects on defaults,
// so the WRONG NODE can hold the group. That is a superset of "the group never
// demotes".
//
// The split is at recognized redundancy-group statement keywords, so a tail
// carrying several statements (`node 0 priority 200 preempt;`) yields one node
// each rather than swallowing the trailing ones. Both a packed tail and real
// children are returned: RG statements are siblings, so nothing is lost if a
// config somehow carries both.
//
// Deliberately NOT fixed inside namedInstances itself. That helper has 130 call
// sites, and 24 of them already read the packed tail off `inst.node.Keys`
// themselves; synthesizing a child there double-feeds those readers. Measured,
// not assumed — making namedInstances synthesize breaks
// TestDHCPRelayOverrides_* (the override tokens get swallowed into Interfaces)
// and TestVRRPTrackInterface_KeysPackedDuplicateStrictReject (lenient
// first-wins yields an empty TrackInterface). See the #6588 PR body for the
// experiment. Other one-sided namedInstances callers are tracked separately.
func redundancyGroupBody(rgNode *Node) []*Node {
	// namedInstances returns TWO different node shapes, and the number of
	// leading identity Keys differs between them:
	//
	//   len(child.Keys) >= 2  -> the node ITSELF, Keys[0]=="redundancy-group",
	//                            Keys[1]==<id>                        -> skip 2
	//   otherwise             -> a `sub` CHILD of a bare `redundancy-group { }`
	//                            container, whose Keys[0] IS the <id>  -> skip 1
	//
	// Keys[0] is an exact discriminator: the first shape is always reached
	// through FindChildren("redundancy-group"), so its Keys[0] is that keyword;
	// the second is a child of that container, so its Keys[0] is the instance
	// name and never the keyword. Using a fixed skip of 2 swallowed the
	// STATEMENT keyword on the second shape and opened a node named after a
	// value, which no switch arm matches — the same silent-nothing outcome,
	// including the dropped election priority, that this function exists to fix.
	skip := 1
	if rgNode.Name() == "redundancy-group" {
		skip = 2
	}
	return packedStatementPropsArity(
		rgNode, skip, isRedundancyGroupStatement, redundancyGroupStatementArity)
}

// redundancyGroupStatements is the SINGLE SOURCE OF TRUTH for what a
// `redundancy-group` body may contain: it is both the compiler's dispatch
// table and the token set redundancyGroupBody splits a packed instance line
// at (#6588).
//
// The two MUST agree. A statement the compiler honours but the splitter does
// not know is not a loud failure — on a packed line carrying more than one
// statement its tokens are appended to whichever statement precedes it, so it
// silently does nothing, while the SAME statement alone on a line still works.
// A developer therefore sees it work, and ships the fold bug.
//
// This was previously a hand-written token list checked by a test that parsed
// compileChassis's source and extracted its `case "..."` literals. That guard
// passed while the statement was still dropped in three ways: a case on a
// named CONSTANT rather than a string literal (the idiom this very file uses
// for monitorWeightKeyword), a statement handled by a helper called outside
// the switch, and a nested switch inside a `default:` arm. Modelling another
// program's source text is the wrong tool; deriving both consumers from one
// table removes the divergence by construction instead.
//
// Adding a statement means adding an entry here, which registers it with the
// splitter in the same edit.
//
// Be precise about what that does and does not guarantee, because an overstated
// invariant is how the next person concludes they need not think about it. The
// invariant is "ALL dispatch goes through this table", and it is made natural
// rather than enforced. Two of the three routes above are now closed by
// construction: a named-constant KEY registers exactly like a literal one, and
// there is no switch left to nest another inside. The third is not. Compiling a
// statement from ad-hoc code beside the lookup — without an entry here — still
// re-opens the fold bug (verified, not assumed).
//
// What changed for that third route is which act is the natural one. With the
// switch, adding a `case` WAS the idiomatic way to add a statement, and it
// diverged silently. Now the idiomatic way is a table entry, which is correct by
// construction, and diverging means putting ad-hoc dispatch beside a five-line
// loop whose only other content is this lookup — obvious in review rather than
// invisible. Demoted, not eliminated; Go offers no construct that would
// eliminate it.
//
// FOURTH ROUTE, opposite direction — the splitter OVER-matches. All three routes
// above are the table under-covering what the compiler honours: a statement is
// compiled but not registered, so its tokens fold into the neighbour. There is
// one more of the other shape, and an earlier version of this comment enumerated
// "three" as if that were the whole space. The splitter matches a registered
// keyword wherever the token appears in the tail, including where the token is a
// VALUE rather than a statement keyword, so a value spelled like a statement is
// STOLEN and compiled as that statement:
//
//	packed:    redundancy-group 1 interface-monitor ip-monitoring weight 255;
//	             -> InterfaceMonitors=[]  IPMonitoring=&{GlobalWeight:0 GlobalThreshold:0 Targets:[]}
//	container: redundancy-group 1 { interface-monitor ip-monitoring weight 255; }
//	             -> InterfaceMonitors=[{ip-monitoring 255}]  IPMonitoring=nil
//
// The two spellings disagree — precisely what splitting the packed line exists
// to prevent. (Measured, not reasoned: both lines above were compiled at THIS
// head. The example deliberately uses ip-monitoring, which still reaches no
// gate. An earlier version of this comment used `preempt`, and that spelling is
// now REJECTED at commit by the arity gate added later in this same PR —
// "preempt: takes no argument but carries [weight 255]" — so quoting it here
// would show output the compiler no longer produces. `node` is likewise caught,
// by the #5694 identity gate. Re-measure this block if either gate moves;
// a stale "measured" claim is how the next reader concludes the analysis was
// already done and stops checking.)
//
// FIXED in #6665, by exactly the move the paragraph that used to sit here said
// would be needed: the splitter is now position-aware. A statement that takes an
// argument reserves its value slot (redundancyGroupStatementArity), so the token
// in that slot cannot re-arm the splitter — the same "reserve the value slot"
// contract monitorEntryNodes already applied one level down for `weight`.
//
// Two claims that used to live here were wrong and are corrected rather than
// deleted, because both were load-bearing for the decision to defer:
//
//   - "no legal Junos interface name collides with any keyword". The reachability
//     argument was "no operator would do this", not "the system prevents it" —
//     and the system does NOT prevent it. `chassis device-map interface
//     <logical-name>` is gated by ValidateDeviceMapLogicalName
//     (schema_validators_devicemap.go), which accepts any non-empty,
//     whitespace-free, dot-free [a-zA-Z0-9-/] string. All six registered
//     keywords pass it. The predicate the old comment said did not exist does.
//
//   - "there is deliberately NO test asserting the divergence: it would pin the
//     wrong answer as correct". True while the divergence stood; the test that
//     belongs here asserts the packed and container spellings AGREE, using the
//     container form as the oracle, which pins the RIGHT answer without
//     hand-writing an expectation. That is
//     TestPackedRGDoesNotStealAKeywordFromTheValueSlot_6665.
//
// The residual, stated rather than implied: `interface-monitor` is variadic, so
// only its FIRST token is protected. `interface-monitor ge-0/0/0 preempt;` still
// reads `preempt` as a statement — and so does the container form, so the two
// spellings agree, which is the property under repair. No local information
// distinguishes "a second monitor named preempt" from "no more monitors, then
// preempt", and inventing one would break the multi-statement packing
// TestRedundancyGroupStatementsSurvivePackedLine_6588 pins.
var redundancyGroupStatements = map[string]func(rg *RedundancyGroup, child *Node){
	"node":                 compileRGNodePriority,
	"gratuitous-arp-count": compileRGGratuitousARPCount,
	"preempt":              compileRGPreempt,
	"strict-vip-ownership": compileRGStrictVIPOwnership,
	"interface-monitor":    compileRGInterfaceMonitors,
	"ip-monitoring":        compileRGIPMonitoring,
}

// isRedundancyGroupStatement reports whether tok opens a statement in a
// `redundancy-group` body. Derived from the dispatch table, so it can never
// fall behind what compileChassis actually compiles.
func isRedundancyGroupStatement(tok string) bool {
	_, ok := redundancyGroupStatements[tok]
	return ok
}

// compileRGNodePriority compiles a `node` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGNodePriority(rg *RedundancyGroup, child *Node) {
	// node <id> priority <value>
	nodeID := 0
	if v := nodeVal(child); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			nodeID = n
		}
	}
	// Look for "priority" in inline keys or children
	for i := 2; i < len(child.Keys)-1; i++ {
		if child.Keys[i] == "priority" {
			if n, err := strconv.Atoi(child.Keys[i+1]); err == nil {
				rg.NodePriorities[nodeID] = n
			}
		}
	}
	if priNode := child.FindChild("priority"); priNode != nil {
		if v := nodeVal(priNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				rg.NodePriorities[nodeID] = n
			}
		}
	}
}

// compileRGGratuitousARPCount compiles a `gratuitous-arp-count` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGGratuitousARPCount(rg *RedundancyGroup, child *Node) {
	if v := nodeVal(child); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rg.GratuitousARPCount = n
		}
	}
}

// compileRGPreempt compiles a `preempt` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGPreempt(rg *RedundancyGroup, child *Node) {
	rg.Preempt = true
}

// compileRGStrictVIPOwnership compiles a `strict-vip-ownership` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGStrictVIPOwnership(rg *RedundancyGroup, child *Node) {
	rg.StrictVIPOwnership = true
}

// compileRGInterfaceMonitors compiles a `interface-monitor` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGInterfaceMonitors(rg *RedundancyGroup, child *Node) {
	// monitorEntryNodes (#6588): the packed one-liner
	// `interface-monitor ge-0/0/0 weight 255;` carries the monitor
	// on the statement's OWN Keys and has no children at all, and a
	// bracketed `[ ge-0/0/0 ge-0/0/1 ]` collapses N monitors onto
	// one node's Keys in EVERY spelling.
	for _, ifChild := range monitorEntryNodes(child, 1) {
		im := &InterfaceMonitor{
			Interface: ifChild.Name(),
		}
		// monitorWeightTokens reads both value locations
		// (`ge-0/0/0 weight 255` and `ge-0/0/0 { weight 255; }`)
		// and is FIRST-WINS, so the compiled weight no longer
		// depends on the spelling. A malformed or duplicated
		// weight is rejected/warned by
		// validateMonitorWeightTokensAST; here it leaves the
		// pre-existing 0 default.
		if toks := monitorWeightTokens(ifChild); len(toks) > 0 {
			if n, err := strconv.Atoi(toks[0]); err == nil {
				im.Weight = n
			}
		}
		rg.InterfaceMonitors = append(rg.InterfaceMonitors, im)
	}
}

// compileRGIPMonitoring compiles a `ip-monitoring` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGIPMonitoring(rg *RedundancyGroup, child *Node) {
	ipm := &IPMonitoring{}
	// #6588: ip-monitoring installs redundancy-group demotion debt
	// through the same election path as interface-monitor, and it
	// packs the same way — `ip-monitoring global-weight 255;` and
	// `ip-monitoring family inet 10.0.1.1 weight 100;` are leaves
	// with no children.
	ipmEntries := packedStatementProps(child, 1, isIPMonitoringProp)
	if gwNode := findNamedNode(ipmEntries, "global-weight"); gwNode != nil {
		if v := nodeVal(gwNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ipm.GlobalWeight = n
			}
		}
	}
	if gtNode := findNamedNode(ipmEntries, "global-threshold"); gtNode != nil {
		if v := nodeVal(gtNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ipm.GlobalThreshold = n
			}
		}
	}
	for _, familyNode := range ipmEntries {
		if familyNode.Name() != "family" {
			continue
		}
		// Compound key "family inet" vs nested family { inet { } }.
		// inetSkip is how many of inetNode's leading Keys name the
		// node itself rather than a monitored address, so a packed
		// target (`family inet 10.0.1.1 weight 100;`) is unpacked
		// from the right offset. Shared with the #6588 weight gate.
		inetNode, inetSkip := ipMonitoringInetNode(familyNode)
		if inetNode == nil {
			continue
		}
		for _, addrChild := range monitorEntryNodes(inetNode, inetSkip) {
			target := &IPMonitorTarget{
				Address: addrChild.Name(),
			}
			// Same FIRST-WINS dual-location weight read as the
			// interface-monitor arm above.
			if toks := monitorWeightTokens(addrChild); len(toks) > 0 {
				if n, err := strconv.Atoi(toks[0]); err == nil {
					target.Weight = n
				}
			}
			ipm.Targets = append(ipm.Targets, target)
		}
	}
	rg.IPMonitoring = ipm
}

// isIPMonitoringProp reports whether tok opens an `ip-monitoring` property.
func isIPMonitoringProp(tok string) bool {
	switch tok {
	case "global-weight", "global-threshold", "family":
		return true
	}
	return false
}

// ipMonitoringGlobalTokens returns every VALUE carried by the named
// `ip-monitoring` global property (`global-weight` / `global-threshold`) in a
// packedStatementProps result, in source order.
//
// This is the globals' counterpart to monitorWeightTokens, and exists for the
// same reason (#6588): compileRGIPMonitoring reads a global with
// findNamedNode + nodeVal, which is FIRST-WINS and silently leaves the 0
// default when the value is missing or fails Atoi. A malformed or duplicated
// global is therefore indistinguishable from `global-weight 0` in the compiled
// struct, so it has to be caught on the AST — and the gate must read the same
// token the compiler does or the two can disagree about which value won.
//
// That correspondence is exact rather than parallel: over the same props slice
// this walks the same nodes with the same name predicate in the same order and
// reads them with the same nodeVal, so
//
//	nodeVal(findNamedNode(props, name)) == ipMonitoringGlobalTokens(props, name)[0]
//
// whenever the property is present at all. The gate rejects len > 1, so where
// the compiler's first-wins pick is observable there is exactly one token and
// the two readers cannot pick differently. Pinned by
// TestIPMonitoringGlobalTokensMatchesCompilerRead_6588.
func ipMonitoringGlobalTokens(props []*Node, name string) []string {
	var out []string
	for _, n := range props {
		if len(n.Keys) > 0 && n.Keys[0] == name {
			out = append(out, nodeVal(n))
		}
	}
	return out
}

// findNamedNode returns the first node in nodes whose first key is name — the
// slice equivalent of Node.FindChild, for callers that must search a
// packedStatementProps result rather than a node's raw Children.
func findNamedNode(nodes []*Node, name string) *Node {
	for _, n := range nodes {
		if len(n.Keys) > 0 && n.Keys[0] == name {
			return n
		}
	}
	return nil
}

// validateBackupRouterDst (#2911, extended by #4808) rejects a `system
// backup-router` whose next-hop or EXPLICIT `destination` is malformed, or
// whose destination is a different address family than the next-hop.
//
// Background: renderBackupRouter (pkg/frr) emits a fallback default route
//
//	<ip|ipv6> route <destination> <next-hop> 250
//
// where the route-prefix keyword is keyed on the next-hop family (#2907 /
// #2891). Both tokens are stored as raw strings by compileSystem's
// `"backup-router"` case with no IP-format validation at all (#4808) — a
// syntactically malformed next-hop ("192.168.1.x") or destination
// ("10.0.0.0/99") sails through commit uncaught and is rendered directly
// into frr.conf. An explicit destination of the WRONG family renders a
// mismatched-family static instead — e.g. `backup-router 2001:db8::1` +
// `destination 0.0.0.0/0` → `ipv6 route 0.0.0.0/0 2001:db8::1 250` (#2911).
// FRR rejects a malformed OR mismatched-family static route, and
// frr-reload fails the ENTIRE static config load on that one bad line, not
// just the offending route. That is exactly the breakage #2907 set out to
// prevent for the empty-destination case, so every way to reach a bad
// rendered line must be caught.
//
// Checks, in order:
//  1. next-hop must parse as an IP address at all (#4808).
//  2. an EXPLICIT destination must parse as a CIDR prefix at all (#4808) —
//     natCIDRIPPart/natAddrFamily below only look at the address portion of
//     a CIDR string, so they alone would accept a bad mask like "/99";
//     net.ParseCIDR validates the whole token.
//  3. an EXPLICIT destination of a different address family than the
//     next-hop is rejected (#2911), once both sides are known to parse.
//
// Only an EXPLICIT destination is format/family checked. An empty
// destination is left to #2907's next-hop-family-aware default (v6
// next-hop → ::/0, v4 → 0.0.0.0/0) and is never malformed or a mismatch.
//
// Family classification reuses natAddrFamily / natCIDRIPPart so the colon
// test (IPv4-mapped IPv6 literal → v6) matches the rest of the compiler.
//
// Strict (commit / commit-check): hard-reject on the first failing check,
// naming the offending value. Lenient (load / peer-sync): warn (accumulating
// across all applicable checks) so an already-persisted or peer-synced
// config an older binary accepted still boots (#1960 fail-closed-on-load
// class).
func validateBackupRouterDst(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	nh := cfg.System.BackupRouter
	dst := cfg.System.BackupRouterDst
	if nh == "" {
		// No backup-router configured — nothing to validate.
		return nil, nil
	}

	var warnings []string

	// #4808: next-hop must be a well-formed IP address. Rendered verbatim as
	// the FRR static route's next-hop; a malformed value fails the entire
	// static config load (frr-reload), not just this route.
	if net.ParseIP(nh) == nil {
		msg := fmt.Sprintf(
			"system backup-router %s: not a valid IP address; FRR rejects a "+
				"malformed next-hop, which fails the entire static config "+
				"load (frr-reload)", nh)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg+" (ignored: backup-router default route not installed until corrected)")
	}

	if dst == "" {
		// #2907's next-hop-family-aware default applies; never malformed or
		// a mismatch.
		return warnings, nil
	}

	// #4808: an explicit destination must be a well-formed CIDR prefix.
	// net.ParseCIDR validates the mask too (natCIDRIPPart below only takes
	// the address portion, so "10.0.0.0/99" would otherwise slip through).
	if _, _, err := net.ParseCIDR(dst); err != nil {
		msg := fmt.Sprintf(
			"system backup-router destination %s: not a valid CIDR prefix; "+
				"FRR rejects a malformed destination, which fails the entire "+
				"static config load (frr-reload)", dst)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg+" (ignored: backup-router default route not installed until corrected)")
	}

	nhFam := natAddrFamily(nh)
	dstFam := natAddrFamily(natCIDRIPPart(dst))
	// One side did not parse as an IP at all — already reported above (or
	// pre-existing address-book-name handling that is not this validator's
	// concern); skip the family comparison, it would be meaningless.
	if nhFam == "" || dstFam == "" {
		return warnings, nil
	}
	if nhFam == dstFam {
		return warnings, nil
	}
	msg := fmt.Sprintf(
		"system backup-router %s destination %s: destination family (%s) "+
			"does not match next-hop family (%s); FRR rejects a "+
			"mismatched-family static route, which fails the entire static "+
			"config load (frr-reload)",
		nh, dst, dstFam, nhFam)
	if lenient {
		return append(warnings, msg+" (ignored: backup-router default route not installed until corrected)"), nil
	}
	return nil, fmt.Errorf("%s", msg)
}

// ntpServerModifierNames returns the modifier keywords modeled as children of
// the `system ntp server` leaf in setSchema (#7132).
//
// This REPLACES ntpServerOptionArgs, a hand-written keyword->argcount table that
// existed only because the schema could not express "a value leaf that also has
// modifiers". It can: `valueList: true` plus modifier children is the #3872
// shape that static `route next-hop` already uses. The table was a second source
// of truth for the same grammar, and every future leaf in this shape would have
// grown its own copy.
func ntpServerModifierNames() map[string]int {
	out := map[string]int{}
	sys, ok := setSchema.children["system"]
	if !ok || sys == nil {
		return out
	}
	ntp, ok := sys.children["ntp"]
	if !ok || ntp == nil {
		return out
	}
	server, ok := ntp.children["server"]
	if !ok || server == nil {
		return out
	}
	for name, child := range server.children {
		// The ARGUMENT COUNT matters as much as the name, and losing it was a
		// real regression caught by Test_6690_NTPServerOptionTokensAreNotServers:
		// the HIERARCHICAL spelling puts `server 1.1.1.1 key 5` on ONE node's
		// Keys, so skipping only the keyword leaves `5` to be read as a second
		// server. That argcount is exactly what the retired ntpServerOptionArgs
		// table carried — it now comes from the schema's own `args`, which is the
		// point of the retirement: one source of truth, not two.
		n := 0
		if child != nil {
			n = child.args
		}
		out[name] = n
	}
	return out
}

// ntpServerValues returns the NTP server addresses carried by one `server` node,
// and the per-server modifiers attached to them (#7132).
//
// Since #7132 a modifier is a schema-modeled CHILD, so the two are separable in
// the AST: `server 1.1.1.1 prefer` files Keys=["server","1.1.1.1"] with a child
// ["prefer"], while `server [ 1.1.1.1 2.2.2.2 ]` still collapses both addresses
// onto Keys. Before that they were byte-identical — Keys=["server",<tok>,<tok>]
// either way — which is why a keyword table was the only available remedy.
//
// The modifiers attach to the LAST address on the node, matching Junos: the
// modifier follows the server it qualifies.
func ntpServerValues(n *Node) ([]string, map[string]NTPServerOption) {
	if n == nil {
		return nil, nil
	}
	modifiers := ntpServerModifierNames()
	var servers []string
	opts := map[string]NTPServerOption{}
	// The COMPACT spelling puts a modifier and its argument on the parent's Keys
	// (`server 1.1.1.1 key 5;`), while the block spelling files them as a child
	// (`server 1.1.1.1 { key 5; }`). Both must produce the same compiled config —
	// that equivalence is the #2419 contract, and TestCompactBlockEquivalence-
	// Inventory2419 caught this reader dropping the compact value when it merely
	// SKIPPED modifiers here instead of capturing them.
	keyTokens := n.Keys[1:]
	for i := 0; i < len(keyTokens); i++ {
		tok := keyTokens[i]
		if nargs, isMod := modifiers[tok]; isMod {
			arg := ""
			if nargs > 0 && i+1 < len(keyTokens) {
				arg = keyTokens[i+1]
			}
			i += nargs
			if len(servers) > 0 {
				target := servers[len(servers)-1]
				cur := opts[target]
				applyNTPServerModifier(&cur, tok, arg)
				opts[target] = cur
			}
			continue
		}
		if tok != "" {
			servers = append(servers, tok)
		}
	}
	// The child walk runs UNCONDITIONALLY, before any modifier is attached.
	//
	// It used to early-return when Keys carried no server, which silently dropped
	// the #6689 nested-BLOCK spelling — `server { 1.1.1.1; 2.2.2.2; }` files both
	// addresses as CHILDREN and leaves Keys with just "server", so the early
	// return discarded every server on that shape. Caught by
	// Test_6690_NTPServerEveryHierarchicalSpelling. The block is the third shape
	// docs/config-schema.md warns about, and it is exactly the one an
	// early-return on Keys cannot see.
	var mods []*Node
	for _, child := range n.Children {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		if _, isMod := modifiers[child.Keys[0]]; isMod {
			mods = append(mods, child)
			continue
		}
		// A bracket-list member or a nested-block server, not a modifier.
		servers = append(servers, child.Keys...)
	}
	if len(servers) == 0 {
		return servers, nil
	}
	target := servers[len(servers)-1]
	cur := opts[target]
	touched := false
	for _, child := range mods {
		name := child.Keys[0]
		touched = true
		arg := ""
		if len(child.Keys) > 1 {
			arg = child.Keys[1]
		}
		applyNTPServerModifier(&cur, name, arg)
	}
	// `touched` records only whether a CHILD modifier was applied to `cur`, so
	// it must not gate the return: the COMPACT spelling files its modifiers on
	// the parent's Keys, and the loop above has already written them into
	// `opts`. Returning nil here because no CHILD was seen discarded every
	// compact-spelled modifier — which is exactly the #2419 divergence this
	// reader was changed to close, reappearing one line below the fix for it.
	//
	// Write `cur` back only when a child actually contributed, so a plain
	// `server 1.1.1.1` with no modifiers at all still yields nil rather than a
	// map holding an all-zero option.
	if touched {
		opts[target] = cur
	}
	if len(opts) == 0 {
		return servers, nil
	}
	return servers, opts
}

// archiveSite is one authored `system archival configuration archive-sites`
// entry: the destination URL, plus whether the operator attached a `password`
// modifier to it.
type archiveSite struct {
	url         string
	hasPassword bool
}

// archiveSiteEntries returns EVERY archive site an `archive-sites` node carries,
// across all four AST shapes the parsers produce (#6692, the #2419 dual-shape
// class). Measured shapes:
//
//	archive-sites [ a b ];                → Keys=["archive-sites","a","b"]
//	archive-sites a password S;           → Keys=["archive-sites","a","password","S"]
//	archive-sites a { password S; }       → Keys=["archive-sites","a"], child ["password","S"]
//	archive-sites { a password S; b; }    → Keys=["archive-sites"], one child per site
//	archive-sites { a { password S; } }   → Keys=["archive-sites"], child "a" with a password child
//
// The pre-#6692 reader took Keys[1] and stopped, so a bracketed list compiled
// its FIRST member only — and because the #4589 leading-dash gate ran on that
// one member, every dropped member also ESCAPED the gate and committed clean.
// The escape was inert while the value was dropped; it stops being inert the
// moment the read widens, which is why the caller now runs the leading-dash
// check over every entry this function returns.
//
// `password` is a MODIFIER, not a value (#6673: a widened read must not PROMOTE
// a token the old reader discarded). It binds to the site immediately preceding
// it and its secret operand is consumed with it, so neither the keyword nor the
// secret can ever land in ArchiveSites and be handed to `scp` as a destination.
// A trailing `password` with no operand still marks the preceding site rather
// than becoming one.
//
// An EMPTY value token is preserved as an entry: the pre-#6692 reader appended
// Keys[1] unconditionally, so `archive-sites ""` compiled one empty site, and
// silently dropping it here would change behaviour on an axis this change is
// not about.
func archiveSiteEntries(n *Node) []archiveSite {
	if n == nil {
		return nil
	}
	// parseTail walks a token stream whose entries are `<url> [password
	// <secret>]` groups. toks excludes the leaf keyword.
	parseTail := func(toks []string) []archiveSite {
		var out []archiveSite
		for i := 0; i < len(toks); i++ {
			if toks[i] == "password" {
				if len(out) > 0 {
					out[len(out)-1].hasPassword = true
				}
				i++ // consume the secret operand, if one was authored
				continue
			}
			out = append(out, archiveSite{url: toks[i]})
		}
		return out
	}
	markLast := func(sites []archiveSite, node *Node) {
		if len(sites) > 0 && node.FindChild("password") != nil {
			sites[len(sites)-1].hasPassword = true
		}
	}

	// Value-on-Keys shapes: the sites ride this node's own tail. Any CHILD here
	// is a modifier block for the last authored site (`archive-sites a {
	// password S; }`), never an additional site.
	if len(n.Keys) > 1 {
		sites := parseTail(n.Keys[1:])
		markLast(sites, n)
		return sites
	}

	// Block shape: one child per site, each child's own Keys carrying that
	// site's `<url> [password <secret>]` tail.
	var out []archiveSite
	for _, child := range n.Children {
		sites := parseTail(child.Keys)
		markLast(sites, child)
		out = append(out, sites...)
	}
	return out
}

// applyNTPServerModifier records one per-server modifier (#7132). Shared by the
// COMPACT (parent Keys) and BLOCK (child node) spellings so the two cannot
// diverge — the divergence being exactly what #2419 is about.
func applyNTPServerModifier(opt *NTPServerOption, name, arg string) {
	switch name {
	case "prefer":
		opt.Prefer = true
	case "key":
		if v, err := strconv.Atoi(arg); err == nil {
			opt.Key = v
		}
	case "version":
		if v, err := strconv.Atoi(arg); err == nil {
			opt.Version = v
		}
	case "routing-instance":
		opt.RoutingInstance = arg
	}
}
