package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
)

const sharedUMEMPhase0ArtifactMaxBytes = 16 << 20

func compileSystem(node *Node, sys *SystemConfig) error {
	for _, child := range node.Children {
		if child.Name() == "dataplane-type" && len(child.Keys) >= 2 {
			sys.DataplaneType = child.Keys[1]
			break
		}
	}
	for _, child := range node.Children {
		switch child.Name() {
		case "host-name":
			if len(child.Keys) >= 2 {
				sys.HostName = child.Keys[1]
			}
		case "dataplane-type":
			if len(child.Keys) >= 2 {
				sys.DataplaneType = child.Keys[1]
			}
		case "domain-name":
			if len(child.Keys) >= 2 {
				sys.DomainName = child.Keys[1]
			}
		case "domain-search":
			// Block: domain-search { dom1; dom2; } or leaf: domain-search dom
			if len(child.Keys) >= 2 {
				sys.DomainSearch = append(sys.DomainSearch, child.Keys[1])
			}
			for _, d := range child.Children {
				if len(d.Keys) >= 1 {
					sys.DomainSearch = append(sys.DomainSearch, d.Keys[0])
				}
			}
		case "time-zone":
			if len(child.Keys) >= 2 {
				sys.TimeZone = child.Keys[1]
			}
		case "no-redirects":
			sys.NoRedirects = true
		case "name-server":
			// Block: name-server { IP1; IP2; } or leaf: name-server IP
			if len(child.Keys) >= 2 {
				sys.NameServers = append(sys.NameServers, child.Keys[1])
			}
			for _, ns := range child.Children {
				if len(ns.Keys) >= 1 {
					sys.NameServers = append(sys.NameServers, ns.Keys[0])
				}
			}
		case "ntp":
			for _, ntpChild := range child.FindChildren("server") {
				if len(ntpChild.Keys) >= 2 {
					sys.NTPServers = append(sys.NTPServers, ntpChild.Keys[1])
				}
			}
			if thNode := child.FindChild("threshold"); thNode != nil {
				if v := nodeVal(thNode); v != "" {
					sys.NTPThreshold, _ = strconv.Atoi(v)
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
			sys.Login = &LoginConfig{}
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := &LoginUser{Name: userInst.name}
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
						for _, authChild := range prop.Children {
							switch authChild.Name() {
							case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
								if v := nodeVal(authChild); v != "" {
									user.SSHKeys = append(user.SSHKeys, v)
								}
							}
						}
					}
				}
				sys.Login.Users = append(sys.Login.Users, user)
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
					sys.RootAuthentication.EncryptedPassword = nodeVal(prop)
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
						sys.Archival.TransferInterval, _ = strconv.Atoi(v)
					}
				}
				for _, asNode := range cfgNode.FindChildren("archive-sites") {
					// Flat-set form (`set ... archive-sites <url>
					// [password <s>]`): schema consumes the URL as a
					// trailing key, so asNode.Keys = ["archive-sites",
					// URL]. Password lands either in subsequent keys
					// (leaf form) or as a child leaf (Keys=["password",
					// "$9$..."]).
					if len(asNode.Keys) >= 2 {
						url := asNode.Keys[1]
						sys.Archival.ArchiveSites = append(sys.Archival.ArchiveSites, url)
						for i := 2; i+1 < len(asNode.Keys); i++ {
							if asNode.Keys[i] == "password" {
								sys.Archival.ArchiveSitesWithPassword = append(
									sys.Archival.ArchiveSitesWithPassword, url)
								break
							}
						}
						for _, child := range asNode.Children {
							if child.IsLeaf && len(child.Keys) >= 1 && child.Keys[0] == "password" {
								sys.Archival.ArchiveSitesWithPassword = append(
									sys.Archival.ArchiveSitesWithPassword, url)
								break
							}
						}
						continue
					}
					// Hierarchical form (archive-sites { <url> { password
					// "$9$..."; } } or archive-sites { <url> password
					// "$9$..."; }): each site is a child node whose first
					// key is the URL.
					for _, site := range asNode.Children {
						if len(site.Keys) >= 1 {
							url := site.Keys[0]
							sys.Archival.ArchiveSites = append(sys.Archival.ArchiveSites, url)
							if site.FindChild("password") != nil {
								sys.Archival.ArchiveSitesWithPassword = append(
									sys.Archival.ArchiveSitesWithPassword, url)
							} else {
								for i := 1; i+1 < len(site.Keys); i++ {
									if site.Keys[i] == "password" {
										sys.Archival.ArchiveSitesWithPassword = append(
											sys.Archival.ArchiveSitesWithPassword, url)
										break
									}
								}
							}
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
			switch sys.DataplaneType {
			case "userspace":
				if sys.UserspaceDataplane == nil {
					sys.UserspaceDataplane = &UserspaceConfig{}
				}
				if err := compileUserspaceDataplane(child, sys.UserspaceDataplane); err != nil {
					return err
				}
			default:
				if sys.DPDKDataplane == nil {
					sys.DPDKDataplane = &DPDKConfig{}
				}
				if err := compileDPDKDataplane(child, sys.DPDKDataplane); err != nil {
					return err
				}
			}
		case "syslog":
			sys.Syslog = &SystemSyslogConfig{}
			for _, slInst := range namedInstances(child.FindChildren("host")) {
				host := &SyslogHostConfig{Address: slInst.name}
				for _, prop := range slInst.node.Children {
					switch prop.Name() {
					case "allow-duplicates":
						host.AllowDuplicates = true
					default:
						if len(prop.Keys) >= 2 {
							host.Facilities = append(host.Facilities, SyslogFacility{
								Facility: prop.Keys[0],
								Severity: prop.Keys[1],
							})
						}
					}
				}
				sys.Syslog.Hosts = append(sys.Syslog.Hosts, host)
			}
			for _, fileInst := range namedInstances(child.FindChildren("file")) {
				file := &SyslogFileConfig{Name: fileInst.name}
				for _, prop := range fileInst.node.Children {
					if len(prop.Keys) >= 2 {
						file.Facility = prop.Keys[0]
						file.Severity = prop.Keys[1]
					}
				}
				sys.Syslog.Files = append(sys.Syslog.Files, file)
			}
			// Parse user destinations: user * { any emergency; }
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := &SyslogUserConfig{User: userInst.name}
				for _, prop := range userInst.node.Children {
					if len(prop.Keys) >= 2 {
						user.Facility = prop.Keys[0]
						user.Severity = prop.Keys[1]
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
							Password: nodeVal(pwNode),
						})
					}
				}
				for _, ch := range authNode.FindChildren("api-key") {
					auth.APIKeys = append(auth.APIKeys, nodeVal(ch))
				}
				sys.Services.WebManagement.APIAuth = auth
			}
		}
	}

	snmpNode := node.FindChild("snmp")
	if snmpNode != nil {
		if err := compileSNMP(snmpNode, sys); err != nil {
			return err
		}
	}

	return nil
}

func hasDNSProxyChild(node *Node) bool {
	for _, child := range node.Children {
		if child.Name() == "dns-proxy" {
			return true
		}
	}
	return false
}

func compileDPDKDataplane(node *Node, cfg *DPDKConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "cores":
			if v := nodeVal(child); v != "" {
				cfg.Cores = v
			}
		case "memory":
			if v := nodeVal(child); v != "" {
				cfg.Memory, _ = strconv.Atoi(v)
			}
		case "socket-mem":
			if v := nodeVal(child); v != "" {
				cfg.SocketMem = v
			}
		case "rx-mode":
			// rx-mode can be a simple value ("polling") or a block ("adaptive { ... }")
			if v := nodeVal(child); v != "" {
				cfg.RXMode = v
			}
			if cfg.RXMode == "adaptive" {
				cfg.AdaptiveConfig = &DPDKAdaptiveConfig{}
				for _, ac := range child.Children {
					switch ac.Name() {
					case "idle-threshold":
						if v := nodeVal(ac); v != "" {
							cfg.AdaptiveConfig.IdleThreshold, _ = strconv.Atoi(v)
						}
					case "resume-threshold":
						if v := nodeVal(ac); v != "" {
							cfg.AdaptiveConfig.ResumeThreshold, _ = strconv.Atoi(v)
						}
					case "sleep-timeout":
						if v := nodeVal(ac); v != "" {
							cfg.AdaptiveConfig.SleepTimeout, _ = strconv.Atoi(v)
						}
					}
				}
			}
		case "ports":
			for _, portChild := range child.Children {
				port := DPDKPort{PCIAddress: portChild.Name()}
				for _, prop := range portChild.Children {
					switch prop.Name() {
					case "interface":
						port.Interface = nodeVal(prop)
					case "rx-mode":
						port.RXMode = nodeVal(prop)
					case "cores":
						port.Cores = nodeVal(prop)
					}
				}
				cfg.Ports = append(cfg.Ports, port)
			}
		}
	}
	return nil
}

func compileUserspaceDataplane(node *Node, cfg *UserspaceConfig) error {
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
				if err := compileUserspaceDataplane(synthParent, cfg); err != nil {
					return err
				}
			}
		case "binary":
			cfg.Binary = nodeVal(child)
		case "control-socket":
			cfg.ControlSocket = nodeVal(child)
		case "state-file":
			cfg.StateFile = nodeVal(child)
		case "workers":
			if v := nodeVal(child); v != "" {
				cfg.Workers, _ = strconv.Atoi(v)
			}
		case "ring-entries":
			if v := nodeVal(child); v != "" {
				cfg.RingEntries, _ = strconv.Atoi(v)
			}
		case "poll-mode":
			if v := nodeVal(child); v == "interrupt" || v == "busy-poll" {
				cfg.PollMode = v
			}
		case "shared-umem":
			shared, err := compileSharedUMEMConfig(child)
			if err != nil {
				return err
			}
			cfg.SharedUMEM = shared
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
				cfg.NetdevBudget, _ = strconv.Atoi(v)
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
						cfg.CoalescenceRXUsecs, _ = strconv.Atoi(v)
					}
				case "tx-usecs":
					if v := nodeVal(sub); v != "" {
						cfg.CoalescenceTXUsecs, _ = strconv.Atoi(v)
					}
				}
			}
		}
	}
	return nil
}

func compileSharedUMEMConfig(node *Node) (*SharedUMEMConfig, error) {
	cfg := &SharedUMEMConfig{}
	for _, child := range node.Children {
		switch child.Name() {
		case "mode":
			cfg.Mode = nodeVal(child)
		case "interface":
			if v := nodeVal(child); v != "" {
				cfg.Interfaces = append(cfg.Interfaces, LinuxIfName(v))
			}
		case "phase0-artifact-file", "artifact-file":
			path := nodeVal(child)
			if path == "" {
				continue
			}
			artifact, err := readSharedUMEMPhase0Artifact(path)
			if err != nil {
				return nil, err
			}
			cfg.Phase0Artifact = artifact
		}
	}
	return cfg, nil
}

func readSharedUMEMPhase0Artifact(path string) (map[string]interface{}, error) {
	file, err := os.Open(path)
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

func normalizeSharedUMEMArtifactInterfaces(artifact map[string]interface{}) error {
	for _, key := range []string{"selected_interfaces", "interfaces"} {
		normalizeSharedUMEMArtifactInterfaceArray(artifact, key)
	}
	for _, key := range []string{
		"driver",
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

func normalizeSharedUMEMArtifactInterfaceArray(artifact map[string]interface{}, key string) {
	values, ok := artifact[key].([]interface{})
	if !ok {
		return
	}
	for i, value := range values {
		name, ok := value.(string)
		if !ok {
			continue
		}
		values[i] = LinuxIfName(name)
	}
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

func compileSNMP(node *Node, sys *SystemConfig) error {
	snmp := &SNMPConfig{
		Communities: make(map[string]*SNMPCommunity),
		TrapGroups:  make(map[string]*SNMPTrapGroup),
		V3Users:     make(map[string]*SNMPv3User),
	}

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
				comm := &SNMPCommunity{Name: commName}
				commChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					commChildren = child.Children[0].Children
				}
				for _, prop := range commChildren {
					if prop.Name() == "authorization" {
						comm.Authorization = nodeVal(prop)
					}
				}
				// Flat form: community public authorization read-only
				for i := 2; i < len(child.Keys)-1; i++ {
					if child.Keys[i] == "authorization" {
						comm.Authorization = child.Keys[i+1]
					}
				}
				if comm.Authorization == "" {
					comm.Authorization = "read-only"
				}
				snmp.Communities[comm.Name] = comm
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
					if prop.Name() == "targets" {
						if v := nodeVal(prop); v != "" {
							tg.Targets = append(tg.Targets, v)
						}
					}
				}
				snmp.TrapGroups[tg.Name] = tg
			}
		case "v3":
			compileSNMPv3(child, snmp)
		}
	}

	sys.SNMP = snmp
	return nil
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
	engineNode := usmNode.FindChild("local-engine")
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
		for _, prop := range userChildren {
			switch prop.Name() {
			case "authentication-md5":
				user.AuthProtocol = "md5"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = nodeVal(pw)
				}
			case "authentication-sha":
				user.AuthProtocol = "sha"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = nodeVal(pw)
				}
			case "authentication-sha256":
				user.AuthProtocol = "sha256"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = nodeVal(pw)
				}
			case "privacy-des":
				user.PrivProtocol = "des"
				if pw := prop.FindChild("privacy-password"); pw != nil {
					user.PrivPassword = nodeVal(pw)
				}
			case "privacy-aes128":
				user.PrivProtocol = "aes128"
				if pw := prop.FindChild("privacy-password"); pw != nil {
					user.PrivPassword = nodeVal(pw)
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
			user.AuthPassword = keys[2]
		}
	case "authentication-sha":
		user.AuthProtocol = "sha"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = keys[2]
		}
	case "authentication-sha256":
		user.AuthProtocol = "sha256"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = keys[2]
		}
	case "privacy-des":
		user.PrivProtocol = "des"
		if len(keys) >= 3 && keys[1] == "privacy-password" {
			user.PrivPassword = keys[2]
		}
	case "privacy-aes128":
		user.PrivProtocol = "aes128"
		if len(keys) >= 3 && keys[1] == "privacy-password" {
			user.PrivPassword = keys[2]
		}
	}
}

func compileSchedulers(node *Node, cfg *Config) error {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*SchedulerConfig)
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
		sched := &SchedulerConfig{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "start-time":
				sched.StartTime = nodeVal(prop)
			case "stop-time":
				sched.StopTime = nodeVal(prop)
			case "start-date":
				sched.StartDate = nodeVal(prop)
			case "stop-date":
				sched.StopDate = nodeVal(prop)
			case "daily":
				sched.Daily = true
			}
		}

		cfg.Schedulers[inst.name] = sched
	}
	return nil
}

func compileChassis(node *Node, ch *ChassisConfig) error {
	clusterNode := node.FindChild("cluster")
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

	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
		rgID := 0
		if n, err := strconv.Atoi(rgInst.name); err == nil {
			rgID = n
		}

		rg := &RedundancyGroup{
			ID:             rgID,
			NodePriorities: make(map[int]int),
		}

		for _, child := range rgInst.node.Children {
			switch child.Name() {
			case "node":
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
			case "gratuitous-arp-count":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						rg.GratuitousARPCount = n
					}
				}
			case "preempt":
				rg.Preempt = true
			case "strict-vip-ownership":
				rg.StrictVIPOwnership = true
			case "interface-monitor":
				for _, ifChild := range child.Children {
					im := &InterfaceMonitor{
						Interface: ifChild.Name(),
					}
					// weight is typically inline: "ge-0/0/0 weight 255"
					for i := 1; i < len(ifChild.Keys)-1; i++ {
						if ifChild.Keys[i] == "weight" {
							if n, err := strconv.Atoi(ifChild.Keys[i+1]); err == nil {
								im.Weight = n
							}
						}
					}
					if wNode := ifChild.FindChild("weight"); wNode != nil {
						if v := nodeVal(wNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								im.Weight = n
							}
						}
					}
					rg.InterfaceMonitors = append(rg.InterfaceMonitors, im)
				}
			case "ip-monitoring":
				ipm := &IPMonitoring{}
				if gwNode := child.FindChild("global-weight"); gwNode != nil {
					if v := nodeVal(gwNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							ipm.GlobalWeight = n
						}
					}
				}
				if gtNode := child.FindChild("global-threshold"); gtNode != nil {
					if v := nodeVal(gtNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							ipm.GlobalThreshold = n
						}
					}
				}
				for _, familyNode := range child.Children {
					if familyNode.Name() != "family" {
						continue
					}
					// Determine inet node: compound key "family inet" vs nested family { inet { } }
					var inetNode *Node
					if len(familyNode.Keys) >= 2 && familyNode.Keys[1] == "inet" {
						inetNode = familyNode
					} else {
						inetNode = familyNode.FindChild("inet")
					}
					if inetNode == nil {
						continue
					}
					for _, addrChild := range inetNode.Children {
						target := &IPMonitorTarget{
							Address: addrChild.Name(),
						}
						// weight inline: "10.0.1.1 weight 100"
						for i := 1; i < len(addrChild.Keys)-1; i++ {
							if addrChild.Keys[i] == "weight" {
								if n, err := strconv.Atoi(addrChild.Keys[i+1]); err == nil {
									target.Weight = n
								}
							}
						}
						if wNode := addrChild.FindChild("weight"); wNode != nil {
							if v := nodeVal(wNode); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									target.Weight = n
								}
							}
						}
						ipm.Targets = append(ipm.Targets, target)
					}
				}
				rg.IPMonitoring = ipm
			}
		}

		ch.Cluster.RedundancyGroups = append(ch.Cluster.RedundancyGroups, rg)
	}

	return nil
}
