package config

import (
	"errors"
	"strings"
	"testing"
)

func TestSyslogSeverityParsing(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security log stream security-events host 192.0.2.1", "set security log stream security-events severity warning", "set security log stream all-events host 192.0.2.2"}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.Log.Streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(cfg.Security.Log.Streams))
	}
	secEvts := cfg.Security.Log.Streams["security-events"]
	if secEvts == nil {
		t.Fatal("missing security-events stream")
	}
	if secEvts.Host != "192.0.2.1" {
		t.Errorf("security-events host: %s", secEvts.Host)
	}
	if secEvts.Severity != "warning" {
		t.Errorf("security-events severity: %s", secEvts.Severity)
	}
	allEvts := cfg.Security.Log.Streams["all-events"]
	if allEvts == nil {
		t.Fatal("missing all-events stream")
	}
	if allEvts.Severity != "" {
		t.Errorf("all-events severity should be empty, got %q", allEvts.Severity)
	}
}

func TestSyslogFacilityParsing(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security log stream auth-events host 10.0.0.1", "set security log stream auth-events severity error", "set security log stream auth-events facility local3", "set security log stream default-events host 10.0.0.2"}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.Log.Streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(cfg.Security.Log.Streams))
	}
	authEvts := cfg.Security.Log.Streams["auth-events"]
	if authEvts == nil {
		t.Fatal("missing auth-events stream")
	}
	if authEvts.Facility != "local3" {
		t.Errorf("auth-events facility: got %q, want %q", authEvts.Facility, "local3")
	}
	if authEvts.Severity != "error" {
		t.Errorf("auth-events severity: got %q, want %q", authEvts.Severity, "error")
	}
	defEvts := cfg.Security.Log.Streams["default-events"]
	if defEvts == nil {
		t.Fatal("missing default-events stream")
	}
	if defEvts.Facility != "" {
		t.Errorf("default-events facility should be empty, got %q", defEvts.Facility)
	}
}

func TestSystemConfig(t *testing.T) {
	input := `system {
    host-name xpf-fw;
    time-zone America/Los_Angeles;
    no-redirects;
    name-server {
        2606:4700:4700::1111;
        2606:4700:4700::1001;
    }
    ntp {
        server 2001:559:8585:ffff::4;
        server 192.168.99.4;
    }
    login {
        user admin {
            uid 2000;
            class super-user;
            authentication {
                ssh-ed25519 "ssh-ed25519 AAAA...";
            }
        }
        user readonly {
            uid 2001;
            class read-only;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.System.HostName != "xpf-fw" {
		t.Errorf("hostname = %q", cfg.System.HostName)
	}
	if cfg.System.TimeZone != "America/Los_Angeles" {
		t.Errorf("timezone = %q", cfg.System.TimeZone)
	}
	if !cfg.System.NoRedirects {
		t.Error("no-redirects not set")
	}
	if len(cfg.System.NameServers) != 2 {
		t.Errorf("expected 2 name-servers, got %d", len(cfg.System.NameServers))
	}
	if len(cfg.System.NTPServers) != 2 {
		t.Errorf("expected 2 NTP servers, got %d", len(cfg.System.NTPServers))
	}
	if cfg.System.Login == nil {
		t.Fatal("login config missing")
	}
	if len(cfg.System.Login.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.System.Login.Users))
	}
	if cfg.System.Login.Users[0].Name != "admin" {
		t.Errorf("user[0] name = %q", cfg.System.Login.Users[0].Name)
	}
	if cfg.System.Login.Users[0].UID != 2000 {
		t.Errorf("user[0] uid = %d", cfg.System.Login.Users[0].UID)
	}
	if cfg.System.Login.Users[0].Class != "super-user" {
		t.Errorf("user[0] class = %q", cfg.System.Login.Users[0].Class)
	}
	if len(cfg.System.Login.Users[0].SSHKeys) != 1 {
		t.Errorf("expected 1 SSH key for admin, got %d", len(cfg.System.Login.Users[0].SSHKeys))
	}
}

func TestDHCPServerConfig(t *testing.T) {
	input := `system {
    services {
        dhcp-local-server {
            group lan-pool {
                interface eth0.0;
                interface eth1.0;
                pool office-pool {
                    subnet 10.0.1.0/24;
                    address-range low 10.0.1.100 high 10.0.1.200;
                    router 10.0.1.1;
                    dns-server 8.8.8.8;
                    dns-server 8.8.4.4;
                    lease-time 3600;
                    domain-name example.local;
                }
            }
            group guest-pool {
                interface eth2.0;
                pool guest {
                    subnet 10.0.2.0/24;
                    address-range low 10.0.2.50 high 10.0.2.150;
                    router 10.0.2.1;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	dhcp := cfg.System.DHCPServer.DHCPLocalServer
	if dhcp == nil {
		t.Fatal("expected DHCPLocalServer to be non-nil")
	}
	if len(dhcp.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(dhcp.Groups))
	}
	lanGroup := dhcp.Groups["lan-pool"]
	if lanGroup == nil {
		t.Fatal("expected group lan-pool")
	}
	if len(lanGroup.Interfaces) != 2 {
		t.Errorf("lan-pool interfaces: expected 2, got %d", len(lanGroup.Interfaces))
	}
	if len(lanGroup.Pools) != 1 {
		t.Fatalf("lan-pool pools: expected 1, got %d", len(lanGroup.Pools))
	}
	pool := lanGroup.Pools[0]
	if pool.Name != "office-pool" {
		t.Errorf("pool name: got %q, want office-pool", pool.Name)
	}
	if pool.Subnet != "10.0.1.0/24" {
		t.Errorf("pool subnet: got %q", pool.Subnet)
	}
	if pool.RangeLow != "10.0.1.100" || pool.RangeHigh != "10.0.1.200" {
		t.Errorf("pool range: %s - %s", pool.RangeLow, pool.RangeHigh)
	}
	if pool.Router != "10.0.1.1" {
		t.Errorf("pool router: got %q", pool.Router)
	}
	if len(pool.DNSServers) != 2 {
		t.Errorf("pool dns: expected 2, got %d", len(pool.DNSServers))
	}
	if pool.LeaseTime != 3600 {
		t.Errorf("pool lease-time: got %d, want 3600", pool.LeaseTime)
	}
	if pool.Domain != "example.local" {
		t.Errorf("pool domain: got %q", pool.Domain)
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set system services dhcp-local-server group test interface eth3.0", "set system services dhcp-local-server group test pool p1 subnet 172.16.0.0/24", "set system services dhcp-local-server group test pool p1 address-range low 172.16.0.10 high 172.16.0.50", "set system services dhcp-local-server group test pool p1 router 172.16.0.1"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}
	if cfg2.System.DHCPServer.DHCPLocalServer == nil {
		t.Fatal("set syntax: DHCP server is nil")
	}
	testGroup := cfg2.System.DHCPServer.DHCPLocalServer.Groups["test"]
	if testGroup == nil {
		t.Fatal("set syntax: missing group test")
	}
	if len(testGroup.Pools) != 1 {
		t.Fatalf("set syntax: expected 1 pool, got %d", len(testGroup.Pools))
	}
	if testGroup.Pools[0].Subnet != "172.16.0.0/24" {
		t.Errorf("set syntax pool subnet: %q", testGroup.Pools[0].Subnet)
	}
}

func TestSystemConfigExtended(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set system host-name test-fw", "set system backup-router 192.168.50.1 destination 192.168.0.0/16", "set system internet-options no-ipv6-reject-zero-hop-limit", "set system services ssh root-login allow", "set system services web-management http", "set system services web-management https", "set system syslog host 192.168.99.3 daemon info", "set system syslog file messages any any"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	sys := cfg.System
	if sys.HostName != "test-fw" {
		t.Errorf("HostName = %q, want test-fw", sys.HostName)
	}
	if sys.BackupRouter != "192.168.50.1" {
		t.Errorf("BackupRouter = %q, want 192.168.50.1", sys.BackupRouter)
	}
	if sys.BackupRouterDst != "192.168.0.0/16" {
		t.Errorf("BackupRouterDst = %q, want 192.168.0.0/16", sys.BackupRouterDst)
	}
	if sys.InternetOptions == nil {
		t.Fatal("InternetOptions is nil")
	}
	if !sys.InternetOptions.NoIPv6RejectZeroHopLimit {
		t.Error("NoIPv6RejectZeroHopLimit should be true")
	}
	if sys.Services == nil {
		t.Fatal("Services is nil")
	}
	if sys.Services.SSH == nil || sys.Services.SSH.RootLogin != "allow" {
		t.Errorf("SSH root-login = %v, want allow", sys.Services.SSH)
	}
	if sys.Services.WebManagement == nil {
		t.Fatal("WebManagement is nil")
	}
	if !sys.Services.WebManagement.HTTP {
		t.Error("HTTP should be true")
	}
	if !sys.Services.WebManagement.HTTPS {
		t.Error("HTTPS should be true")
	}
	if sys.Syslog == nil {
		t.Fatal("Syslog is nil")
	}
	if len(sys.Syslog.Hosts) != 1 {
		t.Fatalf("got %d syslog hosts, want 1", len(sys.Syslog.Hosts))
	}
	if sys.Syslog.Hosts[0].Address != "192.168.99.3" {
		t.Errorf("syslog host = %q, want 192.168.99.3", sys.Syslog.Hosts[0].Address)
	}
	if len(sys.Syslog.Files) != 1 {
		t.Fatalf("got %d syslog files, want 1", len(sys.Syslog.Files))
	}
	if sys.Syslog.Files[0].Name != "messages" {
		t.Errorf("syslog file = %q, want messages", sys.Syslog.Files[0].Name)
	}
}

func TestSystemConfigRootAuthAndArchival(t *testing.T) {
	input := `
system {
    root-authentication {
        encrypted-password "$6$saltsalt$abc123def456";
        ssh-ed25519 "ssh-ed25519 AAAA... user@host";
        ssh-rsa "ssh-rsa AAAA... user@host";
    }
    archival {
        configuration {
            transfer-on-commit;
            archive-sites {
                "scp://backup@10.0.0.1:/configs";
            }
        }
    }
    master-password {
        pseudorandom-function juniper-prf1;
    }
    license {
        autoupdate {
            url https://ae1.juniper.net/junos/key_retrieval;
        }
    }
    processes {
        utmd disable;
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ra := cfg.System.RootAuthentication
	if ra == nil {
		t.Fatal("root-authentication is nil")
	}
	if ra.EncryptedPassword != "$6$saltsalt$abc123def456" {
		t.Errorf("encrypted-password = %q, want %q", ra.EncryptedPassword, "$6$saltsalt$abc123def456")
	}
	if len(ra.SSHKeys) != 2 {
		t.Fatalf("ssh keys count = %d, want 2", len(ra.SSHKeys))
	}
	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("transfer-on-commit should be true")
	}
	if len(arch.ArchiveSites) != 1 {
		t.Fatalf("archive-sites count = %d, want 1", len(arch.ArchiveSites))
	}
	if arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" {
		t.Errorf("archive-site = %q", arch.ArchiveSites[0])
	}
	if cfg.System.MasterPassword != "juniper-prf1" {
		t.Errorf("master-password = %q, want %q", cfg.System.MasterPassword, "juniper-prf1")
	}
	if cfg.System.LicenseAutoUpdate != "https://ae1.juniper.net/junos/key_retrieval" {
		t.Errorf("license autoupdate url = %q", cfg.System.LicenseAutoUpdate)
	}
	if len(cfg.System.DisabledProcesses) != 1 || cfg.System.DisabledProcesses[0] != "utmd" {
		t.Errorf("disabled processes = %v, want [utmd]", cfg.System.DisabledProcesses)
	}
}

// TestArchiveSitesPasswordParsed pins the #651 parser behaviour: a
// site configured with an inline `password "$9$..."` must land on
// ArchiveSitesWithPassword, and a site without one must NOT. Covers
// the three concrete syntaxes the Junos parser produces:
//   - hierarchical nested: archive-sites { "<url>" { password "..."; } }
//   - hierarchical leaf:   archive-sites { "<url>" password "..."; }
//   - flat-set:            set system archival ... archive-sites "<url>" password "..."
//
// The existing ValidateConfig test pre-populates the slice; this test
// exercises the compile-time extraction so regressions in how Junos
// shapes enter ArchiveSitesWithPassword are caught at the parser level.
func TestArchiveSitesPasswordParsed(t *testing.T) {
	type want struct {
		urls       []string
		withPasswd []string
	}

	cases := []struct {
		name  string
		input string
		want  want
	}{
		{
			name: "hierarchical_nested_password",
			input: `
system {
    archival {
        configuration {
            archive-sites {
                "scp://alice@host1/configs" {
                    password "$9$abc";
                }
                "scp://bob@host2/configs";
            }
        }
    }
}
`,
			want: want{
				urls:       []string{"scp://alice@host1/configs", "scp://bob@host2/configs"},
				withPasswd: []string{"scp://alice@host1/configs"},
			},
		},
		{
			name: "hierarchical_leaf_password",
			input: `
system {
    archival {
        configuration {
            archive-sites {
                "scp://carol@host3/configs" password "$9$xyz";
                "scp://dave@host4/configs";
            }
        }
    }
}
`,
			want: want{
				urls:       []string{"scp://carol@host3/configs", "scp://dave@host4/configs"},
				withPasswd: []string{"scp://carol@host3/configs"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser(tc.input)
			tree, errs := p.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse errors: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			arch := cfg.System.Archival
			if arch == nil {
				t.Fatal("archival is nil")
			}
			if !equalStringSlices(arch.ArchiveSites, tc.want.urls) {
				t.Errorf("ArchiveSites = %v, want %v", arch.ArchiveSites, tc.want.urls)
			}
			if !equalStringSlices(arch.ArchiveSitesWithPassword, tc.want.withPasswd) {
				t.Errorf("ArchiveSitesWithPassword = %v, want %v",
					arch.ArchiveSitesWithPassword, tc.want.withPasswd)
			}
		})
	}

	// Flat-set form: each `set` line is parsed independently via
	// ParseSetCommand + tree.SetPath (NewParser merges newlines — see
	// CLAUDE.md "Flat set tests").
	t.Run("flat_set_password", func(t *testing.T) {
		tree := &ConfigTree{}
		setLines := []string{
			`set system archival configuration archive-sites "scp://eve@host5/configs" password "$9$secret"`,
			`set system archival configuration archive-sites "scp://frank@host6/configs"`,
		}
		for _, line := range setLines {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		arch := cfg.System.Archival
		if arch == nil {
			t.Fatal("archival is nil")
		}
		gotURLs := append([]string{}, arch.ArchiveSites...)
		wantURLs := []string{"scp://eve@host5/configs", "scp://frank@host6/configs"}
		if !equalStringSlices(gotURLs, wantURLs) {
			t.Errorf("ArchiveSites = %v, want %v", gotURLs, wantURLs)
		}
		wantPasswd := []string{"scp://eve@host5/configs"}
		if !equalStringSlices(arch.ArchiveSitesWithPassword, wantPasswd) {
			t.Errorf("ArchiveSitesWithPassword = %v, want %v",
				arch.ArchiveSitesWithPassword, wantPasswd)
		}
	})
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := make(map[string]int, len(a))
	for _, s := range a {
		aa[s]++
	}
	for _, s := range b {
		if aa[s] == 0 {
			return false
		}
		aa[s]--
	}
	return true
}

func TestSystemConfigWebManagementEnhanced(t *testing.T) {
	input := `
system {
    services {
        web-management {
            http {
                interface fxp0.0;
            }
            https {
                system-generated-certificate;
                interface fxp0.0;
            }
            api-auth {
                user admin {
                    password s3cret;
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil {
		t.Fatal("web-management is nil")
	}
	if !wm.HTTP {
		t.Error("HTTP should be true")
	}
	if !wm.HTTPS {
		t.Error("HTTPS should be true")
	}
	if wm.HTTPInterface != "fxp0.0" {
		t.Errorf("HTTP interface = %q, want fxp0.0", wm.HTTPInterface)
	}
	if wm.HTTPSInterface != "fxp0.0" {
		t.Errorf("HTTPS interface = %q, want fxp0.0", wm.HTTPSInterface)
	}
	if !wm.SystemGeneratedCert {
		t.Error("system-generated-certificate should be true")
	}
}

func TestAPIAuthConfig(t *testing.T) {
	input := `
system {
    services {
        web-management {
            api-auth {
                expires 2099-01-01;
                user admin {
                    password correct-horse-battery;
                }
                user readonly {
                    password view-only-passphrase;
                }
                api-key machine-generated-key-alpha;
                api-key machine-generated-key-bravo;
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || wm.APIAuth == nil {
		t.Fatal("web-management api-auth is nil")
	}
	if len(wm.APIAuth.Users) != 2 || len(wm.APIAuth.APIKeys) != 2 {
		t.Fatalf("got %d users and %d api-keys, want 2 each", len(wm.APIAuth.Users), len(wm.APIAuth.APIKeys))
	}
	foundAdmin := false
	for _, u := range wm.APIAuth.Users {
		if u.Username == "admin" {
			foundAdmin = VerifyAPIAuthSecret(u.Password.Reveal(), "correct-horse-battery")
		}
	}
	if !foundAdmin {
		t.Error("admin password was not compiled to a usable salted verifier")
	}
	if !VerifyAPIAuthSecret(wm.APIAuth.APIKeys[0].Reveal(), "machine-generated-key-alpha") ||
		!VerifyAPIAuthSecret(wm.APIAuth.APIKeys[1].Reveal(), "machine-generated-key-bravo") {
		t.Error("API keys were not compiled to usable salted verifiers")
	}
}

func TestAPIAuthFlatSet(t *testing.T) {
	cmds := []string{
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth user admin password correct-horse-battery",
		"set system services web-management api-auth api-key machine-generated-key-alpha",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || wm.APIAuth == nil {
		t.Fatal("web-management api-auth is nil")
	}
	if len(wm.APIAuth.Users) != 1 || wm.APIAuth.Users[0].Username != "admin" ||
		!VerifyAPIAuthSecret(wm.APIAuth.Users[0].Password.Reveal(), "correct-horse-battery") {
		t.Errorf("compiled Basic identity = %+v, want admin with usable verifier", wm.APIAuth.Users)
	}
	if len(wm.APIAuth.APIKeys) != 1 ||
		!VerifyAPIAuthSecret(wm.APIAuth.APIKeys[0].Reveal(), "machine-generated-key-alpha") {
		t.Errorf("compiled api-key = %v, want one usable verifier", wm.APIAuth.APIKeys)
	}
}

func TestSyslogMultiFacilityAndUser(t *testing.T) {
	input := `
system {
    syslog {
        user * {
            any emergency;
        }
        host 192.168.1.1 {
            any any;
            daemon info;
            change-log info;
            allow-duplicates;
        }
        file messages {
            any notice;
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	sl := cfg.System.Syslog
	if sl == nil {
		t.Fatal("syslog is nil")
	}
	if len(sl.Users) != 1 {
		t.Fatalf("users count = %d, want 1", len(sl.Users))
	}
	if sl.Users[0].User != "*" {
		t.Errorf("user = %q, want *", sl.Users[0].User)
	}
	if len(sl.Users[0].Selectors) != 1 || sl.Users[0].Selectors[0].Facility != "any" ||
		sl.Users[0].Selectors[0].Severity != "emergency" {
		t.Errorf("user selectors = %+v, want one any/emergency", sl.Users[0].Selectors)
	}
	if len(sl.Hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(sl.Hosts))
	}
	host := sl.Hosts[0]
	if host.Address != "192.168.1.1" {
		t.Errorf("host address = %q", host.Address)
	}
	if !host.AllowDuplicates {
		t.Error("allow-duplicates should be true")
	}
	if len(host.Facilities) != 3 {
		t.Fatalf("host facilities count = %d, want 3", len(host.Facilities))
	}
	expected := []SyslogFacility{{Facility: "any", Severity: "any"}, {Facility: "daemon", Severity: "info"}, {Facility: "change-log", Severity: "info"}}
	for i, exp := range expected {
		if host.Facilities[i] != exp {
			t.Errorf("facility[%d] = %+v, want %+v", i, host.Facilities[i], exp)
		}
	}
}

func TestSystemConfigSetSyntax(t *testing.T) {
	cmds := []string{"set system root-authentication encrypted-password \"$6$abcsalt$hashhash\"", "set system root-authentication ssh-ed25519 \"ssh-ed25519 AAAA\"", "set system master-password pseudorandom-function juniper-prf1", "set system license autoupdate url https://example.com/keys", "set system processes utmd disable", "set system services web-management https system-generated-certificate", "set system services web-management https interface fxp0.0", "set system services web-management api-auth api-key tok-abc-123", "set system syslog user * any emergency", "set system syslog host 10.0.0.1 any any", "set system syslog host 10.0.0.1 daemon info"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.RootAuthentication == nil {
		t.Fatal("root-authentication is nil")
	}
	if cfg.System.RootAuthentication.EncryptedPassword != "$6$abcsalt$hashhash" {
		t.Errorf("encrypted-password = %q", cfg.System.RootAuthentication.EncryptedPassword)
	}
	if len(cfg.System.RootAuthentication.SSHKeys) != 1 {
		t.Errorf("ssh keys = %d, want 1", len(cfg.System.RootAuthentication.SSHKeys))
	}
	if cfg.System.MasterPassword != "juniper-prf1" {
		t.Errorf("master-password = %q", cfg.System.MasterPassword)
	}
	if cfg.System.LicenseAutoUpdate != "https://example.com/keys" {
		t.Errorf("license url = %q", cfg.System.LicenseAutoUpdate)
	}
	if len(cfg.System.DisabledProcesses) != 1 || cfg.System.DisabledProcesses[0] != "utmd" {
		t.Errorf("disabled processes = %v", cfg.System.DisabledProcesses)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil {
		t.Fatal("web-management nil")
	}
	if !wm.HTTPS {
		t.Error("HTTPS should be true")
	}
	if !wm.SystemGeneratedCert {
		t.Error("system-generated-certificate should be true")
	}
	if wm.HTTPSInterface != "fxp0.0" {
		t.Errorf("HTTPS interface = %q", wm.HTTPSInterface)
	}
	if cfg.System.Syslog == nil || len(cfg.System.Syslog.Users) != 1 {
		t.Fatal("syslog user not parsed")
	}
	if cfg.System.Syslog.Users[0].User != "*" {
		t.Errorf("syslog user = %q", cfg.System.Syslog.Users[0].User)
	}
	if len(cfg.System.Syslog.Hosts) != 1 {
		t.Fatalf("syslog hosts = %d", len(cfg.System.Syslog.Hosts))
	}
	if len(cfg.System.Syslog.Hosts[0].Facilities) != 2 {
		t.Errorf("syslog host facilities = %d, want 2", len(cfg.System.Syslog.Hosts[0].Facilities))
	}
}

func TestTopLevelSNMP(t *testing.T) {
	input := `
snmp {
    community public {
        authorization read-only;
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.SNMP == nil {
		t.Fatal("SNMP is nil")
	}
	comm := cfg.System.SNMP.Communities["public"]
	if comm == nil {
		t.Fatal("community public not found")
	}
	if comm.Authorization != "read-only" {
		t.Errorf("authorization = %q, want read-only", comm.Authorization)
	}
}

func TestSNMPv3USMHierarchical(t *testing.T) {
	input := `
snmp {
    v3 {
        usm {
            local-engine {
                user monitor {
                    authentication-sha {
                        authentication-password "secret123";
                    }
                    privacy-aes128 {
                        privacy-password "privpass";
                    }
                }
                user readonly {
                    authentication-md5 {
                        authentication-password "md5pass";
                    }
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.SNMP == nil {
		t.Fatal("SNMP is nil")
	}
	if len(cfg.System.SNMP.V3Users) != 2 {
		t.Fatalf("V3Users count = %d, want 2", len(cfg.System.SNMP.V3Users))
	}
	monitor := cfg.System.SNMP.V3Users["monitor"]
	if monitor == nil {
		t.Fatal("user monitor not found")
	}
	if monitor.AuthProtocol != "sha" {
		t.Errorf("monitor auth = %q, want sha", monitor.AuthProtocol)
	}
	if monitor.AuthPassword != "secret123" {
		t.Errorf("monitor auth password = %q, want secret123", monitor.AuthPassword)
	}
	if monitor.PrivProtocol != "aes128" {
		t.Errorf("monitor priv = %q, want aes128", monitor.PrivProtocol)
	}
	if monitor.PrivPassword != "privpass" {
		t.Errorf("monitor priv password = %q, want privpass", monitor.PrivPassword)
	}
	readonly := cfg.System.SNMP.V3Users["readonly"]
	if readonly == nil {
		t.Fatal("user readonly not found")
	}
	if readonly.AuthProtocol != "md5" {
		t.Errorf("readonly auth = %q, want md5", readonly.AuthProtocol)
	}
	if readonly.PrivProtocol != "" {
		t.Errorf("readonly priv = %q, want empty", readonly.PrivProtocol)
	}
}

func TestSNMPv3USMFlatSet(t *testing.T) {
	lines := []string{"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password adminpass", "set snmp v3 usm local-engine user admin privacy-des privacy-password despass"}
	tree := &ConfigTree{}
	for _, line := range lines {
		parts, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(parts); err != nil {
			t.Fatalf("SetPath(%v): %v", parts, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.SNMP == nil {
		t.Fatal("SNMP is nil")
	}
	admin := cfg.System.SNMP.V3Users["admin"]
	if admin == nil {
		t.Fatal("user admin not found")
	}
	if admin.AuthProtocol != "sha256" {
		t.Errorf("admin auth = %q, want sha256", admin.AuthProtocol)
	}
	if admin.PrivProtocol != "des" {
		t.Errorf("admin priv = %q, want des", admin.PrivProtocol)
	}
}

func TestDHCPInetOptions(t *testing.T) {
	input := `
interfaces {
    reth2 {
        unit 0 {
            family inet {
                dhcp {
                    lease-time 86400;
                    retransmission-attempt 6;
                    retransmission-interval 5;
                    force-discover;
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["reth2"]
	if ifc == nil {
		t.Fatal("reth2 not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.DHCP {
		t.Error("DHCP should be true")
	}
	opts := unit.DHCPOptions
	if opts == nil {
		t.Fatal("DHCPOptions is nil")
	}
	if opts.LeaseTime != 86400 {
		t.Errorf("lease-time = %d, want 86400", opts.LeaseTime)
	}
	if opts.RetransmissionAttempt != 6 {
		t.Errorf("retransmission-attempt = %d, want 6", opts.RetransmissionAttempt)
	}
	if opts.RetransmissionInterval != 5 {
		t.Errorf("retransmission-interval = %d, want 5", opts.RetransmissionInterval)
	}
	if !opts.ForceDiscover {
		t.Error("force-discover should be true")
	}
}

func TestDHCPv6ClientExpanded(t *testing.T) {
	input := `
interfaces {
    reth2 {
        unit 0 {
            family inet6 {
                dhcpv6-client {
                    client-type stateful;
                    client-ia-type ia-pd;
                    client-ia-type ia-na;
                    prefix-delegating {
                        preferred-prefix-length 60;
                        sub-prefix-length 64;
                    }
                    client-identifier duid-type duid-ll;
                    req-option dns-server;
                    update-router-advertisement {
                        interface reth2.0;
                    }
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["reth2"]
	if ifc == nil {
		t.Fatal("reth2 not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.DHCPv6 {
		t.Error("DHCPv6 should be true")
	}
	dc := unit.DHCPv6Client
	if dc == nil {
		t.Fatal("DHCPv6Client is nil")
	}
	if dc.ClientType != "stateful" {
		t.Errorf("client-type = %q, want stateful", dc.ClientType)
	}
	if len(dc.ClientIATypes) != 2 {
		t.Fatalf("client-ia-types = %d, want 2", len(dc.ClientIATypes))
	}
	if dc.ClientIATypes[0] != "ia-pd" || dc.ClientIATypes[1] != "ia-na" {
		t.Errorf("client-ia-types = %v", dc.ClientIATypes)
	}
	if dc.PrefixDelegatingPrefixLen != 60 {
		t.Errorf("preferred-prefix-length = %d, want 60", dc.PrefixDelegatingPrefixLen)
	}
	if dc.PrefixDelegatingSubPrefLen != 64 {
		t.Errorf("sub-prefix-length = %d, want 64", dc.PrefixDelegatingSubPrefLen)
	}
	if dc.DUIDType != "duid-ll" {
		t.Errorf("duid-type = %q, want duid-ll", dc.DUIDType)
	}
	if len(dc.ReqOptions) != 1 || dc.ReqOptions[0] != "dns-server" {
		t.Errorf("req-options = %v, want [dns-server]", dc.ReqOptions)
	}
	if dc.UpdateRAInterface != "reth2.0" {
		t.Errorf("update-ra interface = %q, want reth2.0", dc.UpdateRAInterface)
	}
}

func TestNTPThreshold(t *testing.T) {
	input := `system {
    ntp {
        server 10.0.0.1;
        threshold 300 action accept;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.NTPThreshold != 300 {
		t.Errorf("NTPThreshold = %d, want 300", cfg.System.NTPThreshold)
	}
	if cfg.System.NTPThresholdAction != "accept" {
		t.Errorf("NTPThresholdAction = %q, want accept", cfg.System.NTPThresholdAction)
	}
}

func TestNTPThresholdHierarchical(t *testing.T) {
	input := `system {
    ntp {
        server 10.0.0.1;
        threshold 300 {
            action accept;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.NTPThreshold != 300 {
		t.Errorf("NTPThreshold = %d, want 300", cfg.System.NTPThreshold)
	}
	if cfg.System.NTPThresholdAction != "accept" {
		t.Errorf("NTPThresholdAction = %q, want accept", cfg.System.NTPThresholdAction)
	}
}

func TestDNSServiceEnabled(t *testing.T) {
	input := `system {
    services {
        dns;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.Services == nil {
		t.Fatal("Services is nil")
	}
	if !cfg.System.Services.DNSEnabled {
		t.Error("DNSEnabled should be true")
	}
}

func TestCommitPersistGroupsInheritanceWarned(t *testing.T) {
	tests := []string{
		`system {
    commit {
        persist-groups-inheritance;
    }
}`,
		`system {
    commit persist-groups-inheritance;
}`,
	}
	for _, input := range tests {
		p := NewParser(input)
		tree, errs := p.Parse()
		if errs != nil {
			t.Fatal(errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("unexpected compile error for %q: %v", input, err)
		}
		if !cfg.System.PersistGroupsInheritance {
			t.Fatalf("expected PersistGroupsInheritance to be recorded for %q", input)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "persist-groups-inheritance") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected persist-groups-inheritance warning for %q, got %v", input, cfg.Warnings)
		}
	}
}

func TestDNSProxyWarned(t *testing.T) {
	input := `system {
    services {
        dns {
            dns-proxy {
                default-domain *;
                forwarders {
                    1.1.1.1;
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	if cfg.System.Services == nil || !cfg.System.Services.DNSEnabled {
		t.Fatal("expected DNS service to remain enabled")
	}
	if !cfg.System.Services.DNSProxyConfigured {
		t.Fatal("expected DNSProxyConfigured to be recorded")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "dns-proxy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dns-proxy warning, got %v", cfg.Warnings)
	}
}

// #1715: `system services dns` must emit a commit-check warning that
// resolved-owner mode is unsupported (xpf owns /etc/resolv.conf directly,
// resolved stays disabled+masked).
func TestServicesDNSResolvedOwnerWarned(t *testing.T) {
	input := `system {
    services {
        dns;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	if cfg.System.Services == nil || !cfg.System.Services.DNSEnabled {
		t.Fatal("expected DNSEnabled to be recorded")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "resolved-owner mode is not supported") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected resolved-owner warning, got %v", cfg.Warnings)
	}
}

// #1715: no `system services dns` stanza ⇒ no resolved-owner warning.
func TestServicesDNSResolvedOwnerSilentWhenUnset(t *testing.T) {
	input := `system {
    host-name fw0;
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "resolved-owner mode is not supported") {
			t.Fatalf("did not expect resolved-owner warning, got %v", cfg.Warnings)
		}
	}
}

func TestParseLoginClass(t *testing.T) {
	input := `system {
    login {
        user admin {
            class super-user;
        }
        user monitor {
            class read-only;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.System.Login == nil {
		t.Fatal("expected Login config")
	}
	if len(cfg.System.Login.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.System.Login.Users))
	}
	admin := cfg.System.Login.Users[0]
	if admin.Name != "admin" || admin.Class != "super-user" {
		t.Errorf("expected admin/super-user, got %s/%s", admin.Name, admin.Class)
	}
	monitor := cfg.System.Login.Users[1]
	if monitor.Name != "monitor" || monitor.Class != "read-only" {
		t.Errorf("expected monitor/read-only, got %s/%s", monitor.Name, monitor.Class)
	}
}

func TestArchivalConfigWithTransferInterval(t *testing.T) {
	input := `
system {
    archival {
        configuration {
            transfer-on-commit;
            transfer-interval 30;
            archive-sites {
                "scp://backup@10.0.0.1:/configs";
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("transfer-on-commit should be true")
	}
	if arch.TransferInterval != 30 {
		t.Errorf("transfer-interval = %d, want 30", arch.TransferInterval)
	}
	if len(arch.ArchiveSites) != 1 {
		t.Fatalf("archive-sites count = %d, want 1", len(arch.ArchiveSites))
	}
	if arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" {
		t.Errorf("archive-site = %q", arch.ArchiveSites[0])
	}
	if arch.ArchiveDir != "/var/lib/xpf/archive" {
		t.Errorf("archive-dir = %q, want /var/lib/xpf/archive", arch.ArchiveDir)
	}
	if arch.MaxArchives != 10 {
		t.Errorf("max-archives = %d, want 10", arch.MaxArchives)
	}
}

func TestArchivalConfigSetSyntax(t *testing.T) {
	lines := []string{"system archival configuration transfer-on-commit", "system archival configuration transfer-interval 30", "system archival configuration archive-sites /var/backup"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatalf("SetPath(%v): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("transfer-on-commit should be true")
	}
	if arch.TransferInterval != 30 {
		t.Errorf("transfer-interval = %d, want 30", arch.TransferInterval)
	}
	if len(arch.ArchiveSites) != 1 || arch.ArchiveSites[0] != "/var/backup" {
		t.Errorf("archive-sites = %v", arch.ArchiveSites)
	}
}

// #903: `set system dataplane userspace workers N` was a silent no-op
// before this fix — the parser accepted it but xpfd never read the
// resulting AST node. The fix recurses into the nested `userspace`
// block from compileUserspaceDataplane so the inner setting takes
// effect (operator-friendly: their existing config now actually works
// instead of silently doing nothing). Backward-compatible: a stored
// pre-fix config that uses this form still commits cleanly post-upgrade
// AND now produces the intended runtime effect.
func TestDataplaneUserspaceNestedPathRecurses(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set system dataplane-type userspace",
		"set system dataplane userspace workers 4",
	}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.UserspaceDataplane == nil {
		t.Fatal("expected UserspaceDataplane to be populated")
	}
	if cfg.System.UserspaceDataplane.Workers != 4 {
		t.Errorf("Workers via nested path: got %d, want 4",
			cfg.System.UserspaceDataplane.Workers)
	}
}

// Counter-test: the canonical path `set system dataplane workers N` must
// keep working.
func TestDataplaneWorkersCanonicalPathParses(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set system dataplane-type userspace",
		"set system dataplane workers 7",
	}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.UserspaceDataplane == nil {
		t.Fatal("expected UserspaceDataplane to be populated")
	}
	if cfg.System.UserspaceDataplane.Workers != 7 {
		t.Errorf("Workers: got %d, want 7", cfg.System.UserspaceDataplane.Workers)
	}
}

func TestDataplaneWorkersOmittedTypeUsesUserspaceDefault(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set system dataplane workers 8",
	} {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.DataplaneType != "" {
		t.Fatalf("DataplaneType = %q, want omitted empty value", cfg.System.DataplaneType)
	}
	// The DPDKDataplane field was deleted in #1528. Omitted dataplane-type
	// defaults to userspace; nothing else to assert about DPDK here.
	if cfg.System.UserspaceDataplane == nil {
		t.Fatal("expected UserspaceDataplane to be populated")
	}
	if cfg.System.UserspaceDataplane.Workers != 8 {
		t.Fatalf("Workers = %d, want 8", cfg.System.UserspaceDataplane.Workers)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if strings.Contains(warnings, "system dataplane-type ebpf selects") {
		t.Fatalf("unexpected eBPF deprecation warning for omitted dataplane-type: %s", warnings)
	}
}

// TestDataplaneTypeExplicitEBPFRejectsRetiredCompile asserts that
// `set system dataplane-type ebpf` now hard-errors at compile time
// after the #1476 mechanical source removal. Mirrors the DPDK reject
// pattern in TestDPDKConfigCompileRejects (#1526).
func TestDataplaneTypeExplicitEBPFRejectsRetiredCompile(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set system dataplane-type ebpf",
	} {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded; expected ErrEBPFDataplaneRetired")
	}
	if !errors.Is(err, ErrEBPFDataplaneRetired) {
		t.Fatalf("CompileConfig err = %v; want errors.Is(ErrEBPFDataplaneRetired)", err)
	}
	if !strings.Contains(err.Error(), "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("err missing retirement message: %v", err)
	}
	if !strings.Contains(err.Error(), "use 'set system dataplane-type userspace'") {
		t.Fatalf("err missing remediation: %v", err)
	}
}

func TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility(t *testing.T) {
	// `dpdk` was previously included in this loop; it now hard-errors
	// at compile time via the #1526 retirement reject, so it cannot
	// reach the deprecated-eBPF warning surface. The DPDK rejection
	// is covered by TestDPDKConfigCompileRejects and by the dedicated
	// retirement tests in parser_ast_test.go.
	for _, dataplaneType := range []string{"userspace"} {
		t.Run(dataplaneType, func(t *testing.T) {
			tree := &ConfigTree{}
			cmd := "set system dataplane-type " + dataplaneType
			fields := strings.Fields(cmd)
			if err := tree.SetPath(fields[1:]); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}

			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if cfg.System.DataplaneType != dataplaneType {
				t.Fatalf("DataplaneType = %q, want %q",
					cfg.System.DataplaneType, dataplaneType)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			if strings.Contains(warnings, "deprecated legacy eBPF") {
				t.Fatalf("unexpected eBPF deprecation warning: %s", warnings)
			}
		})
	}
}

func TestDataplaneTypeValidationRejectsUnknownDuplicateValues(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set system dataplane-type mystery",
			"set system dataplane workers 8",
		} {
			fields := strings.Fields(cmd)
			if err := tree.SetPath(fields[1:]); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}

		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), `unknown dataplane-type "mystery"`) {
			t.Fatalf("CompileConfig error = %v, want unknown dataplane-type rejection", err)
		}
	})

	t.Run("valid then unknown", func(t *testing.T) {
		parser := NewParser(`
system {
    dataplane-type userspace;
    dataplane-type mystery;
    dataplane {
        workers 8;
    }
}`)
		tree, parseErrs := parser.Parse()
		if len(parseErrs) > 0 {
			t.Fatalf("Parse errors: %v", parseErrs)
		}

		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), `unknown dataplane-type "mystery"`) {
			t.Fatalf("CompileConfig error = %v, want unknown dataplane-type rejection", err)
		}
	})

	t.Run("unknown then valid", func(t *testing.T) {
		parser := NewParser(`
system {
    dataplane-type mystery;
    dataplane-type userspace;
    dataplane {
        workers 8;
    }
}`)
		tree, parseErrs := parser.Parse()
		if len(parseErrs) > 0 {
			t.Fatalf("Parse errors: %v", parseErrs)
		}

		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), `unknown dataplane-type "mystery"`) {
			t.Fatalf("CompileConfig error = %v, want unknown dataplane-type rejection", err)
		}
	})
}

// TestSSHKeyExchangeCompile verifies the H5 (#2008) ssh key-exchange leaf
// parses + compiles into SSHServiceConfig.KeyExchange, preserving order and
// supporting multiple repeated values, via the flat-set path (ParseSetCommand
// + SetPath, per the project testing rule).
func TestSSHKeyExchangeCompile(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set system services ssh root-login deny",
		"set system services ssh key-exchange ecdh-sha2-nistp256",
		"set system services ssh key-exchange curve25519-sha256",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		t.Fatal("SSH service config is nil")
	}
	ssh := cfg.System.Services.SSH
	if ssh.RootLogin != "deny" {
		t.Errorf("RootLogin = %q, want deny", ssh.RootLogin)
	}
	want := []string{"ecdh-sha2-nistp256", "curve25519-sha256"}
	if len(ssh.KeyExchange) != len(want) {
		t.Fatalf("KeyExchange = %v, want %v", ssh.KeyExchange, want)
	}
	for i := range want {
		if ssh.KeyExchange[i] != want[i] {
			t.Errorf("KeyExchange[%d] = %q, want %q", i, ssh.KeyExchange[i], want[i])
		}
	}
}
