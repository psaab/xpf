package config

import (
	"strings"
	"testing"
)

func TestNAT64(t *testing.T) {
	tree := &ConfigTree{}
	// #2173: a NAT64 source-pool address must be a host route (/32) — the
	// pool holds discrete host source IPs (parse_pool_v4) and a non-host mask
	// is rejected at commit. This fixture is about NAT64 rule-set parsing, so
	// use a canonical /32 host address.
	setCommands := []string{"set security nat source pool nat64-pool address 203.0.113.5/32", "set security nat nat64 rule-set v6-to-v4 prefix 64:ff9b::/96", "set security nat nat64 rule-set v6-to-v4 source-pool nat64-pool"}
	for _, cmd := range setCommands {
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
		t.Fatalf("CompileConfig failed: %v", err)
	}
	if len(cfg.Security.NAT.NAT64) != 1 {
		t.Fatalf("expected 1 NAT64 rule-set, got %d", len(cfg.Security.NAT.NAT64))
	}
	rs := cfg.Security.NAT.NAT64[0]
	if rs.Name != "v6-to-v4" {
		t.Errorf("rule-set name = %q, want %q", rs.Name, "v6-to-v4")
	}
	if rs.Prefix != "64:ff9b::/96" {
		t.Errorf("prefix = %q, want %q", rs.Prefix, "64:ff9b::/96")
	}
	if rs.SourcePool != "nat64-pool" {
		t.Errorf("source-pool = %q, want %q", rs.SourcePool, "nat64-pool")
	}
	hierInput := `security {
    nat {
        nat64 {
            rule-set wkp {
                prefix 64:ff9b::/96;
                source-pool pool1;
            }
        }
    }
}`
	parser := NewParser(hierInput)
	tree2, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse hierarchical: %v", errs)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig hierarchical: %v", err)
	}
	if len(cfg2.Security.NAT.NAT64) != 1 {
		t.Fatalf("hierarchical: expected 1 NAT64 rule-set, got %d", len(cfg2.Security.NAT.NAT64))
	}
	rs2 := cfg2.Security.NAT.NAT64[0]
	if rs2.Name != "wkp" || rs2.Prefix != "64:ff9b::/96" || rs2.SourcePool != "pool1" {
		t.Errorf("hierarchical: got %+v", rs2)
	}
}

func TestFirewallFilter(t *testing.T) {
	input := `firewall {
    family inet {
        filter inet-source-dscp {
            term dscp-to-gigabitpro {
                from {
                    dscp ef;
                }
                then {
                    routing-instance Comcast-GigabitPro;
                }
            }
            term ip-to-atherton-fiber {
                from {
                    source-address {
                        172.16.80.198/32;
                        176.124.71.0/24;
                    }
                }
                then {
                    routing-instance Atherton-Fiber;
                }
            }
            term default {
                then accept;
            }
        }
        filter filter-management {
            term block_unauthorised {
                from {
                    source-address {
                        0.0.0.0/0;
                    }
                    protocol tcp;
                    destination-port ssh;
                }
                then {
                    log;
                    syslog;
                    reject;
                }
            }
            term accept_default {
                then accept;
            }
        }
    }
    family inet6 {
        filter block-ra-adv {
            term t1 {
                from {
                    icmp-type 134;
                    icmp-code 0;
                }
                then discard;
            }
            term t2 {
                then accept;
            }
        }
    }
}
routing-instances {
    Comcast-GigabitPro {
        instance-type virtual-router;
    }
    Atherton-Fiber {
        instance-type virtual-router;
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
	if cfg.Firewall.FiltersInet == nil {
		t.Fatal("expected FiltersInet to be non-nil")
	}
	dscpFilter, ok := cfg.Firewall.FiltersInet["inet-source-dscp"]
	if !ok {
		t.Fatal("expected inet-source-dscp filter")
	}
	if len(dscpFilter.Terms) != 3 {
		t.Errorf("expected 3 terms, got %d", len(dscpFilter.Terms))
	}
	if dscpFilter.Terms[0].DSCP != "ef" {
		t.Errorf("expected dscp ef, got %q", dscpFilter.Terms[0].DSCP)
	}
	if dscpFilter.Terms[0].RoutingInstance != "Comcast-GigabitPro" {
		t.Errorf("expected routing-instance Comcast-GigabitPro, got %q", dscpFilter.Terms[0].RoutingInstance)
	}
	if len(dscpFilter.Terms[1].SourceAddresses) != 2 {
		t.Errorf("expected 2 source addresses, got %d", len(dscpFilter.Terms[1].SourceAddresses))
	}
	mgmtFilter, ok := cfg.Firewall.FiltersInet["filter-management"]
	if !ok {
		t.Fatal("expected filter-management filter")
	}
	if len(mgmtFilter.Terms) != 2 {
		t.Errorf("expected 2 terms, got %d", len(mgmtFilter.Terms))
	}
	if mgmtFilter.Terms[0].Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %q", mgmtFilter.Terms[0].Protocol)
	}
	if mgmtFilter.Terms[0].Action != "reject" {
		t.Errorf("expected action reject, got %q", mgmtFilter.Terms[0].Action)
	}
	if len(mgmtFilter.Terms[0].DestinationPorts) != 1 {
		t.Errorf("expected 1 destination port, got %d", len(mgmtFilter.Terms[0].DestinationPorts))
	}
	if cfg.Firewall.FiltersInet6 == nil {
		t.Fatal("expected FiltersInet6 to be non-nil")
	}
	raFilter, ok := cfg.Firewall.FiltersInet6["block-ra-adv"]
	if !ok {
		t.Fatal("expected block-ra-adv filter")
	}
	if len(raFilter.Terms) != 2 {
		t.Errorf("expected 2 terms, got %d", len(raFilter.Terms))
	}
	if raFilter.Terms[0].ICMPType != 134 {
		t.Errorf("expected icmp-type 134, got %d", raFilter.Terms[0].ICMPType)
	}
	if raFilter.Terms[0].Action != "discard" {
		t.Errorf("expected action discard, got %q", raFilter.Terms[0].Action)
	}
	if len(cfg.RoutingInstances) != 2 {
		t.Errorf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
	}
	setCommands := []string{"set firewall family inet filter test-filter term t1 from dscp af43", "set firewall family inet filter test-filter term t1 then routing-instance ATT", "set firewall family inet filter test-filter term default then accept"}
	tree2 := &ConfigTree{}
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
	tf, ok := cfg2.Firewall.FiltersInet["test-filter"]
	if !ok {
		t.Fatal("expected test-filter from set commands")
	}
	if len(tf.Terms) != 2 {
		t.Errorf("expected 2 terms from set commands, got %d", len(tf.Terms))
	}
	if tf.Terms[0].DSCP != "af43" {
		t.Errorf("expected dscp af43, got %q", tf.Terms[0].DSCP)
	}
}

func TestFirewallFilterMultiAddressSet(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set firewall family inet filter pbr term route from destination-address 10.255.192.40/30", "set firewall family inet filter pbr term route from destination-address 1.0.0.1/32", "set firewall family inet filter pbr term route from source-address 192.203.228.0/24", "set firewall family inet filter pbr term route from source-address 198.182.225.0/24", "set firewall family inet filter pbr term route then routing-instance sfmix"}
	for _, cmd := range setCommands {
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
		t.Fatalf("compile error: %v", err)
	}
	f, ok := cfg.Firewall.FiltersInet["pbr"]
	if !ok {
		t.Fatal("expected pbr filter")
	}
	if len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(f.Terms))
	}
	term := f.Terms[0]
	if len(term.DestAddresses) != 2 {
		t.Errorf("expected 2 destination addresses, got %d: %v", len(term.DestAddresses), term.DestAddresses)
	}
	if len(term.SourceAddresses) != 2 {
		t.Errorf("expected 2 source addresses, got %d: %v", len(term.SourceAddresses), term.SourceAddresses)
	}
	if term.RoutingInstance != "sfmix" {
		t.Errorf("expected routing-instance sfmix, got %q", term.RoutingInstance)
	}
	out := tree.Format()
	if !strings.Contains(out, "10.255.192.40/30") {
		t.Errorf("missing 10.255.192.40/30 in output:\n%s", out)
	}
	if !strings.Contains(out, "1.0.0.1/32") {
		t.Errorf("missing 1.0.0.1/32 in output:\n%s", out)
	}
	if !strings.Contains(out, "192.203.228.0/24") {
		t.Errorf("missing 192.203.228.0/24 in output:\n%s", out)
	}
	if !strings.Contains(out, "198.182.225.0/24") {
		t.Errorf("missing 198.182.225.0/24 in output:\n%s", out)
	}
}

func TestFirewallFilterSourcePort(t *testing.T) {
	input := `firewall {
    family inet {
        filter rate-limit {
            term match-dns {
                from {
                    protocol udp;
                    source-port 53;
                }
                then discard;
            }
            term default {
                then accept;
            }
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
	f, ok := cfg.Firewall.FiltersInet["rate-limit"]
	if !ok {
		t.Fatal("expected rate-limit filter")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	if len(f.Terms[0].SourcePorts) != 1 || f.Terms[0].SourcePorts[0] != "53" {
		t.Errorf("expected source-port [53], got %v", f.Terms[0].SourcePorts)
	}
	if f.Terms[0].Protocol != "udp" {
		t.Errorf("expected protocol udp, got %q", f.Terms[0].Protocol)
	}
	tree2 := &ConfigTree{}
	cmds := []string{"set firewall family inet filter test-sp term t1 from protocol tcp", "set firewall family inet filter test-sp term t1 from source-port 8080", "set firewall family inet filter test-sp term t1 then accept"}
	for _, cmd := range cmds {
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
		t.Fatalf("set-command compile: %v", err)
	}
	sp, ok := cfg2.Firewall.FiltersInet["test-sp"]
	if !ok {
		t.Fatal("expected test-sp filter")
	}
	if len(sp.Terms[0].SourcePorts) != 1 || sp.Terms[0].SourcePorts[0] != "8080" {
		t.Errorf("expected source-port [8080], got %v", sp.Terms[0].SourcePorts)
	}
}

func TestFirewallFilterPortRange(t *testing.T) {
	input := `firewall {
    family inet {
        filter port-range-test {
            term block-range {
                from {
                    protocol tcp;
                    destination-port 8000-9000;
                    source-port 1024-65535;
                }
                then discard;
            }
            term default {
                then accept;
            }
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
	f, ok := cfg.Firewall.FiltersInet["port-range-test"]
	if !ok {
		t.Fatal("expected port-range-test filter")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	term := f.Terms[0]
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "8000-9000" {
		t.Errorf("destination-port = %v, want [8000-9000]", term.DestinationPorts)
	}
	if len(term.SourcePorts) != 1 || term.SourcePorts[0] != "1024-65535" {
		t.Errorf("source-port = %v, want [1024-65535]", term.SourcePorts)
	}
	if term.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", term.Protocol)
	}
	if term.Action != "discard" {
		t.Errorf("action = %q, want discard", term.Action)
	}
}

func TestFirewallFilterDSCPRewrite(t *testing.T) {
	input := `firewall {
    family inet {
        filter dscp-mark {
            term mark-voice {
                from {
                    protocol udp;
                    destination-port 5060;
                }
                then {
                    dscp ef;
                    accept;
                }
            }
            term mark-bulk {
                from {
                    protocol tcp;
                }
                then {
                    dscp af11;
                    accept;
                }
            }
            term default {
                then accept;
            }
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
	f, ok := cfg.Firewall.FiltersInet["dscp-mark"]
	if !ok {
		t.Fatal("expected dscp-mark filter")
	}
	if len(f.Terms) != 3 {
		t.Fatalf("expected 3 terms, got %d", len(f.Terms))
	}
	if f.Terms[0].DSCPRewrite != "ef" {
		t.Errorf("expected DSCPRewrite ef, got %q", f.Terms[0].DSCPRewrite)
	}
	if f.Terms[1].DSCPRewrite != "af11" {
		t.Errorf("expected DSCPRewrite af11, got %q", f.Terms[1].DSCPRewrite)
	}
	if f.Terms[2].DSCPRewrite != "" {
		t.Errorf("expected no DSCPRewrite on default term, got %q", f.Terms[2].DSCPRewrite)
	}
	tree2 := &ConfigTree{}
	cmds := []string{"set firewall family inet filter dscp-set term t1 from protocol udp", "set firewall family inet filter dscp-set term t1 then dscp ef", "set firewall family inet filter dscp-set term t1 then accept"}
	for _, cmd := range cmds {
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
		t.Fatalf("set-command compile: %v", err)
	}
	f2, ok := cfg2.Firewall.FiltersInet["dscp-set"]
	if !ok {
		t.Fatal("expected dscp-set filter")
	}
	if f2.Terms[0].DSCPRewrite != "ef" {
		t.Errorf("set-command: expected DSCPRewrite ef, got %q", f2.Terms[0].DSCPRewrite)
	}
}

func TestFirewallFilterTCPFlags(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{"set firewall family inet filter tcp-flag-test term syn-only from protocol tcp", "set firewall family inet filter tcp-flag-test term syn-only from tcp-flags syn", "set firewall family inet filter tcp-flag-test term syn-only then discard", "set firewall family inet filter tcp-flag-test term syn-ack from protocol tcp", "set firewall family inet filter tcp-flag-test term syn-ack from tcp-flags syn", "set firewall family inet filter tcp-flag-test term syn-ack from tcp-flags ack", "set firewall family inet filter tcp-flag-test term syn-ack then accept", "set firewall family inet filter tcp-flag-test term default then accept"}
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
		t.Fatalf("compile: %v", err)
	}
	f, ok := cfg.Firewall.FiltersInet["tcp-flag-test"]
	if !ok {
		t.Fatal("expected tcp-flag-test filter")
	}
	if len(f.Terms) != 3 {
		t.Fatalf("expected 3 terms, got %d", len(f.Terms))
	}
	if len(f.Terms[0].TCPFlags) != 1 || f.Terms[0].TCPFlags[0] != "syn" {
		t.Errorf("term syn-only: expected TCPFlags [syn], got %v", f.Terms[0].TCPFlags)
	}
	if f.Terms[0].Action != "discard" {
		t.Errorf("term syn-only: expected action discard, got %q", f.Terms[0].Action)
	}
	if len(f.Terms[1].TCPFlags) != 2 {
		t.Errorf("term syn-ack: expected 2 TCPFlags, got %v", f.Terms[1].TCPFlags)
	}
}

func TestFirewallFilterIsFragment(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{"set firewall family inet filter frag-test term drop-frags from is-fragment", "set firewall family inet filter frag-test term drop-frags then discard", "set firewall family inet filter frag-test term allow-rest then accept"}
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
		t.Fatalf("compile: %v", err)
	}
	f, ok := cfg.Firewall.FiltersInet["frag-test"]
	if !ok {
		t.Fatal("expected frag-test filter")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	if !f.Terms[0].IsFragment {
		t.Error("expected IsFragment=true for drop-frags term")
	}
	if f.Terms[0].Action != "discard" {
		t.Errorf("expected action discard, got %q", f.Terms[0].Action)
	}
	if f.Terms[1].IsFragment {
		t.Error("expected IsFragment=false for allow-rest term")
	}
}

func TestFirewallPolicer(t *testing.T) {
	input := `firewall {
    policer rate-limit-1m {
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 15k;
        }
        then discard;
    }
    policer rate-limit-10g {
        if-exceeding {
            bandwidth-limit 10g;
            burst-size-limit 1m;
        }
        then discard;
    }
    family inet {
        filter with-policer {
            term rate-limited {
                from {
                    protocol tcp;
                }
                then {
                    policer rate-limit-1m;
                    accept;
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}
	if len(cfg.Firewall.Policers) != 2 {
		t.Fatalf("expected 2 policers, got %d", len(cfg.Firewall.Policers))
	}
	pol1m := cfg.Firewall.Policers["rate-limit-1m"]
	if pol1m == nil {
		t.Fatal("rate-limit-1m policer not found")
	}
	if pol1m.BandwidthLimit != 125000 {
		t.Errorf("expected bandwidth 125000 bytes/sec, got %d", pol1m.BandwidthLimit)
	}
	if pol1m.BurstSizeLimit != 15000 {
		t.Errorf("expected burst 15000 bytes, got %d", pol1m.BurstSizeLimit)
	}
	if pol1m.ThenAction != "discard" {
		t.Errorf("expected action discard, got %q", pol1m.ThenAction)
	}
	pol10g := cfg.Firewall.Policers["rate-limit-10g"]
	if pol10g == nil {
		t.Fatal("rate-limit-10g policer not found")
	}
	if pol10g.BandwidthLimit != 1250000000 {
		t.Errorf("expected bandwidth 1250000000 bytes/sec, got %d", pol10g.BandwidthLimit)
	}
	if pol10g.BurstSizeLimit != 1000000 {
		t.Errorf("expected burst 1000000 bytes, got %d", pol10g.BurstSizeLimit)
	}
	f := cfg.Firewall.FiltersInet["with-policer"]
	if f == nil {
		t.Fatal("with-policer filter not found")
	}
	if len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(f.Terms))
	}
	if f.Terms[0].Policer != "rate-limit-1m" {
		t.Errorf("expected policer rate-limit-1m, got %q", f.Terms[0].Policer)
	}
}

func TestFirewallPolicerSetSyntax(t *testing.T) {
	lines := []string{"set firewall policer my-policer if-exceeding bandwidth-limit 500k", "set firewall policer my-policer if-exceeding burst-size-limit 10k", "set firewall policer my-policer then discard", "set firewall family inet filter test-filter term t1 then policer my-policer", "set firewall family inet filter test-filter term t1 then accept"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse set %q: %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pol := cfg.Firewall.Policers["my-policer"]
	if pol == nil {
		t.Fatal("my-policer not found")
	}
	if pol.BandwidthLimit != 62500 {
		t.Errorf("expected bandwidth 62500 bytes/sec, got %d", pol.BandwidthLimit)
	}
	if pol.BurstSizeLimit != 10000 {
		t.Errorf("expected burst 10000 bytes, got %d", pol.BurstSizeLimit)
	}
	f := cfg.Firewall.FiltersInet["test-filter"]
	if f == nil {
		t.Fatal("test-filter not found")
	}
	if f.Terms[0].Policer != "my-policer" {
		t.Errorf("expected policer my-policer, got %q", f.Terms[0].Policer)
	}
}

func TestFirewallPrefixList(t *testing.T) {
	input := `policy-options {
    prefix-list management-hosts {
        10.0.0.0/8;
        172.16.0.0/12;
    }
}
firewall {
    family inet {
        filter filter-mgmt {
            term block_unauthorised {
                from {
                    source-address {
                        0.0.0.0/0;
                    }
                    source-prefix-list {
                        management-hosts except;
                    }
                    protocol tcp;
                    destination-port ssh;
                }
                then {
                    log;
                    syslog;
                    count block-counter;
                    reject;
                }
            }
            term accept_default {
                then accept;
            }
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
	pl := cfg.PolicyOptions.PrefixLists["management-hosts"]
	if pl == nil {
		t.Fatal("missing prefix-list management-hosts")
	}
	if len(pl.Prefixes) != 2 {
		t.Errorf("expected 2 prefixes, got %d", len(pl.Prefixes))
	}
	f := cfg.Firewall.FiltersInet["filter-mgmt"]
	if f == nil {
		t.Fatal("missing filter filter-mgmt")
	}
	term := f.Terms[0]
	if len(term.SourcePrefixLists) != 1 {
		t.Fatalf("expected 1 source-prefix-list, got %d", len(term.SourcePrefixLists))
	}
	if term.SourcePrefixLists[0].Name != "management-hosts" {
		t.Errorf("prefix-list name = %q", term.SourcePrefixLists[0].Name)
	}
	if !term.SourcePrefixLists[0].Except {
		t.Error("prefix-list should have except modifier")
	}
	if len(term.DestinationPorts) != 1 {
		t.Errorf("expected 1 destination port, got %d", len(term.DestinationPorts))
	}
	if term.Count != "block-counter" {
		t.Errorf("count = %q, want block-counter", term.Count)
	}
	if !term.Log {
		t.Error("log should be set")
	}
}

func TestFirewallPrefixListSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{"set policy-options prefix-list mgmt-hosts 10.0.0.0/8", "set policy-options prefix-list mgmt-hosts 172.16.0.0/12", "set firewall family inet filter filter-mgmt term block from source-prefix-list mgmt-hosts except", "set firewall family inet filter filter-mgmt term block from protocol tcp", "set firewall family inet filter filter-mgmt term block from destination-port 22", "set firewall family inet filter filter-mgmt term block then reject", "set firewall family inet filter filter-mgmt term allow then accept"}
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
		t.Fatalf("compile error: %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["mgmt-hosts"]
	if pl == nil {
		t.Fatal("missing prefix-list mgmt-hosts")
	}
	if len(pl.Prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(pl.Prefixes))
	}
	f := cfg.Firewall.FiltersInet["filter-mgmt"]
	if f == nil {
		t.Fatal("missing filter filter-mgmt")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	term := f.Terms[0]
	if len(term.SourcePrefixLists) != 1 {
		t.Fatalf("expected 1 source-prefix-list, got %d", len(term.SourcePrefixLists))
	}
	if term.SourcePrefixLists[0].Name != "mgmt-hosts" {
		t.Errorf("prefix-list name = %q, want mgmt-hosts", term.SourcePrefixLists[0].Name)
	}
	if !term.SourcePrefixLists[0].Except {
		t.Error("prefix-list should have except modifier")
	}
	if term.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", term.Protocol)
	}
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "22" {
		t.Errorf("destination-port = %v, want [22]", term.DestinationPorts)
	}
	if term.Action != "reject" {
		t.Errorf("action = %q, want reject", term.Action)
	}
}

func TestFirewallDestPrefixListExcept(t *testing.T) {
	input := `policy-options {
    prefix-list blocked-nets {
        192.168.0.0/16;
    }
}
firewall {
    family inet {
        filter test-filter {
            term deny-blocked {
                from {
                    destination-prefix-list {
                        blocked-nets except;
                    }
                }
                then accept;
            }
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
	f := cfg.Firewall.FiltersInet["test-filter"]
	if f == nil {
		t.Fatal("missing filter test-filter")
	}
	term := f.Terms[0]
	if len(term.DestPrefixLists) != 1 {
		t.Fatalf("expected 1 dest-prefix-list, got %d", len(term.DestPrefixLists))
	}
	if term.DestPrefixLists[0].Name != "blocked-nets" {
		t.Errorf("dest prefix-list name = %q, want blocked-nets", term.DestPrefixLists[0].Name)
	}
	if !term.DestPrefixLists[0].Except {
		t.Error("dest prefix-list should have except modifier")
	}
}

func TestFlowMonitoringConfig(t *testing.T) {
	input := `services {
    flow-monitoring {
        version9 {
            template v9-tmpl {
                flow-active-timeout 60;
                flow-inactive-timeout 15;
                template-refresh-rate {
                    seconds 30;
                }
            }
        }
    }
}
forwarding-options {
    sampling {
        instance sample-1 {
            input {
                rate 1;
            }
            family inet {
                output {
                    flow-server 192.168.99.104 {
                        port 4739;
                        version9-template v9-tmpl;
                        source-address 192.168.99.1;
                    }
                    inline-jflow;
                }
            }
            family inet6 {
                output {
                    flow-server 192.168.99.104 {
                        port 4739;
                        version9-template v9-tmpl;
                    }
                    inline-jflow;
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
	if cfg.Services.FlowMonitoring == nil {
		t.Fatal("expected FlowMonitoring to be non-nil")
	}
	v9 := cfg.Services.FlowMonitoring.Version9
	if v9 == nil {
		t.Fatal("expected Version9 to be non-nil")
	}
	if len(v9.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(v9.Templates))
	}
	tmpl := v9.Templates["v9-tmpl"]
	if tmpl == nil {
		t.Fatal("expected template v9-tmpl")
	}
	if tmpl.FlowActiveTimeout != 60 {
		t.Errorf("active timeout: got %d, want 60", tmpl.FlowActiveTimeout)
	}
	if tmpl.FlowInactiveTimeout != 15 {
		t.Errorf("inactive timeout: got %d, want 15", tmpl.FlowInactiveTimeout)
	}
	if tmpl.TemplateRefreshRate != 30 {
		t.Errorf("refresh rate: got %d, want 30", tmpl.TemplateRefreshRate)
	}
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("expected Sampling to be non-nil")
	}
	if len(cfg.ForwardingOptions.Sampling.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(cfg.ForwardingOptions.Sampling.Instances))
	}
	inst := cfg.ForwardingOptions.Sampling.Instances["sample-1"]
	if inst == nil {
		t.Fatal("expected instance sample-1")
	}
	if inst.InputRate != 1 {
		t.Errorf("input rate: got %d, want 1", inst.InputRate)
	}
	if inst.FamilyInet == nil {
		t.Fatal("expected FamilyInet")
	}
	if !inst.FamilyInet.InlineJflow {
		t.Error("expected inline-jflow for inet")
	}
	if inst.FamilyInet.SourceAddress != "192.168.99.1" {
		t.Errorf("source-address: got %q, want 192.168.99.1", inst.FamilyInet.SourceAddress)
	}
	if len(inst.FamilyInet.FlowServers) != 1 {
		t.Fatalf("expected 1 flow server for inet, got %d", len(inst.FamilyInet.FlowServers))
	}
	fs := inst.FamilyInet.FlowServers[0]
	if fs.Address != "192.168.99.104" {
		t.Errorf("flow-server address: got %q", fs.Address)
	}
	if fs.Port != 4739 {
		t.Errorf("flow-server port: got %d", fs.Port)
	}
	if fs.Version9Template != "v9-tmpl" {
		t.Errorf("flow-server template: got %q", fs.Version9Template)
	}
	if fs.Version != FlowServerVersion9 {
		t.Errorf("flow-server version binding: got %q, want %q (#2136)",
			fs.Version, FlowServerVersion9)
	}
	if inst.FamilyInet6 == nil {
		t.Fatal("expected FamilyInet6")
	}
	if !inst.FamilyInet6.InlineJflow {
		t.Error("expected inline-jflow for inet6")
	}
	if len(inst.FamilyInet6.FlowServers) != 1 {
		t.Fatalf("expected 1 flow server for inet6, got %d", len(inst.FamilyInet6.FlowServers))
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set services flow-monitoring version9 template v9-set flow-active-timeout 120", "set services flow-monitoring version9 template v9-set flow-inactive-timeout 30", "set services flow-monitoring version9 template v9-set template-refresh-rate seconds 45", "set forwarding-options sampling instance jf-inst input rate 100", "set forwarding-options sampling instance jf-inst family inet output flow-server 10.0.0.1 port 2055", "set forwarding-options sampling instance jf-inst family inet output flow-server 10.0.0.1 version9-template v9-set", "set forwarding-options sampling instance jf-inst family inet output inline-jflow"}
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
	if cfg2.Services.FlowMonitoring == nil {
		t.Fatal("set syntax: expected FlowMonitoring")
	}
	tmpl2 := cfg2.Services.FlowMonitoring.Version9.Templates["v9-set"]
	if tmpl2 == nil {
		t.Fatal("set syntax: expected template v9-set")
	}
	if tmpl2.FlowActiveTimeout != 120 {
		t.Errorf("set syntax active timeout: got %d, want 120", tmpl2.FlowActiveTimeout)
	}
	if tmpl2.FlowInactiveTimeout != 30 {
		t.Errorf("set syntax inactive timeout: got %d, want 30", tmpl2.FlowInactiveTimeout)
	}
	if tmpl2.TemplateRefreshRate != 45 {
		t.Errorf("set syntax refresh rate: got %d, want 45", tmpl2.TemplateRefreshRate)
	}
	inst2 := cfg2.ForwardingOptions.Sampling.Instances["jf-inst"]
	if inst2 == nil {
		t.Fatal("set syntax: expected instance jf-inst")
	}
	if inst2.InputRate != 100 {
		t.Errorf("set syntax input rate: got %d, want 100", inst2.InputRate)
	}
	if inst2.FamilyInet == nil {
		t.Fatal("set syntax: expected FamilyInet")
	}
	if !inst2.FamilyInet.InlineJflow {
		t.Error("set syntax: expected inline-jflow")
	}
	if len(inst2.FamilyInet.FlowServers) != 1 {
		t.Fatalf("set syntax: expected 1 flow server, got %d", len(inst2.FamilyInet.FlowServers))
	}
	fs2 := inst2.FamilyInet.FlowServers[0]
	if fs2.Address != "10.0.0.1" || fs2.Port != 2055 {
		t.Errorf("set syntax flow-server: addr=%s port=%d", fs2.Address, fs2.Port)
	}
	if fs2.Version9Template != "v9-set" {
		t.Errorf("set syntax flow-server template: %q", fs2.Version9Template)
	}
	if fs2.Version != FlowServerVersion9 {
		t.Errorf("set syntax flow-server version binding: got %q, want %q (#2136)",
			fs2.Version, FlowServerVersion9)
	}
}

// TestFlowServerVersionIPFIXBinding covers the #2136 per-flow-server
// version-ipfix selector (both hierarchical `version-ipfix { template }`
// and the flat `version-ipfix-template` form), which the compiler must
// parse into FlowServer.Version = version-ipfix + VersionIPFIXTemplate.
// Before #2136 the compiler discarded any per-server IPFIX selector and
// only recognised version9, so an IPFIX-bound collector could not be
// distinguished from a v9-bound one.
func TestFlowServerVersionIPFIXBinding(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set services flow-monitoring version-ipfix template ix-tmpl flow-active-timeout 60",
		"set forwarding-options sampling instance ix-inst input rate 100",
		"set forwarding-options sampling instance ix-inst family inet output flow-server 10.0.0.9 port 4739",
		"set forwarding-options sampling instance ix-inst family inet output flow-server 10.0.0.9 version-ipfix template ix-tmpl",
		"set forwarding-options sampling instance ix-inst family inet6 output flow-server 2001:db8::9 port 4739",
		"set forwarding-options sampling instance ix-inst family inet6 output flow-server 2001:db8::9 version-ipfix-template ix-tmpl",
	}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	inst := cfg.ForwardingOptions.Sampling.Instances["ix-inst"]
	if inst == nil || inst.FamilyInet == nil || len(inst.FamilyInet.FlowServers) != 1 {
		t.Fatalf("expected 1 inet flow-server, got %+v", inst)
	}
	// Hierarchical version-ipfix { template ix-tmpl }
	fs := inst.FamilyInet.FlowServers[0]
	if fs.Version != FlowServerVersionIPFIX {
		t.Errorf("inet version binding: got %q, want %q", fs.Version, FlowServerVersionIPFIX)
	}
	if fs.VersionIPFIXTemplate != "ix-tmpl" {
		t.Errorf("inet ipfix template: got %q, want ix-tmpl", fs.VersionIPFIXTemplate)
	}
	if fs.Version9Template != "" {
		t.Errorf("inet must not carry a v9 template, got %q", fs.Version9Template)
	}
	// Flat version-ipfix-template
	if inst.FamilyInet6 == nil || len(inst.FamilyInet6.FlowServers) != 1 {
		t.Fatalf("expected 1 inet6 flow-server")
	}
	fs6 := inst.FamilyInet6.FlowServers[0]
	if fs6.Version != FlowServerVersionIPFIX {
		t.Errorf("inet6 version binding: got %q, want %q", fs6.Version, FlowServerVersionIPFIX)
	}
	if fs6.VersionIPFIXTemplate != "ix-tmpl" {
		t.Errorf("inet6 ipfix template: got %q, want ix-tmpl", fs6.VersionIPFIXTemplate)
	}
}

func TestV9ExportExtensions(t *testing.T) {
	input := `services {
    flow-monitoring {
        version9 {
            template v9-ext {
                flow-active-timeout 60;
                ipv4-template {
                    export-extension flow-dir;
                    export-extension app-id;
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
		t.Fatalf("unexpected compile error: %v", err)
	}
	if cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil {
		t.Fatal("expected Version9 to be non-nil")
	}
	tmpl := cfg.Services.FlowMonitoring.Version9.Templates["v9-ext"]
	if tmpl == nil {
		t.Fatal("expected template v9-ext")
	}
	if len(tmpl.ExportExtensions) != 2 {
		t.Fatalf("expected 2 export extensions, got %d: %v", len(tmpl.ExportExtensions), tmpl.ExportExtensions)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "app-id") && strings.Contains(w, "v9-ext") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected app-id warning, got %v", cfg.Warnings)
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set services flow-monitoring version9 template v9-set2 flow-active-timeout 90", "set services flow-monitoring version9 template v9-set2 ipv4-template export-extension flow-dir", "set services flow-monitoring version9 template v9-set2 ipv6-template export-extension flow-dir"}
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
	tmpl2 := cfg2.Services.FlowMonitoring.Version9.Templates["v9-set2"]
	if tmpl2 == nil {
		t.Fatal("set syntax: expected template v9-set2")
	}
	if len(tmpl2.ExportExtensions) != 2 {
		t.Fatalf("set syntax: expected 2 extensions, got %d: %v", len(tmpl2.ExportExtensions), tmpl2.ExportExtensions)
	}
	if tmpl2.ExportExtensions[0] != "flow-dir" || tmpl2.ExportExtensions[1] != "flow-dir" {
		t.Fatalf("set syntax: expected both extensions to be flow-dir, got %v", tmpl2.ExportExtensions)
	}
}

func TestIPFIXExportExtensionsWarnUnsupportedAppID(t *testing.T) {
	input := `services {
    flow-monitoring {
        version-ipfix {
            template ipfix-ext {
                flow-active-timeout 60;
                ipv4-template {
                    export-extension app-id;
                }
            }
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
		t.Fatalf("unexpected compile error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "app-id") && strings.Contains(w, "ipfix-ext") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected app-id warning, got %v", cfg.Warnings)
	}
}

func TestALGAndFlowOptions(t *testing.T) {
	input := `security {
    flow {
        tcp-mss {
            ipsec-vpn 1350;
            gre-in 1400;
            gre-out 1380;
        }
        allow-dns-reply;
        allow-embedded-icmp;
    }
    alg {
        dns { disable; }
        ftp { disable; }
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
	if cfg.Security.Flow.TCPMSSIPsecVPN != 1350 {
		t.Errorf("tcp-mss ipsec-vpn: got %d, want 1350", cfg.Security.Flow.TCPMSSIPsecVPN)
	}
	if cfg.Security.Flow.TCPMSSGreIn != 1400 {
		t.Errorf("tcp-mss gre-in: got %d, want 1400", cfg.Security.Flow.TCPMSSGreIn)
	}
	if cfg.Security.Flow.TCPMSSGreOut != 1380 {
		t.Errorf("tcp-mss gre-out: got %d, want 1380", cfg.Security.Flow.TCPMSSGreOut)
	}
	if !cfg.Security.Flow.AllowDNSReply {
		t.Error("expected allow-dns-reply to be true")
	}
	if !cfg.Security.Flow.AllowEmbeddedICMP {
		t.Error("expected allow-embedded-icmp to be true")
	}
	if !cfg.Security.ALG.DNSDisable {
		t.Error("expected ALG DNS disable")
	}
	if !cfg.Security.ALG.FTPDisable {
		t.Error("expected ALG FTP disable")
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set security flow tcp-mss ipsec-vpn 1350", "set security flow tcp-mss gre-in 1400", "set security flow tcp-mss gre-out 1380", "set security flow allow-dns-reply", "set security flow allow-embedded-icmp", "set security alg dns disable", "set security alg ftp disable"}
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
	if cfg2.Security.Flow.TCPMSSIPsecVPN != 1350 {
		t.Errorf("set syntax: tcp-mss ipsec-vpn: got %d, want 1350", cfg2.Security.Flow.TCPMSSIPsecVPN)
	}
	if cfg2.Security.Flow.TCPMSSGreIn != 1400 {
		t.Errorf("set syntax: tcp-mss gre-in: got %d, want 1400", cfg2.Security.Flow.TCPMSSGreIn)
	}
	if cfg2.Security.Flow.TCPMSSGreOut != 1380 {
		t.Errorf("set syntax: tcp-mss gre-out: got %d, want 1380", cfg2.Security.Flow.TCPMSSGreOut)
	}
	if !cfg2.Security.Flow.AllowDNSReply {
		t.Error("set syntax: expected allow-dns-reply")
	}
	if !cfg2.Security.ALG.DNSDisable {
		t.Error("set syntax: expected ALG DNS disable")
	}
	if !cfg2.Security.ALG.FTPDisable {
		t.Error("set syntax: expected ALG FTP disable")
	}
}

func TestDNATWithProtocol(t *testing.T) {
	input := `security {
    zones {
        security-zone untrust {
            interfaces { eth1.0; }
        }
        security-zone dmz {
            interfaces { eth2.0; }
        }
    }
    nat {
        destination {
            pool web-server {
                address 10.0.30.100;
            }
            rule-set untrust-to-dmz {
                from zone untrust;
                rule http-dnat {
                    match {
                        destination-address 203.0.113.10/32;
                        destination-port 80;
                        protocol tcp;
                    }
                    then {
                        destination-nat {
                            pool web-server;
                        }
                    }
                }
                rule https-dnat {
                    match {
                        destination-address 203.0.113.10/32;
                        destination-port 443;
                        protocol tcp;
                    }
                    then {
                        destination-nat {
                            pool web-server;
                        }
                    }
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
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		t.Fatal("DNAT config nil")
	}
	if len(dnat.RuleSets) != 1 {
		t.Fatalf("expected 1 DNAT rule-set, got %d", len(dnat.RuleSets))
	}
	rs := dnat.RuleSets[0]
	if len(rs.Rules) != 2 {
		t.Fatalf("expected 2 DNAT rules, got %d", len(rs.Rules))
	}
	r1 := rs.Rules[0]
	if r1.Name != "http-dnat" {
		t.Errorf("rule 1 name: %s", r1.Name)
	}
	if r1.Match.Protocol != "tcp" {
		t.Errorf("rule 1 protocol: %s", r1.Match.Protocol)
	}
	if r1.Match.DestinationPort != 80 {
		t.Errorf("rule 1 port: %d", r1.Match.DestinationPort)
	}
	if r1.Match.DestinationAddress != "203.0.113.10/32" {
		t.Errorf("rule 1 dst: %s", r1.Match.DestinationAddress)
	}
	if r1.Then.PoolName != "web-server" {
		t.Errorf("rule 1 pool: %s", r1.Then.PoolName)
	}
}

func TestScreenCompilation(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security screen ids-option wan-screen tcp syn-flood alarm-threshold 1000", "set security screen ids-option wan-screen tcp syn-flood attack-threshold 2000", "set security screen ids-option wan-screen tcp land", "set security screen ids-option wan-screen tcp syn-fin", "set security screen ids-option wan-screen tcp no-flag", "set security screen ids-option wan-screen tcp winnuke", "set security screen ids-option wan-screen tcp fin-no-ack", "set security screen ids-option wan-screen icmp ping-death", "set security screen ids-option wan-screen icmp flood threshold 500", "set security screen ids-option wan-screen ip source-route-option", "set security screen ids-option wan-screen ip tear-drop", "set security screen ids-option wan-screen udp flood threshold 1000", "set security screen ids-option wan-screen tcp port-scan threshold 5000", "set security screen ids-option wan-screen ip ip-sweep threshold 3000"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	screen := cfg.Security.Screen["wan-screen"]
	if screen == nil {
		t.Fatal("missing screen profile wan-screen")
	}
	if !screen.TCP.Land {
		t.Error("expected tcp land")
	}
	if !screen.TCP.SynFin {
		t.Error("expected tcp syn-fin")
	}
	if !screen.TCP.NoFlag {
		t.Error("expected tcp tcp-no-flag")
	}
	if !screen.TCP.WinNuke {
		t.Error("expected tcp winnuke")
	}
	if !screen.TCP.FinNoAck {
		t.Error("expected tcp fin-no-ack")
	}
	if screen.TCP.SynFlood == nil {
		t.Fatal("expected syn-flood config")
	}
	if !screen.ICMP.PingDeath {
		t.Error("expected icmp ping-death")
	}
	if screen.ICMP.FloodThreshold != 500 {
		t.Errorf("icmp flood threshold: got %d, want 500", screen.ICMP.FloodThreshold)
	}
	if !screen.IP.SourceRouteOption {
		t.Error("expected ip source-route-option")
	}
	if !screen.IP.TearDrop {
		t.Error("expected ip tear-drop")
	}
	if screen.UDP.FloodThreshold != 1000 {
		t.Errorf("udp flood threshold: got %d, want 1000", screen.UDP.FloodThreshold)
	}
	if screen.TCP.PortScanThreshold != 5000 {
		t.Errorf("tcp port-scan threshold: got %d, want 5000", screen.TCP.PortScanThreshold)
	}
	if screen.IP.IPSweepThreshold != 3000 {
		t.Errorf("ip ip-sweep threshold: got %d, want 3000", screen.IP.IPSweepThreshold)
	}
}

func TestIPsecBindInterface(t *testing.T) {
	input := `security {
    ipsec {
        proposal aes256gcm {
            protocol esp;
            encryption-algorithm aes-256-gcm;
            dh-group 14;
            lifetime-seconds 3600;
        }
        vpn site-a {
            bind-interface st0.0;
            gateway 203.0.113.1;
            local-address 198.51.100.1;
            ipsec-policy aes256gcm;
            local-identity 10.0.0.0/24;
            remote-identity 10.1.0.0/24;
            pre-shared-key "secret123";
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
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.BindInterface != "st0.0" {
		t.Errorf("expected BindInterface=st0.0, got %q", vpn.BindInterface)
	}
	if vpn.Gateway != "203.0.113.1" {
		t.Errorf("expected Gateway=203.0.113.1, got %q", vpn.Gateway)
	}
	if vpn.LocalAddr != "198.51.100.1" {
		t.Errorf("expected LocalAddr=198.51.100.1, got %q", vpn.LocalAddr)
	}
	if vpn.IPsecPolicy != "aes256gcm" {
		t.Errorf("expected IPsecPolicy=aes256gcm, got %q", vpn.IPsecPolicy)
	}
	prop := cfg.Security.IPsec.Proposals["aes256gcm"]
	if prop == nil {
		t.Fatal("missing proposal aes256gcm")
	}
	if prop.EncryptionAlg != "aes-256-gcm" {
		t.Errorf("expected EncryptionAlg=aes-256-gcm, got %q", prop.EncryptionAlg)
	}
}

func TestIPsecBindInterfaceSetSyntax(t *testing.T) {
	setCommands := []string{`set security ipsec proposal aes256gcm protocol esp`, `set security ipsec proposal aes256gcm encryption-algorithm aes-256-gcm`, `set security ipsec proposal aes256gcm dh-group 14`, `set security ipsec vpn site-b bind-interface st1.0`, `set security ipsec vpn site-b gateway 10.2.0.1`, `set security ipsec vpn site-b ipsec-policy aes256gcm`, `set security ipsec vpn site-b local-identity 10.0.0.0/24`, `set security ipsec vpn site-b remote-identity 10.2.0.0/24`, `set security ipsec vpn site-b pre-shared-key "vpnkey"`}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	vpn := cfg.Security.IPsec.VPNs["site-b"]
	if vpn == nil {
		t.Fatal("missing VPN site-b")
	}
	if vpn.BindInterface != "st1.0" {
		t.Errorf("expected BindInterface=st1.0, got %q", vpn.BindInterface)
	}
	if vpn.Gateway != "10.2.0.1" {
		t.Errorf("expected Gateway=10.2.0.1, got %q", vpn.Gateway)
	}
}

func TestIPsecGateway(t *testing.T) {
	input := `security {
    ipsec {
        proposal ike-strong {
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha256-128;
            dh-group 14;
        }
        proposal esp-strong {
            protocol esp;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha256-128;
            dh-group 14;
        }
        gateway remote-gw {
            address 203.0.113.1;
            local-address 198.51.100.1;
            ike-policy ike-strong;
            external-interface untrust0;
        }
        vpn site-a {
            gateway remote-gw;
            ipsec-policy esp-strong;
            bind-interface st0.0;
            local-identity 10.0.0.0/24;
            remote-identity 10.1.0.0/24;
            pre-shared-key "secret123";
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
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("gateway address = %q, want 203.0.113.1", gw.Address)
	}
	if gw.LocalAddress != "198.51.100.1" {
		t.Errorf("gateway local-address = %q, want 198.51.100.1", gw.LocalAddress)
	}
	if gw.IKEPolicy != "ike-strong" {
		t.Errorf("gateway ike-policy = %q, want ike-strong", gw.IKEPolicy)
	}
	if gw.ExternalIface != "untrust0" {
		t.Errorf("gateway external-interface = %q, want untrust0", gw.ExternalIface)
	}
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.Gateway != "remote-gw" {
		t.Errorf("vpn gateway = %q, want remote-gw", vpn.Gateway)
	}
}

func TestIPsecGatewaySetSyntax(t *testing.T) {
	setCommands := []string{`set security ipsec gateway remote-gw address 203.0.113.1`, `set security ipsec gateway remote-gw local-address 198.51.100.1`, `set security ipsec gateway remote-gw ike-policy ike-strong`, `set security ipsec gateway remote-gw external-interface untrust0`, `set security ipsec vpn site-a gateway remote-gw`, `set security ipsec vpn site-a bind-interface st0.0`}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("gateway address = %q", gw.Address)
	}
	if gw.IKEPolicy != "ike-strong" {
		t.Errorf("gateway ike-policy = %q", gw.IKEPolicy)
	}
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.Gateway != "remote-gw" {
		t.Errorf("vpn gateway = %q", vpn.Gateway)
	}
}

func TestIKEAdvancedFeatures(t *testing.T) {
	input := `security {
    ike {
        proposal ike-phase1 {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
            lifetime-seconds 28800;
        }
        policy ike-pol {
            mode main;
            proposals ike-phase1;
            pre-shared-key ascii-text "secret123";
        }
        gateway remote-gw {
            ike-policy ike-pol;
            address 203.0.113.1;
            dead-peer-detection always-send;
            no-nat-traversal;
            local-identity hostname vpn.example.com;
            remote-identity inet 203.0.113.1;
            external-interface wan0;
            local-address 198.51.100.1;
            version v2-only;
        }
        gateway dynamic-gw {
            ike-policy ike-pol;
            dynamic hostname peer.example.com;
            local-identity hostname vpn.example.com;
            external-interface wan0;
            version v2-only;
        }
    }
    ipsec {
        proposal esp-phase2 {
            protocol esp;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha-256-128;
            lifetime-seconds 3600;
        }
        policy ipsec-pol {
            perfect-forward-secrecy {
                keys group14;
            }
            proposals esp-phase2;
        }
        vpn site-a {
            bind-interface st0.0;
            df-bit copy;
            ike {
                gateway remote-gw;
                ipsec-policy ipsec-pol;
            }
            establish-tunnels immediately;
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
	ikeProp := cfg.Security.IPsec.IKEProposals["ike-phase1"]
	if ikeProp == nil {
		t.Fatal("missing IKE proposal ike-phase1")
	}
	if ikeProp.AuthMethod != "pre-shared-keys" {
		t.Errorf("IKE proposal auth-method = %q", ikeProp.AuthMethod)
	}
	if ikeProp.DHGroup != 14 {
		t.Errorf("IKE proposal dh-group = %d, want 14", ikeProp.DHGroup)
	}
	if ikeProp.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("IKE proposal enc = %q", ikeProp.EncryptionAlg)
	}
	if ikeProp.LifetimeSeconds != 28800 {
		t.Errorf("IKE proposal lifetime = %d", ikeProp.LifetimeSeconds)
	}
	ikePol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if ikePol == nil {
		t.Fatal("missing IKE policy ike-pol")
	}
	if ikePol.Mode != "main" {
		t.Errorf("IKE policy mode = %q", ikePol.Mode)
	}
	if ikePol.Proposals != "ike-phase1" {
		t.Errorf("IKE policy proposals = %q", ikePol.Proposals)
	}
	if ikePol.PSK != "secret123" {
		t.Errorf("IKE policy PSK = %q", ikePol.PSK)
	}
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("gateway address = %q", gw.Address)
	}
	if gw.Version != "v2-only" {
		t.Errorf("gateway version = %q", gw.Version)
	}
	if !gw.NoNATTraversal {
		t.Error("gateway no-nat-traversal not set")
	}
	if gw.NATTraversal != "disable" {
		t.Errorf("gateway NATTraversal = %q, want 'disable'", gw.NATTraversal)
	}
	if gw.DeadPeerDetect != "always-send" {
		t.Errorf("gateway dpd = %q", gw.DeadPeerDetect)
	}
	if gw.LocalIDType != "hostname" || gw.LocalIDValue != "vpn.example.com" {
		t.Errorf("gateway local-identity = %q %q", gw.LocalIDType, gw.LocalIDValue)
	}
	if gw.RemoteIDType != "inet" || gw.RemoteIDValue != "203.0.113.1" {
		t.Errorf("gateway remote-identity = %q %q", gw.RemoteIDType, gw.RemoteIDValue)
	}
	dynGw := cfg.Security.IPsec.Gateways["dynamic-gw"]
	if dynGw == nil {
		t.Fatal("missing gateway dynamic-gw")
	}
	if dynGw.DynamicHostname != "peer.example.com" {
		t.Errorf("dynamic gateway hostname = %q", dynGw.DynamicHostname)
	}
	ipsecPol := cfg.Security.IPsec.Policies["ipsec-pol"]
	if ipsecPol == nil {
		t.Fatal("missing IPsec policy ipsec-pol")
	}
	if ipsecPol.PFSGroup != 14 {
		t.Errorf("IPsec policy PFS group = %d, want 14", ipsecPol.PFSGroup)
	}
	if ipsecPol.Proposals != "esp-phase2" {
		t.Errorf("IPsec policy proposals = %q", ipsecPol.Proposals)
	}
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.Gateway != "remote-gw" {
		t.Errorf("vpn gateway = %q", vpn.Gateway)
	}
	if vpn.IPsecPolicy != "ipsec-pol" {
		t.Errorf("vpn ipsec-policy = %q", vpn.IPsecPolicy)
	}
	if vpn.DFBit != "copy" {
		t.Errorf("vpn df-bit = %q", vpn.DFBit)
	}
	if vpn.EstablishTunnels != "immediately" {
		t.Errorf("vpn establish-tunnels = %q", vpn.EstablishTunnels)
	}
	if vpn.BindInterface != "st0.0" {
		t.Errorf("vpn bind-interface = %q", vpn.BindInterface)
	}
}

func TestIKEGatewayLocalCertificateAndDPD(t *testing.T) {
	input := `security {
    ike {
        gateway remote-gw {
            ike-policy ike-pol;
            address 203.0.113.1;
            local-certificate gw-cert.pem;
            dead-peer-detection {
                optimized;
                interval 7;
                threshold 3;
            }
            external-interface wan0;
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
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.LocalCertificate != "gw-cert.pem" {
		t.Fatalf("local-certificate = %q, want gw-cert.pem", gw.LocalCertificate)
	}
	if gw.DeadPeerDetect != "optimized" {
		t.Fatalf("dead-peer-detection = %q, want optimized", gw.DeadPeerDetect)
	}
	if gw.DPDInterval != 7 {
		t.Fatalf("dpd interval = %d, want 7", gw.DPDInterval)
	}
	if gw.DPDThreshold != 3 {
		t.Fatalf("dpd threshold = %d, want 3", gw.DPDThreshold)
	}
}

func TestIPsecTrafficSelectorSyntax(t *testing.T) {
	input := `security {
    ipsec {
        vpn site-a {
            bind-interface st0.0;
            traffic-selector corp-a {
                local-ip 10.0.1.0/24;
                remote-ip 10.10.1.0/24;
            }
            traffic-selector corp-b {
                local-ip 10.0.2.0/24;
                remote-ip 10.10.2.0/24;
            }
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
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if len(vpn.TrafficSelectors) != 2 {
		t.Fatalf("expected 2 traffic selectors, got %d", len(vpn.TrafficSelectors))
	}
	if vpn.TrafficSelectors["corp-a"].LocalIP != "10.0.1.0/24" {
		t.Fatalf("corp-a local-ip = %q", vpn.TrafficSelectors["corp-a"].LocalIP)
	}
	if vpn.TrafficSelectors["corp-b"].RemoteIP != "10.10.2.0/24" {
		t.Fatalf("corp-b remote-ip = %q", vpn.TrafficSelectors["corp-b"].RemoteIP)
	}
}

func TestIKEGatewayLocalCertificateAndTrafficSelectorSetSyntax(t *testing.T) {
	setCommands := []string{`set security ike gateway gw1 address 203.0.113.1`, `set security ike gateway gw1 local-certificate gw-cert.pem`, `set security ike gateway gw1 dead-peer-detection optimized`, `set security ike gateway gw1 dead-peer-detection interval 7`, `set security ike gateway gw1 dead-peer-detection threshold 3`, `set security ipsec vpn site-a bind-interface st0.0`, `set security ipsec vpn site-a traffic-selector corp-a local-ip 10.0.1.0/24`, `set security ipsec vpn site-a traffic-selector corp-a remote-ip 10.10.1.0/24`}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("missing gateway gw1")
	}
	if gw.LocalCertificate != "gw-cert.pem" {
		t.Fatalf("local-certificate = %q", gw.LocalCertificate)
	}
	if gw.DeadPeerDetect != "optimized" || gw.DPDInterval != 7 || gw.DPDThreshold != 3 {
		t.Fatalf("unexpected DPD config: %+v", gw)
	}
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil || vpn.TrafficSelectors["corp-a"] == nil {
		t.Fatal("missing traffic-selector corp-a")
	}
	if vpn.TrafficSelectors["corp-a"].LocalIP != "10.0.1.0/24" {
		t.Fatalf("corp-a local-ip = %q", vpn.TrafficSelectors["corp-a"].LocalIP)
	}
}

func TestIKEAdvancedSetSyntax(t *testing.T) {
	setCommands := []string{`set security ike proposal ike-p1 authentication-method pre-shared-keys`, `set security ike proposal ike-p1 dh-group group14`, `set security ike proposal ike-p1 encryption-algorithm aes-256-cbc`, `set security ike policy pol1 mode main`, `set security ike policy pol1 proposals ike-p1`, `set security ike policy pol1 pre-shared-key ascii-text mysecret`, `set security ike gateway gw1 ike-policy pol1`, `set security ike gateway gw1 address 10.0.0.1`, `set security ike gateway gw1 version v2-only`, `set security ike gateway gw1 no-nat-traversal`, `set security ike gateway gw1 dead-peer-detection always-send`, `set security ike gateway gw1 local-identity hostname vpn.test.com`, `set security ike gateway gw1 remote-identity inet 10.0.0.1`, `set security ipsec proposal esp-p2 protocol esp`, `set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc`, `set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128`, `set security ipsec policy ipsec-pol perfect-forward-secrecy keys group5`, `set security ipsec policy ipsec-pol proposals esp-p2`, `set security ipsec vpn tun1 bind-interface st0.0`, `set security ipsec vpn tun1 df-bit copy`, `set security ipsec vpn tun1 establish-tunnels immediately`, `set security ipsec vpn tun1 ike gateway gw1`, `set security ipsec vpn tun1 ike ipsec-policy ipsec-pol`}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ikeProp := cfg.Security.IPsec.IKEProposals["ike-p1"]
	if ikeProp == nil {
		t.Fatal("missing IKE proposal")
	}
	if ikeProp.DHGroup != 14 {
		t.Errorf("dh-group = %d, want 14", ikeProp.DHGroup)
	}
	ikePol := cfg.Security.IPsec.IKEPolicies["pol1"]
	if ikePol == nil {
		t.Fatal("missing IKE policy")
	}
	if ikePol.PSK != "mysecret" {
		t.Errorf("PSK = %q", ikePol.PSK)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("missing gateway")
	}
	if gw.Version != "v2-only" {
		t.Errorf("version = %q", gw.Version)
	}
	if !gw.NoNATTraversal {
		t.Error("no-nat-traversal not set")
	}
	if gw.NATTraversal != "disable" {
		t.Errorf("NATTraversal = %q, want 'disable'", gw.NATTraversal)
	}
	if gw.LocalIDType != "hostname" || gw.LocalIDValue != "vpn.test.com" {
		t.Errorf("local-identity = %q %q", gw.LocalIDType, gw.LocalIDValue)
	}
	ipsecPol := cfg.Security.IPsec.Policies["ipsec-pol"]
	if ipsecPol == nil {
		t.Fatal("missing IPsec policy")
	}
	if ipsecPol.PFSGroup != 5 {
		t.Errorf("PFS group = %d, want 5", ipsecPol.PFSGroup)
	}
	vpn := cfg.Security.IPsec.VPNs["tun1"]
	if vpn == nil {
		t.Fatal("missing VPN")
	}
	if vpn.DFBit != "copy" {
		t.Errorf("df-bit = %q", vpn.DFBit)
	}
	if vpn.EstablishTunnels != "immediately" {
		t.Errorf("establish-tunnels = %q", vpn.EstablishTunnels)
	}
	if vpn.Gateway != "gw1" {
		t.Errorf("gateway = %q", vpn.Gateway)
	}
	if vpn.IPsecPolicy != "ipsec-pol" {
		t.Errorf("ipsec-policy = %q", vpn.IPsecPolicy)
	}
}

func TestIPsecNATTraversal(t *testing.T) {
	input := `security {
    ike {
        gateway force-gw {
            address 10.0.0.1;
            nat-traversal force;
            version v2-only;
        }
        gateway disable-gw {
            address 10.0.0.2;
            no-nat-traversal;
        }
        gateway enable-gw {
            address 10.0.0.3;
            nat-traversal enable;
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
	fgw := cfg.Security.IPsec.Gateways["force-gw"]
	if fgw == nil {
		t.Fatal("missing force-gw")
	}
	if fgw.NATTraversal != "force" {
		t.Errorf("force-gw NATTraversal = %q, want 'force'", fgw.NATTraversal)
	}
	dgw := cfg.Security.IPsec.Gateways["disable-gw"]
	if dgw == nil {
		t.Fatal("missing disable-gw")
	}
	if !dgw.NoNATTraversal {
		t.Error("disable-gw NoNATTraversal not set")
	}
	if dgw.NATTraversal != "disable" {
		t.Errorf("disable-gw NATTraversal = %q, want 'disable'", dgw.NATTraversal)
	}
	egw := cfg.Security.IPsec.Gateways["enable-gw"]
	if egw == nil {
		t.Fatal("missing enable-gw")
	}
	if egw.NATTraversal != "enable" {
		t.Errorf("enable-gw NATTraversal = %q, want 'enable'", egw.NATTraversal)
	}
	if egw.NoNATTraversal {
		t.Error("enable-gw should not have NoNATTraversal set")
	}
}

func TestIPsecNATTraversalFlatSet(t *testing.T) {
	lines := []string{`set security ike gateway gw1 address 10.0.0.1`, `set security ike gateway gw1 nat-traversal force`, `set security ike gateway gw1 version v2-only`}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("missing gateway gw1")
	}
	if gw.NATTraversal != "force" {
		t.Errorf("NATTraversal = %q, want 'force'", gw.NATTraversal)
	}
	if gw.Address != "10.0.0.1" {
		t.Errorf("Address = %q, want '10.0.0.1'", gw.Address)
	}
}

func TestHostInboundIPsec(t *testing.T) {
	input := `security {
    zones {
        security-zone vpn {
            interfaces { st0; }
            host-inbound-traffic {
                system-services {
                    ping;
                    ipsec;
                    ike;
                }
            }
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
	zone := cfg.Security.Zones["vpn"]
	if zone == nil {
		t.Fatal("missing vpn zone")
	}
	if zone.HostInboundTraffic == nil {
		t.Fatal("missing host-inbound-traffic")
	}
	services := zone.HostInboundTraffic.SystemServices
	expected := map[string]bool{"ping": false, "ipsec": false, "ike": false}
	for _, svc := range services {
		if _, ok := expected[svc]; ok {
			expected[svc] = true
		}
	}
	for svc, found := range expected {
		if !found {
			t.Errorf("expected system-service %q not found in %v", svc, services)
		}
	}
}

func TestPolicyReject(t *testing.T) {
	input := `security {
    zones {
        security-zone trust { interfaces { eth0; } }
        security-zone untrust { interfaces { eth1; } }
    }
    policies {
        from-zone untrust to-zone trust {
            policy block-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { reject; }
            }
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
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "untrust" || zpp.ToZone != "trust" {
		t.Errorf("zone pair: from=%s to=%s", zpp.FromZone, zpp.ToZone)
	}
	if len(zpp.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(zpp.Policies))
	}
	pol := zpp.Policies[0]
	if pol.Name != "block-all" {
		t.Errorf("policy name: %s", pol.Name)
	}
	if pol.Action != PolicyReject {
		t.Errorf("expected PolicyReject (%d), got %d", PolicyReject, pol.Action)
	}
	tree2 := &ConfigTree{}
	setCommands := []string{"set security zones security-zone trust interfaces eth0", "set security zones security-zone untrust interfaces eth1", "set security policies from-zone untrust to-zone trust policy block-all match source-address any", "set security policies from-zone untrust to-zone trust policy block-all match destination-address any", "set security policies from-zone untrust to-zone trust policy block-all match application any", "set security policies from-zone untrust to-zone trust policy block-all then reject"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}
	if len(cfg2.Security.Policies) != 1 {
		t.Fatalf("set: expected 1 zone-pair, got %d", len(cfg2.Security.Policies))
	}
	if cfg2.Security.Policies[0].Policies[0].Action != PolicyReject {
		t.Errorf("set: expected PolicyReject, got %d", cfg2.Security.Policies[0].Policies[0].Action)
	}
}

func TestPolicyDenyAll(t *testing.T) {
	input := `security {
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then { permit; }
            }
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
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Errorf("expected DefaultPolicy=PolicyDeny (%d), got %d", PolicyDeny, cfg.Security.DefaultPolicy)
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	pol := cfg.Security.Policies[0].Policies[0]
	if pol.Action != PolicyPermit {
		t.Errorf("expected PolicyPermit, got %d", pol.Action)
	}
}

func TestPolicyOptions(t *testing.T) {
	input := `policy-options {
    prefix-list management-hosts {
        10.9.9.0/24;
        172.16.50.0/24;
        2001:559:8585:100::d/128;
    }
    policy-statement to_BV-FIREHOUSE {
        term default_v4 {
            from {
                protocol direct;
                route-filter 192.168.50.0/24 exact;
                route-filter 192.168.99.0/24 exact;
            }
            then accept;
        }
        then reject;
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
	pl := cfg.PolicyOptions.PrefixLists["management-hosts"]
	if pl == nil {
		t.Fatal("missing prefix-list management-hosts")
	}
	if len(pl.Prefixes) != 3 {
		t.Fatalf("management-hosts: expected 3 prefixes, got %d", len(pl.Prefixes))
	}
	if pl.Prefixes[0] != "10.9.9.0/24" {
		t.Errorf("first prefix: got %q, want 10.9.9.0/24", pl.Prefixes[0])
	}
	ps := cfg.PolicyOptions.PolicyStatements["to_BV-FIREHOUSE"]
	if ps == nil {
		t.Fatal("missing policy-statement to_BV-FIREHOUSE")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(ps.Terms))
	}
	term := ps.Terms[0]
	if term.Name != "default_v4" {
		t.Errorf("term name: got %q, want default_v4", term.Name)
	}
	if len(term.FromProtocols) != 1 || term.FromProtocols[0] != "direct" {
		t.Errorf("from protocol: got %v, want [direct]", term.FromProtocols)
	}
	if len(term.RouteFilters) != 2 {
		t.Fatalf("expected 2 route-filters, got %d", len(term.RouteFilters))
	}
	if term.RouteFilters[0].Prefix != "192.168.50.0/24" {
		t.Errorf("route-filter 0: got %q", term.RouteFilters[0].Prefix)
	}
	if term.RouteFilters[0].MatchType != "exact" {
		t.Errorf("match-type: got %q, want exact", term.RouteFilters[0].MatchType)
	}
	if term.Action != "accept" {
		t.Errorf("action: got %q, want accept", term.Action)
	}
	if ps.DefaultAction != "reject" {
		t.Errorf("default action: got %q, want reject", ps.DefaultAction)
	}
}

func TestPolicyOptionsSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{"set policy-options prefix-list mgmt 10.0.0.0/8", "set policy-options prefix-list mgmt 172.16.0.0/12", "set policy-options policy-statement export-policy term t1 from protocol direct", "set policy-options policy-statement export-policy term t1 from route-filter 10.0.0.0/8 exact", "set policy-options policy-statement export-policy term t1 then accept"}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["mgmt"]
	if pl == nil {
		t.Fatal("missing prefix-list mgmt")
	}
	if len(pl.Prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(pl.Prefixes))
	}
	ps := cfg.PolicyOptions.PolicyStatements["export-policy"]
	if ps == nil {
		t.Fatal("missing policy-statement export-policy")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(ps.Terms))
	}
}

// firstRouteFilter returns the single route-filter compiled from the
// given set/brace config under policy-statement "p" term "t1". It fails
// the test if the shape is not exactly one statement / one term / one
// route-filter so each #2072 case asserts against a known target.
func firstRouteFilter(t *testing.T, cfg *Config) *RouteFilter {
	t.Helper()
	ps := cfg.PolicyOptions.PolicyStatements["p"]
	if ps == nil {
		t.Fatal("missing policy-statement p")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(ps.Terms))
	}
	if len(ps.Terms[0].RouteFilters) != 1 {
		t.Fatalf("expected 1 route-filter, got %d", len(ps.Terms[0].RouteFilters))
	}
	return ps.Terms[0].RouteFilters[0]
}

// TestRouteFilterUptoCompile_FlatSet is the #2072 regression for the
// compiler: "upto /N" via flat set syntax must parse the /N length into
// RouteFilter.UptoLen (it stayed 0 before the fix, silently dropping the
// operator's upper bound). Uses ParseSetCommand + SetPath per the
// project's flat-set testing rule.
func TestRouteFilterUptoCompile_FlatSet(t *testing.T) {
	cases := []struct {
		name      string
		cmd       string
		wantUpto  int
		wantMatch string
	}{
		{"v4_upto24", "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 upto /24", 24, "upto"},
		{"v6_upto48", "set policy-options policy-statement p term t1 from route-filter 2001:db8::/32 upto /48", 48, "upto"},
		{"v4_upto_eq_plen", "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 upto /8", 8, "upto"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			path, err := ParseSetCommand(tc.cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", tc.cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			rf := firstRouteFilter(t, cfg)
			if rf.MatchType != tc.wantMatch {
				t.Errorf("MatchType = %q, want %q", rf.MatchType, tc.wantMatch)
			}
			if rf.UptoLen != tc.wantUpto {
				t.Errorf("UptoLen = %d, want %d (the /N length must be parsed, #2072)", rf.UptoLen, tc.wantUpto)
			}
		})
	}
}

// TestRouteFilterUptoCompile_Brace covers the other AST shape: a brace
// parse packs "route-filter <prefix> upto /N" into one leaf node, with
// the length at Keys[3]. The compiler must read it from there too.
func TestRouteFilterUptoCompile_Brace(t *testing.T) {
	src := `policy-options {
  policy-statement p {
    term t1 {
      from {
        route-filter 10.0.0.0/8 upto /24;
      }
      then accept;
    }
  }
}`
	p := NewParser(src)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rf := firstRouteFilter(t, cfg)
	if rf.MatchType != "upto" {
		t.Errorf("MatchType = %q, want upto", rf.MatchType)
	}
	if rf.UptoLen != 24 {
		t.Errorf("UptoLen = %d, want 24 (brace-parse /N must be parsed, #2072)", rf.UptoLen)
	}
}

// TestRouteFilterMatchTypes_NonUptoUnchanged asserts the other match
// types still compile with UptoLen == 0 (the upto length parsing must
// not bleed into exact/longer/orlonger).
func TestRouteFilterMatchTypes_NonUptoUnchanged(t *testing.T) {
	cases := []struct {
		name  string
		cmd   string
		match string
	}{
		{"exact", "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 exact", "exact"},
		{"longer", "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 longer", "longer"},
		{"orlonger", "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 orlonger", "orlonger"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			path, err := ParseSetCommand(tc.cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand: %v", err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			rf := firstRouteFilter(t, cfg)
			if rf.MatchType != tc.match {
				t.Errorf("MatchType = %q, want %q", rf.MatchType, tc.match)
			}
			if rf.UptoLen != 0 {
				t.Errorf("UptoLen = %d, want 0 for non-upto match type", rf.UptoLen)
			}
		})
	}
}

// TestParseRouteFilterLen unit-tests the length token parser directly so
// the malformed-token rejection (which makes the renderer degrade
// safely) is locked regardless of the AST plumbing (Codex #2102 gap).
func TestParseRouteFilterLen(t *testing.T) {
	cases := []struct {
		tok    string
		wantN  int
		wantOK bool
	}{
		{"/24", 24, true},
		{"24", 24, true},
		{"/1", 1, true},
		{"/128", 128, true},
		// zero rejected: "upto /0" is not a meaningful length and must stay
		// distinguishable from an unset UptoLen (Codex #2102 MAJOR).
		{"/0", 0, false},
		{"/129", 0, false}, // > 128
		{"/-1", 0, false},  // negative
		{"/+24", 0, false}, // signed-plus must be rejected (Atoi would accept it)
		{"/abc", 0, false}, // letters
		{"/", 0, false},    // empty after slash
		{"", 0, false},     // empty
		{"/2a", 0, false},  // trailing letters
	}
	for _, tc := range cases {
		t.Run(tc.tok, func(t *testing.T) {
			n, ok := parseRouteFilterLen(tc.tok)
			if ok != tc.wantOK || n != tc.wantN {
				t.Errorf("parseRouteFilterLen(%q) = (%d,%v), want (%d,%v)", tc.tok, n, ok, tc.wantN, tc.wantOK)
			}
		})
	}
}

// TestRouteFilterUptoCompile_MalformedLength asserts that an upto with a
// non-numeric length token compiles with UptoLen 0 (the renderer then
// degrades to the orlonger default rather than emitting a bad line).
func TestRouteFilterUptoCompile_MalformedLength(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 upto /abc")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rf := firstRouteFilter(t, cfg)
	if rf.MatchType != "upto" {
		t.Errorf("MatchType = %q, want upto", rf.MatchType)
	}
	if rf.UptoLen != 0 {
		t.Errorf("UptoLen = %d, want 0 for a malformed length token", rf.UptoLen)
	}
}

func TestIKEProposalSetSyntax(t *testing.T) {
	setCommands := []string{`set security ike proposal ike-aes256 authentication-method pre-shared-keys`, `set security ike proposal ike-aes256 encryption-algorithm aes-256-cbc`, `set security ike proposal ike-aes256 authentication-algorithm sha-256`, `set security ike proposal ike-aes256 dh-group group14`, `set security ike proposal ike-aes256 lifetime-seconds 28800`, `set security ike policy ike-strong mode main`, `set security ike policy ike-strong proposals ike-aes256`, `set security ike gateway remote-gw address 203.0.113.1`, `set security ike gateway remote-gw ike-policy ike-strong`, `set security ike gateway remote-gw external-interface untrust0`}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	prop := cfg.Security.IPsec.IKEProposals["ike-aes256"]
	if prop == nil {
		t.Fatal("missing IKE proposal ike-aes256")
	}
	if prop.AuthMethod != "pre-shared-keys" {
		t.Errorf("auth-method = %q, want pre-shared-keys", prop.AuthMethod)
	}
	if prop.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("encryption = %q, want aes-256-cbc", prop.EncryptionAlg)
	}
	if prop.DHGroup != 14 {
		t.Errorf("dh-group = %d, want 14", prop.DHGroup)
	}
	if prop.LifetimeSeconds != 28800 {
		t.Errorf("lifetime = %d, want 28800", prop.LifetimeSeconds)
	}
	pol := cfg.Security.IPsec.IKEPolicies["ike-strong"]
	if pol == nil {
		t.Fatal("missing IKE policy ike-strong")
	}
	if pol.Mode != "main" {
		t.Errorf("mode = %q, want main", pol.Mode)
	}
	if pol.Proposals != "ike-aes256" {
		t.Errorf("proposals = %q, want ike-aes256", pol.Proposals)
	}
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("address = %q, want 203.0.113.1", gw.Address)
	}
	if gw.IKEPolicy != "ike-strong" {
		t.Errorf("ike-policy = %q, want ike-strong", gw.IKEPolicy)
	}
}

func TestIPsecProposalSetSyntax(t *testing.T) {
	setCommands := []string{`set security ipsec proposal esp-aes256 protocol esp`, `set security ipsec proposal esp-aes256 encryption-algorithm aes-256-cbc`, `set security ipsec proposal esp-aes256 authentication-algorithm hmac-sha-256-128`, `set security ipsec proposal esp-aes256 lifetime-seconds 3600`, `set security ipsec policy ipsec-strong proposals esp-aes256`}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	prop := cfg.Security.IPsec.Proposals["esp-aes256"]
	if prop == nil {
		t.Fatal("missing IPsec proposal esp-aes256")
	}
	if prop.Protocol != "esp" {
		t.Errorf("protocol = %q, want esp", prop.Protocol)
	}
	if prop.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("encryption = %q, want aes-256-cbc", prop.EncryptionAlg)
	}
	if prop.AuthAlg != "hmac-sha-256-128" {
		t.Errorf("auth-alg = %q, want hmac-sha-256-128", prop.AuthAlg)
	}
	if prop.LifetimeSeconds != 3600 {
		t.Errorf("lifetime = %d, want 3600", prop.LifetimeSeconds)
	}
	pol := cfg.Security.IPsec.Policies["ipsec-strong"]
	if pol == nil {
		t.Fatal("missing IPsec policy ipsec-strong")
	}
	if pol.Proposals != "esp-aes256" {
		t.Errorf("proposals = %q, want esp-aes256", pol.Proposals)
	}
}

func TestZoneSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security zones security-zone trust interfaces trust0", "set security zones security-zone trust interfaces trust1", "set security zones security-zone trust screen untrust-screen", "set security zones security-zone trust host-inbound-traffic system-services ping", "set security zones security-zone trust host-inbound-traffic system-services ssh", "set security zones security-zone trust host-inbound-traffic protocols ospf", "set security zones security-zone untrust interfaces untrust0"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatal("trust zone not found")
	}
	if len(trust.Interfaces) != 2 {
		t.Fatalf("trust interfaces = %v, want 2", trust.Interfaces)
	}
	if trust.ScreenProfile != "untrust-screen" {
		t.Errorf("trust screen = %q, want untrust-screen", trust.ScreenProfile)
	}
	if trust.HostInboundTraffic == nil {
		t.Fatal("trust host-inbound-traffic is nil")
	}
	if len(trust.HostInboundTraffic.SystemServices) != 2 {
		t.Errorf("system-services = %v, want [ping ssh]", trust.HostInboundTraffic.SystemServices)
	}
	if len(trust.HostInboundTraffic.Protocols) != 1 || trust.HostInboundTraffic.Protocols[0] != "ospf" {
		t.Errorf("protocols = %v, want [ospf]", trust.HostInboundTraffic.Protocols)
	}
	untrust := cfg.Security.Zones["untrust"]
	if untrust == nil {
		t.Fatal("untrust zone not found")
	}
	if len(untrust.Interfaces) != 1 || untrust.Interfaces[0] != "untrust0" {
		t.Errorf("untrust interfaces = %v, want [untrust0]", untrust.Interfaces)
	}
}

func TestValidateConfigWarnsSynCookieWithoutRootSecret(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set system dataplane-type userspace",
		"set security flow syn-flood-protection-mode syn-cookie",
		"set security zones security-zone trust screen flood",
		"set security screen ids-option flood tcp syn-flood attack-threshold 100",
	}
	for _, cmd := range setCommands {
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
		t.Fatalf("CompileConfig failed: %v", err)
	}

	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "active userspace-dp SYN-cookie screen profiles require") {
		t.Fatalf("expected userspace SYN-cookie secret warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "Legacy eBPF SYN-cookie handling uses kernel helpers") {
		t.Fatalf("expected legacy eBPF scope note, got: %s", warnings)
	}
}

func TestValidateConfigDoesNotWarnSynCookieWithRootSecret(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set system dataplane-type userspace",
		`set system root-authentication encrypted-password "$6$rounds=5000$salt$hash"`,
		"set security flow syn-flood-protection-mode syn-cookie",
		"set security zones security-zone trust screen flood",
		"set security screen ids-option flood tcp syn-flood attack-threshold 100",
	}
	for _, cmd := range setCommands {
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
		t.Fatalf("CompileConfig failed: %v", err)
	}

	warnings := strings.Join(cfg.Warnings, "\n")
	if strings.Contains(warnings, "active userspace-dp SYN-cookie screen profiles require") {
		t.Fatalf("unexpected userspace SYN-cookie secret warning: %s", warnings)
	}
}

func TestValidateConfigDoesNotWarnDormantSynCookieWithoutRootSecret(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set system dataplane-type userspace",
		"set security flow syn-flood-protection-mode syn-cookie",
		"set security zones security-zone trust screen flood",
		"set security screen ids-option flood tcp land",
	}
	for _, cmd := range setCommands {
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
		t.Fatalf("CompileConfig failed: %v", err)
	}

	warnings := strings.Join(cfg.Warnings, "\n")
	if strings.Contains(warnings, "active userspace-dp SYN-cookie screen profiles require") {
		t.Fatalf("unexpected dormant userspace SYN-cookie warning: %s", warnings)
	}
}

func TestValidateConfigWarnsDefaultUserspaceSynCookieWithoutRootSecret(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set security flow syn-flood-protection-mode syn-cookie",
		"set security zones security-zone trust screen flood",
		"set security screen ids-option flood tcp syn-flood attack-threshold 100",
	}
	for _, cmd := range setCommands {
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
		t.Fatalf("CompileConfig failed: %v", err)
	}

	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "active userspace-dp SYN-cookie screen profiles require") {
		t.Fatalf("expected default-userspace SYN-cookie warning, got: %s", warnings)
	}
}

func TestScreenSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security screen ids-option untrust-screen icmp ping-death", "set security screen ids-option untrust-screen tcp land", "set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1000", "set security screen ids-option untrust-screen tcp syn-flood attack-threshold 500", "set security screen ids-option untrust-screen ip source-route-option"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	profile := cfg.Security.Screen["untrust-screen"]
	if profile == nil {
		t.Fatal("screen profile not found")
	}
	if !profile.ICMP.PingDeath {
		t.Error("PingDeath should be true")
	}
	if !profile.TCP.Land {
		t.Error("Land should be true")
	}
	if profile.TCP.SynFlood == nil {
		t.Fatal("SynFlood is nil")
	}
	if profile.TCP.SynFlood.AlarmThreshold != 1000 {
		t.Errorf("AlarmThreshold = %d, want 1000", profile.TCP.SynFlood.AlarmThreshold)
	}
	if profile.TCP.SynFlood.AttackThreshold != 500 {
		t.Errorf("AttackThreshold = %d, want 500", profile.TCP.SynFlood.AttackThreshold)
	}
	if !profile.IP.SourceRouteOption {
		t.Error("SourceRouteOption should be true")
	}
}

func TestNATSourceSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security nat source pool snat-pool address 203.0.113.0/24", "set security nat source rule-set trust-to-untrust from zone trust", "set security nat source rule-set trust-to-untrust to zone untrust", "set security nat source rule-set trust-to-untrust rule snat-rule match source-address 10.0.0.0/8", "set security nat source rule-set trust-to-untrust rule snat-rule then source-nat interface"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["snat-pool"]
	if pool == nil {
		t.Fatal("source pool not found")
	}
	if len(pool.Addresses) != 1 || pool.Addresses[0] != "203.0.113.0/24" {
		t.Errorf("pool addresses = %v, want [203.0.113.0/24]", pool.Addresses)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.Name != "trust-to-untrust" {
		t.Errorf("rule-set name = %q, want trust-to-untrust", rs.Name)
	}
	if rs.FromZone != "trust" {
		t.Errorf("from zone = %q, want trust", rs.FromZone)
	}
	if rs.ToZone != "untrust" {
		t.Errorf("to zone = %q, want untrust", rs.ToZone)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs.Rules))
	}
	rule := rs.Rules[0]
	if rule.Name != "snat-rule" {
		t.Errorf("rule name = %q, want snat-rule", rule.Name)
	}
	if rule.Match.SourceAddress != "10.0.0.0/8" {
		t.Errorf("match source = %q, want 10.0.0.0/8", rule.Match.SourceAddress)
	}
	if !rule.Then.Interface {
		t.Error("then should be source-nat interface")
	}
}

func TestPolicySetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security policies from-zone trust to-zone untrust policy allow-all match source-address any", "set security policies from-zone trust to-zone untrust policy allow-all match destination-address any", "set security policies from-zone trust to-zone untrust policy allow-all match application any", "set security policies from-zone trust to-zone untrust policy allow-all then permit", "set security policies from-zone trust to-zone untrust policy allow-all then log session-init", "set security policies from-zone trust to-zone untrust policy allow-all then count"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("got %d zone-pair policies, want 1", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "trust" || zpp.ToZone != "untrust" {
		t.Errorf("zones = %s->%s, want trust->untrust", zpp.FromZone, zpp.ToZone)
	}
	if len(zpp.Policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(zpp.Policies))
	}
	pol := zpp.Policies[0]
	if pol.Name != "allow-all" {
		t.Errorf("policy name = %q, want allow-all", pol.Name)
	}
	if pol.Action != PolicyPermit {
		t.Errorf("action = %d, want permit", pol.Action)
	}
	if pol.Log == nil || !pol.Log.SessionInit {
		t.Error("log session-init should be true")
	}
	if !pol.Count {
		t.Error("count should be true")
	}
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "any" {
		t.Errorf("source-address = %v, want [any]", pol.Match.SourceAddresses)
	}
}

func TestPolicyMatchSingleLineSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	// TestPolicyMatchSingleLineSetSyntax verifies that multiple match criteria on
	// a single set line become siblings under match, not nested children.
	// e.g. "set ... match destination-address any source-address any application any"
	for _, cmd := range []string{"set security policies from-zone lan to-zone wan policy allow-ps match destination-address any source-address any application any", "set security policies from-zone lan to-zone wan policy allow-ps then permit"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("got %d zone-pair policies, want 1", len(cfg.Security.Policies))
	}
	pol := cfg.Security.Policies[0].Policies[0]
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "any" {
		t.Errorf("source-address = %v, want [any]", pol.Match.SourceAddresses)
	}
	if len(pol.Match.DestinationAddresses) != 1 || pol.Match.DestinationAddresses[0] != "any" {
		t.Errorf("destination-address = %v, want [any]", pol.Match.DestinationAddresses)
	}
	if len(pol.Match.Applications) != 1 || pol.Match.Applications[0] != "any" {
		t.Errorf("application = %v, want [any]", pol.Match.Applications)
	}
}

func TestGlobalPolicies(t *testing.T) {
	input := `
security {
    policies {
        global {
            policy icmpv6-allow {
                match {
                    source-address any-ipv6;
                    destination-address any-ipv6;
                    application junos-icmp6-all;
                }
                then {
                    permit;
                }
            }
            policy default-deny {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                    log {
                        session-init;
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("got %d global policies, want 2", len(cfg.Security.GlobalPolicies))
	}
	pol0 := cfg.Security.GlobalPolicies[0]
	if pol0.Name != "icmpv6-allow" {
		t.Errorf("policy 0 name = %q, want icmpv6-allow", pol0.Name)
	}
	if pol0.Action != PolicyPermit {
		t.Errorf("policy 0 action = %d, want permit", pol0.Action)
	}
	if len(pol0.Match.Applications) != 1 || pol0.Match.Applications[0] != "junos-icmp6-all" {
		t.Errorf("policy 0 apps = %v, want [junos-icmp6-all]", pol0.Match.Applications)
	}
	pol1 := cfg.Security.GlobalPolicies[1]
	if pol1.Name != "default-deny" {
		t.Errorf("policy 1 name = %q, want default-deny", pol1.Name)
	}
	if pol1.Action != PolicyDeny {
		t.Errorf("policy 1 action = %d, want deny", pol1.Action)
	}
	if pol1.Log == nil || !pol1.Log.SessionInit {
		t.Error("policy 1 log session-init should be true")
	}
}

func TestGlobalPoliciesSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security policies global policy allow-icmpv6 match source-address any-ipv6", "set security policies global policy allow-icmpv6 match destination-address any-ipv6", "set security policies global policy allow-icmpv6 match application junos-icmp6-all", "set security policies global policy allow-icmpv6 then permit"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("got %d global policies, want 1", len(cfg.Security.GlobalPolicies))
	}
	pol := cfg.Security.GlobalPolicies[0]
	if pol.Name != "allow-icmpv6" {
		t.Errorf("name = %q, want allow-icmpv6", pol.Name)
	}
	if pol.Action != PolicyPermit {
		t.Errorf("action = %d, want permit", pol.Action)
	}
}

func TestApplicationSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set applications application my-http protocol tcp", "set applications application my-http destination-port 8080", "set applications application-set web-apps application my-http", "set applications application-set web-apps application junos-https"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	app := cfg.Applications.Applications["my-http"]
	if app == nil {
		t.Fatal("application my-http not found")
	}
	if app.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", app.Protocol)
	}
	if app.DestinationPort != "8080" {
		t.Errorf("destination-port = %q, want 8080", app.DestinationPort)
	}
	as := cfg.Applications.ApplicationSets["web-apps"]
	if as == nil {
		t.Fatal("application-set web-apps not found")
	}
	if len(as.Applications) != 2 {
		t.Fatalf("got %d apps in set, want 2", len(as.Applications))
	}
}

func TestSecurityLogEnhancements(t *testing.T) {
	input := `
security {
    log {
        mode stream;
        format sd-syslog;
        source-interface reth1.100;
        stream syslog-container {
            format sd-syslog;
            category all;
            host {
                192.168.99.3;
            }
            source-address 172.16.100.1;
        }
        stream filebeat-syslog {
            host {
                192.168.99.106;
                port 9006;
            }
            source-address 192.168.99.1;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	log := cfg.Security.Log
	if log.Mode != "stream" {
		t.Errorf("Mode = %q, want stream", log.Mode)
	}
	if log.Format != "sd-syslog" {
		t.Errorf("Format = %q, want sd-syslog", log.Format)
	}
	if log.SourceInterface != "reth1.100" {
		t.Errorf("SourceInterface = %q, want reth1.100", log.SourceInterface)
	}
	if len(log.Streams) != 2 {
		t.Fatalf("got %d streams, want 2", len(log.Streams))
	}
	s1 := log.Streams["syslog-container"]
	if s1 == nil {
		t.Fatal("missing stream syslog-container")
	}
	if s1.Host != "192.168.99.3" {
		t.Errorf("syslog-container host = %q, want 192.168.99.3", s1.Host)
	}
	if s1.Format != "sd-syslog" {
		t.Errorf("syslog-container format = %q, want sd-syslog", s1.Format)
	}
	if s1.Category != "all" {
		t.Errorf("syslog-container category = %q, want all", s1.Category)
	}
	if s1.SourceAddress != "172.16.100.1" {
		t.Errorf("syslog-container source-address = %q, want 172.16.100.1", s1.SourceAddress)
	}
	s2 := log.Streams["filebeat-syslog"]
	if s2 == nil {
		t.Fatal("missing stream filebeat-syslog")
	}
	if s2.Host != "192.168.99.106" {
		t.Errorf("filebeat-syslog host = %q, want 192.168.99.106", s2.Host)
	}
	if s2.Port != 9006 {
		t.Errorf("filebeat-syslog port = %d, want 9006", s2.Port)
	}
	if s2.SourceAddress != "192.168.99.1" {
		t.Errorf("filebeat-syslog source-address = %q, want 192.168.99.1", s2.SourceAddress)
	}
}

func TestNATMultiZoneBracketList(t *testing.T) {
	input := `security {
    nat {
        source {
            rule-set multi-zone-snat {
                from zone [ guest lan dmz ];
                to zone [ Internet-ATT Internet-BCI ];
                rule catch-all {
                    match {
                        source-address 0.0.0.0/0;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
        destination {
            pool web-server {
                address 10.0.1.100/32 port 80;
            }
            rule-set multi-zone-dnat {
                from zone [ Internet-ATT Internet-BCI ];
                rule http-in {
                    match {
                        destination-address 1.2.3.4/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat {
                            pool {
                                web-server;
                            }
                        }
                    }
                }
            }
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
	if len(cfg.Security.NAT.Source) != 6 {
		t.Fatalf("got %d source rule-sets, want 6 (3×2 Cartesian)", len(cfg.Security.NAT.Source))
	}
	zonePairs := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Source {
		zonePairs[rs.FromZone+"->"+rs.ToZone] = true
		if len(rs.Rules) != 1 || rs.Rules[0].Name != "catch-all" {
			t.Errorf("rule-set %s->%s: expected 1 rule 'catch-all', got %d", rs.FromZone, rs.ToZone, len(rs.Rules))
		}
	}
	for _, pair := range []string{"guest->Internet-ATT", "guest->Internet-BCI", "lan->Internet-ATT", "lan->Internet-BCI", "dmz->Internet-ATT", "dmz->Internet-BCI"} {
		if !zonePairs[pair] {
			t.Errorf("missing zone pair: %s", pair)
		}
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("no destination NAT config")
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 2 {
		t.Fatalf("got %d DNAT rule-sets, want 2", len(cfg.Security.NAT.Destination.RuleSets))
	}
	dnatZones := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		dnatZones[rs.FromZone] = true
	}
	if !dnatZones["Internet-ATT"] || !dnatZones["Internet-BCI"] {
		t.Errorf("DNAT from zones = %v, want Internet-ATT + Internet-BCI", dnatZones)
	}
}

func TestNATMultiZoneSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security nat source rule-set internal-to-internet from zone [ guest lan ]", "set security nat source rule-set internal-to-internet to zone Internet-ATT", "set security nat source rule-set internal-to-internet rule catch-all match source-address 0.0.0.0/0", "set security nat source rule-set internal-to-internet rule catch-all then source-nat interface"} {
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
	if len(cfg.Security.NAT.Source) != 2 {
		t.Fatalf("got %d source rule-sets, want 2", len(cfg.Security.NAT.Source))
	}
	zones := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Source {
		zones[rs.FromZone] = true
		if rs.ToZone != "Internet-ATT" {
			t.Errorf("to-zone = %q, want Internet-ATT", rs.ToZone)
		}
	}
	if !zones["guest"] || !zones["lan"] {
		t.Errorf("from zones = %v, want guest + lan", zones)
	}
}

func TestNATSourceOff(t *testing.T) {
	input := `security {
    nat {
        source {
            rule-set exempt {
                from zone internal;
                to zone Internet;
                rule no-nat {
                    match {
                        source-address 192.203.228.0/24;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            off;
                        }
                    }
                }
                rule catch-all {
                    match {
                        source-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
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
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if len(rs.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs.Rules))
	}
	r0 := rs.Rules[0]
	if r0.Name != "no-nat" {
		t.Errorf("rule[0] name = %q, want no-nat", r0.Name)
	}
	if !r0.Then.Off {
		t.Error("rule[0] should have Then.Off = true")
	}
	if r0.Then.Interface {
		t.Error("rule[0] should NOT have Then.Interface")
	}
	r1 := rs.Rules[1]
	if !r1.Then.Interface {
		t.Error("rule[1] should have Then.Interface = true")
	}
	if r1.Then.Off {
		t.Error("rule[1] should NOT have Then.Off")
	}
}

func TestNATSourceOffSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security nat source rule-set exempt from zone internal", "set security nat source rule-set exempt to zone Internet", "set security nat source rule-set exempt rule no-nat match source-address 192.203.228.0/24", "set security nat source rule-set exempt rule no-nat then source-nat off"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
	}
	if len(cfg.Security.NAT.Source[0].Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(cfg.Security.NAT.Source[0].Rules))
	}
	r := cfg.Security.NAT.Source[0].Rules[0]
	if !r.Then.Off {
		t.Error("Then.Off should be true")
	}
	if r.Match.SourceAddress != "192.203.228.0/24" {
		t.Errorf("source address = %q, want 192.203.228.0/24", r.Match.SourceAddress)
	}
}

func TestDNATApplicationMatch(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool web-server {
                address 192.168.1.100/32;
            }
            rule-set internet-dnat {
                from zone untrust;
                rule app-match {
                    match {
                        destination-address 1.2.3.4/32;
                        application junos-http;
                    }
                    then {
                        destination-nat {
                            pool {
                                web-server;
                            }
                        }
                    }
                }
            }
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
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("no destination NAT config")
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 1 {
		t.Fatalf("got %d DNAT rule-sets, want 1", len(cfg.Security.NAT.Destination.RuleSets))
	}
	r := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if r.Match.Application != "junos-http" {
		t.Errorf("application = %q, want junos-http", r.Match.Application)
	}
	if r.Then.PoolName != "web-server" {
		t.Errorf("pool = %q, want web-server", r.Then.PoolName)
	}
}

func TestPolicyStatementNextHopAndLoadBalance(t *testing.T) {
	input := `policy-options {
    policy-statement load-balancing-policy {
        then {
            load-balance consistent-hash;
        }
    }
    policy-statement to-peer {
        term send-routes {
            from {
                protocol direct;
                prefix-list management-hosts;
                route-filter 10.0.0.0/8 exact;
            }
            then {
                next-hop peer-address;
                accept;
            }
        }
        then reject;
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	lb := cfg.PolicyOptions.PolicyStatements["load-balancing-policy"]
	if lb == nil {
		t.Fatal("load-balancing-policy not found")
	}
	peer := cfg.PolicyOptions.PolicyStatements["to-peer"]
	if peer == nil {
		t.Fatal("to-peer not found")
	}
	if len(peer.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(peer.Terms))
	}
	term := peer.Terms[0]
	if len(term.FromProtocols) != 1 || term.FromProtocols[0] != "direct" {
		t.Errorf("from protocol = %v, want [direct]", term.FromProtocols)
	}
	if term.PrefixList != "management-hosts" {
		t.Errorf("prefix-list = %q, want management-hosts", term.PrefixList)
	}
	if term.NextHop != "peer-address" {
		t.Errorf("next-hop = %q, want peer-address", term.NextHop)
	}
	if term.Action != "accept" {
		t.Errorf("action = %q, want accept", term.Action)
	}
	if len(term.RouteFilters) != 1 {
		t.Fatalf("got %d route-filters, want 1", len(term.RouteFilters))
	}
	if peer.DefaultAction != "reject" {
		t.Errorf("default action = %q, want reject", peer.DefaultAction)
	}
}

func TestPolicyStatementSetSyntax(t *testing.T) {
	cmds := []string{"set policy-options policy-statement lb then load-balance consistent-hash", "set policy-options policy-statement to-peer term t1 from protocol direct", "set policy-options policy-statement to-peer term t1 from prefix-list mgmt", "set policy-options policy-statement to-peer term t1 then next-hop peer-address", "set policy-options policy-statement to-peer term t1 then accept", "set policy-options policy-statement to-peer then reject"}
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
	peer := cfg.PolicyOptions.PolicyStatements["to-peer"]
	if peer == nil {
		t.Fatal("to-peer not found")
	}
	if len(peer.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(peer.Terms))
	}
	term := peer.Terms[0]
	if term.PrefixList != "mgmt" {
		t.Errorf("prefix-list = %q, want mgmt", term.PrefixList)
	}
	if term.NextHop != "peer-address" {
		t.Errorf("next-hop = %q, want peer-address", term.NextHop)
	}
	if term.Action != "accept" {
		t.Errorf("action = %q, want accept", term.Action)
	}
	lb := cfg.PolicyOptions.PolicyStatements["lb"]
	if lb == nil {
		t.Fatal("lb not found")
	}
}

func TestPolicyStatementRouteMapAttributesSetSyntax(t *testing.T) {
	cmds := []string{"set policy-options policy-statement PREFER-LOCAL term 10 from protocol bgp", "set policy-options policy-statement PREFER-LOCAL term 10 then local-preference 200", "set policy-options policy-statement PREFER-LOCAL term 10 then metric 100", "set policy-options policy-statement PREFER-LOCAL term 10 then community 65000:100", "set policy-options policy-statement PREFER-LOCAL term 10 then origin igp", "set policy-options policy-statement PREFER-LOCAL term 10 then accept"}
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
	ps := cfg.PolicyOptions.PolicyStatements["PREFER-LOCAL"]
	if ps == nil {
		t.Fatal("PREFER-LOCAL not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	term := ps.Terms[0]
	if len(term.FromProtocols) != 1 || term.FromProtocols[0] != "bgp" {
		t.Errorf("from protocol = %v, want [bgp]", term.FromProtocols)
	}
	if term.LocalPreference != 200 {
		t.Errorf("local-preference = %d, want 200", term.LocalPreference)
	}
	if term.Metric != 100 {
		t.Errorf("metric = %d, want 100", term.Metric)
	}
	if term.Community != "65000:100" {
		t.Errorf("community = %q, want 65000:100", term.Community)
	}
	if term.Origin != "igp" {
		t.Errorf("origin = %q, want igp", term.Origin)
	}
	if term.Action != "accept" {
		t.Errorf("action = %q, want accept", term.Action)
	}
}

func TestSecurityZoneTCPRst(t *testing.T) {
	input := `
security {
    zones {
        security-zone trust {
            tcp-rst;
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/1.0;
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
	if !cfg.Security.Zones["trust"].TCPRst {
		t.Error("trust zone tcp-rst should be true")
	}
	if cfg.Security.Zones["untrust"].TCPRst {
		t.Error("untrust zone tcp-rst should be false")
	}
}

func TestSSHKnownHostsAndPolicyStats(t *testing.T) {
	input := `
security {
    ssh-known-hosts {
        host 192.168.0.253 {
            ecdsa-sha2-nistp256-key AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY;
        }
    }
    policy-stats {
        system-wide enable;
    }
    pre-id-default-policy {
        then {
            log {
                session-close;
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
	if len(cfg.Security.SSHKnownHosts) != 1 {
		t.Fatalf("ssh-known-hosts count = %d, want 1", len(cfg.Security.SSHKnownHosts))
	}
	keys := cfg.Security.SSHKnownHosts["192.168.0.253"]
	if len(keys) != 1 {
		t.Fatalf("host keys count = %d, want 1", len(keys))
	}
	if keys[0].Type != "ecdsa-sha2-nistp256-key" {
		t.Errorf("key type = %q", keys[0].Type)
	}
	if !cfg.Security.PolicyStatsEnabled {
		t.Error("policy-stats should be enabled")
	}
	pidp := cfg.Security.PreIDDefaultPolicy
	if pidp == nil {
		t.Fatal("pre-id-default-policy is nil")
	}
	if pidp.LogSessionInit {
		t.Error("session-init should be false")
	}
	if !pidp.LogSessionClose {
		t.Error("session-close should be true")
	}
}

func TestRAPreferenceAndNAT64Lifetime(t *testing.T) {
	input := `protocols {
    router-advertisement {
        interface reth2.0 {
            prefix 2001:db8::/64;
            preference high;
            nat64prefix 64:ff9b::/96 {
                lifetime 600;
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
		t.Fatal(err)
	}
	if len(cfg.Protocols.RouterAdvertisement) == 0 {
		t.Fatal("no RA interfaces")
	}
	ra := cfg.Protocols.RouterAdvertisement[0]
	if ra.Preference != "high" {
		t.Errorf("Preference = %q, want high", ra.Preference)
	}
	if ra.NAT64Prefix != "64:ff9b::/96" {
		t.Errorf("NAT64Prefix = %q, want 64:ff9b::/96", ra.NAT64Prefix)
	}
	if ra.NAT64PrefixLife != 600 {
		t.Errorf("NAT64PrefixLife = %d, want 600", ra.NAT64PrefixLife)
	}
}

func TestNATAddressPersistent(t *testing.T) {
	input := `security {
    nat {
        source {
            address-persistent;
            pool my-pool {
                address 10.0.0.1/32;
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
		t.Fatal(err)
	}
	if !cfg.Security.NAT.AddressPersistent {
		t.Error("AddressPersistent should be true")
	}
}

func TestDNATMultiPort(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool web-server {
                address 10.0.1.100/32;
                address port 80;
            }
            rule-set untrust-dnat {
                from zone untrust;
                rule multi-port {
                    match {
                        destination-address 10.0.2.10/32;
                        destination-port {
                            32400;
                            443;
                        }
                    }
                    then {
                        destination-nat pool web-server;
                    }
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
		t.Fatal(err)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("Destination NAT is nil")
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 1 {
		t.Fatalf("RuleSets = %d, want 1", len(cfg.Security.NAT.Destination.RuleSets))
	}
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) != 1 {
		t.Fatalf("Rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Match.DestinationPort != 32400 {
		t.Errorf("DestinationPort = %d, want 32400", rule.Match.DestinationPort)
	}
	if len(rule.Match.DestinationPorts) != 2 {
		t.Fatalf("DestinationPorts = %d, want 2", len(rule.Match.DestinationPorts))
	}
	if rule.Match.DestinationPorts[0] != 32400 || rule.Match.DestinationPorts[1] != 443 {
		t.Errorf("DestinationPorts = %v, want [32400, 443]", rule.Match.DestinationPorts)
	}
}

func findZonePair(policies []* // findZonePair finds a ZonePairPolicies by "from→to" key in the slice.
ZonePairPolicies, key string) *ZonePairPolicies {
	parts := strings.SplitN(key, "→", 2)
	if len(parts) != 2 {
		return nil
	}
	for _, p := range policies {
		if p.FromZone == parts[0] && p.ToZone == parts[1] {
			return p
		}
	}
	return nil
}

func TestIPsecAggressiveModeSetSyntax(t *testing.T) {
	cmds := []string{"set security ike proposal ike-phase1 authentication-method pre-shared-keys", "set security ike proposal ike-phase1 encryption-algorithm aes-256-cbc", "set security ike proposal ike-phase1 authentication-algorithm sha-256", "set security ike proposal ike-phase1 dh-group group14", "set security ike policy ike-pol mode aggressive", "set security ike policy ike-pol proposals ike-phase1", "set security ike policy ike-pol pre-shared-key ascii-text secret123", "set security ike gateway gw1 address 203.0.113.1", "set security ike gateway gw1 local-address 198.51.100.1", "set security ike gateway gw1 ike-policy ike-pol", "set security ike gateway gw1 external-interface wan0", "set security ike gateway gw1 version v1-only", "set security ike gateway gw1 dynamic hostname peer.example.com", "set security ipsec vpn site-a ike gateway gw1", "set security ipsec vpn site-a df-bit copy", "set security ipsec vpn site-a establish-tunnels immediately", "set security ipsec vpn site-a bind-interface st0.0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ikePol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if ikePol == nil {
		t.Fatal("IKE policy ike-pol not found")
	}
	if ikePol.Mode != "aggressive" {
		t.Errorf("IKE policy mode = %q, want %q", ikePol.Mode, "aggressive")
	}
	if ikePol.PSK != "secret123" {
		t.Errorf("IKE policy PSK = %q, want %q", ikePol.PSK, "secret123")
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("gateway gw1 not found")
	}
	if gw.LocalAddress != "198.51.100.1" {
		t.Errorf("gateway local-address = %q, want %q", gw.LocalAddress, "198.51.100.1")
	}
	if gw.DynamicHostname != "peer.example.com" {
		t.Errorf("gateway dynamic hostname = %q, want %q", gw.DynamicHostname, "peer.example.com")
	}
	if gw.Version != "v1-only" {
		t.Errorf("gateway version = %q, want %q", gw.Version, "v1-only")
	}
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("VPN site-a not found")
	}
	if vpn.DFBit != "copy" {
		t.Errorf("VPN df-bit = %q, want %q", vpn.DFBit, "copy")
	}
	if vpn.EstablishTunnels != "immediately" {
		t.Errorf("VPN establish-tunnels = %q, want %q", vpn.EstablishTunnels, "immediately")
	}
	if vpn.BindInterface != "st0.0" {
		t.Errorf("VPN bind-interface = %q, want %q", vpn.BindInterface, "st0.0")
	}
	if vpn.Gateway != "gw1" {
		t.Errorf("VPN gateway = %q, want %q", vpn.Gateway, "gw1")
	}
}

func TestDNATSourceAddressName(t *testing.T) {
	input := `security {
    address-book {
        global {
            address srv1 10.0.1.100/32;
            address-set net_todd_control4 {
                address srv1;
            }
        }
    }
    nat {
        destination {
            pool host_control4 {
                address 10.0.30.100;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule todd-control4 {
                    match {
                        source-address-name net_todd_control4;
                        destination-address 50.220.171.30/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat pool host_control4;
                    }
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
		t.Fatal(err)
	}
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		t.Fatal("DNAT config nil")
	}
	if len(dnat.RuleSets) != 1 {
		t.Fatalf("want 1 rule-set, got %d", len(dnat.RuleSets))
	}
	rule := dnat.RuleSets[0].Rules[0]
	if rule.Match.SourceAddressName != "net_todd_control4" {
		t.Errorf("SourceAddressName = %q, want net_todd_control4", rule.Match.SourceAddressName)
	}
	if rule.Match.DestinationAddress != "50.220.171.30/32" {
		t.Errorf("DestinationAddress = %q, want 50.220.171.30/32", rule.Match.DestinationAddress)
	}
	if rule.Match.DestinationPort != 80 {
		t.Errorf("DestinationPort = %d, want 80", rule.Match.DestinationPort)
	}
}

func TestDNATSourceAddressNameSetSyntax(t *testing.T) {
	lines := []string{"set security nat destination pool web1 address 10.0.30.100", "set security nat destination rule-set wan-dnat from zone untrust", "set security nat destination rule-set wan-dnat rule r1 match source-address-name mynet", "set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32", "set security nat destination rule-set wan-dnat rule r1 match destination-port 443", "set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1"}
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
		t.Fatal(err)
	}
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		t.Fatal("DNAT config nil")
	}
	rule := dnat.RuleSets[0].Rules[0]
	if rule.Match.SourceAddressName != "mynet" {
		t.Errorf("SourceAddressName = %q, want mynet", rule.Match.SourceAddressName)
	}
}

func TestDNATPortRange(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool host1 {
                address 10.0.30.100;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule port-range {
                    match {
                        destination-address 50.220.171.30/32;
                        destination-port {
                            80;
                            443;
                            20000 to 20005;
                        }
                    }
                    then {
                        destination-nat pool host1;
                    }
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
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if len(rule.Match.DestinationPorts) != 8 {
		t.Fatalf("DestinationPorts = %v (len %d), want 8", rule.Match.DestinationPorts, len(rule.Match.DestinationPorts))
	}
	if rule.Match.DestinationPort != 80 {
		t.Errorf("DestinationPort = %d, want 80", rule.Match.DestinationPort)
	}
	if rule.Match.DestinationPorts[2] != 20000 {
		t.Errorf("port[2] = %d, want 20000", rule.Match.DestinationPorts[2])
	}
	if rule.Match.DestinationPorts[7] != 20005 {
		t.Errorf("port[7] = %d, want 20005", rule.Match.DestinationPorts[7])
	}
}

func TestDNATPortRangeSetSyntax(t *testing.T) {
	lines := []string{"set security nat destination pool web1 address 10.0.30.100", "set security nat destination rule-set wan-dnat from zone untrust", "set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32", "set security nat destination rule-set wan-dnat rule r1 match destination-port 80", "set security nat destination rule-set wan-dnat rule r1 match destination-port 443", "set security nat destination rule-set wan-dnat rule r1 match destination-port 20000 to 20003", "set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1"}
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
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if len(rule.Match.DestinationPorts) != 6 {
		t.Fatalf("DestinationPorts = %v (len %d), want 6", rule.Match.DestinationPorts, len(rule.Match.DestinationPorts))
	}
}

func TestDNATProtocolGRE(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool gre-host {
                address 10.0.30.50;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule gre-dnat {
                    match {
                        destination-address 209.237.133.188/32;
                        protocol gre;
                    }
                    then {
                        destination-nat pool gre-host;
                    }
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
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if rule.Match.Protocol != "gre" {
		t.Errorf("Protocol = %q, want gre", rule.Match.Protocol)
	}
}

func TestDNATProtocolICMP6(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool icmp-host {
                address 2001:db8::100;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule icmp6-dnat {
                    match {
                        destination-address 2001:db8::1/128;
                        protocol icmp6;
                    }
                    then {
                        destination-nat pool icmp-host;
                    }
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
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if rule.Match.Protocol != "icmp6" {
		t.Errorf("Protocol = %q, want icmp6", rule.Match.Protocol)
	}
}

func TestSNATMultipleSourceAddressBracketList(t *testing.T) {
	input := `
security {
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address [ 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ];
                    }
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("expected 1 rule-set, got %d", len(cfg.Security.NAT.Source))
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Match.SourceAddress != "10.0.0.0/8" {
		t.Errorf("SourceAddress = %q, want 10.0.0.0/8", rules[0].Match.SourceAddress)
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(rules[0].Match.SourceAddresses) != len(want) {
		t.Fatalf("SourceAddresses len = %d, want %d", len(rules[0].Match.SourceAddresses), len(want))
	}
	for i, w := range want {
		if rules[0].Match.SourceAddresses[i] != w {
			t.Errorf("SourceAddresses[%d] = %q, want %q", i, rules[0].Match.SourceAddresses[i], w)
		}
	}
}

func TestSNATMultipleSourceAddressSetSyntax(t *testing.T) {
	lines := []string{"set security nat source rule-set rs1 from zone trust", "set security nat source rule-set rs1 to zone untrust", "set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8", "set security nat source rule-set rs1 rule r1 match source-address 172.16.0.0/12", "set security nat source rule-set rs1 rule r1 match source-address 192.168.0.0/16", "set security nat source rule-set rs1 rule r1 then source-nat interface"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.Security.NAT.Source) == 0 {
		t.Fatal("NAT source config is empty")
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(rules[0].Match.SourceAddresses) != len(want) {
		t.Fatalf("SourceAddresses len = %d, want %d", len(rules[0].Match.SourceAddresses), len(want))
	}
	for i, w := range want {
		if rules[0].Match.SourceAddresses[i] != w {
			t.Errorf("SourceAddresses[%d] = %q, want %q", i, rules[0].Match.SourceAddresses[i], w)
		}
	}
}

func TestDNATApplicationMatching(t *testing.T) {
	input := `
security {
    nat {
        destination {
            pool web-pool {
                address 10.0.1.100/32;
            }
            rule-set rs1 {
                from zone untrust;
                rule web-dnat {
                    match {
                        destination-address 203.0.113.1/32;
                        application junos-http;
                    }
                    then {
                        destination-nat pool web-pool;
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("NAT destination config is nil")
	}
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Match.Application != "junos-http" {
		t.Errorf("Application = %q, want junos-http", rules[0].Match.Application)
	}
	if rules[0].Match.DestinationAddress != "203.0.113.1/32" {
		t.Errorf("DestinationAddress = %q, want 203.0.113.1/32", rules[0].Match.DestinationAddress)
	}
}

func TestDNATApplicationSet(t *testing.T) {
	input := `
applications {
    application unifi-tcp-8080 {
        protocol tcp;
        destination-port 8080;
    }
    application unifi-udp-3478 {
        protocol udp;
        destination-port 3478;
    }
    application-set unifi-controller {
        application unifi-tcp-8080;
        application unifi-udp-3478;
    }
}
security {
    nat {
        destination {
            pool unifi-pool {
                address 10.0.1.50/32;
            }
            rule-set rs1 {
                from zone untrust;
                rule unifi-dnat {
                    match {
                        destination-address 203.0.113.10/32;
                        application unifi-controller;
                    }
                    then {
                        destination-nat pool unifi-pool;
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Match.Application != "unifi-controller" {
		t.Errorf("Application = %q, want unifi-controller", rules[0].Match.Application)
	}
	as, ok := cfg.Applications.ApplicationSets["unifi-controller"]
	if !ok {
		t.Fatal("application-set unifi-controller not found")
	}
	if len(as.Applications) != 2 {
		t.Errorf("application-set has %d members, want 2", len(as.Applications))
	}
	expanded, err := ExpandApplicationSet("unifi-controller", &cfg.Applications)
	if err != nil {
		t.Fatalf("expand application-set: %v", err)
	}
	if len(expanded) != 2 {
		t.Errorf("expanded to %d apps, want 2", len(expanded))
	}
}

func TestSNATDestinationAddressBracketList(t *testing.T) {
	input := `
security {
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address 10.0.0.0/8;
                        destination-address [ 203.0.113.0/24 198.51.100.0/24 ];
                    }
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Match.DestinationAddress != "203.0.113.0/24" {
		t.Errorf("DestinationAddress = %q, want 203.0.113.0/24", rules[0].Match.DestinationAddress)
	}
	want := []string{"203.0.113.0/24", "198.51.100.0/24"}
	if len(rules[0].Match.DestinationAddresses) != len(want) {
		t.Fatalf("DestinationAddresses len = %d, want %d", len(rules[0].Match.DestinationAddresses), len(want))
	}
	for i, w := range want {
		if rules[0].Match.DestinationAddresses[i] != w {
			t.Errorf("DestinationAddresses[%d] = %q, want %q", i, rules[0].Match.DestinationAddresses[i], w)
		}
	}
}

func TestSNATMultipleAddressPairsSetSyntax(t *testing.T) {
	lines := []string{"set security nat source rule-set rs1 from zone trust", "set security nat source rule-set rs1 to zone untrust", "set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8", "set security nat source rule-set rs1 rule r1 match source-address 172.16.0.0/12", "set security nat source rule-set rs1 rule r1 match destination-address 203.0.113.0/24", "set security nat source rule-set rs1 rule r1 match destination-address 198.51.100.0/24", "set security nat source rule-set rs1 rule r1 then source-nat off"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	wantSrc := []string{"10.0.0.0/8", "172.16.0.0/12"}
	if len(rules[0].Match.SourceAddresses) != len(wantSrc) {
		t.Fatalf("SourceAddresses len = %d, want %d", len(rules[0].Match.SourceAddresses), len(wantSrc))
	}
	for i, w := range wantSrc {
		if rules[0].Match.SourceAddresses[i] != w {
			t.Errorf("SourceAddresses[%d] = %q, want %q", i, rules[0].Match.SourceAddresses[i], w)
		}
	}
	wantDst := []string{"203.0.113.0/24", "198.51.100.0/24"}
	if len(rules[0].Match.DestinationAddresses) != len(wantDst) {
		t.Fatalf("DestinationAddresses len = %d, want %d", len(rules[0].Match.DestinationAddresses), len(wantDst))
	}
	for i, w := range wantDst {
		if rules[0].Match.DestinationAddresses[i] != w {
			t.Errorf("DestinationAddresses[%d] = %q, want %q", i, rules[0].Match.DestinationAddresses[i], w)
		}
	}
	if !rules[0].Then.Off {
		t.Error("expected Then.Off = true")
	}
}

func TestStaticNATInet(t *testing.T) {
	input := `
security {
    nat {
        static {
            rule-set nat64-test {
                from zone lan;
                rule ipv6-clients {
                    match {
                        source-address ::/0;
                        destination-address 64:ff9b::/96;
                    }
                    then {
                        static-nat {
                            inet;
                        }
                    }
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
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rs := cfg.Security.NAT.Static[0]
	if rs.FromZone != "lan" {
		t.Errorf("from-zone = %q, want lan", rs.FromZone)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
	rule := rs.Rules[0]
	if rule.Match != "64:ff9b::/96" {
		t.Errorf("match = %q, want 64:ff9b::/96", rule.Match)
	}
	if rule.SourceAddress != "::/0" {
		t.Errorf("source-address = %q, want ::/0", rule.SourceAddress)
	}
	if rule.Then != "inet" {
		t.Errorf("then = %q, want inet", rule.Then)
	}
}

func TestStaticNATInetSetSyntax(t *testing.T) {
	lines := []string{"set security nat static rule-set nat64 from zone lan", "set security nat static rule-set nat64 rule r1 match source-address ::/0", "set security nat static rule-set nat64 rule r1 match destination-address 64:ff9b::/96", "set security nat static rule-set nat64 rule r1 then static-nat inet"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "inet" {
		t.Errorf("then = %q, want inet", rule.Then)
	}
	if rule.SourceAddress != "::/0" {
		t.Errorf("source-address = %q, want ::/0", rule.SourceAddress)
	}
}

func TestNPTv6HierarchicalSyntax(t *testing.T) {
	input := `
security {
    nat {
        static {
            rule-set nptv6-test {
                from zone wan;
                rule r1 {
                    match {
                        destination-address 2001:db8:100::/48;
                    }
                    then {
                        static-nat {
                            nptv6-prefix {
                                fd01:0203:0405::/48;
                            }
                        }
                    }
                }
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rs := cfg.Security.NAT.Static[0]
	if rs.FromZone != "wan" {
		t.Errorf("from-zone = %q, want wan", rs.FromZone)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
	rule := rs.Rules[0]
	if !rule.IsNPTv6 {
		t.Error("expected IsNPTv6 = true")
	}
	if rule.Match != "2001:db8:100::/48" {
		t.Errorf("match = %q, want 2001:db8:100::/48", rule.Match)
	}
	if rule.Then != "fd01:0203:0405::/48" {
		t.Errorf("then = %q, want fd01:0203:0405::/48", rule.Then)
	}
}

func TestNPTv6SetSyntax(t *testing.T) {
	lines := []string{"set security nat static rule-set nptv6-rs from zone untrust", "set security nat static rule-set nptv6-rs rule r1 match destination-address 2602:fd41:0070::/48", "set security nat static rule-set nptv6-rs rule r1 then static-nat nptv6-prefix fd35:1940:0027::/48"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if !rule.IsNPTv6 {
		t.Error("expected IsNPTv6 = true")
	}
	if rule.Match != "2602:fd41:0070::/48" {
		t.Errorf("match = %q, want 2602:fd41:0070::/48", rule.Match)
	}
	if rule.Then != "fd35:1940:0027::/48" {
		t.Errorf("then = %q, want fd35:1940:0027::/48", rule.Then)
	}
}

func TestNATv6v4NoFragHeader(t *testing.T) {
	input := `
security {
    nat {
        natv6v4 {
            no-v6-frag-header;
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
		t.Fatal(err)
	}
	if cfg.Security.NAT.NATv6v4 == nil {
		t.Fatal("NATv6v4 is nil")
	}
	if !cfg.Security.NAT.NATv6v4.NoV6FragHeader {
		t.Error("NoV6FragHeader should be true")
	}
}

func TestNATv6v4SetSyntax(t *testing.T) {
	lines := []string{"set security nat natv6v4 no-v6-frag-header"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.NAT.NATv6v4 == nil {
		t.Fatal("NATv6v4 is nil")
	}
	if !cfg.Security.NAT.NATv6v4.NoV6FragHeader {
		t.Error("NoV6FragHeader should be true")
	}
}

func TestFlexibleMatchRange(t *testing.T) {
	input := `firewall {
    family inet {
        filter flex-test {
            term t1 {
                from {
                    flexible-match-range {
                        range proto-check {
                            match-start layer-3;
                            byte-offset 9;
                            bit-length 8;
                            match-value 0x11;
                            match-mask 0xFF;
                        }
                    }
                }
                then accept;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}
	f := cfg.Firewall.FiltersInet["flex-test"]
	if f == nil {
		t.Fatal("flex-test filter not found")
	}
	if len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(f.Terms))
	}
	fm := f.Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("FlexMatch is nil")
	}
	if fm.MatchStart != "layer-3" {
		t.Errorf("MatchStart = %q, want layer-3", fm.MatchStart)
	}
	if fm.ByteOffset != 9 {
		t.Errorf("ByteOffset = %d, want 9", fm.ByteOffset)
	}
	if fm.BitLength != 8 {
		t.Errorf("BitLength = %d, want 8", fm.BitLength)
	}
	if fm.Value != 0x11 {
		t.Errorf("Value = 0x%x, want 0x11", fm.Value)
	}
	if fm.Mask != 0xFF {
		t.Errorf("Mask = 0x%x, want 0xFF", fm.Mask)
	}
}

func TestFlexibleMatchRangeSetSyntax(t *testing.T) {
	lines := []string{"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 match-start layer-3", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 byte-offset 12", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 bit-length 32", "set firewall family inet filter flex-set term t1 from flexible-match-range range r1 range 0x0a000000/0xff000000", "set firewall family inet filter flex-set term t1 then discard"}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["flex-set"]
	if f == nil {
		t.Fatal("flex-set filter not found")
	}
	fm := f.Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("FlexMatch is nil")
	}
	if fm.ByteOffset != 12 {
		t.Errorf("ByteOffset = %d, want 12", fm.ByteOffset)
	}
	if fm.BitLength != 32 {
		t.Errorf("BitLength = %d, want 32", fm.BitLength)
	}
	if fm.Value != 0x0a000000 {
		t.Errorf("Value = 0x%x, want 0x0a000000", fm.Value)
	}
	if fm.Mask != 0xff000000 {
		t.Errorf("Mask = 0x%x, want 0xff000000", fm.Mask)
	}
}

func TestScreenSessionLimitCompilation(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set security screen ids-option wan-screen limit-session source-ip-based 100", "set security screen ids-option wan-screen limit-session destination-ip-based 200", "set security screen ids-option wan-screen tcp land"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	screen := cfg.Security.Screen["wan-screen"]
	if screen == nil {
		t.Fatal("missing screen profile wan-screen")
	}
	if screen.LimitSession.SourceIPBased != 100 {
		t.Errorf("SourceIPBased = %d, want 100", screen.LimitSession.SourceIPBased)
	}
	if screen.LimitSession.DestinationIPBased != 200 {
		t.Errorf("DestinationIPBased = %d, want 200", screen.LimitSession.DestinationIPBased)
	}
	if !screen.TCP.Land {
		t.Error("Land should be true")
	}
}

func TestScreenSessionLimitHierarchical(t *testing.T) {
	input := `
security {
    screen {
        ids-option test-screen {
            limit-session {
                source-ip-based 50;
                destination-ip-based 75;
            }
        }
    }
}
`
	tree, perrs := NewParser(input).Parse()
	if perrs != nil {
		t.Fatalf("parse error: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	screen := cfg.Security.Screen["test-screen"]
	if screen == nil {
		t.Fatal("missing screen profile test-screen")
	}
	if screen.LimitSession.SourceIPBased != 50 {
		t.Errorf("SourceIPBased = %d, want 50", screen.LimitSession.SourceIPBased)
	}
	if screen.LimitSession.DestinationIPBased != 75 {
		t.Errorf("DestinationIPBased = %d, want 75", screen.LimitSession.DestinationIPBased)
	}
}
