package config

import "testing"

// #8939, the IPsec family. SIX readers under `security ike` / `security ipsec`
// dropped every leaf after the first of a flat `set` command. All six are in
// compiler_ipsec.go; they were found by compiling each container by hand, and
// THREE of them are not in the #8939 ratchet fixture (see below).
//
//	set security ipsec vpn v1 ike gateway G ipsec-policy P
//	  -> gateway="G"  ipsec-policy=""
//
// REACHABILITY, MEASURED, because it is not uniform across this family and the
// severity does not survive the assumption that it is. `SchemaValidate*` runs
// HARD on the operator commit path (compileTreeStrict) and downgrades to a
// slog.Warn on Store.Load and Store.SyncApply (compileTreeLenient says so in
// its own comment). Through configstore.CheckText:
//
//	security ike gateway g1 { bogus-token 5; }        -> ACCEPTED
//	security ipsec vpn v1   { bogus-token 5; }        -> ACCEPTED
//	security flow tcp-session { bogus-token 5; }      -> rejected, closed world
//
// So `security ike gateway` and `security ipsec vpn` are OPEN-WORLD subtrees:
// the packed spelling reaches the compiler from an ordinary operator commit.
// The closed-world containers below (`vpn-monitor`, `traffic-selector`,
// `dead-peer-detection`) reject the packed spelling at commit and reach this
// code only via the tolerant ingress -- boot from the persisted DB, and HA
// config sync from the peer, where no operator is watching. Both channels are
// real; they are not the same claim, and this cell does not conflate them.
//
// THREE LEAVES WHEREVER A THIRD EXISTS. At two leaves a flat run is
// indistinguishable from ordinary nesting, so a recursive descent passes; the
// third leaf packs onto ONE node's Keys and only a keyword-delimited scan
// reaches it (#9079).
func TestIPsecFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg
	}
	vpnOf := func(t *testing.T, cfg *Config) *IPsecVPN {
		t.Helper()
		v := cfg.Security.IPsec.VPNs["v1"]
		if v == nil {
			t.Fatal("the command produced no vpn (#8939)")
		}
		return v
	}

	t.Run("vpn ike", func(t *testing.T) {
		b := "set security ipsec vpn v1 ike "
		ref := vpnOf(t, build(t, b+"gateway G", b+"ipsec-policy P"))
		if ref.Gateway == "" || ref.IPsecPolicy == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
				"below would pass against a vpn that carries nothing (#8939)", ref)
		}
		got := vpnOf(t, build(t, b+"gateway G ipsec-policy P"))
		if got.Gateway != ref.Gateway {
			t.Errorf("ike gateway = %q, want %q (#8939)", got.Gateway, ref.Gateway)
		}
		// Phase-2 crypto. Dropped, the tunnel negotiates the strongSwan
		// default proposal set instead of the configured policy -- the same
		// failure the ike-policy reference gate spells out for phase-1.
		if got.IPsecPolicy != ref.IPsecPolicy {
			t.Errorf("ike ipsec-policy = %q, want %q (#8939)", got.IPsecPolicy, ref.IPsecPolicy)
		}
	})

	t.Run("vpn top level", func(t *testing.T) {
		// The VPN's own leaf set includes the direct `gateway` and
		// `ipsec-policy` references. #10327 declares those compiler-read leaves
		// so packed SetPath runs and the nested block form retain the same
		// values; the split-arm comparison below pins every reader shape.
		b := "set security ipsec vpn v1 "
		ref := vpnOf(t, build(t, b+"bind-interface st0.1", b+"df-bit clear",
			b+"establish-tunnels immediately", b+"local-address 10.0.0.1",
			b+"gateway G", b+"ipsec-policy P"))
		if ref.BindInterface == "" || ref.DFBit == "" || ref.EstablishTunnels == "" ||
			ref.LocalAddr == "" || ref.Gateway == "" || ref.IPsecPolicy == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		got := vpnOf(t, build(t, b+"bind-interface st0.1 df-bit clear "+
			"establish-tunnels immediately local-address 10.0.0.1 "+
			"gateway G ipsec-policy P"))
		if got.BindInterface != ref.BindInterface || got.DFBit != ref.DFBit ||
			got.EstablishTunnels != ref.EstablishTunnels || got.LocalAddr != ref.LocalAddr ||
			got.Gateway != ref.Gateway || got.IPsecPolicy != ref.IPsecPolicy {
			t.Errorf("packed vpn = %+v, want the split arm's %+v (#8939)", got, ref)
		}
	})

	t.Run("vpn-monitor", func(t *testing.T) {
		b := "set security ipsec vpn v1 vpn-monitor "
		ref := vpnOf(t, build(t, b+"destination-ip 192.0.2.9", b+"optimized",
			b+"source-interface ge-0/0/0"))
		if !ref.VPNMonitor || ref.VPNMonitorDestinationIP == "" ||
			!ref.VPNMonitorOptimized || ref.VPNMonitorSourceInterface == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "destination-ip 192.0.2.9 optimized"},
			{"three leaves", b + "destination-ip 192.0.2.9 optimized source-interface ge-0/0/0"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := vpnOf(t, build(t, tc.cmd))
				if got.VPNMonitorDestinationIP != ref.VPNMonitorDestinationIP {
					t.Errorf("destination-ip = %q, want %q (#8939)",
						got.VPNMonitorDestinationIP, ref.VPNMonitorDestinationIP)
				}
				if got.VPNMonitorOptimized != ref.VPNMonitorOptimized {
					t.Errorf("optimized = %v, want %v (#8939)",
						got.VPNMonitorOptimized, ref.VPNMonitorOptimized)
				}
				if tc.name == "three leaves" &&
					got.VPNMonitorSourceInterface != ref.VPNMonitorSourceInterface {
					t.Errorf("source-interface = %q, want %q -- this is the leaf a "+
						"recursive descent drops (#8939)",
						got.VPNMonitorSourceInterface, ref.VPNMonitorSourceInterface)
				}
			})
		}
	})

	t.Run("traffic-selector", func(t *testing.T) {
		b := "set security ipsec vpn v1 traffic-selector ts1 "
		refTS := vpnOf(t, build(t, b+"local-ip 10.0.0.0/8", b+"remote-ip 172.16.0.0/12")).
			TrafficSelectors["ts1"]
		if refTS == nil || refTS.LocalIP == "" || refTS.RemoteIP == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", refTS)
		}
		gotTS := vpnOf(t, build(t, b+"local-ip 10.0.0.0/8 remote-ip 172.16.0.0/12")).
			TrafficSelectors["ts1"]
		if gotTS == nil {
			t.Fatalf("the packed command produced no traffic-selector (#8939)")
		}
		if gotTS.LocalIP != refTS.LocalIP || gotTS.RemoteIP != refTS.RemoteIP {
			t.Errorf("packed selector = %+v, want %+v (#8939)", gotTS, refTS)
		}
	})

	t.Run("dead-peer-detection", func(t *testing.T) {
		// BOTH gateway containers, through ONE shared reader
		// (parseDeadPeerDetectionNode). The gateway loops around it are
		// DUPLICATED -- that was the #9077 finding -- so asserting both is
		// what proves the shared reader is genuinely shared here.
		for _, base := range []string{
			"set security ike gateway g1 dead-peer-detection ",
			"set security ipsec gateway g1 dead-peer-detection ",
		} {
			t.Run(base, func(t *testing.T) {
				gwOf := func(cfg *Config) *IPsecGateway {
					g := cfg.Security.IPsec.Gateways["g1"]
					if g == nil {
						t.Fatal("the command produced no gateway (#8939)")
					}
					return g
				}
				ref := gwOf(build(t, base+"always-send", base+"interval 10", base+"threshold 4"))
				if !ref.DPDEnable || ref.DeadPeerDetect == "" || ref.DPDInterval == 0 || ref.DPDThreshold == 0 {
					t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
				}
				for _, tc := range []struct{ name, cmd string }{
					{"two leaves", base + "always-send interval 10"},
					{"three leaves", base + "always-send interval 10 threshold 4"},
				} {
					t.Run(tc.name, func(t *testing.T) {
						got := gwOf(build(t, tc.cmd))
						if got.DeadPeerDetect != ref.DeadPeerDetect {
							t.Errorf("mode = %q, want %q (#8939)", got.DeadPeerDetect, ref.DeadPeerDetect)
						}
						// Tuned DPD timers. Dropped, DPD stays enabled and
						// silently reverts to the defaults, so peer loss is
						// detected later than the operator configured.
						if got.DPDInterval != ref.DPDInterval {
							t.Errorf("interval = %d, want %d (#8939)", got.DPDInterval, ref.DPDInterval)
						}
						if tc.name == "three leaves" && got.DPDThreshold != ref.DPDThreshold {
							t.Errorf("threshold = %d, want %d -- the leaf a recursive "+
								"descent drops (#8939)", got.DPDThreshold, ref.DPDThreshold)
						}
					})
				}
			})
		}
	})
}

// TestIPsecTrafficSelectorGateReadsTheRun8939 is the half of the
// traffic-selector fix that is NOT in the compiler, and without it the
// compiler half is INERT.
//
// validateIPsecTrafficSelectorsStrict (#4098/#5692) walks the same children.
// On the flat spelling the remote-ip node nests UNDER local-ip, so
// trafficSelectorValues counted `remote-ip` as a second local-ip VALUE and the
// gate rejected the command NAMING THE WRONG PROBLEM:
//
//	local-ip "remote-ip" is not a valid CIDR prefix, host address, or IP range
//
// A wrong diagnostic is worse than a missing one: it sends the operator to
// look at a prefix that is fine. This asserts the gate now reads the run the
// operator typed.
//
// The #5692 duplicate-prefix rejects this gate exists for are asserted
// unchanged in compiler_ipsec_ts_dup_5692_test.go: expandFlatRun only splits a
// node whose Keys carry a further schema sibling, and repeated sibling leaves
// arrive as separate children with no sibling keyword in their Keys.
//
// WHAT THIS DELIBERATELY DOES NOT ASSERT: that the packed spelling is
// ADMISSIBLE. `traffic-selector` is a CLOSED-WORLD subtree, so the typed-leaf
// schema walk rejects the trailing `remote-ip` before this gate is reached on
// the operator commit path. That rejection is a separate, campaign-level
// question (is the closed-world walk right to refuse a flat run at all?) and
// it is not settled by a compiler change. It is logged, not asserted, so this
// cell does not go RED when that decision lands either way.
func TestIPsecTrafficSelectorGateReadsTheRun8939(t *testing.T) {
	tree := &ConfigTree{}
	const cmd = "set security ipsec vpn v1 traffic-selector ts1 " +
		"local-ip 10.0.0.0/8 remote-ip 172.16.0.0/12"
	p, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(p); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("the #4098/#5692 admission gate rejected the packed "+
			"traffic-selector: %v\nThe compiler-side walk is inert while this "+
			"rejects (#8939).", err)
	}
	if err := SchemaValidateWithDefinitions(tree, tree, nil); err != nil {
		t.Logf("NOTE: the typed-leaf schema walk still refuses this spelling on the "+
			"operator commit path (%v), so the fix above is reached via Store.Load "+
			"and Store.SyncApply. Not asserted -- see the comment.", err)
	}
}
