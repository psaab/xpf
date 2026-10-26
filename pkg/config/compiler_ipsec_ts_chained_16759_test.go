package config

import (
	"strings"
	"testing"
)

// #16759: a traffic-selector chained after other VPN leaves in one flat
// set command --
//
//	set security ipsec vpn v1 gateway gw1 ipsec-policy epol1
//	    bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24
//	    remote-ip 10.2.0.0/24
//
// is nested inside the run by SetPath. compileIPsec read only direct
// FindChildren("traffic-selector") and validateIPsecTrafficSelectorsStrict
// did the same, so the selector was lost with no error, EffectiveTraffic-
// Selectors widened the route-based SA to any<->any, and the #4098/#5692
// shape gate was bypassed. These tests require the chained spelling to
// compile and validate exactly like the split spelling. Reuses the
// #14684 preamble/buildTree (preamble14684, buildTree14684).

func selectors16759(t *testing.T, cfg *Config) map[string]*IPsecTrafficSelector {
	t.Helper()
	vpn := cfg.Security.IPsec.VPNs["v1"]
	if vpn == nil {
		t.Fatal("no vpn v1 compiled")
	}
	return vpn.TrafficSelectors
}

func TestIPsecChainedTrafficSelectorCompiles16759(t *testing.T) {
	forms := map[string][]string{
		"chained-full": {
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24",
		},
		"chained-bind-only": {
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1",
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24",
		},
		"ts-own-run": {
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0",
			"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24",
		},
		"ts-after-bind-split-value": {
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1",
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24",
		},
	}
	for name, cmds := range forms {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree14684(t, cmds...))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			sel := selectors16759(t, cfg)
			if len(sel) != 1 {
				t.Fatalf("TrafficSelectors=%v, want exactly ts1", sel)
			}
			ts := sel["ts1"]
			if ts == nil || ts.LocalIP != "10.1.0.0/24" || ts.RemoteIP != "10.2.0.0/24" {
				t.Fatalf("ts1=%+v, want local 10.1.0.0/24 remote 10.2.0.0/24", ts)
			}
		})
	}

	t.Run("split control unchanged", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1",
			"set security ipsec vpn v1 ipsec-policy epol1",
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.1.0.0/24",
			"set security ipsec vpn v1 traffic-selector ts1 remote-ip 10.2.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "10.1.0.0/24" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("split TrafficSelectors=%v", sel)
		}
	})

	t.Run("braced control unchanged", func(t *testing.T) {
		tree := parseHierText(t, `security {
  ike {
    proposal p1 { authentication-method pre-shared-keys; encryption-algorithm aes-256-cbc; authentication-algorithm sha-256; dh-group group14; }
    policy ike-pol { proposals p1; pre-shared-key ascii-text secret123; }
    gateway gw1 { ike-policy ike-pol; address 192.0.2.1; }
  }
  ipsec {
    proposal esp1 { protocol esp; encryption-algorithm aes-256-gcm; }
    policy epol1 { proposals esp1; }
    vpn v1 {
      gateway gw1;
      ipsec-policy epol1;
      bind-interface st0.0;
      traffic-selector ts1 { local-ip 10.1.0.0/24; remote-ip 10.2.0.0/24; }
    }
  }
}`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "10.1.0.0/24" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("braced TrafficSelectors=%v", sel)
		}
	})

	t.Run("chained masked padding canonicalized", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/08 remote-ip 10.2.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ts := selectors16759(t, cfg)["ts1"]
		if ts == nil {
			t.Fatal("chained selector ts1 missing; want canonicalized local-ip 10.1.0.0/8 (#12507)")
		}
		if ts.LocalIP != "10.1.0.0/8" {
			t.Fatalf("chained local-ip canonicalized to %q, want 10.1.0.0/8 (#12507)", ts.LocalIP)
		}
	})

	// #17802: distinct same-named selector fragments chained in
	// different packed runs (gateway run carries local-ip, bind-interface
	// run carries remote-ip) are NOT duplicate sightings: the old
	// name+header-Keys dedup discarded the second body, silently
	// widening the missing side. The fragments must merge into one
	// selector with both authored prefixes.
	t.Run("same-named chained fragments across runs merge", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 traffic-selector ts1 local-ip 10.1.0.0/24",
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 remote-ip 10.2.0.0/24",
			"set security ipsec vpn v1 ipsec-policy epol1",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "10.1.0.0/24" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("same-named fragments TrafficSelectors=%v, want ts1 local 10.1.0.0/24 remote 10.2.0.0/24 merged (#17802)", sel)
		}
	})

	// #17802 control: an IDENTICAL same-named chained fragment in a
	// second run is a duplicate re-sighting and must still dedup
	// (compile once, no #5692 double-count).
	t.Run("identical same-named chained fragment deduped", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24",
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfig identical re-sighting: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "10.1.0.0/24" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("identical re-sighting TrafficSelectors=%v, want single ts1 (#17802)", sel)
		}
	})

	// #17802: direct (split) fragment plus chained fragment of the
	// same name, in both authoring orders, must merge.
	t.Run("direct plus chained same-named fragments merge", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0",
			"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.1.0.0/24",
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 remote-ip 10.2.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "10.1.0.0/24" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("direct+chained TrafficSelectors=%v, want merged ts1 (#17802)", sel)
		}
	})

	t.Run("chained plus direct same-named fragments merge", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24",
			"set security ipsec vpn v1 traffic-selector ts1 remote-ip 10.2.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "10.1.0.0/24" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("chained+direct TrafficSelectors=%v, want merged ts1 (#17802)", sel)
		}
	})
}

func TestIPsecChainedTrafficSelectorValidated16759(t *testing.T) {
	t.Run("strict invalid chained local-ip rejected", func(t *testing.T) {
		_, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 traffic-selector ts1 local-ip not-a-prefix remote-ip 10.2.0.0/24",
		))
		if err == nil {
			t.Fatal("CompileConfig accepted chained traffic-selector with local-ip not-a-prefix; want #4098 reject (#16759)")
		}
		if !strings.Contains(err.Error(), "#4098") || !strings.Contains(err.Error(), "ts1") {
			t.Fatalf("reject %q should name ts1 and #4098", err.Error())
		}
	})

	t.Run("strict invalid own-run local-ip rejected as control", func(t *testing.T) {
		_, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 traffic-selector ts1 local-ip not-a-prefix remote-ip 10.2.0.0/24",
		))
		if err == nil {
			t.Fatal("control: own-run invalid local-ip unexpectedly accepted")
		}
	})

	t.Run("lenient invalid chained warns and still compiles selector", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 traffic-selector ts1 local-ip not-a-prefix remote-ip 10.2.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfigLenient must not fail on persisted chained config (#1960): %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#4098") && strings.Contains(w, "ts1") {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient chained invalid selector produced no #4098 warning; warnings=%v", cfg.Warnings)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 1 || sel["ts1"].LocalIP != "not-a-prefix" || sel["ts1"].RemoteIP != "10.2.0.0/24" {
			t.Fatalf("lenient TrafficSelectors=%v, want ts1 kept verbatim", sel)
		}
	})

	t.Run("chained duplicate local-ip rejected", func(t *testing.T) {
		// Two local-ip values packed in the chained run: the compiler
		// keeps only the last, so the #5692 gate must reject.
		_, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24 local-ip 10.3.0.0/24 remote-ip 10.2.0.0/24",
		))
		if err == nil {
			t.Fatal("CompileConfig accepted chained selector with two local-ip values; want #5692 reject (#16759)")
		}
		if !strings.Contains(err.Error(), "#5692") {
			t.Fatalf("reject %q should name #5692", err.Error())
		}
	})

	t.Run("two chained named selectors accumulate", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24 remote-ip 10.2.0.0/24 traffic-selector ts2 local-ip 10.3.0.0/24 remote-ip 10.4.0.0/24",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		sel := selectors16759(t, cfg)
		if len(sel) != 2 || sel["ts1"].RemoteIP != "10.2.0.0/24" || sel["ts2"].LocalIP != "10.3.0.0/24" {
			t.Fatalf("chained two-selector TrafficSelectors=%v", sel)
		}
	})

	t.Run("invalid second same-named chained fragment rejected", func(t *testing.T) {
		_, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 traffic-selector ts1 local-ip 10.1.0.0/24",
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 remote-ip not-a-prefix",
			"set security ipsec vpn v1 ipsec-policy epol1",
		))
		if err == nil {
			t.Fatal("CompileConfig accepted invalid second same-named chained fragment; want #4098 reject (#17802)")
		}
		if !strings.Contains(err.Error(), "#4098") || !strings.Contains(err.Error(), "not-a-prefix") {
			t.Fatalf("reject %q should identify invalid second fragment and #4098", err.Error())
		}
	})

	t.Run("conflicting second same-named chained fragment rejected", func(t *testing.T) {
		_, err := CompileConfig(buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 traffic-selector ts1 local-ip 10.1.0.0/24",
			"set security ipsec vpn v1 bind-interface st0.0 traffic-selector ts1 local-ip 10.3.0.0/24 remote-ip 10.2.0.0/24",
			"set security ipsec vpn v1 ipsec-policy epol1",
		))
		if err == nil {
			t.Fatal("CompileConfig accepted conflicting same-named fragments; want #5692 reject (#17802)")
		}
		if !strings.Contains(err.Error(), "#5692") || !strings.Contains(err.Error(), "ts1") {
			t.Fatalf("reject %q should identify conflicting ts1 fragment and #5692", err.Error())
		}
	})
}

