package frr

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func compileQNHMetricConfig11447(t *testing.T, commands ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return compiled
}

func qnhMetricShowOutput11447(sequence, metric int) []byte {
	return []byte("permit, sequence " + strconv.Itoa(sequence) +
		" Invoked 0 (0 milliseconds total)\n Set clauses:\n  metric " +
		strconv.Itoa(metric) + "\n")
}

func qnhMetricRender11447(t *testing.T, commands ...string) string {
	t.Helper()
	compiled := compileQNHMetricConfig11447(t, commands...)
	return New().buildManagedSection(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
}

func qnhMetricRenderAndOverlays11447(t *testing.T, commands ...string) (string, map[string]string) {
	t.Helper()
	compiled := compileQNHMetricConfig11447(t, commands...)
	return New().buildManagedSectionWithQNH11447(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		OSPFv3:        compiled.Protocols.OSPFv3,
		RIP:           compiled.Protocols.RIP,
		ISIS:          compiled.Protocols.ISIS,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
}

func routeMapBlock11447(rendered, name string) string {
	var block strings.Builder
	inMap := false
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, "route-map ") {
			isTarget := strings.HasPrefix(line, "route-map "+name+" ")
			if inMap && !isTarget {
				break
			}
			if isTarget {
				inMap = true
			}
		}
		if inMap {
			block.WriteString(line)
			block.WriteByte('\n')
		}
		if inMap && line == "!" {
			break
		}
	}
	return block.String()
}

func TestQualifiedNextHopMetricReachesStaticRedistribution11447(t *testing.T) {
	rendered, overlays := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
	)
	if !strings.Contains(rendered, "redistribute static route-map ") {
		t.Fatalf("static OSPF export has no synthesized route-map for QNH metric:\n%s", rendered)
	}
	if strings.Contains(rendered, "set metric 10\n") {
		t.Fatalf("integrated FRR config must keep the QNH metric action out of all daemon copies:\n%s", rendered)
	}
	if !strings.Contains(rendered, "match ip next-hop prefix-list ") {
		t.Fatalf("QNH base route-map must distinguish the qualified gateway, not only the destination:\n%s", rendered)
	}
	if !strings.Contains(overlays["ospfd"], "set metric 10\n") {
		t.Fatalf("ospfd QNH overlay omitted the configured metric:\n%v", overlays)
	}
}

func TestQualifiedNextHopMetricDoesNotSetBGPMetric11447(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols bgp local-as 65001",
		"set protocols bgp export static",
	)
	rendered := New().buildManagedSection(&FullConfig{
		BGP:           compiled.Protocols.BGP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if !strings.Contains(rendered, "redistribute static\n") {
		t.Fatalf("BGP static redistribution was lost:\n%s", rendered)
	}
	if strings.Contains(rendered, "redistribute static route-map ") {
		t.Fatalf("qualified-next-hop IGP metric must not become BGP MED:\n%s", rendered)
	}
}

func TestQualifiedNextHopMetricDoesNotOverrideAuthoredPolicyMetric11447(t *testing.T) {
	rendered, overlays := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export EXPORT-STATIC",
		"set policy-options policy-statement EXPORT-STATIC term SET-METRIC from protocol static",
		"set policy-options policy-statement EXPORT-STATIC term SET-METRIC then metric 100",
		"set policy-options policy-statement EXPORT-STATIC term SET-METRIC then accept",
		"set policy-options policy-statement EXPORT-STATIC term SET-CONNECTED from protocol connected",
		"set policy-options policy-statement EXPORT-STATIC term SET-CONNECTED then metric 200",
		"set policy-options policy-statement EXPORT-STATIC term SET-CONNECTED then accept",
	)
	var mapName string
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute static route-map ") {
			mapName = strings.TrimPrefix(line, "redistribute static route-map ")
			break
		}
	}
	if mapName == "" {
		t.Fatalf("static policy export lacks a route-map:\n%s", rendered)
	}
	block := routeMapBlock11447(rendered, mapName)
	if strings.Contains(block, "match source-protocol ") {
		t.Fatalf("QNH static redistribute map must use its attachment instead of a source-protocol clause:\n%s", block)
	}
	if strings.Contains(block, "set metric 10\n") {
		t.Fatalf("the QNH metric action belongs in the ospfd-only overlay:\n%s", block)
	}
	if strings.Contains(block, "set metric 200\n") {
		t.Fatalf("QNH static redistribute map included a connected-only policy term:\n%s", block)
	}
	if !strings.Contains(block, "set metric 100\n") {
		t.Fatalf("authored static policy metric was not retained in integrated config:\n%s", block)
	}
	overlay := overlays["ospfd"]
	if !strings.Contains(overlay, "route-map "+mapName+" permit 10\n set metric 10\n") ||
		strings.Contains(overlay, "set metric 100\n") {
		t.Fatalf("the daemon overlay must contain only the generated QNH action, not authored policy actions:\n%s", overlay)
	}
}

func TestQualifiedNextHopMetricMatchesGatewayNotOnlyPrefix11447(t *testing.T) {
	rendered := qnhMetricRender11447(t,
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1",
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.2 metric 10",
		"set protocols ospf export static",
	)
	if !strings.Contains(rendered, "ip prefix-list ") || !strings.Contains(rendered, "192.0.2.2/32") {
		t.Fatalf("route-map must define an exact gateway match for the metric-bearing qualified next-hop:\n%s", rendered)
	}
	if strings.Contains(rendered, "permit 192.0.2.1/32") {
		t.Fatalf("plain primary next-hop must not be assigned the qualified next-hop metric:\n%s", rendered)
	}
}

func TestQualifiedNextHopMetricSupportsHostAndIPv6Routes11447(t *testing.T) {
	t.Run("IPv4 host route", func(t *testing.T) {
		rendered := qnhMetricRender11447(t,
			"set routing-options static route 203.0.113.7 qualified-next-hop 192.0.2.10 metric 10",
			"set protocols ospf export static",
		)
		if !strings.Contains(rendered, "203.0.113.7/32") || !strings.Contains(rendered, "192.0.2.10/32") {
			t.Fatalf("host route QNH metric must match normalized destination and gateway prefixes:\n%s", rendered)
		}
	})

	t.Run("IPv6 route", func(t *testing.T) {
		compiled := compileQNHMetricConfig11447(t,
			"set routing-options static route 2001:db8:10::/64 qualified-next-hop 2001:db8::10 metric 10",
			"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0",
			"set protocols ospf3 export static",
		)
		rendered := New().buildManagedSection(&FullConfig{
			OSPFv3:        compiled.Protocols.OSPFv3,
			StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
			PolicyOptions: &compiled.PolicyOptions,
		})
		if !strings.Contains(rendered, "router ospf6\n redistribute static\n") ||
			strings.Contains(rendered, "redistribute static route-map ") ||
			strings.Contains(rendered, "match ipv6 address prefix-list ") ||
			strings.Contains(rendered, "match ipv6 next-hop prefix-list ") ||
			strings.Contains(rendered, "set metric 10\n") {
			t.Fatalf("OSPFv3 cannot evaluate the IPv6 next-hop discriminator, so its redistribution must not attach a QNH metric map:\n%s", rendered)
		}
	})
}

func TestQualifiedNextHopMetricGatesIGPsByMatchCapability12071(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set routing-options static route 2001:db8:10::/64 qualified-next-hop 2001:db8::10 metric 20",
		"set protocols ospf export static",
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf3 export static",
		"set protocols rip group g neighbor ge-0/0/0.0",
		"set protocols rip redistribute static",
		"set protocols isis interface ge-0/0/0.0",
		"set protocols isis export static",
	)
	rendered, overlays := New().buildManagedSectionWithQNH11447(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		OSPFv3:        compiled.Protocols.OSPFv3,
		RIP:           compiled.Protocols.RIP,
		ISIS:          compiled.Protocols.ISIS,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})

	var qnhMap string
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute static route-map ") {
			qnhMap = strings.TrimPrefix(line, "redistribute static route-map ")
			break
		}
	}
	if qnhMap == "" {
		t.Fatalf("OSPF static export must attach the QNH metric map:\n%s", rendered)
	}
	if !strings.Contains(rendered, "router ospf\n redistribute static route-map "+qnhMap+"\n") ||
		!strings.Contains(rendered, "router rip\n network ge-0/0/0.0\n redistribute static route-map "+qnhMap+"\n") {
		t.Fatalf("the fully capable IPv4 daemons must attach the shared QNH metric map:\n%s", rendered)
	}
	if !strings.Contains(rendered, "router ospf6\n redistribute static\n") ||
		strings.Contains(rendered, "router ospf6\n redistribute static route-map "+qnhMap) ||
		!strings.Contains(rendered, "redistribute ipv4 static level-2\n") ||
		strings.Contains(rendered, "redistribute ipv4 static level-2 route-map "+qnhMap) ||
		strings.Contains(rendered, "redistribute ipv6 static level-2 route-map "+qnhMap) {
		t.Fatalf("OSPFv3 and IS-IS must not attach the QNH map without next-hop match support:\n%s", rendered)
	}
	mapBlock := routeMapBlock11447(rendered, qnhMap)
	if !strings.Contains(mapBlock, "match ip address prefix-list ") ||
		!strings.Contains(mapBlock, "match ip next-hop prefix-list ") ||
		strings.Contains(mapBlock, "set metric ") ||
		strings.Contains(mapBlock, "match ipv6 ") {
		t.Fatalf("integrated QNH map must contain only metric-free, fully discriminated IPv4 sequences:\n%s", mapBlock)
	}
	if len(overlays) != 2 {
		t.Fatalf("metric overlays must target exactly ospfd and ripd, got %v", mapValues11447(overlays))
	}
	for _, daemon := range []string{"ospfd", "ripd"} {
		overlay := overlays[daemon]
		if !strings.Contains(overlay, "route-map "+qnhMap+" permit 10\n set metric 10\n") ||
			strings.Contains(overlay, "set metric 20\n") {
			t.Errorf("%s overlay must carry only the fully matched IPv4 QNH metric:\n%s", daemon, overlay)
		}
	}
}

func TestQNHMetricManagerFallbackRetryAndClear11447(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
		"set protocols rip redistribute static",
	)
	fc := &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		RIP:           compiled.Protocols.RIP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
	base, overlays := New().buildManagedSectionWithQNH11447(fc)
	var qnhMap string
	for _, line := range strings.Split(base, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute static route-map ") {
			qnhMap = strings.TrimPrefix(line, "redistribute static route-map ")
			break
		}
	}
	if qnhMap == "" || overlays["ospfd"] == "" || overlays["ripd"] == "" {
		t.Fatalf("fixture must render one shared QNH map and both capable-daemon overlays:\nbase:\n%s\noverlays:\n%v", base, overlays)
	}

	// Simulate the pre-fix integrated config, with a metric action present in
	// every daemon's shared route-map copy.
	legacy := strings.Replace(base, " on-match next\n", " set metric 10\n on-match next\n", 1)
	if legacy == base {
		t.Fatal("fixture did not contain a QNH on-match sequence to seed")
	}
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	oldConfig := "log syslog informational\n" + markerBegin + "\n" + legacy + "\n" + markerEnd + "\n"
	if err := os.WriteFile(confPath, []byte(oldConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	reloadErr := errors.New("frr-reload.py unavailable")
	fake := &fakeExecutor{
		frrReloadPyHook: func(call int) error {
			if call == 1 {
				return reloadErr
			}
			return nil
		},
		daemonCommandResponseSeq: map[string][]daemonCommandResult{
			"ripd": {
				{},
				{response: qnhMetricShowOutput11447(10, 10)},
				{response: qnhMetricShowOutput11447(10, 10)},
				{},
			},
		},
		daemonCommandCallCount: make(map[string]int),
	}
	m := New()
	m.frrConf = confPath
	m.exec = fake
	m.DisableDegradedRetry()
	t.Cleanup(m.Stop)

	if err := m.ApplyFull(fc); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("fallback apply error = %v, want ErrFRRReloadDegraded", err)
	}
	wantApplyOrder := "daemon-load:ospfd,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd,global-load,reload,global-load,daemon-load:ospfd,global-load,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd"
	if got := strings.Join(fake.callOrder, ","); got != wantApplyOrder {
		t.Fatalf("fallback operation order = %q, want %q", got, wantApplyOrder)
	}
	if len(fake.daemonLoads) != 8 {
		t.Fatalf("targeted config loads = %d, want four clears, ospfd overlay, and three post-overlay capability clears", len(fake.daemonLoads))
	}
	for _, call := range fake.daemonLoads[:4] {
		if !strings.Contains(call.config, "route-map "+qnhMap+" permit 10\n") ||
			!strings.Contains(call.config, "no set metric\n") ||
			strings.Contains(call.config, " set metric ") {
			t.Errorf("%s clear was not restricted to the old QNH sequence:\n%s", call.daemon, call.config)
		}
	}
	if call := fake.daemonLoads[4]; call.daemon != "ospfd" || !strings.Contains(call.config, "set metric 10\n") {
		t.Errorf("ospfd overlay = %+v, want daemon-scoped metric 10", call)
	}
	for _, call := range fake.daemonLoads[5:] {
		if !strings.Contains(call.config, "no set metric\n") || strings.Contains(call.config, "\n set metric ") {
			t.Errorf("%s did not receive only the post-overlay metric cleanup:\n%s", call.daemon, call.config)
		}
	}
	if got := fake.globalLoads[2]; !strings.Contains(got, "set metric 10\n") {
		t.Fatalf("integrated ripd overlay = %q, want metric 10", got)
	}
	installedConfig, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(installedConfig), "set metric 10\n") {
		t.Fatalf("new integrated frr.conf retained the QNH metric action:\n%s", installedConfig)
	}

	// A full-diff retry wipes the overlays and Manager must restore both.
	if stop, notFound := m.retryReloadOnce(context.Background()); !stop || notFound {
		t.Fatalf("retry result = (%v, %v), want (converged, found)", stop, notFound)
	}
	wantRetryTail := "reload,daemon-load:ospfd,global-load,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd"
	if got := strings.Join(fake.callOrder[len(fake.callOrder)-6:], ","); got != wantRetryTail {
		t.Fatalf("retry did not restore both supported-daemon overlays and scrub unsupported copies: got %q, want %q", got, wantRetryTail)
	}

	// Clear removes manager-owned actions on all daemon copies, including the
	// ripd copy whose daemon-scoped load silently no-ops on FRR 10.7.
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	wantClearTail := "daemon-load:ospfd,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd,global-load,reload"
	if got := strings.Join(fake.callOrder[len(fake.callOrder)-6:], ","); got != wantClearTail {
		t.Fatalf("Clear operation order = %q, want %q", got, wantClearTail)
	}
	if m.qnhMetricOverlays != nil {
		t.Fatalf("Clear retained desired QNH overlays: %v", m.qnhMetricOverlays)
	}
}

func TestQNHMetricPartialDaemonCleanup11447(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
	)
	fc := &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
	newManager := func(t *testing.T, fake *fakeExecutor) *Manager {
		t.Helper()
		base, _ := New().buildManagedSectionWithQNH11447(fc)
		legacy := strings.Replace(base, " on-match next\n", " set metric 10\n on-match next\n", 1)
		if legacy == base {
			t.Fatal("fixture did not contain a QNH on-match sequence to seed")
		}
		confPath := filepath.Join(t.TempDir(), "frr.conf")
		oldConfig := "log syslog informational\n" + markerBegin + "\n" + legacy + "\n" + markerEnd + "\n"
		if err := os.WriteFile(confPath, []byte(oldConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		m := New()
		m.frrConf = confPath
		m.exec = fake
		m.DisableDegradedRetry()
		t.Cleanup(m.Stop)
		return m
	}

	ripCompiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
		"set protocols rip redistribute static",
	)
	ripFC := &FullConfig{
		OSPF:          ripCompiled.Protocols.OSPF,
		RIP:           ripCompiled.Protocols.RIP,
		StaticRoutes:  ripCompiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &ripCompiled.PolicyOptions,
	}
	newRipManager := func(t *testing.T, fake *fakeExecutor) *Manager {
		t.Helper()
		m := New()
		m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
		m.exec = fake
		m.DisableDegradedRetry()
		t.Cleanup(m.Stop)
		return m
	}
	connectErr := errors.New("exit status 1")
	connectOutput := []byte("Exiting: failed to connect to any daemons.\n")
	absentDaemons := []string{"ospf6d", "isisd", "bgpd"}

	t.Run("skips absent clear daemons and keeps commits/removal working", func(t *testing.T) {
		fake := &fakeExecutor{
			daemonLoadErrByDaemon:  make(map[string]error),
			daemonLoadRespByDaemon: make(map[string][]byte),
		}
		for _, daemon := range absentDaemons {
			fake.daemonLoadErrByDaemon[daemon] = connectErr
			fake.daemonLoadRespByDaemon[daemon] = connectOutput
		}
		m := newManager(t, fake)
		if err := m.ApplyFull(fc); err != nil {
			t.Fatalf("partial-daemon ApplyFull: %v", err)
		}
		wantFirstApply := "daemon-load:ospfd,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd,global-load,reload,daemon-load:ospfd"
		if got := strings.Join(fake.callOrder, ","); got != wantFirstApply {
			t.Fatalf("partial-daemon call order = %q, want %q", got, wantFirstApply)
		}
		call := fake.daemonLoads[0]
		if !strings.Contains(call.config, "no set metric\n") ||
			strings.Contains(call.config, "\n set metric ") {
			t.Errorf("running daemon %s did not receive stale-metric cleanup:\n%s", call.daemon, call.config)
		}
		if len(fake.globalLoads) != 1 || !strings.Contains(fake.globalLoads[0], "no set metric\n") {
			t.Fatalf("integrated clear must remove stale ripd metric actions: %q", fake.globalLoads)
		}

		if err := m.ApplyFull(fc); err != nil {
			t.Fatalf("second ApplyFull with absent cleanup daemons: %v", err)
		}
		if err := m.Clear(); err != nil {
			t.Fatalf("Clear with absent cleanup daemons: %v", err)
		}
	})

	t.Run("configuration load errors remain hard", func(t *testing.T) {
		loadErr := errors.New("exit status 1")
		fake := &fakeExecutor{
			daemonLoadErrByDaemon: map[string]error{"isisd": loadErr},
			daemonLoadRespByDaemon: map[string][]byte{
				"isisd": []byte("% Unknown command: route-map\n"),
			},
		}
		m := newManager(t, fake)
		err := m.ApplyFull(fc)
		if !errors.Is(err, loadErr) || errors.Is(err, errQNHMetricDaemonUnavailable11447) {
			t.Fatalf("config rejection error = %v, want a hard non-connect load failure", err)
		}
		if fake.frrReloadPyCalls != 0 {
			t.Fatalf("reload ran after a hard QNH clear error: %d calls", fake.frrReloadPyCalls)
		}
	})

	t.Run("overlay connection errors remain strict", func(t *testing.T) {
		fake := &fakeExecutor{
			daemonLoadErrByDaemon: map[string]error{"ospfd": connectErr},
			daemonLoadRespByDaemon: map[string][]byte{
				"ospfd": connectOutput,
			},
		}
		m := newManager(t, fake)
		err := m.ApplyFull(fc)
		if !errors.Is(err, errQNHMetricDaemonUnavailable11447) ||
			!strings.Contains(err.Error(), "apply QNH metric overlay to ospfd") {
			t.Fatalf("unavailable overlay error = %v, want strict ospfd overlay failure", err)
		}
	})

	t.Run("ripd integrated rc-zero no-op is rejected", func(t *testing.T) {
		fake := &fakeExecutor{
			daemonCommandResp: map[string][]byte{"ripd": qnhMetricShowOutput11447(10, 9)},
		}
		m := newRipManager(t, fake)
		err := m.ApplyFull(ripFC)
		if err == nil || !strings.Contains(err.Error(), "ripd route-map") ||
			!strings.Contains(err.Error(), "metrics [9], want exactly [10]") {
			t.Fatalf("silent ripd overlay no-op error = %v, want exact post-verify mismatch", err)
		}
	})

	t.Run("ripd overlay connection errors remain strict", func(t *testing.T) {
		fake := &fakeExecutor{
			daemonCommandResp: map[string][]byte{"ripd": connectOutput},
			daemonCommandErr:  map[string]error{"ripd": connectErr},
		}
		m := newRipManager(t, fake)
		err := m.ApplyFull(ripFC)
		if !errors.Is(err, errQNHMetricDaemonUnavailable11447) ||
			!strings.Contains(err.Error(), "verify QNH metric overlay on ripd") {
			t.Fatalf("unavailable ripd overlay error = %v, want a strict verified-overlay failure", err)
		}
	})
}

func TestQNHMetricPartialOverlayIsClearedBeforeRetry11447(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
		"set protocols rip redistribute static",
	)
	fc := &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		RIP:           compiled.Protocols.RIP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
	loadErr := errors.New("ripd overlay load failed")
	fake := &fakeExecutor{
		vtyshLoadErr: loadErr,
		daemonCommandResponseSeq: map[string][]daemonCommandResult{
			"ripd": {
				{},
				{response: qnhMetricShowOutput11447(10, 10)},
			},
		},
	}
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	m.exec = fake
	m.DisableDegradedRetry()
	t.Cleanup(m.Stop)

	if err := m.ApplyFull(fc); !errors.Is(err, loadErr) {
		t.Fatalf("ApplyFull error = %v, want the failed integrated RIP overlay load", err)
	}
	if got, want := strings.Join(fake.callOrder, ","), "reload,daemon-load:ospfd,global-load"; got != want {
		t.Fatalf("partial overlay operation order = %q, want %q", got, want)
	}
	if len(m.qnhMetricOverlayCleanup) == 0 {
		t.Fatal("partial overlay failure did not retain QNH sequence identities for retry cleanup")
	}

	fake.vtyshLoadErr = nil
	if stop, notFound := m.retryReloadOnce(context.Background()); !stop || notFound {
		t.Fatalf("retry result = (%v, %v), want (converged, found)", stop, notFound)
	}
	wantRetry := "daemon-load:ospfd,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd,global-load,reload,daemon-load:ospfd,global-load,daemon-load:ospf6d,daemon-load:isisd,daemon-load:bgpd"
	if got := strings.Join(fake.callOrder[len(fake.callOrder)-11:], ","); got != wantRetry {
		t.Fatalf("retry did not clear the partial overlay before reloading and replaying: got %q, want %q", got, wantRetry)
	}
	for _, call := range fake.daemonLoads[1:5] {
		if !strings.Contains(call.config, "no set metric\n") || strings.Contains(call.config, "\n set metric ") {
			t.Errorf("%s retry cleanup was not limited to removing the prior QNH action:\n%s", call.daemon, call.config)
		}
	}
	for _, call := range fake.daemonLoads[6:9] {
		if !strings.Contains(call.config, "no set metric\n") || strings.Contains(call.config, "\n set metric ") {
			t.Errorf("%s post-overlay cleanup contained a metric-bearing command:\n%s", call.daemon, call.config)
		}
	}
	if got := fake.globalLoads[2]; !strings.Contains(got, "set metric 10\n") {
		t.Fatalf("retry did not use integrated vtysh for ripd overlay: %q", got)
	}
	if len(m.qnhMetricOverlayCleanup) != 0 {
		t.Fatalf("successful overlay replay left cleanup pending: %v", m.qnhMetricOverlayCleanup)
	}
}

func TestFRRLoadQualifiedNextHopMetric11447(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("FRR config check runs as root")
	}
	bgpd := os.Getenv("FRR_BGPD_BINARY")
	if bgpd == "" {
		var err error
		bgpd, err = exec.LookPath("bgpd")
		if err != nil {
			for _, candidate := range []string{"/usr/lib/frr/bgpd", "/usr/libexec/frr/bgpd"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					bgpd = candidate
					break
				}
			}
		}
	}
	if bgpd == "" {
		t.Skip("FRR bgpd is not installed; config-load validation unavailable")
	}
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols bgp local-as 65001",
		"set protocols bgp export static",
	)
	rendered := New().buildManagedSection(&FullConfig{
		BGP:           compiled.Protocols.BGP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if !strings.Contains(rendered, "redistribute static\n") ||
		strings.Contains(rendered, "redistribute static route-map ") ||
		strings.Contains(rendered, "set metric 10\n") {
		t.Fatalf("BGP receives the metric-free shared QNH map but no QNH attachment or metric action:\n%s", rendered)
	}
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, bgpd, "-C", "-f", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("FRR bgpd rejected the metric-free QNH redistribution config: %v\n%s\nconfig:\n%s", err, output, rendered)
	}
}

func TestFRRLoadOSPFQualifiedNextHopMetric11447(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("FRR config check runs as root")
	}
	ospfd := os.Getenv("FRR_OSPFD_BINARY")
	if ospfd == "" {
		var err error
		ospfd, err = exec.LookPath("ospfd")
		if err != nil {
			for _, candidate := range []string{"/usr/lib/frr/ospfd", "/usr/libexec/frr/ospfd"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					ospfd = candidate
					break
				}
			}
		}
	}
	if ospfd == "" {
		t.Skip("FRR ospfd is not installed; config-load validation unavailable")
	}
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf router-id 10.255.0.1",
		"set protocols ospf export static",
	)
	rendered, overlays := New().buildManagedSectionWithQNH11447(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if !strings.Contains(rendered, "redistribute static route-map ") ||
		!strings.Contains(rendered, "match ip next-hop prefix-list ") ||
		strings.Contains(rendered, "set metric 10\n") ||
		!strings.Contains(overlays["ospfd"], "set metric 10\n") {
		t.Fatalf("compiled OSPF export must split the metric-free base from its targeted overlay:\nbase:\n%s\noverlay:\n%s", rendered, overlays["ospfd"])
	}
	// vtysh's per-daemon load merges these same sequence headers, so checking
	// the composed file here validates both command grammars with the daemon's
	// own parser; the live test below checks the installed effective copy.
	effectiveConfig := rendered + "\n" + overlays["ospfd"]
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte(effectiveConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, ospfd, "-C", "-f", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("FRR ospfd rejected the composed QNH config: %v\n%s\nconfig:\n%s", err, output, effectiveConfig)
	}
}
