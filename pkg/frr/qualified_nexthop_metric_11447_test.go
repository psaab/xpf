package frr

import (
	"context"
	"errors"
	"log/slog"
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
func qnhMetricShowOutputNoMetric11447(sequence int) []byte {
	return []byte("permit, sequence " + strconv.Itoa(sequence) +
		" Invoked 0 (0 milliseconds total)\n Set clauses:\n")
}

func legacyQNHMetricConfig11447(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/qualified_nexthop_metric_legacy_55da4b506.conf")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestQNHMetricCleanupRecognizesRealLegacyIPv6Sequence11447(t *testing.T) {
	legacy := legacyQNHMetricConfig11447(t)
	sequences := qnhMetricSequencesFromConfig11447(legacy)
	const routeMap = "xpf-qnh-static-ec82feb6c470a32b-xpf-redist"
	for _, want := range []int{10, 20} {
		if _, ok := sequences[routeMap][want]; !ok {
			t.Errorf("legacy QNH sequence %d missing from cleanup identities: %v", want, sequences)
		}
	}
	broadcast := qnhMetricSequencesWithSetMetricFromConfig11447(legacy)
	for _, want := range []int{10, 20} {
		if _, ok := broadcast[routeMap][want]; !ok {
			t.Errorf("legacy QNH sequence %d missing from broadcast-metric identities: %v", want, broadcast)
		}
	}
	if _, ok := broadcast[routeMap][30]; ok {
		t.Fatalf("plain terminal sequence must not be treated as a broadcast metric identity: %v", broadcast)
	}
	if _, ok := sequences[routeMap][30]; ok {
		t.Fatalf("plain terminal sequence must not be treated as a QNH metric identity: %v", sequences)
	}

	clear := renderQNHMetricSequenceReconciliation11447(sequences,
		qnhMetricRouteMapSequencesFromConfig11447("route-map "+routeMap+" permit 10\n"))
	if !strings.Contains(clear, "no set metric") ||
		!strings.Contains(clear, "no route-map "+routeMap+" permit 20\n") {
		t.Fatalf("legacy v4/v6 metric actions must be cleared and the stale IPv6 sequence removed:\n%s", clear)
	}
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
	if len(overlays) != 1 || overlays["ospfd"] == "" {
		t.Fatalf("only OSPF may receive a QNH metric overlay, got %v", mapValues11447(overlays))
	}
	if !strings.Contains(overlays["ospfd"], "route-map "+qnhMap+" permit 10\n set metric 10\n") ||
		strings.Contains(overlays["ospfd"], "set metric 20\n") {
		t.Errorf("ospfd overlay must carry only the fully matched IPv4 QNH metric:\n%s", overlays["ospfd"])
	}
}

func TestQNHMetricRIPKeepsDefaultMetricWithWarning11447(t *testing.T) {
	var logs strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	rendered, overlays := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
		"set protocols rip redistribute static",
	)
	if len(overlays) != 1 || overlays["ospfd"] == "" {
		t.Fatalf("RIP must not receive a QNH metric overlay: %v", overlays)
	}
	if !strings.Contains(rendered, "router rip\n redistribute static route-map ") ||
		strings.Contains(rendered, " set metric ") {
		t.Fatalf("RIP must retain the metric-free route-map attachment:\n%s", rendered)
	}
	if !strings.Contains(logs.String(), "issue=#12071") ||
		!strings.Contains(logs.String(), "redistribution=static") ||
		!strings.Contains(logs.String(), "RIP receives its default metric") {
		t.Fatalf("RIP metric limitation warning omitted affected redistribution or default-metric impact: %s", logs.String())
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
	if qnhMap == "" || overlays["ospfd"] == "" || len(overlays) != 1 {
		t.Fatalf("fixture must render one shared QNH map and an OSPF-only overlay:\nbase:\n%s\noverlays:\n%v", base, overlays)
	}

	legacy := legacyQNHMetricConfig11447(t)
	if !strings.Contains(legacy, "route-map "+qnhMap+" permit 20\n match ipv6 address ") {
		t.Fatalf("base-rendered legacy fixture does not contain the expected IPv6 QNH sequence:\n%s", legacy)
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
			"ospfd": {
				{response: qnhMetricShowOutputNoMetric11447(10)},
				{response: qnhMetricShowOutput11447(10, 10)},
				{response: qnhMetricShowOutput11447(10, 10)},
				{response: nil},
			},
		},
	}
	m := New()
	m.frrConf = confPath
	m.exec = fake
	m.DisableDegradedRetry()
	t.Cleanup(m.Stop)

	if err := m.ApplyFull(fc); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("fallback apply error = %v, want ErrFRRReloadDegraded", err)
	}
	if got, want := strings.Join(fake.callOrder, ","), "reload,global-load,global-load,daemon-load:ospfd"; got != want {
		t.Fatalf("fallback operation order = %q, want %q", got, want)
	}
	if len(fake.globalLoads) != 2 || !strings.Contains(fake.globalLoads[1], "no set metric\n") {
		t.Fatalf("legacy metric cleanup must follow the successful additive load: %q", fake.globalLoads)
	}
	if len(fake.daemonLoads) != 1 || fake.daemonLoads[0].daemon != "ospfd" ||
		!strings.Contains(fake.daemonLoads[0].config, "set metric 10\n") {
		t.Fatalf("only ospfd should receive the positive QNH overlay: %+v", fake.daemonLoads)
	}
	if strings.Contains(fake.globalLoads[0], " set metric ") {
		t.Fatalf("the integrated load must remain metric-free:\n%s", fake.globalLoads[0])
	}
	installedConfig, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(installedConfig), " set metric ") {
		t.Fatalf("new integrated frr.conf retained a QNH metric action:\n%s", installedConfig)
	}

	if stop, notFound := m.retryReloadOnce(context.Background()); !stop || notFound {
		t.Fatalf("retry result = (%v, %v), want (converged, found)", stop, notFound)
	}
	if got, want := strings.Join(fake.callOrder[len(fake.callOrder)-2:], ","), "reload,daemon-load:ospfd"; got != want {
		t.Fatalf("full-diff retry must replay only OSPF's overlay: got %q, want %q", got, want)
	}

	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got, want := strings.Join(fake.callOrder[len(fake.callOrder)-2:], ","), "reload,global-load"; got != want {
		t.Fatalf("Clear operation order = %q, want %q", got, want)
	}
	if m.qnhMetricOverlays != nil {
		t.Fatalf("Clear retained desired QNH overlays: %v", m.qnhMetricOverlays)
	}
}

func TestQNHMetricCleanupVerifiesEveryKnownDaemon11447(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
	)
	fc := &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
	newManagerWithLegacy := func(t *testing.T, fake *fakeExecutor) *Manager {
		t.Helper()
		confPath := filepath.Join(t.TempDir(), "frr.conf")
		oldConfig := "log syslog informational\n" + markerBegin + "\n" +
			legacyQNHMetricConfig11447(t) + "\n" + markerEnd + "\n"
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
	metricFree := []byte("route-map: xpf-qnh-static-test\n permit, sequence 10\n Set clauses:\n")

	t.Run("reads back every known daemon", func(t *testing.T) {
		responses := make(map[string][]byte, len(qnhMetricCleanupDaemons11447))
		for _, daemon := range qnhMetricCleanupDaemons11447 {
			responses[daemon] = metricFree
		}
		fake := &fakeExecutor{
			daemonCommandResp: responses,
			daemonCommandResponseSeq: map[string][]daemonCommandResult{
				"ospfd": {
					{response: qnhMetricShowOutputNoMetric11447(10)},
					{response: qnhMetricShowOutput11447(10, 10)},
				},
			},
		}
		m := newManagerWithLegacy(t, fake)
		if err := m.ApplyFull(fc); err != nil {
			t.Fatalf("ApplyFull: %v", err)
		}
		if got, want := strings.Join(fake.callOrder, ","), "reload,global-load,daemon-load:ospfd"; got != want {
			t.Fatalf("reload/cleanup/overlay order = %q, want %q", got, want)
		}
		for _, daemon := range qnhMetricCleanupDaemons11447 {
			found := false
			for _, call := range fake.daemonCommands {
				if call.daemon == daemon && strings.HasPrefix(call.command, "show route-map ") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no route-map readback attempted for %s", daemon)
			}
			if daemon != "ospfd" && strings.Contains(strings.ToLower(string(responses[daemon])), "metric ") {
				t.Errorf("test fixture for %s accidentally contains a metric action", daemon)
			}
		}
		if len(fake.daemonLoads) != 1 || fake.daemonLoads[0].daemon != "ospfd" {
			t.Fatalf("only ospfd may receive a positive metric overlay: %+v", fake.daemonLoads)
		}
	})

	t.Run("unavailable copy is skipped", func(t *testing.T) {
		connectErr := errors.New("exit status 1")
		fake := &fakeExecutor{
			daemonCommandErr:  map[string]error{"ripngd": connectErr},
			daemonCommandResp: map[string][]byte{"ripngd": []byte("Exiting: failed to connect to any daemons.\n")},
			daemonCommandResponseSeq: map[string][]daemonCommandResult{
				"ospfd": {
					{response: qnhMetricShowOutputNoMetric11447(10)},
					{response: qnhMetricShowOutput11447(10, 10)},
				},
			},
		}
		m := newManagerWithLegacy(t, fake)
		if err := m.ApplyFull(fc); err != nil {
			t.Fatalf("ApplyFull with stopped ripngd: %v", err)
		}
	})

	t.Run("verification rejection remains hard", func(t *testing.T) {
		loadErr := errors.New("exit status 1")
		fake := &fakeExecutor{
			daemonCommandErr:  map[string]error{"fabricd": loadErr},
			daemonCommandResp: map[string][]byte{"fabricd": []byte("% Unknown command: show route-map\n")},
		}
		m := newManagerWithLegacy(t, fake)
		err := m.ApplyFull(fc)
		if !errors.Is(err, loadErr) || !strings.Contains(err.Error(), "fabricd") {
			t.Fatalf("fabricd metric readback error = %v, want hard verification failure", err)
		}
		if got, want := strings.Join(fake.callOrder, ","), "reload,global-load"; got != want {
			t.Fatalf("overlay must not apply after failed cleanup verification: got %q, want %q", got, want)
		}
	})
}

func TestQNHMetricPartialOverlayRetryReloadsBeforeReplay11447(t *testing.T) {
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
	loadErr := errors.New("ospfd overlay load failed")
	fake := &fakeExecutor{
		daemonLoadErrByDaemon: map[string]error{"ospfd": loadErr},
		daemonCommandResp:     map[string][]byte{"ospfd": qnhMetricShowOutput11447(10, 10)},
	}
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	m.exec = fake
	m.DisableDegradedRetry()
	t.Cleanup(m.Stop)

	if err := m.ApplyFull(fc); !errors.Is(err, loadErr) {
		t.Fatalf("ApplyFull error = %v, want the failed OSPF overlay load", err)
	}
	if got, want := strings.Join(fake.callOrder, ","), "reload,daemon-load:ospfd"; got != want {
		t.Fatalf("partial overlay operation order = %q, want %q", got, want)
	}
	if len(m.qnhMetricOverlayCleanup) == 0 {
		t.Fatal("partial overlay failure did not retain QNH sequence identities for retry cleanup")
	}

	delete(fake.daemonLoadErrByDaemon, "ospfd")
	if stop, notFound := m.retryReloadOnce(context.Background()); !stop || notFound {
		t.Fatalf("retry result = (%v, %v), want (converged, found)", stop, notFound)
	}
	if got, want := strings.Join(fake.callOrder[len(fake.callOrder)-2:], ","), "reload,daemon-load:ospfd"; got != want {
		t.Fatalf("retry must reload before replaying only OSPF's overlay: got %q, want %q", got, want)
	}
	if len(fake.globalLoads) != 0 {
		t.Fatalf("retry unexpectedly used an integrated QNH overlay load: %q", fake.globalLoads)
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
