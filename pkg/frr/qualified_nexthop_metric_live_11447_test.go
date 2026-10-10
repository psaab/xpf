package frr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestQualifiedNextHopMetricAppearsInOSPFLSDB11447(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("live FRR LSDB validation requires root and network namespaces")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2 is unavailable for isolated OSPF validation")
	}
	zebra := liveFRRBinary11447(t, "FRR_ZEBRA_BINARY", "/usr/lib/frr/zebra", "/usr/libexec/frr/zebra")
	staticd := liveFRRBinary11447(t, "FRR_STATICD_BINARY", "/usr/lib/frr/staticd", "/usr/libexec/frr/staticd")
	ospfd := liveFRRBinary11447(t, "FRR_OSPFD_BINARY", "/usr/lib/frr/ospfd", "/usr/libexec/frr/ospfd")
	ospf6d := liveFRRBinary11447(t, "FRR_OSPF6D_BINARY", "/usr/lib/frr/ospf6d", "/usr/libexec/frr/ospf6d")
	ripd := liveFRRBinary11447(t, "FRR_RIPD_BINARY", "/usr/lib/frr/ripd", "/usr/libexec/frr/ripd")
	isisd := liveFRRBinary11447(t, "FRR_ISISD_BINARY", "/usr/lib/frr/isisd", "/usr/libexec/frr/isisd")
	bgpd := liveFRRBinary11447(t, "FRR_BGPD_BINARY", "/usr/lib/frr/bgpd", "/usr/libexec/frr/bgpd")
	mgmtd := liveFRRBinary11447(t, "FRR_MGMTD_BINARY", "/usr/lib/frr/mgmtd", "/usr/libexec/frr/mgmtd")
	ripngd := liveFRRBinary11447(t, "FRR_RIPNGD_BINARY", "/usr/lib/frr/ripngd")
	eigrpd := liveFRRBinary11447(t, "FRR_EIGRPD_BINARY", "/usr/lib/frr/eigrpd")
	fabricd := liveFRRBinary11447(t, "FRR_FABRICD_BINARY", "/usr/lib/frr/fabricd")
	pimd := liveFRRBinary11447(t, "FRR_PIMD_BINARY", "/usr/lib/frr/pimd")
	pim6d := liveFRRBinary11447(t, "FRR_PIM6D_BINARY", "/usr/lib/frr/pim6d")
	babeld := liveFRRBinary11447(t, "FRR_BABELD_BINARY", "/usr/lib/frr/babeld")
	pbrd := liveFRRBinary11447(t, "FRR_PBRD_BINARY", "/usr/lib/frr/pbrd")
	vrrpd := liveFRRBinary11447(t, "FRR_VRRPD_BINARY", "/usr/lib/frr/vrrpd")
	bfdd := liveFRRBinary11447(t, "FRR_BFDD_BINARY", "/usr/lib/frr/bfdd")
	vtysh, err := exec.LookPath("vtysh")
	if err != nil {
		t.Skip("FRR vtysh is unavailable for isolated OSPF validation")
	}

	for i, tc := range []struct {
		name         string
		exportPolicy bool
		ripExport    bool
		primary      bool
		wantMetric   int
	}{
		{name: "OSPF-only daemon-scoped overlay", wantMetric: 10},
		{name: "authored policy override survives QNH shrink", exportPolicy: true, wantMetric: 100},
		{name: "RIP default metric; no broadcast", ripExport: true, wantMetric: 10},
		{name: "primary active then QNH backup", primary: true, wantMetric: 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			liveOSPFMetricLSDB11447(t,
				ip, zebra, staticd, ospfd, ospf6d, ripd, isisd, bgpd, mgmtd,
				ripngd, eigrpd, fabricd, pimd, pim6d, babeld, pbrd, vrrpd, bfdd,
				vtysh, i, tc.exportPolicy, tc.ripExport, tc.primary, tc.wantMetric)
		})
	}
}

func liveFRRBinary11447(t *testing.T, envName string, candidates ...string) string {
	t.Helper()
	if binary := os.Getenv(envName); binary != "" {
		return binary
	}
	if binary, err := exec.LookPath(strings.TrimSuffix(filepath.Base(candidates[0]), filepath.Ext(candidates[0]))); err == nil {
		return binary
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Skipf("%s is unavailable for live FRR LSDB validation", envName)
	return ""
}

func liveOSPFMetricLSDB11447(
	t *testing.T,
	ip, zebra, staticd, ospfd, ospf6d, ripd, isisd, bgpd, mgmtd string,
	ripngd, eigrpd, fabricd, pimd, pim6d, babeld, pbrd, vrrpd, bfdd, vtysh string,
	index int,
	exportPolicy, ripExport, primary bool,
	wantMetric int,
) {
	t.Helper()
	id := fmt.Sprintf("%d-%d", os.Getpid(), index)
	namespace := "xpf-qnh-" + id
	pathspace := "xpf-qnh-" + id
	hostIf := fmt.Sprintf("x47h%d", os.Getpid()%1000000)
	nsIf := fmt.Sprintf("x47n%d", os.Getpid()%1000000)
	hostIf2 := fmt.Sprintf("x48h%d", os.Getpid()%1000000)
	nsIf2 := fmt.Sprintf("x48n%d", os.Getpid()%1000000)
	frrUser, err := user.Lookup("frr")
	if err != nil {
		t.Skip("FRR daemon account is unavailable")
	}
	vtyGroup, err := user.LookupGroup("frrvty")
	if err != nil {
		t.Skip("FRR VTY group is unavailable")
	}
	frrUID, err := strconv.Atoi(frrUser.Uid)
	if err != nil {
		t.Fatal(err)
	}
	vtyGID, err := strconv.Atoi(vtyGroup.Gid)
	if err != nil {
		t.Fatal(err)
	}
	tempDir, err := os.MkdirTemp("", "xpf-qnh-11447-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(tempDir, frrUID, vtyGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tempDir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	for _, configDir := range []string{tempDir, filepath.Join(tempDir, pathspace)} {
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "vtysh.conf"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runVTY := func(timeout time.Duration, args ...string) ([]byte, error) {
		vtyshArgs := []string{"--no-fork", "--config_dir", tempDir, "-N", pathspace}
		commandArgs := append([]string{vtysh}, vtyshArgs...)
		return runQNHCommand11447(timeout, append(commandArgs, args...)...)
	}
	configPath := filepath.Join(tempDir, "frr.conf")
	daemonConfig := filepath.Join(tempDir, "daemon.conf")
	if err := os.WriteFile(daemonConfig, []byte("hostname xpf-qnh-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runQNHCommand11447(5*time.Second, ip, "netns", "add", namespace); err != nil {
		t.Skipf("network namespace setup is unavailable: %v: %s", err, out)
	}
	pidFiles := []string{
		filepath.Join(tempDir, "zebra.pid"),
		filepath.Join(tempDir, "mgmtd.pid"),
		filepath.Join(tempDir, "staticd.pid"),
		filepath.Join(tempDir, "ospfd.pid"),
		filepath.Join(tempDir, "ospf6d.pid"),
		filepath.Join(tempDir, "ripd.pid"),
		filepath.Join(tempDir, "isisd.pid"),
		filepath.Join(tempDir, "bgpd.pid"),
		filepath.Join(tempDir, "ripngd.pid"),
		filepath.Join(tempDir, "eigrpd.pid"),
		filepath.Join(tempDir, "fabricd.pid"),
		filepath.Join(tempDir, "pimd.pid"),
		filepath.Join(tempDir, "pim6d.pid"),
		filepath.Join(tempDir, "babeld.pid"),
		filepath.Join(tempDir, "pbrd.pid"),
		filepath.Join(tempDir, "vrrpd.pid"),
		filepath.Join(tempDir, "bfdd.pid"),
	}
	t.Cleanup(func() {
		for _, pidFile := range pidFiles {
			data, err := os.ReadFile(pidFile)
			if err != nil {
				continue
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
		time.Sleep(200 * time.Millisecond)
		_, _ = runQNHCommand11447(5*time.Second, ip, "netns", "del", namespace)
		_, _ = runQNHCommand11447(5*time.Second, ip, "link", "del", hostIf)
		if primary {
			_, _ = runQNHCommand11447(5*time.Second, ip, "link", "del", hostIf2)
		}
		_ = os.RemoveAll(filepath.Join("/var/run/frr", pathspace))
	})

	run := func(args ...string) string {
		t.Helper()
		out, err := runQNHCommand11447(10*time.Second, args...)
		if err != nil {
			t.Fatalf("command %q failed: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run(ip, "link", "add", hostIf, "type", "veth", "peer", "name", nsIf)
	run(ip, "link", "set", nsIf, "netns", namespace)
	run(ip, "addr", "add", "192.0.2.10/24", "dev", hostIf)
	run(ip, "link", "set", hostIf, "up")
	run(ip, "-n", namespace, "link", "set", "lo", "up")
	run(ip, "-n", namespace, "addr", "add", "192.0.2.1/24", "dev", nsIf)
	run(ip, "-n", namespace, "link", "set", nsIf, "up")
	if primary {
		run(ip, "link", "add", hostIf2, "type", "veth", "peer", "name", nsIf2)
		run(ip, "link", "set", nsIf2, "netns", namespace)
		run(ip, "addr", "add", "192.0.3.20/24", "dev", hostIf2)
		run(ip, "link", "set", hostIf2, "up")
		run(ip, "-n", namespace, "addr", "add", "192.0.3.1/24", "dev", nsIf2)
		run(ip, "-n", namespace, "link", "set", nsIf2, "up")
	}
	routePrefix := "203.0.113.0/24"
	commands := []string{}
	if primary {
		routePrefix = "198.51.100.0/24"
		commands = append(commands, "set routing-options static route "+routePrefix+" next-hop 192.0.3.20")
		commands = append(commands, "set routing-options static route "+routePrefix+" qualified-next-hop 192.0.2.10 preference 100")
	}
	if exportPolicy {
		commands = append(commands, "set routing-options static route 198.51.100.0/24 qualified-next-hop 192.0.2.20 metric 20")
	}
	commands = append(commands, "set routing-options static route "+routePrefix+" qualified-next-hop 192.0.2.10 metric 10")
	commands = append(commands,
		"set protocols ospf router-id 10.255.0.1",
		"set protocols ospf area 0.0.0.0 interface "+nsIf+" passive",
	)
	if ripExport {
		commands = append(commands, "set protocols rip redistribute static")
	}
	if exportPolicy {
		commands = append(commands,
			"set protocols ospf export EXPORT-STATIC",
			"set policy-options policy-statement EXPORT-STATIC term STATIC from protocol static",
			"set policy-options policy-statement EXPORT-STATIC term STATIC then metric 100",
			"set policy-options policy-statement EXPORT-STATIC term STATIC then accept",
		)
	} else {
		commands = append(commands, "set protocols ospf export static")
	}
	compiled := compileQNHMetricConfig11447(t, commands...)
	rendered, overlays := New().buildManagedSectionWithQNH11447(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		RIP:           compiled.Protocols.RIP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	initialSection := rendered
	if !exportPolicy && !primary {
		initialSection = legacyQNHMetricConfig11447(t)
	}
	initial := markerBegin + "\n" + initialSection + "\n" + markerEnd + "\n"
	if err := os.WriteFile(configPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	qnhMap := qnhRedistributionMap11447(rendered)
	if qnhMap == "" {
		t.Fatalf("rendered config has no QNH redistribution map:\n%s", rendered)
	}
	for _, daemon := range []struct {
		binary string
		pid    string
		config string
	}{
		{binary: zebra, pid: pidFiles[0], config: daemonConfig},
		{binary: mgmtd, pid: pidFiles[1]},
		{binary: staticd, pid: pidFiles[2]},
		{binary: ospfd, pid: pidFiles[3], config: configPath},
		{binary: ospf6d, pid: pidFiles[4]},
		{binary: ripd, pid: pidFiles[5]},
		{binary: isisd, pid: pidFiles[6]},
		{binary: bgpd, pid: pidFiles[7]},
		{binary: ripngd, pid: pidFiles[8]},
		{binary: eigrpd, pid: pidFiles[9]},
		{binary: fabricd, pid: pidFiles[10]},
		{binary: pimd, pid: pidFiles[11]},
		{binary: pim6d, pid: pidFiles[12]},
		{binary: babeld, pid: pidFiles[13]},
		{binary: pbrd, pid: pidFiles[14]},
		{binary: vrrpd, pid: pidFiles[15]},
		{binary: bfdd, pid: pidFiles[16]},
	} {
		args := []string{"netns", "exec", namespace, daemon.binary, "-N", pathspace, "-d"}
		if daemon.config != "" {
			args = append(args, "-f", daemon.config)
		}
		args = append(args, "-i", daemon.pid, "-A", "127.0.0.1", "-P", "0", "-u", "frr", "-g", "frrvty")
		if daemon.binary == mgmtd {
			args = append(args, "--log", "file:"+filepath.Join(tempDir, "mgmtd-daemon.log"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, ip, args...)
		logPath := filepath.Join(tempDir, filepath.Base(daemon.binary)+".log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		err = cmd.Run()
		_ = logFile.Close()
		cancel()
		if err != nil {
			logOutput, _ := os.ReadFile(logPath)
			t.Fatalf("starting FRR daemon %s: %v\n%s", daemon.binary, err, logOutput)
		}
	}
	ready := false
	for range 20 {
		if _, err := runVTY(3*time.Second, "-d", "zebra", "-c", "show version"); err == nil {
			ready = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatal("FRR zebra VTY did not become ready")
	}
	manager := New()
	manager.frrConf = configPath
	if !strings.HasPrefix(filepath.Clean(manager.frrConf), filepath.Clean(tempDir)+string(os.PathSeparator)) {
		t.Fatalf("live FRR config path %q escaped isolated temp dir %q", manager.frrConf, tempDir)
	}
	manager.exec = liveQNHExecutor11447{runVTY: runVTY}
	manager.DisableDegradedRetry()
	t.Cleanup(manager.Stop)
	if err := manager.commitManagedSection(rendered, overlays); err != nil &&
		!errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("committing the metric-free managed section and OSPF overlay: %v", err)
	}
	if exportPolicy {
		shrinkingRoute := "set routing-options static route 198.51.100.0/24 qualified-next-hop 192.0.2.20 metric 20"
		shrunkCommands := make([]string, 0, len(commands)-1)
		for _, command := range commands {
			if command != shrinkingRoute {
				shrunkCommands = append(shrunkCommands, command)
			}
		}
		shrunkCompiled := compileQNHMetricConfig11447(t, shrunkCommands...)
		shrunk, shrunkOverlays := New().buildManagedSectionWithQNH11447(&FullConfig{
			OSPF:          shrunkCompiled.Protocols.OSPF,
			RIP:           shrunkCompiled.Protocols.RIP,
			StaticRoutes:  shrunkCompiled.RoutingOptions.StaticRoutes,
			PolicyOptions: &shrunkCompiled.PolicyOptions,
		})
		if err := manager.commitManagedSection(shrunk, shrunkOverlays); err != nil &&
			!errors.Is(err, ErrFRRReloadDegraded) {
			t.Fatalf("committing authored-policy config after QNH shrink: %v", err)
		}
		qnhMap = qnhRedistributionMap11447(shrunk)
		output, err := runVTY(3*time.Second, "-d", "ospfd", "-c", "show route-map "+qnhMap)
		if err != nil {
			t.Fatalf("showing authored route-map after QNH shrink: %v\n%s", err, output)
		}
		if metrics := qnhMetricActionsFromShow11447(output)[20]; len(metrics) != 1 || metrics[0] != 100 {
			t.Fatalf("authored metric at reused route-map sequence 20 = %v, want [100]:\n%s", metrics, output)
		}
		var reusedAuthoredBlock string
		for _, block := range routeMapSequenceBlocks11447(string(output)) {
			if strings.Contains(block, "sequence 20") {
				reusedAuthoredBlock = block
				break
			}
		}
		if reusedAuthoredBlock == "" {
			t.Fatalf("authored route-map sequence 20 is absent after QNH shrink:\n%s", output)
		}
		for _, staleQNH := range []string{
			"xpf-qnh-dst-",
			"xpf-qnh-nh-",
			"on-match next",
			"match interface ",
		} {
			if strings.Contains(strings.ToLower(reusedAuthoredBlock), staleQNH) {
				t.Fatalf("reused authored route-map sequence 20 retains old QNH clause %q:\n%s", staleQNH, reusedAuthoredBlock)
			}
		}
	}
	if !exportPolicy {
		assertQNHMetricDaemonMaps11447(t, runVTY, qnhMap, ripExport)
	}

	want := fmt.Sprintf("Metric: %d", wantMetric)
	var routeOutput, databaseOutput string
	for range 20 {
		route, routeErr := runVTY(3*time.Second, "-d", "zebra", "-c", "show ip route "+routePrefix)
		database, databaseErr := runVTY(3*time.Second, "-d", "ospfd", "-c", "show ip ospf database external "+strings.Split(routePrefix, "/")[0])
		routeOutput, databaseOutput = string(route), string(database)
		if routeErr == nil && databaseErr == nil && ospfLSDBHasMetric11447(databaseOutput, wantMetric) {
			if primary {
				run(ip, "-n", namespace, "link", "set", nsIf2, "down")
				if got, ok := waitOSPFMetric11447(runVTY, strings.Split(routePrefix, "/")[0], 10, 20*time.Second); !ok {
					t.Fatalf("primary link-down LSDB metric = %d, want 10", got)
				}
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	kernelRoutes, _ := runQNHCommand11447(3*time.Second, ip, "-n", namespace, "route", "show")
	staticConfig, _ := runVTY(3*time.Second, "-d", "staticd", "-c", "show running-config")
	t.Fatalf("OSPF LSDB did not show %s for the redistributed static route\nroute:\n%s\nLSDB:\n%s\nkernel routes:\n%s\nstaticd config:\n%s\nconfig:\n%s", want, routeOutput, databaseOutput, kernelRoutes, staticConfig, rendered)

}

type liveQNHExecutor11447 struct {
	runVTY func(time.Duration, ...string) ([]byte, error)
}

func liveQNHTimeout11447(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			return remaining
		}
		return time.Millisecond
	}
	return 10 * time.Second
}

func (e liveQNHExecutor11447) Vtysh(ctx context.Context, command string) (string, error) {
	output, err := e.runVTY(liveQNHTimeout11447(ctx), "-c", command)
	return string(output), err
}

func (liveQNHExecutor11447) FrrReloadPy(context.Context, string) error {
	return fmt.Errorf("unexpected frr-reload.py call in QNH live transport test")
}

func (e liveQNHExecutor11447) VtyshLoad(ctx context.Context, conf string) ([]byte, error) {
	return e.runVTY(liveQNHTimeout11447(ctx), "-f", conf)
}

func (e liveQNHExecutor11447) VtyshLoadDaemon(ctx context.Context, daemon, conf string) ([]byte, error) {
	return e.runVTY(liveQNHTimeout11447(ctx), "-d", daemon, "-f", conf)
}

func (e liveQNHExecutor11447) VtyshDaemon(ctx context.Context, daemon, command string) ([]byte, error) {
	return e.runVTY(liveQNHTimeout11447(ctx), "-d", daemon, "-c", command)
}

func (liveQNHExecutor11447) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return nil, nil, fmt.Errorf("unexpected vtysh stream call in QNH live transport test")
}

func runQNHCommand11447(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
}
func qnhRedistributionMap11447(config string) string {
	var routeMap string
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "route-map" {
			routeMap = fields[1]
			continue
		}
		if routeMap != "" && strings.Contains(line, "match ip address prefix-list xpf-qnh-dst-") {
			return routeMap
		}
	}
	return ""
}

func assertQNHMetricDaemonMaps11447(
	t *testing.T,
	runVTY func(time.Duration, ...string) ([]byte, error),
	routeMap string,
	ripConfigured bool,
) {
	t.Helper()
	for _, check := range []struct {
		daemon     string
		wantMetric bool
		required   bool
	}{
		{daemon: "ospfd", wantMetric: true, required: true},
		{daemon: "ripd", required: ripConfigured},
		{daemon: "isisd"},
		{daemon: "ospf6d"},
		{daemon: "bgpd"},
		{daemon: "ripngd"},
		{daemon: "eigrpd"},
		{daemon: "fabricd"},
		{daemon: "pimd"},
		{daemon: "pim6d"},
		{daemon: "babeld"},
		{daemon: "pbrd"},
		{daemon: "vrrpd"},
		{daemon: "bfdd"},
		{daemon: "zebra"},
		{daemon: "staticd"},
		{daemon: "mgmtd"},
	} {
		output, err := runVTY(3*time.Second, "-d", check.daemon, "-c", "show route-map "+routeMap)
		if err != nil {
			t.Fatalf("showing %s route-map %s: %v\n%s", check.daemon, routeMap, err, output)
		}
		blocks := routeMapSequenceBlocks11447(string(output))
		if len(blocks) == 0 {
			if check.required {
				t.Fatalf("%s has no route-map %s sequence:\n%s", check.daemon, routeMap, output)
			}
			continue
		}
		if !check.wantMetric {
			for _, block := range blocks {
				if strings.Contains(strings.ToLower(block), "metric ") {
					t.Errorf("%s route-map %s has an unsupported QNH metric action:\n%s", check.daemon, routeMap, block)
				}
			}
			continue
		}
		foundQNHMetric := false
		for _, block := range blocks {
			lower := strings.ToLower(block)
			if !strings.Contains(lower, "xpf-qnh-dst-") {
				continue
			}
			if !strings.Contains(lower, "xpf-qnh-nh-") {
				t.Errorf("%s route-map %s has a QNH destination sequence without a next-hop discriminator:\n%s", check.daemon, routeMap, block)
				continue
			}
			foundExactMetric := false
			for _, line := range strings.Split(lower, "\n") {
				if strings.TrimSpace(line) == "metric 10" {
					foundExactMetric = true
					break
				}
			}
			if !foundExactMetric {
				t.Errorf("%s route-map %s QNH sequence lacks overlay metric 10:\n%s", check.daemon, routeMap, block)
				continue
			}
			foundQNHMetric = true
		}
		if !foundQNHMetric {
			t.Errorf("%s route-map %s has no effective QNH destination + next-hop metric sequence:\n%s", check.daemon, routeMap, output)
		}
	}
}

func waitOSPFMetric11447(
	runVTY func(time.Duration, ...string) ([]byte, error),
	prefix string,
	want int,
	timeout time.Duration,
) (int, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := runVTY(3*time.Second, "-d", "ospfd", "-c", "show ip ospf database external "+prefix)
		if err == nil && ospfLSDBHasMetric11447(string(output), want) {
			return want, true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, false
}

func routeMapSequenceBlocks11447(output string) []string {
	var blocks []string
	var block strings.Builder
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToLower(line), "sequence ") {
			if block.Len() > 0 {
				blocks = append(blocks, block.String())
				block.Reset()
			}
		}
		if block.Len() > 0 || strings.Contains(strings.ToLower(line), "sequence ") {
			block.WriteString(line)
			block.WriteByte('\n')
		}
	}
	if block.Len() > 0 {
		blocks = append(blocks, block.String())
	}
	return blocks
}

func ospfLSDBHasMetric11447(output string, want int) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Metric:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Metric:"))
		if len(fields) == 0 {
			continue
		}
		metric, err := strconv.Atoi(strings.TrimSuffix(fields[0], ","))
		if err == nil && metric == want {
			return true
		}
	}
	return false
}
