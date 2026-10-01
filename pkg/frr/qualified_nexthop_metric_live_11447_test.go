package frr

import (
	"context"
	"fmt"
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
	mgmtd := liveFRRBinary11447(t, "FRR_MGMTD_BINARY", "/usr/lib/frr/mgmtd", "/usr/libexec/frr/mgmtd")
	vtysh, err := exec.LookPath("vtysh")
	if err != nil {
		t.Skip("FRR vtysh is unavailable for isolated OSPF validation")
	}

	for i, tc := range []struct {
		name         string
		exportPolicy bool
		wantMetric   int
	}{
		{name: "qualified metric", wantMetric: 10},
		{name: "authored policy override", exportPolicy: true, wantMetric: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			liveOSPFMetricLSDB11447(t, ip, zebra, staticd, ospfd, mgmtd, vtysh, i, tc.exportPolicy, tc.wantMetric)
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

func liveOSPFMetricLSDB11447(t *testing.T, ip, zebra, staticd, ospfd, mgmtd, vtysh string, index int, exportPolicy bool, wantMetric int) {
	t.Helper()
	id := fmt.Sprintf("%d-%d", os.Getpid(), index)
	namespace := "xpf-qnh-" + id
	pathspace := "xpf-qnh-" + id
	hostIf := fmt.Sprintf("x47h%d", os.Getpid()%1000000)
	nsIf := fmt.Sprintf("x47n%d", os.Getpid()%1000000)
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

	commands := []string{
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf router-id 10.255.0.1",
		"set protocols ospf area 0.0.0.0 interface " + nsIf + " passive",
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
	rendered := New().buildManagedSection(&FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if err := os.WriteFile(configPath, []byte(rendered), 0o644); err != nil {
		t.Fatal(err)
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
	if output, err := runVTY(3*time.Second, "-f", configPath); err != nil {
		mgmtdLog, _ := os.ReadFile(filepath.Join(tempDir, "mgmtd-daemon.log"))
		t.Fatalf("loading generated FRR config: %v\n%s\nmgmtd log:\n%s", err, output, mgmtdLog)
	}

	want := fmt.Sprintf("Metric: %d", wantMetric)
	var routeOutput, databaseOutput string
	for range 20 {
		route, routeErr := runVTY(3*time.Second, "-d", "zebra", "-c", "show ip route 203.0.113.0/24")
		database, databaseErr := runVTY(3*time.Second, "-d", "ospfd", "-c", "show ip ospf database external 203.0.113.0")
		routeOutput, databaseOutput = string(route), string(database)
		if routeErr == nil && databaseErr == nil && ospfLSDBHasMetric11447(databaseOutput, wantMetric) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	kernelRoutes, _ := runQNHCommand11447(3*time.Second, ip, "-n", namespace, "route", "show")
	staticConfig, _ := runVTY(3*time.Second, "-d", "staticd", "-c", "show running-config")
	t.Fatalf("OSPF LSDB did not show %s for the redistributed static route\nroute:\n%s\nLSDB:\n%s\nkernel routes:\n%s\nstaticd config:\n%s\nconfig:\n%s", want, routeOutput, databaseOutput, kernelRoutes, staticConfig, rendered)
}

func runQNHCommand11447(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
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
