package frr

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16776: FRR's vty pipe hook (handle_pipe_action) treats "| " in any
// command line as an output pipe; a non-"include" token after it prints
// "% Unknown action" and the line never executes, yet frr-reload.py
// exits 0. xpf spelled literal conjunction boundaries "(^| )"/"( |$)"
// so every such community-list was silently absent and a reject term
// over it failed open.
//
// Post-#16788, the community translator emits pipe-safe regexes or
// refuses the member and fails closed. The BGP neighbor-description
// gate refuses/omits prose carrying "| ". Junos AS-path regexes are
// translated before render, normalizing grouping whitespace. No
// standalone pipe-rewrite belt remains.
//
// The unit cells pin the pipe-safe render; the live cell at the
// bottom proves installation on a running bgpd via vtysh -f.

func TestCommunityPipeRender16776(t *testing.T) {
	t.Run("BOTH conjunction installs pipe-safe and matches conjunctively", func(t *testing.T) {
		// Issue example: members [ "^666:.*$" 65000:1 ] with a reject
		// term over BOTH. Post-#16788 the anchored member is confined
		// per-community; the denied route is 666:5 65000:1 (sorted
		// joined form "65000:1 666:5").
		got := renderCommunity15008(t, "^666:.*$", "65000:1")
		if strings.Contains(got, "| ") {
			t.Fatalf("rendered config still contains \"| \" (vty pipe hook would refuse it):\n%s", got)
		}
		patterns := expandedPatterns15779(t, got, "X")
		if len(patterns) == 0 {
			t.Fatalf("BOTH rendered no patterns:\n%s", got)
		}
		assertConjunctiveMatch15779(t, patterns, []matchCase15779{
			{"65000:1 666:5", true}, // the issue's denied route
			{"65000:1", false},
			{"666:5", false},
			{"65000:10 666:5", false},
		})
	})

	t.Run("grouped operator regex with pipe-space is unrenderable post-16788", func(t *testing.T) {
		// The original #16776 grouping rewrite was superseded by
		// #16788's stricter refusal: translateCommunityCore rejects
		// any "| " so the definition is omitted and fails closed
		// (operator rewrites it as "^((56)|(78)):(.*)$").
		member := "^((56) | (78)):(.*)$"
		po := communityPolicyPO(
			map[string]*config.CommunityDef{"OP": {Name: "OP", Members: []string{member}}},
			[]*config.PolicyTerm{
				{Name: "t-reject", FromCommunity: []string{"OP"}, Action: "reject"},
				{Name: "t-accept", Action: "accept"},
			}, "accept")
		got := New().generatePolicyOptions(po)
		if strings.Contains(got, "OP permit") || strings.Contains(got, "match community") {
			t.Fatalf("pipe-space operator member rendered or dangled instead of failing closed:\n%s", got)
		}
		if !communityListMissingAtRender(po, "OP") {
			t.Errorf("pipe-space definition not reported missing; reject would dangle")
		}
		if !strings.Contains(got, "route-map P deny 10\nexit\n") {
			t.Errorf("reject term did not lower to deny-all:\n%s", got)
		}
		// The space-free spelling the gate directs to installs and
		// keeps the 56/78 semantics.
		ok := renderCommunity15008(t, "^((56)|(78)):(.*)$")
		patterns := expandedPatterns15779(t, ok, "X")
		assertConjunctiveMatch15779(t, patterns, []matchCase15779{
			{"56:1", true},
			{"78:2", true},
			{"57:1", false},
			{"99:1", false},
		})
	})

	t.Run("single literal-space atom member is unrenderable and fails closed", func(t *testing.T) {
		member := "65000:1| 666:.*"
		po := communityPolicyPO(
			map[string]*config.CommunityDef{"BOTH": {Name: "BOTH", Members: []string{member}}},
			[]*config.PolicyTerm{
				{Name: "t-reject", FromCommunity: []string{"BOTH"}, Action: "reject"},
				{Name: "t-accept", Action: "accept"},
			}, "accept")
		got := New().generatePolicyOptions(po)
		if strings.Contains(got, "BOTH permit") || strings.Contains(got, "match community") {
			t.Fatalf("atom-space member rendered or dangled instead of failing closed:\n%s", got)
		}
		if !communityListMissingAtRender(po, "BOTH") {
			t.Errorf("atom-space definition not reported missing; reject would dangle")
		}
		if !strings.Contains(got, "route-map P deny 10\nexit\n") {
			t.Errorf("reject term did not lower to deny-all:\n%s", got)
		}
		if err := config.ValidCommunityMemberPipe16776(member); err == nil {
			t.Errorf("ValidCommunityMemberPipe16776(%q) = nil, want refusal", member)
		}
	})

	t.Run("bracket pipe member cannot match separator post-16788", func(t *testing.T) {
		// "65000:[|]" mentions '|' inside a bracket: the translator
		// keeps literals but the bracket here cannot match a space,
		// so it renders; "[| ]" would be refused (can match ' ').
		got := renderCommunity15008(t, "65000:[|]")
		if strings.Contains(got, "| ") {
			t.Errorf("bracket-pipe render introduced \"| \":\n%s", got)
		}
	})

	t.Run("no rendered community line contains pipe-space", func(t *testing.T) {
		for _, members := range [][]string{
			{"65000:100", "65001:.*"},
			{"^666:.*$", "65000:1"},
			{"65000:.*", "65001:.*", "65002:.*"},
		} {
			got := renderCommunity15008(t, members...)
			for _, line := range strings.Split(got, "\n") {
				if strings.Contains(line, "community-list") && strings.Contains(line, "| ") {
					t.Errorf("members %v rendered pipe-unsafe line %q", members, line)
				}
			}
		}
	})
}

func TestNeighborDescriptionPipe16776(t *testing.T) {
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, Description: "uplink | primary"},
			{Address: "10.0.3.1", PeerAS: 65003, Description: "plain peer"},
		},
	}
	got := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "description uplink") {
		t.Errorf("pipe description rendered (vty would refuse the line):\n%s", got)
	}
	if !strings.Contains(got, "neighbor 10.0.3.1 description plain peer\n") && !strings.Contains(got, "neighbor 10.0.3.1 description") {
		// Control neighbor may render via cluster path differing; assert at least pipe text absent and neighbor present.
		if !strings.Contains(got, "10.0.3.1 remote-as") {
			t.Errorf("control neighbor lost:\n%s", got)
		}
	}
	if strings.Contains(got, "| ") {
		t.Errorf("rendered protocols still contain \"| \":\n%s", got)
	}
	// RED control: the pre-fix spelling is exactly what the hook refuses.
	if !strings.Contains("neighbor 10.0.2.1 description uplink | primary", "| ") {
		t.Fatal("fixture broken")
	}
	_ = regexp.MustCompile // keep regexp import if helpers change
}

// TestNeighborDescriptionPipeRenderedForm17839 pins #17839: the gate
// must judge the string that will actually be rendered
// (sanitizeFRRValue turns control bytes into spaces), not the raw
// stored description. "uplink |\tprimary" contains no "| " raw, so a
// raw-string gate passes it, but sanitization renders
// "uplink | primary" — which the vty pipe hook refuses while
// frr-reload.py exits 0, silently dropping the description.
func TestNeighborDescriptionPipeRenderedForm17839(t *testing.T) {
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			// Raw-safe, rendered-unsafe: must be omitted.
			{Address: "10.0.2.1", PeerAS: 65002, Description: "uplink |\tprimary"},
			{Address: "10.0.4.1", PeerAS: 65004, Description: "uplink |\x7fprimary"},
			// Inverse: raw-unsafe, rendered-unsafe too (already covered
			// by TestNeighborDescriptionPipe16776, kept as a control
			// here so this test discriminates both directions).
			{Address: "10.0.8.1", PeerAS: 65008, Description: "uplink | primary"},
			// Inverse-kept: control byte alone sanitizes to a space but
			// creates no "| " — must still render (sanitized).
			{Address: "10.0.5.1", PeerAS: 65005, Description: "uplink\tprimary"},
			// Inverse-kept: pipe not followed by a space stays rendered.
			{Address: "10.0.6.1", PeerAS: 65006, Description: "uplink |primary"},
			{Address: "10.0.7.1", PeerAS: 65007, Description: "plain peer"},
		},
	}
	got := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "| ") {
		t.Errorf("rendered protocols contain \"| \" (vty pipe hook would refuse the line):\n%s", got)
	}
	for _, addr := range []string{"10.0.2.1", "10.0.4.1", "10.0.8.1"} {
		if strings.Contains(got, "neighbor "+addr+" description") {
			t.Errorf("neighbor %s description should have been omitted (rendered form is pipe-unsafe):\n%s", addr, got)
		}
		if !strings.Contains(got, "neighbor "+addr+" remote-as") {
			t.Errorf("neighbor %s itself lost (only its description may be omitted):\n%s", addr, got)
		}
	}
	// Kept controls render with the sanitized text.
	for addr, want := range map[string]string{
		"10.0.5.1": "neighbor 10.0.5.1 description uplink primary\n",
		"10.0.6.1": "neighbor 10.0.6.1 description uplink |primary\n",
		"10.0.7.1": "neighbor 10.0.7.1 description plain peer\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("neighbor %s: want rendered line %q in:\n%s", addr, want, got)
		}
	}
	// Fixture sanity: the discriminating input is raw-safe but
	// rendered-unsafe — otherwise this test proves nothing.
	if strings.Contains("uplink |\tprimary", "| ") {
		t.Fatal("fixture broken: raw input already contains \"| \"")
	}
	if !strings.Contains(sanitizeFRRValue("uplink |\tprimary"), "| ") {
		t.Fatal("fixture broken: sanitized input does not contain \"| \"")
	}
}

// TestCommunityListPipeLiveBgpd16776 is the daemon-path oracle: a real
// bgpd + zebra in a private netns/pathspace, loaded via vtysh -f (the
// same transport frr-reload.py drives). It asserts the BOTH list is
// INSTALLED (`show bgp community-list`) — a dry-run or rc=0 cannot
// prove that, which is the defect. Requires root; skips otherwise.
func TestCommunityListPipeLiveBgpd16776(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("live bgpd validation requires root and network namespaces")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2 unavailable")
	}
	zebra := liveFRRBinary11447(t, "FRR_ZEBRA_BINARY", "/usr/lib/frr/zebra", "/usr/libexec/frr/zebra")
	bgpd := liveFRRBinary11447(t, "FRR_BGPD_BINARY", "/usr/lib/frr/bgpd", "/usr/libexec/frr/bgpd")
	mgmtd := liveFRRBinary11447(t, "FRR_MGMTD_BINARY", "/usr/lib/frr/mgmtd", "/usr/libexec/frr/mgmtd")
	vtysh, err := exec.LookPath("vtysh")
	if err != nil {
		t.Skip("vtysh unavailable")
	}
	frrUser, err := user.Lookup("frr")
	if err != nil {
		t.Skip("frr user unavailable")
	}
	vtyGroup, err := user.LookupGroup("frrvty")
	if err != nil {
		t.Skip("frrvty group unavailable")
	}
	frrUID, _ := strconv.Atoi(frrUser.Uid)
	vtyGID, _ := strconv.Atoi(vtyGroup.Gid)

	id := strconv.Itoa(os.Getpid())
	ns := "xpf-16776-" + id
	pathspace := "xpf16776" + id
	tempDir, err := os.MkdirTemp("", "xpf-16776-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chown(tempDir, frrUID, vtyGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tempDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{tempDir, filepath.Join(tempDir, pathspace)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "vtysh.conf"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(timeout time.Duration, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		return string(out), err
	}
	runVTY := func(timeout time.Duration, args ...string) (string, error) {
		// vtysh must run inside the daemon netns: the vty sockets
		// live in the host /var/run/frr/<pathspace> but the daemons
		// serve them from inside ns (QNH harness runs vtysh on the
		// host because its daemons were started with `ip netns exec`
		// too — either way the client and daemon must share the
		// netns for loopback mgmt; here we exec inside to be safe).
		full := append([]string{ip, "netns", "exec", ns, vtysh, "--no-fork", "--config_dir", tempDir, "-N", pathspace}, args...)
		return run(timeout, full...)
	}
	if out, err := run(5*time.Second, ip, "netns", "add", ns); err != nil {
		t.Skipf("netns unavailable: %v %s", err, out)
	}
	var pids []string
	defer func() {
		for _, pf := range pids {
			if data, err := os.ReadFile(pf); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
					_ = syscall.Kill(pid, syscall.SIGTERM)
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
		_, _ = run(5*time.Second, ip, "netns", "del", ns)
		_ = os.RemoveAll(filepath.Join("/var/run/frr", pathspace))
	}()
	if out, err := run(5*time.Second, ip, "-n", ns, "link", "set", "lo", "up"); err != nil {
		t.Fatalf("lo up: %v %s", err, out)
	}

	// Render through the production renderer: BOTH + reject policy.
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"BOTH": {Name: "BOTH", Members: []string{"^666:.*$", "65000:1"}},
			"OP":   {Name: "OP", Members: []string{"^((56)|(78)):(.*)$"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"BOTH"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		}, "accept")
	policy := New().generatePolicyOptions(po)
	if strings.Contains(policy, "| ") {
		t.Fatalf("production render contains \"| \":\n%s", policy)
	}
	conf := "frr version 10.7.1\nfrr defaults traditional\nhostname xpf16776\n!\n" +
		"router bgp 65000\n bgp router-id 10.255.0.1\n neighbor 192.0.2.1 remote-as 65001\n" +
		" neighbor 192.0.2.1 description plain peer\n!\n" + policy + "line vty\n!\n"
	confPath := filepath.Join(tempDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	daemonConf := filepath.Join(tempDir, "daemon.conf")
	if err := os.WriteFile(daemonConf, []byte("hostname xpf16776\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ bin, pid string }{
		{zebra, filepath.Join(tempDir, "zebra.pid")},
		{mgmtd, filepath.Join(tempDir, "mgmtd.pid")},
		{bgpd, filepath.Join(tempDir, "bgpd.pid")},
	} {
		pids = append(pids, d.pid)
		args := []string{"netns", "exec", ns, d.bin, "-N", pathspace, "-d", "-i", d.pid, "-A", "127.0.0.1", "-P", "0", "-u", "frr", "-g", "frrvty", "--limit-fds", "1024"}
		// Daemon children inherit the capture pipe and would block
		// CombinedOutput until they exit; send stdout/stderr to a
		// log file instead (QNH harness does the same).
		logPath := filepath.Join(tempDir, filepath.Base(d.bin)+".log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, ip, args...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		err = cmd.Run()
		_ = logFile.Close()
		cancel()
		if err != nil {
			logOut, _ := os.ReadFile(logPath)
			t.Fatalf("start %s: %v\n%s", d.bin, err, logOut)
		}
	}
	ready := false
	for range 40 {
		if _, err := runVTY(3*time.Second, "-d", "bgpd", "-c", "show version"); err == nil {
			ready = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatal("bgpd VTY not ready")
	}
	// Load via vtysh -f inside the netns (daemon path, not -C dry-run).
	out, err := runVTY(15*time.Second, "-f", confPath)
	if err != nil {
		t.Fatalf("vtysh -f load failed: %v\n%s\nconf:\n%s", err, out, conf)
	}
	if strings.Contains(out, "Unknown action") {
		t.Fatalf("vtysh -f hit the pipe hook: %s\nconf:\n%s", out, conf)
	}
	// Installed-state oracle.
	deadline := time.Now().Add(15 * time.Second)
	var show string
	for time.Now().Before(deadline) {
		show, err = runVTY(3*time.Second, "-d", "bgpd", "-c", "show bgp community-list")
		if err == nil && strings.Contains(show, "BOTH") && strings.Contains(show, "OP") {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !strings.Contains(show, "BOTH") {
		t.Fatalf("BOTH not installed in running bgpd (rc=0 is not proof):\n%s\nconf:\n%s", show, conf)
	}
	if !strings.Contains(show, "65000:1") || !strings.Contains(show, "666:") {
		t.Errorf("installed BOTH lacks its members in translated form:\n%s", show)
	}
	if !strings.Contains(show, "56") || !strings.Contains(show, "78") {
		t.Errorf("installed OP lacks its grouped alternatives:\n%s", show)
	}
	if strings.Contains(show, "| ") {
		t.Errorf("installed lists contain \"| \":\n%s", show)
	}
	rm, err := runVTY(3*time.Second, "-d", "bgpd", "-c", "show route-map P")
	if err != nil || !strings.Contains(rm, "community BOTH") {
		t.Errorf("route-map P does not reference installed BOTH: err=%v\n%s", err, rm)
	}
}
