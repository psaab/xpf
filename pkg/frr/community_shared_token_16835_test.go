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

// #16835 (R3-F12-02): one community may satisfy two members.
//
// #15779/#16788 render a multi-member expanded definition as one
// community-list of ordered permutation patterns, and each pattern
// consumes at least one whole token per factor (even a zero-width
// factor occurrence has nonempty consumed extent in a consuming
// match), so one community that satisfies two regex members can
// never satisfy the conjunction at the list layer: members
// [65000:.* .*:100] miss a route carrying only 65000:100, while
// 65000:7 1:100 (distinct tokens) matched. These tests pin the full
// acceptance matrix — both defect rows, the separated controls, the
// absent-member controls and the substring controls — through the
// PRODUCTION renderer against the same POSIX-ERE oracle FRR's
// regcomp(REG_EXTENDED) evaluates (the #8449 agreement), plus
// pipe-freedom (#16776) and policy-level behavior.

// renderCommunity16835 builds one community definition and returns
// New().generatePolicyOptions(po).
func renderCommunity16835(t *testing.T, name string, members ...string) string {
	t.Helper()
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			name: {Name: name, Members: members},
		},
	}
	return New().generatePolicyOptions(po)
}

func chainPatterns16835(t *testing.T, rendered string, members []string, publicName string) []string {
	t.Helper()
	var patterns []string
	for _, member := range members {
		name := communityChainListName16835(publicName, member)
		prefix := "bgp community-list expanded " + name + " permit "
		var found []string
		for _, line := range strings.Split(rendered, "\n") {
			if strings.HasPrefix(line, prefix) {
				found = append(found, strings.TrimPrefix(line, prefix))
			}
		}
		if len(found) != 1 {
			t.Fatalf("want exactly 1 chain pattern for member %q (list %s), got %q:\n%s", member, name, found, rendered)
		}
		patterns = append(patterns, found[0])
	}
	return patterns
}

// evalChain16835 evaluates the chain the way bgpd evaluates the
// generated route-map continuation: one member list after another,
// each evaluated independently against the route's joined community
// string. That independence is what lets one token satisfy two
// members — and what makes the whole conjunction true only when
// EVERY member list matches somewhere.
func evalChain16835(t *testing.T, patterns []string, joined string) bool {
	t.Helper()
	for _, p := range patterns {
		if strings.Contains(p, "| ") {
			t.Errorf("rendered pattern %q carries \"| \" (vty pipe hook, R3-A11-04)", p)
		}
		if strings.Contains(p, "(?") {
			t.Errorf("rendered pattern %q carries a non-POSIX construct", p)
		}
		re, err := regexp.CompilePOSIX(p)
		if err != nil {
			t.Fatalf("rendered pattern %q fails POSIX compile: %v", p, err)
		}
		if !re.MatchString(joined) {
			return false
		}
	}
	return true
}

func TestCommunityChainSharedToken16835(t *testing.T) {
	members := []string{"65000:.*", ".*:100"}
	for _, tc := range []struct {
		joined string
		want   bool
	}{
		{"65000:100", true},         // the shared-token row: ONE community satisfies BOTH members
		{"65000:7 1:100", true},     // control: distinct tokens, one per member
		{"65000:7", false},          // .*:100 absent
		{"1:100", false},            // 65000:.* absent
		{"65000:7 65001:100", true}, // second member on its own token
		{"65000:1000", true},        // .*:100 is a substring member of 65000:1000
		{"165000:200", false},       // member offset inside a token: neither member cleanly satisfied
		{"", false},
	} {
		got := renderCommunity16835(t, "SH", members...)
		patterns := chainPatterns16835(t, got, members, "SH")
		if m := evalChain16835(t, patterns, tc.joined); m != tc.want {
			t.Errorf("SH chain vs %q = %v, want %v (patterns %q)", tc.joined, m, tc.want, patterns)
		}
	}
}

func TestCommunityChainAdjacentLiterals16835(t *testing.T) {
	members := []string{"65000:100", "65000:200", "65001:.*"}
	for _, tc := range []struct {
		joined string
		want   bool
	}{
		{"65000:100 65000:200 65001:5", true},     // adjacent row: the two literals are consecutive in the sorted string
		{"65000:100 65000:200", false},            // regex member absent
		{"65000:100 65001:5", false},              // second literal absent
		{"65001:5", false},                        // literals absent
		{"65000:100 7:1 65000:200 65001:5", true}, // separated control
		{"65000:2000 65000:100 65001:5", false},   // substring control: 65000:200 must not match 65000:2000
		{"165000:200 65000:100 65001:5", false},   // substring control: 65000:200 must not match inside 165000:200
		{"65000:100 65000:200 65001:5 9:9", true}, // trailing extra community
	} {
		got := renderCommunity16835(t, "MIX", members...)
		patterns := chainPatterns16835(t, got, members, "MIX")
		if m := evalChain16835(t, patterns, tc.joined); m != tc.want {
			t.Errorf("MIX chain vs %q = %v, want %v (patterns %q)", tc.joined, m, tc.want, patterns)
		}
	}
}

func TestCommunityChainRenderShape16835(t *testing.T) {
	got := renderCommunity16835(t, "SH", "65000:.*", ".*:100")
	if strings.Contains(got, "| ") {
		t.Fatalf("render carries \"| \" (vty pipe hook):\n%s", got)
	}
	for _, member := range []string{"65000:.*", ".*:100"} {
		name := communityChainListName16835("SH", member)
		if !strings.Contains(got, "bgp community-list expanded "+name+" permit ") {
			t.Fatalf("chain list for member %q not rendered:\n%s", member, got)
		}
	}
	// The public list keeps its #15779 permutation render.
	existing := expandedPatterns15779(t, got, "SH")
	if len(existing) != 2 {
		t.Fatalf("public SH list must keep 2 permutation entries, got %q:\n%s", existing, got)
	}
	// And the chain evaluates the shared row the public list cannot.
	patterns := chainPatterns16835(t, got, []string{"65000:.*", ".*:100"}, "SH")
	if !evalChain16835(t, patterns, "65000:100") {
		t.Fatalf("chain misses the shared token 65000:100: %q", patterns)
	}
}

// RED-on-revert evidence: the pre-#16835 render — the public
// permutation list evaluated the way FRR evaluates one list (any
// entry matches) — misses BOTH defect rows. Any revert that drops
// the chain evaluation while keeping this test green has widened
// nothing; the chain is the only mechanism under test here.
func TestCommunityPublicListMissesDefectRows16835(t *testing.T) {
	got := renderCommunity16835(t, "SH", "65000:.*", ".*:100")
	patterns := expandedPatterns15779(t, got, "SH")
	if anyMatch16788(t, patterns, "65000:100") {
		t.Fatalf("public list unexpectedly matches the shared token; the chain is no longer load-bearing: %q", patterns)
	}
	got = renderCommunity16835(t, "MIX", "65000:100", "65000:200", "65001:.*")
	patterns = expandedPatterns15779(t, got, "MIX")
	// The #16788 sequencer already covers the adjacent row at the
	// list layer (it shares the separator), so this asserts no
	// regression rather than a defect: the list must match here.
	if !anyMatch16788(t, patterns, "65000:100 65000:200 65001:5") {
		t.Fatalf("public list regressed the adjacent row: %q", patterns)
	}
}

func TestCommunityChainPolicyRender16835(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"SH"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		}, "accept")
	got := New().generatePolicyOptions(po)
	for _, want := range []string{
		"bgp community-list expanded SH permit ",
		" match community SH\n",
		"route-map P deny 10\n",
		"route-map P permit 20\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("policy render missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "| ") {
		t.Errorf("policy render carries \"| \":\n%s", got)
	}
	if communityChainWidth16835(po, "SH") != 2 {
		t.Errorf("SH must resolve to a 2-member chain")
	}
	if communityExtraTermSeqWeight16835(po, "SH") != 1 {
		t.Errorf("a 2-member chain must reserve exactly 1 continuation sequence")
	}
	if !communityOrphanTerm16835(po, po.PolicyStatements["P"].Terms[0]) {
		t.Errorf("reject term over SH only must be chain-eligible (orphan shape)")
	}
	if communityTermSeqCount16835(po, []string{"SH"}, 10) != 30 {
		t.Errorf("next term must start past the reserved chain slot")
	}
}

func TestCommunityChainNonOrphanShapes16835(t *testing.T) {
	po := &config.PolicyOptionsConfig{Communities: map[string]*config.CommunityDef{
		"SH":  {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		"LIT": {Name: "LIT", Members: []string{"65000:100", "65000:200"}},
		"ONE": {Name: "ONE", Members: []string{"65000:.*"}},
		"BIG": {Name: "BIG", Members: []string{"65000:.*", "65001:.*", "65002:.*", "65003:.*", "65004:.*"}},
	}}
	for _, tc := range []struct {
		name string
		term *config.PolicyTerm
		want bool
	}{
		{"chain only", &config.PolicyTerm{FromCommunity: []string{"SH"}}, true},
		{"chain plus prefix-list", &config.PolicyTerm{FromCommunity: []string{"SH"}, PrefixList: []string{"PL"}}, false},
		{"chain plus as-path", &config.PolicyTerm{FromCommunity: []string{"SH"}, FromASPath: []string{"AP"}}, false},
		{"chain plus protocol", &config.PolicyTerm{FromCommunity: []string{"SH"}, FromProtocols: []string{"bgp"}}, false},
		{"literal definition is standard, never a chain", &config.PolicyTerm{FromCommunity: []string{"LIT"}}, false},
		{"single member is not a chain", &config.PolicyTerm{FromCommunity: []string{"ONE"}}, false},
		{"past-bound definition renders nothing", &config.PolicyTerm{FromCommunity: []string{"BIG"}}, false},
		{"undefined name is not a chain", &config.PolicyTerm{FromCommunity: []string{"NOPE"}}, false},
	} {
		if got := communityOrphanTerm16835(po, tc.term); got != tc.want {
			t.Errorf("%s: orphan = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCommunityChainLiveBgpd16835 is the daemon-path oracle: a real
// bgpd + zebra in a private netns/pathspace, loaded via vtysh -f (the
// same transport frr-reload.py drives). It asserts the #16835 chain
// lists are INSTALLED (`show bgp community-list`) — a dry-run or
// rc=0 cannot prove that. Requires root; skips otherwise. The
// behavioral authority for the shared-token row is the POSIX oracle
// above; this cell proves the daemon installs the rendered chains.
func TestCommunityChainLiveBgpd16835(t *testing.T) {
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
	ns := "xpf-16835-" + id
	pathspace := "xpf16835" + id
	tempDir, err := os.MkdirTemp("", "xpf-16835-")
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

	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"SH":  {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
			"MIX": {Name: "MIX", Members: []string{"65000:100", "65000:200", "65001:.*"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"SH"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		}, "accept")
	policy := New().generatePolicyOptions(po)
	if strings.Contains(policy, "| ") {
		t.Fatalf("production render contains \"| \":\n%s", policy)
	}
	conf := "frr version 10.7.1\nfrr defaults traditional\nhostname xpf16835\n!\n" +
		"router bgp 65000\n bgp router-id 10.255.0.1\n neighbor 192.0.2.1 remote-as 65001\n" +
		" neighbor 192.0.2.1 description plain peer\n!\n" + policy + "line vty\n!\n"
	confPath := filepath.Join(tempDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	daemonConf := filepath.Join(tempDir, "daemon.conf")
	if err := os.WriteFile(daemonConf, []byte("hostname xpf16835\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ bin, pid string }{
		{zebra, filepath.Join(tempDir, "zebra.pid")},
		{mgmtd, filepath.Join(tempDir, "mgmtd.pid")},
		{bgpd, filepath.Join(tempDir, "bgpd.pid")},
	} {
		pids = append(pids, d.pid)
		args := []string{"netns", "exec", ns, d.bin, "-N", pathspace, "-d", "-i", d.pid, "-A", "127.0.0.1", "-P", "0", "-u", "frr", "-g", "frrvty", "--limit-fds", "1024"}
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
	out, err := runVTY(15*time.Second, "-f", confPath)
	if err != nil {
		t.Fatalf("vtysh -f load failed: %v\n%s\nconf:\n%s", err, out, conf)
	}
	if strings.Contains(out, "Unknown action") {
		t.Fatalf("vtysh -f hit the pipe hook: %s\nconf:\n%s", out, conf)
	}
	deadline := time.Now().Add(15 * time.Second)
	var show string
	for time.Now().Before(deadline) {
		show, err = runVTY(3*time.Second, "-d", "bgpd", "-c", "show bgp community-list")
		if err == nil && strings.Contains(show, "SH") && strings.Contains(show, "MIX") {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	for _, want := range []string{"SH", "MIX", communityChainListName16835("SH", "65000:.*"), communityChainListName16835("SH", ".*:100"), communityChainListName16835("MIX", "65000:100"), communityChainListName16835("MIX", "65001:.*")} {
		if !strings.Contains(show, want) {
			t.Errorf("installed community-lists lack %q:\n%s\nconf:\n%s", want, show, conf)
		}
	}
	if strings.Contains(show, "| ") {
		t.Errorf("installed lists contain \"| \":\n%s", show)
	}
	rm, err := runVTY(3*time.Second, "-d", "bgpd", "-c", "show route-map P")
	if err != nil || !strings.Contains(rm, "community SH") {
		t.Errorf("route-map P does not reference installed SH: err=%v\n%s", err, rm)
	}
}
