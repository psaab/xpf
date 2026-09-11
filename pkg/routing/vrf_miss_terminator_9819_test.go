package routing

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeVRFLinks9819 is a minimal vrfOps. It writes every link mutation into a
// log it shares with fakeTerm9819, so a cell can assert what happened BEFORE
// what, not only what happened.
type fakeVRFLinks9819 struct {
	events *[]string
	links  map[string]*netlink.Vrf
	delErr error
}

func newFakeVRFLinks9819(events *[]string) *fakeVRFLinks9819 {
	return &fakeVRFLinks9819{events: events, links: map[string]*netlink.Vrf{}}
}

func (f *fakeVRFLinks9819) LinkByName(name string) (netlink.Link, error) {
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	return nil, errLinkNotFound{fmt.Errorf("link %s not found", name)}
}

func (f *fakeVRFLinks9819) LinkAdd(l netlink.Link) error {
	*f.events = append(*f.events, "link-add "+l.Attrs().Name)
	v, ok := l.(*netlink.Vrf)
	if !ok {
		return fmt.Errorf("fake: unexpected non-VRF add %T", l)
	}
	cp := *v
	f.links[v.Name] = &cp
	return nil
}

func (f *fakeVRFLinks9819) LinkDel(l netlink.Link) error {
	*f.events = append(*f.events, "link-del "+l.Attrs().Name)
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.links, l.Attrs().Name)
	return nil
}

func (f *fakeVRFLinks9819) LinkSetUp(netlink.Link) error                   { return nil }
func (f *fakeVRFLinks9819) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }

func (f *fakeVRFLinks9819) LinkList() ([]netlink.Link, error) {
	out := make([]netlink.Link, 0, len(f.links))
	for _, l := range f.links {
		out = append(out, l)
	}
	return out, nil
}

// fakeTerm9819 models the kernel's answers the terminator relies on: EEXIST
// for an install of a rule already present, ENOENT for a delete of an absent
// one. TestVRFMissTerminatorOnRealKernel9819 checks those answers on a kernel.
type fakeTerm9819 struct {
	events  *[]string
	present map[int]bool
	addErr  error
}

func newFakeTerm9819(events *[]string) *fakeTerm9819 {
	return &fakeTerm9819{events: events, present: map[int]bool{}}
}

func (f *fakeTerm9819) RuleAddL3mdevUnreachable(family, priority int) error {
	*f.events = append(*f.events, fmt.Sprintf("term-add %d %d", family, priority))
	if f.addErr != nil {
		return f.addErr
	}
	if f.present[family] {
		return unix.EEXIST
	}
	f.present[family] = true
	return nil
}

func (f *fakeTerm9819) RuleDel(r *netlink.Rule) error {
	*f.events = append(*f.events, fmt.Sprintf("term-del %d %d", r.Family, r.Priority))
	if r.Priority != vrfMissTerminatorPriority || !f.present[r.Family] {
		return unix.ENOENT
	}
	delete(f.present, r.Family)
	return nil
}

func termAdd9819(family int) string {
	return fmt.Sprintf("term-add %d %d", family, vrfMissTerminatorPriority)
}

func indexOf9819(events []string, prefix string) int {
	for i, e := range events {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

// TestVRFReconcileInstallsMissTerminatorBeforeAnyVRF9819 pins the ORDER: both
// families' terminators go in before the first VRF device exists. An outcome
// check cannot see this, because after Reconcile returns the terminator and
// the VRF are both present either way. A terminator installed after the device
// leaves a window in which the new VRF's misses fall through to main.
func TestVRFReconcileInstallsMissTerminatorBeforeAnyVRF9819(t *testing.T) {
	var events []string
	v := &vrfManager{ops: newFakeVRFLinks9819(&events), term: newFakeTerm9819(&events)}
	if err := v.Reconcile([]VRFSpec{{Name: "a", TableID: 100}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := []string{termAdd9819(unix.AF_INET), termAdd9819(unix.AF_INET6), "link-add vrf-a"}
	if strings.Join(events, " | ") != strings.Join(want, " | ") {
		t.Fatalf("event order = %q, want %q", events, want)
	}
}

// TestVRFCreateInstallsMissTerminator9819 covers the single-VRF Create path,
// which must not be a way around the terminator.
func TestVRFCreateInstallsMissTerminator9819(t *testing.T) {
	var events []string
	v := &vrfManager{ops: newFakeVRFLinks9819(&events), term: newFakeTerm9819(&events)}
	if err := v.Create("a", 100); err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []string{termAdd9819(unix.AF_INET), termAdd9819(unix.AF_INET6), "link-add vrf-a"}
	if strings.Join(events, " | ") != strings.Join(want, " | ") {
		t.Fatalf("event order = %q, want %q", events, want)
	}
}

// TestVRFReconcileReassertsMissTerminator9819 pins that every reconcile
// re-asserts the terminator. A rule deleted behind xpfd's back comes back on
// the next apply, and the EEXIST an already-installed rule produces is success,
// not a commit failure.
func TestVRFReconcileReassertsMissTerminator9819(t *testing.T) {
	var events []string
	term := newFakeTerm9819(&events)
	v := &vrfManager{ops: newFakeVRFLinks9819(&events), term: term}
	desired := []VRFSpec{{Name: "a", TableID: 100}}
	if err := v.Reconcile(desired); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	delete(term.present, unix.AF_INET) // removed out of band
	if err := v.Reconcile(desired); err != nil {
		t.Fatalf("second Reconcile must treat the v6 EEXIST as success: %v", err)
	}
	if !term.present[unix.AF_INET] || !term.present[unix.AF_INET6] {
		t.Fatalf("the second reconcile must restore the missing terminator; present=%v", term.present)
	}
}

// TestVRFReconcileRemovesMissTerminatorOnlyWhenNothingIsOwned9819 covers the
// three ways a reconcile can arrive with nothing desired.
func TestVRFReconcileRemovesMissTerminatorOnlyWhenNothingIsOwned9819(t *testing.T) {
	desired := []VRFSpec{{Name: "a", TableID: 100}}

	t.Run("the last VRF is removed", func(t *testing.T) {
		var events []string
		term := newFakeTerm9819(&events)
		v := &vrfManager{ops: newFakeVRFLinks9819(&events), term: term}
		if err := v.Reconcile(desired); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if err := v.Reconcile(nil); err != nil {
			t.Fatalf("Reconcile(nil): %v", err)
		}
		if len(term.present) != 0 {
			t.Fatalf("terminator must be removed once no VRF remains; present=%v", term.present)
		}
		if del, rm := indexOf9819(events, "link-del vrf-a"), indexOf9819(events, "term-del"); del < 0 || rm < del {
			t.Fatalf("the terminator must be removed AFTER the last VRF is gone; events=%q", events)
		}
	})

	t.Run("a VRF whose delete failed keeps its terminator", func(t *testing.T) {
		var events []string
		term := newFakeTerm9819(&events)
		links := newFakeVRFLinks9819(&events)
		v := &vrfManager{ops: links, term: term}
		if err := v.Reconcile(desired); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		links.delErr = unix.EBUSY
		if err := v.Reconcile(nil); err == nil {
			t.Fatal("a failed VRF delete must surface")
		}
		if !v.IsManaged("a") {
			t.Fatal("precondition: the undeleted VRF stays tracked")
		}
		if !term.present[unix.AF_INET] || !term.present[unix.AF_INET6] {
			t.Fatalf("vrf-a is still in the kernel, so its misses still need ending; present=%v", term.present)
		}
	})

	t.Run("a box with no VRF never installs one and commits cleanly", func(t *testing.T) {
		var events []string
		v := &vrfManager{ops: newFakeVRFLinks9819(&events), term: newFakeTerm9819(&events)}
		if err := v.Reconcile(nil); err != nil {
			t.Fatalf("an absent terminator is the desired end state, not an error: %v", err)
		}
		if i := indexOf9819(events, "term-add"); i >= 0 {
			t.Fatalf("no VRF is desired, so nothing may be installed; events=%q", events)
		}
	})
}

// TestVRFReconcileMissTerminatorFailureSurfaces9819 pins both halves of the
// failure contract. The error reaches the commit, the #5700 vrfErr path, so the
// next apply retries it. The VRF is still created, because skipping the link
// reconcile would turn one missing rule into a missing routing instance.
func TestVRFReconcileMissTerminatorFailureSurfaces9819(t *testing.T) {
	var events []string
	term := newFakeTerm9819(&events)
	term.addErr = unix.EPERM
	v := &vrfManager{ops: newFakeVRFLinks9819(&events), term: term}
	err := v.Reconcile([]VRFSpec{{Name: "a", TableID: 100}})
	if err == nil || !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "VRF miss terminator") {
		t.Fatalf("Reconcile error = %v, want the terminator's EPERM", err)
	}
	if !v.IsManaged("a") {
		t.Fatal("a terminator failure must not skip creating the VRF")
	}
}

func returnRules9819(ops *fakeRuleOps, family int) []string {
	var out []string
	for _, r := range ops.rules[family] {
		if r.Priority != ribGroupReturnRulePriority {
			continue
		}
		out = append(out, fmt.Sprintf("iif=%s oif=%s table=%d dst=%v src=%v",
			r.IifName, r.OifName, r.Table, r.Dst, r.Src))
	}
	sort.Strings(out)
	return out
}

// TestRibGroupReturnRules9819 pins which sources get a return path and what it
// is. The population is the leak-into-main set, narrowed to families whose
// leak installed a prefix and to instances that have a VRF device. The path is
// `main`, and nothing else, via both selectors.
func TestRibGroupReturnRules9819(t *testing.T) {
	ribGroups := map[string]*config.RibGroup{
		"src-leak":  {ImportRibs: []string{"src.inet.0", "inet.0"}},
		"src-leak6": {ImportRibs: []string{"src.inet6.0", "inet6.0"}},
		"b-leak":    {ImportRibs: []string{"b.inet.0", "inet.0"}},
		"c-leak6":   {ImportRibs: []string{"c.inet6.0", "inet6.0"}},
		"f-leak":    {ImportRibs: []string{"f.inet.0", "inet.0"}},
		"vrf-only":  {ImportRibs: []string{"n.inet.0", "b.inet.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "src", TableID: 200, InterfaceRoutesRibGroup: "src-leak", InterfaceRoutesRibGroupV6: "src-leak6"},
		{Name: "b", TableID: 300, InterfaceRoutesRibGroup: "b-leak"},    // v4 leak; its v6 prefix is not leaked
		{Name: "c", TableID: 400, InterfaceRoutesRibGroupV6: "c-leak6"}, // v6 leak with no v6 prefix
		{Name: "f", TableID: 500, InstanceType: "forwarding", InterfaceRoutesRibGroup: "f-leak"},
		{Name: "n", TableID: 600, InterfaceRoutesRibGroup: "vrf-only"}, // VRF->VRF: no main leak
		{Name: "plain", TableID: 700},
	}
	connected := map[string][]string{
		"src":   {"10.30.0.0/24", "2001:db8:30::/64"},
		"b":     {"10.40.0.0/24", "2001:db8:40::/64"},
		"c":     {"10.50.0.0/24"},
		"f":     {"10.60.0.0/24"},
		"n":     {"10.70.0.0/24"},
		"plain": {"10.80.0.0/24"},
	}
	wantV4 := []string{
		"iif= oif=vrf-b table=254 dst=<nil> src=<nil>",
		"iif= oif=vrf-src table=254 dst=<nil> src=<nil>",
		"iif=vrf-b oif= table=254 dst=<nil> src=<nil>",
		"iif=vrf-src oif= table=254 dst=<nil> src=<nil>",
	}
	wantV6 := []string{
		"iif= oif=vrf-src table=254 dst=<nil> src=<nil>",
		"iif=vrf-src oif= table=254 dst=<nil> src=<nil>",
	}

	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}
	// Twice: clear() must own the return priority, or the second apply
	// stacks a duplicate set on the first.
	for pass := 1; pass <= 2; pass++ {
		if err := rg.Apply(ribGroups, instances, connected); err != nil {
			t.Fatalf("pass %d: Apply: %v", pass, err)
		}
		if got := returnRules9819(ops, unix.AF_INET); strings.Join(got, "\n") != strings.Join(wantV4, "\n") {
			t.Errorf("pass %d: v4 return rules =\n%s\nwant\n%s", pass, strings.Join(got, "\n"), strings.Join(wantV4, "\n"))
		}
		if got := returnRules9819(ops, unix.AF_INET6); strings.Join(got, "\n") != strings.Join(wantV6, "\n") {
			t.Errorf("pass %d: v6 return rules =\n%s\nwant\n%s", pass, strings.Join(got, "\n"), strings.Join(wantV6, "\n"))
		}
	}

	// The final rib-group removal takes the return rules with the leaks.
	if err := rg.Apply(nil, instances, connected); err != nil {
		t.Fatalf("zero-transition Apply: %v", err)
	}
	if got := append(returnRules9819(ops, unix.AF_INET), returnRules9819(ops, unix.AF_INET6)...); len(got) != 0 {
		t.Fatalf("return rules must not outlive the last rib-group: %q", got)
	}
}

// netnsChild9819 marks the re-executed test binary that runs inside the
// private network namespace.
const netnsChild9819 = "XPF_9819_NETNS_CHILD"

// TestVRFMissTerminatorOnRealKernel9819 is the kernel half, in the #9420
// style. It re-executes this test binary in a private user and network
// namespace and drives a Manager built by New, so the raw FRA_L3MDEV encoder,
// the production wiring and the kernel's EEXIST/ENOENT answers are exercised,
// not modelled.
//
// The defect is reproduced before the fix is applied, in the same run. A fix
// row that says "unreachable" cannot tell "terminated" from "this topology had
// no route anyway" without a baseline row that resolved.
func TestVRFMissTerminatorOnRealKernel9819(t *testing.T) {
	if os.Getenv(netnsChild9819) == "1" {
		vrfMissTerminatorNetnsChild9819(t)
		return
	}
	for _, tool := range []string{"unshare", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0],
		"-test.run", "^TestVRFMissTerminatorOnRealKernel9819$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), netnsChild9819+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-9819") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-9819") {
		t.Fatalf("real-kernel cell failed inside the namespace (%v):\n%s", err, out)
	}
}

func vrfMissTerminatorNetnsChild9819(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-9819")
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	// get returns the first line of an `ip route get`, error text included: an
	// unreachable verdict arrives as an RTNETLINK error, and that is the
	// observation.
	get := func(args ...string) string {
		out, _ := exec.Command("ip", args...).CombinedOutput()
		line, _, _ := strings.Cut(string(out), "\n")
		return strings.TrimSpace(line)
	}
	expect := func(label string, args []string, want string) {
		t.Helper()
		if got := get(args...); !strings.Contains(got, want) {
			t.Errorf("%s: ip %s = %q, want %q", label, strings.Join(args, " "), got, want)
		}
	}
	rules := func(family string) string {
		t.Helper()
		out, err := exec.Command("ip", family, "rule", "show").CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s rule show: %v: %s", family, err, out)
		}
		return string(out)
	}
	for _, p := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(p, []byte("1"), 0o644); err != nil {
			t.Logf("%s: %v (the main-ingress controls below would fail if forwarding were off)", p, err)
		}
	}

	run("link", "set", "lo", "up")
	run("link", "add", "xmain", "type", "dummy")
	run("link", "set", "xmain", "up")
	run("addr", "add", "10.20.0.1/24", "dev", "xmain")
	run("-6", "addr", "add", "2001:db8:20::1/64", "dev", "xmain", "nodad")
	run("route", "add", "default", "via", "10.20.0.254", "dev", "xmain", "onlink")
	run("-6", "route", "add", "default", "via", "2001:db8:20::fe", "dev", "xmain", "onlink")
	vrf := func(name, table, slave, v4, v6 string) {
		run("link", "add", name, "type", "vrf", "table", table)
		run("link", "set", name, "up")
		run("link", "add", slave, "type", "dummy")
		run("link", "set", slave, "master", name)
		run("link", "set", slave, "up")
		run("addr", "add", v4, "dev", slave)
		run("-6", "addr", "add", v6, "dev", slave, "nodad")
	}
	vrf("vrf-a", "100", "slavea", "10.10.0.1/24", "2001:db8:10::1/64")
	vrf("vrf-src", "200", "slavesrc", "10.30.0.1/24", "2001:db8:30::1/64")
	vrf("vrf-b", "300", "slaveb", "10.40.0.1/24", "2001:db8:40::1/64")
	run("route", "add", "10.77.0.0/16", "via", "10.10.0.254", "dev", "slavea", "onlink", "table", "100")

	var (
		missSlave4     = []string{"route", "get", "10.99.0.1", "from", "10.10.0.50", "iif", "slavea"}
		missSocket4    = []string{"route", "get", "10.99.0.1", "vrf", "vrf-a"}
		missSlave6     = []string{"-6", "route", "get", "2001:db8:99::1", "from", "2001:db8:10::50", "iif", "slavea"}
		missSocket6    = []string{"-6", "route", "get", "2001:db8:99::1", "vrf", "vrf-a"}
		leakSocket4    = []string{"route", "get", "10.30.0.5", "vrf", "vrf-a"}
		leakSlave4     = []string{"route", "get", "10.30.0.5", "from", "10.10.0.50", "iif", "slavea"}
		srcOtherLeak4  = []string{"route", "get", "10.40.0.5", "vrf", "vrf-src"}
		connected4     = []string{"route", "get", "10.10.0.9", "vrf", "vrf-a"}
		static4        = []string{"route", "get", "10.77.0.1", "vrf", "vrf-a"}
		mainToLeak4    = []string{"route", "get", "10.30.0.5", "from", "10.20.0.50", "iif", "xmain"}
		returnSlave4   = []string{"route", "get", "10.20.0.50", "from", "10.30.0.5", "iif", "slavesrc"}
		returnSocket4  = []string{"route", "get", "10.20.0.50", "vrf", "vrf-src"}
		mainToLeak6    = []string{"-6", "route", "get", "2001:db8:30::5", "from", "2001:db8:20::50", "iif", "xmain"}
		returnSocket6  = []string{"-6", "route", "get", "2001:db8:20::50", "vrf", "vrf-src"}
		mainUntouched4 = []string{"route", "get", "10.99.0.1", "from", "10.20.0.50", "iif", "xmain"}
	)

	m, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// 0. The defect, before any xpf rule: a VRF miss leaves through main.
	expect("baseline slave miss", missSlave4, "dev xmain")
	expect("baseline socket miss", missSocket4, "dev xmain")
	expect("baseline v6 socket miss", missSocket6, "dev xmain")
	if t.Failed() {
		t.Fatal("the baseline did not reproduce #9819, so the rows below would not measure the fix")
	}

	ribGroups := map[string]*config.RibGroup{
		"src-leak":  {ImportRibs: []string{"src.inet.0", "inet.0"}},
		"src-leak6": {ImportRibs: []string{"src.inet6.0", "inet6.0"}},
		"b-leak":    {ImportRibs: []string{"b.inet.0", "inet.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "a", TableID: 100},
		{Name: "src", TableID: 200, InterfaceRoutesRibGroup: "src-leak", InterfaceRoutesRibGroupV6: "src-leak6"},
		{Name: "b", TableID: 300, InterfaceRoutesRibGroup: "b-leak"},
	}
	connected := map[string][]string{
		"src": {"10.30.0.0/24", "2001:db8:30::/64"},
		"b":   {"10.40.0.0/24"},
	}
	desired := []VRFSpec{{Name: "a", TableID: 100}, {Name: "src", TableID: 200}, {Name: "b", TableID: 300}}

	// 1. The rib-group band alone reaches VRF lookups (SYN-RIB-03).
	if err := m.ApplyRibGroupRules(ribGroups, instances, connected); err != nil {
		t.Fatalf("ApplyRibGroupRules: %v", err)
	}
	expect("band reaches a VRF lookup", leakSocket4, "table 200")
	if t.Failed() {
		t.Fatal("the band did not reach a VRF lookup, so the leak rows below would not measure the fix")
	}

	// 2. The fix.
	if err := m.ReconcileVRFs(desired); err != nil {
		t.Fatalf("ReconcileVRFs: %v", err)
	}
	for _, c := range []struct {
		label string
		args  []string
	}{
		{"slave miss", missSlave4}, {"socket miss", missSocket4},
		{"v6 slave miss", missSlave6}, {"v6 socket miss", missSocket6},
		{"socket lookup of a leaked prefix", leakSocket4}, {"slave lookup of a leaked prefix", leakSlave4},
	} {
		expect(c.label, c.args, "unreachable")
	}
	// The source's return path is main, and only main: another source's
	// leaked prefix resolves through main's default, not in that source's
	// table.
	expect("source miss resolves in main", srcOtherLeak4, "dev xmain")
	if got := get(srcOtherLeak4...); strings.Contains(got, "table 300") {
		t.Errorf("a source's miss must not reach the band: %q", got)
	}
	// Controls.
	expect("VRF connected route", connected4, "table 100")
	expect("VRF static route", static4, "table 100")
	expect("main still uses the leak, reverse path included", mainToLeak4, "table 200")
	expect("return lookup from the source's slave", returnSlave4, "dev xmain")
	expect("return lookup from a source-bound socket", returnSocket4, "dev xmain")
	expect("v6 main still uses the leak", mainToLeak6, "table 200")
	expect("v6 return lookup from a source-bound socket", returnSocket6, "dev xmain")
	expect("main routing untouched", mainUntouched4, "via 10.20.0.254")

	// 3. A second apply of both is clean and installs nothing twice.
	if err := m.ReconcileVRFs(desired); err != nil {
		t.Fatalf("second ReconcileVRFs (EEXIST must be success): %v", err)
	}
	if err := m.ApplyRibGroupRules(ribGroups, instances, connected); err != nil {
		t.Fatalf("second ApplyRibGroupRules: %v", err)
	}
	for _, fam := range []string{"-4", "-6"} {
		if n := strings.Count(rules(fam), "unreachable"); n != 1 {
			t.Errorf("ip %s rule: %d terminators after a re-apply, want 1:\n%s", fam, n, rules(fam))
		}
	}
	expect("socket miss after re-apply", missSocket4, "unreachable")
	expect("return lookup after re-apply", returnSocket4, "dev xmain")

	// 4. Removal takes everything back out.
	if err := m.ApplyRibGroupRules(nil, instances, nil); err != nil {
		t.Fatalf("zero-transition ApplyRibGroupRules: %v", err)
	}
	if r := rules("-4"); strings.Contains(r, "1500:") {
		t.Errorf("return rules must go with the last rib-group:\n%s", r)
	}
	if err := m.ReconcileVRFs(nil); err != nil {
		t.Fatalf("ReconcileVRFs(nil): %v", err)
	}
	for _, fam := range []string{"-4", "-6"} {
		if r := rules(fam); strings.Contains(r, "unreachable") {
			t.Errorf("ip %s rule: the terminator must go with the last VRF:\n%s", fam, r)
		}
	}
	if !t.Failed() {
		fmt.Println("NETNS-CHILD-PASSED-9819")
	}
}

// rulesInWindow9819 counts a family's rules with lo <= priority < hi.
func rulesInWindow9819(ops *fakeRuleOps, family, lo, hi int) int {
	n := 0
	for _, r := range ops.rules[family] {
		if r.Priority >= lo && r.Priority < hi {
			n++
		}
	}
	return n
}

// assertRibGroupRulesInClearedWindows9819 is the #1706 "nothing leaks across
// applies" invariant for the rib-group manager. Each rule must sit at a
// priority ribGroupManager.clear() removes: the leak window, or the #9819
// return priority.
func assertRibGroupRulesInClearedWindows9819(t *testing.T, ops *fakeRuleOps) {
	t.Helper()
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, r := range ops.rules[family] {
			inLeak := r.Priority >= ribGroupLeakRulePriority && r.Priority < ribGroupLeakRulePriority+maxRibGroupLeakRules
			if !inLeak && r.Priority != ribGroupReturnRulePriority {
				t.Errorf("rule priority %d is in no window clear() scans ([%d,%d) or %d) — would leak",
					r.Priority, ribGroupLeakRulePriority, ribGroupLeakRulePriority+maxRibGroupLeakRules, ribGroupReturnRulePriority)
			}
		}
	}
}
