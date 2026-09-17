package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gnft "github.com/google/nftables"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"golang.org/x/sys/unix"
)

const transitBarrierInnerEnv9852 = "XPF_TRANSIT_BARRIER_9852_INNER"

// TestTransitBarrierBootUnitFailsClosed9852 is the static fail-on-revert proof
// for the cold-boot boundary. RequiredBy plus Before makes networkd activation
// conditional on a successful barrier install; the bare ExecStart (without a
// systemd '-' prefix) preserves that failure into the required unit. The unit
// contains no sysctl writer: #9725 remains the sole forwarding-knob owner.
func TestTransitBarrierBootUnitFailsClosed9852(t *testing.T) {
	root := transitBarrierRepoRoot9852(t)
	unit := transitBarrierReadFile9852(t, filepath.Join(root, "scripts", "image", "xpf-transit-closed.service"))
	unitCode := transitBarrierUnitCodeOnly9852(unit)
	if !strings.Contains(unitCode, "[Unit]") {
		t.Fatal("boot barrier unit has no [Unit] section; ordering directives could be ignored")
	}
	unitSection := transitBarrierSection9852(unitCode, "Unit")
	serviceSection := transitBarrierSection9852(unitCode, "Service")
	installSection := transitBarrierSection9852(unitCode, "Install")
	for _, check := range []struct {
		section string
		want    string
	}{
		{section: unitSection, want: "After=nftables.service"},
		{section: unitSection, want: "Before=network-pre.target systemd-networkd.service frr.service xpfd.service"},
		{section: serviceSection, want: "ExecStart=/usr/local/sbin/xpfd transit-barrier close"},
		{section: installSection, want: "RequiredBy=systemd-networkd.service"},
		{section: serviceSection, want: "Type=oneshot"},
		{section: serviceSection, want: "RemainAfterExit=yes"},
	} {
		if !strings.Contains(check.section, check.want) {
			t.Errorf("boot barrier unit missing %q in effective section", check.want)
		}
	}
	if strings.Contains(serviceSection, "ExecStart=-") {
		t.Error("boot barrier unit ignores ExecStart failure; networkd could recreate bridges without a barrier")
	}
	for _, forbidden := range []string{"ip_forward", "conf/all/forwarding", "sysctl"} {
		if strings.Contains(unitCode, forbidden) {
			t.Errorf("boot barrier unit owns #9725 forwarding knob %q; barrier must remain bridge-only", forbidden)
		}
	}

	xpfdUnit := transitBarrierReadFile9852(t, filepath.Join(root, "test", "incus", "xpfd.service"))
	if !strings.Contains(xpfdUnit, "After=network-online.target frr.service") {
		t.Fatalf("xpfd service ordering changed unexpectedly; cannot prove networkd-to-xpfd boot window: %q", xpfdUnit)
	}

	barrierSource := transitBarrierReadFile9852(t, filepath.Join(root, "pkg", "nftables", "transit_barrier.go"))
	code := transitBarrierCodeOnly9852(barrierSource)
	if !strings.Contains(code, "ChainHookForward") {
		t.Error("transit barrier has no forward hook; bridged transit is not fenced")
	}
	if strings.Contains(code, "ChainHookInput") || strings.Contains(code, "ChainHookOutput") {
		t.Error("transit barrier gained an input/output hook and could disturb management or loopback")
	}
}

// TestTransitBarrierBootStaging9852 is the fail-on-revert proof that every
// image/install surface carries the early unit. The Incus paths deploy raw
// binaries (so they cannot rely on package units); the image and Debian paths
// each stage and enable the same source unit.
func TestTransitBarrierBootStaging9852(t *testing.T) {
	root := transitBarrierRepoRoot9852(t)
	checks := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "debian package",
			path: filepath.Join(root, "debian", "rules"),
			want: []string{
				"cp scripts/image/xpf-transit-closed.service debian/xpf.xpf-transit-closed.service",
				"dh_installsystemd --no-start --no-stop-on-upgrade --name=xpf-transit-closed",
			},
		},
		{
			name: "baked image",
			path: filepath.Join(root, "scripts", "image", "bake.py"),
			want: []string{
				"--copy-in\", f\"{HERE}/xpf-transit-closed.service:/usr/lib/systemd/system",
				"systemctl enable xpf-transit-closed.service",
			},
		},
		{
			name: "standalone Incus",
			path: filepath.Join(root, "test", "incus", "setup.sh"),
			want: []string{
				"${PROJECT_ROOT}/scripts/image/xpf-transit-closed.service",
				"systemctl enable --now xpf-transit-closed.service",
			},
		},
		{
			name: "cluster Incus",
			path: filepath.Join(root, "test", "incus", "cluster-setup.sh"),
			want: []string{
				"${PROJECT_ROOT}/scripts/image/xpf-transit-closed.service",
				"systemctl enable --now xpf-transit-closed.service",
			},
		},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			source := transitBarrierReadFile9852(t, check.path)
			for _, want := range check.want {
				if !strings.Contains(source, want) {
					t.Errorf("%s missing %q", check.path, want)
				}
			}
		})
	}
}

// TestTransitBarrierNetlinkParity9852 runs in a private network namespace and
// proves the actual barrier objects produced by the netlink installer: both
// families, one forward base chain, explicit priority 0, policy DROP, and no
// rules. Reinstalling and comparing the observed shape proves daemon takeover
// is idempotent; removal proves the #9725 open path can clear both legs.
func TestTransitBarrierNetlinkParity9852(t *testing.T) {
	if os.Getenv(transitBarrierInnerEnv9852) == "1" {
		runTransitBarrierNetlinkParityInner9852(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("bridge-barrier kernel cell SKIPPED: unshare not found")
	}
	args := []string{"-rn", os.Args[0], "-test.run", "^TestTransitBarrierNetlinkParity9852$", "-test.v"}
	cmd := exec.Command(unshare, args...)
	cmd.Env = append(os.Environ(), transitBarrierInnerEnv9852+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("inner bridge-barrier output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "operation not permitted") || strings.Contains(string(out), "unshare:") {
			t.Skipf("bridge-barrier kernel cell SKIPPED: cannot create private netns (%v)", err)
		}
		t.Fatalf("bridge-barrier kernel cell FAILED: %v", err)
	}
}

type transitBarrierShape9852 struct {
	family   gnft.TableFamily
	table    string
	chain    string
	hook     gnft.ChainHook
	priority gnft.ChainPriority
	typ      gnft.ChainType
	policy   gnft.ChainPolicy
	rules    int
}

func runTransitBarrierNetlinkParityInner9852(t *testing.T) {
	inst := xnft.NewNetlinkInstaller()
	if err := inst.RemoveTransitBarrier(); err != nil {
		t.Fatalf("remove stale barrier before cell: %v", err)
	}
	defer func() {
		if err := inst.RemoveTransitBarrier(); err != nil {
			t.Errorf("remove barrier after cell: %v", err)
		}
	}()

	if err := inst.InstallTransitBarrier(); err != nil {
		if transitBarrierUnsupported9852(err) {
			t.Skipf("bridge-barrier kernel cell SKIPPED: nf_tables family unavailable: %v", err)
		}
		t.Fatalf("install barrier: %v", err)
	}
	first := make(map[gnft.TableFamily]transitBarrierShape9852, 2)
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		got := transitBarrierReadShape9852(t, family)
		want := transitBarrierShape9852{
			family: family, table: xnft.TransitBarrierTableName, chain: "forward",
			hook: *gnft.ChainHookForward, priority: 0,
			typ: gnft.ChainTypeFilter, policy: gnft.ChainPolicyDrop, rules: 0,
		}
		if got != want {
			t.Errorf("family %d barrier shape = %+v, want %+v", family, got, want)
		}
		first[family] = got
	}

	if err := inst.InstallTransitBarrier(); err != nil {
		t.Fatalf("idempotent reinstall barrier: %v", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		got := transitBarrierReadShape9852(t, family)
		if got != first[family] {
			t.Errorf("family %d changed across idempotent reinstall: first=%+v second=%+v", family, first[family], got)
		}
	}

	if err := inst.RemoveTransitBarrier(); err != nil {
		t.Fatalf("remove installed barrier: %v", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		if transitBarrierTableExists9852(t, family) {
			t.Errorf("family %d still has %s after RemoveTransitBarrier", family, xnft.TransitBarrierTableName)
		}
	}
}

func transitBarrierReadShape9852(t *testing.T, family gnft.TableFamily) transitBarrierShape9852 {
	t.Helper()
	conn, err := gnft.New()
	if err != nil {
		t.Fatalf("open nftables connection: %v", err)
	}
	tables, err := conn.ListTablesOfFamily(family)
	if err != nil {
		t.Fatalf("list family %d tables: %v", family, err)
	}
	var table *gnft.Table
	for _, candidate := range tables {
		if candidate.Name == xnft.TransitBarrierTableName {
			table = candidate
			break
		}
	}
	if table == nil {
		t.Fatalf("family %d missing table %s", family, xnft.TransitBarrierTableName)
	}
	chains, err := conn.ListChainsOfTableFamily(family)
	if err != nil {
		t.Fatalf("list family %d chains: %v", family, err)
	}
	var chain *gnft.Chain
	for _, candidate := range chains {
		if candidate.Table != nil && candidate.Table.Name == table.Name && candidate.Name == "forward" {
			chain = candidate
			break
		}
	}
	if chain == nil || chain.Hooknum == nil || chain.Priority == nil || chain.Policy == nil {
		t.Fatalf("family %d missing complete forward base chain: %+v", family, chain)
	}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		t.Fatalf("list family %d forward rules: %v", family, err)
	}
	return transitBarrierShape9852{
		family: family, table: table.Name, chain: chain.Name,
		hook: *chain.Hooknum, priority: *chain.Priority,
		typ: chain.Type, policy: *chain.Policy, rules: len(rules),
	}
}

func transitBarrierTableExists9852(t *testing.T, family gnft.TableFamily) bool {
	t.Helper()
	conn, err := gnft.New()
	if err != nil {
		t.Fatalf("open nftables connection: %v", err)
	}
	tables, err := conn.ListTablesOfFamily(family)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT) {
			return false
		}
		t.Fatalf("list family %d tables after removal: %v", family, err)
	}
	for _, table := range tables {
		if table.Name == xnft.TransitBarrierTableName {
			return true
		}
	}
	return false
}

func transitBarrierUnsupported9852(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "operation not supported") ||
		strings.Contains(text, "address family not supported") ||
		strings.Contains(text, "protocol not supported")
}

func transitBarrierRepoRoot9852(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func transitBarrierReadFile9852(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func transitBarrierCodeOnly9852(source string) string {
	var lines []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func transitBarrierUnitCodeOnly9852(source string) string {
	var lines []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func transitBarrierSection9852(source, name string) string {
	var lines []string
	active := false
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			active = trimmed == "["+name+"]"
			continue
		}
		if active {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
