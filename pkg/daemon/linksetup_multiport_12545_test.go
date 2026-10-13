package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// #12545: NICs that put several netdevs on one PCI function (mlx4, cxgb4,
// switchdev representors) share one busAddr. enumeratePCINICs must order
// those ties by the hardware port identity (dev_port, then
// phys_port_name), never by the current interface name: after a successful
// claim renames port 0 to fxp0, a name-sorted re-enumeration puts fxp0
// after its still-kernel-named sibling ("fxp0" > "enp1s0d1"
// lexicographically), so the claimed interface lands at enum_index=1 and
// the bootstrap index-0 remedy refuses forever, telling the operator to
// re-wire to the port they just left.

// multiportSysfs12545 builds a fake /sys/class/net tree:

//	<root>/<name>/device -> <root>/pci/<busAddr>/... (symlink chain whose
//	                        real path ends in the PCI address)
//	<root>/<name>/device/driver -> ../drivers/<driver>
//	<root>/<name>/dev_port, <root>/<name>/phys_port_name (optional files)
//
// The device symlink target is a directory whose name IS the PCI address,
// so filepath.EvalSymlinks + extractPCIAddr resolve it exactly as on a
// real box.
type multiportDev12545 struct {
	name, busAddr, driver string
	devPort               *int
	devPortRaw            string // malformed/unparseable file contents, if set
	physPortName          string // "" = file absent
}

func writeMultiportSysfs12545(t *testing.T, devs []multiportDev12545) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range devs {
		netDir := filepath.Join(root, d.name)
		if err := os.MkdirAll(netDir, 0o755); err != nil {
			t.Fatal(err)
		}
		pciDir := filepath.Join(root, "pci", d.busAddr)
		if err := os.MkdirAll(pciDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(pciDir, filepath.Join(netDir, "device")); err != nil {
			t.Fatal(err)
		}
		drvDir := filepath.Join(root, "drivers", d.driver)
		if err := os.MkdirAll(drvDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(drvDir, filepath.Join(netDir, "device", "driver")); err != nil {
			// device is a symlink to pciDir, so this creates
			// pciDir/driver; a second function sharing the busAddr
			// would try to create it again.
			if !os.IsExist(err) {
				t.Fatal(err)
			}
		}
		if d.devPortRaw != "" {
			if err := os.WriteFile(filepath.Join(netDir, "dev_port"),
				[]byte(d.devPortRaw+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		} else if d.devPort != nil {
			if err := os.WriteFile(filepath.Join(netDir, "dev_port"),
				[]byte(fmt.Sprintf("%d\n", *d.devPort)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if d.physPortName != "" {
			if err := os.WriteFile(filepath.Join(netDir, "phys_port_name"),
				[]byte(d.physPortName+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func intPtr12545(v int) *int { return &v }

func enumerate12545(t *testing.T, devs []multiportDev12545) []pciNIC {
	t.Helper()
	root := writeMultiportSysfs12545(t, devs)
	old := sysClassNetRoot
	sysClassNetRoot = root
	t.Cleanup(func() { sysClassNetRoot = old })
	nics, err := enumeratePCINICs()
	if err != nil {
		t.Fatalf("enumeratePCINICs: %v", err)
	}
	return nics
}

func nicNames12545(nics []pciNIC) []string {
	out := make([]string, len(nics))
	for i, n := range nics {
		out[i] = n.name
	}
	return out
}

func wantNames12545(t *testing.T, nics []pciNIC, want []string) {
	t.Helper()
	got := nicNames12545(nics)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("#12545: enumeration order = %v, want %v", got, want)
	}
}

// The reported bug, end to end at the enumeration layer: both ports of
// one mlx4 function, first boot (kernel names) and second boot (port 0
// claimed as fxp0). The claimed port must stay at index 0 in both.
func TestEnumerateMultiportSharedFunctionSettles12545(t *testing.T) {
	const bus = "0000:01:00.0"

	first := enumerate12545(t, []multiportDev12545{
		{name: "enp1s0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
		{name: "enp1s0d1", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(1)},
	})
	wantNames12545(t, first, []string{"enp1s0", "enp1s0d1"})

	// After the claim, port 0 wears fxp0. Lexicographically
	// "enp1s0d1" < "fxp0", so a name tie-break would demote the claimed
	// port to index 1 (the never-settling refusal).
	second := enumerate12545(t, []multiportDev12545{
		{name: "fxp0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
		{name: "enp1s0d1", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(1)},
	})
	wantNames12545(t, second, []string{"fxp0", "enp1s0d1"})
}

// dev_port is numeric: port 10 sorts after port 2 even though the kernel
// names (and "10" as a string) sort the other way. Kills lexical dev_port
// and pure name tie-breaks.
func TestEnumerateMultiportDevPortNumeric12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "enp1s0d10", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(10)},
		{name: "enp1s0d2", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(2)},
		{name: "enp1s0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
	})
	wantNames12545(t, nics, []string{"enp1s0", "enp1s0d2", "enp1s0d10"})
}

// A port with a readable dev_port precedes one without; two dev_port-less
// ports keep deterministic name order. Kills "missing sorts first" and
// nondeterministic-equal mutants.
func TestEnumerateMultiportMissingDevPortLast12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "aaa0", busAddr: bus, driver: "mlx4_en"},
		{name: "zzz0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
		{name: "mmm0", busAddr: bus, driver: "mlx4_en"},
	})
	wantNames12545(t, nics, []string{"zzz0", "aaa0", "mmm0"})
}

// A malformed dev_port is treated as unavailable rather than as port zero;
// when both dev_port values tie, phys_port_name orders the pair before
// falling back to names.
func TestEnumerateMultiportUnparseableDevPortFallsBack12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "z-rep", busAddr: bus, driver: "mlx5_core", devPortRaw: "bogus", physPortName: "p1"},
		{name: "a-rep", busAddr: bus, driver: "mlx5_core", devPortRaw: "not-a-number", physPortName: "p0"},
	})
	wantNames12545(t, nics, []string{"a-rep", "z-rep"})
}

// When dev_port is duplicated, phys_port_name must distinguish it before
// current names; a missing phys_port_name still uses a stable name fallback.
func TestEnumerateMultiportDuplicateDevPortFallsBack12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "z-rep", busAddr: bus, driver: "mlx5_core", devPort: intPtr12545(0), physPortName: "p1"},
		{name: "a-rep", busAddr: bus, driver: "mlx5_core", devPort: intPtr12545(0), physPortName: "p0"},
		{name: "c-rep", busAddr: bus, driver: "mlx5_core", devPort: intPtr12545(0)},
		{name: "b-rep", busAddr: bus, driver: "mlx5_core", devPort: intPtr12545(0)},
	})
	wantNames12545(t, nics, []string{"a-rep", "z-rep", "b-rep", "c-rep"})
}

// phys_port_name covers switchdev representors (dev_port may be absent):
// p1 before p0 in name order must still enumerate p0 first. Kills
// raw-string phys_port_name compares when combined with the numeric case
// below.
func TestEnumerateMultiportPhysPortName12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "enp1s0f1np1", busAddr: bus, driver: "mlx5_core", physPortName: "p1"},
		{name: "enp1s0f0np0", busAddr: bus, driver: "mlx5_core", physPortName: "p0"},
	})
	wantNames12545(t, nics, []string{"enp1s0f0np0", "enp1s0f1np1"})
}

// pf1vf10 vs pf0vf2 style representors: the trailing number is numeric,
// so vf2 (port 2) precedes vf10 (port 10) — a raw-string compare inverts
// them. dev_port is present-but-equal here is impossible on real
// representors, so phys_port_name alone must carry the order.
func TestEnumerateMultiportPhysPortNameNumeric12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "rep10", busAddr: bus, driver: "mlx5_core", physPortName: "pf0vf10"},
		{name: "rep2", busAddr: bus, driver: "mlx5_core", physPortName: "pf0vf2"},
	})
	wantNames12545(t, nics, []string{"rep2", "rep10"})
}

// Full dev_port ties fall through to phys_port_name, then to name, so the
// comparator stays a strict total order (sort.Slice is not stable).
func TestEnumerateMultiportTieFallthrough12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "b0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0), physPortName: "p1"},
		{name: "a0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0), physPortName: "p0"},
		{name: "d0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
		{name: "c0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
	})
	wantNames12545(t, nics, []string{"a0", "b0", "c0", "d0"})
}

// Regression guard: distinct functions keep (sortKey, busAddr) order with
// a virtio NIC first, regardless of port attributes on the hardware NICs.
func TestEnumerateDistinctFunctionsUnchanged12545(t *testing.T) {
	nics := enumerate12545(t, []multiportDev12545{
		{name: "enp6s0", busAddr: "0000:06:00.0", driver: "igb", devPort: intPtr12545(0)},
		{name: "enp5s0", busAddr: "0000:05:00.0", driver: "virtio_net", devPort: intPtr12545(0)},
		{name: "enp7s0", busAddr: "0000:05:00.1", driver: "igb", devPort: intPtr12545(0)},
	})
	wantNames12545(t, nics, []string{"enp5s0", "enp7s0", "enp6s0"})
}

// Bootstrap remedy index-0 stability: feed the enumeration through the
// same index-0 acceptance the lifeline remedy applies (nics[0] is the
// claimed fxp0), mirroring setupBootstrapLifeline's idx==0 requirement.
func TestEnumerateMultiportClaimedStaysIndexZero12545(t *testing.T) {
	const bus = "0000:01:00.0"
	nics := enumerate12545(t, []multiportDev12545{
		{name: "enp1s0d1", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(1)},
		{name: "fxp0", busAddr: bus, driver: "mlx4_en", devPort: intPtr12545(0)},
	})
	if len(nics) == 0 || nics[0].name != "fxp0" {
		t.Fatalf("#12545: claimed fxp0 must enumerate at index 0, got %v", nicNames12545(nics))
	}
}
