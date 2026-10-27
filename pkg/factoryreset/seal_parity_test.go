package factoryreset

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// seal_parity_test.go binds zeroize's erase set to the image seal set
// (#17085, R4-Q46-01). bake.py declares SYSPREP_ENABLE_OPS /
// SYSPREP_PURGE_PATHS the SINGLE SOURCE for the seal, and wipeSealMapping
// claims to mirror them. Before this test the mirror was hand-maintained:
// #10769 was the demonstrated cost (SSH host keys, machine-id and the
// SNMPv3 EngineID survived a factory reset because the runtime erase set
// was never derived from the seal). The test parses both tuples out of
// bake.py, requires every member to have exactly one disposition in
// wipeSealMapping (leg marker or survivor-with-reason), requires no stale
// rows, and drives the production wipe once (PerformZeroizeWipe against
// the redirected appliance tree) asserting every leg member's planted
// prior-tenant path is gone (or, for machine-id, rotated) and the day-0
// survivor stamp is gone after completion. The mapping's leg field is an
// honest marker only: posture gates and the configured config root live
// inside the production wipe, so no per-member closure could be
// production-identical; the driven leg is PerformZeroizeWipe itself.

func sealParityRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

var sealTupleStringRe = regexp.MustCompile(`"([^"]*)"`)

// parseSealTuple extracts the string members of one top-level bake.py
// tuple (NAME = ( ... )) from bake source text. It fails the test when
// the tuple is absent or empty: a parser that finds nothing must never
// pass vacuously.
func parseSealTuple(t *testing.T, src, name string) []string {
	t.Helper()
	start := strings.Index(src, name+" = (")
	if start < 0 {
		t.Fatalf("bake.py: tuple %s not found", name)
	}
	rest := src[start:]
	end := strings.Index(rest, "\n)")
	if end < 0 {
		t.Fatalf("bake.py: tuple %s has no closing paren", name)
	}
	var members []string
	for _, m := range sealTupleStringRe.FindAllStringSubmatch(rest[:end], -1) {
		members = append(members, m[1])
	}
	if len(members) == 0 {
		t.Fatalf("bake.py: tuple %s parsed empty", name)
	}
	return members
}

func parseSealTuples(t *testing.T, src string) (ops, purge []string) {
	t.Helper()
	return parseSealTuple(t, src, "SYSPREP_ENABLE_OPS"),
		parseSealTuple(t, src, "SYSPREP_PURGE_PATHS")
}

// sealPlantedPath returns the redirected-tree path a member's prior-tenant
// artifact is planted at, and whether the assertion is rotation (content
// changed, file present) rather than absence. Members not listed here have
// no behavioral plant: they must carry a survivor reason instead.
func sealPlantedPath(root string) map[string]struct {
	path   string
	rotate bool
} {
	j := filepath.Join
	return map[string]struct {
		path   string
		rotate bool
	}{
		"machine-id":                        {j(root, "etc", "machine-id"), true},
		"ssh-hostkeys":                      {j(root, "etc", "ssh", "ssh_host_ed25519_key"), false},
		"ssh-userdir":                       {j(root, "root", ".ssh", "id_ed25519"), false},
		"logfiles":                          {j(root, "var", "log", "seal-parity.log"), false},
		"tmp-files":                         {j(root, "tmp", "seal-parity-tmp"), false},
		"bash-history":                      {j(root, "root", ".bash_history"), false},
		"package-manager-cache":             {j(root, "var", "lib", "apt", "lists", "seal-parity_Packages"), false},
		"backup-files":                      {j(root, "etc", "hostname.bak"), false},
		"passwd-backups":                    {j(root, "etc", "passwd-"), false},
		"utmp":                              {j(root, "run", "utmp"), false},
		"/etc/xpf/.configdb":                {j(root, "etc", "xpf", ".configdb", "active.json"), false},
		"/etc/xpf/xpf.conf":                 {j(root, "etc", "xpf", "xpf.conf"), false},
		"/etc/xpf/.day0-config-rejected":    {j(root, "etc", "xpf", ".day0-config-rejected"), false},
		"/etc/xpf/.root-grown":              {j(root, "etc", "xpf", ".root-grown"), false},
		"/var/lib/xpf/snmp-engine-id":       {j(root, "var", "lib", "xpf", "snmp-engine-id"), false},
		"/var/lib/xpf/snmp-engineboots":     {j(root, "var", "lib", "xpf", "snmp-engineboots"), false},
		"/var/lib/xpf/uefi-bootorder-front": {j(root, "var", "lib", "xpf", "uefi-bootorder-front"), false},
		"/var/lib/systemd/random-seed":      {j(root, "var", "lib", "systemd", "random-seed"), false},
		"/var/lib/apt/lists/*":              {j(root, "var", "lib", "apt", "lists", "seal-parity_Packages"), false},
	}
}

func TestSealParityMappingCoversBakeTuples17085(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(sealParityRepoRoot(t), "scripts", "image", "bake.py"))
	if err != nil {
		t.Fatalf("read bake.py: %v", err)
	}
	ops, purge := parseSealTuples(t, string(src))
	members := append(append([]string{}, ops...), purge...)

	// Every parsed member has exactly one disposition: a leg marker XOR a
	// non-empty survivor reason. Deleting a mapping row reds here.
	for _, m := range members {
		d, ok := wipeSealMapping[m]
		if !ok {
			t.Errorf("seal member %q has no wipeSealMapping row: zeroize does not account for it", m)
			continue
		}
		if d.leg == (d.survivor != "") {
			t.Errorf("seal member %q must have exactly one of leg / survivor reason, got leg=%v survivor=%q", m, d.leg, d.survivor)
		}
	}
	// No stale rows: a row for a member the seal no longer declares is
	// drift in the other direction.
	declared := make(map[string]bool, len(members))
	for _, m := range members {
		declared[m] = true
	}
	for key := range wipeSealMapping {
		if !declared[key] {
			t.Errorf("wipeSealMapping row %q is stale: bake.py declares no such seal member", key)
		}
	}

	// Fixture-copy calibration: appending an unmapped member to a copy of
	// a tuple must be detectable by the same check (proves the coverage
	// assertion can fail, not merely that it runs).
	fixture := string(src) + "\nSYSPREP_ENABLE_OPS = (\n    \"seal-parity-unmapped-fixture\",\n)\n"
	// parseSealTuple anchors on the first occurrence, so splice the
	// fixture member into the real tuple text instead of shadowing it.
	idx := strings.Index(fixture, "\"utmp\",")
	if idx < 0 {
		t.Fatal("fixture splice anchor \"utmp\" not found in bake copy")
	}
	fixture = fixture[:idx] + "\"seal-parity-unmapped-fixture\",\n    " + fixture[idx:]
	fops, _ := parseSealTuples(t, fixture)
	found := false
	for _, m := range fops {
		if m == "seal-parity-unmapped-fixture" {
			found = true
		}
	}
	if !found {
		t.Fatal("fixture member was not parsed from the doctored bake copy")
	}
	if _, ok := wipeSealMapping["seal-parity-unmapped-fixture"]; ok {
		t.Fatal("fixture member unexpectedly present in wipeSealMapping")
	}
}

func TestSealParityLegsErasePlantedPaths17085(t *testing.T) {
	root := t.TempDir()
	restore := RedirectWipePathsForTesting(root)
	defer restore()

	plants := sealPlantedPath(root)
	// The config-root members are erased by wipeConfigDir against the
	// configured root PerformZeroizeWipe is handed, which in this tree is
	// root/etc/xpf (RedirectWipePathsForTesting plants the appliance
	// marker there and the pending-path seam points into it).
	configDir := filepath.Join(root, "etc", "xpf")
	const priorMachineID = "0123456789abcdef0123456789abcdef\n"
	for member, plant := range plants {
		body := "prior-tenant seal residue"
		if member == "machine-id" {
			body = priorMachineID
		}
		if err := os.MkdirAll(filepath.Dir(plant.path), 0o700); err != nil {
			t.Fatalf("plant %s (%s): mkdir: %v", member, plant.path, err)
		}
		if err := os.WriteFile(plant.path, []byte(body), 0o600); err != nil {
			t.Fatalf("plant %s (%s): %v", member, plant.path, err)
		}
	}
	// Plant the normal day-0 stamp at the survivor path BEFORE the wipe:
	// beginZeroize must overwrite it with the prefixed pending record, the
	// config leg must preserve it while pending, and completeZeroize must
	// remove it after every leg succeeds — so after a completed wipe the
	// loader-visible path must be absent. RedirectWipePathsForTesting
	// points configstore.FactoryResetPendingPath at this exact path
	// (root/etc/xpf/.day0-config-applied, which is also configDir's marker
	// here because the redirected config root equals the loader root).
	day0StampPath := filepath.Join(configDir, configstore.Day0ConfigAppliedBase)
	if err := os.MkdirAll(filepath.Dir(day0StampPath), 0o700); err != nil {
		t.Fatalf("plant day0 stamp dir: %v", err)
	}
	if err := os.WriteFile(day0StampPath, []byte("/dev/vdb prior-tenant day-0 stamp\n"), 0o600); err != nil {
		t.Fatalf("plant day0 stamp: %v", err)
	}

	// Every leg member must have a plant (a leg with no behavioral proof
	// is a survivor that has not admitted it); every survivor must not.
	for member, d := range wipeSealMapping {
		_, planted := plants[member]
		if d.leg && !planted {
			t.Errorf("seal member %q maps to a leg but has no planted-path proof", member)
		}
		if !d.leg && planted {
			t.Errorf("seal member %q is a survivor but has a planted path", member)
		}
	}

	if err := PerformZeroizeWipe(configDir, "xpf.conf", ""); err != nil {
		t.Fatalf("PerformZeroizeWipe: %v", err)
	}

	for member, plant := range plants {
		if plant.rotate {
			body, err := os.ReadFile(plant.path)
			if err != nil {
				t.Errorf("seal member %q: rotated path %s missing after wipe: %v", member, plant.path, err)
				continue
			}
			if string(body) == priorMachineID {
				t.Errorf("seal member %q: prior identity survived at %s", member, plant.path)
			}
			continue
		}
		if _, err := os.Lstat(plant.path); !os.IsNotExist(err) {
			t.Errorf("seal member %q: planted path %s survived zeroize (err=%v)", member, plant.path, err)
		}
	}

	// Survivor behavior (F2): the planted normal stamp above was
	// overwritten by beginZeroize with the prefixed pending record,
	// held through every wipe leg by the config leg, and removed by
	// completeZeroize after final verification — so after this completed
	// PerformZeroizeWipe the pending/loader path must be absent (Lstat),
	// and the mapping must keep admitting it is not a plain leg.
	if _, err := os.Lstat(day0StampPath); !os.IsNotExist(err) {
		t.Errorf("day0 survivor path %s must be absent after completed zeroize (err=%v)", day0StampPath, err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Errorf("pending path %s must be absent after completed zeroize (err=%v)", configstore.FactoryResetPendingPath, err)
	}
	if d := wipeSealMapping["/etc/xpf/.day0-config-applied"]; d.leg || d.survivor == "" {
		t.Errorf(".day0-config-applied must remain a survivor-with-reason, got leg=%v survivor=%q", d.leg, d.survivor)
	}
}
