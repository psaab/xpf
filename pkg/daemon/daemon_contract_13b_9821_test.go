package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// goldenRow9821 is the minimal projection of the cell-13 contract golden
// this belt-level check reads: row name, linux device, and stubbed ifindex.
type goldenRow9821 struct {
	Name      string `json:"name"`
	LinuxName string `json:"linux_name"`
	Ifindex   int    `json:"ifindex"`
}

func readContractGoldenRows9821(t *testing.T) []goldenRow9821 {
	t.Helper()
	// Test cwd is pkg/daemon.
	path := filepath.Join("..", "dataplane", "userspace", "testdata", "contract-9821-declared-snapshot.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the contract golden must exist — run the producer cell first)", path, err)
	}
	var doc struct {
		Interfaces []goldenRow9821 `json:"interfaces"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Interfaces) == 0 {
		t.Fatal("contract golden carries no interface rows — it asserts nothing")
	}
	return doc.Interfaces
}

// TestContractBindSubsetOfGoldenRows9821 is the 13b fake-link VRF bind: every
// device step-0a binds for the probe config resolves to a golden row WITH a
// (stubbed) link — the kernel bind targets a real row, never thin air — and
// the dotted member binds exactly its declared device. Belt-level: no daemon
// process, no cluster; the golden's stubbed ifindexes stand in for links.
func TestContractBindSubsetOfGoldenRows9821(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces ge-0/0/5.0 unit 0 family inet address 10.55.0.1/24",
		"set interfaces ge-0/0/6 unit 0 family inet address 10.56.0.1/24",
		"set routing-instances RA interface ge-0/0/5.0",
		"set routing-instances RA interface ge-0/0/6.0",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		tree.SetPath(path)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("probe config must compile strict: %v", err)
	}
	rows := readContractGoldenRows9821(t)
	byLinux := map[string]goldenRow9821{}
	for _, r := range rows {
		if _, dup := byLinux[r.LinuxName]; !dup {
			byLinux[r.LinuxName] = r
		}
	}
	tunMap := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		for _, member := range ri.Interfaces {
			bound := riMemberLinuxNames(cfg, tunMap, member)
			if len(bound) == 0 {
				t.Errorf("member %q binds nothing — a whole member must bind its devices", member)
			}
			for _, dev := range bound {
				row, ok := byLinux[dev]
				if !ok {
					t.Errorf("member %q binds %q, which names no golden row — the bind targets thin air", member, dev)
					continue
				}
				if row.Ifindex <= 0 {
					t.Errorf("member %q binds %q, whose golden row has no link (ifindex %d)", member, dev, row.Ifindex)
				}
			}
			if member == "ge-0/0/5.0" && !reflect.DeepEqual(bound, []string{"ge-0-0-5.0"}) {
				t.Errorf("dotted member binds %q — want exactly [ge-0-0-5.0]", bound)
			}
		}
	}
}
