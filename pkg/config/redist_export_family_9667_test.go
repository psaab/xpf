package config

import (
	"strings"
	"testing"
)

// #9667: the strict commit gate checks a bare export token's address family
// against its use site, using the shared RedistributionSourceFamilies table.
func TestBareExportTokenFamilyIsCheckedAtCommit_9667(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		want string // "" = accepted; else a substring of the refusal
	}{
		{"ospf refuses an IPv6-only source", []string{"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", "set protocols ospf export ospf6"}, "IPv6 routes, which protocols ospf cannot carry"},
		{"ospf3 refuses an IPv4-only source", []string{"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0", "set protocols ospf3 export ospf"}, "IPv4 routes, which protocols ospf3 cannot carry"},
		{"ospf3 accepts ripng (used to be refused as unknown)", []string{"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0", "set protocols ospf3 export ripng"}, ""},
		{"bgp accepts ospf6 (rendered under ipv6 unicast)", []string{"set protocols bgp local-as 65001", "set protocols bgp export ospf6"}, ""},
		{"bgp accepts a dual-family source", []string{"set protocols bgp local-as 65001", "set protocols bgp export static"}, ""},
		{"a non-lowercase spelling is still unknown", []string{"set protocols bgp local-as 65001", "set protocols bgp export Static"}, "references neither a known redistribution protocol"},
	} {
		_, err := CompileConfig(buildTree(t, tc.cmds))
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: want refusal containing %q, got %v", tc.name, tc.want, err)
		}
	}
}

// TestBareExportTokenFamilyWarnsOnTolerantLoad_9667: the tolerant path keeps an
// already-persisted config booting and says why the line will not render.
func TestBareExportTokenFamilyWarnsOnTolerantLoad_9667(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", "set protocols ospf export ospf6"}))
	if err != nil {
		t.Fatalf("the tolerant path must not refuse: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#9667") && strings.Contains(w, "ospf6") {
			found = true
		}
	}
	if !found {
		t.Errorf("tolerant load must warn about the family mismatch: %v", cfg.Warnings)
	}
}
