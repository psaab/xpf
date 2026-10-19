package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15051 (A20-01): a Junos `$9$` BGP authentication-key migrated from
// Junos display output must render the DECODED plaintext into frr.conf
// (`neighbor <addr> password QZ1agnL21L`), not the obfuscated blob.
// Driven through the production parse + strict CompileConfig + render
// path so the cell observes the compile-time decode, not a render-time
// patch. On origin/master the blob renders verbatim and the strict
// compile accepts it, so the contains-check fires.
func TestJunos9BGPKeyRendersDecoded15051(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 authentication-key \"$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW\"",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	m := New()
	got := m.generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "neighbor 10.0.0.1 password QZ1agnL21L\n") {
		t.Errorf("rendered BGP config must carry the decoded key QZ1agnL21L (#15051), got:\n%s", got)
	}
	if strings.Contains(got, "$9$") {
		t.Errorf("rendered BGP config still carries the $9$ blob (#15051):\n%s", got)
	}
}

// TestJunos9MalformedBGPRefusedBeforeRender15051: `$9$garbage` is a
// strict commit error, so it can never reach the renderer as a live key.
func TestJunos9MalformedBGPRefusedBeforeRender15051(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 authentication-key \"$9$garbage\"",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted $9$garbage — want strict refusal before render (#15051)")
	}
}
