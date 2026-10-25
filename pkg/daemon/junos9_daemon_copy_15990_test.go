package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
)

// #15990 fold-3 witness: provenance is a FIELD on config.Secret, so the
// daemon's production copy path (assembleFRRConfig ->
// filterFRRProtocolInterfaces11310 -> frr ifname copies -> OSPF union)
// carries the compile adjudication by construction. At the fold-2 head
// the identity-keyed registry was dropped by these copies, so a valid
// key whose one-pass plaintext begins `$9$` was re-decoded/omitted, and
// the OSPF legacy-view sync hardcoded Junos9Decoded onto a retained
// undecodable blob, rendering `ip ospf authentication-key $9$i` live.
//
// FAIL-ON-REVERT: restoring the registry (or a hardcoded Decoded stamp
// in the legacy sync) drops/mislabels provenance on this path and the
// assertions below fire.
func TestJunos9DaemonCopyPreservesProvenance15990(t *testing.T) {
	build := func(t *testing.T, cmds []string) *config.ConfigTree {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}
	render := func(t *testing.T, cfg *config.Config) string {
		t.Helper()
		fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
		dir := t.TempDir()
		conf := filepath.Join(dir, "frr.conf")
		if err := os.WriteFile(conf, []byte("frr version 10.6\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		m := frr.NewForTest(conf, &frr.RecordingExecutor{})
		if err := m.ApplyFull(fc); err != nil {
			t.Fatalf("ApplyFull: %v", err)
		}
		b, err := os.ReadFile(conf)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	const outer = "$9$Qzzzz36BIErlK" // one-pass plaintext: "$9$"
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		`set protocols bgp group g1 neighbor 10.0.0.1 authentication-key "` + outer + `"`,
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key \"" + outer + "\"",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + outer + "\"",
		"set protocols rip authentication-type md5",
		`set protocols rip authentication-key "` + outer + `"`,
		"set protocols rip neighbor ge-0/0/3",
		"set protocols isis net 49.0001.0100.0000.0001.00",
		"set protocols isis authentication-type md5",
		`set protocols isis authentication-key "` + outer + `"`,
		"set protocols isis interface ge-0/0/2.0 authentication-type md5",
		`set protocols isis interface ge-0/0/2.0 authentication-key "` + outer + `"`,
	}
	for _, tc := range []struct {
		name    string
		compile func(*config.ConfigTree) (*config.Config, error)
	}{
		{"strict", config.CompileConfig},
		{"tolerant", config.CompileConfigLenient},
	} {
		t.Run(tc.name+" daemon copy renders $9$ plaintext once", func(t *testing.T) {
			cfg, err := tc.compile(build(t, cmds))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got := render(t, cfg)
			for _, want := range []string{
				" neighbor 10.0.0.1 password $9$\n",
				" ip ospf message-digest-key 1 md5 $9$\n",
				" ip ospf authentication-key $9$\n",
				" ip rip authentication string $9$\n",
				" area-password md5 $9$\n",
				" isis password md5 $9$\n",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q through assembleFRRConfig copies (#15990):\n%s", want, got)
				}
			}
		})
	}

	// GLM B1 combo: md5 $9$i + simple-password $9$i on ONE interface,
	// tolerant load. The legacy view must inherit Undecodable from the
	// md5 key's Secret field — the interface is withheld, and no
	// `authentication-key $9$i` line may appear.
	bad := []string{
		`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "$9$i"`,
		`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication simple-password "$9$i"`,
		"set protocols rip authentication-type md5",
		`set protocols rip authentication-key "$9$i"`,
		"set protocols rip neighbor ge-0/0/3",
		"set protocols isis authentication-type md5",
		`set protocols isis authentication-key "$9$i"`,
	}
	cfg, err := config.CompileConfigLenient(build(t, bad))
	if err != nil {
		t.Fatalf("lenient bad compile: %v", err)
	}
	iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
	if iface.AuthKey.Provenance() != config.Junos9Undecodable {
		t.Fatalf("legacy OSPF AuthKey provenance = %v, want Junos9Undecodable (must propagate from the md5 key field, never a literal)", iface.AuthKey.Provenance())
	}
	got := render(t, cfg)
	if strings.Contains(got, "$9$i") || strings.Contains(got, "ge-0/0/0.0") ||
		strings.Contains(got, "router rip") || strings.Contains(got, "router isis") {
		t.Errorf("tolerant undecodable credentials rendered through daemon copies (#15990 B1):\n%s", got)
	}
}
