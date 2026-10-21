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

// #15990: `$9$i` decodes to ZERO bytes. Strict commit refuses it before
// render; the tolerant pipeline retains the warned blob in the compiled
// config, so the FRR belt must resolve it through the decoder and
// withhold the enclosing capability. For BGP, the affected neighbor is
// not declared; for RIP, no interface is enrolled. The literal blob
// must never reach frr.conf as an authentication key.
//
// FAIL-ON-REVERT: removing the decoder resolution from authTokenOrOmit
// renders `password $9$i` / `ip rip authentication string $9$i` and
// enrolls both adjacencies, so the neighbor/network assertions fire.
// Restoring decode-to-empty as ("", nil) makes strict compile accept
// the key and store Secret(""), firing the strict assertions.
func TestJunos9DecodeToEmptyBGPNotRenderedPasswordless15990(t *testing.T) {
	buildTree := func(t *testing.T, cmds []string) *config.ConfigTree {
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

	bgpCmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		`set protocols bgp group g1 neighbor 10.0.0.1 authentication-key "$9$i"`,
		"set protocols bgp group g1 neighbor 10.0.0.2 peer-as 65002",
		"set protocols bgp group g1 neighbor 10.0.0.2 authentication-key realpass1",
	}
	if _, err := config.CompileConfig(buildTree(t, bgpCmds)); err == nil {
		t.Fatal("CompileConfig accepted a BGP key that decodes to empty — want strict refusal (#15990)")
	} else if strings.Contains(err.Error(), "$9$i") {
		t.Fatalf("refusal LEAKED the secret value: %v", err)
	}

	// Executed tolerant pipeline: CompileConfigLenient retains the
	// warned `$9$i` blob, then the production renderer must exclude
	// only that neighbor while retaining the healthy neighbor/password.
	cfg, err := config.CompileConfigLenient(buildTree(t, bgpCmds))
	if err != nil {
		t.Fatalf("CompileConfigLenient must boot a persisted decode-to-empty BGP config: %v", err)
	}
	warned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15051") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected a #15051 lenient warning, got: %v", cfg.Warnings)
	}
	m := New()
	got := m.generateProtocols(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS, "", 0, nil, nil)
	if strings.Contains(got, "neighbor 10.0.0.1") {
		t.Errorf("tolerant BGP neighbor with a decode-to-empty key must be excluded (#15990):\n%s", got)
	}
	if !strings.Contains(got, "neighbor 10.0.0.2 password realpass1\n") {
		t.Errorf("healthy BGP control must render with its password (#15990):\n%s", got)
	}
	if strings.Contains(got, "$9$") {
		t.Errorf("rendered BGP config carries a literal $9$ blob (#15990):\n%s", got)
	}

	// Executed tolerant RIP pipeline: the formerly fail-closed parent
	// shape must not reactivate with `string $9$i`; no RIP stanza or
	// network enrollment may render.
	ripCmds := []string{
		"set protocols rip authentication-type md5",
		`set protocols rip authentication-key "$9$i"`,
		"set protocols rip neighbor ge-0/0/3",
	}
	if _, err := config.CompileConfig(buildTree(t, ripCmds)); err == nil {
		t.Fatal("CompileConfig accepted a RIP key that decodes to empty — want strict refusal (#15990)")
	}
	ripCfg, err := config.CompileConfigLenient(buildTree(t, ripCmds))
	if err != nil {
		t.Fatalf("CompileConfigLenient must boot a persisted decode-to-empty RIP config: %v", err)
	}
	if got := ripCfg.Protocols.RIP.AuthKey.Reveal(); got != "$9$i" {
		t.Fatalf("tolerant RIP AuthKey = %q, want warned blob retained for render belt", got)
	}
	got = m.generateProtocols(ripCfg.Protocols.OSPF, ripCfg.Protocols.OSPFv3, ripCfg.Protocols.BGP, ripCfg.Protocols.RIP, ripCfg.Protocols.ISIS, "", 0, nil, nil)
	if strings.Contains(got, "router rip") || strings.Contains(got, "network ge-0/0/3") ||
		strings.Contains(got, "ip rip authentication") || strings.Contains(got, "$9$") {
		t.Errorf("tolerant RIP with a decode-to-empty key must not enroll any interface (#15990):\n%s", got)
	}

	// Controls through the same tolerant pipeline: plaintext and valid
	// `$9$` RIP keys still enroll, with the valid blob decoded.
	for _, tc := range []struct {
		name string
		key  string
		want string
	}{
		{"plaintext", "plainkey1", " ip rip authentication string plainkey1\n"},
		{"valid $9$", `"$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW"`, " ip rip authentication string QZ1agnL21L\n"},
	} {
		t.Run("rip control "+tc.name, func(t *testing.T) {
			cmds := []string{
				"set protocols rip authentication-type md5",
				"set protocols rip authentication-key " + tc.key,
				"set protocols rip neighbor ge-0/0/3",
			}
			ctl, err := config.CompileConfigLenient(buildTree(t, cmds))
			if err != nil {
				t.Fatalf("CompileConfigLenient control: %v", err)
			}
			out := m.generateProtocols(ctl.Protocols.OSPF, ctl.Protocols.OSPFv3, ctl.Protocols.BGP, ctl.Protocols.RIP, ctl.Protocols.ISIS, "", 0, nil, nil)
			if !strings.Contains(out, " network ge-0/0/3\n") || !strings.Contains(out, tc.want) || strings.Contains(out, "$9$") {
				t.Errorf("RIP control did not render decoded enrollment (#15990):\n%s", out)
			}
		})
	}
}

// #15990 tolerant render parity for the remaining compile-walked
// routing credentials: a warned OSPF or IS-IS `$9$` blob must follow
// that protocol's existing fail-closed shape, never render literally.
// This is a direct-render belt cell because these compiled configs are
// exactly what CompileConfigLenient hands the renderer after retaining
// the original blob (asserted for BGP and RIP above).
func TestJunos9MalformedOSPFISISWithheld15990(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/0.0", AuthType: "md5", AuthKey: config.Secret("$9$i"), AuthKeyID: 1, AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 1, Key: config.Secret("$9$i")}}},
		{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: config.Secret("$9$garbage")},
		{Name: "ge-0/0/2.0", AuthType: "simple", AuthKey: config.Secret("s3cret")},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "ge-0/0/0.0") || strings.Contains(got, "ge-0/0/1.0") || strings.Contains(got, "$9$") {
		t.Errorf("malformed OSPF credentials activated interfaces or rendered literally (#15990):\n%s", got)
	}
	if !strings.Contains(got, "interface ge-0/0/2.0\n") || !strings.Contains(got, " ip ospf authentication-key s3cret\n") {
		t.Errorf("healthy OSPF control was withheld (#15990):\n%s", got)
	}

	// Bad global IS-IS auth withholds the whole stanza (existing #14977).
	isis := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: config.Secret("$9$i"),
		Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: config.Secret("s3cret")}}}
	got = m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if strings.Contains(got, "router isis") || strings.Contains(got, "trust0") || strings.Contains(got, "$9$") {
		t.Errorf("decode-to-empty global IS-IS credential activated the stanza (#15990):\n%s", got)
	}

	// Bad interface IS-IS auth withholds only that interface when the
	// global credential is healthy.
	isis.AuthType, isis.AuthKey = "md5", config.Secret("s3cret")
	isis.Interfaces = []*config.ISISInterface{
		{Name: "trust0", AuthType: "md5", AuthKey: config.Secret("$9$garbage")},
		{Name: "trust1", AuthType: "md5", AuthKey: config.Secret("s3cret")},
	}
	got = m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if strings.Contains(got, "interface trust0\n") || strings.Contains(got, "$9$") {
		t.Errorf("malformed IS-IS interface credential was activated or rendered literally (#15990):\n%s", got)
	}
	if !strings.Contains(got, " area-password md5 s3cret\n") || !strings.Contains(got, "interface trust1\n") ||
		!strings.Contains(got, " isis password md5 s3cret\n") {
		t.Errorf("healthy IS-IS global/interface controls were withheld (#15990):\n%s", got)
	}
}
