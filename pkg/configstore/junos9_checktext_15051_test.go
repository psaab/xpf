package configstore

import (
	"strings"
	"testing"
)

// #15051 through the real operator check pipeline: a `$9$garbage`
// routing authentication-key must be refused by CheckText (the strict
// commit-check Store.Commit uses), and the valid `$9$` probe must
// check clean and compile to the decoded plaintext.
func TestCheckTextJunos9RoutingKey15051(t *testing.T) {
	bad := "protocols { bgp { local-as 65001; group g1 { neighbor 10.0.0.1 { peer-as 65001; " +
		"authentication-key \"$9$garbage\"; } } } }"
	if _, err := CheckText(bad, -1); err == nil {
		t.Fatal("CheckText accepted $9$garbage as a BGP authentication-key (#15051)")
	} else if !strings.Contains(err.Error(), "authentication-key") {
		t.Fatalf("CheckText refusal must name the leaf, got: %v", err)
	}
	good := "protocols { bgp { local-as 65001; group g1 { neighbor 10.0.0.1 { peer-as 65001; " +
		"authentication-key \"$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW\"; } } } }"
	cfg, err := CheckText(good, -1)
	if err != nil {
		t.Fatalf("control: valid $9$ BGP key refused by CheckText: %v", err)
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 ||
		cfg.Protocols.BGP.Neighbors[0].AuthPassword.Reveal() != "QZ1agnL21L" {
		t.Fatalf("CheckText compiled AuthPassword = %q, want decoded QZ1agnL21L (#15051)",
			cfg.Protocols.BGP.Neighbors[0].AuthPassword.Reveal())
	}
}
