package config

import "testing"

// #14422 (DR15-H7) — a credential carried as a PACKED leaf in nested group H
// loses its fromGroups provenance when the #9855 same-instance/promote merge
// synthesizes its body, so a destination `apply-groups-except H` cannot drop
// it. The braced spelling of the identical credential is correctly dropped.
// All cells go through strict CompileConfig and assert the compiled
// credential field; the no-except controls prove the merge still works.

func bgpNestedExceptText14422(hPacked, gBare bool, except string) string {
	hCred := `neighbor 192.0.2.1 { authentication-key H-SECRET; }`
	if hPacked {
		hCred = `neighbor 192.0.2.1 authentication-key H-SECRET;`
	}
	gPeer := `neighbor 192.0.2.1 { peer-as 65002; }`
	if gBare {
		gPeer = `neighbor 192.0.2.1;`
	}
	exceptStmt := ""
	if except != "" {
		exceptStmt = "apply-groups-except " + except + "; "
	}
	return `groups {
  H { protocols { bgp { group EXT { ` + hCred + ` } } } }
  G { protocols { bgp { group EXT { ` + gPeer + ` apply-groups H; } } } }
}
apply-groups G;
protocols { bgp { local-as 65001; group EXT { ` + exceptStmt + `neighbor 192.0.2.1 { peer-as 65002; } } } }`
}

func bgpAuth14422(t *testing.T, text string) string {
	t.Helper()
	cfg := compile9422(t, parseTree9422(t, text))
	if cfg.Protocols.BGP == nil {
		t.Fatal("BGP config is nil")
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("neighbors: got %d, want 1 (%+v)", len(cfg.Protocols.BGP.Neighbors), cfg.Protocols.BGP.Neighbors)
	}
	return string(cfg.Protocols.BGP.Neighbors[0].AuthPassword)
}

func TestDR15H7NestedPackedCredentialExcept14422(t *testing.T) {
	cases := []struct {
		name    string
		hPacked bool
		gBare   bool
		except  string
		want    string
	}{
		{name: "S packed no except", hPacked: true, except: "", want: "H-SECRET"},
		{name: "S braced no except", hPacked: false, except: "", want: "H-SECRET"},
		{name: "S packed except H", hPacked: true, except: "H", want: ""},
		{name: "S braced except H", hPacked: false, except: "H", want: ""},
		{name: "S packed except G", hPacked: true, except: "G", want: ""},
		{name: "P packed no except", hPacked: true, gBare: true, except: "", want: "H-SECRET"},
		{name: "P packed except H", hPacked: true, gBare: true, except: "H", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bgpAuth14422(t, bgpNestedExceptText14422(c.hPacked, c.gBare, c.except)); got != c.want {
				t.Errorf("AuthPassword = %q, want %q", got, c.want)
			}
		})
	}
}

func ospfNestedExceptText14422(except string) string {
	exceptStmt := ""
	if except != "" {
		exceptStmt = "apply-groups-except " + except + "; "
	}
	return `groups {
  H { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 authentication md5 7 key OSPFSECRET; } } } }
  G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { hello-interval 10; } apply-groups H; } } } }
}
apply-groups G;
protocols { ospf { area 0.0.0.0 { ` + exceptStmt + `interface ge-0/0/0.0 { hello-interval 10; } } } }`
}

func TestDR15H7NestedPackedOSPFExcept14422(t *testing.T) {
	for _, c := range []struct {
		name, except, want string
	}{
		{name: "OSPF packed no except", except: "", want: "OSPFSECRET"},
		{name: "OSPF packed except H", except: "H", want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := compile9422(t, parseTree9422(t, ospfNestedExceptText14422(c.except)))
			if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 || len(cfg.Protocols.OSPF.Areas[0].Interfaces) != 1 {
				t.Fatalf("OSPF shape: %+v", cfg.Protocols.OSPF)
			}
			iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
			if got := string(iface.AuthKey); got != c.want {
				t.Errorf("AuthKey = %q, want %q (AuthType %q)", got, c.want, iface.AuthType)
			}
		})
	}
}
