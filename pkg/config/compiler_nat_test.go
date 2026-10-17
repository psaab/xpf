package config

import (
	"fmt"
	"reflect"
	"testing"
)

// #14346: parseDNATPortList silently dropped ports in braced
// destination-port stanzas. The len(m.Children)>0 branch read only
// m.Keys[1], returned early on the first "to" child (never walking its
// siblings), and read only child.Name() (Keys[0]) per child. So:
//   - destination-port { [ 80 443 ]; }            kept only 80
//   - destination-port 8000 { to 8005; 443; }     kept only 8000..8005
//   - destination-port [ 80 443 ] { 8080; }       kept only 80 and 8080
//
// with 0 errors and 0 warnings on strict CompileConfig, in both source and
// destination NAT (both route destination-port through parseDNATPortList).
// The dropped tokens never reached InvalidDestinationPorts, so the strict
// invalid-port gate was blind to them.
//
// RED-on-revert: restore the children-branch early return / Keys[1]-only /
// Name()-only reads and every case below loses the asserted ports.
//
// Hierarchical syntax MUST be built via NewParser (flat-set SetPath cannot
// express the braced shapes).

func bracedDNATTree(t *testing.T, dport string) *ConfigTree {
	t.Helper()
	text := fmt.Sprintf(`
security {
    zones { security-zone untrust; }
    nat {
        destination {
            pool p1 { address 192.168.1.10; }
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; %s }
                    then { destination-nat pool p1; }
                }
            }
        }
    }
}`, dport)
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func TestParseDNATPortListBracedBracketAndSiblingChildren(t *testing.T) {
	cases := []struct {
		name  string
		dport string
		want  []int
	}{
		{
			name:  "bracket list inside braces",
			dport: `destination-port { [ 80 443 ]; }`,
			want:  []int{80, 443},
		},
		{
			name:  "to child plus sibling port",
			dport: `destination-port 8000 { to 8005; 443; }`,
			want:  []int{8000, 8001, 8002, 8003, 8004, 8005, 443},
		},
		{
			name:  "bracket head plus braced child",
			dport: `destination-port [ 80 443 ] { 8080; }`,
			want:  []int{80, 443, 8080},
		},
	}
	for _, tc := range cases {
		t.Run("dnat/"+tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(bracedDNATTree(t, tc.dport))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if len(cfg.Security.NAT.Destination.RuleSets) != 1 ||
				len(cfg.Security.NAT.Destination.RuleSets[0].Rules) != 1 {
				t.Fatalf("unexpected destination NAT shape: %+v", cfg.Security.NAT.Destination)
			}
			got := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationPorts
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DestinationPorts = %v, want %v (braced ports must not be dropped)", got, tc.want)
			}
		})
	}

	// The same braced form through the source-NAT caller (shared parser),
	// as a source-nat off exemption rule.
	t.Run("snat/bracket list inside braces", func(t *testing.T) {
		text := `
security {
    zones { security-zone lan; security-zone wan; }
    nat {
        source {
            rule-set RS {
                from zone lan;
                to zone wan;
                rule R1 {
                    match { destination-port { [ 80 443 ]; } }
                    then { source-nat off; }
                }
            }
        }
    }
}`
		tree, errs := NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if len(cfg.Security.NAT.Source) != 1 || len(cfg.Security.NAT.Source[0].Rules) != 1 {
			t.Fatalf("unexpected source NAT shape: %+v", cfg.Security.NAT.Source)
		}
		got := cfg.Security.NAT.Source[0].Rules[0].Match.DestinationPorts
		if want := []int{80, 443}; !reflect.DeepEqual(got, want) {
			t.Fatalf("DestinationPorts = %v, want %v (braced ports must not be dropped)", got, want)
		}
	})
}
