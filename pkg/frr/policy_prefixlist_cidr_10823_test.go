package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10823: routing-only policy-options prefix-lists bypass the firewall-scoped
// CIDR gate. Even strict compilation can therefore carry malformed values into
// rendering, and tolerant compilation must keep persisted configurations
// bootable. Neither path may emit an FRR-invalid definition or inline ACL line.
func TestPolicyPrefixListRenderOmitsMalformedCIDRs10823(t *testing.T) {
	for _, tc := range []struct {
		name    string
		invalid string
	}{
		{name: "out-of-range prefix length", invalid: "10.0.0.0/33"},
		{name: "bad octet", invalid: "999.0.0.0/8"},
		{name: "non-IP", invalid: "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []struct {
				name    string
				compile func(*config.ConfigTree) (*config.Config, error)
			}{
				{name: "strict", compile: config.CompileConfig},
				{name: "tolerant", compile: config.CompileConfigLenient},
			} {
				t.Run(mode.name, func(t *testing.T) {
					src := fmt.Sprintf(`policy-options {
  prefix-list PL {
    192.0.2.0/24;
    %s;
    203.0.113.0/24;
  }
  policy-statement P {
    term t1 {
      from {
        prefix-list PL;
        route-filter 192.0.2.0/24 exact;
      }
      then accept;
    }
  }
  policy-statement SIBLING {
    term allow {
      from {
        route-filter 198.51.100.0/24 exact;
      }
      then accept;
    }
  }
}`, tc.invalid)
					tree, parseErrs := config.NewParser(src).Parse()
					if len(parseErrs) != 0 {
						t.Fatalf("parse: %v", parseErrs)
					}
					cfg, err := mode.compile(tree)
					if err != nil {
						t.Fatalf("%s compile: %v", mode.name, err)
					}
					got := New().generatePolicyOptions(&cfg.PolicyOptions)
					if strings.Contains(got, tc.invalid) {
						t.Fatalf("malformed prefix-list entry %q reached FRR output:\n%s", tc.invalid, got)
					}
					for _, want := range []string{
						"ip prefix-list PL seq 5 permit 192.0.2.0/24\n",
						"ip prefix-list PL seq 15 permit 203.0.113.0/24\n",
						"access-list ",
						" permit 192.0.2.0/24 exact-match\n",
						" permit 203.0.113.0/24 exact-match\n",
						"route-map SIBLING permit 10\n",
					} {
						if !strings.Contains(got, want) {
							t.Errorf("valid sibling / required inline ACL output %q missing:\n%s", want, got)
						}
					}
				})
			}
		})
	}
}
