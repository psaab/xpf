package config

import (
	"os"
	"strings"
	"testing"
)

type nestedPrefixNATCase18366 struct {
	name, leaf, nested, plain string
}

func nestedPrefixNATCases18366() []nestedPrefixNATCase18366 {
	firewallPrefixLists := `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl6 { 2001:db8::/32; }
}`
	return []nestedPrefixNATCase18366{
		{
			name:   "inet source-prefix-list",
			leaf:   "source-prefix-list",
			nested: firewallPrefixLists + ` firewall { family inet { filter f { term t { from { source-prefix-list { pl1 { unexpected { 10.0.0.0/8; } } } } then accept; } } } }`,
			plain:  firewallPrefixLists + ` firewall { family inet { filter f { term t { from { source-prefix-list { pl1; } } then accept; } } } }`,
		},
		{
			name:   "inet destination-prefix-list",
			leaf:   "destination-prefix-list",
			nested: firewallPrefixLists + ` firewall { family inet { filter f { term t { from { destination-prefix-list { pl1 { unexpected { 10.0.0.0/8; } } } } then accept; } } } }`,
			plain:  firewallPrefixLists + ` firewall { family inet { filter f { term t { from { destination-prefix-list { pl1; } } then accept; } } } }`,
		},
		{
			name:   "inet6 source-prefix-list",
			leaf:   "source-prefix-list",
			nested: firewallPrefixLists + ` firewall { family inet6 { filter f { term t { from { source-prefix-list { pl6 { unexpected { 2001:db8::/32; } } } } then accept; } } } }`,
			plain:  firewallPrefixLists + ` firewall { family inet6 { filter f { term t { from { source-prefix-list { pl6; } } then accept; } } } }`,
		},
		{
			name:   "inet6 destination-prefix-list",
			leaf:   "destination-prefix-list",
			nested: firewallPrefixLists + ` firewall { family inet6 { filter f { term t { from { destination-prefix-list { pl6 { unexpected { 2001:db8::/32; } } } } then accept; } } } }`,
			plain:  firewallPrefixLists + ` firewall { family inet6 { filter f { term t { from { destination-prefix-list { pl6; } } then accept; } } } }`,
		},
		{
			name: "source NAT source-address",
			leaf: "source-address",
			nested: `security {
    zones { security-zone trust; security-zone untrust; }
    nat {
        source {
            rule-set rs {
                from zone trust;
                to zone untrust;
                rule r {
                    match {
                        source-address {
                            10.0.0.0/8 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}`,
			plain: `security {
    zones { security-zone trust; security-zone untrust; }
    nat {
        source {
            rule-set rs {
                from zone trust;
                to zone untrust;
                rule r {
                    match { source-address 10.0.0.0/8; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "source NAT destination-address",
			leaf: "destination-address",
			nested: `security {
    zones { security-zone trust; security-zone untrust; }
    nat {
        source {
            rule-set rs {
                from zone trust;
                to zone untrust;
                rule r {
                    match {
                        destination-address {
                            10.0.0.0/8 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}`,
			plain: `security {
    zones { security-zone trust; security-zone untrust; }
    nat {
        source {
            rule-set rs {
                from zone trust;
                to zone untrust;
                rule r {
                    match { destination-address 10.0.0.0/8; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "destination NAT source-address",
			leaf: "source-address",
			nested: `security {
    zones { security-zone untrust; }
    nat {
        destination {
            pool p { address 192.0.2.2/32; }
            rule-set rs {
                from zone untrust;
                rule r {
                    match {
                        source-address {
                            10.0.0.0/8 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { destination-nat { pool p; } }
                }
            }
        }
    }
}`,
			plain: `security {
    zones { security-zone untrust; }
    nat {
        destination {
            pool p { address 192.0.2.2/32; }
            rule-set rs {
                from zone untrust;
                rule r {
                    match { source-address 10.0.0.0/8; }
                    then { destination-nat { pool p; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "destination NAT destination-address",
			leaf: "destination-address",
			nested: `security {
    zones { security-zone untrust; }
    nat {
        destination {
            pool p { address 192.0.2.2/32; }
            rule-set rs {
                from zone untrust;
                rule r {
                    match {
                        destination-address {
                            10.0.0.0/8 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { destination-nat { pool p; } }
                }
            }
        }
    }
}`,
			plain: `security {
    zones { security-zone untrust; }
    nat {
        destination {
            pool p { address 192.0.2.2/32; }
            rule-set rs {
                from zone untrust;
                rule r {
                    match { destination-address 10.0.0.0/8; }
                    then { destination-nat { pool p; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "static NAT source-address",
			leaf: "source-address",
			nested: `security {
    zones { security-zone trust; }
    nat {
        static {
            rule-set rs {
                from zone trust;
                rule r {
                    match {
                        destination-address 203.0.113.1/32;
                        source-address {
                            10.0.0.0/8 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { static-nat { prefix 10.8.0.1/32; } }
                }
            }
        }
    }
}`,
			plain: `security {
    zones { security-zone trust; }
    nat {
        static {
            rule-set rs {
                from zone trust;
                rule r {
                    match {
                        destination-address 203.0.113.1/32;
                        source-address 10.0.0.0/8;
                    }
                    then { static-nat { prefix 10.8.0.1/32; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "static NAT destination-address",
			leaf: "destination-address",
			nested: `security {
    zones { security-zone trust; }
    nat {
        static {
            rule-set rs {
                from zone trust;
                rule r {
                    match {
                        destination-address {
                            203.0.113.1/32 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { static-nat { prefix 10.8.0.1/32; } }
                }
            }
        }
    }
}`,
			plain: `security {
    zones { security-zone trust; }
    nat {
        static {
            rule-set rs {
                from zone trust;
                rule r {
                    match { destination-address 203.0.113.1/32; }
                    then { static-nat { prefix 10.8.0.1/32; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "NAT64 source-address",
			leaf: "source-address",
			nested: `security {
    nat {
        source { pool p64 { address 100.64.0.7/32; } }
        nat64 {
            rule-set rs {
                prefix 64:ff9b::/96;
                source-pool p64;
                match {
                    source-address {
                        2001:db8::/32 {
                            unexpected { 2001:db8:1::/48; }
                        }
                    }
                }
            }
        }
    }
}`,
			plain: `security {
    nat {
        source { pool p64 { address 100.64.0.7/32; } }
        nat64 {
            rule-set rs {
                prefix 64:ff9b::/96;
                source-pool p64;
                match { source-address 2001:db8::/32; }
            }
        }
    }
}`,
		},
	}
}

func assertNestedListRefused18366(t *testing.T, err error, leaf string) {
	t.Helper()
	if err == nil || !IsNestedListContentSchemaError(err) {
		t.Fatalf("expected nested-list content schema refusal for %s, got %v", leaf, err)
	}
	if !strings.Contains(err.Error(), leaf) || !strings.Contains(err.Error(), "nested content") {
		t.Fatalf("nested-content error %q must name %s", err, leaf)
	}
}

func TestNestedPrefixNATContentRejected18366(t *testing.T) {
	for _, tc := range nestedPrefixNATCases18366() {
		t.Run(tc.name, func(t *testing.T) {
			nested := parseHierText(t, tc.nested)
			assertNestedListRefused18366(t, SchemaValidate(nested), tc.leaf)
			_, err := CompileConfig(nested)
			assertNestedListRefused18366(t, err, tc.leaf)
			_, err = CompileConfigLenient(nested)
			assertNestedListRefused18366(t, err, tc.leaf)

			plain := parseHierText(t, tc.plain)
			if err := SchemaValidate(plain); err != nil {
				t.Fatalf("SchemaValidate rejected plain value-list control: %v", err)
			}
			if _, err := CompileConfig(plain); err != nil {
				t.Fatalf("strict compile rejected plain value-list control: %v", err)
			}
			if _, err := CompileConfigLenient(plain); err != nil {
				t.Fatalf("lenient compile rejected plain value-list control: %v", err)
			}
		})
	}
}

func TestNestedPrefixNATRefusalCensus18366(t *testing.T) {
	cos, err := os.ReadFile("schema_cos.go")
	if err != nil {
		t.Fatal(err)
	}
	security, err := os.ReadFile("schema_security.go")
	if err != nil {
		t.Fatal(err)
	}
	markedCount := func(src []byte, leaf string, natMatch bool) int {
		count := 0
		for _, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, `"`+leaf+`":`) ||
				!strings.Contains(line, "refuseNonLeafBlockChildren: true") {
				continue
			}
			if natMatch && !strings.Contains(line, "prefix to match") {
				continue
			}
			count++
		}
		return count
	}
	for _, leaf := range []string{"source-prefix-list", "destination-prefix-list"} {
		if got := markedCount(cos, leaf, false); got != 2 {
			t.Errorf("schema_cos.go %s refusal leaves = %d, want 2 (inet and inet6)", leaf, got)
		}
	}
	for leaf, want := range map[string]int{"source-address": 4, "destination-address": 3} {
		if got := markedCount(security, leaf, true); got != want {
			t.Errorf("schema_security.go %s NAT match refusal leaves = %d, want %d", leaf, got, want)
		}
	}
	for _, line := range strings.Split(string(security), "\n") {
		if strings.Contains(line, `"address":`) && (strings.Contains(line, "Address, prefix or range to answer ARP") || strings.Contains(line, "Address, prefix or range to answer NDP")) && strings.Contains(line, "refuseNonLeafBlockChildren: true") {
			t.Errorf("proxy-ARP/NDP custom address grammar must remain unmarked: %s", line)
		}
	}
}

func TestProxyARPRangeGrammarRemainsAccepted18366(t *testing.T) {
	tree := parseHierText(t, `security { nat { proxy-arp { interface ge-0/0/0.0 { address 192.0.2.1 to 192.0.2.3; } } } }`)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected the proxy-ARP range grammar: %v", err)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile rejected the proxy-ARP range grammar: %v", err)
	}
}
