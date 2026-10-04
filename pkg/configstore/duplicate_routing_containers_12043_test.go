package configstore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLoadOverrideCommitPreservesRepeatedUnnamedRoutingContainers12043 is
// the end-to-end fail-on-revert cell: hierarchical load override retains
// repeated siblings, and strict Commit must compile them like Junos' merged
// form rather than quietly dropping route or protocol state.
func TestLoadOverrideCommitPreservesRepeatedUnnamedRoutingContainers12043(t *testing.T) {
	cases := []struct {
		name   string
		dup    string
		merged string
		read   func(*config.Config) any
		valid  func(any) bool
	}{
		{
			name: "routing-options static",
			dup: `routing-options {
				static { route 10.10.0.0/16 { next-hop 192.0.2.1; } }
				static { route 192.0.2.0/24 { next-hop 192.0.2.2; } }
			}`,
			merged: `routing-options {
				static {
					route 10.10.0.0/16 { next-hop 192.0.2.1; }
					route 192.0.2.0/24 { next-hop 192.0.2.2; }
				}
			}`,
			read: func(c *config.Config) any { return c.RoutingOptions.StaticRoutes },
			valid: func(v any) bool {
				routes, ok := v.([]*config.StaticRoute)
				return ok && len(routes) == 2
			},
		},
		{
			name: "routing-instances routing-options",
			dup: `routing-instances { blue {
				instance-type virtual-router;
				routing-options { static { route 10.20.0.0/16 { next-hop 192.0.2.1; } } }
				routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.2; } } }
			} }`,
			merged: `routing-instances { blue {
				instance-type virtual-router;
				routing-options { static {
					route 10.20.0.0/16 { next-hop 192.0.2.1; }
					route 192.0.2.0/24 { next-hop 192.0.2.2; }
				} }
			} }`,
			read: func(c *config.Config) any {
				if ri := routingInstance12043(c, "blue"); ri != nil {
					return ri.StaticRoutes
				}
				return nil
			},
			valid: func(v any) bool {
				routes, ok := v.([]*config.StaticRoute)
				return ok && len(routes) == 2
			},
		},
		{
			name: "routing-instances protocols",
			dup: `routing-instances { blue {
				instance-type virtual-router;
				protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }
				protocols { bgp { local-as 65001; group external { peer-as 65002; neighbor 192.0.2.1; } } }
			} }`,
			merged: `routing-instances { blue {
				instance-type virtual-router;
				protocols {
					ospf { area 0.0.0.0 { interface ge-0/0/0.0; } }
					bgp { local-as 65001; group external { peer-as 65002; neighbor 192.0.2.1; } }
				}
			} }`,
			read: func(c *config.Config) any {
				if ri := routingInstance12043(c, "blue"); ri != nil {
					return struct {
						OSPF *config.OSPFConfig
						BGP  *config.BGPConfig
					}{ri.OSPF, ri.BGP}
				}
				return nil
			},
			valid: func(v any) bool {
				protocols, ok := v.(struct {
					OSPF *config.OSPFConfig
					BGP  *config.BGPConfig
				})
				return ok && protocols.OSPF != nil && protocols.BGP != nil
			},
		},
	}

	commit := func(t *testing.T, text string) *config.Config {
		t.Helper()
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		defer s.ExitConfigure()
		if err := s.LoadOverride(text); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		compiled, err := s.Commit()
		if err != nil {
			t.Fatalf("strict Commit: %v", err)
		}
		return compiled
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mergedConfig := commit(t, tc.merged)
			want := tc.read(mergedConfig)
			if !tc.valid(want) {
				t.Fatalf("merged control did not produce the expected state: %#v", want)
			}
			duplicateConfig := commit(t, tc.dup)
			got := tc.read(duplicateConfig)
			if !tc.valid(got) {
				t.Fatalf("duplicate form lost expected state on strict commit: %#v", got)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("LoadOverride+Commit duplicate state differs from merged control:\n duplicate: %#v\n merged:    %#v", got, want)
			}
			if !hasRoutingContainerMergeWarning12043(duplicateConfig.Warnings) {
				t.Errorf("duplicate container merged without its #12043 diagnostic: %v", duplicateConfig.Warnings)
			}
		})
	}
}

func hasRoutingContainerMergeWarning12043(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#12043") {
			return true
		}
	}
	return false
}

func routingInstance12043(c *config.Config, name string) *config.RoutingInstanceConfig {
	for _, instance := range c.RoutingInstances {
		if instance.Name == name {
			return instance
		}
	}
	return nil
}
