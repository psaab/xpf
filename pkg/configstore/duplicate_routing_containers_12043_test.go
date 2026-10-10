package configstore

import (
	"path/filepath"
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
		issue  string
		dup    string
		merged string
		read   func(*config.Config) any
		valid  func(any) bool
	}{
		{
			name:  "routing-options static",
			issue: "#12120",
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
			name:  "routing-instances routing-options",
			issue: "#12043",
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
			name:  "routing-instances protocols",
			issue: "#12043",
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
			if !hasRoutingContainerMergeWarning(duplicateConfig.Warnings, tc.issue) {
				t.Errorf("duplicate container merged without its %s diagnostic: %v", tc.issue, duplicateConfig.Warnings)
			}
		})
	}
}

func hasRoutingContainerMergeWarning(warnings []string, issue string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, issue) {
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

func TestLoadOverrideCommitAndReloadPreservesRoutingMergeFixes12120(t *testing.T) {
	commitAndReload := func(t *testing.T, text string) (*config.Config, *config.Config) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config")
		store := newTestStoreAt(t, path)
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(text); err != nil {
			store.ExitConfigure()
			t.Fatalf("LoadOverride: %v", err)
		}
		committed, err := store.Commit()
		store.ExitConfigure()
		if err != nil {
			t.Fatalf("strict Commit: %v", err)
		}
		reloaded := newTestStoreAt(t, path)
		if err := reloaded.Load(); err != nil {
			t.Fatalf("tolerant Store.Load: %v", err)
		}
		return committed, reloaded.ActiveConfig()
	}

	const interfaces = `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } } `
	for _, perInterface := range []bool{false, true} {
		scope := "zone"
		var site string
		var hostProtocols func(*config.Config) []string
		if perInterface {
			scope = "interface"
			site = `interfaces { ge-0/0/0.0 { host-inbound-traffic { protocols { `
			hostProtocols = func(c *config.Config) []string {
				zone := c.Security.Zones["trust"]
				if zone == nil {
					return nil
				}
				for _, host := range zone.InterfaceHostInbound {
					if host != nil {
						return host.Protocols
					}
				}
				return nil
			}
		} else {
			site = `interfaces { ge-0/0/0.0; } host-inbound-traffic { protocols { `
			hostProtocols = func(c *config.Config) []string {
				zone := c.Security.Zones["trust"]
				if zone == nil || zone.HostInboundTraffic == nil {
					return nil
				}
				return zone.HostInboundTraffic.Protocols
			}
		}
		closeScope := ` } } } } }`
		if perInterface {
			closeScope = ` } } } } } } }`
		}
		dup := interfaces + `security { zones { security-zone trust { ` + site +
			`all; ospf3 { except; } ospf3 { except; }` + closeScope
		merged := interfaces + `security { zones { security-zone trust { ` + site +
			`all; ospf3 { except; }` + closeScope
		t.Run(scope, func(t *testing.T) {
			gotCommit, gotReload := commitAndReload(t, dup)
			wantCommit, wantReload := commitAndReload(t, merged)
			for _, phase := range []struct {
				name      string
				got, want *config.Config
			}{
				{name: "strict Commit", got: gotCommit, want: wantCommit},
				{name: "tolerant reload", got: gotReload, want: wantReload},
			} {
				if !reflect.DeepEqual(hostProtocols(phase.got), hostProtocols(phase.want)) {
					t.Fatalf("%s %s host-inbound protocols = %v, want control state %v",
						scope, phase.name, hostProtocols(phase.got), hostProtocols(phase.want))
				}
				for _, proto := range hostProtocols(phase.got) {
					if proto == "ospf3" {
						t.Fatalf("%s %s host-inbound ospf3 exclusion lost: %v",
							scope, phase.name, hostProtocols(phase.got))
					}
				}
				if hasRoutingContainerMergeWarning(phase.got.Warnings, "#12120") {
					t.Fatalf("%s %s host-inbound emitted a routing merge warning: %v",
						scope, phase.name, phase.got.Warnings)
				}
			}
		})
	}

	const ribGroups = `routing-options { rib-groups { leak { import-rib [ inet.0 blue.inet.0 ]; } } } `
	for _, tc := range []struct {
		name, tail, controlTail string
	}{
		{
			name: "X1",
			tail: `routing-instances { blue { instance-type virtual-router; routing-options {
				interface-routes { rib-group { inet leak; } rib-group { inet6 leak; } }
			} } }`,
			controlTail: `routing-instances { blue { instance-type virtual-router; routing-options {
				interface-routes { rib-group { inet leak; inet6 leak; } }
			} } }`,
		},
		{
			name: "X3",
			tail: `routing-instances { blue { instance-type virtual-router; routing-options {
				interface-routes { rib-group { inet leak; } rib-group { inet6 leak; } }
			} routing-options { autonomous-system 65001; } } }`,
			controlTail: `routing-instances { blue { instance-type virtual-router; routing-options {
				interface-routes { rib-group { inet leak; inet6 leak; } }
				autonomous-system 65001;
			} } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotCommit, gotReload := commitAndReload(t, ribGroups+tc.tail)
			wantCommit, wantReload := commitAndReload(t, ribGroups+tc.controlTail)
			read := func(cfg *config.Config) struct{ V4, V6 string } {
				ri := routingInstance12043(cfg, "blue")
				if ri == nil {
					return struct{ V4, V6 string }{}
				}
				return struct{ V4, V6 string }{
					ri.InterfaceRoutesRibGroup, ri.InterfaceRoutesRibGroupV6,
				}
			}
			for _, cfg := range []*config.Config{gotCommit, gotReload} {
				if state := read(cfg); state != (struct{ V4, V6 string }{"leak", "leak"}) {
					t.Fatalf("%s interface-routes rib-group = %#v, want both families", tc.name, state)
				}
				if !hasRoutingContainerMergeWarning(cfg.Warnings, "#12120") {
					t.Fatalf("%s nested rib-group fold warning missing: %v", tc.name, cfg.Warnings)
				}
			}
			if read(gotCommit) != read(wantCommit) || read(gotReload) != read(wantReload) {
				t.Fatalf("%s Store reload differs from merged control: duplicate=%#v control=%#v",
					tc.name, read(gotReload), read(wantReload))
			}
		})
	}

	t.Run("global-strict-rejects-both-merged-selectors", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(`routing-options { interface-routes {
			rib-group { inet RG4; } rib-group { inet6 RG6; }
		} }`); err != nil {
			store.ExitConfigure()
			t.Fatalf("LoadOverride: %v", err)
		}
		_, err := store.Commit()
		store.ExitConfigure()
		if err == nil || !strings.Contains(err.Error(), `inet "RG4"`) ||
			!strings.Contains(err.Error(), `inet6 "RG6"`) {
			t.Fatalf("strict global Commit error = %v, want both merged selectors", err)
		}
	})
}
