package config

import "testing"

// #11777: block-spelled `apply-groups { g1; g2; }` carries its names as child
// leaves (Keys=["apply-groups"], Children=[[g1] [g2]]), but expansion collected
// only Keys[1:] and then stripped the node unconditionally — so the block
// spelling silently applied nothing on a clean commit. The `-except` twin
// (collectExceptNames9862) has the same Keys-only read, so a block exclusion
// silently fails to exclude.

func TestApplyGroupsBlockSpellingInherits11777(t *testing.T) {
	rows := []struct {
		name  string
		text  string
		host  string
		tzone string
	}{
		{
			name: "single",
			text: `groups { G { system { host-name FROM-G; } } }
apply-groups { G; }
system { domain-name example.com; }`,
			host: "FROM-G",
		},
		{
			name: "multi",
			text: `groups {
  G { system { host-name FROM-G; } }
  H { system { time-zone UTC; } }
}
apply-groups { G; H; }
system { domain-name example.com; }`,
			host:  "FROM-G",
			tzone: "UTC",
		},
		{
			name: "nested",
			text: `groups { G { system { host-name FROM-G; } } }
system { apply-groups { G; } domain-name example.com; }`,
			host: "FROM-G",
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cfg := compile9422(t, parseTree9422(t, r.text))
			if cfg.System.HostName != r.host {
				t.Fatalf("block apply-groups not inherited: HostName=%q want %q", cfg.System.HostName, r.host)
			}
			if cfg.System.TimeZone != r.tzone {
				t.Fatalf("block apply-groups not inherited: TimeZone=%q want %q", cfg.System.TimeZone, r.tzone)
			}
			if cfg.System.DomainName != "example.com" {
				t.Fatalf("inline statement lost: DomainName=%q", cfg.System.DomainName)
			}
		})
	}
}

func TestApplyGroupsExceptBlockSpellingExcludes11777(t *testing.T) {
	const control = `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { domain-name example.com; }`
	ctrl := compile9422(t, parseTree9422(t, control))
	if ctrl.System.HostName != "FROM-GROUP" {
		t.Fatalf("POSITIVE CONTROL broken: without the exclusion the group must be inherited, got HostName=%q", ctrl.System.HostName)
	}

	rows := []struct {
		name string
		text string
	}{
		{
			name: "single",
			text: `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except { G; } domain-name example.com; }`,
		},
		{
			name: "multi",
			text: `groups {
  G { system { host-name FROM-G; } }
  H { system { time-zone UTC; } }
}
apply-groups [ G H ];
system { apply-groups-except { G; H; } domain-name example.com; }`,
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cfg := compile9422(t, parseTree9422(t, r.text))
			if cfg.System.HostName != "" || cfg.System.TimeZone != "" {
				t.Fatalf("block apply-groups-except did not exclude: HostName=%q TimeZone=%q", cfg.System.HostName, cfg.System.TimeZone)
			}
			if cfg.System.DomainName != "example.com" {
				t.Fatalf("inline statement lost: DomainName=%q", cfg.System.DomainName)
			}
		})
	}
}
