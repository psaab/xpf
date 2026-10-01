package config

import (
	"strings"
	"testing"
)

func TestSamplingSourceAddressesRequireIPAndMatchingFamilies11445(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{
			name: "output source is not an IP",
			lines: []string{
				"set forwarding-options sampling instance i1 family inet output source-address not-an-ip",
				"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 port 2055",
			},
			wantErr: "source-address",
		},
		{
			name: "IPv6 output source under inet",
			lines: []string{
				"set forwarding-options sampling instance i1 family inet output source-address 2001:db8::1",
				"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 port 2055",
			},
			wantErr: "source-address",
		},
		{
			name: "per-server source has wrong family",
			lines: []string{
				"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 port 2055",
				"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 source-address 2001:db8::1",
			},
			wantErr: "source-address",
		},
		{
			name: "collector literal has wrong family",
			lines: []string{
				"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
				"set forwarding-options sampling instance i1 family inet output flow-server 2001:db8::10 port 2055",
			},
			wantErr: "source-address",
		},
		{
			name: "inline-jflow source has wrong family",
			lines: []string{
				"set forwarding-options sampling instance i1 family inet output inline-jflow source-address 2001:db8::1",
			},
			wantErr: "source-address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatalf("CompileConfig accepted an invalid sampling source-address; want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CompileConfig error %q does not identify %q", err, tc.wantErr)
			}
		})
	}
}

func TestSamplingSourceAddressNonLocalWarns11445(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set forwarding-options sampling instance i1 family inet output source-address 198.51.100.1",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 port 2055",
	}))
	if err != nil {
		t.Fatalf("CompileConfig rejected a parseable, family-matched source-address: %v", err)
	}
	commitWarnings := 0
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "source-address") && strings.Contains(warning, "not configured on a local interface") {
			commitWarnings++
		}
	}
	if commitWarnings != 1 {
		t.Fatalf("compile should report the non-local source exactly once in commit warnings, got %d in %v",
			commitWarnings, cfg.Warnings)
	}
	validatorWarnings := 0
	for _, warning := range ValidateConfig(cfg) {
		if strings.Contains(warning, "source-address") && strings.Contains(warning, "not configured on a local interface") {
			validatorWarnings++
		}
	}
	if validatorWarnings != 1 {
		t.Fatalf("ValidateConfig should warn once that the source is not configured locally, got %d in %v",
			validatorWarnings, ValidateConfig(cfg))
	}
}

func TestSamplingSourceAddressInvalidLenientLoadWarns11445(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set forwarding-options sampling instance i1 family inet output source-address not-an-ip",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 port 2055",
	}))
	if err != nil {
		t.Fatalf("lenient load rejected an invalid persisted source-address: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "sampling source-address") && strings.Contains(warning, "not-an-ip") {
			return
		}
	}
	t.Fatalf("lenient load did not warn about the invalid source-address: %v", cfg.Warnings)
}

func TestSamplingLocalInetAndInet6SourceAddressesCompile11445(t *testing.T) {
	cases := []struct {
		name   string
		source string
		v6     bool
		lines  []string
	}{
		{
			name:   "inet",
			source: "10.0.0.1",
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
				"set forwarding-options sampling instance i1 family inet output flow-server 192.0.2.10 port 2055",
			},
		},
		{
			name:   "inet6",
			source: "2001:db8::1",
			v6:     true,
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
				"set forwarding-options sampling instance i1 family inet6 output source-address 2001:db8::1",
				"set forwarding-options sampling instance i1 family inet6 output flow-server 2001:db8::10 port 2055",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("CompileConfig rejected a local source-address: %v", err)
			}
			inst := cfg.ForwardingOptions.Sampling.Instances["i1"]
			if inst == nil {
				t.Fatal("sampling instance i1 was not compiled")
			}
			fam := inst.FamilyInet
			if tc.v6 {
				fam = inst.FamilyInet6
			}
			if fam == nil || len(fam.FlowServers) != 1 {
				t.Fatalf("sampling family/collector was not compiled: %+v", inst)
			}
			if fam.SourceAddress != tc.source {
				t.Fatalf("local source-address = %q, want %q", fam.SourceAddress, tc.source)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "source-address") {
					t.Fatalf("local source-address unexpectedly appeared in commit warnings: %q", warning)
				}
			}
			for _, warning := range ValidateConfig(cfg) {
				if strings.Contains(warning, "source-address") {
					t.Fatalf("local source-address unexpectedly warned: %q", warning)
				}
			}
		})
	}
}
