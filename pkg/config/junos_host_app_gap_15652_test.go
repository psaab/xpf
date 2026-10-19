package config

import (
	"strings"
	"testing"
)

// #15652 V5-03: user-shadowed junos-ssh (tcp/2222) must be honoured before
// predefined (tcp/22); application-set and multi-term permits must expand
// instead of aborting appL4Matches (ok=false -> silent).

func TestJunosHostShadowedAndSet15652(t *testing.T) {
	t.Run("shadowed junos-ssh warns for uncovered ssh", func(t *testing.T) {
		lines := policyBase7374([]string{"junos-ssh"}, []string{"ssh"})
		lines = append(lines,
			"set applications application junos-ssh protocol tcp",
			"set applications application junos-ssh destination-port 2222",
		)
		cfg := compileGap7374(t, lines)
		ws := junosHostWarnings7374(t, cfg)
		found := false
		for _, w := range ws {
			if strings.Contains(w, "application-restricted permit") {
				found = true
			}
		}
		if !found {
			t.Fatalf("shadowed junos-ssh tcp/2222 permit vs zone ssh tcp/22 must warn (predefined-first resolver hid gap), warnings=%v", ws)
		}
	})

	t.Run("shadowed junos-ssh covering 22 is silent control", func(t *testing.T) {
		lines := policyBase7374([]string{"junos-ssh"}, []string{"ssh"})
		lines = append(lines,
			"set applications application junos-ssh protocol tcp",
			"set applications application junos-ssh destination-port 22",
		)
		cfg := compileGap7374(t, lines)
		for _, w := range junosHostWarnings7374(t, cfg) {
			if strings.Contains(w, "application-restricted permit") {
				t.Fatalf("user junos-ssh tcp/22 covering ssh must be silent, got %s", w)
			}
		}
	})

	t.Run("application-set permit warns for uncovered service", func(t *testing.T) {
		lines := policyBase7374([]string{"mgmt-set"}, []string{"ssh", "https"})
		lines = append(lines,
			"set applications application-set mgmt-set application junos-ssh",
		)
		cfg := compileGap7374(t, lines)
		found := false
		for _, w := range junosHostWarnings7374(t, cfg) {
			if strings.Contains(w, "application-restricted permit") {
				found = true
			}
		}
		if !found {
			t.Fatalf("application-set permit (only ssh) vs https admit must warn; set expansion aborted advisory")
		}
	})

	t.Run("multi-term permit warns for uncovered service", func(t *testing.T) {
		lines := policyBase7374([]string{"multiapp"}, []string{"ssh", "https"})
		lines = append(lines,
			"set applications application multiapp term t1 protocol tcp destination-port 22",
		)
		// multi-term needs at least term form; single term above mints implicit set.
		lines = append(lines,
			"set applications application multiapp term t2 protocol tcp destination-port 2222",
		)
		cfg := compileGap7374(t, lines)
		found := false
		for _, w := range junosHostWarnings7374(t, cfg) {
			if strings.Contains(w, "application-restricted permit") {
				found = true
			}
		}
		if !found {
			t.Fatalf("multi-term permit (22,2222) vs https admit must warn; multi-term aborted advisory, warnings=%v", junosHostWarnings7374(t, cfg))
		}
	})

	t.Run("predefined application-set permit warns", func(t *testing.T) {
		lines := policyBase7374([]string{"junos-sip"}, []string{"ssh"})
		cfg := compileGap7374(t, lines)
		found := false
		for _, w := range junosHostWarnings7374(t, cfg) {
			if strings.Contains(w, "application-restricted permit") {
				found = true
			}
		}
		if !found {
			t.Fatalf("predefined set junos-sip permit vs ssh admit must warn")
		}
	})
}
