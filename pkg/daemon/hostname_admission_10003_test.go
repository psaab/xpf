package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10003 apply-path controls. Admission rejects malformed new values before
// this path; this cell proves the existing daemon seam still applies a valid
// FQDN and preserves both no-op guards for empty/unchanged values.
func TestApplyHostnameAdmissionControls10003(t *testing.T) {
	t.Run("valid FQDN reaches kernel and durable file", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath, restoreHost := sethostname, hostnamePath, osHostname
		t.Cleanup(func() { sethostname, hostnamePath, osHostname = restoreSet, restorePath, restoreHost })

		hostFile := filepath.Join(t.TempDir(), "hostname")
		hostnamePath = hostFile
		current := "old.example.net"
		osHostname = func() (string, error) { return current, nil }
		var applied []string
		sethostname = func(raw []byte) error {
			applied = append(applied, string(raw))
			current = string(raw)
			return nil
		}

		d.applyHostname(&config.Config{System: config.SystemConfig{HostName: "router1.example.net"}})
		if len(applied) != 1 || applied[0] != "router1.example.net" {
			t.Fatalf("valid FQDN did not reach sethostname: %v", applied)
		}
		got, err := os.ReadFile(hostFile)
		if err != nil {
			t.Fatalf("read durable hostname: %v", err)
		}
		if string(got) != "router1.example.net\n" {
			t.Fatalf("durable hostname = %q, want %q", got, "router1.example.net\n")
		}
	})

	t.Run("empty value remains an early no-op", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath, restoreHost := sethostname, hostnamePath, osHostname
		t.Cleanup(func() { sethostname, hostnamePath, osHostname = restoreSet, restorePath, restoreHost })

		hostFile := filepath.Join(t.TempDir(), "hostname")
		if err := os.WriteFile(hostFile, []byte("keep\n"), 0644); err != nil {
			t.Fatal(err)
		}
		hostnamePath = hostFile
		osHostname = func() (string, error) { return "old.example.net", nil }
		var applied []string
		sethostname = func(raw []byte) error { applied = append(applied, string(raw)); return nil }

		d.applyHostname(&config.Config{})
		if len(applied) != 0 {
			t.Fatalf("empty host-name called sethostname: %v", applied)
		}
		got, err := os.ReadFile(hostFile)
		if err != nil {
			t.Fatalf("read unchanged hostname file: %v", err)
		}
		if string(got) != "keep\n" {
			t.Fatalf("empty host-name changed durable file to %q", got)
		}
	})

	t.Run("unchanged value remains an early no-op", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath, restoreHost := sethostname, hostnamePath, osHostname
		t.Cleanup(func() { sethostname, hostnamePath, osHostname = restoreSet, restorePath, restoreHost })

		hostFile := filepath.Join(t.TempDir(), "hostname")
		if err := os.WriteFile(hostFile, []byte("steady.example.net\n"), 0644); err != nil {
			t.Fatal(err)
		}
		hostnamePath = hostFile
		osHostname = func() (string, error) { return "steady.example.net", nil }
		var applied []string
		sethostname = func(raw []byte) error { applied = append(applied, string(raw)); return nil }

		d.applyHostname(&config.Config{System: config.SystemConfig{HostName: "steady.example.net"}})
		if len(applied) != 0 {
			t.Fatalf("unchanged host-name called sethostname: %v", applied)
		}
		got, err := os.ReadFile(hostFile)
		if err != nil {
			t.Fatalf("read unchanged hostname file: %v", err)
		}
		if string(got) != "steady.example.net\n" {
			t.Fatalf("unchanged host-name changed durable file to %q", got)
		}
	})

	t.Run("tolerated invalid value is not applied", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath, restoreHost := sethostname, hostnamePath, osHostname
		t.Cleanup(func() { sethostname, hostnamePath, osHostname = restoreSet, restorePath, restoreHost })

		hostFile := filepath.Join(t.TempDir(), "hostname")
		if err := os.WriteFile(hostFile, []byte("keep.example.net\n"), 0644); err != nil {
			t.Fatal(err)
		}
		hostnamePath = hostFile
		osHostname = func() (string, error) { return "old.example.net", nil }
		var applied []string
		sethostname = func(raw []byte) error { applied = append(applied, string(raw)); return nil }
		cfg := &config.Config{System: config.SystemConfig{HostName: "bad name"}}

		d.applyHostname(cfg)
		if len(applied) != 0 {
			t.Fatalf("invalid tolerated host-name called sethostname: %v", applied)
		}
		got, err := os.ReadFile(hostFile)
		if err != nil {
			t.Fatalf("read protected hostname file: %v", err)
		}
		if string(got) != "keep.example.net\n" {
			t.Fatalf("invalid tolerated host-name changed durable file to %q", got)
		}

		// The DNS-valid but Linux-overlong boundary is also tolerated on
		// boot; the apply belt must refuse it before sethostname(2).
		cfg.System.HostName = strings.Repeat("a", 32) + "." + strings.Repeat("b", 32)
		d.applyHostname(cfg)
		if len(applied) != 0 {
			t.Fatalf("65-byte tolerated host-name called sethostname: %v", applied)
		}
	})
}
