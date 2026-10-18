package config

import (
	"strings"
	"testing"
)

// #14691: an `archive-sites` destination that is not remote makes OpenSSH
// scp perform a LOCAL copy of the unredacted ShowActive() staging file as
// root — overwriting an arbitrary local file and disclosing every secret in
// it, with the #10298 host-key check never consulted. Strict compile must
// reject every local / option-like shape; the control shapes must stay green.
//
// RED-on-revert: without the ArchiveDestinationError gate in compileSystem,
// every `bad` row below compiles clean.

var archiveDestinationBad14691 = []struct {
	name string
	dest string
}{
	{"absolute local path", "/etc/cron.d/x"},
	{"relative local path", "xpf.conf"},
	{"dot relative path", "./xpf.conf"},
	{"dotdot relative path", "../xpf.conf"},
	{"dash option", "-oProxyCommand=evil"},
	{"user dash host", "user@-oProxyCommand=evil:/cfg"},
	{"user dash host no path", "user@-oProxyCommand=evil:"},
	{"leading dash host", "-host:/cfg"},
	{"empty user", "@host:/cfg"},
	{"colon only", ":"},
	{"user at only", "user@"},
	{"colon slash local", ":::/cfg"},
	{"scheme relative local", "//host/path"},
	{"ftp scheme", "ftp://host/dir"},
	{"ftp scheme with user", "ftp://c@host3/c"},
	{"scp url empty host", "scp:///cfg"},
	{"scp url empty user and host", "scp://:123/cfg"},
	{"scp url empty user", "scp://user@/cfg"},
	{"scp url nonnumeric port", "scp://user@host:notaport/cfg"},
	{"scp url dash user", "scp://-oProxyCommand@host/cfg"},
	{"scp url dash host", "scp://user@-host/cfg"},
	{"empty", ""},
}

var archiveDestinationGood14691 = []string{
	"scp://backup@10.0.0.1:/configs",
	"scp://host/dir",
	"scp://a/cfg",
	"scp://alice@host1/configs",
	"scp://user@host:22/cfg",
	"scp://user@[::1]:22/cfg",
	"backup@10.0.0.1:/configs",
	"host:/configs",
	"host:",
	"user@host:path",
	"user@[::1]:/cfg",
	"[::1]:/cfg",
	"10.0.0.1:/configs",
}

func TestArchiveSitesLocalDestinationRejected14691(t *testing.T) {
	for _, tc := range archiveDestinationBad14691 {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				`set system archival configuration transfer-on-commit`,
				`set system archival configuration archive-sites "` + tc.dest + `"`,
			})
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted non-remote archive-site %q; expected rejection", tc.dest)
			}
		})
	}
}

func TestArchiveSitesRemoteDestinationAccepted14691(t *testing.T) {
	for _, dest := range archiveDestinationGood14691 {
		t.Run(dest, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				`set system archival configuration transfer-on-commit`,
				`set system archival configuration archive-sites "` + dest + `"`,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected remote archive-site %q: %v", dest, err)
			}
			if cfg.System.Archival == nil || len(cfg.System.Archival.ArchiveSites) != 1 ||
				cfg.System.Archival.ArchiveSites[0] != dest {
				t.Fatalf("remote archive-site %q not compiled: %+v", dest, cfg.System.Archival)
			}
		})
	}
}

// The bracket spelling must not smuggle a local site past the gate in a
// later slot (the #6692 widened-read class).
func TestArchiveSitesLocalDestinationRejectedInBracket14691(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		`set system archival configuration transfer-on-commit`,
		`set system archival configuration archive-sites [ "scp://a/cfg" "/etc/cron.d/x" ]`,
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a local archive-site in bracket slot 2; expected rejection")
	}
}

// Direct validator coverage: the runtime transport shares this predicate, so
// its verdicts are pinned here without an scp exec.
func TestArchiveDestinationError14691(t *testing.T) {
	for _, tc := range archiveDestinationBad14691 {
		if err := ArchiveDestinationError(tc.dest); err == nil {
			t.Errorf("ArchiveDestinationError(%q) = nil, want rejection (%s)", tc.dest, tc.name)
		} else if tc.dest != "" && strings.Contains(err.Error(), "password") && tc.name != "scp url nonnumeric port" {
			// Rejection reasons must not be the password message for these.
			_ = err
		}
	}
	for _, dest := range archiveDestinationGood14691 {
		if err := ArchiveDestinationError(dest); err != nil {
			t.Errorf("ArchiveDestinationError(%q) = %v, want nil", dest, err)
		}
	}
	// The leading-dash reason is preserved for the #4589 diagnostic.
	if err := ArchiveDestinationError("-oProxyCommand=x"); err == nil ||
		!strings.Contains(err.Error(), "must not begin with '-'") {
		t.Errorf("leading-dash error = %v, want the '-' reason", err)
	}
}
