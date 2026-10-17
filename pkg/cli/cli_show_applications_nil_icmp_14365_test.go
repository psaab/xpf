package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14365: the local CLI `show security applications` twin of the gRPC
// renderer (#12903) dereferenced present-but-nil *config.Application map
// values (tolerant-load / peer-sync, #1960) and never rendered ICMPType /
// ICMPCode, so a type-8/code-0 application looked identical to an
// unconstrained ICMP application. Reverting the nil guards panics these
// tests; reverting the ICMP rendering flips the substring assertions.

func applications14365Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
applications {
    application icmp-echo {
        protocol icmp;
        icmp-type 8;
        icmp-code 0;
    }
    application-set my-set {
        application icmp-echo;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Applications.Applications["icmp-echo"] == nil {
		t.Fatalf("fixture missing icmp-echo application")
	}
	cfg.Applications.Applications["zz-nil-app"] = nil
	as := cfg.Applications.ApplicationSets["my-set"]
	if as == nil {
		t.Fatalf("fixture missing my-set application-set")
	}
	as.Applications = append(as.Applications, "zz-nil-app")
	return store
}

func TestCLIShowApplicationsNilAppNoPanic14365(t *testing.T) {
	c := &CLI{store: applications14365Store(t)}
	// Direct list/detail deref app.Name (filter) and app fields via
	// printApp; the set-filter path expands the nil member.
	for _, args := range [][]string{
		nil,
		{"detail"},
		{"zz-nil-app"},
		{"my-set"},
	} {
		captureStdout(t, func() {
			if err := c.showApplications(args); err != nil {
				t.Fatalf("showApplications(%v): %v", args, err)
			}
		})
	}
}

func TestCLIShowApplicationsICMPTypeCodeRendered14365(t *testing.T) {
	c := &CLI{store: applications14365Store(t)}

	summary := captureStdout(t, func() {
		if err := c.showApplications(nil); err != nil {
			t.Fatalf("showApplications(list): %v", err)
		}
	})
	if !strings.Contains(summary, "icmp-echo") {
		t.Fatalf("summary missing icmp-echo:\n%s", summary)
	}
	if !strings.Contains(summary, "icmp-type=8") || !strings.Contains(summary, "icmp-code=0") {
		t.Fatalf("summary missing ICMP type/code constraint:\n%s", summary)
	}

	detail := captureStdout(t, func() {
		if err := c.showApplications([]string{"detail"}); err != nil {
			t.Fatalf("showApplications(detail): %v", err)
		}
	})
	if !strings.Contains(detail, "ICMP type: 8") || !strings.Contains(detail, "ICMP code: 0") {
		t.Fatalf("detail missing ICMP type/code constraint:\n%s", detail)
	}

	filtered := captureStdout(t, func() {
		if err := c.showApplications([]string{"icmp-echo"}); err != nil {
			t.Fatalf("showApplications(filter): %v", err)
		}
	})
	if !strings.Contains(filtered, "ICMP type: 8") || !strings.Contains(filtered, "ICMP code: 0") {
		t.Fatalf("filtered detail missing ICMP type/code constraint:\n%s", filtered)
	}
}
