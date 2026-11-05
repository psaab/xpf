package configstore

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSNMPClientListQualifierPairing18844(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries string
	}{
		{"qualifier cannot pair across children", `10.1.0.0/16; restrict 0.0.0.0/0;`},
		{"leading qualifier after another child", `10.1.0.0/16; 10.1.1.0/24; restrict 0.0.0.0/0;`},
		{"repeated qualifier", `10.1.0.0/16 restrict restrict;`},
		{"malformed qualifier", `10.1.0.0/16 restric;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := `system { host-name fw; }
snmp {
    client-list mgmt { ` + tc.entries + ` }
    community scoped { authorization read-only; client-list-name mgmt; }
}`
			if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "client-list") {
				t.Fatalf("CheckText error = %v, want strict malformed client-list rejection", err)
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
			cfg, err := store.SyncApply(text, nil)
			if err != nil {
				t.Fatalf("lenient SyncApply rejected stored config: %v", err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatal("lenient SyncApply did not warn about malformed client-list qualifiers")
			}
			community := cfg.System.SNMP.Communities["scoped"]
			if community == nil {
				t.Fatal("lenient SyncApply did not compile the scoped community")
			}
			for _, source := range []string{"10.1.3.7", "10.1.2.7"} {
				if community.AllowsSource(net.ParseIP(source).To4()) {
					t.Errorf("quarantined community allowed %s for malformed client-list statement %q",
						source, tc.entries)
				}
			}
		})
	}
}

func TestSNMPClientListQualifierValidForms18844(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{
			name: "braced statements",
			text: `system { host-name fw; }
snmp {
    client-list mgmt { 10.1.0.0/16; 10.1.2.0/24 restrict; }
    community scoped { authorization read-only; client-list-name mgmt; }
}`,
		},
		{
			name: "flat multi-token run",
			text: `set system host-name fw
set snmp client-list mgmt 10.1.0.0/16 10.1.2.0/24 restrict
set snmp community scoped authorization read-only
set snmp community scoped client-list-name mgmt`,
		},
		{
			name: "bracketed multi-token run",
			text: `set system host-name fw
set snmp client-list mgmt [ 10.1.0.0/16 10.1.2.0/24 restrict ]
set snmp community scoped authorization read-only
set snmp community scoped client-list-name mgmt`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("CheckText rejected valid client-list statements: %v", err)
			}
			assertSNMPClientListRestriction18844(t, cfg)
		})
	}
}

func TestSNMPInlineClientQualifierCannotCrossChildren18844(t *testing.T) {
	text := `system { host-name fw; }
snmp {
    community scoped {
        authorization read-only;
        clients { 10.1.0.0/16; restrict 0.0.0.0/0; }
    }
}`
	if _, err := CheckText(text, -1); err == nil {
		t.Fatal("CheckText accepted restrict pairing across inline clients children")
	}
	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("lenient SyncApply rejected stored config: %v", err)
	}
	community := cfg.System.SNMP.Communities["scoped"]
	if community == nil {
		t.Fatal("lenient SyncApply did not compile the scoped community")
	}
	if community.AllowsSource(net.ParseIP("10.1.3.7").To4()) ||
		community.AllowsSource(net.ParseIP("10.1.2.7").To4()) {
		t.Fatal("malformed inline clients did not quarantine the community to deny-all")
	}
}

func TestSNMPClientListNestedPrefixStillRefused18844(t *testing.T) {
	text := `system { host-name fw; }
snmp {
    client-list {
        mgmt { 10.1.0.0/16 { 10.2.0.0/16; } }
    }
    community scoped { authorization read-only; client-list-name mgmt; }
}`
	if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "nested content") {
		t.Fatalf("CheckText error = %v, want nested client-list prefix refusal", err)
	}
	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if _, err := store.SyncApply(text, nil); err == nil || !strings.Contains(err.Error(), "nested content") {
		t.Fatalf("lenient SyncApply error = %v, want compiler-side nested prefix refusal", err)
	}
}

func assertSNMPClientListRestriction18844(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg.System.SNMP == nil {
		t.Fatal("SNMP config was not compiled")
	}
	community := cfg.System.SNMP.Communities["scoped"]
	if community == nil {
		t.Fatal("CheckText did not compile the scoped community")
	}
	if !community.AllowsSource(net.ParseIP("10.1.3.7").To4()) {
		t.Error("10.1.3.7 is in the /16 allow and outside the restricted /24; it must be served")
	}
	if community.AllowsSource(net.ParseIP("10.1.2.7").To4()) {
		t.Error("10.1.2.7 is in the longer-prefix restricted /24; it must be denied")
	}
}
