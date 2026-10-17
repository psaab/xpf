package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14388 (DR6-H4): lenient compile of OSPF MD5 with only out-of-range
// key-ids must not render an unauthenticated OSPF interface. Both adjacent
// routers leniently loading the same template would otherwise form a
// null-auth adjacency while both configs state MD5. The renderer is the
// last writer of frr.conf, so it must omit the whole interface block
// (area activation included) when AuthType is md5 but no key survives.
//
// Fixture uses the exact hierarchical spelling from the issue, rendered
// through CompileConfigLenient -> buildManagedSection (the production
// assemble path). Empty/unsafe secrets are the same "no key survives"
// class and are pinned at the direct-render layer.

func ospfMD5Lenient14388(t *testing.T, body string) (*config.Config, *bytes.Buffer, func()) {
	t.Helper()
	tree, perrs := config.NewParser(body).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	return cfg, &logs, func() { slog.SetDefault(prev) }
}

func TestOSPFLenientMD5OnlyOutOfRangeKeysOmitsInterface14388(t *testing.T) {
	src := `protocols {
  ospf {
    area 0.0.0.0 {
      interface ge-0/0/0 {
        authentication {
          md5 0 {
            key "s3cr3t-md5";
          }
          md5 256 {
            key "s3cr3t-md5";
          }
          md5 1000 {
            key "s3cr3t-md5";
          }
        }
      }
    }
  }
}`
	cfg, logs, restore := ospfMD5Lenient14388(t, src)
	defer restore()
	// Lenient compile must warn, not hard-fail (#1960 no-brick).
	foundWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "OSPF MD5 key-id") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("lenient compile warnings missing OSPF MD5 key-id downgrade: %v", cfg.Warnings)
	}
	got := New().buildManagedSection(&FullConfig{OSPF: cfg.Protocols.OSPF})
	if strings.Contains(got, "interface ge-0/0/0") {
		t.Fatalf("unauthenticated OSPF interface rendered for all-invalid MD5 keys:\n%s", got)
	}
	if strings.Contains(got, "ip ospf area") {
		t.Fatalf("OSPF area activation rendered without auth:\n%s", got)
	}
	if strings.Contains(got, "s3cr3t-md5") {
		t.Fatalf("secret leaked into frr.conf:\n%s", got)
	}
	if !strings.Contains(logs.String(), "ge-0/0/0") {
		t.Fatalf("render warning must name the omitted interface; logs: %s", logs.String())
	}
	if strings.Contains(logs.String(), "s3cr3t-md5") {
		t.Fatalf("render warning leaked secret: %s", logs.String())
	}
}

// Controls: in-range and mixed keys still render; simple untouched.
func TestOSPFMD5SurvivingKeyControls14388(t *testing.T) {
	cases := []struct {
		name       string
		iface      *config.OSPFInterface
		wantBlock  bool
		wantKey    string
		forbidKeys []string
	}{
		{
			name:      "valid single",
			iface:     &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKey: "s3cr3t-md5", AuthKeyID: 1},
			wantBlock: true,
			wantKey:   " ip ospf message-digest-key 1 md5 s3cr3t-md5\n",
		},
		{
			name: "mixed out-of-range plus valid via AuthMD5Keys",
			iface: &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKeyID: 1, AuthKey: "good-key",
				AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 0, Key: "bad-key"}, {ID: 1, Key: "good-key"}}},
			wantBlock:  true,
			wantKey:    " ip ospf message-digest-key 1 md5 good-key\n",
			forbidKeys: []string{"bad-key"},
		},
		{
			name:      "simple unaffected",
			iface:     &config.OSPFInterface{Name: "eth0", AuthType: "simple", AuthKey: "plainpw"},
			wantBlock: true,
			wantKey:   " ip ospf authentication-key plainpw\n",
		},
		{
			name:      "no auth unaffected",
			iface:     &config.OSPFInterface{Name: "eth0"},
			wantBlock: true,
		},
		{
			name:      "md5 empty secret only",
			iface:     &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKeyID: 1},
			wantBlock: false,
		},
		{
			name:      "md5 unsafe secret only",
			iface:     &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKey: "has space", AuthKeyID: 1},
			wantBlock: false,
		},
		{
			name:      "md5 all out-of-range direct",
			iface:     &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKey: "s3cr3t-md5", AuthKeyID: 256},
			wantBlock: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ospf := &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{
				ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{tc.iface},
			}}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if tc.wantBlock {
				if !strings.Contains(got, "interface eth0\n") {
					t.Fatalf("interface block missing:\n%s", got)
				}
				if !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
					t.Fatalf("area activation missing:\n%s", got)
				}
			} else {
				if strings.Contains(got, "interface eth0") || strings.Contains(got, "ip ospf area") {
					t.Fatalf("md5 with no surviving key must omit interface:\n%s", got)
				}
			}
			if tc.wantKey != "" && !strings.Contains(got, tc.wantKey) {
				t.Fatalf("want key line %q:\n%s", tc.wantKey, got)
			}
			for _, fk := range tc.forbidKeys {
				if strings.Contains(got, fk) {
					t.Fatalf("forbidden key %q rendered:\n%s", fk, got)
				}
			}
		})
	}
}

// VRF instance path shares generateProtocols; pin it too.
func TestOSPFMD5NoSurvivingKeyOmitsVRFInterface14388(t *testing.T) {
	ospf := &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{
		ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
			{Name: "eth0", AuthType: "md5", AuthKey: "s3cr3t-md5", AuthKeyID: 0},
			{Name: "eth1", AuthType: "md5", AuthKey: "good", AuthKeyID: 2},
		},
	}}}
	got := New().generateProtocols(ospf, nil, nil, nil, nil, "vrf-tenant", 0, nil, nil)
	if strings.Contains(got, "interface eth0") {
		t.Fatalf("VRF unauthenticated interface rendered:\n%s", got)
	}
	if !strings.Contains(got, "interface eth1\n") || !strings.Contains(got, "ip ospf message-digest-key 2 md5 good") {
		t.Fatalf("VRF valid interface must still render:\n%s", got)
	}
}
