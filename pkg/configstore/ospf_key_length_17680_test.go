package configstore

import (
	"strings"
	"testing"
)

const junos9OSPFMD5Key17680 = "$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW"

func ospfMD5CheckText17680(key string) string {
	return `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication md5 1 key "` + key + `"; } } } }`
}

func ospfSimpleCheckText17680(key string) string {
	return `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication simple-password "` + key + `"; } } } }`
}

func TestCheckTextOSPFKeyLengthBytes17680(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		wantError string
		wantAuth  string
		wantKey   string
	}{
		{
			name:     "valid encoded MD5 key uses decoded 10-byte plaintext",
			text:     ospfMD5CheckText17680(junos9OSPFMD5Key17680),
			wantAuth: "md5",
			wantKey:  "QZ1agnL21L",
		},
		{
			name:      "MD5 key over byte limit rejected",
			text:      ospfMD5CheckText17680(strings.Repeat("é", 16)),
			wantError: "32 bytes",
		},
		{
			name:     "MD5 key at byte limit accepted",
			text:     ospfMD5CheckText17680(strings.Repeat("é", 8)),
			wantAuth: "md5",
			wantKey:  strings.Repeat("é", 8),
		},
		{
			name:      "simple password over byte limit rejected",
			text:      ospfSimpleCheckText17680(strings.Repeat("é", 8)),
			wantError: "16 bytes",
		},
		{
			name:     "simple password at byte limit accepted",
			text:     ospfSimpleCheckText17680(strings.Repeat("é", 4)),
			wantAuth: "simple",
			wantKey:  strings.Repeat("é", 4),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("CheckText error = %v, want rejection reporting %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckText rejected valid OSPF key: %v", err)
			}
			if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 ||
				len(cfg.Protocols.OSPF.Areas[0].Interfaces) != 1 {
				t.Fatalf("CheckText did not compile the OSPF interface: %+v", cfg.Protocols.OSPF)
			}
			iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
			if iface.AuthType != tc.wantAuth {
				t.Fatalf("compiled authentication type = %q, want %q", iface.AuthType, tc.wantAuth)
			}
			gotKey := iface.AuthKey.Reveal()
			if tc.wantAuth == "md5" {
				if len(iface.AuthMD5Keys) != 1 {
					t.Fatalf("compiled MD5 keys = %d, want 1", len(iface.AuthMD5Keys))
				}
				gotKey = iface.AuthMD5Keys[0].Key.Reveal()
			}
			if gotKey != tc.wantKey {
				t.Fatalf("compiled key = %q, want %q", gotKey, tc.wantKey)
			}
		})
	}
}
