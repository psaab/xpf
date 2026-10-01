package config

import (
	"strings"
	"testing"
)

func TestAPIAuthCredentialSchemaRejectsInvalidClassesAndUnknownFields11544(t *testing.T) {
	valid := []string{
		"set system services web-management api-auth class read-only",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth user admin password correct-horse-battery",
		"set system services web-management api-auth user admin class read-only",
		"set system services web-management api-auth user admin expires 2099-01-01",
		"set system services web-management api-auth key automation secret machine-generated-key-for-api-auth",
		"set system services web-management api-auth key automation class read-only",
		"set system services web-management api-auth key automation expires 2099-01-01",
	}
	validTree := buildTreeFromSets(t, valid...)
	if err := SchemaValidate(validTree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected a valid API-auth credential shape: %v", err)
	}
	if _, err := CompileConfig(validTree); err != nil {
		t.Fatalf("CompileConfig rejected a valid API-auth credential shape: %v", err)
	}

	cases := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "default class reference",
			command: "set system services web-management api-auth class undefined-class",
			want:    "not defined",
		},
		{
			name:    "Basic user class reference",
			command: "set system services web-management api-auth user admin class undefined-class",
			want:    "not defined",
		},
		{
			name:    "named API key class reference",
			command: "set system services web-management api-auth key automation class undefined-class",
			want:    "not defined",
		},
		{
			name:    "unknown Basic user field",
			command: "set system services web-management api-auth user admin unexpected value",
			want:    "unknown configuration keyword",
		},
		{
			name:    "unknown named API key field",
			command: "set system services web-management api-auth key automation unexpected value",
			want:    "unknown configuration keyword",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commands := append(append([]string(nil), valid...), tc.command)
			err := SchemaValidate(buildTreeFromSets(t, commands...), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SchemaValidate error = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
