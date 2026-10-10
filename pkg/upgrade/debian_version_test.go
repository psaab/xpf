package upgrade

import "testing"

func TestCompareDebianVersions(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "epoch", a: "2:1.0", b: "10:1.0", want: -1},
		{name: "leading zero epoch", a: "0001:1.0", b: "1:1.0", want: 0},
		{name: "tilde prerelease", a: "1.0~rc1", b: "1.0", want: -1},
		{name: "revision", a: "1.0-1", b: "1.0", want: 1},
		{name: "revision order", a: "1.0-2", b: "1.0-10", want: -1},
		{name: "numeric block", a: "1.0.10", b: "1.0.9", want: 1},
		{name: "upstream continuation", a: "1.0", b: "1.0.0", want: -1},
		{name: "end sorts after tilde", a: "1.0a", b: "1.0a~", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareDebianVersions(tt.a, tt.b)
			if err != nil || got != tt.want {
				t.Fatalf("compareDebianVersions(%q, %q) = %d, err=%v; want %d", tt.a, tt.b, got, err, tt.want)
			}
		})
	}
}

func TestCompareDebianVersionsRejectsUnorderableValues(t *testing.T) {
	for _, version := range []string{"unknown", "release-one", "1.0:", "1.0-"} {
		t.Run(version, func(t *testing.T) {
			if _, err := compareDebianVersions(version, "1.0"); err == nil {
				t.Fatalf("compareDebianVersions(%q, %q) accepted an unorderable version", version, "1.0")
			}
		})
	}
}
