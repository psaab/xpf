package configstore

import (
	"testing"
)

func TestCheckTextRejectsDroppedSecurityPolicyEnforcementSubtrees11014(t *testing.T) {
	for _, tc := range []struct {
		name  string
		child string
	}{
		{
			name: "nested term",
			child: `term nested {
                        match { source-address 10.0.0.0/8; }
                        then { deny; }
                    }`,
		},
		{
			name:  "session options",
			child: `session-options { inactivity-timeout 60; }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := `security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                ` + tc.child + `
            }
        }
    }
}`
			if _, err := CheckText(text, -1); err == nil {
				t.Fatal("strict CheckText accepted an unknown enforcement-bearing policy subtree")
			}
		})
	}
}
