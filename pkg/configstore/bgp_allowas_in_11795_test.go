package configstore

import (
	"fmt"
	"strings"
	"testing"
)

func bgpLoopsCommitText11795(scope, value string) string {
	if scope == "group" {
		return fmt.Sprintf(`protocols { bgp { local-as 65001; group G { peer-as 65002; loops %s; neighbor 192.0.2.1; } } }`, value)
	}
	return fmt.Sprintf(`protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.1 { loops %s; } } } }`, value)
}

func TestCheckTextBGPAllowASInRange11795(t *testing.T) {
	for _, scope := range []string{"group", "neighbor"} {
		for _, value := range []string{"banana", "default", "0", "-1", "11", "99999999999999999999"} {
			t.Run(scope+"/reject-"+value, func(t *testing.T) {
				_, err := CheckText(bgpLoopsCommitText11795(scope, value), -1)
				if err == nil || !strings.Contains(err.Error(), "loops") {
					t.Fatalf("CheckText accepted invalid %s loops %q or omitted its diagnostic: %v", scope, value, err)
				}
			})
		}
		for _, value := range []string{"1", "10"} {
			t.Run(scope+"/accept-"+value, func(t *testing.T) {
				if _, err := CheckText(bgpLoopsCommitText11795(scope, value), -1); err != nil {
					t.Fatalf("CheckText rejected valid %s loops %q: %v", scope, value, err)
				}
			})
		}
	}
}
