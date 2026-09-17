// sysfs link state helpers used by `show interfaces ...` presenters.
package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readLinkSpeed reads the link speed in Mbps from sysfs. Returns 0 on
// error or when the link is down.
func readLinkSpeed(ifaceName string) int {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/speed")
	if err != nil {
		return 0
	}
	speed, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || speed <= 0 {
		return 0
	}
	return speed
}

// readLinkDuplex reads the link duplex from sysfs. Returns "" on error.
func readLinkDuplex(ifaceName string) string {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/duplex")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// formatSpeed formats a link speed in Mbps to a human-readable string.
// Exact multiples of 1000 render as integer Gbps; other gigabit-plus
// speeds render one decimal, truncated with integer math rather than
// float rounding. Speeds below 1000 Mbps retain their Mbps display.
func formatSpeed(mbps int) string {
	if mbps >= 1000 {
		if mbps%1000 == 0 {
			return fmt.Sprintf("%dGbps", mbps/1000)
		}
		return fmt.Sprintf("%d.%dGbps", mbps/1000, (mbps%1000)/100)
	}
	return fmt.Sprintf("%dMbps", mbps)
}

// formatDuplex formats a sysfs duplex string to display form.
func formatDuplex(duplex string) string {
	switch strings.ToLower(duplex) {
	case "full":
		return "Full-duplex"
	case "half":
		return "Half-duplex"
	default:
		return duplex
	}
}
