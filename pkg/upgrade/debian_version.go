package upgrade

import (
	"fmt"
	"strings"
)

// compareDebianVersions compares Debian version strings using the epoch,
// upstream-version, and Debian-revision ordering from dpkg. Versions accepted
// by ValidateVersionSegment but outside Debian's ordering grammar are rejected
// so callers can retain status rather than guess.
func compareDebianVersions(a, b string) (int, error) {
	aEpoch, aUpstream, aRevision, err := splitDebianVersion(a)
	if err != nil {
		return 0, fmt.Errorf("invalid Debian version %q: %w", a, err)
	}
	bEpoch, bUpstream, bRevision, err := splitDebianVersion(b)
	if err != nil {
		return 0, fmt.Errorf("invalid Debian version %q: %w", b, err)
	}
	if c := compareNumericStrings(aEpoch, bEpoch); c != 0 {
		return c, nil
	}
	if c := compareDebianPart(aUpstream, bUpstream); c != 0 {
		return c, nil
	}
	return compareDebianPart(aRevision, bRevision), nil
}

func splitDebianVersion(version string) (epoch, upstream, revision string, err error) {
	if err := ValidateVersionSegment(version); err != nil {
		return "", "", "", err
	}
	epoch = "0"
	if colon := strings.IndexByte(version, ':'); colon >= 0 {
		if colon == 0 {
			return "", "", "", fmt.Errorf("empty epoch")
		}
		epoch = version[:colon]
		for i := range epoch {
			if !asciiDigit(epoch[i]) {
				return "", "", "", fmt.Errorf("epoch is not numeric")
			}
		}
		version = version[colon+1:]
	}

	revision = "0"
	if dash := strings.LastIndexByte(version, '-'); dash >= 0 {
		upstream, revision = version[:dash], version[dash+1:]
		if revision == "" {
			return "", "", "", fmt.Errorf("empty Debian revision")
		}
	} else {
		upstream = version
	}
	if upstream == "" || !asciiDigit(upstream[0]) {
		return "", "", "", fmt.Errorf("upstream version must start with a digit")
	}
	for i := range upstream {
		c := upstream[i]
		if !asciiDigit(c) && !asciiLetter(c) && c != '.' && c != '+' && c != '~' && c != '-' {
			return "", "", "", fmt.Errorf("unsupported upstream character %q", c)
		}
	}
	for i := range revision {
		c := revision[i]
		if !asciiDigit(c) && !asciiLetter(c) && c != '.' && c != '+' && c != '~' {
			return "", "", "", fmt.Errorf("unsupported Debian revision character %q", c)
		}
	}
	return epoch, upstream, revision, nil
}

func compareNumericStrings(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return compareBytes(a, b)
}

func compareDebianPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !asciiDigit(a[i])) || (j < len(b) && !asciiDigit(b[j])) {
			var ac, bc byte
			if i < len(a) {
				ac = a[i]
			}
			if j < len(b) {
				bc = b[j]
			}
			if ao, bo := debianCharOrder(ac), debianCharOrder(bc); ao < bo {
				return -1
			} else if ao > bo {
				return 1
			}
			if i < len(a) && !asciiDigit(a[i]) {
				i++
			}
			if j < len(b) && !asciiDigit(b[j]) {
				j++
			}
		}

		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		startA, startB := i, j
		for i < len(a) && asciiDigit(a[i]) {
			i++
		}
		for j < len(b) && asciiDigit(b[j]) {
			j++
		}
		if i-startA < j-startB {
			return -1
		}
		if i-startA > j-startB {
			return 1
		}
		if c := compareBytes(a[startA:i], b[startB:j]); c != 0 {
			return c
		}
	}
	return 0
}

func debianCharOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case asciiLetter(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareBytes(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func asciiDigit(c byte) bool { return c >= '0' && c <= '9' }

func asciiLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
