package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ArchiveDestinationError reports why an archive-sites value is not a remote
// scp destination (#14691): a local destination makes OpenSSH scp copy the
// unredacted active configuration onto a local file as root, bypassing SSH
// host-key verification entirely. It is shared verbatim by the strict
// compiler gate and the runtime scp transport so the two layers can never
// diverge on the same input. OpenSSH decides local-vs-remote by the text
// before the first colon: no colon, or a colon only after a '/', means a
// local operand. A nil result therefore requires a remote
// [user@]host:path or scp://[user@]host[:port]/path with a valid host.
func ArchiveDestinationError(dest string) error {
	reject := func(format string, args ...any) error {
		return fmt.Errorf("system archival archive-sites %q: %s",
			RedactURL(dest), fmt.Sprintf(format, args...))
	}
	if dest == "" {
		return reject("archive-site destination must not be empty; use a remote scp destination such as scp://user@host/path or user@host:path")
	}
	if strings.HasPrefix(dest, "-") {
		return reject("an archive-site URL must not begin with '-' (it is passed to scp as a destination, not an option)")
	}
	if strings.Contains(dest, "://") {
		return validateArchiveURLDestination(dest, reject)
	}
	colon := strings.IndexByte(dest, ':')
	if i := strings.Index(dest, "]:"); i >= 0 {
		// Bracketed IPv6 host: the remote colon follows the closing bracket,
		// not the first colon inside the literal.
		colon = i + 1
	}
	slash := strings.IndexByte(dest, '/')
	if colon < 0 || (slash >= 0 && slash < colon) {
		return reject("archive-site destination is not remote; a local destination would make scp copy the unredacted active configuration to a local file — use user@host:path or scp://user@host/path")
	}
	host, err := archiveRemoteHost(dest[:colon])
	if err != nil {
		return reject("%s", err)
	}
	if err := validateArchiveRemoteHost(host); err != nil {
		return reject("%s", err)
	}
	return nil
}
func validateArchiveURLDestination(dest string, reject func(string, ...any) error) error {
	u, err := url.Parse(dest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return reject("archive-site destination is not a valid remote scp URL; use scp://user@host/path")
	}
	if !strings.EqualFold(u.Scheme, "scp") {
		return reject("archive-site destination scheme %q is not supported; archival uses scp, use an scp:// destination", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return reject("archive-site destination has no remote host; a local destination would make scp copy the unredacted active configuration to a local file")
	}
	if err := validateArchiveRemoteHost(host); err != nil {
		return reject("%s", err)
	}
	if p := u.Port(); p != "" && !isAllDigits(p) {
		return reject("archive-site destination port %q is not numeric", p)
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return reject("inline URL password is not supported; use SSH key authentication")
		}
		if u.User.Username() == "" {
			return reject("archive-site destination has an empty user")
		}
		if err := validateArchiveUser(u.User.Username()); err != nil {
			return reject("%s", err)
		}
	}
	return nil
}

// archiveRemoteHost strips an optional user@ prefix from the text before the
// destination colon, validating the user on the way.
func archiveRemoteHost(hostPart string) (string, error) {
	if i := strings.LastIndex(hostPart, "@"); i >= 0 {
		user, host := hostPart[:i], hostPart[i+1:]
		if user == "" {
			return "", fmt.Errorf("archive-site destination has an empty user")
		}
		if err := validateArchiveUser(user); err != nil {
			return "", err
		}
		return host, nil
	}
	return hostPart, nil
}

func validateArchiveUser(user string) error {
	if strings.HasPrefix(user, "-") {
		return fmt.Errorf("archive-site destination user must not begin with '-'")
	}
	if strings.Contains(user, "/") {
		return fmt.Errorf("archive-site destination user %q is not valid", user)
	}
	return nil
}

func validateArchiveRemoteHost(host string) error {
	if host == "" {
		return fmt.Errorf("archive-site destination has no remote host; a local destination would make scp copy the unredacted active configuration to a local file")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("archive-site destination host must not begin with '-'")
	}
	// Bracketed IPv6 literal, as Hostname() returns it without brackets for
	// URL destinations; both spellings validate the interior as an IP.
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 || host[end+1:] != "" {
			return fmt.Errorf("archive-site destination host %q is not a valid bracketed IPv6 literal", host)
		}
		host = host[1:end]
		if ip := net.ParseIP(host); ip == nil {
			return fmt.Errorf("archive-site destination host %q is not a valid bracketed IPv6 literal", "["+host+"]")
		}
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		// An unbracketed IPv6 host in scheme-less form never reaches here
		// whole (the first colon splits it and the empty first segment is
		// rejected), so a parsed IP here is IPv4 or a URL hostname.
		return nil
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return fmt.Errorf("archive-site destination host %q is not a valid remote host", host)
		}
	}
	return nil
}
