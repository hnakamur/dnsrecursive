package recursive

import "fmt"

const (
	// maxLabelLength is the maximum length of a label permitted by RFC 1035.
	maxLabelLength = 63
	// maxNameLength is the maximum length of a DNS name.
	maxNameLength = 254
)

// A FQDN is a fully-qualified DNS name or name suffix.
type FQDN string

func ToFQDN(s string) (FQDN, error) {
	if len(s) == 0 || s == "." {
		return FQDN("."), nil
	}

	if s[0] == '.' {
		s = s[1:]
	}
	raw := s
	totalLen := len(s)
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	} else {
		totalLen += 1 // account for missing dot
	}
	if totalLen > maxNameLength {
		return "", fmt.Errorf("%q is too long to be a DNS name", s)
	}

	st := 0
	for i := range len(s) {
		if s[i] != '.' {
			continue
		}
		label := s[st:i]
		// You might be tempted to do further validation of the
		// contents of labels here, based on the hostname rules in RFC
		// 1123. However, DNS labels are not always subject to
		// hostname rules. In general, they can contain any non-zero
		// byte sequence, even though in practice a more restricted
		// set is used.
		//
		// See https://github.com/tailscale/tailscale/issues/2024 for more.
		if len(label) == 0 || len(label) > maxLabelLength {
			return "", fmt.Errorf("%q is not a valid DNS label", label)
		}
		st = i + 1
	}

	if raw[len(raw)-1] != '.' {
		raw = raw + "."
	}
	return FQDN(raw), nil
}

// WithTrailingDot returns f as a string, with a trailing dot.
func (f FQDN) WithTrailingDot() string {
	return string(f)
}
