package auth

import (
	"errors"
	"strings"
)

// authParams is a comma-separated list of auth-params of HTTP credentials (RFC 9110, section 11.2):
//
//	auth-param = token BWS "=" BWS ( token / quoted-string )
type authParams string

var errMalformedAuthParams = errors.New("malformed auth-params")

// splitCredentials returns the auth-scheme and the auth-params of an Authorization header value.
func splitCredentials(header string) (string, authParams) {
	scheme, params, _ := strings.Cut(header, " ")
	return scheme, authParams(params)
}

// next cuts the first auth-param off the list, skipping empty list elements. A quoted-string value
// is returned unquoted, quoted-pairs are not supported since no AWS parameter value can have them.
// An empty name with no error means the end of the list.
func (p *authParams) next() (name, value string, err error) {
	s := strings.TrimLeft(string(*p), " \t,")
	if s == "" {
		*p = ""
		return "", "", nil
	}

	name, s, ok := strings.Cut(s, "=")
	name = strings.TrimRight(name, " \t")
	if !ok || name == "" || strings.ContainsAny(name, " \t,\"") {
		return "", "", errMalformedAuthParams
	}

	s = strings.TrimLeft(s, " \t")
	if rest, quoted := strings.CutPrefix(s, `"`); quoted {
		value, s, ok = strings.Cut(rest, `"`)
		ok = ok && !strings.Contains(value, `\`)
	} else {
		end := strings.IndexAny(s, " \t,")
		if end < 0 {
			end = len(s)
		}
		value, s = s[:end], s[end:]
		ok = !strings.Contains(value, `"`)
	}

	s = strings.TrimLeft(s, " \t")
	if !ok || s != "" && s[0] != ',' {
		return "", "", errMalformedAuthParams
	}

	*p = authParams(s)
	return name, value, nil
}
