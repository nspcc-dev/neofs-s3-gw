package auth

import "regexp"

type RegexpSubmatcher struct {
	re *regexp.Regexp
}

// NewRegexpMatcher creates a new regexp sub matcher.
func NewRegexpMatcher(re *regexp.Regexp) *RegexpSubmatcher {
	return &RegexpSubmatcher{re: re}
}

// GetSubmatches returns matches from provided string. Zero length indicates no match.
func (r *RegexpSubmatcher) GetSubmatches(target string) map[string]string {
	matches := r.re.FindStringSubmatch(target)
	l := len(matches)

	sub := make(map[string]string, l)
	for i, name := range r.re.SubexpNames() {
		if i > 0 && i <= l {
			sub[name] = matches[i]
		}
	}
	return sub
}
