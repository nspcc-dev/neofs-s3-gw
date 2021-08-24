package auth

import "regexp"

type regexpSubmatcher struct {
	re *regexp.Regexp
}

func (r *regexpSubmatcher) getSubmatches(target string) map[string]string {
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
