package auth

import "regexp"

type regexpSubmatcher struct {
	re *regexp.Regexp
}

func (resm *regexpSubmatcher) getSubmatches(target string) map[string]string {
	matches := resm.re.FindStringSubmatch(target)
	l := len(matches)
	submatches := make(map[string]string, l)
	for i, name := range resm.re.SubexpNames() {
		if i > 0 && i <= l {
			submatches[name] = matches[i]
		}
	}
	return submatches
}
