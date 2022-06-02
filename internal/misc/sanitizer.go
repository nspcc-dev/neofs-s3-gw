package misc

import "strings"

// SanitizeString sanitizes string before using it in logs. Required
// for data from the user input: request body, headers, etc.
func SanitizeString(s string) string {
	return strings.Replace(s, "\n", "", -1)
}
