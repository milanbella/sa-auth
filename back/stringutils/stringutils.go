package stringutils

import "strings"

// NullIfBlank returns nil when the provided value is empty after trimming
// whitespace; otherwise it returns the original string.
func NullIfBlank(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
