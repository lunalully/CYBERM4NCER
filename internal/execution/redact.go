package execution

import (
	"regexp"
	"strings"
)

var (
	sensitiveFlag = regexp.MustCompile(`(?i)(password|passwd|passphrase|token|secret|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|cookie|authorization|bearer|session|credential)`)
	headerFlag    = regexp.MustCompile(`(?i)^(--?h|--header|--headers)$`)
	userInfo      = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)
	headerSecret  = regexp.MustCompile(`(?i)((?:authorization|cookie)\s*:\s*).+`)
	inlineSecret  = regexp.MustCompile(`(?i)((?:password|passwd|token|secret|api[-_]?key|access[-_]?key)\s*[=:]\s*)[^\s,;]+`)
)

// RedactArgs returns a copy safe for logs and database storage. The actual
// process arguments are never mutated.
//
// Values following credential flags, Authorization/Cookie headers, inline
// key=value secrets and URL userinfo are redacted.
func RedactArgs(args []string) []string {
	redacted := make([]string, 0, len(args))
	redactNext := false
	for _, arg := range args {
		if redactNext {
			redacted = append(redacted, "[REDACTED]")
			redactNext = false
			continue
		}
		if name, _, ok := strings.Cut(arg, "="); ok && isSensitiveFlag(name) {
			redacted = append(redacted, name+"=[REDACTED]")
			continue
		}
		if headerFlag.MatchString(arg) || isSensitiveFlag(arg) {
			redacted = append(redacted, arg)
			redactNext = true
			continue
		}
		value := userInfo.ReplaceAllString(arg, "${1}[REDACTED]@")
		value = headerSecret.ReplaceAllString(value, "${1}[REDACTED]")
		value = inlineSecret.ReplaceAllString(value, "${1}[REDACTED]")
		redacted = append(redacted, value)
	}
	return redacted
}

func isSensitiveFlag(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	if name == arg {
		return false
	}
	name = strings.TrimSpace(strings.SplitN(name, "=", 2)[0])
	return sensitiveFlag.MatchString(name)
}
