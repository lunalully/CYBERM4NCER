package tools

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var semverPattern = regexp.MustCompile(`(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][0-9a-z.-]+)?$`)

// SemVersion is a minimal semantic version used for compatibility checks.
// Prerelease/build metadata does not affect the comparison.
type SemVersion struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

// ParseSemVersion parses "1.2.3", "v1.2" and "1.2.3-dev".
func ParseSemVersion(value string) (SemVersion, bool) {
	match := semverPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return SemVersion{}, false
	}
	parts := [3]int{}
	for i := 1; i <= 3; i++ {
		if match[i] == "" {
			continue
		}
		parsed, err := strconv.Atoi(match[i])
		if err != nil {
			return SemVersion{}, false
		}
		parts[i-1] = parsed
	}
	return SemVersion{Major: parts[0], Minor: parts[1], Patch: parts[2], Raw: value}, true
}

// Compare returns -1, 0 or 1.
func (v SemVersion) Compare(other SemVersion) int {
	switch {
	case v.Major != other.Major:
		return compareInt(v.Major, other.Major)
	case v.Minor != other.Minor:
		return compareInt(v.Minor, other.Minor)
	case v.Patch != other.Patch:
		return compareInt(v.Patch, other.Patch)
	default:
		return 0
	}
}

func (v SemVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// CheckMinimum reports whether version satisfies the minimum. An empty
// minimum is always satisfied.
func CheckMinimum(version, minimum string) (bool, error) {
	if strings.TrimSpace(minimum) == "" {
		return true, nil
	}
	parsedMin, ok := ParseSemVersion(minimum)
	if !ok {
		return false, fmt.Errorf("invalid minimum version %q", minimum)
	}
	parsedVersion, ok := ParseSemVersion(version)
	if !ok {
		return false, fmt.Errorf("invalid tool version %q", version)
	}
	return parsedVersion.Compare(parsedMin) >= 0, nil
}
