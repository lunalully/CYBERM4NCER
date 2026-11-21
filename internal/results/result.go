// Package results defines the normalized finding model shared by all
// modules. Tool-specific parsers land in Phase 4; the model and
// deduplication fingerprint are defined here so adapters agree on shape.
package results

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Severity is the normalized finding severity.
type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ParseSeverity normalizes a severity string.
func ParseSeverity(value string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown":
		return SeverityUnknown, nil
	case "info", "informational":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "moderate":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityUnknown, fmt.Errorf("invalid severity %q", value)
	}
}

// Rank orders severities from least to most severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Result is the standard internal finding representation.
type Result struct {
	ID          string         `json:"id"`
	ProjectID   string         `json:"project_id,omitempty"`
	OperationID string         `json:"operation_id,omitempty"`
	ExecutionID string         `json:"execution_id,omitempty"`
	Asset       string         `json:"asset"`
	Kind        string         `json:"kind"`
	Source      string         `json:"source"`
	Tool        string         `json:"tool"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	References  []string       `json:"references,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
	Fingerprint string         `json:"fingerprint"`
	Validated   bool           `json:"validated"`
	CreatedAt   time.Time      `json:"created_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
}

// Fingerprint identifies a finding for deduplication. Evidence is
// intentionally excluded so repeated scans converge while distinct
// occurrences remain representable through separate evidence records.
func Fingerprint(tool, kind, asset, title, location string) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(tool)),
		strings.ToLower(strings.TrimSpace(kind)),
		strings.ToLower(strings.TrimSpace(asset)),
		NormalizeText(title),
		strings.TrimSpace(location),
	}
	digest := sha256.New()
	for _, part := range parts {
		_, _ = digest.Write([]byte(part))
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// NormalizeText collapses whitespace and lowercases a title for stable
// comparison.
func NormalizeText(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}
