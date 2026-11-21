package id

import (
	"regexp"
	"testing"
)

func TestNewFormatAndUniqueness(t *testing.T) {
	pattern := regexp.MustCompile(`^exec_[0-9a-f]{12}[0-9a-f]{16}$`)
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		value := New("exec")
		if !pattern.MatchString(value) {
			t.Fatalf("invalid id %q", value)
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate id %q", value)
		}
		seen[value] = struct{}{}
	}
}

func TestInvalidPrefixPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid prefix")
		}
	}()
	New("INVALID PREFIX")
}
