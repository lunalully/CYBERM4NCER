// Package id generates short, time-sortable, prefixed identifiers.
//
// Identifiers have the form "<prefix>_<12 hex timestamp><16 hex random>".
// The timestamp component makes identifiers created in different
// milliseconds sort lexicographically, which keeps database listings and
// log correlation predictable without an external dependency.
package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,11}$`)

// New returns a new identifier for the given prefix.
func New(prefix string) string {
	if !prefixPattern.MatchString(prefix) {
		panic(fmt.Sprintf("id: invalid prefix %q", prefix))
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		// crypto/rand failure means the process cannot safely generate IDs.
		panic(fmt.Sprintf("id: random source failed: %v", err))
	}
	return fmt.Sprintf("%s_%012x%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(random[:]))
}
