package cli

import (
	"errors"
	"fmt"
)

// ExitError carries a process exit code through Cobra.
type ExitError struct {
	Code   int
	Err    error
	Silent bool
}

// Error implements error.
func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

// Unwrap supports errors.Is/As.
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode extracts an exit code from an error.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	return 1
}

func silentExit(code int) error {
	return &ExitError{Code: code, Silent: true}
}
