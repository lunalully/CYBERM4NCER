package execution

// Status is the terminal or in-flight state of an execution.
type Status string

const (
	StatusRunning  Status = "running"
	StatusSuccess  Status = "success"
	StatusFailed   Status = "failed"
	StatusTimeout  Status = "timeout"
	StatusCanceled Status = "canceled"
	StatusError    Status = "error"
)

// Terminal reports whether the status represents a finished execution.
func (s Status) Terminal() bool {
	switch s {
	case StatusSuccess, StatusFailed, StatusTimeout, StatusCanceled, StatusError:
		return true
	default:
		return false
	}
}
