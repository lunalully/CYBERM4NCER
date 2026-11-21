//go:build !linux

package execution

import (
	"os"
	"os/exec"
)

func configureProcess(*exec.Cmd) {}

func killProcessGroup(process *os.Process) error {
	if process == nil {
		return nil
	}
	return process.Kill()
}
