package version

import (
	"runtime"
	"testing"
)

func TestCurrent(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" || info.BuildDate == "" {
		t.Fatalf("incomplete build info: %+v", info)
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("go version = %s", info.GoVersion)
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("platform = %s/%s", info.OS, info.Arch)
	}
}
