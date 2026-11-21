package tools

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/execution"
)

// Detection status values.
const (
	DetectionInstalled    = "installed"
	DetectionMissing      = "missing"
	DetectionIncompatible = "incompatible"
	DetectionUnknown      = "unknown"
	DetectionError        = "error"
)

// Detection is the result of probing one tool.
type Detection struct {
	Name          string `json:"name"`
	Path          string `json:"path,omitempty"`
	Version       string `json:"version,omitempty"`
	Found         bool   `json:"found"`
	Status        string `json:"status"`
	Compatible    bool   `json:"compatible"`
	MinVersion    string `json:"min_version,omitempty"`
	TestedVersion string `json:"tested_version,omitempty"`
	Raw           string `json:"raw,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Detector probes installed tools through the execution engine, so version
// checks inherit timeouts, output limits and safe argv handling.
type Detector struct {
	runner      *execution.Runner
	timeout     time.Duration
	concurrency int
}

// NewDetector builds a detector. A zero timeout defaults to 5s and a zero
// concurrency defaults to 4.
func NewDetector(runner *execution.Runner, timeout time.Duration, concurrency int) (*Detector, error) {
	if runner == nil {
		return nil, fmt.Errorf("detector requires an execution runner")
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if timeout < 0 {
		return nil, fmt.Errorf("detector timeout cannot be negative")
	}
	if concurrency == 0 {
		concurrency = 4
	}
	if concurrency < 1 || concurrency > 64 {
		return nil, fmt.Errorf("detector concurrency must be between 1 and 64")
	}
	return &Detector{runner: runner, timeout: timeout, concurrency: concurrency}, nil
}

// Detect probes a single tool.
func (d *Detector) Detect(ctx context.Context, manifest Manifest) Detection {
	detection := Detection{
		Name:          manifest.Name,
		MinVersion:    manifest.MinVersion,
		TestedVersion: manifest.TestedVersion,
		Status:        DetectionMissing,
	}
	path, err := exec.LookPath(manifest.Binary)
	if err != nil {
		detection.Error = err.Error()
		return detection
	}
	detection.Found = true
	detection.Path = path

	request := execution.Request{
		Tool:    manifest.Name,
		Path:    path,
		Args:    manifest.VersionCheck.Args,
		Timeout: d.timeout,
	}
	if isExpectDenial(manifest.VersionCheck.AcceptExitCodes) {
		// Usage-only tools exit non-zero after printing their banner.
		request.ExpectedExitCodes = manifest.VersionCheck.AcceptExitCodes
	}
	result, err := d.runner.Run(ctx, request)
	if err != nil {
		detection.Status = DetectionError
		detection.Error = err.Error()
		return detection
	}
	output := strings.TrimSpace(result.StdoutPreview + "\n" + result.StderrPreview)
	if len(output) > 4000 {
		output = output[:4000]
	}
	detection.Raw = output
	// A version probe that prints a parseable version has answered the
	// question even if the tool exits non-zero (some tools reject extra
	// invocations or print usage). Only interruption or missing output is an
	// error.
	if version := manifest.VersionFromOutput(output); version != "" && result.Status != execution.StatusTimeout && result.Status != execution.StatusCanceled {
		compatible, err := CheckMinimum(version, manifest.MinVersion)
		if err != nil {
			detection.Status = DetectionUnknown
			detection.Version = version
			detection.Error = err.Error()
			return detection
		}
		detection.Version = version
		detection.Compatible = compatible
		if !compatible {
			detection.Status = DetectionIncompatible
			detection.Error = fmt.Sprintf("version %s is below required %s", version, manifest.MinVersion)
			return detection
		}
		detection.Status = DetectionInstalled
		return detection
	}
	if errors.Is(ctx.Err(), context.Canceled) || result.Status == execution.StatusTimeout || result.Status == execution.StatusCanceled {
		detection.Status = DetectionError
		detection.Error = result.Error
		return detection
	}

	version := manifest.VersionFromOutput(output)
	if version == "" {
		detection.Status = DetectionUnknown
		if manifest.MinVersion != "" {
			detection.Compatible = false
			detection.Error = "version output could not be parsed"
		} else {
			detection.Compatible = true
			detection.Error = "version output could not be parsed"
		}
		return detection
	}
	detection.Version = version
	compatible, err := CheckMinimum(version, manifest.MinVersion)
	if err != nil {
		detection.Status = DetectionUnknown
		detection.Error = err.Error()
		return detection
	}
	detection.Compatible = compatible
	if !compatible {
		detection.Status = DetectionIncompatible
		detection.Error = fmt.Sprintf("version %s is below required %s", version, manifest.MinVersion)
		return detection
	}
	detection.Status = DetectionInstalled
	return detection
}

// isExpectDenial reports whether the caller declared non-zero, successful
// exit codes for the probe.
func isExpectDenial(codes []int) bool {
	return len(codes) > 0
}

// DetectAll probes manifests concurrently while preserving input order.
func (d *Detector) DetectAll(ctx context.Context, manifests []Manifest) []Detection {
	detections := make([]Detection, len(manifests))
	sem := make(chan struct{}, d.concurrency)
	var wg sync.WaitGroup
	for i, manifest := range manifests {
		wg.Add(1)
		go func(index int, item Manifest) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				detections[index] = Detection{
					Name:   item.Name,
					Status: DetectionError,
					Error:  ctx.Err().Error(),
				}
				return
			}
			detections[index] = d.Detect(ctx, item)
		}(i, manifest)
	}
	wg.Wait()
	return detections
}
