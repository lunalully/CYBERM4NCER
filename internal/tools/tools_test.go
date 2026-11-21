package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/execution"
)

func TestSemVersion(t *testing.T) {
	tests := []struct {
		value string
		want  string
		ok    bool
	}{
		{"1.2.3", "1.2.3", true},
		{"v1.2.3", "1.2.3", true},
		{"1.2", "1.2.0", true},
		{"1", "1.0.0", true},
		{"2.1.0-dev", "2.1.0", true},
		{"3.6", "3.6.0", true},
		{"not-a-version", "", false},
		{"1.2.3.4", "", false},
	}
	for _, test := range tests {
		version, ok := ParseSemVersion(test.value)
		if ok != test.ok {
			t.Errorf("%s: ok=%t, want %t", test.value, ok, test.ok)
			continue
		}
		if ok && version.String() != test.want {
			t.Errorf("%s: got %s, want %s", test.value, version.String(), test.want)
		}
	}
}

func TestCheckMinimum(t *testing.T) {
	ok, err := CheckMinimum("3.11.1", "3.0.0")
	if err != nil || !ok {
		t.Fatalf("3.11.1 >= 3.0.0: ok=%t err=%v", ok, err)
	}
	ok, err = CheckMinimum("2.9.0", "3.0.0")
	if err != nil || ok {
		t.Fatalf("2.9.0 < 3.0.0: ok=%t err=%v", ok, err)
	}
	ok, err = CheckMinimum("anything", "")
	if err != nil || !ok {
		t.Fatalf("empty minimum: ok=%t err=%v", ok, err)
	}
}

func TestLoadEmbeddedRegistry(t *testing.T) {
	registry, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	manifests := registry.List()
	if len(manifests) < 15 {
		t.Fatalf("registry has %d manifests, expected at least 15", len(manifests))
	}
	for i := 1; i < len(manifests); i++ {
		if manifests[i-1].Name >= manifests[i].Name {
			t.Fatalf("manifests are not sorted: %s >= %s", manifests[i-1].Name, manifests[i].Name)
		}
	}
	for _, name := range []string{"subfinder", "httpx", "nuclei", "nmap", "sqlmap"} {
		if _, ok := registry.Get(name); !ok {
			t.Fatalf("missing manifest %s", name)
		}
	}
}

func TestEmbeddedInvocationsAreReviewed(t *testing.T) {
	registry, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	withInvocations := 0
	for _, manifest := range registry.List() {
		for _, invocation := range manifest.Invocations {
			withInvocations++
			for _, arg := range invocation.Args {
				if strings.TrimSpace(arg) == "" {
					t.Errorf("%s/%s: empty argument", manifest.Name, invocation.Name)
				}
				if strings.ContainsAny(arg, ";|&`$\n") && !strings.HasPrefix(arg, "{{") {
					t.Errorf("%s/%s: argument %q looks like shell syntax", manifest.Name, invocation.Name, arg)
				}
			}
			if invocation.Mode == "credential" {
				hasWordlist := false
				for _, option := range invocation.Options {
					if option.Name == "userlist" || option.Name == "passlist" || option.Name == "wordlist" {
						hasWordlist = true
					}
				}
				if !hasWordlist {
					t.Errorf("%s/%s: credential invocation must require wordlists", manifest.Name, invocation.Name)
				}
			}
			if invocation.UsesCapturedPorts && len(manifest.Usage.DefaultPorts) == 0 {
				t.Errorf("%s/%s: uses captured ports but declares no default ports", manifest.Name, invocation.Name)
			}
		}
	}
	if withInvocations < 20 {
		t.Fatalf("only %d invocations reviewed", withInvocations)
	}
}

func TestAggressiveToolsCoverRequestedSet(t *testing.T) {
	registry, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"wafw00f", "telnet", "nc", "hydra", "medusa", "masscan", "rustscan",
		"nmap", "naabu", "ffuf", "gobuster", "feroxbuster", "dirb", "nuclei",
		"sqlmap", "nikto", "sslscan", "testssl", "katana", "httpx", "whatweb",
		"nxc", "enum4linux-ng", "dalfox", "arjun", "dirsearch", "wpscan",
	}
	for _, name := range required {
		manifest, ok := registry.Get(name)
		if !ok {
			t.Errorf("missing manifest %s", name)
			continue
		}
		if len(manifest.Invocations) == 0 {
			t.Errorf("%s has no invocations", name)
		}
	}
}

func TestManifestValidation(t *testing.T) {
	valid := fakeManifest("valid")
	valid.Homepage = "http://insecure.example.com"
	if err := valid.Compile(); err == nil {
		t.Fatal("expected homepage validation error")
	}

	valid = fakeManifest("valid")
	valid.VersionCheck.Regex = "("
	if err := valid.Compile(); err == nil {
		t.Fatal("expected regex validation error")
	}

	valid = fakeManifest("valid")
	valid.Install = nil
	if err := valid.Compile(); err == nil {
		t.Fatal("expected install validation error")
	}
}

func fakeManifest(name string) Manifest {
	return Manifest{
		Name:          name,
		Description:   "Test tool",
		Category:      "recon",
		Homepage:      "https://example.com",
		Documentation: "https://example.com/docs",
		License:       "MIT",
		Binary:        "sh",
		MinVersion:    "1.0.0",
		Architectures: []string{"any"},
		Risk:          "low",
		Capabilities:  []string{"test"},
		Outputs:       []string{"text"},
		VersionCheck:  VersionCheck{Args: []string{"-c", "printf 'fake 1.2.3'"}, Regex: `fake\s+([0-9.]+)`},
		Install:       []InstallMethod{{Method: "manual"}},
	}
}

func newTestDetector(t *testing.T) *Detector {
	t.Helper()
	runner, err := execution.New(execution.Options{
		Workers:   2,
		Artifacts: execution.DiscardArtifacts{},
		Recorder:  execution.NoopRecorder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := NewDetector(runner, 2*time.Second, 2)
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func TestDetectInstalled(t *testing.T) {
	manifest := fakeManifest("fake")
	if err := manifest.Compile(); err != nil {
		t.Fatal(err)
	}
	detection := newTestDetector(t).Detect(context.Background(), manifest)
	if detection.Status != DetectionInstalled || detection.Version != "1.2.3" || !detection.Compatible {
		t.Fatalf("detection = %+v", detection)
	}
	if detection.Path == "" {
		t.Fatal("path not resolved")
	}
}

func TestDetectIncompatible(t *testing.T) {
	manifest := fakeManifest("fake")
	manifest.MinVersion = "9.0.0"
	if err := manifest.Compile(); err != nil {
		t.Fatal(err)
	}
	detection := newTestDetector(t).Detect(context.Background(), manifest)
	if detection.Status != DetectionIncompatible || detection.Compatible {
		t.Fatalf("detection = %+v", detection)
	}
}

func TestDetectMissing(t *testing.T) {
	manifest := fakeManifest("fake")
	manifest.Binary = "cyberm4ncer-binary-that-does-not-exist"
	if err := manifest.Compile(); err != nil {
		t.Fatal(err)
	}
	detection := newTestDetector(t).Detect(context.Background(), manifest)
	if detection.Status != DetectionMissing || detection.Found {
		t.Fatalf("detection = %+v", detection)
	}
}

func TestDetectUnknownVersion(t *testing.T) {
	manifest := fakeManifest("fake")
	manifest.VersionCheck.Args = []string{"-c", "printf 'no version here'"}
	if err := manifest.Compile(); err != nil {
		t.Fatal(err)
	}
	detection := newTestDetector(t).Detect(context.Background(), manifest)
	if detection.Status != DetectionUnknown || detection.Compatible {
		t.Fatalf("detection = %+v", detection)
	}
}

func TestDetectAllPreservesOrder(t *testing.T) {
	first := fakeManifest("first")
	second := fakeManifest("second")
	if err := first.Compile(); err != nil {
		t.Fatal(err)
	}
	if err := second.Compile(); err != nil {
		t.Fatal(err)
	}
	detections := newTestDetector(t).DetectAll(context.Background(), []Manifest{first, second})
	if len(detections) != 2 || detections[0].Name != "first" || detections[1].Name != "second" {
		t.Fatalf("detections = %+v", detections)
	}
}
