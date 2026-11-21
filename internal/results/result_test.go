package results

import "testing"

func TestParseSeverity(t *testing.T) {
	tests := map[string]Severity{
		"":              SeverityUnknown,
		"info":          SeverityInfo,
		"INFORMATIONAL": SeverityInfo,
		"low":           SeverityLow,
		"moderate":      SeverityMedium,
		"high":          SeverityHigh,
		"critical":      SeverityCritical,
	}
	for input, want := range tests {
		got, err := ParseSeverity(input)
		if err != nil || got != want {
			t.Errorf("%q: got %s, %v", input, got, err)
		}
	}
	if _, err := ParseSeverity("catastrophic"); err == nil {
		t.Fatal("expected invalid severity error")
	}
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Fatal("critical must rank above high")
	}
}

func TestFingerprintNormalizesText(t *testing.T) {
	first := Fingerprint("Nuclei", "vulnerability", "Example.com", "  SQL   Injection  ", "https://example.com/a")
	second := Fingerprint("nuclei", "VULNERABILITY", "example.com", "sql injection", "https://example.com/a")
	if first != second {
		t.Fatalf("fingerprints differ: %s != %s", first, second)
	}
	third := Fingerprint("nuclei", "vulnerability", "example.com", "XSS", "https://example.com/a")
	if first == third {
		t.Fatal("different titles produced the same fingerprint")
	}
	fourth := Fingerprint("nuclei", "vulnerability", "other.com", "sql injection", "https://example.com/a")
	if first == fourth {
		t.Fatal("different assets produced the same fingerprint")
	}
}

func TestNormalizeText(t *testing.T) {
	if got := NormalizeText("  A\tB\n C "); got != "a b c" {
		t.Fatalf("normalize = %q", got)
	}
}
