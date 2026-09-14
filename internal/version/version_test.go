package version

import (
	"os"
	"strings"
	"testing"
)

func TestVersionMatchesBuildSource(t *testing.T) {
	b, e := os.ReadFile("../../VERSION")
	if e != nil {
		t.Fatal(e)
	}
	if Version != strings.TrimSpace(string(b)) {
		t.Fatalf("fallback version %s differs from VERSION", Version)
	}
}
