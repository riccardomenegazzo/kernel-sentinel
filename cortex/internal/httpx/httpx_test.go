package httpx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretPrecedence(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "s")
	_ = os.WriteFile(p, []byte("file-token\n"), 0600)
	_ = os.Setenv("X_TOKEN", "env-token")
	v, e := Secret("direct", "X_TOKEN", p)
	if e != nil || v != "file-token" {
		t.Fatalf("%q %v", v, e)
	}
	v, e = Secret("direct", "X_TOKEN", "")
	if e != nil || v != "env-token" {
		t.Fatalf("%q %v", v, e)
	}
}
