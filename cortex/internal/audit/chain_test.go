package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChainVerifyAndTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	key := []byte("01234567890123456789012345678901")
	c, err := New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append("i1", "plan", map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.Append("i1", "execute", map[string]any{"x": 2}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, key); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	b[len(b)/2] ^= 1
	if err := os.WriteFile(path, b, 0640); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, key); err == nil {
		t.Fatal("tampering should fail verification")
	}
}
