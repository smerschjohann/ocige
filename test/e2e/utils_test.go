package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func runOcige(t *testing.T, args ...string) []byte {
	t.Helper()
	cmdArgs := append([]string{"run", "./cmd/ocige"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = "../.." // Run from root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ocige %v failed: %v\nOutput: %s", args, err, string(out))
	}
	return out
}

func runOcigeExpectError(t *testing.T, args ...string) []byte {
	t.Helper()
	cmdArgs := append([]string{"run", "./cmd/ocige"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = "../.." // Run from root
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("ocige %v succeeded but expected error\nOutput: %s", args, string(out))
	}
	return out
}

func runOcigeWithStdin(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()
	cmdArgs := append([]string{"run", "./cmd/ocige"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = "../.." // Run from root
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ocige %v failed: %v\nOutput: %s", args, err, string(out))
	}
	return out
}

func verifyFileContent(t *testing.T, path string, expected []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", path, err)
	}
	if !bytes.Equal(data, expected) {
		t.Errorf("Content mismatch for %s: expected %q, got %q", path, string(expected), string(data))
	}
}

func extractRecipient(t *testing.T, keyFile string) string {
	t.Helper()
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "# Public key: ") {
			return strings.TrimPrefix(l, "# Public key: ")
		}
	}
	t.Fatal("Could not find public key in keygen output")
	return ""
}
