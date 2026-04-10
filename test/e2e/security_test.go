package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNonPQKeyRejection(t *testing.T) {
	registry := setupRegistry(t)
	defer teardownRegistry(t)

	tmpDir, err := os.MkdirTemp("", "ocige-security-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("secret data"), 0644)

	// Standard X25519 keys (NOT PQ-safe)
	nonPQRecipient := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	nonPQIdentity := "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"

	recipientFile := filepath.Join(tmpDir, "bad_recipient.txt")
	identityFile := filepath.Join(tmpDir, "bad_identity.txt")
	os.WriteFile(recipientFile, []byte(nonPQRecipient), 0644)
	os.WriteFile(identityFile, []byte(nonPQIdentity), 0600)

	targetURL := fmt.Sprintf("%s/test/security-artifact:latest", registry)

	t.Run("PushWithNonPQRecipient", func(t *testing.T) {
		pushCmd := exec.Command("go", "run", "./cmd/ocige", "push", 
			"--recipients", recipientFile,
			"--insecure",
			targetURL,
			testFile)
		pushCmd.Dir = "../../"
		
		out, err := pushCmd.CombinedOutput()
		if err == nil {
			t.Fatal("Push should have failed with non-PQ recipient, but it succeeded")
		}

		fmt.Printf("Push output as expected: %s\n", string(out))
		if !strings.Contains(string(out), "non-PQ recipient found") {
			t.Errorf("Expected error message 'non-PQ recipient found', got: %s", string(out))
		}
	})

	t.Run("PullWithNonPQIdentity", func(t *testing.T) {
		// Even if push failed, we can try to pull (assuming some artifact exists or just for identity parsing)
		pullCmd := exec.Command("go", "run", "./cmd/ocige", "pull", 
			"--identity", identityFile,
			"--insecure",
			targetURL)
		pullCmd.Dir = "../../"
		
		out, err := pullCmd.CombinedOutput()
		if err == nil {
			t.Fatal("Pull should have failed with non-PQ identity, but it succeeded")
		}

		fmt.Printf("Pull output as expected: %s\n", string(out))
		if !strings.Contains(string(out), "non-PQ identity found") {
			t.Errorf("Expected error message 'non-PQ identity found', got: %s", string(out))
		}
	})
}
