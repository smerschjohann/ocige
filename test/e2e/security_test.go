package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityKeyValidation(t *testing.T) {
	registry := setupRegistry(t)
	defer teardownRegistry(t)

	tmpDir, err := os.MkdirTemp("", "ocige-security-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("secret data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Standard X25519 keys (NOT PQ-safe, should be blocked on PUSH)
	nonPQRecipient := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	nonPQIdentity := "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"

	// Plugin-style keys (allowed on PUSH/PULL because they MIGHT be PQ-safe)
	pluginRecipient := "age1fido217vll9sss4euqm" // Mock-style plugin address

	recipientFile := filepath.Join(tmpDir, "bad_recipient.txt")
	pluginRecipientFile := filepath.Join(tmpDir, "plugin_recipient.txt")
	identityFile := filepath.Join(tmpDir, "any_identity.txt")

	if err := os.WriteFile(recipientFile, []byte(nonPQRecipient), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pluginRecipientFile, []byte(pluginRecipient), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityFile, []byte(nonPQIdentity), 0600); err != nil {
		t.Fatal(err)
	}

	targetURL := fmt.Sprintf("%s/test/security-artifact:latest", registry)

	t.Run("PushWithNonPQRecipientRejection", func(t *testing.T) {
		out := runOcigeExpectError(t, "push",
			"--recipients", recipientFile,
			"--insecure",
			targetURL,
			testFile)

		if !strings.Contains(string(out), "non-PQ recipient found") {
			t.Errorf("Expected error message 'non-PQ recipient found', got: %s", string(out))
		}
	})

	t.Run("PushWithNonPQRecipientOverride", func(t *testing.T) {
		// Using the --allow-non-pq flag should bypass the check.
		out := runOcige(t, "push",
			"--recipients", recipientFile,
			"--allow-non-pq",
			"--insecure",
			targetURL,
			testFile)

		if strings.Contains(string(out), "non-PQ recipient found") {
			t.Errorf("Push was incorrectly blocked by PQ-check despite --allow-non-pq flag: %s", string(out))
		}
	})

	t.Run("PushWithPluginRecipientAcceptance", func(t *testing.T) {
		// This should fail for OTHER reasons (registry unreachable or something), 
		// but NOT because of key validation.
		// Since we want to test VALIDATION specifically, we check if the error is about the key.
		
		// It will likely fail with "age-plugin-fido2 not found" or something
		cmdArgs := []string{"push", "--recipients", pluginRecipientFile, "--insecure", targetURL, testFile}
		cmd := exec.Command("go", append([]string{"run", "./cmd/ocige"}, cmdArgs...)...)
		cmd.Dir = "../.."
		out, _ := cmd.CombinedOutput()

		// We expect a failure because age-plugin-fido2 is likely not in the test environment,
		// but it should NOT say "non-PQ recipient found".
		if strings.Contains(string(out), "non-PQ recipient found") {
			t.Errorf("Plugin recipient was incorrectly blocked by PQ-check: %s", string(out))
		}
	})

	t.Run("PullWithAnyIdentityAllowed", func(t *testing.T) {
		// Should NOT fail with "non-PQ identity found" anymore.
		cmdArgs := []string{"pull", "--identity", identityFile, "--insecure", targetURL}
		cmd := exec.Command("go", append([]string{"run", "./cmd/ocige"}, cmdArgs...)...)
		cmd.Dir = "../.."
		out, _ := cmd.CombinedOutput()

		if strings.Contains(string(out), "non-PQ identity found") {
			t.Errorf("Identity was incorrectly blocked by PQ-check: %s", string(out))
		}
	})
}
