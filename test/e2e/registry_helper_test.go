package e2e

import (
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

const registryContainerName = "ocige-test-registry"
const registryPort = "5001"

func setupRegistry(t *testing.T) string {
	t.Helper()

	// Try podman first, then docker
	cmd := "podman"
	if _, err := exec.LookPath(cmd); err != nil {
		cmd = "docker"
	}

	// Stop/Remove existing container if any
	_ = exec.Command(cmd, "stop", registryContainerName).Run()
	_ = exec.Command(cmd, "rm", registryContainerName).Run()

	// Start registry
	runCmd := exec.Command(cmd, "run", "-d",
		"-p", registryPort+":5000",
		"--name", registryContainerName,
		"registry:2")

	if err := runCmd.Run(); err != nil {
		t.Fatalf("Failed to start registry container: %v", err)
	}

	// Wait for registry to be ready
	registryURL := fmt.Sprintf("http://localhost:%s/v2/", registryPort)
	ready := false
	for i := 0; i < 20; i++ {
		resp, err := http.Get(registryURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !ready {
		t.Fatal("Registry failed to become ready in time")
	}

	return fmt.Sprintf("localhost:%s", registryPort)
}

func teardownRegistry(t *testing.T) {
	t.Helper()

	cmd := "podman"
	if _, err := exec.LookPath(cmd); err != nil {
		cmd = "docker"
	}

	_ = exec.Command(cmd, "stop", registryContainerName).Run()
	_ = exec.Command(cmd, "rm", registryContainerName).Run()
}
