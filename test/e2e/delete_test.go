package e2e

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const deleteRegistryContainerName = "ocige-test-registry-delete"
const deleteRegistryPort = "5002"

// setupRegistryWithDeleteEnabled starts a registry that allows manifest and blob deletion.
func setupRegistryWithDeleteEnabled(t *testing.T) string {
	t.Helper()

	cmd := "podman"
	if _, err := exec.LookPath(cmd); err != nil {
		cmd = "docker"
	}

	_ = exec.Command(cmd, "stop", deleteRegistryContainerName).Run()
	_ = exec.Command(cmd, "rm", deleteRegistryContainerName).Run()

	runCmd := exec.Command(cmd, "run", "-d",
		"-p", deleteRegistryPort+":5000",
		"--name", deleteRegistryContainerName,
		"-e", "REGISTRY_STORAGE_DELETE_ENABLED=true",
		"registry:2")

	if err := runCmd.Run(); err != nil {
		t.Fatalf("Failed to start delete-enabled registry container: %v", err)
	}

	registryURL := fmt.Sprintf("http://localhost:%s/v2/", deleteRegistryPort)
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
		t.Fatal("Delete-enabled registry failed to become ready in time")
	}

	t.Cleanup(func() {
		_ = exec.Command(cmd, "stop", deleteRegistryContainerName).Run()
		_ = exec.Command(cmd, "rm", deleteRegistryContainerName).Run()
	})

	return fmt.Sprintf("localhost:%s", deleteRegistryPort)
}

func TestDeleteManifestE2E(t *testing.T) {
	registry := setupRegistryWithDeleteEnabled(t)

	tmpDir, err := os.MkdirTemp("", "ocige-e2e-delete-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	validRecipient := "age1pq17ffjcvhjhmzr5k0t3yr0vz2vzg6rgr76570jwurws3jy7z40a4qsjmmq9q32km800xpt5g23sl33xcsc9sn7zrksxsf6a6js6463ymqhd2nqswakr0py2ey9zgzmt8dtt0te5perge4h7z2vd7qtvvlznjk20020uw4hsunyvhwx09gmqruvy9wagwegjfynchmhdcafhckn9ze4ypyedwfu2r2jr9fqcs7r0zm06d2z4ap736x2ulsm29wg0vde4pnvtcjx0wer4qq3thgav4qk2dyy43etkeachv2z36dvcw3wxs228fq7vywf4xnph2rhk46q8y7ewpna8cv3hvkqfk20swcmwva7e4f52kmx63dvrj0qjwlt3xz4eduuxqf3zwngt2804tf3p9w7gcj4ld9v02ss9azkvjlndrrfp2c4fepn4aksqwcty6aq9wva39my52v9pefnzkrun9f26dw0u3szfwruq79j0032g3uq7h9n8xzxr2g8fmxvxl8aypcjjy38myjcc0crxhx6zsnyzn6rvv6xmdgzfp7xjnrupfsp8yyzqjvuyagcknp8c595wtw598mjsfskxgwdw9ntyanheag2z0epxgyxzrpxw8dxk2fk3u6j4xhj7y56nxalqpvn0trts4p5eg3u4zzcqmpeukdymkhfq5nej6g0dw4jvfkrtfr3wdjsyaq2f3ujk6dl49dmperut2wtfhf0v45s4rr30lq7u0zkunquy3lnk0nahw4vykm80f6pw2xh906tvtxr8z2sj7svlnvqxxqu0j73vt3yq2emmzsy98c8c4z2fm5skzc5f97kq2cxppxquwmvdjdx5g6lgsynk7m7nexttx4rsv6hcm3fpqse09v9rtcmncq84xg89xxjttyrxj9zfwftn26sj30c29ckg4sjly4e669cdkhpdzrpgrmjrssmfpatqnmrsdgmpg7u0fsgce7gx3jhshwvfnd9tfcx5988nwnahvxrdf96ufuut0fgkh7y9x4etukfpecsdtxgvxzr402ykasvkt9nacdgn748ruyaeze6uc2zn4aumkq6ex4vrke7n9vs7ylr0356yhgzeln2s4aakdf3v3jkw3k9smy8hptmjtjl25jhudzkrn969vd9yhwkszantt36dydgc25634nj4dtrpjqjc99x6u7rna4w5ltq040gzukxtnsy58y8djg3y72rhuyzc33uqvfy4ryq625052yuh2hch8lcrfkvzcvjzpsjzvay4t08vyrny83s8vvdc8ym3vwy6tvs3n57jyuryesqnsxqt6fe63qnv9garz5umz0dhugy3u423tv5qc0uqgm82ulxjumpl5k8xths2g0m8dyy6pkgevvusetefmcvhz0uvlfrxj74d9suyv3ke3xz4lfssepp3ja7l5pvqwfsxdf6jqafvnxfxggg87exw3v2kck53dwvqap4ka4z94mqjjzf8g25nklqcw7d8gcpyugdmvssrgrqkf6kjer04xdvml9aqe5vja7eq3g7s2c2ew3aru6thwypwfh3qzmtwzk0fp46wdzuulgj0xcnjrydkwl2yc3ane3u62pxymnsdc3ysx4ctz0gquasr2ryufds26fs3sgsnz9gse2dmdj65c38saqcsq35gfq54y2n04zvnfsrre5fs60e2uesvg9ruz38533989u3fvpwaf9pjsrznrkymamzf9ampq7gqwehcxj7ywun9u2qjmdg8n76gp46aqzzc643lyvtwrvf26q9yj9a3vcjz0qpvuectwm8xf0yevgjal9fzutn6gttpwugrr595fwy692qnwsl6jx8r287lz7xn9gmc2xmkcm4nzt0nrx94l3np5e7fg7jfcx755fjt8pfqlvpy7aja5f6hu9muxd8yl27h8954zk5k5s3x58rzmf0"
	validIdentity := "AGE-SECRET-KEY-PQ-1C6VXJNRF5Y9WCX0QCQYN75DR8VX5W23PXJ3X680LKZS33929ZD4QA3CH6P"

	keyFile := filepath.Join(tmpDir, "key.txt")
	recipientFile := filepath.Join(tmpDir, "recipient.txt")
	if err := os.WriteFile(keyFile, []byte(validIdentity), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recipientFile, []byte(validRecipient), 0644); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(tmpDir, "hello.txt")
	if err := os.WriteFile(testFile, []byte("hello delete test"), 0644); err != nil {
		t.Fatal(err)
	}

	targetURL := fmt.Sprintf("%s/test/delete-manifest:latest", registry)

	t.Run("DeleteManifestOnly", func(t *testing.T) {
		// Push the artifact
		runOcige(t, "push", "--recipients", recipientFile, "--insecure", targetURL, testFile)

		// Verify it is accessible before deletion
		outDir := filepath.Join(tmpDir, "extracted_before_delete")
		runOcige(t, "pull", "--identity", keyFile, "--insecure", "--output", outDir, targetURL)
		verifyFileContent(t, filepath.Join(outDir, "hello.txt"), []byte("hello delete test"))

		// Delete the manifest
		runOcige(t, "delete", "--insecure", targetURL)

		// Verify pull now fails (manifest is gone)
		runOcigeExpectError(t, "pull", "--identity", keyFile, "--insecure", "--output", filepath.Join(tmpDir, "extracted_after_delete"), targetURL)
	})

	t.Run("DeleteManifestWithBlobs", func(t *testing.T) {
		blobsTarget := fmt.Sprintf("%s/test/delete-blobs:latest", registry)

		// Push the artifact
		runOcige(t, "push", "--recipients", recipientFile, "--insecure", blobsTarget, testFile)

		// Delete manifest and all blobs
		runOcige(t, "delete", "--blobs", "--insecure", blobsTarget)

		// Verify pull now fails
		runOcigeExpectError(t, "pull", "--identity", keyFile, "--insecure", "--output", filepath.Join(tmpDir, "extracted_after_blobs_delete"), blobsTarget)
	})

	t.Run("DeleteNonExistentFails", func(t *testing.T) {
		nonExistentTarget := fmt.Sprintf("%s/test/does-not-exist:latest", registry)
		runOcigeExpectError(t, "delete", "--insecure", nonExistentTarget)
	})
}
