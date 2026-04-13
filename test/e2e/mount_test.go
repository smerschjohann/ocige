package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMountE2E(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); os.IsNotExist(err) {
		t.Skip("FUSE not available")
	}

	registry := setupRegistry(t)
	defer teardownRegistry(t)

	tmpDir, err := os.MkdirTemp("", "ocige-mount-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Prepare files
	data1 := []byte("This is file 1 content.")
	file1Path := filepath.Join(tmpDir, "file1.txt")
	os.WriteFile(file1Path, data1, 0644)

	subDir := filepath.Join(tmpDir, "subdir")
	os.Mkdir(subDir, 0755)
	data2 := []byte("Nested file content.")
	file2Path := filepath.Join(subDir, "file2.txt")
	os.WriteFile(file2Path, data2, 0644)

	// 2. Prepare keys
	recipient := "age1pq17ffjcvhjhmzr5k0t3yr0vz2vzg6rgr76570jwurws3jy7z40a4qsjmmq9q32km800xpt5g23sl33xcsc9sn7zrksxsf6a6js6463ymqhd2nqswakr0py2ey9zgzmt8dtt0te5perge4h7z2vd7qtvvlznjk20020uw4hsunyvhwx09gmqruvy9wagwegjfynchmhdcafhckn9ze4ypyedwfu2r2jr9fqcs7r0zm06d2z4ap736x2ulsm29wg0vde4pnvtcjx0wer4qq3thgav4qk2dyy43etkeachv2z36dvcw3wxs228fq7vywf4xnph2rhk46q8y7ewpna8cv3hvkqfk20swcmwva7e4f52kmx63dvrj0qjwlt3xz4eduuxqf3zwngt2804tf3p9w7gcj4ld9v02ss9azkvjlndrrfp2c4fepn4aksqwcty6aq9wva39my52v9pefnzkrun9f26dw0u3szfwruq79j0032g3uq7h9n8xzxr2g8fmxvxl8aypcjjy38myjcc0crxhx6zsnyzn6rvv6xmdgzfp7xjnrupfsp8yyzqjvuyagcknp8c595wtw598mjsfskxgwdw9ntyanheag2z0epxgyxzrpxw8dxk2fk3u6j4xhj7y56nxalqpvn0trts4p5eg3u4zzcqmpeukdymkhfq5nej6g0dw4jvfkrtfr3wdjsyaq2f3ujk6dl49dmperut2wtfhf0v45s4rr30lq7u0zkunquy3lnk0nahw4vykm80f6pw2xh906tvtxr8z2sj7svlnvqxxqu0j73vt3yq2emmzsy98c8c4z2fm5skzc5f97kq2cxppxquwmvdjdx5g6lgsynk7m7nexttx4rsv6hcm3fpqse09v9rtcmncq84xg89xxjttyrxj9zfwftn26sj30c29ckg4sjly4e669cdkhpdzrpgrmjrssmfpatqnmrsdgmpg7u0fsgce7gx3jhshwvfnd9tfcx5988nwnahvxrdf96ufuut0fgkh7y9x4etukfpecsdtxgvxzr402ykasvkt9nacdgn748ruyaeze6uc2zn4aumkq6ex4vrke7n9vs7ylr0356yhgzeln2s4aakdf3v3jkw3k9smy8hptmjtjl25jhudzkrn969vd9yhwkszantt36dydgc25634nj4dtrpjqjc99x6u7rna4w5ltq040gzukxtnsy58y8djg3y72rhuyzc33uqvfy4ryq625052yuh2hch8lcrfkvzcvjzpsjzvay4t08vyrny83s8vvdc8ym3vwy6tvs3n57jyuryesqnsxqt6fe63qnv9garz5umz0dhugy3u423tv5qc0uqgm82ulxjumpl5k8xths2g0m8dyy6pkgevvusetefmcvhz0uvlfrxj74d9suyv3ke3xz4lfssepp3ja7l5pvqwfsxdf6jqafvnxfxggg87exw3v2kck53dwvqap4ka4z94mqjjzf8g25nklqcw7d8gcpyugdmvssrgrqkf6kjer04xdvml9aqe5vja7eq3g7s2c2ew3aru6thwypwfh3qzmtwzk0fp46wdzuulgj0xcnjrydkwl2yc3ane3u62pxymnsdc3ysx4ctz0gquasr2ryufds26fs3sgsnz9gse2dmdj65c38saqcsq35gfq54y2n04zvnfsrre5fs60e2uesvg9ruz38533989u3fvpwaf9pjsrznrkymamzf9ampq7gqwehcxj7ywun9u2qjmdg8n76gp46aqzzc643lyvtwrvf26q9yj9a3vcjz0qpvuectwm8xf0yevgjal9fzutn6gttpwugrr595fwy692qnwsl6jx8r287lz7xn9gmc2xmkcm4nzt0nrx94l3np5e7fg7jfcx755fjt8pfqlvpy7aja5f6hu9muxd8yl27h8954zk5k5s3x58rzmf0"
	identity := "AGE-SECRET-KEY-PQ-1C6VXJNRF5Y9WCX0QCQYN75DR8VX5W23PXJ3X680LKZS33929ZD4QA3CH6P"
	keyFile := filepath.Join(tmpDir, "key.txt")
	os.WriteFile(keyFile, []byte(identity), 0600)
	recipientFile := filepath.Join(tmpDir, "recipient.txt")
	os.WriteFile(recipientFile, []byte(recipient), 0644)

	targetURL := fmt.Sprintf("%s/test/mount:latest", registry)

	// 3. Push data
	t.Logf("Pushing test data to %s...", targetURL)
	runOcige(t, "push", "--recipients", recipientFile, "--insecure", targetURL, file1Path, subDir)

	// 4. Start mount
	mountPoint := filepath.Join(tmpDir, "mount")
	os.Mkdir(mountPoint, 0755)
	cacheDir := filepath.Join(tmpDir, "cache")

	t.Logf("Starting mount at %s...", mountPoint)
	mountCmd := exec.Command("go", "run", "./cmd/ocige", "mount", "--identity", keyFile, "--insecure", "--cache-dir", cacheDir, targetURL, mountPoint)
	mountCmd.Dir = "../../"
	mountCmd.Stdout = os.Stdout
	mountCmd.Stderr = os.Stderr
	mountCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // Create a process group
	err = mountCmd.Start()
	if err != nil {
		t.Fatalf("Failed to start mount process: %v", err)
	}

	// Ensure cleanup
	defer func() {
		if mountCmd.Process != nil {
			t.Log("Cleaning up mount process...")
			// Send SIGINT to the entire process group
			syscall.Kill(-mountCmd.Process.Pid, syscall.SIGINT)

			// Poll for exit or force kill after timeout
			done := make(chan error, 1)
			go func() { done <- mountCmd.Wait() }()
			select {
			case <-done:
				t.Log("Mount process exited gracefully.")
			case <-time.After(5 * time.Second):
				t.Log("Mount process timed out, killing process group...")
				syscall.Kill(-mountCmd.Process.Pid, syscall.SIGKILL)
			}
		}
	}()

	// 5. Poll for mount availability
	t.Log("Waiting for mount to become ready...")
	ready := false
	for i := 0; i < 20; i++ {
		st, err := os.Stat(filepath.Join(mountPoint, "file1.txt"))
		if err == nil {
			t.Logf("Mount ready! file1.txt size: %d", st.Size())
			ready = true
			break
		}
		if i%5 == 0 {
			t.Logf("Still waiting for mount... (%d/20)", i)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Mount did not become ready in time")
	}

	// 6. Verify content
	t.Log("Verifying content...")
	verifyFileContent(t, filepath.Join(mountPoint, "file1.txt"), data1)
	verifyFileContent(t, filepath.Join(mountPoint, "subdir", "file2.txt"), data2)

	// 7. Test read-only
	t.Log("Verifying read-only enforcement...")
	err = os.WriteFile(filepath.Join(mountPoint, "new.txt"), []byte("fail"), 0644)
	if err == nil {
		t.Error("Should not be able to write to a read-only mount")
	} else {
		t.Logf("Correctly received error for write: %v", err)
	}

	// 8. Graceful shutdown (SIGINT)
	t.Log("Sending SIGINT to mount process group...")
	syscall.Kill(-mountCmd.Process.Pid, syscall.SIGINT)
	err = mountCmd.Wait()
	if err != nil {
		t.Logf("Mount process exited with error (expected SIGINT): %v", err)
	}
	t.Log("TestMountE2E completed successfully.")

	mountCmd.Process = nil // prevent double kill in defer
}
