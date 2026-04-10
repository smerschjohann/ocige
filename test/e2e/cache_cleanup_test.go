package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheCleanupE2E(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); os.IsNotExist(err) {
		t.Skip("FUSE not available")
	}

	registry := setupRegistry(t)
	defer teardownRegistry(t)

	tmpDir, err := os.MkdirTemp("", "ocige-cache-cleanup-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Prepare files
	data1 := []byte("Large test file content to ensure multiple chunks if needed.")
	file1Path := filepath.Join(tmpDir, "file1.bin")
	os.WriteFile(file1Path, data1, 0644)

	// 2. Prepare keys
	recipient := "age1pq17ffjcvhjhmzr5k0t3yr0vz2vzg6rgr76570jwurws3jy7z40a4qsjmmq9q32km800xpt5g23sl33xcsc9sn7zrksxsf6a6js6463ymqhd2nqswakr0py2ey9zgzmt8dtt0te5perge4h7z2vd7qtvvlznjk20020uw4hsunyvhwx09gmqruvy9wagwegjfynchmhdcafhckn9ze4ypyedwfu2r2jr9fqcs7r0zm06d2z4ap736x2ulsm29wg0vde4pnvtcjx0wer4qq3thgav4qk2dyy43etkeachv2z36dvcw3wxs228fq7vywf4xnph2rhk46q8y7ewpna8cv3hvkqfk20swcmwva7e4f52kmx63dvrj0qjwlt3xz4eduuxqf3zwngt2804tf3p9w7gcj4ld9v02ss9azkvjlndrrfp2c4fepn4aksqwcty6aq9wva39my52v9pefnzkrun9f26dw0u3szfwruq79j0032g3uq7h9n8xzxr2g8fmxvxl8aypcjjy38myjcc0crxhx6zsnyzn6rvv6xmdgzfp7xjnrupfsp8yyzqjvuyagcknp8c595wtw598mjsfskxgwdw9ntyanheag2z0epxgyxzrpxw8dxk2fk3u6j4xhj7y56nxalqpvn0trts4p5eg3u4zzcqmpeukdymkhfq5nej6g0dw4jvfkrtfr3wdjsyaq2f3ujk6dl49dmperut2wtfhf0v45s4rr30lq7u0zkunquy3lnk0nahw4vykm80f6pw2xh906tvtxr8z2sj7svlnvqxxqu0j73vt3yq2emmzsy98c8c4z2fm5skzc5f97kq2cxppxquwmvdjdx5g6lgsynk7m7nexttx4rsv6hcm3fpqse09v9rtcmncq84xg89xxjttyrxj9zfwftn26sj30c29ckg4sjly4e669cdkhpdzrpgrmjrssmfpatqnmrsdgmpg7u0fsgce7gx3jhshwvfnd9tfcx5988nwnahvxrdf96ufuut0fgkh7y9x4etukfpecsdtxgvxzr402ykasvkt9nacdgn748ruyaeze6uc2zn4aumkq6ex4vrke7n9vs7ylr0356yhgzeln2s4aakdf3v3jkw3k9smy8hptmjtjl25jhudzkrn969vd9yhwkszantt36dydgc25634nj4dtrpjqjc99x6u7rna4w5ltq040gzukxtnsy58y8djg3y72rhuyzc33uqvfy4ryq625052yuh2hch8lcrfkvzcvjzpsjzvay4t08vyrny83s8vvdc8ym3vwy6tvs3n57jyuryesqnsxqt6fe63qnv9garz5umz0dhugy3u423tv5qc0uqgm82ulxjumpl5k8xths2g0m8dyy6pkgevvusetefmcvhz0uvlfrxj74d9suyv3ke3xz4lfssepp3ja7l5pvqwfsxdf6jqafvnxfxggg87exw3v2kck53dwvqap4ka4z94mqjjzf8g25nklqcw7d8gcpyugdmvssrgrqkf6kjer04xdvml9aqe5vja7eq3g7s2c2ew3aru6thwypwfh3qzmtwzk0fp46wdzuulgj0xcnjrydkwl2yc3ane3u62pxymnsdc3ysx4ctz0gquasr2ryufds26fs3sgsnz9gse2dmdj65c38saqcsq35gfq54y2n04zvnfsrre5fs60e2uesvg9ruz38533989u3fvpwaf9pjsrznrkymamzf9ampq7gqwehcxj7ywun9u2qjmdg8n76gp46aqzzc643lyvtwrvf26q9yj9a3vcjz0qpvuectwm8xf0yevgjal9fzutn6gttpwugrr595fwy692qnwsl6jx8r287lz7xn9gmc2xmkcm4nzt0nrx94l3np5e7fg7jfcx755fjt8pfqlvpy7aja5f6hu9muxd8yl27h8954zk5k5s3x58rzmf0"
	identity := "AGE-SECRET-KEY-PQ-1C6VXJNRF5Y9WCX0QCQYN75DR8VX5W23PXJ3X680LKZS33929ZD4QA3CH6P"
	keyFile := filepath.Join(tmpDir, "key.txt")
	os.WriteFile(keyFile, []byte(identity), 0600)
	recipientFile := filepath.Join(tmpDir, "recipient.txt")
	os.WriteFile(recipientFile, []byte(recipient), 0644)

	targetURL := fmt.Sprintf("%s/test/cache-cleanup:latest", registry)

	// 3. Push and Mount to populate cache
	mustRun(t, "../../", "go", "run", "./cmd/ocige", "push", "--recipients", recipientFile, "--insecure", targetURL, file1Path)

	mountPoint := filepath.Join(tmpDir, "mount")
	os.Mkdir(mountPoint, 0755)
	cacheDir := filepath.Join(tmpDir, "cache")
	chunksDir := filepath.Join(cacheDir, "chunks")

	mountCmd := exec.Command("go", "run", "./cmd/ocige", "mount", "--identity", keyFile, "--insecure", "--cache-dir", cacheDir, targetURL, mountPoint)
	mountCmd.Dir = "../../"
	if err := mountCmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Read file to ensure chunks are cached
	time.Sleep(2 * time.Second) // Wait for mount
	_, err = os.ReadFile(filepath.Join(mountPoint, "file1.bin"))
	if err != nil {
		t.Logf("Warning: Read failed (mount might not be ready yet): %v", err)
	}

	// Stop mount
	mountCmd.Process.Kill()
	mountCmd.Wait()
	exec.Command("umount", mountPoint).Run()

	// 4. Verify cache is NOT empty
	files, _ := os.ReadDir(chunksDir)
	if len(files) == 0 {
		t.Fatal("Cache should not be empty after read")
	}

	// 5. Run targeted cleanup
	mustRun(t, "../../", "go", "run", "./cmd/ocige", "cache", "cleanup", "--cache-dir", cacheDir, "--insecure", targetURL)

	// 6. Verify specific chunks are gone
	files, _ = os.ReadDir(chunksDir)
	if len(files) != 0 {
		t.Errorf("Cache should be empty after targeted cleanup, got %d files", len(files))
	}

	// 7. Populate again for global cleanup
	mustRun(t, "../../", "go", "run", "./cmd/ocige", "push", "--recipients", recipientFile, "--insecure", targetURL, file1Path)
	// (Simulate cache population manually for speed)
	os.MkdirAll(chunksDir, 0755)
	os.WriteFile(filepath.Join(chunksDir, "sha256_deadbeef"), []byte("data"), 0644)

	// 8. Run global cleanup
	mustRun(t, "../../", "go", "run", "./cmd/ocige", "cache", "cleanup", "--cache-dir", cacheDir)

	// 9. Verify global cleanup
	files, _ = os.ReadDir(chunksDir)
	if len(files) != 0 {
		t.Errorf("Cache should be empty after global cleanup, got %d files", len(files))
	}
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Command %s %v failed: %v\nOutput: %s", name, args, err, string(out))
	}
}
