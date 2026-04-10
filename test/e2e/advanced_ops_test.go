package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvancedOpsE2E(t *testing.T) {
	registry := setupRegistry(t)
	defer teardownRegistry(t)

	tmpDir, err := os.MkdirTemp("", "ocige-e2e-advanced-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Keys
	validRecipient := "age1pq17ffjcvhjhmzr5k0t3yr0vz2vzg6rgr76570jwurws3jy7z40a4qsjmmq9q32km800xpt5g23sl33xcsc9sn7zrksxsf6a6js6463ymqhd2nqswakr0py2ey9zgzmt8dtt0te5perge4h7z2vd7qtvvlznjk20020uw4hsunyvhwx09gmqruvy9wagwegjfynchmhdcafhckn9ze4ypyedwfu2r2jr9fqcs7r0zm06d2z4ap736x2ulsm29wg0vde4pnvtcjx0wer4qq3thgav4qk2dyy43etkeachv2z36dvcw3wxs228fq7vywf4xnph2rhk46q8y7ewpna8cv3hvkqfk20swcmwva7e4f52kmx63dvrj0qjwlt3xz4eduuxqf3zwngt2804tf3p9w7gcj4ld9v02ss9azkvjlndrrfp2c4fepn4aksqwcty6aq9wva39my52v9pefnzkrun9f26dw0u3szfwruq79j0032g3uq7h9n8xzxr2g8fmxvxl8aypcjjy38myjcc0crxhx6zsnyzn6rvv6xmdgzfp7xjnrupfsp8yyzqjvuyagcknp8c595wtw598mjsfskxgwdw9ntyanheag2z0epxgyxzrpxw8dxk2fk3u6j4xhj7y56nxalqpvn0trts4p5eg3u4zzcqmpeukdymkhfq5nej6g0dw4jvfkrtfr3wdjsyaq2f3ujk6dl49dmperut2wtfhf0v45s4rr30lq7u0zkunquy3lnk0nahw4vykm80f6pw2xh906tvtxr8z2sj7svlnvqxxqu0j73vt3yq2emmzsy98c8c4z2fm5skzc5f97kq2cxppxquwmvdjdx5g6lgsynk7m7nexttx4rsv6hcm3fpqse09v9rtcmncq84xg89xxjttyrxj9zfwftn26sj30c29ckg4sjly4e669cdkhpdzrpgrmjrssmfpatqnmrsdgmpg7u0fsgce7gx3jhshwvfnd9tfcx5988nwnahvxrdf96ufuut0fgkh7y9x4etukfpecsdtxgvxzr402ykasvkt9nacdgn748ruyaeze6uc2zn4aumkq6ex4vrke7n9vs7ylr0356yhgzeln2s4aakdf3v3jkw3k9smy8hptmjtjl25jhudzkrn969vd9yhwkszantt36dydgc25634nj4dtrpjqjc99x6u7rna4w5ltq040gzukxtnsy58y8djg3y72rhuyzc33uqvfy4ryq625052yuh2hch8lcrfkvzcvjzpsjzvay4t08vyrny83s8vvdc8ym3vwy6tvs3n57jyuryesqnsxqt6fe63qnv9garz5umz0dhugy3u423tv5qc0uqgm82ulxjumpl5k8xths2g0m8dyy6pkgevvusetefmcvhz0uvlfrxj74d9suyv3ke3xz4lfssepp3ja7l5pvqwfsxdf6jqafvnxfxggg87exw3v2kck53dwvqap4ka4z94mqjjzf8g25nklqcw7d8gcpyugdmvssrgrqkf6kjer04xdvml9aqe5vja7eq3g7s2c2ew3aru6thwypwfh3qzmtwzk0fp46wdzuulgj0xcnjrydkwl2yc3ane3u62pxymnsdc3ysx4ctz0gquasr2ryufds26fs3sgsnz9gse2dmdj65c38saqcsq35gfq54y2n04zvnfsrre5fs60e2uesvg9ruz38533989u3fvpwaf9pjsrznrkymamzf9ampq7gqwehcxj7ywun9u2qjmdg8n76gp46aqzzc643lyvtwrvf26q9yj9a3vcjz0qpvuectwm8xf0yevgjal9fzutn6gttpwugrr595fwy692qnwsl6jx8r287lz7xn9gmc2xmkcm4nzt0nrx94l3np5e7fg7jfcx755fjt8pfqlvpy7aja5f6hu9muxd8yl27h8954zk5k5s3x58rzmf0"
	validIdentity := "AGE-SECRET-KEY-PQ-1C6VXJNRF5Y9WCX0QCQYN75DR8VX5W23PXJ3X680LKZS33929ZD4QA3CH6P"

	keyFile := filepath.Join(tmpDir, "key.txt")
	recipientFile := filepath.Join(tmpDir, "recipient.txt")
	os.WriteFile(keyFile, []byte(validIdentity), 0600)
	os.WriteFile(recipientFile, []byte(validRecipient), 0644)

	targetURL := fmt.Sprintf("%s/test/advanced:latest", registry)

	var keyFiles []string

	// 1. Initial Push
	file1 := filepath.Join(tmpDir, "file1.txt")
	data1 := []byte("Initial data")
	os.WriteFile(file1, data1, 0644)

	t.Run("Append", func(t *testing.T) {
		// Push first file
		runOcige(t, "push", "--recipients", recipientFile, "--insecure", targetURL, file1)

		// Append second file
		file2 := filepath.Join(tmpDir, "file2.txt")
		data2 := []byte("Appended data")
		os.WriteFile(file2, data2, 0644)

		runOcige(t, "append", "--identity", keyFile, "--insecure", targetURL, file2)

		// Verify both exist
		outDir := filepath.Join(tmpDir, "extracted_append")
		runOcige(t, "pull", "--identity", keyFile, "--insecure", "--output", outDir, targetURL)
		verifyFileContent(t, filepath.Join(outDir, "file1.txt"), data1)
		verifyFileContent(t, filepath.Join(outDir, "file2.txt"), data2)
	})

	t.Run("AppendOverwrite", func(t *testing.T) {
		file1Updated := filepath.Join(tmpDir, "file1.txt")
		data1Updated := []byte("Updated initial data")
		os.WriteFile(file1Updated, data1Updated, 0644)

		// Should fail without force/overwrite (if we implement that check)
		// For now let's just test that --force works if we implement it.
		runOcige(t, "append", "--identity", keyFile, "--insecure", "--force", targetURL, file1Updated)

		outDir := filepath.Join(tmpDir, "extracted_overwrite")
		runOcige(t, "pull", "--identity", keyFile, "--insecure", "--output", outDir, targetURL)
		verifyFileContent(t, filepath.Join(outDir, "file1.txt"), data1Updated)
	})

	t.Run("Rekey", func(t *testing.T) {
		// 1. Generate new key
		key2File := filepath.Join(tmpDir, "key2.txt")
		recip2File := filepath.Join(tmpDir, "recip2.txt")
		
		runOcige(t, "keygen", "--output", key2File)
		// Extract recipient from keygen output file
		recip2 := extractRecipient(t, key2File)
		os.WriteFile(recip2File, []byte(recip2), 0644)

		// 2. Perform Rekey (Targeting 'latest' tag)
		runOcige(t, "rekey", "--identity", keyFile, "--insecure", targetURL, recip2File)

		// 3. Verify old key fails
		badPullCmd := exec.Command("go", "run", "cmd/ocige", "pull", "--identity", keyFile, "--insecure", targetURL)
		badPullCmd.Dir = "../.."
		if err := badPullCmd.Run(); err == nil {
			t.Errorf("Pull with OLD key should have failed after rekey")
		}

		// 4. Verify new key works
		outDir := filepath.Join(tmpDir, "extracted_rekey")
		runOcige(t, "pull", "--identity", key2File, "--insecure", "--output", outDir, targetURL)
		verifyFileContent(t, filepath.Join(outDir, "file1.txt"), []byte("Updated initial data"))
	})

	t.Run("MultiKeyRekey", func(t *testing.T) {
		// 1. Generate 3 keys
		var recipients []string

		for i := 1; i <= 3; i++ {
			k := filepath.Join(tmpDir, fmt.Sprintf("multi_key%d.txt", i))
			runOcige(t, "keygen", "-o", k)
			
			recip := extractRecipient(t, k)
			recipients = append(recipients, recip)
			keyFiles = append(keyFiles, k)
		}

		// Combined recipients file
		combinedRecipFile := filepath.Join(tmpDir, "combined_recips.txt")
		os.WriteFile(combinedRecipFile, []byte(strings.Join(recipients, "\n")), 0644)

		// 2. Perform Rekey for ALL 3 recipients
		// We use key2File from previous test as the 'current' valid identity
		key2File := filepath.Join(tmpDir, "key2.txt")
		runOcige(t, "rekey", "--identity", key2File, "--insecure", targetURL, combinedRecipFile)

		// 3. Verify ALL 3 keys can pull
		for i, kf := range keyFiles {
			outDir := filepath.Join(tmpDir, fmt.Sprintf("extracted_multi_%d", i))
			runOcige(t, "pull", "--identity", kf, "--insecure", "--output", outDir, targetURL)
			verifyFileContent(t, filepath.Join(outDir, "file1.txt"), []byte("Updated initial data"))
		}
	})

	t.Run("Remove", func(t *testing.T) {
		// Use one of the keys from MultiKeyRekey (which updated the artifact)
		validKF := keyFiles[0]
		runOcige(t, "remove", "--identity", validKF, "--insecure", targetURL, "file2.txt")

		// Verify file2 is gone, file1 remains
		outDir := filepath.Join(tmpDir, "extracted_remove")
		os.MkdirAll(outDir, 0755)
		runOcige(t, "pull", "--identity", validKF, "--insecure", "--output", outDir, targetURL)
		
		if _, err := os.Stat(filepath.Join(outDir, "file2.txt")); !os.IsNotExist(err) {
			t.Errorf("file2.txt should have been removed")
		}
		verifyFileContent(t, filepath.Join(outDir, "file1.txt"), []byte("Updated initial data"))
	})
}

func runOcige(t *testing.T, args ...string) {
	t.Helper()
	cmdArgs := append([]string{"run", "./cmd/ocige"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = "../.." // Run from root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ocige %v failed: %v\nOutput: %s", args, err, string(out))
	}
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
