package e2e

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type corruptingResponseWriter struct {
	http.ResponseWriter
	corrupted bool
}

func (w *corruptingResponseWriter) Write(b []byte) (int, error) {
	if !w.corrupted && len(b) > 0 {
		b[0] ^= 0xFF // Flip bits of the first byte
		w.corrupted = true
	}
	return w.ResponseWriter.Write(b)
}

func TestPullerStabilityProxy(t *testing.T) {
	registry := setupRegistry(t)
	defer teardownRegistry(t)

	tmpDir, err := os.MkdirTemp("", "ocige-e2e-stability-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Prepare a 5MB multi-chunk file
	file1 := filepath.Join(tmpDir, "large_file.bin")
	data1 := make([]byte, 5*1024*1024)
	if _, err := rand.Read(data1); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file1, data1, 0644); err != nil {
		t.Fatal(err)
	}

	// Prepare keys
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

	targetURL := fmt.Sprintf("%s/test/stability:latest", registry)

	// Push the 5MB file with 1MB chunk size (so it creates 5 chunks)
	pushCmd := exec.Command("go", "run", "./cmd/ocige", "push",
		"--recipients", recipientFile,
		"--chunk-size", "1",
		"--insecure",
		targetURL,
		file1)
	pushCmd.Dir = "../../"
	if out, err := pushCmd.CombinedOutput(); err != nil {
		t.Fatalf("Push failed: %v\nOutput: %s", err, string(out))
	}

	// Create reverse proxy to introduce faults
	u, _ := url.Parse("http://" + registry)
	proxy := httputil.NewSingleHostReverseProxy(u)

	var blobGetCount int32
	var mode int32 // 0 = normal, 1 = delay, 2 = corrupt

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
			c := atomic.AddInt32(&blobGetCount, 1)
			m := atomic.LoadInt32(&mode)

			if m == 1 && c == 3 {
				// Delay the first file chunk request by 2 seconds
				// This forces one of the chunks to be slow, while others finish fast and get buffered
				time.Sleep(2 * time.Second)
			}

			if m == 2 && c >= 4 {
				// Corrupt all requests from 4 onwards to definitively exhaust retries
				cw := &corruptingResponseWriter{ResponseWriter: w}
				proxy.ServeHTTP(cw, r)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	})

	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()
	proxyHost := strings.TrimPrefix(proxyServer.URL, "http://")
	proxyURL := fmt.Sprintf("%s/test/stability:latest", proxyHost)

	t.Run("PullOutOfOrder", func(t *testing.T) {
		atomic.StoreInt32(&mode, 1) // Delay mode
		atomic.StoreInt32(&blobGetCount, 0)

		outDir := filepath.Join(tmpDir, "extracted_delay")
		pullCmd := exec.Command("go", "run", "./cmd/ocige", "pull",
			"--identity", keyFile,
			"--insecure",
			"--output", outDir,
			proxyURL)
		pullCmd.Dir = "../../"

		out, err := pullCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Pull failed on out-of-order chunks: %v\nOutput: %s", err, string(out))
		}

		verifyFile(t, filepath.Join(outDir, "large_file.bin"), data1)
	})

	t.Run("PullCorruption", func(t *testing.T) {
		atomic.StoreInt32(&mode, 2) // Corrupt mode
		atomic.StoreInt32(&blobGetCount, 0)

		outDir := filepath.Join(tmpDir, "extracted_corrupt")
		pullCmd := exec.Command("go", "run", "./cmd/ocige", "pull",
			"--identity", keyFile,
			"--insecure",
			"--output", outDir,
			proxyURL)
		pullCmd.Dir = "../../"

		out, err := pullCmd.CombinedOutput()
		if err == nil {
			t.Fatalf("Pull succeeded despite corruption! Output: %s", string(out))
		}

		if !strings.Contains(string(out), "failed to decrypt and authenticate") {
			t.Fatalf("Pull failed but didn't mention decryption failure: %s", string(out))
		}
	})
}
