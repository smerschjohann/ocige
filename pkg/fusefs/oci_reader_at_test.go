package fusefs

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOCIReaderAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oci-reader-at-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	header := []byte("HEADER")
	chunk1Data := []byte("CHUNK1_DATA")
	chunk2Data := []byte("CHUNK2")

	path1 := filepath.Join(tempDir, "chunk1")
	path2 := filepath.Join(tempDir, "chunk2")

	os.WriteFile(path1, chunk1Data, 0644)
	os.WriteFile(path2, chunk2Data, 0644)

	slot1 := newChunkSlot()
	slot2 := newChunkSlot()

	var prefetchIdx int
	var prefetchMu sync.Mutex
	prefetcher := func(idx int) {
		prefetchMu.Lock()
		prefetchIdx = idx
		prefetchMu.Unlock()
	}

	sizes := []int64{int64(len(chunk1Data)), int64(len(chunk2Data))}
	reader := NewOCIReaderAtAsync(header, []*chunkSlot{slot1, slot2}, sizes, prefetcher)

	// Resolve slots
	slot1.resolve(path1, int64(len(chunk1Data)), nil)
	slot2.resolve(path2, int64(len(chunk2Data)), nil)

	// Test case 1: Read from header
	buf := make([]byte, 3)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || string(buf) != "HEA" {
		t.Errorf("Read 1 failed: got %q", string(buf))
	}

	// Test case 2: Read across header-chunk boundary
	buf = make([]byte, 10)
	n, err = reader.ReadAt(buf, 4) // "ER" + "CHUNK1_DA"
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 || string(buf) != "ERCHUNK1_D" {
		t.Errorf("Read 2 failed: got %q", string(buf))
	}

	// Test case 3: Read across chunk1-chunk2 boundary
	// chunk1 starts at 6, len 11 -> ends at 17
	buf = make([]byte, 5)
	n, err = reader.ReadAt(buf, 15) // last 2 of chunk1 ("TA") + first 3 of chunk2 ("CHU")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf) != "TACHU" {
		t.Errorf("Read 3 failed: got %q", string(buf))
	}

	// Test case 4: EOF
	buf = make([]byte, 10)
	n, err = reader.ReadAt(buf, int64(len(header)+len(chunk1Data)+len(chunk2Data))-2)
	if err != io.EOF && err != nil {
		t.Fatalf("Expected EOF or nil, got %v", err)
	}
	if n != 2 || string(buf[:n]) != "K2" {
		t.Errorf("Read 4 failed: got %q", string(buf[:n]))
	}

	// Test case 5: Prefetcher
	// Read near end of chunk 1
	buf = make([]byte, 1)
	_, _ = reader.ReadAt(buf, 16) // offset 16 is in chunk 1 (starts at 6, len 11)
	// local offset in chunk 1 is 16-6 = 10. Chunk 1 size is 11. 10 > 11*3/4 (8.25)
	prefetchMu.Lock()
	pIdx := prefetchIdx
	prefetchMu.Unlock()
	if pIdx != 1 {
		t.Errorf("Prefetcher not triggered: got %d", pIdx)
	}
}

func TestOCIReaderAt_Blocking(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oci-reader-at-blocking-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	header := []byte("H")
	slot := newChunkSlot()
	reader := NewOCIReaderAtAsync(header, []*chunkSlot{slot}, []int64{5}, nil)

	data := []byte("WORLD")
	path := filepath.Join(tempDir, "world")
	os.WriteFile(path, data, 0644)

	var wg sync.WaitGroup
	wg.Add(1)
	var readN int
	var readErr error
	var readBuf = make([]byte, 5)

	go func() {
		defer wg.Done()
		readN, readErr = reader.ReadAt(readBuf, 1)
	}()

	// Sleep slightly to ensure wait() is called
	// (Not foolproof but good for basic check)
	slot.resolve(path, 5, nil)
	wg.Wait()

	if readErr != nil {
		t.Fatal(readErr)
	}
	if readN != 5 || string(readBuf) != "WORLD" {
		t.Errorf("Blocking read failed: got %q", string(readBuf))
	}
}
