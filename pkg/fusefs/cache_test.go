package fusefs

import (
	"os"
	"testing"
)

func TestDiskCache(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocige-cache-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	maxSize := int64(100) // 100 bytes
	cache, err := NewDiskCache(tempDir, maxSize)
	if err != nil {
		t.Fatal(err)
	}

	// Test Put and GetPath
	digest1 := "sha256:aaaa"
	data1 := []byte("hello world") // 11 bytes
	path1, err := cache.Put(digest1, data1)
	if err != nil {
		t.Fatal(err)
	}

	gotPath, ok := cache.GetPath(digest1)
	if !ok || gotPath != path1 {
		t.Errorf("GetPath failed: got %v, %v", gotPath, ok)
	}

	// Test GetOrFetch
	digest2 := "sha256:bbbb"
	data2 := []byte("foobar") // 6 bytes
	path2, err := cache.GetOrFetch(digest2, func() ([]byte, error) {
		return data2, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if path2 == "" {
		t.Error("GetOrFetch returned empty path")
	}

	// Test Eviction
	largeData := make([]byte, 90) // Total will be 11 + 6 + 90 = 107 > 100
	digest3 := "sha256:cccc"
	_, err = cache.Put(digest3, largeData)
	if err != nil {
		t.Fatal(err)
	}

	// digest1 should be evicted (least recently used)
	_, ok = cache.GetPath(digest1)
	if ok {
		t.Error("digest1 should have been evicted")
	}

	// digest2 and digest3 should still be there
	_, ok = cache.GetPath(digest2)
	if !ok {
		t.Error("digest2 should still be in cache")
	}

	// Test Delete
	err = cache.Delete(digest2)
	if err != nil {
		t.Fatal(err)
	}
	_, ok = cache.GetPath(digest2)
	if ok {
		t.Error("digest2 should have been deleted")
	}

	// Test Clear
	err = cache.Clear()
	if err != nil {
		t.Fatal(err)
	}
	if cache.current != 0 || len(cache.entries) != 0 || cache.lru.Len() != 0 {
		t.Error("Clear failed to reset state")
	}
	files, _ := os.ReadDir(tempDir)
	if len(files) != 0 {
		t.Error("Clear failed to remove files from disk")
	}
}
