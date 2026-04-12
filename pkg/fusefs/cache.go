package fusefs

import (
	"container/list"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DiskCache stores encrypted OCI chunks as files on disk.
type DiskCache struct {
	dir       string
	maxSize   int64
	mu        sync.Mutex
	entries   map[string]*cacheEntry
	lru       *list.List
	current   int64
	fetches   map[string]*fetchResult
	fetchesMu sync.Mutex
}

type cacheEntry struct {
	digest     string
	path       string
	size       int64
	lastAccess time.Time
	element    *list.Element
}

type fetchResult struct {
	once sync.Once
	path string
	err  error
}

// NewDiskCache creates a new or opens an existing DiskCache.
func NewDiskCache(dir string, maxSize int64) (*DiskCache, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	c := &DiskCache{
		dir:     dir,
		maxSize: maxSize,
		entries: make(map[string]*cacheEntry),
		lru:     list.New(),
		fetches: make(map[string]*fetchResult),
	}

	// Scan directory for existing entries
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to scan cache dir: %w", err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasPrefix(f.Name(), "sha256_") {
			continue
		}

		info, err := f.Info()
		if err != nil {
			continue
		}

		digest := strings.Replace(f.Name(), "_", ":", 1)
		path := filepath.Join(dir, f.Name())

		entry := &cacheEntry{
			digest:     digest,
			path:       path,
			size:       info.Size(),
			lastAccess: info.ModTime(),
		}
		entry.element = c.lru.PushBack(entry)
		c.entries[digest] = entry
		c.current += entry.size
	}

	// Evict if over size initially
	c.evict()

	return c, nil
}

// GetPath returns the path to a cached chunk if it exists.
func (c *DiskCache) GetPath(digest string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[digest]
	if !ok {
		return "", false
	}

	// Update LRU
	entry.lastAccess = time.Now()
	c.lru.MoveToBack(entry.element)
	return entry.path, true
}

// Put saves data under the given digest and returns the path.
func (c *DiskCache) Put(digest string, data []byte) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[digest]; ok {
		entry.lastAccess = time.Now()
		c.lru.MoveToBack(entry.element)
		return entry.path, nil
	}

	fileName := strings.Replace(digest, ":", "_", 1)
	path := filepath.Join(c.dir, fileName)

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write cache file: %w", err)
	}

	entry := &cacheEntry{
		digest:     digest,
		path:       path,
		size:       int64(len(data)),
		lastAccess: time.Now(),
	}
	entry.element = c.lru.PushBack(entry)
	c.entries[digest] = entry
	c.current += entry.size

	c.evict()

	return path, nil
}

// GetOrFetch atomically gets from cache or fetches using fetchFn.
func (c *DiskCache) GetOrFetch(digest string, fetchFn func() ([]byte, error)) (string, error) {
	if path, ok := c.GetPath(digest); ok {
		return path, nil
	}

	c.fetchesMu.Lock()
	res, ok := c.fetches[digest]
	if !ok {
		res = &fetchResult{}
		c.fetches[digest] = res
	}
	c.fetchesMu.Unlock()

	res.once.Do(func() {
		data, err := fetchFn()
		if err != nil {
			res.err = err
			return
		}
		res.path, res.err = c.Put(digest, data)
	})

	// Cleanup fetch result after completion to prevent leak
	// Note: Subsequent callers might still find it if they raced, but GetPath will catch them.
	if res.err == nil {
		c.fetchesMu.Lock()
		delete(c.fetches, digest)
		c.fetchesMu.Unlock()
	}

	return res.path, res.err
}

func (c *DiskCache) evict() {
	for c.current > c.maxSize && c.lru.Len() > 0 {
		el := c.lru.Front()
		entry := el.Value.(*cacheEntry)

		if err := os.Remove(entry.path); err == nil || os.IsNotExist(err) {
			delete(c.entries, entry.digest)
			c.lru.Remove(el)
			c.current -= entry.size
		} else {
			// If we can't remove it, we stop to avoid infinite loop
			break
		}
	}
}

// Delete removes a specific digest from the cache disk and state.
func (c *DiskCache) Delete(digest string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[digest]
	if !ok {
		return nil // Already gone
	}

	if err := os.Remove(entry.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file %s: %w", entry.path, err)
	}

	delete(c.entries, digest)
	c.lru.Remove(entry.element)
	c.current -= entry.size

	return nil
}

// Clear removes all cached files and resets the cache state.
func (c *DiskCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Remove files from disk
	files, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("failed to read cache dir: %w", err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		path := filepath.Join(c.dir, f.Name())
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove cache file %s: %w", path, err)
		}
	}

	// 2. Clear state
	c.entries = make(map[string]*cacheEntry)
	c.lru.Init()
	c.current = 0

	c.fetchesMu.Lock()
	c.fetches = make(map[string]*fetchResult)
	c.fetchesMu.Unlock()

	return nil
}

// Close is a no-op as the cache is persistent.
func (c *DiskCache) Close() error {
	return nil
}
