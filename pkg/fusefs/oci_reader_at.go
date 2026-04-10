package fusefs

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// chunkSlot is a future for an OCI chunk on disk.
type chunkSlot struct {
	mu   sync.Mutex
	cond *sync.Cond
	path string
	size int64
	err  error
	done bool
}

func newChunkSlot() *chunkSlot {
	s := &chunkSlot{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *chunkSlot) resolve(path string, size int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	s.size = size
	s.err = err
	s.done = true
	s.cond.Broadcast()
}

func (s *chunkSlot) wait() (string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.done {
		s.cond.Wait()
	}
	return s.path, s.size, s.err
}

// OCIReaderAt implements io.ReaderAt over an Age header followed by OCI chunks.
type OCIReaderAt struct {
	header       []byte
	headerLen    int64
	slots        []*chunkSlot
	chunkOffsets []int64 // Start offset of each chunk relative to payload start
	chunkSizes   []int64
	total        int64
	prefetcher   func(chunkIdx int)
}

// NewOCIReaderAtAsync builds the virtual stream with pending chunk slots.
func NewOCIReaderAtAsync(header []byte, slots []*chunkSlot, chunkSizes []int64, prefetcher func(int)) *OCIReaderAt {
	offsets := make([]int64, len(chunkSizes))
	current := int64(0)
	for i, sz := range chunkSizes {
		offsets[i] = current
		current += sz
	}

	return &OCIReaderAt{
		header:       header,
		headerLen:    int64(len(header)),
		slots:        slots,
		chunkOffsets: offsets,
		chunkSizes:   chunkSizes,
		total:        int64(len(header)) + current,
		prefetcher:   prefetcher,
	}
}

func (r *OCIReaderAt) Size() int64 {
	return r.total
}

func (r *OCIReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.total {
		return 0, io.EOF
	}

	totalRead := 0
	remaining := int64(len(p))

	// Phase 1: Read from header
	if off < r.headerLen {
		n := copy(p, r.header[off:])
		totalRead += n
		off += int64(n)
		remaining -= int64(n)
		if remaining == 0 {
			return totalRead, nil
		}
	}

	// Phase 2: Read from OCI chunks
	payloadOff := off - r.headerLen
	for remaining > 0 && off < r.total {
		chunkIdx, localOff := r.resolveOffset(payloadOff)
		if chunkIdx < 0 || chunkIdx >= len(r.slots) {
			break
		}

		path, _, err := r.slots[chunkIdx].wait()
		if err != nil {
			return totalRead, fmt.Errorf("failed to wait for chunk %d: %w", chunkIdx, err)
		}

		chunkSize := r.chunkSizes[chunkIdx]

		// Prefetch hint
		if localOff > chunkSize*3/4 && chunkIdx+1 < len(r.slots) {
			if r.prefetcher != nil {
				r.prefetcher(chunkIdx + 1)
			}
		}

		toRead := min(remaining, chunkSize-localOff)
		f, err := os.Open(path)
		if err != nil {
			return totalRead, fmt.Errorf("failed to open chunk file %s: %w", path, err)
		}
		
		n, err := f.ReadAt(p[totalRead:totalRead+int(toRead)], localOff)
		f.Close()
		
		if n > 0 {
			totalRead += n
			off += int64(n)
			payloadOff += int64(n)
			remaining -= int64(n)
		}
		
		if err != nil && err != io.EOF {
			return totalRead, err
		}
		if (err == io.EOF || n == int(toRead)) && remaining > 0 {
			// Continue to next chunk
			continue
		}
		if remaining == 0 {
			return totalRead, nil
		}
	}

	if totalRead == 0 {
		return 0, io.EOF
	}
	return totalRead, nil
}

func (r *OCIReaderAt) resolveOffset(payloadOff int64) (int, int64) {
	// Simple linear search for now, given N is typically small (e.g. 100MB chunks for a few GB)
	// Can be optimized with binary search if needed.
	for i := len(r.chunkOffsets) - 1; i >= 0; i-- {
		if payloadOff >= r.chunkOffsets[i] {
			return i, payloadOff - r.chunkOffsets[i]
		}
	}
	return -1, -1
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
