package fusefs

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"ocige/pkg/ociregistry"
)

// VirtualRoot is the root node of the mounted filesystem.
type VirtualRoot struct {
	fs.Inode
	index   *ociregistry.Index
	fetcher *ChunkFetcher
}

// OnAdd is called when the FS is mounted. It builds the complete tree.
func (r *VirtualRoot) OnAdd(ctx context.Context) {
	for _, entry := range r.index.Files {
		r.addFile(ctx, entry)
	}
}

func (r *VirtualRoot) addFile(ctx context.Context, entry ociregistry.FileEntry) {
	dirPath, fileName := filepath.Split(entry.Path)
	dirPath = strings.Trim(dirPath, "/")

	// Traverse/build directory path
	curr := &r.Inode
	if dirPath != "" {
		segments := strings.Split(dirPath, "/")
		for _, seg := range segments {
			child := curr.GetChild(seg)
			if child == nil {
				// Create new directory
				dirNode := &VirtualDir{}
				child = curr.NewInode(ctx, dirNode, fs.StableAttr{Mode: syscall.S_IFDIR})
				curr.AddChild(seg, child, false)
			}
			curr = child
		}
	}

	// Create file node
	fileNode := &VirtualFile{
		entry:   entry,
		fetcher: r.fetcher,
	}
	child := curr.NewInode(ctx, fileNode, fs.StableAttr{Mode: syscall.S_IFREG})
	curr.AddChild(fileName, child, false)
}

// VirtualDir represents a directory in the virtual filesystem.
type VirtualDir struct {
	fs.Inode
}

func (d *VirtualDir) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0555 | syscall.S_IFDIR
	return fs.OK
}

// VirtualFile represents a file in the virtual filesystem.
type VirtualFile struct {
	fs.Inode
	entry   ociregistry.FileEntry
	fetcher *ChunkFetcher

	reader   *FileReaderAt
	readerMu sync.Mutex
}

func (f *VirtualFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0444 | syscall.S_IFREG
	out.Size = uint64(f.entry.Size)
	return fs.OK
}

func (f *VirtualFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// Enforce read-only
	if flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_APPEND|syscall.O_TRUNC) != 0 {
		return nil, 0, syscall.EROFS
	}

	f.readerMu.Lock()
	defer f.readerMu.Unlock()

	if f.reader == nil {
		reader, err := f.fetcher.OpenFile(ctx, f.entry)
		if err != nil {
			return nil, 0, syscall.EIO
		}
		f.reader = reader
	}

	// FOPEN_KEEP_CACHE: allow kernel to cache data.
	// This is safe since our files are read-only and immutable for the life of the mount.
	return nil, fuse.FOPEN_KEEP_CACHE, fs.OK
}

func (f *VirtualFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.readerMu.Lock()
	reader := f.reader
	f.readerMu.Unlock()

	if reader == nil {
		return nil, syscall.EIO
	}

	// We ReadAt directly into the dest slice if possible, or use a temp buffer
	// Plaintext.ReadAt doesn't guarantee filling the slice if EOF reached
	n, err := reader.Plaintext.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, syscall.EIO
	}

	return fuse.ReadResultData(dest[:n]), fs.OK
}
