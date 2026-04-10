package ageutils

import (
	"bytes"
	"io"
)

// HeaderExtractor wraps an io.Writer and intercepts the age header.
type HeaderExtractor struct {
	Target       io.Writer
	buf          bytes.Buffer
	headerFound  bool
	Header       []byte
}

func NewHeaderExtractor(target io.Writer) *HeaderExtractor {
	return &HeaderExtractor{
		Target: target,
	}
}

func (e *HeaderExtractor) Write(p []byte) (n int, err error) {
	if e.headerFound {
		return e.Target.Write(p)
	}

	// We are still looking for the header end.
	e.buf.Write(p)
	b := e.buf.Bytes()

	// The age header ends with "\n--- <MAC>\n"
	idx := bytes.Index(b, []byte("\n--- "))
	if idx != -1 {
		// Find the newline after the --- 
		headerEnd := idx + 1
		endOfLine := bytes.IndexByte(b[headerEnd:], '\n')
		if endOfLine != -1 {
			e.headerFound = true
			totalHeaderLen := headerEnd + endOfLine + 1
			e.Header = make([]byte, totalHeaderLen)
			copy(e.Header, b[:totalHeaderLen])

			// Flush remaining bytes to target
			remaining := b[totalHeaderLen:]
			if len(remaining) > 0 {
				nWritten, err := e.Target.Write(remaining)
				if err != nil {
					return len(p), err // standard io.Writer assumes len(p) or partial.
				}
				if nWritten != len(remaining) {
					return len(p), io.ErrShortWrite
				}
			}
			e.buf.Reset() // clear buffer
			return len(p), nil
		}
	}
	// Still haven't found the full header
	return len(p), nil
}
