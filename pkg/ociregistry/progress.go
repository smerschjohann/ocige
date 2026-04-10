package ociregistry

import (
	"fmt"
	"io"
	"sync"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

type ProgressManager struct {
	p      *mpb.Progress
	silent bool
	bars   map[string]*mpb.Bar
	mu     sync.Mutex
}

func NewProgressManager(silent bool) *ProgressManager {
	var p *mpb.Progress
	if !silent {
		p = mpb.New()
	}
	return &ProgressManager{
		p:      p,
		silent: silent,
		bars:   make(map[string]*mpb.Bar),
	}
}

func (m *ProgressManager) Wait() {
	if m.p != nil {
		m.p.Wait()
	}
}

func (m *ProgressManager) AddBar(id string, total int64, label string) *mpb.Bar {
	if m.silent || m.p == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	bar := m.p.AddBar(total,
		mpb.PrependDecorators(
			decor.Name(label, decor.WC{W: len(label) + 1, C: decor.DindentRight}),
			decor.Counters(decor.SizeB1024(0), "% .2f / % .2f", decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_GO, 60),
			decor.Name(" ] "),
			decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncSpace),
		),
	)
	m.bars[id] = bar
	return bar
}

func (m *ProgressManager) TrackReader(id string, label string, total int64, r io.Reader) io.ReadCloser {
	if m.silent || m.p == nil {
		return io.NopCloser(r)
	}
	bar := m.AddBar(id, total, label)
	return bar.ProxyReader(r)
}

func (m *ProgressManager) Message(msg string) {
	if m.silent {
		return
	}
	if m.p != nil {
		fmt.Fprintln(m.p, msg)
	} else {
		fmt.Println(msg)
	}
}

func (m *ProgressManager) AbortAll() {
	if m.silent || m.p == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, bar := range m.bars {
		bar.Abort(false)
	}
}
