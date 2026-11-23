package vfs

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// Fileread opens a file for reading. The file is stat'ed first so a missing
// path, a directory or a virtual node fails at open with the right status.
// The transfer slot taken here is released by Close.
func (f *FS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	ctx := r.Context()
	loc, err := f.resolve(ctx, r.Filepath)
	if err != nil {
		return nil, err
	}
	if loc.virtual() {
		return nil, failure("is a directory")
	}
	release, ok := f.limiter.Acquire(f.user)
	if !ok {
		return nil, failure("too many concurrent transfers")
	}
	files := f.filesFor(loc)
	e, err := files.Stat(ctx, loc.rest)
	if err != nil {
		release()
		return nil, f.fail("read stat", err)
	}
	if e.Dir {
		release()
		return nil, failure("is a directory")
	}
	return &readerAt{
		ctx:     ctx,
		fs:      f,
		files:   files,
		path:    loc.rest,
		size:    e.Size,
		release: release,
	}, nil
}

// readerAt serves ReadAt over one streamed download. Contiguous reads reuse
// the open body. A read at any other offset reopens the download there with
// a Range request. The file is never buffered whole.
type readerAt struct {
	ctx     context.Context
	fs      *FS
	files   *apiclient.Files
	path    string
	size    int64 // size at open; the stream is not reopened past it
	release func()

	mu        sync.Mutex // guards the fields below and serialises reads
	cur       io.ReadCloser
	pos       int64 // offset the next byte of cur comes from
	closed    bool
	held      []heldRange // bytes read past while jumping ahead, for late reads
	heldBytes int
}

// Limits for pipelined reads. pkg/sftp handles read packets on a pool of
// workers, so a client's sequential reads can arrive slightly out of order.
// A read a short way ahead of the stream skips forward and keeps the skipped
// bytes, so the read that arrives late is served from memory instead of
// reopening the download.
const (
	maxSkipBytes = 2 << 20 // largest forward gap bridged on the open stream
	maxHeldBytes = 4 << 20 // cap on skipped bytes kept
)

// heldRange is a run of file bytes read past and kept for a later ReadAt.
type heldRange struct {
	off  int64
	data []byte
}

// ReadAt implements io.ReaderAt. A short result always comes with a non-nil
// error, as the ReaderAt contract requires.
func (r *readerAt) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, failure("file closed")
	}
	if off < 0 {
		return 0, failure("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.takeHeld(p, off) {
		return len(p), nil
	}
	n := 0
	retried := false
	for n < len(p) {
		pos := off + int64(n)
		if r.size >= 0 && pos >= r.size {
			return n, io.EOF
		}
		if r.cur != nil && pos > r.pos && pos-r.pos <= maxSkipBytes {
			r.skipTo(pos)
		}
		if r.cur == nil || r.pos != pos {
			if err := r.open(pos); err != nil {
				return n, err
			}
		}
		m, err := r.cur.Read(p[n:])
		n += m
		r.pos += int64(m)
		count(r.fs.onBytes, "read", m)
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) && (r.size < 0 || r.pos >= r.size) {
			return n, io.EOF
		}
		// The stream broke, or ended before the size seen at open. Retry once
		// from the current offset; a second failure is reported.
		r.dropCur()
		if retried {
			return n, failure("transfer interrupted")
		}
		retried = true
	}
	return n, nil
}

// skipTo reads the open stream forward to pos and keeps the bytes it passes.
// If the stream breaks, it is dropped and the caller reopens at pos.
func (r *readerAt) skipTo(pos int64) {
	gap := make([]byte, pos-r.pos)
	m, err := io.ReadFull(r.cur, gap)
	count(r.fs.onBytes, "read", m)
	if err != nil {
		r.dropCur()
		return
	}
	r.hold(r.pos, gap)
	r.pos = pos
}

// hold keeps skipped bytes, dropping the oldest when over the cap.
func (r *readerAt) hold(off int64, data []byte) {
	r.held = append(r.held, heldRange{off: off, data: data})
	r.heldBytes += len(data)
	for r.heldBytes > maxHeldBytes && len(r.held) > 0 {
		r.heldBytes -= len(r.held[0].data)
		r.held = r.held[1:]
	}
}

// takeHeld serves p at off from one held range that covers all of it, and
// keeps whatever is left of that range. It reports whether it served p.
func (r *readerAt) takeHeld(p []byte, off int64) bool {
	end := off + int64(len(p))
	for i, h := range r.held {
		hEnd := h.off + int64(len(h.data))
		if off < h.off || end > hEnd {
			continue
		}
		copy(p, h.data[off-h.off:end-h.off])
		rest := make([]heldRange, 0, len(r.held)+1)
		rest = append(rest, r.held[:i]...)
		if off > h.off {
			rest = append(rest, heldRange{off: h.off, data: h.data[:off-h.off]})
		}
		if end < hEnd {
			rest = append(rest, heldRange{off: end, data: h.data[end-h.off:]})
		}
		rest = append(rest, r.held[i+1:]...)
		r.held = rest
		r.heldBytes -= len(p)
		return true
	}
	return false
}

// open starts a download at pos. An offset the API rejects with 416 is end of
// file, not an error.
func (r *readerAt) open(pos int64) error {
	r.dropCur()
	body, err := r.files.Download(r.ctx, r.path, pos)
	if err != nil {
		if errors.Is(err, apiclient.ErrBadOffset) {
			return io.EOF
		}
		return r.fs.fail("read", err)
	}
	r.cur = body
	r.pos = pos
	return nil
}

// dropCur closes the current download body, if any.
func (r *readerAt) dropCur() {
	if r.cur != nil {
		_ = r.cur.Close()
		r.cur = nil
	}
}

// Close ends the read and releases the transfer slot. It is idempotent.
func (r *readerAt) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.dropCur()
	r.release()
	return nil
}
