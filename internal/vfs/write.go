package vfs

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// errTransferAborted is the reason a pipe is closed when an upload is
// abandoned. The API sees a broken body and commits nothing.
var errTransferAborted = errors.New("transfer aborted")

// Filewrite opens a file for writing. Creating, replacing and resuming an
// existing file at an offset are supported; appending is not.
func (f *FS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	ctx := r.Context()
	flags := r.Pflags()
	if flags.Append {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	loc, err := f.resolveWrite(ctx, r.Filepath)
	if err != nil {
		return nil, err
	}
	files := f.filesFor(loc)
	exists := true
	e, err := files.Stat(ctx, loc.rest)
	switch {
	case errors.Is(err, apiclient.ErrNotFound):
		exists = false
	case err != nil:
		return nil, f.fail("write stat", err)
	case e.Dir:
		return nil, failure("is a directory")
	}
	if exists && flags.Excl {
		return nil, failure("file exists")
	}
	if !exists && !flags.Creat {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	release, ok := f.limiter.Acquire(f.user)
	if !ok {
		return nil, failure("too many concurrent transfers")
	}
	return newWriter(ctx, f, files, loc.rest, release, flags.Creat || flags.Trunc, !exists || flags.Trunc), nil
}

// Limits on how far out of order a client's writes may arrive. pkg/sftp
// handles write packets on a pool of workers, so pipelined writes from one
// client can reach WriteAt a few chunks out of order. The writer holds such
// chunks until the gap before them is filled. A chunk further ahead than the
// window, or more held data than the cap, aborts the upload.
const (
	maxReorderBytes  = 4 << 20 // furthest a chunk may start beyond the next expected offset, and the cap on held bytes
	maxReorderChunks = 16      // most chunks held at once
	baseWindow       = 8       // chunks gathered before the start offset of a resume is fixed
)

// writer turns WriteAt calls into one streamed PUT. The bytes go through an
// io.Pipe into a single request. The API commits the file only when the body
// ends cleanly, so an upload that is abandoned or has a gap in it is never
// committed. The stream runs front to back: chunks that arrive slightly out
// of order are held until their predecessors arrive. A new or truncated file
// starts at offset 0. For an existing file opened without truncation, the
// start offset is the lowest of the first few chunks, which resumes the file
// there.
type writer struct {
	ctx       context.Context
	fs        *FS
	files     *apiclient.Files
	path      string
	create    bool // Creat or Trunc was set: a write-less close still creates the file
	baseKnown bool // the stream must start at offset 0 (new or truncated file)
	release   func()
	pr        *io.PipeReader
	pw        *io.PipeWriter
	finished  chan struct{} // closed when the stream goroutine has returned
	aborted   atomic.Bool

	mu           sync.Mutex // guards the fields below
	streaming    bool       // the stream goroutine is running
	closed       bool
	next         int64            // offset the stream expects next
	pending      map[int64][]byte // chunks held until the stream reaches them
	pendingBytes int
	streamErr    error // result of the stream; written before finished closes
	closeErr     error
}

// newWriter returns a writer that has not started its request yet.
func newWriter(ctx context.Context, fs *FS, files *apiclient.Files, p string, release func(), create, baseKnown bool) *writer {
	pr, pw := io.Pipe()
	return &writer{
		ctx:       ctx,
		fs:        fs,
		files:     files,
		path:      p,
		create:    create,
		baseKnown: baseKnown,
		release:   release,
		pr:        pr,
		pw:        pw,
		finished:  make(chan struct{}),
		pending:   make(map[int64][]byte),
	}
}

// WriteAt implements io.WriterAt. A chunk at the stream's position blocks
// until the stream has taken the bytes, which gives the client backpressure.
func (w *writer) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, failure("file closed")
	}
	if w.aborted.Load() {
		return 0, failure("transfer aborted")
	}
	if off < 0 {
		return 0, failure("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !w.streaming && w.baseKnown && off == 0 {
		w.begin(0)
	}
	switch {
	case w.streaming && off == w.next:
		if err := w.push(p); err != nil {
			return 0, err
		}
		if err := w.drain(); err != nil {
			return len(p), err
		}
	case w.streaming && off < w.next:
		w.abort(errTransferAborted)
		return 0, sftp.ErrSSHFxOpUnsupported
	default:
		if err := w.hold(p, off); err != nil {
			return 0, err
		}
		if !w.streaming && !w.baseKnown && len(w.pending) >= baseWindow {
			w.beginAtLowest()
			if err := w.drain(); err != nil {
				return len(p), err
			}
		}
	}
	return len(p), nil
}

// begin starts the stream at off.
func (w *writer) begin(off int64) {
	w.streaming = true
	w.next = off
	go w.run(off)
}

// beginAtLowest starts the stream at the lowest held chunk. It is used for a
// resume, where the first offset the client writes is not known in advance.
func (w *writer) beginAtLowest() {
	lowest := int64(-1)
	for off := range w.pending {
		if lowest < 0 || off < lowest {
			lowest = off
		}
	}
	w.begin(lowest)
}

// hold keeps a copy of a chunk that is ahead of the stream. pkg/sftp reuses
// its buffer after WriteAt returns, so the bytes must be copied.
func (w *writer) hold(p []byte, off int64) error {
	if _, dup := w.pending[off]; dup {
		w.abort(errTransferAborted)
		return sftp.ErrSSHFxOpUnsupported
	}
	limit := w.next
	if !w.streaming && !w.baseKnown {
		limit = off // a resume may start anywhere
	}
	if off+int64(len(p)) > limit+maxReorderBytes ||
		len(w.pending) >= maxReorderChunks ||
		w.pendingBytes+len(p) > maxReorderBytes {
		w.abort(errTransferAborted)
		return sftp.ErrSSHFxOpUnsupported
	}
	w.pending[off] = append([]byte(nil), p...)
	w.pendingBytes += len(p)
	return nil
}

// push writes one chunk to the stream at its current position.
func (w *writer) push(p []byte) error {
	n, err := w.pw.Write(p)
	w.next += int64(n)
	count(w.fs.onBytes, "write", n)
	if err != nil {
		// The stream ended early, for example with 413 or 507. Its error is
		// the one to report.
		<-w.finished
		return w.streamFailure()
	}
	return nil
}

// drain streams every held chunk that now continues the stream.
func (w *writer) drain() error {
	for {
		chunk, ok := w.pending[w.next]
		if !ok {
			return nil
		}
		delete(w.pending, w.next)
		w.pendingBytes -= len(chunk)
		if err := w.push(chunk); err != nil {
			return err
		}
	}
}

// run performs the streamed PUT. It closes the pipe reader when done, so a
// blocked WriteAt always returns.
func (w *writer) run(off int64) {
	err := w.files.Stream(w.ctx, w.path, off, w.pr, -1)
	if err != nil {
		w.streamErr = w.fs.fail("write", err)
		_ = w.pr.CloseWithError(w.streamErr)
	} else {
		_ = w.pr.Close()
	}
	close(w.finished)
}

// streamFailure is the error to report once the stream has ended with an
// error. Call it only after finished is closed.
func (w *writer) streamFailure() error {
	if w.streamErr != nil {
		return w.streamErr
	}
	return failure("transfer failed")
}

// abort marks the upload as abandoned and breaks the body so nothing is
// committed. It does not take mu, so it is safe during a blocked WriteAt.
func (w *writer) abort(err error) {
	w.aborted.Store(true)
	_ = w.pw.CloseWithError(err)
}

// TransferError is called by pkg/sftp when the connection fails mid-transfer.
// It abandons the upload, so the half-written file is not committed.
func (w *writer) TransferError(err error) {
	if err == nil {
		err = errTransferAborted
	}
	w.abort(err)
}

// Close ends the upload. A clean end commits it. An aborted upload, or one
// with a gap that never filled, commits nothing. An unstarted create or
// truncate with no data makes an empty file. Close is idempotent.
func (w *writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	defer w.release()
	flushErr := w.flushPending()
	w.pending = nil
	switch {
	case w.aborted.Load():
		if w.streaming {
			_ = w.pw.CloseWithError(errTransferAborted)
			<-w.finished
		}
		w.closeErr = failure("transfer aborted")
		if flushErr != nil {
			w.closeErr = flushErr
		}
	case !w.streaming:
		if w.create {
			w.closeErr = w.fs.fail("create", w.files.Stream(w.ctx, w.path, 0, strings.NewReader(""), 0))
		}
	default:
		_ = w.pw.Close()
		<-w.finished
		w.closeErr = w.streamErr
	}
	return w.closeErr
}

// flushPending runs at Close. Held chunks of a resume are streamed from their
// lowest offset. Anything still held after that, or held for a new file whose
// first chunk never came, is a gap: the upload is aborted. The error is the
// stream's, when the stream failed while draining.
func (w *writer) flushPending() error {
	if len(w.pending) == 0 || w.aborted.Load() {
		return nil
	}
	if !w.streaming {
		if w.baseKnown {
			w.abort(errTransferAborted)
			return nil
		}
		w.beginAtLowest()
	}
	err := w.drain()
	if err != nil || len(w.pending) > 0 {
		w.abort(errTransferAborted)
	}
	return err
}
