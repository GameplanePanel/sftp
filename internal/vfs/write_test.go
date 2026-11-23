package vfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// pattern returns n bytes that differ from one position to the next.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func TestSequentialWriteIsOneStream(t *testing.T) {
	var wrote int
	fx := newFixture(t, nil, Options{OnBytes: func(dir string, n int) {
		if dir == "write" {
			wrote += n
		}
	}}, testServers)
	data := pattern(1 << 20)
	w, err := fx.fs.Filewrite(openReq("/survival/big.bin", fxfWrite|fxfCreat|fxfTrunc))
	if err != nil {
		t.Fatalf("open for write: %v", err)
	}
	const chunk = 64 << 10
	for off := 0; off < len(data); off += chunk {
		if n, err := w.WriteAt(data[off:off+chunk], int64(off)); err != nil || n != chunk {
			t.Fatalf("WriteAt(%d) = %d, %v", off, n, err)
		}
	}
	closeOrFail(t, w)

	st := fx.api.snapshot()
	if len(st.streamQueries) != 1 || st.streamQueries[0].Get("offset") != "0" {
		t.Fatalf("stream requests = %v, want one with offset=0", st.streamQueries)
	}
	got, ok := fx.api.fileData(testNS, "survival", "/big.bin")
	if !ok || !bytes.Equal(got, data) {
		t.Fatalf("committed file differs from written data (ok=%v, len=%d)", ok, len(got))
	}
	if wrote != len(data) {
		t.Fatalf("OnBytes(write) total = %d, want %d", wrote, len(data))
	}
}

func TestResumeAtOffsetKeepsPrefix(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/r.bin", []byte("0123456789"))
	w, err := fx.fs.Filewrite(openReq("/survival/r.bin", fxfWrite))
	if err != nil {
		t.Fatalf("open for resume: %v", err)
	}
	if n, err := w.WriteAt([]byte("ABC"), 10); err != nil || n != 3 {
		t.Fatalf("WriteAt(10) = %d, %v", n, err)
	}
	closeOrFail(t, w)

	st := fx.api.snapshot()
	if len(st.streamQueries) != 1 || st.streamQueries[0].Get("offset") != "10" {
		t.Fatalf("stream requests = %v, want one with offset=10", st.streamQueries)
	}
	got, _ := fx.api.fileData(testNS, "survival", "/r.bin")
	if string(got) != "0123456789ABC" {
		t.Fatalf("resumed file = %q, want 0123456789ABC", got)
	}
}

func TestOutOfOrderWriteAbortsWithoutCommit(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/o.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.WriteAt([]byte("aaaa"), 0); err != nil {
		t.Fatalf("first WriteAt: %v", err)
	}
	if _, err := w.WriteAt([]byte("bbbb"), 1<<30); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("far WriteAt err = %v, want op unsupported", err)
	}
	if err := w.(io.Closer).Close(); err == nil {
		t.Fatal("Close after abort returned nil, want an error")
	}
	if fx.api.has(testNS, "survival", "/o.bin") {
		t.Fatal("aborted upload was committed")
	}
}

func TestBackwardsWriteIsUnsupported(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/back.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.WriteAt([]byte("aaaa"), 0); err != nil {
		t.Fatalf("first WriteAt: %v", err)
	}
	if _, err := w.WriteAt([]byte("bb"), 0); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("backwards WriteAt err = %v, want op unsupported", err)
	}
	_ = w.(io.Closer).Close()
	if fx.api.has(testNS, "survival", "/back.bin") {
		t.Fatal("aborted upload was committed")
	}
}

func TestZeroLengthCreateMakesEmptyFile(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/empty.txt", fxfWrite|fxfCreat|fxfTrunc))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	closeOrFail(t, w)
	got, ok := fx.api.fileData(testNS, "survival", "/empty.txt")
	if !ok || len(got) != 0 {
		t.Fatalf("empty create: exists=%v len=%d, want an empty file", ok, len(got))
	}
}

func TestExclusiveCreateOnExistingFails(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/e.txt", []byte("old"))
	if _, err := fx.fs.Filewrite(openReq("/survival/e.txt", fxfWrite|fxfCreat|fxfExcl)); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("excl on existing err = %v, want failure", err)
	}
}

func TestAppendIsUnsupported(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	if _, err := fx.fs.Filewrite(openReq("/survival/a.txt", fxfWrite|fxfAppend|fxfCreat)); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("append err = %v, want op unsupported", err)
	}
}

func TestStreamFailuresSurfaceAndDoNotCommit(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{413, sftp.ErrSSHFxFailure},
		{507, sftp.ErrSSHFxFailure},
		{403, sftp.ErrSSHFxPermissionDenied},
	}
	for _, c := range cases {
		fx := newFixture(t, nil, Options{}, testServers)
		fx.api.setStreamFail(c.status)
		w, err := fx.fs.Filewrite(openReq("/survival/fail.bin", fxfWrite|fxfCreat))
		if err != nil {
			t.Fatalf("status %d: open: %v", c.status, err)
		}
		_, err = w.WriteAt(pattern(1024), 0)
		if err == nil {
			err = w.(io.Closer).Close()
		}
		if !errors.Is(err, c.want) {
			t.Errorf("status %d: err = %v, want %v", c.status, err, c.want)
		}
		if fx.api.has(testNS, "survival", "/fail.bin") {
			t.Errorf("status %d: failed upload was committed", c.status)
		}
	}
}

func TestTransferErrorDoesNotCommit(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/cut.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.WriteAt(pattern(4096), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	w.(*writer).TransferError(errors.New("connection lost"))
	if err := w.(io.Closer).Close(); err == nil {
		t.Fatal("Close after TransferError returned nil")
	}
	if fx.api.has(testNS, "survival", "/cut.bin") {
		t.Fatal("transfer cut mid-way was committed")
	}
}

func TestRenameVariants(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/a.txt", []byte("a"))
	fx.api.seedFile(testNS, "survival", "/b.txt", []byte("b"))

	if err := fx.fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/survival/a.txt", Target: "/survival/c.txt"}); err != nil {
		t.Fatalf("plain rename: %v", err)
	}
	if fx.api.has(testNS, "survival", "/a.txt") || !fx.api.has(testNS, "survival", "/c.txt") {
		t.Fatal("plain rename did not move the file")
	}
	if err := fx.fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/survival/c.txt", Target: "/survival/b.txt"}); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("rename onto existing err = %v, want failure", err)
	}
	if err := fx.fs.PosixRename(&sftp.Request{Method: "PosixRename", Filepath: "/survival/c.txt", Target: "/survival/b.txt"}); err != nil {
		t.Fatalf("posix rename over existing: %v", err)
	}
	if got, _ := fx.api.fileData(testNS, "survival", "/b.txt"); string(got) != "a" {
		t.Fatalf("posix rename target = %q, want a", got)
	}
	if err := fx.fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/survival/b.txt", Target: "/_namespaces/" + otherNS + "/modded/b.txt"}); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("cross-server rename err = %v, want op unsupported", err)
	}
	if err := fx.fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/survival/none", Target: "/survival/z"}); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("missing source err = %v, want no such file", err)
	}
}

func TestMkdirRmdirRemove(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/f.txt", []byte("f"))

	if err := fx.fs.Filecmd(opReq("Mkdir", "/survival/newdir")); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := fx.fs.Filecmd(opReq("Mkdir", "/survival/newdir")); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("mkdir existing err = %v, want failure", err)
	}
	if err := fx.fs.Filecmd(opReq("Mkdir", "/survival/newdir/sub")); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := fx.fs.Filecmd(opReq("Remove", "/survival/newdir")); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("remove directory err = %v, want failure", err)
	}
	if err := fx.fs.Filecmd(opReq("Rmdir", "/survival/newdir")); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("rmdir non-empty err = %v, want failure", err)
	}
	if err := fx.fs.Filecmd(opReq("Rmdir", "/survival/newdir/sub")); err != nil {
		t.Fatalf("rmdir empty: %v", err)
	}
	if err := fx.fs.Filecmd(opReq("Rmdir", "/survival/newdir")); err != nil {
		t.Fatalf("rmdir now-empty: %v", err)
	}
	if err := fx.fs.Filecmd(opReq("Remove", "/survival/f.txt")); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if err := fx.fs.Filecmd(opReq("Mkdir", "/survival")); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("mkdir server folder err = %v, want permission denied", err)
	}
	for _, q := range fx.api.snapshot().deletes {
		if q.Has("recursive") {
			t.Fatalf("delete sent recursive: %v", q)
		}
	}
}

func TestSetstatRules(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/s.txt", []byte("s"))
	set := func(p string, flags uint32) error {
		return fx.fs.Filecmd(&sftp.Request{Method: "Setstat", Filepath: p, Flags: flags})
	}
	if err := set("/survival/s.txt", attrPerm); err != nil {
		t.Errorf("chmod-style setstat: %v", err)
	}
	if err := set("/survival/s.txt", attrPerm|attrModTime); err != nil {
		t.Errorf("time setstat: %v", err)
	}
	if err := set("/survival/s.txt", attrUIDGID); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Errorf("chown err = %v, want permission denied", err)
	}
	if err := set("/survival/s.txt", attrSize); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Errorf("truncate err = %v, want op unsupported", err)
	}
	if err := set("/survival/none", attrPerm); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Errorf("setstat missing err = %v, want no such file", err)
	}
	if err := set("/survival", attrPerm); err != nil {
		t.Errorf("setstat on virtual folder: %v", err)
	}
}

func TestLinkAndReadlinkUnsupported(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	for _, m := range []string{"Link", "Symlink"} {
		err := fx.fs.Filecmd(&sftp.Request{Method: m, Filepath: "/survival/a", Target: "/survival/b"})
		if !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
			t.Errorf("%s err = %v, want op unsupported", m, err)
		}
	}
	if _, err := fx.fs.Filelist(opReq("Readlink", "/survival/a")); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Errorf("readlink err = %v, want op unsupported", err)
	}
}

func TestTransferCapBlocksThenReleases(t *testing.T) {
	fx := newFixture(t, nil, Options{Limiter: NewLimiter(1)}, testServers)
	first, err := fx.fs.Filewrite(openReq("/survival/one.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := fx.fs.Filewrite(openReq("/survival/two.bin", fxfWrite|fxfCreat)); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("second open err = %v, want failure", err)
	}
	closeOrFail(t, first)
	third, err := fx.fs.Filewrite(openReq("/survival/three.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open after release: %v", err)
	}
	closeOrFail(t, third)
}

func TestTargetLoginWritesInsideServer(t *testing.T) {
	target := &apiclient.Target{Namespace: testNS, Server: "survival"}
	fx := newFixture(t, target, Options{}, testServers)
	if err := fx.fs.Filecmd(opReq("Mkdir", "/mods")); err != nil {
		t.Fatalf("mkdir in target root: %v", err)
	}
	if !fx.api.has(testNS, "survival", "/mods") {
		t.Fatal("mkdir did not create the folder on the target server")
	}
}

// TestEndToEndOverSFTPProtocol drives the real pkg/sftp request server and
// client over an in-memory pipe, through the FS handlers.
func TestEndToEndOverSFTPProtocol(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	cliConn, srvConn := net.Pipe()
	srv := sftp.NewRequestServer(srvConn, fx.fs.Handlers())
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()

	client, err := sftp.NewClientPipe(cliConn, cliConn)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = srv.Close()
		<-served
	})

	big := pattern(3 << 20)
	if err := client.Mkdir("/survival/up"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := client.Create("/survival/up/big.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for off := 0; off < len(big); off += 32 << 10 {
		end := min(off+32<<10, len(big))
		if _, err := f.Write(big[off:end]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	if got, ok := fx.api.fileData(testNS, "survival", "/up/big.bin"); !ok || !bytes.Equal(got, big) {
		t.Fatalf("uploaded file differs (ok=%v, len=%d)", ok, len(got))
	}

	rf, err := client.Open("/survival/up/big.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	back, err := io.ReadAll(rf)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if err := rf.Close(); err != nil {
		t.Fatalf("close download: %v", err)
	}
	if !bytes.Equal(back, big) {
		t.Fatalf("downloaded %d bytes, differs from upload", len(back))
	}

	if err := client.Rename("/survival/up/big.bin", "/survival/up/moved.bin"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	entries, err := client.ReadDir("/survival/up")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "moved.bin" || entries[0].Size() != int64(len(big)) {
		t.Fatalf("readdir = %v, want moved.bin of %d bytes", entries, len(big))
	}
}

func TestReorderedChunksAreStreamedInOrder(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/re.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const chunk = 1000
	data := pattern(6 * chunk)
	// Chunks 2, 1, 0, 5, 3, 4: as a worker pool may deliver pipelined writes.
	for _, i := range []int{2, 1, 0, 5, 3, 4} {
		if n, err := w.WriteAt(data[i*chunk:(i+1)*chunk], int64(i*chunk)); err != nil || n != chunk {
			t.Fatalf("WriteAt chunk %d = %d, %v", i, n, err)
		}
	}
	closeOrFail(t, w)
	st := fx.api.snapshot()
	if len(st.streamQueries) != 1 || st.streamQueries[0].Get("offset") != "0" {
		t.Fatalf("stream requests = %v, want one with offset=0", st.streamQueries)
	}
	if got, _ := fx.api.fileData(testNS, "survival", "/re.bin"); !bytes.Equal(got, data) {
		t.Fatalf("reordered upload differs: got %d bytes, want %d", len(got), len(data))
	}
}

func TestChunkGapAtCloseAbortsWithoutCommit(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/gap.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.WriteAt([]byte("aaaa"), 0); err != nil {
		t.Fatalf("WriteAt 0: %v", err)
	}
	if _, err := w.WriteAt([]byte("cccc"), 8); err != nil {
		t.Fatalf("WriteAt 8: %v", err)
	}
	if err := w.(io.Closer).Close(); err == nil {
		t.Fatal("Close with a gap returned nil")
	}
	if fx.api.has(testNS, "survival", "/gap.bin") {
		t.Fatal("upload with a gap was committed")
	}
}

func TestFirstChunkMissingForNewFileAborts(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	w, err := fx.fs.Filewrite(openReq("/survival/nofirst.bin", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.WriteAt([]byte("bbbb"), 4); err != nil {
		t.Fatalf("WriteAt 4: %v", err)
	}
	if err := w.(io.Closer).Close(); err == nil {
		t.Fatal("Close without the first chunk returned nil")
	}
	if fx.api.has(testNS, "survival", "/nofirst.bin") {
		t.Fatal("upload without its first chunk was committed")
	}
}

func TestResumeWithReorderedChunksStartsAtLowest(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/res.bin", []byte("0123456789"))
	w, err := fx.fs.Filewrite(openReq("/survival/res.bin", fxfWrite))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.WriteAt([]byte("CC"), 12); err != nil {
		t.Fatalf("WriteAt 12: %v", err)
	}
	if _, err := w.WriteAt([]byte("AA"), 10); err != nil {
		t.Fatalf("WriteAt 10: %v", err)
	}
	closeOrFail(t, w)
	st := fx.api.snapshot()
	if len(st.streamQueries) != 1 || st.streamQueries[0].Get("offset") != "10" {
		t.Fatalf("stream requests = %v, want one with offset=10", st.streamQueries)
	}
	if got, _ := fx.api.fileData(testNS, "survival", "/res.bin"); string(got) != "0123456789AACC" {
		t.Fatalf("resumed file = %q, want 0123456789AACC", got)
	}
}
