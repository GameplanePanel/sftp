package vfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

func TestTreeRootListsDefaultServersAndNamespaces(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	lister, err := fx.fs.Filelist(opReq("List", "/"))
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	got := names(t, lister)
	want := []string{"_namespaces", "survival"}
	if !equalStrings(got, want) {
		t.Fatalf("root listing = %v, want %v", got, want)
	}
	if n := fx.api.snapshot().serversCalls; n < 1 {
		t.Fatalf("servers calls = %d, want at least 1", n)
	}
}

func TestTreeNamespaceFolders(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(otherNS, "modded", "/mods/a.jar", []byte("jar"))

	ns, err := fx.fs.Filelist(opReq("List", "/_namespaces"))
	if err != nil {
		t.Fatalf("list _namespaces: %v", err)
	}
	if got := names(t, ns); !equalStrings(got, []string{otherNS}) {
		t.Fatalf("_namespaces = %v, want [%s]", got, otherNS)
	}

	servers, err := fx.fs.Filelist(opReq("List", "/_namespaces/"+otherNS))
	if err != nil {
		t.Fatalf("list namespace: %v", err)
	}
	if got := names(t, servers); !equalStrings(got, []string{"modded"}) {
		t.Fatalf("namespace servers = %v, want [modded]", got)
	}

	if _, err := fx.fs.Filelist(opReq("List", "/_namespaces/nope")); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("unknown namespace err = %v, want no such file", err)
	}

	st, err := fx.fs.Filelist(opReq("Stat", "/_namespaces/"+otherNS+"/modded/mods/a.jar"))
	if err != nil {
		t.Fatalf("stat nested file: %v", err)
	}
	if info := listNames(t, st); len(info) != 1 || info[0].Size() != 3 {
		t.Fatalf("nested stat = %+v, want one entry of size 3", info)
	}
}

func TestTargetLoginIsRootedAtServer(t *testing.T) {
	target := &apiclient.Target{Namespace: testNS, Server: "survival"}
	fx := newFixture(t, target, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/world/level.dat", []byte("x"))

	lister, err := fx.fs.Filelist(opReq("List", "/"))
	if err != nil {
		t.Fatalf("list target root: %v", err)
	}
	if got := names(t, lister); !equalStrings(got, []string{"world"}) {
		t.Fatalf("target root = %v, want [world]", got)
	}
	if n := fx.api.snapshot().serversCalls; n != 0 {
		t.Fatalf("target login called Servers %d times, want 0", n)
	}
}

func TestResolvePathTable(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	ctx := context.Background()
	cases := []struct {
		in     string
		kind   kind
		ns     string
		server string
		rest   string
	}{
		{"/", kindRoot, "", "", ""},
		{"/survival", kindServer, testNS, "survival", "/"},
		{"/survival/a/b/c", kindRemote, testNS, "survival", "/a/b/c"},
		{"/survival/a/../b", kindRemote, testNS, "survival", "/b"},
		{"/_namespaces", kindNamespaces, "", "", ""},
		{"/_namespaces/" + otherNS, kindNamespace, otherNS, "", ""},
		{"/_namespaces/" + otherNS + "/modded/x", kindRemote, otherNS, "modded", "/x"},
	}
	for _, c := range cases {
		loc, err := fx.fs.resolve(ctx, c.in)
		if err != nil {
			t.Errorf("resolve(%q): %v", c.in, err)
			continue
		}
		if loc.kind != c.kind || loc.namespace != c.ns || loc.server != c.server || loc.rest != c.rest {
			t.Errorf("resolve(%q) = %+v, want kind=%d ns=%q server=%q rest=%q", c.in, loc, c.kind, c.ns, c.server, c.rest)
		}
	}
}

func TestResolveRefusesUnknownAndHidden(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	ctx := context.Background()
	for _, in := range []string{"../escape", "/unknown", "/survival/.secret", "/.hidden/x"} {
		if _, err := fx.fs.resolve(ctx, in); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
			t.Errorf("resolve(%q) err = %v, want no such file", in, err)
		}
	}
}

func TestDotfilesHiddenFromListAndStat(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/cfg/server.properties", []byte("a=1"))
	fx.api.seedFile(testNS, "survival", "/cfg/.env", []byte("SECRET=1"))

	lister, err := fx.fs.Filelist(opReq("List", "/survival/cfg"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := names(t, lister); !equalStrings(got, []string{"server.properties"}) {
		t.Fatalf("listing = %v, want only server.properties", got)
	}
	if _, err := fx.fs.Filelist(opReq("Stat", "/survival/cfg/.env")); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("stat dotfile err = %v, want no such file", err)
	}
	if _, err := fx.fs.Fileread(opReq("Get", "/survival/cfg/.env")); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("read dotfile err = %v, want no such file", err)
	}
	if _, err := fx.fs.Filewrite(openReq("/survival/cfg/.env", fxfWrite|fxfCreat)); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("write dotfile err = %v, want permission denied", err)
	}
}

func TestVirtualNodesAreReadOnly(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/a.txt", []byte("a"))
	deny := sftp.ErrSSHFxPermissionDenied
	checks := map[string]error{
		"mkdir root":          fx.fs.Filecmd(opReq("Mkdir", "/")),
		"mkdir server":        fx.fs.Filecmd(opReq("Mkdir", "/survival")),
		"rmdir server":        fx.fs.Filecmd(opReq("Rmdir", "/survival")),
		"remove server":       fx.fs.Filecmd(opReq("Remove", "/survival")),
		"rename server":       fx.fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/survival", Target: "/survival/x"}),
		"rename into virtual": fx.fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/survival/a.txt", Target: "/_namespaces"}),
	}
	for name, err := range checks {
		if !errors.Is(err, deny) {
			t.Errorf("%s: err = %v, want permission denied", name, err)
		}
	}
	if _, err := fx.fs.Filewrite(openReq("/survival", fxfWrite|fxfCreat)); !errors.Is(err, deny) {
		t.Errorf("write to server folder: err = %v, want permission denied", err)
	}
}

func TestTargetServerRootIsReadOnly(t *testing.T) {
	target := &apiclient.Target{Namespace: testNS, Server: "survival"}
	fx := newFixture(t, target, Options{}, testServers)
	if err := fx.fs.Filecmd(opReq("Mkdir", "/")); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("mkdir / err = %v, want permission denied", err)
	}
	if err := fx.fs.Filecmd(opReq("Remove", "/")); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("remove / err = %v, want permission denied", err)
	}
}

func TestReadWholeFile(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/world/a.txt", []byte("0123456789"))

	r, err := fx.fs.Fileread(opReq("Get", "/survival/world/a.txt"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeOrFail(t, r)
	buf := make([]byte, 10)
	n, err := r.ReadAt(buf, 0)
	if err != nil || n != 10 || string(buf) != "0123456789" {
		t.Fatalf("ReadAt = %d %q %v, want 10 bytes", n, buf[:n], err)
	}
	if _, err := r.ReadAt(buf, 10); err != io.EOF {
		t.Fatalf("read past end err = %v, want EOF", err)
	}
}

func TestRangedReadAndConnectionReuse(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	fx.api.seedFile(testNS, "survival", "/big.bin", data)

	r, err := fx.fs.Fileread(opReq("Get", "/survival/big.bin"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeOrFail(t, r)

	buf := make([]byte, 4)
	if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatalf("read at 0: %v", err)
	}
	if _, err := r.ReadAt(buf, 4); err != nil {
		t.Fatalf("read at 4: %v", err)
	}
	if got := fx.api.snapshot().downloads; got != 1 {
		t.Fatalf("contiguous reads opened %d downloads, want 1", got)
	}

	// A short jump ahead is bridged on the open stream, not reopened.
	if _, err := r.ReadAt(buf, 20); err != nil {
		t.Fatalf("jump read: %v", err)
	}
	if string(buf) != string(data[20:24]) {
		t.Fatalf("jump read = %q, want %q", buf, data[20:24])
	}
	if got := fx.api.snapshot().downloads; got != 1 {
		t.Fatalf("short jump opened %d downloads, want 1", got)
	}

	// The bytes jumped over are kept, so a late read of them is served
	// from memory.
	if _, err := r.ReadAt(buf, 8); err != nil {
		t.Fatalf("late read: %v", err)
	}
	if string(buf) != string(data[8:12]) {
		t.Fatalf("late read = %q, want %q", buf, data[8:12])
	}
	if got := fx.api.snapshot().downloads; got != 1 {
		t.Fatalf("late read opened %d downloads, want 1", got)
	}

	// A read behind the stream that was not kept reopens the download.
	if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := fx.api.snapshot().downloads; got != 2 {
		t.Fatalf("seek back opened %d downloads total, want 2", got)
	}
}

func TestFarSeekReopensWithRange(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	data := pattern(3 << 20)
	fx.api.seedFile(testNS, "survival", "/far.bin", data)
	r, err := fx.fs.Fileread(opReq("Get", "/survival/far.bin"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeOrFail(t, r)

	buf := make([]byte, 16)
	if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatalf("read at 0: %v", err)
	}
	far := int64(3<<20 - 16)
	if _, err := r.ReadAt(buf, far); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("far read: %v", err)
	}
	if !bytes.Equal(buf, data[far:]) {
		t.Fatal("far read returned the wrong bytes")
	}
	st := fx.api.snapshot()
	want := "bytes=" + strconv.FormatInt(far, 10) + "-"
	if st.downloads != 2 || st.ranges[1] != want {
		t.Fatalf("downloads=%d ranges=%q, want 2 with %s", st.downloads, st.ranges, want)
	}
}

func TestReadShortReadReturnsError(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/short.bin", []byte("abc"))
	r, err := fx.fs.Fileread(opReq("Get", "/survival/short.bin"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeOrFail(t, r)
	buf := make([]byte, 10)
	n, err := r.ReadAt(buf, 0)
	if n != 3 || err != io.EOF {
		t.Fatalf("ReadAt past end = %d %v, want 3 and EOF", n, err)
	}
}

func TestReadMissingAndDirectoryFailAtOpen(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedDir(testNS, "survival", "/world")
	if _, err := fx.fs.Fileread(opReq("Get", "/survival/missing")); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("missing err = %v, want no such file", err)
	}
	if _, err := fx.fs.Fileread(opReq("Get", "/survival/world")); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("directory err = %v, want failure", err)
	}
	if _, err := fx.fs.Fileread(opReq("Get", "/survival")); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("virtual dir err = %v, want failure", err)
	}
}

func TestListingSortedDirsFirstAndFiltered(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	fx.api.seedFile(testNS, "survival", "/d/b.txt", []byte("b"))
	fx.api.seedFile(testNS, "survival", "/d/a.txt", []byte("a"))
	fx.api.seedFile(testNS, "survival", "/d/.hidden", []byte("h"))
	fx.api.seedDir(testNS, "survival", "/d/zdir")

	lister, err := fx.fs.Filelist(opReq("List", "/survival/d"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"zdir", "a.txt", "b.txt"}
	if got := names(t, lister); !equalStrings(got, want) {
		t.Fatalf("listing = %v, want %v", got, want)
	}
}

func TestStatVirtualFolderIsDirectory(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	lister, err := fx.fs.Filelist(opReq("Stat", "/survival"))
	if err != nil {
		t.Fatalf("stat server folder: %v", err)
	}
	info := listNames(t, lister)
	if len(info) != 1 || !info[0].IsDir() || info[0].Name() != "survival" {
		t.Fatalf("stat server folder = %+v, want one dir named survival", info)
	}
}

func TestToSFTPMapping(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"nil", nil, nil},
		{"not found", &apiclient.Error{Status: 404, Err: apiclient.ErrNotFound}, sftp.ErrSSHFxNoSuchFile},
		{"permission", &apiclient.Error{Status: 403, Err: apiclient.ErrPermission}, sftp.ErrSSHFxPermissionDenied},
		{"bad request", &apiclient.Error{Status: 400, Err: apiclient.ErrBadRequest}, sftp.ErrSSHFxPermissionDenied},
		{"unauthorized", &apiclient.Error{Status: 401, Err: apiclient.ErrUnauthorized}, sftp.ErrSSHFxPermissionDenied},
		{"exists", &apiclient.Error{Status: 409, Err: apiclient.ErrExists}, sftp.ErrSSHFxFailure},
		{"no space", &apiclient.Error{Status: 507, Err: apiclient.ErrNoSpace}, sftp.ErrSSHFxFailure},
		{"too large", &apiclient.Error{Status: 413, Err: apiclient.ErrTooLarge}, sftp.ErrSSHFxFailure},
		{"bad offset", &apiclient.Error{Status: 416, Err: apiclient.ErrBadOffset}, sftp.ErrSSHFxFailure},
		{"busy", &apiclient.Error{Status: 429, Err: apiclient.ErrBusy}, sftp.ErrSSHFxFailure},
		{"unavailable", &apiclient.Error{Status: 503, Err: apiclient.ErrUnavailable}, sftp.ErrSSHFxFailure},
		{"canceled", context.Canceled, sftp.ErrSSHFxConnectionLost},
		{"deadline", context.DeadlineExceeded, sftp.ErrSSHFxConnectionLost},
		{"status passthrough", sftp.ErrSSHFxOpUnsupported, sftp.ErrSSHFxOpUnsupported},
		{"unknown", errors.New("boom http://secret"), sftp.ErrSSHFxFailure},
	}
	for _, c := range cases {
		got := toSFTP(c.in)
		if !errors.Is(got, c.want) {
			t.Errorf("%s: toSFTP(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
	if msg := toSFTP(errors.New("boom http://secret")).Error(); msg != sftp.ErrSSHFxFailure.Error() {
		t.Errorf("unknown error leaked text: %q", msg)
	}
}

func TestLimiterCapsPerUser(t *testing.T) {
	l := NewLimiter(1)
	release, ok := l.Acquire("Alice")
	if !ok {
		t.Fatal("first acquire refused")
	}
	if _, ok := l.Acquire("alice"); ok {
		t.Fatal("second acquire for the same user (case-insensitive) allowed")
	}
	if _, ok := l.Acquire("bob"); !ok {
		t.Fatal("other user refused")
	}
	release()
	release()
	if _, ok := l.Acquire("alice"); !ok {
		t.Fatal("acquire after release refused")
	}

	var unlimited *Limiter
	if _, ok := unlimited.Acquire("x"); !ok {
		t.Fatal("nil limiter refused")
	}
}

// equalStrings reports whether two string slices hold the same values in order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// closeOrFail closes a handle returned by Fileread or Filewrite and fails the
// test on error. Both handle types implement io.Closer.
func closeOrFail(t *testing.T, handle any) {
	t.Helper()
	c, ok := handle.(io.Closer)
	if !ok {
		t.Fatalf("handle %T is not an io.Closer", handle)
	}
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
