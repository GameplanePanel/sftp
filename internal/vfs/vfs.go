// Package vfs presents Gameplane game servers as an SFTP file tree for one
// authenticated connection. Every file operation is forwarded to the Gameplane
// API as the signed-in user; the package never reads a game volume itself.
//
// Layout for a login without a target (tree login):
//
//	/<server>/...                       servers in the default namespace
//	/_namespaces/<ns>/<server>/...      servers in other namespaces
//
// Only the server folders and their contents are writable. The root, the
// _namespaces folders and each server's top folder are read-only virtual
// directories. A login with a target ("server" or "namespace/server") is
// rooted at that server, and its root is the server's files.
package vfs

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// DefaultNamespace is the namespace the API uses when a request names none.
// It matches the API's scope.DefaultNamespace.
const DefaultNamespace = "gameplane-games"

const (
	namespacesDir  = "_namespaces"
	serverCacheTTL = 5 * time.Second
)

// API is the part of *apiclient.Client the file system uses.
type API interface {
	Servers(ctx context.Context, token string) ([]apiclient.ServerRef, error)
	Files(token, namespace, server string) *apiclient.Files
}

// Options configures an FS. The zero value is usable.
type Options struct {
	// DefaultNamespace is the namespace whose servers appear at the top of a
	// tree login. Empty means DefaultNamespace.
	DefaultNamespace string
	// Limiter caps concurrent transfers per user. Nil means unlimited.
	Limiter *Limiter
	// OnBytes is called with "read" or "write" and the bytes moved. May be nil.
	OnBytes func(direction string, n int)
	// Logger receives debug logs. Nil discards them.
	Logger *slog.Logger
}

// FS is the virtual file system of one authenticated SSH connection. It is
// safe for concurrent use by the SFTP request workers.
type FS struct {
	api     API
	token   string
	user    string
	target  *apiclient.Target
	started time.Time
	defNS   string
	limiter *Limiter
	onBytes func(direction string, n int)
	log     *slog.Logger

	mu       sync.Mutex
	loaded   bool
	servers  []apiclient.ServerRef
	loadedAt time.Time
}

// New returns the file system for session. The session token is used for
// every API call the FS makes.
func New(api API, session apiclient.Session, opts Options) *FS {
	ns := opts.DefaultNamespace
	if ns == "" {
		ns = DefaultNamespace
	}
	lg := opts.Logger
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	return &FS{
		api:     api,
		token:   session.Token,
		user:    strings.ToLower(session.User),
		target:  session.Target,
		started: time.Now(),
		defNS:   ns,
		limiter: opts.Limiter,
		onBytes: opts.OnBytes,
		log:     lg,
	}
}

// Compile-time checks that FS provides the optional pkg/sftp interfaces.
var (
	_ sftp.FileReader           = (*FS)(nil)
	_ sftp.FileWriter           = (*FS)(nil)
	_ sftp.FileCmder            = (*FS)(nil)
	_ sftp.PosixRenameFileCmder = (*FS)(nil)
	_ sftp.FileLister           = (*FS)(nil)
	_ sftp.LstatFileLister      = (*FS)(nil)
	_ sftp.TransferError        = (*writer)(nil)
	_ io.ReaderAt               = (*readerAt)(nil)
	_ io.Closer                 = (*readerAt)(nil)
	_ io.WriterAt               = (*writer)(nil)
	_ io.Closer                 = (*writer)(nil)
)

// Handlers returns the pkg/sftp handler set backed by this FS.
func (f *FS) Handlers() sftp.Handlers {
	return sftp.Handlers{FileGet: f, FilePut: f, FileCmd: f, FileList: f}
}

// kind classifies a resolved path.
type kind int

const (
	kindRoot       kind = iota // "/" of a tree login (virtual)
	kindNamespaces             // "/_namespaces" (virtual)
	kindNamespace              // "/_namespaces/<ns>" (virtual)
	kindServer                 // a server's top folder in a tree login (virtual, lists via API)
	kindRemote                 // a path inside a server
)

// location is a resolved path.
type location struct {
	kind      kind
	namespace string
	server    string
	// rest is the absolute path on the server ("/" for the server root). It is
	// empty for the purely virtual kinds.
	rest string
}

// virtual reports whether the location is a synthetic directory that the API
// does not hold. Stat answers those without an API call.
func (l location) virtual() bool { return l.kind != kindRemote }

// writable reports whether create, rename and remove may apply here. The
// server root and every virtual node are read-only.
func (l location) writable() bool { return l.kind == kindRemote && l.rest != "/" }

// sameServer reports whether two locations live in the same server.
func (l location) sameServer(o location) bool {
	return l.kind == kindRemote && o.kind == kindRemote &&
		l.namespace == o.namespace && l.server == o.server
}

// splitParts returns the components of a clean absolute path.
func splitParts(clean string) []string {
	trimmed := strings.Trim(clean, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// hiddenPath reports whether any component of the clean path starts with a
// dot. Such files are never listed, read or written through SFTP.
func hiddenPath(clean string) bool {
	for _, part := range splitParts(clean) {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// resolve maps a client path to a location. Dotted components and unknown
// servers or namespaces give ErrSSHFxNoSuchFile. Other failures come back as
// SFTP statuses too.
func (f *FS) resolve(ctx context.Context, p string) (location, error) {
	clean := path.Clean("/" + p)
	if hiddenPath(clean) {
		return location{}, sftp.ErrSSHFxNoSuchFile
	}
	if f.target != nil {
		return location{kind: kindRemote, namespace: f.target.Namespace, server: f.target.Server, rest: clean}, nil
	}
	parts := splitParts(clean)
	if len(parts) == 0 {
		return location{kind: kindRoot}, nil
	}
	if parts[0] != namespacesDir {
		return f.serverLocation(ctx, f.defNS, parts[0], parts[1:])
	}
	switch len(parts) {
	case 1:
		return location{kind: kindNamespaces}, nil
	case 2:
		ok, err := f.hasNamespace(ctx, parts[1])
		if err != nil {
			return location{}, f.fail("servers", err)
		}
		if !ok {
			return location{}, sftp.ErrSSHFxNoSuchFile
		}
		return location{kind: kindNamespace, namespace: parts[1]}, nil
	default:
		return f.serverLocation(ctx, parts[1], parts[2], parts[3:])
	}
}

// serverLocation resolves a server and the rest of the path below it.
func (f *FS) serverLocation(ctx context.Context, ns, server string, rest []string) (location, error) {
	ok, err := f.hasServer(ctx, ns, server)
	if err != nil {
		return location{}, f.fail("servers", err)
	}
	if !ok {
		return location{}, sftp.ErrSSHFxNoSuchFile
	}
	if len(rest) == 0 {
		return location{kind: kindServer, namespace: ns, server: server, rest: "/"}, nil
	}
	return location{kind: kindRemote, namespace: ns, server: server, rest: "/" + strings.Join(rest, "/")}, nil
}

// resolveWrite is resolve for a path that will be changed. Dotted names are
// refused as permission errors, and so are virtual nodes and server roots.
func (f *FS) resolveWrite(ctx context.Context, p string) (location, error) {
	if hiddenPath(path.Clean("/" + p)) {
		return location{}, sftp.ErrSSHFxPermissionDenied
	}
	loc, err := f.resolve(ctx, p)
	if err != nil {
		return location{}, err
	}
	if !loc.writable() {
		return location{}, sftp.ErrSSHFxPermissionDenied
	}
	return loc, nil
}

// inventory returns the servers the session may reach. It is cached for
// serverCacheTTL unless force is set.
func (f *FS) inventory(ctx context.Context, force bool) ([]apiclient.ServerRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !force && f.loaded && time.Since(f.loadedAt) < serverCacheTTL {
		return f.servers, nil
	}
	list, err := f.api.Servers(ctx, f.token)
	if err != nil {
		return nil, err
	}
	f.servers = list
	f.loaded = true
	f.loadedAt = time.Now()
	return list, nil
}

// hasServer reports whether the session may reach ns/server. Tree logins
// only; target logins never call this.
func (f *FS) hasServer(ctx context.Context, ns, server string) (bool, error) {
	list, err := f.inventory(ctx, false)
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.Namespace == ns && s.Server == server {
			return true, nil
		}
	}
	return false, nil
}

// hasNamespace reports whether any reachable server is in a namespace other
// than the default one and named ns.
func (f *FS) hasNamespace(ctx context.Context, ns string) (bool, error) {
	list, err := f.inventory(ctx, false)
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.Namespace == ns && ns != f.defNS {
			return true, nil
		}
	}
	return false, nil
}

// filesFor returns the API file handle for a remote location.
func (f *FS) filesFor(loc location) *apiclient.Files {
	return f.api.Files(f.token, loc.namespace, loc.server)
}

// virtualInfo describes a synthetic directory.
func (f *FS) virtualInfo(name string) fileInfo {
	return fileInfo{name: name, mode: fs.ModeDir | 0o755, modTime: f.started}
}

// statLocation answers a stat for a location. Virtual nodes never call the API.
func (f *FS) statLocation(ctx context.Context, loc location) (fileInfo, error) {
	switch loc.kind {
	case kindRoot:
		return f.virtualInfo("/"), nil
	case kindNamespaces:
		return f.virtualInfo(namespacesDir), nil
	case kindNamespace:
		return f.virtualInfo(loc.namespace), nil
	case kindServer:
		return f.virtualInfo(loc.server), nil
	default:
		e, err := f.filesFor(loc).Stat(ctx, loc.rest)
		if err != nil {
			return fileInfo{}, f.fail("stat", err)
		}
		info := entryInfo(e)
		if info.name == "" || info.name == "." {
			info.name = path.Base(loc.rest)
		}
		return info, nil
	}
}

// listLocation lists a directory location. Dotted names are filtered out.
func (f *FS) listLocation(ctx context.Context, loc location) ([]fileInfo, error) {
	switch loc.kind {
	case kindRoot:
		list, err := f.inventory(ctx, true)
		if err != nil {
			return nil, f.fail("list", err)
		}
		var out []fileInfo
		seenNS := false
		for _, s := range list {
			if s.Namespace == f.defNS {
				out = append(out, f.virtualInfo(s.Server))
			} else {
				seenNS = true
			}
		}
		if seenNS {
			out = append(out, f.virtualInfo(namespacesDir))
		}
		return sortInfos(out), nil
	case kindNamespaces:
		list, err := f.inventory(ctx, false)
		if err != nil {
			return nil, f.fail("list", err)
		}
		var out []fileInfo
		seen := map[string]bool{}
		for _, s := range list {
			if s.Namespace != f.defNS && !seen[s.Namespace] {
				seen[s.Namespace] = true
				out = append(out, f.virtualInfo(s.Namespace))
			}
		}
		return sortInfos(out), nil
	case kindNamespace:
		list, err := f.inventory(ctx, false)
		if err != nil {
			return nil, f.fail("list", err)
		}
		var out []fileInfo
		for _, s := range list {
			if s.Namespace == loc.namespace {
				out = append(out, f.virtualInfo(s.Server))
			}
		}
		return sortInfos(out), nil
	default:
		entries, err := f.filesFor(loc).List(ctx, loc.rest)
		if err != nil {
			return nil, f.fail("list", err)
		}
		out := make([]fileInfo, 0, len(entries))
		for _, e := range entries {
			info := entryInfo(e)
			if strings.HasPrefix(info.name, ".") {
				continue
			}
			out = append(out, info)
		}
		return sortInfos(out), nil
	}
}

// sortInfos orders directories first, then by name, so listings are stable.
func sortInfos(in []fileInfo) []fileInfo {
	slices.SortFunc(in, func(a, b fileInfo) int {
		if a.IsDir() != b.IsDir() {
			if a.IsDir() {
				return -1
			}
			return 1
		}
		return strings.Compare(a.name, b.name)
	})
	return in
}

// fileInfo is an os.FileInfo for one entry.
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

// Name implements os.FileInfo.
func (i fileInfo) Name() string { return i.name }

// Size implements os.FileInfo.
func (i fileInfo) Size() int64 { return i.size }

// Mode implements os.FileInfo.
func (i fileInfo) Mode() fs.FileMode { return i.mode }

// ModTime implements os.FileInfo.
func (i fileInfo) ModTime() time.Time { return i.modTime }

// IsDir implements os.FileInfo.
func (i fileInfo) IsDir() bool { return i.mode.IsDir() }

// Sys implements os.FileInfo. It is nil, so pkg/sftp reports uid and gid 0.
func (i fileInfo) Sys() any { return nil }

// entryInfo converts an API entry to a fileInfo.
func entryInfo(e apiclient.Entry) fileInfo {
	mode := e.FileMode()
	if e.Dir {
		mode |= os.ModeDir
	}
	name := e.Name
	if name == "" {
		name = path.Base(e.Path)
	}
	return fileInfo{name: name, size: e.Size, mode: mode, modTime: e.ModTime}
}

// listerAt serves a slice of infos to pkg/sftp in pieces.
type listerAt []os.FileInfo

// ListAt implements sftp.ListerAt. It returns io.EOF with the last entries.
func (l listerAt) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if off < 0 || off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[off:])
	if off+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

// infosToLister converts infos to a sftp.ListerAt.
func infosToLister(in []fileInfo) listerAt {
	out := make(listerAt, len(in))
	for i, info := range in {
		out[i] = info
	}
	return out
}

// count reports bytes moved in one direction when a hook is set.
func count(fn func(string, int), direction string, n int) {
	if fn != nil && n > 0 {
		fn(direction, n)
	}
}
