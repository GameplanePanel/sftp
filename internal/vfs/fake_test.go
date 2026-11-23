package vfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

const (
	testToken = "gpsftp_test"
	testNS    = DefaultNamespace
	otherNS   = "mods"
)

// SFTP open and attribute flag bits, as sent on the wire.
const (
	fxfRead   = 0x01
	fxfWrite  = 0x02
	fxfAppend = 0x04
	fxfCreat  = 0x08
	fxfTrunc  = 0x10
	fxfExcl   = 0x20

	attrSize    = 0x01
	attrUIDGID  = 0x02
	attrPerm    = 0x04
	attrModTime = 0x08
)

var fixedTime = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

// testServers are the servers every tree test starts from: one in the default
// namespace and one in another namespace.
var testServers = []apiclient.ServerRef{
	{Namespace: testNS, Server: "survival"},
	{Namespace: otherNS, Server: "modded"},
}

type node struct {
	dir  bool
	data []byte
	mod  time.Time
}

// stats is a copy of the fake's call counters, taken under its lock.
type stats struct {
	serversCalls  int
	downloads     int
	ranges        []string
	streamQueries []url.Values
	deletes       []url.Values
}

// fakeAPI is an in-memory stand-in for the Gameplane API's SFTP file routes.
// It keeps one tree per namespace and server. Like the real agent, it commits
// an upload only when the body ends cleanly.
type fakeAPI struct {
	srv *httptest.Server

	mu         sync.Mutex
	servers    []apiclient.ServerRef
	trees      map[string]map[string]*node
	streamFail int // when non-zero, PUT answers this status without committing
	st         stats
}

func newFakeAPI(t *testing.T, servers []apiclient.ServerRef) *fakeAPI {
	t.Helper()
	f := &fakeAPI{servers: servers, trees: map[string]map[string]*node{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// client returns a real apiclient.Client aimed at the fake.
func (f *fakeAPI) client(t *testing.T) *apiclient.Client {
	t.Helper()
	c, err := apiclient.NewWithHTTPClient(apiclient.Config{BaseURL: f.srv.URL, ServiceToken: "gpsftps_test"}, f.srv.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

// tree returns the node map for ns/server, creating the root. Caller holds mu.
func (f *fakeAPI) tree(ns, server string) map[string]*node {
	key := ns + "/" + server
	m, ok := f.trees[key]
	if !ok {
		m = map[string]*node{"/": {dir: true, mod: fixedTime}}
		f.trees[key] = m
	}
	return m
}

// seedFile creates a file, and any missing parent folders, before a test runs.
func (f *fakeAPI) seedFile(ns, server, p string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.tree(ns, server)
	ensureParents(m, p)
	m[p] = &node{data: append([]byte(nil), data...), mod: fixedTime}
}

// seedDir creates a folder, and any missing parents, before a test runs.
func (f *fakeAPI) seedDir(ns, server, p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.tree(ns, server)
	ensureParents(m, p)
	m[p] = &node{dir: true, mod: fixedTime}
}

// has reports whether a path exists in ns/server.
func (f *fakeAPI) has(ns, server, p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.tree(ns, server)[p]
	return ok
}

// fileData returns a committed file's bytes.
func (f *fakeAPI) fileData(ns, server, p string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.tree(ns, server)[p]
	if !ok || n.dir {
		return nil, false
	}
	return n.data, true
}

// setStreamFail makes every later PUT fail with status code, without committing.
func (f *fakeAPI) setStreamFail(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streamFail = code
}

// snapshot copies the call counters.
func (f *fakeAPI) snapshot() stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.st
	s.ranges = append([]string(nil), f.st.ranges...)
	s.streamQueries = append([]url.Values(nil), f.st.streamQueries...)
	s.deletes = append([]url.Values(nil), f.st.deletes...)
	return s
}

// ensureParents creates the folders above p that do not exist yet.
func ensureParents(m map[string]*node, p string) {
	for d := path.Dir(p); ; d = path.Dir(d) {
		if _, ok := m[d]; !ok {
			m[d] = &node{dir: true, mod: fixedTime}
		}
		if d == "/" || d == "." {
			return
		}
	}
}

// hasChildren reports whether anything lies below dir.
func hasChildren(m map[string]*node, dir string) bool {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for k := range m {
		if k != dir && strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// wireEntry is the JSON shape of the API's Entry.
type wireEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	Dir     bool   `json:"dir"`
	ModTime string `json:"modTime"`
}

func toWire(p string, n *node) wireEntry {
	mode := "-rw-r--r--"
	if n.dir {
		mode = "drwxr-xr-x"
	}
	name := path.Base(p)
	if p == "/" {
		name = ""
	}
	mt := n.mod
	if mt.IsZero() {
		mt = fixedTime
	}
	return wireEntry{Name: name, Path: p, Size: int64(len(n.data)), Mode: mode, Dir: n.dir, ModTime: mt.UTC().Format(time.RFC3339)}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// serve routes the SFTP-facing API paths. It holds mu for the whole request.
func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/sftp/v1/servers" {
		f.st.serversCalls++
		items := f.servers
		if items == nil {
			items = []apiclient.ServerRef{}
		}
		writeJSON(w, map[string]any{"items": items})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "servers" || parts[2] != "files" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if q.Has("cluster") {
		http.Error(w, "cluster is not a client parameter", http.StatusBadRequest)
		return
	}
	ns := q.Get("namespace")
	if ns == "" {
		ns = testNS
	}
	server := parts[1]
	if !f.serverExists(ns, server) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	want := map[string]string{
		"list": http.MethodGet, "stat": http.MethodGet, "download": http.MethodGet,
		"mkdir": http.MethodPost, "rename": http.MethodPost,
		"delete": http.MethodDelete, "stream": http.MethodPut,
	}[parts[3]]
	if want == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != want {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean("/" + q.Get("path"))
	m := f.tree(ns, server)
	switch parts[3] {
	case "list":
		f.list(w, m, p)
	case "stat":
		n, ok := m[p]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, toWire(p, n))
	case "download":
		f.download(w, r, m, p)
	case "mkdir":
		f.mkdir(w, m, p)
	case "rename":
		f.rename(w, r, m)
	case "delete":
		f.delete(w, m, p, q)
	case "stream":
		f.stream(w, r, m, p, q)
	}
}

func (f *fakeAPI) serverExists(ns, server string) bool {
	for _, s := range f.servers {
		if s.Namespace == ns && s.Server == server {
			return true
		}
	}
	return false
}

func (f *fakeAPI) list(w http.ResponseWriter, m map[string]*node, p string) {
	n, ok := m[p]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !n.dir {
		http.Error(w, "not a directory", http.StatusBadRequest)
		return
	}
	out := []wireEntry{}
	for k, c := range m {
		if k == "/" || path.Dir(k) != p || strings.HasPrefix(path.Base(k), ".") {
			continue
		}
		out = append(out, toWire(k, c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, out)
}

func (f *fakeAPI) download(w http.ResponseWriter, r *http.Request, m map[string]*node, p string) {
	n, ok := m[p]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if n.dir {
		http.Error(w, "is a directory", http.StatusBadRequest)
		return
	}
	f.st.downloads++
	f.st.ranges = append(f.st.ranges, r.Header.Get("Range"))
	http.ServeContent(w, r, path.Base(p), n.mod, bytes.NewReader(n.data))
}

func (f *fakeAPI) mkdir(w http.ResponseWriter, m map[string]*node, p string) {
	if n, ok := m[p]; ok {
		if n.dir {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "exists", http.StatusConflict)
		return
	}
	ensureParents(m, p)
	m[p] = &node{dir: true, mod: time.Now()}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeAPI) rename(w http.ResponseWriter, r *http.Request, m map[string]*node) {
	var in struct {
		From      string `json:"from"`
		To        string `json:"to"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	from := path.Clean("/" + in.From)
	to := path.Clean("/" + in.To)
	if from == "/" || to == "/" {
		http.Error(w, "root", http.StatusBadRequest)
		return
	}
	if _, ok := m[from]; !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, ok := m[to]; ok {
		if !in.Overwrite {
			http.Error(w, "exists", http.StatusConflict)
			return
		}
		for k := range m {
			if k == to || strings.HasPrefix(k, to+"/") {
				delete(m, k)
			}
		}
	}
	var moved []string
	for k := range m {
		if k == from || strings.HasPrefix(k, from+"/") {
			moved = append(moved, k)
		}
	}
	for _, k := range moved {
		n := m[k]
		delete(m, k)
		m[to+strings.TrimPrefix(k, from)] = n
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeAPI) delete(w http.ResponseWriter, m map[string]*node, p string, q url.Values) {
	if p == "/" {
		http.Error(w, "root", http.StatusBadRequest)
		return
	}
	n, ok := m[p]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if n.dir && hasChildren(m, p) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	delete(m, p)
	f.st.deletes = append(f.st.deletes, q)
	w.WriteHeader(http.StatusNoContent)
}

// stream reads the whole body, then commits it. It commits nothing when the
// body ends in an error, which is how an aborted upload stays uncommitted.
func (f *fakeAPI) stream(w http.ResponseWriter, r *http.Request, m map[string]*node, p string, q url.Values) {
	off, err := strconv.ParseInt(q.Get("offset"), 10, 64)
	if err != nil || off < 0 {
		http.Error(w, "bad offset", http.StatusBadRequest)
		return
	}
	if n, ok := m[p]; ok && n.dir {
		http.Error(w, "is a directory", http.StatusBadRequest)
		return
	}
	var prefix []byte
	if off > 0 {
		n, ok := m[p]
		if !ok || off > int64(len(n.data)) {
			http.Error(w, "bad offset", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		prefix = n.data[:off]
	}
	f.st.streamQueries = append(f.st.streamQueries, q)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body read", http.StatusBadRequest)
		return
	}
	if f.streamFail != 0 {
		http.Error(w, "injected", f.streamFail)
		return
	}
	data := append(append([]byte(nil), prefix...), body...)
	ensureParents(m, p)
	m[p] = &node{data: data, mod: time.Now()}
	w.WriteHeader(http.StatusNoContent)
}

// fixture is one FS on top of a fresh fake API.
type fixture struct {
	api *fakeAPI
	fs  *FS
}

func newFixture(t *testing.T, target *apiclient.Target, opts Options, servers []apiclient.ServerRef) fixture {
	t.Helper()
	api := newFakeAPI(t, servers)
	sess := apiclient.Session{Token: testToken, User: "Alice", Target: target}
	return fixture{api: api, fs: New(api.client(t), sess, opts)}
}

// opReq is a request for a path-only operation.
func opReq(method, p string) *sftp.Request {
	return &sftp.Request{Method: method, Filepath: p}
}

// openReq is a Put or Get request carrying open flags.
func openReq(p string, flags uint32) *sftp.Request {
	return &sftp.Request{Method: "Put", Filepath: p, Flags: flags}
}

// listNames lists everything a ListerAt holds, following pkg/sftp's paging.
func listNames(t *testing.T, l sftp.ListerAt) []os.FileInfo {
	t.Helper()
	var out []os.FileInfo
	buf := make([]os.FileInfo, 4)
	var off int64
	for {
		n, err := l.ListAt(buf, off)
		out = append(out, buf[:n]...)
		off += int64(n)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("ListAt: %v", err)
		}
		if n == 0 {
			t.Fatal("ListAt made no progress")
		}
	}
}

// names returns the names of a ListerAt's entries.
func names(t *testing.T, l sftp.ListerAt) []string {
	t.Helper()
	var out []string
	for _, fi := range listNames(t, l) {
		out = append(out, fi.Name())
	}
	return out
}
