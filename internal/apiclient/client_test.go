package apiclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testServiceToken = "gpsftps_test"

// newTestClient returns a Client whose API is the plain-HTTP server h.
func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewWithHTTPClient(Config{BaseURL: srv.URL, ServiceToken: testServiceToken}, srv.Client())
	if err != nil {
		t.Fatalf("NewWithHTTPClient: %v", err)
	}
	return c
}

func assertBearer(t *testing.T, r *http.Request, want string) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+want {
		t.Errorf("Authorization = %q, want Bearer %s", got, want)
	}
}

// assertCommon checks what every request must look like: no cluster query
// parameter (the API derives it from the token) and no problem+json Accept.
func assertCommon(t *testing.T, r *http.Request) {
	t.Helper()
	if _, ok := r.URL.Query()["cluster"]; ok {
		t.Errorf("request sent a cluster query parameter: %s", r.URL.RawQuery)
	}
	if got := r.Header.Get("Accept"); strings.Contains(got, "problem+json") {
		t.Errorf("request sent Accept %q", got)
	}
}

func TestLoginSendsOnlyOneCredential(t *testing.T) {
	cases := []struct {
		name       string
		req        LoginRequest
		wantKey    string
		absentKey  string
		resp       string
		wantTarget *Target
	}{
		{
			name:       "password",
			req:        LoginRequest{Username: "alice+mods/survival", Password: "s3cret", RemoteAddr: "203.0.113.7:51234"},
			wantKey:    "password",
			absentKey:  "publicKey",
			resp:       `{"sessionToken":"gpsftp_abc","expiresAt":"2026-11-23T10:15:00Z","user":"alice","target":{"namespace":"mods","server":"survival"}}`,
			wantTarget: &Target{Namespace: "mods", Server: "survival"},
		},
		{
			name:       "public key",
			req:        LoginRequest{Username: "alice", PublicKey: "ssh-ed25519 AAAA", RemoteAddr: "203.0.113.7:51234"},
			wantKey:    "publicKey",
			absentKey:  "password",
			resp:       `{"sessionToken":"gpsftp_def","expiresAt":"2026-11-23T10:15:00Z","user":"alice","target":null}`,
			wantTarget: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/sftp/v1/login" {
					t.Errorf("got %s %s, want POST /sftp/v1/login", r.Method, r.URL.Path)
				}
				assertBearer(t, r, testServiceToken)
				assertCommon(t, r)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode body: %v", err)
				}
				if _, ok := body[tc.wantKey]; !ok {
					t.Errorf("body has no %q: %v", tc.wantKey, body)
				}
				if _, ok := body[tc.absentKey]; ok {
					t.Errorf("body unexpectedly has %q: %v", tc.absentKey, body)
				}
				if body["remoteAddr"] != "203.0.113.7:51234" {
					t.Errorf("remoteAddr = %v", body["remoteAddr"])
				}
				if _, err := w.Write([]byte(tc.resp)); err != nil {
					t.Errorf("write response: %v", err)
				}
			})
			sess, err := c.Login(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			if !strings.HasPrefix(sess.Token, "gpsftp_") {
				t.Errorf("Token = %q", sess.Token)
			}
			if !sess.ExpiresAt.Equal(time.Date(2026, 11, 23, 10, 15, 0, 0, time.UTC)) {
				t.Errorf("ExpiresAt = %v", sess.ExpiresAt)
			}
			if sess.User != "alice" {
				t.Errorf("User = %q", sess.User)
			}
			switch {
			case tc.wantTarget == nil && sess.Target != nil:
				t.Errorf("Target = %+v, want nil", *sess.Target)
			case tc.wantTarget != nil && (sess.Target == nil || *sess.Target != *tc.wantTarget):
				t.Errorf("Target = %+v, want %+v", sess.Target, *tc.wantTarget)
			}
		})
	}
}

func TestLoginErrorStatuses(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusTooManyRequests, ErrBusy},
		{http.StatusServiceUnavailable, ErrUnavailable},
	}
	for _, tc := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "invalid credentials", tc.status)
		})
		_, err := c.Login(context.Background(), LoginRequest{Username: "alice", Password: "x"})
		if !errors.Is(err, tc.want) {
			t.Fatalf("status %d: err = %v, want %v", tc.status, err, tc.want)
		}
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Status != tc.status {
			t.Fatalf("status %d: err = %#v, want *Error with that status", tc.status, err)
		}
	}
}

func TestLoginRejectsMissingServiceToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("no request expected without a service token")
	}))
	t.Cleanup(srv.Close)
	c, err := NewWithHTTPClient(Config{BaseURL: srv.URL}, srv.Client())
	if err != nil {
		t.Fatalf("NewWithHTTPClient: %v", err)
	}
	if _, err := c.Login(context.Background(), LoginRequest{Username: "alice", Password: "x"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Login err = %v, want ErrUnauthorized", err)
	}
}

func TestLoginRejectsBadResponse(t *testing.T) {
	bodies := []string{
		`{"sessionToken":"gpsftp_x","expiresAt":"soon","user":"alice"}`,
		`{"sessionToken":"","expiresAt":"2026-11-23T10:15:00Z","user":"alice"}`,
		`not json`,
	}
	for _, body := range bodies {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write: %v", err)
			}
		})
		if _, err := c.Login(context.Background(), LoginRequest{Username: "alice", Password: "x"}); !errors.Is(err, ErrFailure) {
			t.Fatalf("body %q: err = %v, want ErrFailure", body, err)
		}
	}
}

func TestCheckSessionsBatches(t *testing.T) {
	tokens := make([]string, 600)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("gpsftp_%03d", i)
	}
	var mu sync.Mutex
	var sizes []int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sftp/v1/sessions/check" {
			t.Errorf("path = %s", r.URL.Path)
		}
		assertBearer(t, r, testServiceToken)
		assertCommon(t, r)
		var in struct {
			SessionTokens []string `json:"sessionTokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode: %v", err)
		}
		mu.Lock()
		sizes = append(sizes, len(in.SessionTokens))
		mu.Unlock()
		// Report the first token of each batch as revoked.
		if _, err := fmt.Fprintf(w, `{"revoked":[%q]}`, in.SessionTokens[0]); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	revoked, err := c.CheckSessions(context.Background(), tokens)
	if err != nil {
		t.Fatalf("CheckSessions: %v", err)
	}
	if len(sizes) != 2 || sizes[0] != 500 || sizes[1] != 100 {
		t.Fatalf("batch sizes = %v, want [500 100]", sizes)
	}
	if len(revoked) != 2 || revoked[0] != "gpsftp_000" || revoked[1] != "gpsftp_500" {
		t.Fatalf("revoked = %v", revoked)
	}
}

func TestCheckSessionsEmptyMakesNoRequest(t *testing.T) {
	c := newTestClient(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("no request expected for empty input")
	})
	revoked, err := c.CheckSessions(context.Background(), nil)
	if err != nil || len(revoked) != 0 {
		t.Fatalf("CheckSessions(nil) = %v, %v", revoked, err)
	}
}

func TestServersDecodesItems(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/sftp/v1/servers" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		assertBearer(t, r, "gpsftp_s")
		assertCommon(t, r)
		if _, err := w.Write([]byte(`{"items":[{"namespace":"games","server":"survival"},{"namespace":"mods","server":"valheim"}]}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	got, err := c.Servers(context.Background(), "gpsftp_s")
	if err != nil {
		t.Fatalf("Servers: %v", err)
	}
	want := []ServerRef{{Namespace: "games", Server: "survival"}, {Namespace: "mods", Server: "valheim"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Servers = %+v, want %+v", got, want)
	}
	if _, err := c.Servers(context.Background(), ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Servers with empty token: err = %v, want ErrUnauthorized", err)
	}
}

func TestEntryFileMode(t *testing.T) {
	cases := []struct {
		mode string
		want os.FileMode
	}{
		{"drwxr-xr-x", os.ModeDir | 0o755},
		{"-rw-r--r--", 0o644},
		{"Lrwxrwxrwx", os.ModeSymlink | 0o777},
		{"-rwxrwxrwx", 0o777},
		{"", 0},
	}
	for _, tc := range cases {
		if got := (Entry{Mode: tc.mode}).FileMode(); got != tc.want {
			t.Errorf("FileMode(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestListStatDecodeEntries(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r, "gpsftp_tok")
		assertCommon(t, r)
		if r.URL.Query().Get("namespace") != "mods" {
			t.Errorf("namespace = %q", r.URL.Query().Get("namespace"))
		}
		if r.URL.Query().Get("path") != "/" {
			t.Errorf("path = %q", r.URL.Query().Get("path"))
		}
		switch r.URL.Path {
		case "/servers/survival/files/list":
			_, err := w.Write([]byte(`[
				{"name":"world","path":"/world","size":0,"mode":"drwxr-xr-x","dir":true,"modTime":"2026-11-23T10:00:00Z"},
				{"name":"server.properties","path":"/server.properties","size":123,"mode":"-rw-r--r--","dir":false,"modTime":"2026-11-23T10:00:00Z"},
				{"name":"link","path":"/link","size":0,"mode":"Lrwxrwxrwx","dir":false,"modTime":"not-a-time"}
			]`))
			if err != nil {
				t.Errorf("write: %v", err)
			}
		case "/servers/survival/files/stat":
			_, err := w.Write([]byte(`{"name":"","path":"/","size":0,"mode":"drwxr-xr-x","dir":true,"modTime":"2026-11-23T10:00:00Z"}`))
			if err != nil {
				t.Errorf("write: %v", err)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	f := c.Files("gpsftp_tok", "mods", "survival")
	entries, err := f.List(context.Background(), "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if entries[0].FileMode() != os.ModeDir|0o755 || !entries[0].Dir {
		t.Errorf("dir entry mode = %v", entries[0].FileMode())
	}
	if entries[1].FileMode() != 0o644 || entries[1].Size != 123 {
		t.Errorf("file entry = %+v", entries[1])
	}
	if !entries[1].ModTime.Equal(time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("file ModTime = %v", entries[1].ModTime)
	}
	if entries[2].FileMode() != os.ModeSymlink|0o777 {
		t.Errorf("symlink mode = %v", entries[2].FileMode())
	}
	if !entries[2].ModTime.IsZero() {
		t.Errorf("bad modTime should decode to zero, got %v", entries[2].ModTime)
	}

	root, err := f.Stat(context.Background(), "/")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if root.Path != "/" || root.Name != "" || !root.Dir {
		t.Errorf("Stat(/) = %+v", root)
	}
}

func TestEntryUnmarshalRejectsBadJSON(t *testing.T) {
	var e Entry
	if err := json.Unmarshal([]byte(`{"name":1}`), &e); err == nil {
		t.Fatal("expected decode error for wrong type")
	}
}

func TestDownloadOffsets(t *testing.T) {
	cases := []struct {
		name      string
		offset    int64
		wantRange string
		status    int
		serve     string
		want      string
	}{
		{"from start", 0, "", http.StatusOK, "hello world", "hello world"},
		{"range honoured", 5, "bytes=5-", http.StatusPartialContent, "world", "world"},
		{"range ignored", 5, "bytes=5-", http.StatusOK, "hello world", " world"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r, "gpsftp_tok")
				assertCommon(t, r)
				if got := r.Header.Get("Range"); got != tc.wantRange {
					t.Errorf("Range = %q, want %q", got, tc.wantRange)
				}
				if r.URL.Query().Get("path") != "/a.bin" {
					t.Errorf("path = %q", r.URL.Query().Get("path"))
				}
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.serve)); err != nil {
					t.Errorf("write: %v", err)
				}
			})
			rc, err := c.Files("gpsftp_tok", "mods", "survival").Download(context.Background(), "/a.bin", tc.offset)
			if err != nil {
				t.Fatalf("Download: %v", err)
			}
			defer func() { _ = rc.Close() }()
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("body = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDownloadErrors(t *testing.T) {
	t.Run("short body", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte("hello")); err != nil {
				t.Errorf("write: %v", err)
			}
		})
		_, err := c.Files("gpsftp_tok", "", "survival").Download(context.Background(), "/a.bin", 50)
		if !errors.Is(err, ErrFailure) {
			t.Fatalf("err = %v, want ErrFailure", err)
		}
	})
	t.Run("range beyond end", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		})
		_, err := c.Files("gpsftp_tok", "", "survival").Download(context.Background(), "/a.bin", 99)
		if !errors.Is(err, ErrBadOffset) {
			t.Fatalf("err = %v, want ErrBadOffset", err)
		}
	})
	t.Run("negative offset makes no request", func(t *testing.T) {
		c := newTestClient(t, func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("no request expected for a negative offset")
		})
		_, err := c.Files("gpsftp_tok", "", "survival").Download(context.Background(), "/a.bin", -1)
		if !errors.Is(err, ErrBadOffset) {
			t.Fatalf("err = %v, want ErrBadOffset", err)
		}
	})
}

func TestStreamUnknownLengthIsChunked(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/servers/survival/files/stream" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		assertBearer(t, r, "gpsftp_tok")
		assertCommon(t, r)
		q := r.URL.Query()
		if q.Get("path") != "/a/b" || q.Get("offset") != "0" || q.Get("namespace") != "mods" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		if r.ContentLength != -1 {
			t.Errorf("ContentLength = %d, want -1 (chunked)", r.ContentLength)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if string(body) != "payload" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	f := c.Files("gpsftp_tok", "mods", "survival")
	if err := f.Stream(context.Background(), "/a/b", 0, strings.NewReader("payload"), -1); err != nil {
		t.Fatalf("Stream: %v", err)
	}
}

func TestStreamKnownLengthAndOffset(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") != "3" {
			t.Errorf("offset = %q", r.URL.Query().Get("offset"))
		}
		if r.ContentLength != 7 {
			t.Errorf("ContentLength = %d, want 7", r.ContentLength)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if string(body) != "payload" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusOK)
	})
	err := c.Files("gpsftp_tok", "mods", "survival").Stream(context.Background(), "/a/b", 3, strings.NewReader("payload"), 7)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
}

func TestStreamStatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusBadRequest, ErrBadRequest},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrPermission},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusConflict, ErrExists},
		{http.StatusRequestEntityTooLarge, ErrTooLarge},
		{http.StatusRequestedRangeNotSatisfiable, ErrBadOffset},
		{http.StatusTooManyRequests, ErrBusy},
		{http.StatusBadGateway, ErrUnavailable},
		{http.StatusServiceUnavailable, ErrUnavailable},
		{http.StatusGatewayTimeout, ErrUnavailable},
		{http.StatusInsufficientStorage, ErrNoSpace},
		{http.StatusInternalServerError, ErrFailure},
		{http.StatusTeapot, ErrFailure},
	}
	for _, tc := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", tc.status)
		})
		err := c.Files("gpsftp_tok", "", "survival").Stream(context.Background(), "/a", 0, strings.NewReader("x"), -1)
		if !errors.Is(err, tc.want) {
			t.Fatalf("status %d: err = %v, want %v", tc.status, err, tc.want)
		}
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Status != tc.status || apiErr.Msg != "nope" {
			t.Fatalf("status %d: err = %#v, want *Error{Status: %d, Msg: nope}", tc.status, err, tc.status)
		}
	}
}

func TestRenameMkdirDelete(t *testing.T) {
	t.Run("rename without overwrite", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/servers/survival/files/rename" {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			assertBearer(t, r, "gpsftp_tok")
			assertCommon(t, r)
			if _, ok := r.URL.Query()["path"]; ok {
				t.Errorf("rename must not send path: %s", r.URL.RawQuery)
			}
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Errorf("decode: %v", err)
			}
			if in["from"] != "/a" || in["to"] != "/b" || in["overwrite"] != false {
				t.Errorf("body = %v", in)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := c.Files("gpsftp_tok", "mods", "survival").Rename(context.Background(), "/a", "/b", false); err != nil {
			t.Fatalf("Rename: %v", err)
		}
	})
	t.Run("rename with overwrite", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Errorf("decode: %v", err)
			}
			if in["overwrite"] != true {
				t.Errorf("overwrite = %v, want true", in["overwrite"])
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := c.Files("gpsftp_tok", "", "survival").Rename(context.Background(), "/a", "/b", true); err != nil {
			t.Fatalf("Rename: %v", err)
		}
	})
	t.Run("rename target exists", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "exists", http.StatusConflict)
		})
		if err := c.Files("gpsftp_tok", "", "survival").Rename(context.Background(), "/a", "/b", false); !errors.Is(err, ErrExists) {
			t.Fatalf("Rename err = %v, want ErrExists", err)
		}
	})
	t.Run("mkdir", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/servers/survival/files/mkdir" {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			if r.URL.Query().Get("path") != "/new/dir" {
				t.Errorf("path = %q", r.URL.Query().Get("path"))
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := c.Files("gpsftp_tok", "", "survival").Mkdir(context.Background(), "/new/dir"); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
	})
	t.Run("delete is never recursive", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/servers/survival/files/delete" {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			if _, ok := r.URL.Query()["recursive"]; ok {
				t.Errorf("delete sent recursive: %s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("path") != "/x" {
				t.Errorf("path = %q", r.URL.Query().Get("path"))
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := c.Files("gpsftp_tok", "", "survival").Delete(context.Background(), "/x"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	})
}

func TestNewValidatesBaseURL(t *testing.T) {
	for _, raw := range []string{"", "ftp://example.test", "https://", "://bad", "example.test:8080"} {
		if _, err := New(Config{BaseURL: raw}); err == nil {
			t.Errorf("New(%q) succeeded, want error", raw)
		}
	}
	c, err := New(Config{BaseURL: " https://api.example.test/ "})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.baseURL != "https://api.example.test" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.hc.Timeout != defaultTimeout {
		t.Errorf("default timeout = %v, want %v", c.hc.Timeout, defaultTimeout)
	}
	if c.streamHC.Timeout != 0 {
		t.Errorf("stream client timeout = %v, want none", c.streamHC.Timeout)
	}
	if _, err := NewWithHTTPClient(Config{BaseURL: "https://api.example.test"}, nil); err == nil {
		t.Error("NewWithHTTPClient with nil client succeeded")
	}
}

func TestNewCAFile(t *testing.T) {
	dir := t.TempDir()

	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New(Config{BaseURL: "https://api.example.test", CAFile: badPEM}); err == nil {
		t.Error("New with a PEM-free CA file succeeded")
	}
	if _, err := New(Config{BaseURL: "https://api.example.test", CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Error("New with a missing CA file succeeded")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"items":[]}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	caPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	trusted, err := New(Config{BaseURL: srv.URL, CAFile: caPEM, ServiceToken: testServiceToken})
	if err != nil {
		t.Fatalf("New with CA: %v", err)
	}
	if _, err := trusted.Servers(context.Background(), "gpsftp_x"); err != nil {
		t.Fatalf("Servers over trusted TLS: %v", err)
	}

	untrusted, err := New(Config{BaseURL: srv.URL, ServiceToken: testServiceToken})
	if err != nil {
		t.Fatalf("New without CA: %v", err)
	}
	if _, err := untrusted.Servers(context.Background(), "gpsftp_x"); err == nil {
		t.Error("Servers over an unknown certificate succeeded, want TLS failure")
	}
}

func TestLoadServiceToken(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte("  gpsftps_abc \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadServiceToken(good)
	if err != nil || got != "gpsftps_abc" {
		t.Fatalf("LoadServiceToken = %q, %v", got, err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadServiceToken(empty); err == nil {
		t.Error("empty token file accepted")
	}
	if _, err := LoadServiceToken(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing token file accepted")
	}
}

func TestErrorMessage(t *testing.T) {
	err := &Error{Status: http.StatusNotFound, Op: "stat", Msg: "no such file", Err: ErrNotFound}
	msg := err.Error()
	for _, want := range []string{"stat", "not found", "HTTP 404", "no such file"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, missing %q", msg, want)
		}
	}
	if !errors.Is(err, ErrNotFound) {
		t.Error("errors.Is(ErrNotFound) = false")
	}
}

func TestTrimMessage(t *testing.T) {
	if got := trimMessage([]byte("  hi \n")); got != "hi" {
		t.Errorf("trimMessage = %q", got)
	}
	long := strings.Repeat("a", 1000)
	if got := trimMessage([]byte(long)); len(got) != maxMessageLen {
		t.Errorf("len = %d, want %d", len(got), maxMessageLen)
	}
	if got := trimMessage([]byte{0xff, 'o', 'k'}); got != "ok" {
		t.Errorf("invalid UTF-8 not stripped: %q", got)
	}
}

func TestEndSessionSendsToken(t *testing.T) {
	var got struct {
		SessionTokens []string `json:"sessionTokens"`
	}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sftp/v1/sessions/end" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		assertBearer(t, r, testServiceToken)
		assertCommon(t, r)
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.EndSession(context.Background(), "gpsftp_x"); err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	if len(got.SessionTokens) != 1 || got.SessionTokens[0] != "gpsftp_x" {
		t.Fatalf("body tokens = %v", got.SessionTokens)
	}
}

func TestEndSessionErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := c.EndSession(context.Background(), "gpsftp_x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: err = %v, want ErrNotFound", err)
	}
	if err := c.EndSession(context.Background(), ""); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty token: err = %v, want ErrBadRequest", err)
	}
}
