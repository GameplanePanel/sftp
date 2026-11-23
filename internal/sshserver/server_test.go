package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/ssh"
)

// fakeAPI stands in for the Gameplane API. Successful logins mint a new
// token per call. The user is the part of the username before "+".
type fakeAPI struct {
	mu       sync.Mutex
	loginErr error
	logins   []apiclient.LoginRequest
	revoke   func(tokens []string) []string
	seq      int
}

func (f *fakeAPI) Login(_ context.Context, r apiclient.LoginRequest) (apiclient.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins = append(f.logins, r)
	if f.loginErr != nil {
		return apiclient.Session{}, f.loginErr
	}
	f.seq++
	user, target, hasTarget := strings.Cut(r.Username, "+")
	sess := apiclient.Session{
		Token:     fmt.Sprintf("gpsftp_test_%d", f.seq),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		User:      user,
	}
	if hasTarget {
		sess.Target = &apiclient.Target{Namespace: "games", Server: target}
	}
	return sess, nil
}

func (f *fakeAPI) CheckSessions(_ context.Context, tokens []string) ([]string, error) {
	f.mu.Lock()
	fn := f.revoke
	f.mu.Unlock()
	if fn == nil {
		return nil, nil
	}
	return fn(tokens), nil
}

func (f *fakeAPI) setRevoke(fn func([]string) []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoke = fn
}

func (f *fakeAPI) lastLogin(t *testing.T) apiclient.LoginRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.logins) == 0 {
		t.Fatal("no login reached the API")
	}
	return f.logins[len(f.logins)-1]
}

// testFS refuses every file operation except listing an empty root.
type testFS struct{}

func (testFS) Fileread(*sftp.Request) (io.ReaderAt, error) { return nil, sftp.ErrSSHFxOpUnsupported }
func (testFS) Filewrite(*sftp.Request) (io.WriterAt, error) {
	return nil, sftp.ErrSSHFxOpUnsupported
}
func (testFS) Filecmd(*sftp.Request) error                   { return sftp.ErrSSHFxOpUnsupported }
func (testFS) Filelist(*sftp.Request) (sftp.ListerAt, error) { return emptyLister{}, nil }

type emptyLister struct{}

func (emptyLister) ListAt([]os.FileInfo, int64) (int, error) { return 0, io.EOF }

func testHandlers(apiclient.Session, string) sftp.Handlers {
	fs := testFS{}
	return sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs}
}

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

type harness struct {
	t       *testing.T
	addr    string
	api     *fakeAPI
	metrics *Metrics
	reg     *prometheus.Registry
}

// newHarness starts a server on a loopback port and stops it at cleanup.
func newHarness(t *testing.T, mutate func(*Config), api *fakeAPI) *harness {
	t.Helper()
	return newHarnessWith(t, mutate, api, testHandlers)
}

// newHarnessWith is newHarness with a custom SFTP handler factory.
func newHarnessWith(t *testing.T, mutate func(*Config), api *fakeAPI, hf HandlerFactory) *harness {
	t.Helper()
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	cfg := Config{
		HostKeys:      []ssh.Signer{newEd25519Signer(t)},
		CheckInterval: time.Hour,
		Logger:        slog.New(slog.DiscardHandler),
		Metrics:       m,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg, api, hf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return &harness{t: t, addr: l.Addr().String(), api: api, metrics: m, reg: reg}
}

func (h *harness) dialErr(user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

func (h *harness) mustDial(user string, auth ...ssh.AuthMethod) *ssh.Client {
	h.t.Helper()
	c, err := h.dialErr(user, auth...)
	if err != nil {
		h.t.Fatalf("dial as %q: %v", user, err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	return c
}

// readRoot opens the SFTP subsystem and lists "/".
func readRoot(c *ssh.Client) error {
	sc, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()
	_, err = sc.ReadDir("/")
	return err
}

func waitClosed(t *testing.T, c *ssh.Client) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = c.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not closed")
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPasswordLoginServesSFTP(t *testing.T) {
	api := &fakeAPI{}
	h := newHarness(t, nil, api)
	c := h.mustDial("alice+mods/survival", ssh.Password("pw"))
	if err := readRoot(c); err != nil {
		t.Fatalf("sftp ReadDir: %v", err)
	}
	got := api.lastLogin(t)
	if got.Username != "alice+mods/survival" || got.Password != "pw" || got.PublicKey != "" || got.RemoteAddr == "" {
		t.Fatalf("login request = %+v", got)
	}
}

func TestWrongPasswordIsGenericallyDenied(t *testing.T) {
	h := newHarness(t, nil, &fakeAPI{loginErr: apiclient.ErrUnauthorized})
	_, err := h.dialErr("alice", ssh.Password("wrong"))
	if err == nil {
		t.Fatal("dial succeeded with a refused password")
	}
	if strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("auth error leaks the cause: %v", err)
	}
	if got := testutil.ToFloat64(h.metrics.logins.WithLabelValues(loginDenied)); got != 1 {
		t.Fatalf("denied logins = %v, want 1", got)
	}
}

func TestAPIFailureCountsAsError(t *testing.T) {
	h := newHarness(t, nil, &fakeAPI{loginErr: errors.New("api down")})
	if _, err := h.dialErr("alice", ssh.Password("pw")); err == nil {
		t.Fatal("dial succeeded when the API failed")
	}
	if got := testutil.ToFloat64(h.metrics.logins.WithLabelValues(loginError)); got != 1 {
		t.Fatalf("error logins = %v, want 1", got)
	}
}

func TestPublicKeyLoginSendsVerifiedKey(t *testing.T) {
	clientKey := newEd25519Signer(t)
	api := &fakeAPI{}
	h := newHarness(t, nil, api)
	c := h.mustDial("bob", ssh.PublicKeys(clientKey))
	if err := readRoot(c); err != nil {
		t.Fatalf("sftp ReadDir: %v", err)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(clientKey.PublicKey())))
	got := api.lastLogin(t)
	if got.PublicKey != want || got.Password != "" {
		t.Fatalf("login request = %+v, want public key %q", got, want)
	}
}

func TestRefusedPublicKeyClosesConnection(t *testing.T) {
	h := newHarness(t, nil, &fakeAPI{loginErr: apiclient.ErrUnauthorized})
	c, err := h.dialErr("bob", ssh.PublicKeys(newEd25519Signer(t)))
	if err == nil {
		// Key auth completes in the SSH layer before the API check, so the
		// server closes the connection right after it. The SFTP layer then
		// fails.
		defer func() { _ = c.Close() }()
		if readRoot(c) == nil {
			t.Fatal("sftp worked for a refused key")
		}
	}
}

func TestNonSFTPRequestsAreRefused(t *testing.T) {
	h := newHarness(t, nil, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))

	if s, err := c.NewSession(); err == nil {
		if err := s.Shell(); err == nil {
			t.Error("shell was accepted")
		}
		_ = s.Close()
	}
	if s, err := c.NewSession(); err == nil {
		if err := s.Run("ls"); err == nil {
			t.Error("exec was accepted")
		}
		_ = s.Close()
	}
	if s, err := c.NewSession(); err == nil {
		if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
			t.Error("pty was accepted")
		}
		_ = s.Close()
	}
	if s, err := c.NewSession(); err == nil {
		if err := s.RequestSubsystem("scp"); err == nil {
			t.Error("non-sftp subsystem was accepted")
		}
		_ = s.Close()
	}
	if conn, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		_ = conn.Close()
		t.Error("direct-tcpip channel was accepted")
	}
	if l, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = l.Close()
		t.Error("tcpip-forward was accepted")
	}
}

func TestSecondSFTPSubsystemIsRefused(t *testing.T) {
	h := newHarness(t, nil, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	sc, err := sftp.NewClient(c)
	if err != nil {
		t.Fatalf("first sftp: %v", err)
	}
	defer func() { _ = sc.Close() }()
	s, err := c.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RequestSubsystem("sftp"); err == nil {
		t.Fatal("second sftp subsystem was accepted")
	}
}

func TestRevokedSessionIsClosed(t *testing.T) {
	api := &fakeAPI{}
	h := newHarness(t, func(c *Config) { c.CheckInterval = 20 * time.Millisecond }, api)
	c := h.mustDial("alice", ssh.Password("pw"))
	if err := readRoot(c); err != nil {
		t.Fatalf("sftp ReadDir: %v", err)
	}
	api.setRevoke(func(tokens []string) []string { return tokens })
	waitClosed(t, c)
	eventually(t, "session gauge back to 0", func() bool {
		return testutil.ToFloat64(h.metrics.sessions) == 0
	})
	if got := testutil.ToFloat64(h.metrics.revokes); got != 1 {
		t.Fatalf("revoked_total = %v, want 1", got)
	}
}

func TestConnectionSurvivesChecksWithoutRevocation(t *testing.T) {
	api := &fakeAPI{}
	h := newHarness(t, func(c *Config) { c.CheckInterval = 20 * time.Millisecond }, api)
	c := h.mustDial("alice", ssh.Password("pw"))
	// Several check runs pass with nothing revoked; the connection must
	// stay open across them.
	time.Sleep(100 * time.Millisecond)
	if err := readRoot(c); err != nil {
		t.Fatalf("connection dropped after checks: %v", err)
	}
}

func TestSessionCapPerUser(t *testing.T) {
	api := &fakeAPI{}
	h := newHarness(t, func(c *Config) { c.MaxSessionsPerUser = 2 }, api)

	a1 := h.mustDial("alice", ssh.Password("pw"))
	if err := readRoot(a1); err != nil {
		t.Fatalf("alice 1: %v", err)
	}
	a2 := h.mustDial("alice", ssh.Password("pw"))
	if err := readRoot(a2); err != nil {
		t.Fatalf("alice 2: %v", err)
	}
	if _, err := h.dialErr("alice", ssh.Password("pw")); err == nil {
		t.Fatal("third connection for alice was accepted")
	}
	if got := testutil.ToFloat64(h.metrics.logins.WithLabelValues(loginLimit)); got < 1 {
		t.Fatalf("limit logins = %v, want at least 1", got)
	}

	bob := h.mustDial("bob", ssh.Password("pw"))
	if err := readRoot(bob); err != nil {
		t.Fatalf("bob should not share alice's cap: %v", err)
	}

	_ = a1.Close()
	eventually(t, "a slot to be freed", func() bool {
		c, err := h.dialErr("alice", ssh.Password("pw"))
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
}

func TestIdleConnectionIsClosed(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.IdleTimeout = 200 * time.Millisecond }, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	waitClosed(t, c)
}

func TestHandshakeIdleIsClosed(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.LoginTimeout = 100 * time.Millisecond }, &fakeAPI{})
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if err := raw.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	// The server sends its banner first. After that it must hang up on a
	// client that never sends a version of its own.
	buf := make([]byte, 1)
	for {
		if _, err := raw.Read(buf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("silent pre-auth connection was not closed")
			}
			return
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	key := newEd25519Signer(t)
	api := &fakeAPI{}
	cases := map[string]struct {
		cfg Config
		api API
		hf  HandlerFactory
	}{
		"nil api":        {Config{HostKeys: []ssh.Signer{key}}, nil, testHandlers},
		"nil handlers":   {Config{HostKeys: []ssh.Signer{key}}, api, nil},
		"no host keys":   {Config{}, api, testHandlers},
		"negative idle":  {Config{HostKeys: []ssh.Signer{key}, IdleTimeout: -1}, api, testHandlers},
		"negative cap":   {Config{HostKeys: []ssh.Signer{key}, MaxSessionsPerUser: -1}, api, testHandlers},
		"negative check": {Config{HostKeys: []ssh.Signer{key}, CheckInterval: -time.Second}, api, testHandlers},
	}
	for name, tc := range cases {
		if _, err := New(tc.cfg, tc.api, tc.hf); err == nil {
			t.Errorf("%s: New accepted the config", name)
		}
	}
}

func TestServeRejectsSecondCall(t *testing.T) {
	srv, err := New(Config{HostKeys: []ssh.Signer{newEd25519Signer(t)}}, &fakeAPI{}, testHandlers)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.Addr() != nil {
		t.Fatal("Addr before Serve should be nil")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	eventually(t, "Addr to be set", func() bool { return srv.Addr() != nil })
	if err := srv.Serve(ctx, l); err == nil {
		t.Error("second Serve call succeeded")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned %v after cancel", err)
	}
}

func TestSessionExtensionsRoundTrip(t *testing.T) {
	want := apiclient.Session{
		Token:     "gpsftp_x",
		ExpiresAt: time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC),
		User:      "alice",
		Target:    &apiclient.Target{Namespace: "mods", Server: "survival"},
	}
	got, err := sessionFromExtensions(sessionExtensions(want))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got.Token != want.Token || !got.ExpiresAt.Equal(want.ExpiresAt) || got.User != want.User || *got.Target != *want.Target {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	want.Target = nil
	got, err = sessionFromExtensions(sessionExtensions(want))
	if err != nil || got.Target != nil {
		t.Fatalf("round trip without target = %+v, %v", got, err)
	}
	if _, err := sessionFromExtensions(map[string]string{}); err == nil {
		t.Error("missing token accepted")
	}
	if _, err := sessionFromExtensions(map[string]string{extSessionToken: "t", extExpiresAt: "soon"}); err == nil {
		t.Error("bad expiresAt accepted")
	}
}

func TestMetricsRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	if _, err := NewMetrics(reg); err == nil {
		t.Error("registering the same metrics twice succeeded")
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{"gameplane_sftp_sessions", "gameplane_sftp_logins_total", "gameplane_sftp_revoked_total", "gameplane_sftp_bytes_total"} {
		if !names[want] {
			t.Errorf("metric %s not exposed", want)
		}
	}
	m.AddBytes("write", 5)
	m.AddBytes("write", 0)
	m.AddBytes("read", -3)
	if got := testutil.ToFloat64(m.bytes.WithLabelValues("write")); got != 5 {
		t.Fatalf("bytes write = %v, want 5", got)
	}
}

func TestNilMetricsAreSafe(t *testing.T) {
	var m *Metrics
	m.AddBytes("read", 10)
	m.login(loginOK)
	m.sessionOpened()
	m.sessionClosed()
	m.revoked()
}

func writeKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func TestLoadHostKeysFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_host_ed25519_key")
	writeKey(t, path)
	signers, err := LoadHostKeys(path)
	if err != nil || len(signers) != 1 {
		t.Fatalf("LoadHostKeys(file) = %d keys, %v", len(signers), err)
	}
}

func TestLoadHostKeysSecretLayout(t *testing.T) {
	dir := t.TempDir()
	// Kubernetes Secret volumes: a hidden ..data link to a timestamped
	// directory, with the visible names as links into it.
	writeKey(t, filepath.Join(dir, "..2026_11_23", "ssh_host_ed25519_key"))
	if err := os.Symlink("..2026_11_23", filepath.Join(dir, "..data")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "ssh_host_ed25519_key"), filepath.Join(dir, "ssh_host_ed25519_key")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), []byte("ssh-ed25519 AAAA"), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	signers, err := LoadHostKeys(dir)
	if err != nil || len(signers) != 1 {
		t.Fatalf("LoadHostKeys(secret dir) = %d keys, %v; want 1", len(signers), err)
	}
}

func TestLoadHostKeysErrors(t *testing.T) {
	if _, err := LoadHostKeys(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing path accepted")
	}
	empty := t.TempDir()
	if _, err := LoadHostKeys(empty); err == nil {
		t.Error("empty directory accepted")
	}
	junk := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(junk, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadHostKeys(junk); err == nil {
		t.Error("unparseable key accepted")
	}
}
