// Package sshserver accepts SSH connections, authenticates them through the
// Gameplane API and serves the SFTP subsystem and nothing else. Every other
// channel type and request (shell, exec, pty, forwarding) is refused. See
// specs.md for the contract.
package sshserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultAddr          = ":2222"
	defaultIdleTimeout   = 15 * time.Minute
	defaultMaxSessions   = 4
	defaultCheckInterval = 30 * time.Second
	defaultLoginTimeout  = 10 * time.Second
	acceptRetryDelay     = 100 * time.Millisecond
	serverVersion        = "SSH-2.0-Gameplane-SFTP"
	maxAuthTries         = 3
	sftpSubsystem        = "sftp"

	extSessionToken = "sessionToken"
	extUser         = "user"
	extNamespace    = "namespace"
	extServer       = "server"
	extExpiresAt    = "expiresAt"
	extPublicKey    = "publicKey"
)

// errPermissionDenied is the only authentication error the SSH client ever
// sees. It never says why a login failed (core rule 3).
var errPermissionDenied = errors.New("permission denied")

// API is the part of the Gameplane API client the server needs. *apiclient.Client
// satisfies it.
type API interface {
	Login(ctx context.Context, r apiclient.LoginRequest) (apiclient.Session, error)
	CheckSessions(ctx context.Context, tokens []string) ([]string, error)
}

// HandlerFactory builds the SFTP request handlers for one authenticated
// SFTP subsystem. user is the login name the API returned.
type HandlerFactory func(sess apiclient.Session, user string) sftp.Handlers

// Config configures a Server. Zero values take the defaults documented on
// each field.
type Config struct {
	// Addr is the listen address the caller binds. Serve takes the listener,
	// so Addr is informational. Default ":2222".
	Addr string
	// HostKeys are the server's host keys. At least one is required.
	HostKeys []ssh.Signer
	// IdleTimeout closes an authenticated connection with no traffic for
	// this long. Default 15m.
	IdleTimeout time.Duration
	// MaxSessionsPerUser caps concurrent authenticated connections per user.
	// Default 4.
	MaxSessionsPerUser int
	// CheckInterval is how often the server asks the API which of its
	// session tokens were revoked. Default 30s.
	CheckInterval time.Duration
	// LoginTimeout bounds each API call and the SSH handshake before
	// authentication completes. Default 10s.
	LoginTimeout time.Duration
	// Logger receives operational logs. Never passwords, tokens or keys.
	Logger *slog.Logger
	// Metrics receives counters and gauges. Nil disables them.
	Metrics *Metrics
}

// Server is an SSH server that serves SFTP for authenticated users.
type Server struct {
	cfg     Config
	api     API
	hf      HandlerFactory
	sshCfg  *ssh.ServerConfig
	log     *slog.Logger
	metrics *Metrics

	mu       sync.Mutex
	listener net.Listener
	open     map[net.Conn]struct{} // every accepted connection, until it ends
	tokens   map[string]*connState // session token -> authenticated connection
	perUser  map[string]int        // lowercased user -> authenticated connections
	closing  bool                  // set once Serve's context ends
}

// New validates cfg and returns a Server. It does not listen.
func New(cfg Config, api API, hf HandlerFactory) (*Server, error) {
	if api == nil {
		return nil, errors.New("sshserver: nil API client")
	}
	if hf == nil {
		return nil, errors.New("sshserver: nil handler factory")
	}
	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("sshserver: no host keys")
	}
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		api:     api,
		hf:      hf,
		log:     cfg.Logger,
		metrics: cfg.Metrics,
		open:    make(map[net.Conn]struct{}),
		tokens:  make(map[string]*connState),
		perUser: make(map[string]int),
	}
	sc := &ssh.ServerConfig{
		PasswordCallback:  s.passwordCallback,
		PublicKeyCallback: s.publicKeyCallback,
		MaxAuthTries:      maxAuthTries,
		ServerVersion:     serverVersion,
	}
	for _, k := range cfg.HostKeys {
		sc.AddHostKey(k)
	}
	s.sshCfg = sc
	return s, nil
}

func (c Config) withDefaults() (Config, error) {
	if c.Addr == "" {
		c.Addr = defaultAddr
	}
	if c.IdleTimeout < 0 || c.CheckInterval < 0 || c.LoginTimeout < 0 {
		return c, errors.New("sshserver: negative timeout")
	}
	if c.MaxSessionsPerUser < 0 {
		return c, errors.New("sshserver: negative session cap")
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.MaxSessionsPerUser == 0 {
		c.MaxSessionsPerUser = defaultMaxSessions
	}
	if c.CheckInterval == 0 {
		c.CheckInterval = defaultCheckInterval
	}
	if c.LoginTimeout == 0 {
		c.LoginTimeout = defaultLoginTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c, nil
}

// Addr returns the address Serve is listening on, or nil before Serve starts.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts connections on l until ctx ends. On shutdown it closes the
// listener and every open connection, waits for them to finish, and returns
// nil. It also runs the revocation check loop for the duration.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return errors.New("sshserver: already serving")
	}
	s.listener = l
	s.mu.Unlock()

	stop := context.AfterFunc(ctx, s.shutdown)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.checkLoop(ctx)
	}()

	var acceptErr error
	for {
		raw, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, net.ErrClosed) {
				acceptErr = fmt.Errorf("accept: %w", err)
				break
			}
			s.log.Warn("accept failed", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(acceptRetryDelay):
			}
			continue
		}
		if !s.track(raw) {
			_ = raw.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(raw)
			s.handle(ctx, raw)
		}()
	}
	s.shutdown()
	wg.Wait()
	return acceptErr
}

// shutdown closes the listener and every open connection and marks the
// server closing so no new connection is tracked.
func (s *Server) shutdown() {
	s.mu.Lock()
	s.closing = true
	l := s.listener
	conns := make([]net.Conn, 0, len(s.open))
	for c := range s.open {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.open[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, c)
}

// connState is one authenticated connection.
type connState struct {
	sconn       *ssh.ServerConn
	sess        apiclient.Session
	user        string // API user name as returned by login
	key         string // lowercased user, the per-user cap key
	sftpStarted atomic.Bool
	revoked     atomic.Bool
}

// handle runs one TCP connection from handshake to close.
func (s *Server) handle(ctx context.Context, raw net.Conn) {
	remote := raw.RemoteAddr().String()
	dc := &deadlineConn{Conn: raw}
	dc.idle.Store(int64(s.cfg.LoginTimeout))

	sconn, chans, reqs, err := ssh.NewServerConn(dc, s.sshCfg)
	if err != nil {
		s.log.Debug("ssh handshake ended", "remote", remote, "err", err)
		_ = raw.Close()
		return
	}
	defer func() { _ = sconn.Close() }()

	// The SSH mux is already blocked in a read whose deadline came from the
	// handshake. Push it out so a public-key login call to the API, which may
	// take up to LoginTimeout, is not cut off by it.
	dc.idle.Store(int64(max(s.cfg.IdleTimeout, s.cfg.LoginTimeout)))
	dc.touch()
	sess, err := s.establish(ctx, sconn)
	if err != nil {
		return
	}
	// Switch to the idle timeout now.
	dc.idle.Store(int64(s.cfg.IdleTimeout))
	dc.touch()

	st := &connState{sconn: sconn, sess: sess, user: sess.User, key: strings.ToLower(sess.User)}
	if !s.admit(st) {
		s.metrics.login(loginLimit)
		s.log.Info("login refused", "user", st.user, "remote", remote, "result", loginLimit)
		return
	}
	defer s.release(st)
	s.metrics.login(loginOK)
	s.metrics.sessionOpened()
	defer s.metrics.sessionClosed()
	s.log.Info("ssh session opened", "user", st.user, "remote", remote)
	defer s.log.Info("ssh session closed", "user", st.user, "remote", remote)

	go ssh.DiscardRequests(reqs)
	var channels sync.WaitGroup
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		channels.Add(1)
		go func() {
			defer channels.Done()
			s.serveSession(nc, st)
		}()
	}
	channels.Wait()
}

// establish returns the session for a finished handshake. Password logins
// were checked in the password callback. Public-key logins are checked here,
// after the SSH layer has verified the signature, so the API only ever sees
// keys the client proved it holds.
func (s *Server) establish(ctx context.Context, sconn *ssh.ServerConn) (apiclient.Session, error) {
	perms := sconn.Permissions
	if perms == nil {
		return apiclient.Session{}, errPermissionDenied
	}
	if line := perms.Extensions[extPublicKey]; line != "" {
		lctx, cancel := context.WithTimeout(ctx, s.cfg.LoginTimeout)
		defer cancel()
		sess, err := s.api.Login(lctx, apiclient.LoginRequest{
			Username:   sconn.User(),
			PublicKey:  line,
			RemoteAddr: sconn.RemoteAddr().String(),
		})
		if err != nil {
			s.loginFailed(sconn.User(), sconn.RemoteAddr().String(), err)
			return apiclient.Session{}, errPermissionDenied
		}
		return sess, nil
	}
	sess, err := sessionFromExtensions(perms.Extensions)
	if err != nil {
		return apiclient.Session{}, errPermissionDenied
	}
	return sess, nil
}

// admit records an authenticated connection and enforces the per-user cap.
func (s *Server) admit(st *connState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perUser[st.key] >= s.cfg.MaxSessionsPerUser {
		return false
	}
	s.perUser[st.key]++
	s.tokens[st.sess.Token] = st
	return true
}

func (s *Server) release(st *connState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.perUser[st.key] - 1; n > 0 {
		s.perUser[st.key] = n
	} else {
		delete(s.perUser, st.key)
	}
	if s.tokens[st.sess.Token] == st {
		delete(s.tokens, st.sess.Token)
	}
}

func (s *Server) atLimit(user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perUser[strings.ToLower(user)] >= s.cfg.MaxSessionsPerUser
}

// passwordCallback logs the user in through the API. Its error is always the
// generic permission-denied error.
func (s *Server) passwordCallback(conn ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.LoginTimeout)
	defer cancel()
	sess, err := s.api.Login(ctx, apiclient.LoginRequest{
		Username:   conn.User(),
		Password:   string(pw),
		RemoteAddr: conn.RemoteAddr().String(),
	})
	if err != nil {
		s.loginFailed(conn.User(), conn.RemoteAddr().String(), err)
		return nil, errPermissionDenied
	}
	// Fast refusal for a user already at the cap. admit enforces it again
	// after the handshake, which is the authoritative check.
	if s.atLimit(sess.User) {
		s.metrics.login(loginLimit)
		s.log.Info("login refused", "user", sess.User, "remote", conn.RemoteAddr().String(), "result", loginLimit)
		return nil, errPermissionDenied
	}
	return &ssh.Permissions{Extensions: sessionExtensions(sess)}, nil
}

// publicKeyCallback only records the offered key. The SSH layer calls it
// before the signature is checked, so the API is not asked here; establish
// does that after the handshake.
func (s *Server) publicKeyCallback(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	return &ssh.Permissions{Extensions: map[string]string{extPublicKey: line}}, nil
}

func (s *Server) loginFailed(user, remote string, err error) {
	result := loginError
	if errors.Is(err, apiclient.ErrUnauthorized) || errors.Is(err, apiclient.ErrBusy) {
		result = loginDenied
	}
	s.metrics.login(result)
	s.log.Info("login refused", "user", user, "remote", remote, "result", result)
	s.log.Debug("login error", "user", user, "err", err)
}

// serveSession handles one session channel. Only one sftp subsystem may run
// per connection. shell and exec are refused and the channel is closed.
func (s *Server) serveSession(nc ssh.NewChannel, st *connState) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	var sftpDone sync.WaitGroup
	for req := range reqs {
		switch req.Type {
		case "subsystem":
			if name, ok := subsystemName(req.Payload); !ok || name != sftpSubsystem || !st.sftpStarted.CompareAndSwap(false, true) {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			sftpDone.Add(1)
			go func() {
				defer sftpDone.Done()
				s.serveSFTP(ch, st)
			}()
		case "shell", "exec":
			_ = req.Reply(false, nil)
			_ = ch.Close()
		default:
			// pty-req, env, x11-req, window-change, signal, auth-agent-req
			// and anything unknown: refused.
			_ = req.Reply(false, nil)
		}
	}
	sftpDone.Wait()
	_ = ch.Close()
}

func subsystemName(payload []byte) (string, bool) {
	var p struct{ Name string }
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return "", false
	}
	return p.Name, true
}

func (s *Server) serveSFTP(ch ssh.Channel, st *connState) {
	srv := sftp.NewRequestServer(ch, s.hf(st.sess, st.user))
	if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
		s.log.Debug("sftp subsystem ended", "user", st.user, "err", err)
	}
	_ = srv.Close()
}

// checkLoop asks the API every CheckInterval which session tokens were
// revoked and closes those connections.
func (s *Server) checkLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.CheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkOnce(ctx)
		}
	}
}

func (s *Server) checkOnce(ctx context.Context) {
	s.mu.Lock()
	tokens := make([]string, 0, len(s.tokens))
	for tok := range s.tokens {
		tokens = append(tokens, tok)
	}
	s.mu.Unlock()
	if len(tokens) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.LoginTimeout)
	defer cancel()
	revoked, err := s.api.CheckSessions(cctx, tokens)
	if err != nil {
		// Keep the connections. Failing open is not a revocation, and
		// closing on a transient API error would drop healthy users.
		s.log.Warn("session check failed; connections kept", "err", err)
		return
	}
	for _, tok := range revoked {
		s.mu.Lock()
		st := s.tokens[tok]
		s.mu.Unlock()
		if st == nil || !st.revoked.CompareAndSwap(false, true) {
			continue
		}
		s.log.Info("session revoked", "user", st.user)
		s.metrics.revoked()
		_ = st.sconn.Close()
	}
}

// deadlineConn pushes the connection deadline forward on every read and
// write. idle holds the timeout in nanoseconds; zero means no deadline.
type deadlineConn struct {
	net.Conn
	idle atomic.Int64
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	c.touch()
	return c.Conn.Read(p)
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	c.touch()
	return c.Write(p)
}

func (c *deadlineConn) touch() {
	if d := time.Duration(c.idle.Load()); d > 0 {
		_ = c.SetDeadline(time.Now().Add(d))
	}
}

// sessionExtensions carries a successful login through ssh.Permissions.
func sessionExtensions(sess apiclient.Session) map[string]string {
	ext := map[string]string{
		extSessionToken: sess.Token,
		extUser:         sess.User,
		extExpiresAt:    sess.ExpiresAt.Format(time.RFC3339),
	}
	if sess.Target != nil {
		ext[extNamespace] = sess.Target.Namespace
		ext[extServer] = sess.Target.Server
	}
	return ext
}

func sessionFromExtensions(ext map[string]string) (apiclient.Session, error) {
	tok := ext[extSessionToken]
	if tok == "" {
		return apiclient.Session{}, errors.New("sshserver: no session token")
	}
	expires, err := time.Parse(time.RFC3339, ext[extExpiresAt])
	if err != nil {
		return apiclient.Session{}, fmt.Errorf("sshserver: expiresAt: %w", err)
	}
	sess := apiclient.Session{Token: tok, ExpiresAt: expires, User: ext[extUser]}
	if ns := ext[extNamespace]; ns != "" {
		sess.Target = &apiclient.Target{Namespace: ns, Server: ext[extServer]}
	}
	return sess, nil
}
