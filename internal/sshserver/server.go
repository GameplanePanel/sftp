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
	defaultMaxPreAuth    = 64
	defaultMaxPreAuthIP  = 8
	defaultCheckInterval = 30 * time.Second
	defaultLoginTimeout  = 10 * time.Second
	defaultRevalidate    = 2 * time.Minute
	acceptRetryDelay     = 100 * time.Millisecond
	// maxSessionChannels caps the session channels one connection may hold
	// open at once: the SFTP channel plus one extra that is refused and
	// closed. Further channel opens are rejected before they are accepted,
	// so no goroutine or channel buffer is spent on them.
	maxSessionChannels = 2
	serverVersion      = "SSH-2.0-Gameplane-SFTP"
	maxAuthTries       = 3
	sftpSubsystem      = "sftp"

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
	// EndSession closes the API session a login created. The server calls it
	// when it drops a connection whose login succeeded at the API.
	EndSession(ctx context.Context, token string) error
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
	// MaxPreAuthConnections caps concurrent connections that have not yet
	// finished authentication. A connection over the cap is closed at once.
	// Default 64.
	MaxPreAuthConnections int
	// MaxPreAuthPerIP caps the connections one source IP may have before
	// authentication, so a single address cannot take every pre-auth slot.
	// A connection over the cap is closed at once. Default 8.
	MaxPreAuthPerIP int
	// CheckInterval is how often the server asks the API which of its
	// session tokens were revoked. Default 30s.
	CheckInterval time.Duration
	// LoginTimeout bounds each API call and the SSH handshake before
	// authentication completes, and how long an accepted session channel
	// may take to start the SFTP subsystem. Default 10s.
	LoginTimeout time.Duration
	// RevalidateWithin closes a connection whose session the API has not
	// confirmed as valid for this long, for example because every session
	// check failed. A connection is also closed once its session's known
	// expiry passes without a confirmation. Default 2m.
	RevalidateWithin time.Duration
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

	mu        sync.Mutex
	listener  net.Listener
	base      context.Context              // Serve's context; Background before Serve
	open      map[net.Conn]struct{}        // every accepted connection, until it ends
	tokens    map[string]*connState        // session token -> authenticated connection
	perUser   map[string]int               // lowercased user -> authenticated connections
	closing   bool                         // set once Serve's context ends
	preAuth   int                          // connections still before authentication
	preAuthIP map[string]int               // source IP -> connections still before authentication
	pending   map[string]apiclient.Session // remote address -> password login awaiting handshake end
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
		cfg:       cfg,
		api:       api,
		hf:        hf,
		log:       cfg.Logger,
		metrics:   cfg.Metrics,
		open:      make(map[net.Conn]struct{}),
		tokens:    make(map[string]*connState),
		perUser:   make(map[string]int),
		pending:   make(map[string]apiclient.Session),
		preAuthIP: make(map[string]int),
		base:      context.Background(),
	}
	sc := &ssh.ServerConfig{
		PasswordCallback:          s.passwordCallback,
		PublicKeyCallback:         s.publicKeyCallback,
		VerifiedPublicKeyCallback: s.verifiedPublicKeyCallback,
		MaxAuthTries:              maxAuthTries,
		ServerVersion:             serverVersion,
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
	if c.IdleTimeout < 0 || c.CheckInterval < 0 || c.LoginTimeout < 0 || c.RevalidateWithin < 0 {
		return c, errors.New("sshserver: negative timeout")
	}
	if c.MaxSessionsPerUser < 0 {
		return c, errors.New("sshserver: negative session cap")
	}
	if c.MaxPreAuthConnections < 0 || c.MaxPreAuthPerIP < 0 {
		return c, errors.New("sshserver: negative pre-auth connection cap")
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.MaxSessionsPerUser == 0 {
		c.MaxSessionsPerUser = defaultMaxSessions
	}
	if c.MaxPreAuthConnections == 0 {
		c.MaxPreAuthConnections = defaultMaxPreAuth
	}
	if c.MaxPreAuthPerIP == 0 {
		c.MaxPreAuthPerIP = defaultMaxPreAuthIP
	}
	if c.CheckInterval == 0 {
		c.CheckInterval = defaultCheckInterval
	}
	if c.LoginTimeout == 0 {
		c.LoginTimeout = defaultLoginTimeout
	}
	if c.RevalidateWithin == 0 {
		c.RevalidateWithin = defaultRevalidate
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
	s.base = ctx
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
		ip := sourceIP(raw.RemoteAddr())
		if !s.acquirePreAuth(ip) {
			s.untrack(raw)
			_ = raw.Close()
			s.metrics.preAuthRejected()
			s.log.Info("connection refused", "remote", raw.RemoteAddr().String(), "reason", "pre-auth cap")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(raw)
			s.handle(ctx, raw, sync.OnceFunc(func() { s.releasePreAuth(ip) }))
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

// acquirePreAuth takes one pre-authentication slot for source IP ip, or
// reports that the global or the per-IP cap is reached.
func (s *Server) acquirePreAuth(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preAuth >= s.cfg.MaxPreAuthConnections || s.preAuthIP[ip] >= s.cfg.MaxPreAuthPerIP {
		return false
	}
	s.preAuth++
	s.preAuthIP[ip]++
	return true
}

func (s *Server) releasePreAuth(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preAuth--
	if n := s.preAuthIP[ip] - 1; n > 0 {
		s.preAuthIP[ip] = n
	} else {
		delete(s.preAuthIP, ip)
	}
}

// sourceIP returns the IP part of a connection's remote address, or the whole
// address when it has no port.
func sourceIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// Revoke closes the connection that holds session token tok, as when the
// API reports it revoked. The file system calls it when the API refuses the
// session on a file request, so a revoked session does not wait for the next
// check. An unknown token is ignored.
func (s *Server) Revoke(tok string) {
	s.mu.Lock()
	st := s.tokens[tok]
	s.mu.Unlock()
	if st == nil || !st.revoked.CompareAndSwap(false, true) {
		return
	}
	s.log.Info("session refused by the API; connection closed", "user", st.user)
	s.metrics.revoked()
	_ = st.sconn.Close()
}

// endSession tells the API to close a session this server created but will
// not use. It keeps ctx's values but not its cancellation, so a shutdown
// does not skip it. A
// failure is only logged: the session still expires on its own.
func (s *Server) endSession(ctx context.Context, sess apiclient.Session) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.LoginTimeout)
	defer cancel()
	if err := s.api.EndSession(ctx, sess.Token); err != nil {
		s.log.Debug("end session failed", "user", sess.User, "err", err)
	}
}

func (s *Server) baseCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.base
}

func (s *Server) takePending(remote string) (apiclient.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.pending[remote]
	delete(s.pending, remote)
	return sess, ok
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
	channels    atomic.Int32 // session channels accepted and not yet finished
	// ttl is how long the API keeps the session valid without use, taken
	// from the expiry at login. validUntil (Unix nanoseconds) is the latest
	// time the session can still be valid without a new confirmation.
	ttl        time.Duration
	validUntil atomic.Int64
}

// confirm records that the API reported the session valid at t.
func (st *connState) confirm(t time.Time, within time.Duration) {
	st.validUntil.Store(t.Add(min(within, st.ttl)).UnixNano())
}

// handle runs one TCP connection from handshake to close. releasePreAuth
// frees the connection's pre-authentication slot; it is safe to call twice.
func (s *Server) handle(ctx context.Context, raw net.Conn, releasePreAuth func()) {
	defer releasePreAuth()
	remote := raw.RemoteAddr().String()
	dc := &deadlineConn{Conn: raw}
	dc.idle.Store(int64(s.cfg.LoginTimeout))
	// The handshake gets an absolute deadline, so a client that sends a byte
	// now and then cannot keep its pre-auth slot past LoginTimeout.
	dc.hard.Store(time.Now().Add(s.cfg.LoginTimeout).UnixNano())

	sconn, chans, reqs, err := ssh.NewServerConn(dc, s.sshCfg)
	// A password or public-key login already created an API session in its callback.
	pwSess, hasPW := s.takePending(remote)
	if err != nil {
		s.log.Debug("ssh handshake ended", "remote", remote, "err", err)
		_ = raw.Close()
		if hasPW {
			s.endSession(ctx, pwSess)
		}
		return
	}
	defer func() { _ = sconn.Close() }()

	dc.hard.Store(0)
	// The SSH mux is already blocked in a read whose deadline came from the
	// handshake. Push it out to the session's own timeout.
	dc.idle.Store(int64(max(s.cfg.IdleTimeout, s.cfg.LoginTimeout)))
	dc.touch()
	sess, err := s.establish(ctx, sconn, pwSess, hasPW)
	releasePreAuth()
	if err != nil {
		return
	}
	// Switch to the idle timeout now.
	dc.idle.Store(int64(s.cfg.IdleTimeout))
	dc.touch()

	now := time.Now()
	st := &connState{sconn: sconn, sess: sess, user: sess.User, key: strings.ToLower(sess.User), ttl: sess.ExpiresAt.Sub(now)}
	st.confirm(now, s.cfg.RevalidateWithin)
	if !s.admit(st) {
		s.endSession(ctx, sess)
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
		if st.channels.Add(1) > maxSessionChannels {
			st.channels.Add(-1)
			_ = nc.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}
		channels.Add(1)
		go func() {
			defer channels.Done()
			defer st.channels.Add(-1)
			s.serveSession(nc, st)
		}()
	}
	channels.Wait()
}

// establish returns the session for a finished handshake. Password and
// public-key logins were both checked with the API during authentication (the
// key only after the SSH layer verified its signature), and their session
// travels in the permissions.
func (s *Server) establish(ctx context.Context, sconn *ssh.ServerConn, pwSess apiclient.Session, hasPW bool) (apiclient.Session, error) {
	perms := sconn.Permissions
	if perms == nil {
		if hasPW {
			s.endSession(ctx, pwSess)
		}
		return apiclient.Session{}, errPermissionDenied
	}
	sess, err := sessionFromExtensions(perms.Extensions)
	if err == nil && !sess.ExpiresAt.After(time.Now()) {
		err = errors.New("sshserver: session already expired")
	}
	if err != nil {
		if hasPW {
			s.endSession(ctx, pwSess)
		}
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
	return s.loggedIn(conn, sess)
}

// loggedIn finishes a login the API accepted during authentication: it
// refuses a user already at the session cap and remembers the session until
// the handshake ends.
func (s *Server) loggedIn(conn ssh.ConnMetadata, sess apiclient.Session) (*ssh.Permissions, error) {
	// Fast refusal for a user already at the cap. admit enforces it again
	// after the handshake, which is the authoritative check.
	if s.atLimit(sess.User) {
		s.endSession(s.baseCtx(), sess)
		s.metrics.login(loginLimit)
		s.log.Info("login refused", "user", sess.User, "remote", conn.RemoteAddr().String(), "result", loginLimit)
		return nil, errPermissionDenied
	}
	// Remember the session until the handshake ends, so a connection dropped
	// before it is used can still end it.
	s.mu.Lock()
	s.pending[conn.RemoteAddr().String()] = sess
	s.mu.Unlock()
	return &ssh.Permissions{Extensions: sessionExtensions(sess)}, nil
}

// publicKeyCallback only records the offered key. The SSH layer calls it
// before the signature is checked, so the API is not asked here;
// verifiedPublicKeyCallback does that once the signature is verified.
func (s *Server) publicKeyCallback(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	return &ssh.Permissions{Extensions: map[string]string{extPublicKey: line}}, nil
}

// verifiedPublicKeyCallback logs the user in through the API with a key whose
// signature the SSH layer has verified. A key the API refuses fails only that
// authentication attempt, so the client goes on to its next key or to the
// password prompt instead of losing the connection.
func (s *Server) verifiedPublicKeyCallback(conn ssh.ConnMetadata, _ ssh.PublicKey, perms *ssh.Permissions, _ string) (*ssh.Permissions, error) {
	line := ""
	if perms != nil {
		line = perms.Extensions[extPublicKey]
	}
	if line == "" {
		return nil, errPermissionDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.LoginTimeout)
	defer cancel()
	sess, err := s.api.Login(ctx, apiclient.LoginRequest{
		Username:   conn.User(),
		PublicKey:  line,
		RemoteAddr: conn.RemoteAddr().String(),
	})
	if err != nil {
		s.loginFailed(conn.User(), conn.RemoteAddr().String(), err)
		return nil, errPermissionDenied
	}
	return s.loggedIn(conn, sess)
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
	// A channel must start the SFTP subsystem within LoginTimeout, or it is
	// closed. initState is 0 while waiting, 1 once a subsystem request won the
	// race, 2 once the deadline closed the channel.
	var initState atomic.Int32
	initTimer := time.AfterFunc(s.cfg.LoginTimeout, func() {
		if initState.CompareAndSwap(0, 2) {
			_ = ch.Close()
		}
	})
	defer initTimer.Stop()
	var sftpDone sync.WaitGroup
	// mine is set once this channel runs the connection's sftp subsystem.
	// While another channel runs it, this one is an extra: every request is
	// refused and the channel is closed right after, so it never sits idle.
	mine := false
	refuse := func(req *ssh.Request) {
		_ = req.Reply(false, nil)
		if !mine && st.sftpStarted.Load() {
			_ = ch.Close()
		}
	}
	for req := range reqs {
		switch req.Type {
		case "subsystem":
			if name, ok := subsystemName(req.Payload); !ok || name != sftpSubsystem || !initState.CompareAndSwap(0, 1) || !st.sftpStarted.CompareAndSwap(false, true) {
				refuse(req)
				continue
			}
			mine = true
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
			refuse(req)
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
	// The confirmation time is taken before the request, so a slow answer
	// never extends a session past what the API actually saw.
	asked := time.Now()
	cctx, cancel := context.WithTimeout(ctx, s.cfg.LoginTimeout)
	defer cancel()
	revoked, err := s.api.CheckSessions(cctx, tokens)
	if err != nil {
		// One failed check keeps the connections, so a short API blip does
		// not drop healthy users. A session left unconfirmed for
		// RevalidateWithin, or past its expiry, is closed by expireStale.
		s.log.Warn("session check failed", "err", err)
		s.expireStale(time.Now())
		return
	}
	gone := make(map[string]struct{}, len(revoked))
	for _, tok := range revoked {
		gone[tok] = struct{}{}
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
	s.mu.Lock()
	for _, tok := range tokens {
		if _, isGone := gone[tok]; isGone {
			continue
		}
		if st := s.tokens[tok]; st != nil {
			st.confirm(asked, s.cfg.RevalidateWithin)
		}
	}
	s.mu.Unlock()
	s.expireStale(time.Now())
}

// expireStale closes every connection whose session has not been confirmed
// by the API recently enough to still be valid (fail closed).
func (s *Server) expireStale(now time.Time) {
	s.mu.Lock()
	var stale []*connState
	for _, st := range s.tokens {
		if now.UnixNano() > st.validUntil.Load() {
			stale = append(stale, st)
		}
	}
	s.mu.Unlock()
	for _, st := range stale {
		if !st.revoked.CompareAndSwap(false, true) {
			continue
		}
		s.log.Info("session not confirmed by the API; connection closed", "user", st.user)
		s.metrics.unconfirmed()
		_ = st.sconn.Close()
	}
}

// deadlineConn pushes the connection deadline forward on every read and
// write. idle holds the timeout in nanoseconds; zero means no deadline. hard,
// when non-zero, is an absolute deadline (Unix nanoseconds) that a touch never
// moves past.
type deadlineConn struct {
	net.Conn
	idle atomic.Int64
	hard atomic.Int64
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	c.touch()
	return c.Conn.Read(p)
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	c.touch()
	return c.Conn.Write(p)
}

func (c *deadlineConn) touch() {
	var deadline time.Time
	if d := time.Duration(c.idle.Load()); d > 0 {
		deadline = time.Now().Add(d)
	}
	if h := c.hard.Load(); h != 0 {
		if hd := time.Unix(0, h); deadline.IsZero() || hd.Before(deadline) {
			deadline = hd
		}
	}
	if !deadline.IsZero() {
		_ = c.SetDeadline(deadline)
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
