// Package apiclient is the sftp service's only path to the Gameplane API. It
// logs SFTP users in, checks which session tokens are still valid, lists the
// servers a session may reach and performs file operations as that session.
// It never talks to game pods directly; the API owns authorisation and the
// agent round trip.
package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors. Every failure from the API maps to exactly one of these
// through errors.Is; the wrapping *Error carries the HTTP status and body text.
var (
	ErrNotFound     = errors.New("not found")
	ErrPermission   = errors.New("permission denied")
	ErrExists       = errors.New("already exists")
	ErrNoSpace      = errors.New("no space left")
	ErrTooLarge     = errors.New("file too large")
	ErrUnauthorized = errors.New("unauthorized")
	ErrBadRequest   = errors.New("bad request")
	ErrBadOffset    = errors.New("bad offset")
	ErrBusy         = errors.New("busy: rate limited")
	ErrUnavailable  = errors.New("unavailable")
	ErrFailure      = errors.New("operation failed")
)

const (
	defaultTimeout   = 30 * time.Second
	defaultUserAgent = "gameplane-sftp"
	maxErrorBody     = 1024
	maxMessageLen    = 256
	maxCheckTokens   = 500
	maxLoginBody     = 1 << 20
	maxListBody      = 64 << 20
)

// Error is a failed API call. Err is the sentinel for the failure class and
// Status is the HTTP status, or zero when no response was received.
type Error struct {
	Status int
	Op     string
	Msg    string
	Err    error
}

// Error implements error.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("apiclient: ")
	b.WriteString(e.Op)
	b.WriteString(": ")
	if e.Err != nil {
		b.WriteString(e.Err.Error())
	} else {
		b.WriteString("error")
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " (HTTP %d)", e.Status)
	}
	if e.Msg != "" {
		b.WriteString(": ")
		b.WriteString(e.Msg)
	}
	return b.String()
}

// Unwrap returns the sentinel so errors.Is works on the failure class.
func (e *Error) Unwrap() error { return e.Err }

// Config configures a Client.
type Config struct {
	// BaseURL is the API origin, for example https://gameplane-api.gameplane.svc:8080.
	// A trailing slash is trimmed. It must use https unless AllowInsecureHTTP
	// is set.
	BaseURL string
	// AllowInsecureHTTP lets New accept an http:// BaseURL. The service token,
	// passwords and session tokens then cross the network in clear text, so
	// set it only when the hop never leaves a trusted network, such as the
	// pod network between the SFTP pod and the API Service of one cluster.
	AllowInsecureHTTP bool
	// ServiceToken is the contents of the service token file, trimmed. It is
	// used only for Login and CheckSessions.
	ServiceToken string
	// CAFile is an optional PEM bundle appended to the system roots.
	CAFile string
}

// Client talks to the Gameplane API. It is safe for concurrent use.
type Client struct {
	baseURL      string
	serviceToken string
	userAgent    string
	hc           *http.Client // bounded by Timeout
	streamHC     *http.Client // no overall timeout; context only
}

// New builds a Client with a TLS 1.2+ transport that verifies the API's
// certificate. BaseURL must be https unless AllowInsecureHTTP is set. CAFile,
// when set, must hold at least one PEM certificate. Redirects are never
// followed: a redirected request fails, so credentials are never re-sent to
// another URL.
func New(cfg Config) (*Client, error) {
	base, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if u, _ := url.Parse(base); u.Scheme == "http" && !cfg.AllowInsecureHTTP {
		return nil, errors.New("apiclient: base URL must use https (http needs AllowInsecureHTTP)")
	}
	pool, err := loadCAPool(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: defaultTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}
	// Streaming calls (Download and Stream) use the second client and are
	// bounded by their context only.
	hc := &http.Client{Transport: tr, Timeout: defaultTimeout, CheckRedirect: refuseRedirect}
	stream := &http.Client{Transport: tr, CheckRedirect: refuseRedirect}
	return newClient(base, cfg, hc, stream), nil
}

// NewWithHTTPClient builds a Client that sends every request through hc. It
// is meant for tests; CAFile in cfg is ignored because hc owns
// TLS and timeouts.
func NewWithHTTPClient(cfg Config, hc *http.Client) (*Client, error) {
	base, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if hc == nil {
		return nil, errors.New("apiclient: nil http client")
	}
	return newClient(base, cfg, hc, hc), nil
}

// LoadServiceToken reads the service token file and returns its trimmed
// contents. An empty file is an error.
func LoadServiceToken(path string) (string, error) {
	data, err := readConfigFile(path)
	if err != nil {
		return "", fmt.Errorf("read service token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("service token file is empty")
	}
	return token, nil
}

func newClient(base string, cfg Config, hc, stream *http.Client) *Client {
	return &Client{
		baseURL:      base,
		serviceToken: strings.TrimSpace(cfg.ServiceToken),
		userAgent:    defaultUserAgent,
		hc:           hc,
		streamHC:     stream,
	}
}

// refuseRedirect stops the client at the first redirect and returns the 3xx
// response, which maps to ErrFailure. Following it would re-send the login
// body (password or key) and the bearer token to wherever the API pointed.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func validateBaseURL(raw string) (string, error) {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("apiclient: parse base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("apiclient: base URL must use http or https")
	}
	if u.Host == "" {
		return "", errors.New("apiclient: base URL has no host")
	}
	return s, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("apiclient: read CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("apiclient: CA file contains no PEM certificates")
	}
	return pool, nil
}

// readConfigFile reads an operator-supplied file (a mounted secret or config
// map). It goes through os.Root so the read stays inside the file's directory:
// a path cannot escape with ".." or a symlink that leaves that directory.
func readConfigFile(path string) ([]byte, error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return data, nil
}

// LoginRequest is one SFTP login attempt. Exactly one of Password or PublicKey
// must be set; the API rejects anything else with a generic 401.
type LoginRequest struct {
	// Username is the full SSH username, including any "+target" suffix.
	Username string `json:"username"`
	// Password is the plaintext password, when password auth is used.
	Password string `json:"password,omitempty"`
	// PublicKey is an authorized_keys line, when public-key auth is used.
	PublicKey string `json:"publicKey,omitempty"`
	// RemoteAddr is the client's address, for example "203.0.113.7:51234".
	RemoteAddr string `json:"remoteAddr"`
}

// Target names the server a session is bound to.
type Target struct {
	Namespace string `json:"namespace"`
	Server    string `json:"server"`
}

// Session is a successful login.
type Session struct {
	Token     string
	ExpiresAt time.Time
	User      string
	// Target is nil when the login did not name a server.
	Target *Target
}

type loginResponse struct {
	SessionToken string  `json:"sessionToken"`
	ExpiresAt    string  `json:"expiresAt"`
	User         string  `json:"user"`
	Target       *Target `json:"target"`
}

// Login exchanges a login attempt for a session token. It uses the service
// token. A 401 maps to ErrUnauthorized and a 429 to ErrBusy.
func (c *Client) Login(ctx context.Context, r LoginRequest) (Session, error) {
	if c.serviceToken == "" {
		return Session{}, &Error{Op: "login", Msg: "service token not configured", Err: ErrUnauthorized}
	}
	var resp loginResponse
	if err := c.callJSON(ctx, "login", http.MethodPost, "/sftp/v1/login", c.serviceToken, nil, r, &resp, maxLoginBody); err != nil {
		return Session{}, err
	}
	if resp.SessionToken == "" {
		return Session{}, &Error{Op: "login", Msg: "response has no session token", Err: ErrFailure}
	}
	expires, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		return Session{}, &Error{Op: "login", Msg: "invalid expiresAt", Err: ErrFailure}
	}
	return Session{Token: resp.SessionToken, ExpiresAt: expires, User: resp.User, Target: resp.Target}, nil
}

// CheckSessions returns the tokens the API no longer accepts. It sends at
// most 500 tokens per request and uses the service token. An empty input
// makes no request.
func (c *Client) CheckSessions(ctx context.Context, tokens []string) ([]string, error) {
	var revoked []string
	for start := 0; start < len(tokens); start += maxCheckTokens {
		end := min(start+maxCheckTokens, len(tokens))
		in := struct {
			SessionTokens []string `json:"sessionTokens"`
		}{SessionTokens: tokens[start:end]}
		var out struct {
			Revoked []string `json:"revoked"`
		}
		if c.serviceToken == "" {
			return nil, &Error{Op: "sessions check", Msg: "service token not configured", Err: ErrUnauthorized}
		}
		if err := c.callJSON(ctx, "sessions check", http.MethodPost, "/sftp/v1/sessions/check", c.serviceToken, nil, in, &out, maxListBody); err != nil {
			return nil, err
		}
		revoked = append(revoked, out.Revoked...)
	}
	return revoked, nil
}

// EndSession asks the API to close one session, identified by its token. The
// server calls it for a login it created but will not use, so the session does
// not stay open until it expires. It uses the service token.
func (c *Client) EndSession(ctx context.Context, token string) error {
	if token == "" {
		return &Error{Op: "sessions end", Msg: "no session token", Err: ErrBadRequest}
	}
	if c.serviceToken == "" {
		return &Error{Op: "sessions end", Msg: "service token not configured", Err: ErrUnauthorized}
	}
	in := struct {
		SessionTokens []string `json:"sessionTokens"`
	}{SessionTokens: []string{token}}
	return c.exec(ctx, "sessions end", http.MethodPost, "/sftp/v1/sessions/end", c.serviceToken, nil, in)
}

// ServerRef is one server a session may reach.
type ServerRef struct {
	Namespace string `json:"namespace"`
	Server    string `json:"server"`
	// Write is the API's write decision for this server. Nil (an API that
	// does not send it) leaves the decision to the API at commit time.
	Write *bool `json:"write,omitempty"`
}

// ReadOnly reports whether the API said the session may not change files on
// this server.
func (s ServerRef) ReadOnly() bool { return s.Write != nil && !*s.Write }

// Servers lists the servers the session may reach.
func (c *Client) Servers(ctx context.Context, sessionToken string) ([]ServerRef, error) {
	if sessionToken == "" {
		return nil, &Error{Op: "servers", Msg: "no session token", Err: ErrUnauthorized}
	}
	var out struct {
		Items []ServerRef `json:"items"`
	}
	if err := c.callJSON(ctx, "servers", http.MethodGet, "/sftp/v1/servers", sessionToken, nil, nil, &out, maxListBody); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Entry is one file or directory reported by the agent.
type Entry struct {
	Name    string
	Path    string
	Size    int64
	Mode    string // os.FileMode.String() form, for example "drwxr-xr-x"
	Dir     bool
	ModTime time.Time // zero when the API sent an unparseable time
}

// UnmarshalJSON decodes an Entry and tolerates a bad modTime.
func (e *Entry) UnmarshalJSON(b []byte) error {
	var raw struct {
		Name    string `json:"name"`
		Path    string `json:"path"`
		Size    int64  `json:"size"`
		Mode    string `json:"mode"`
		Dir     bool   `json:"dir"`
		ModTime string `json:"modTime"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	e.Name = raw.Name
	e.Path = raw.Path
	e.Size = raw.Size
	e.Mode = raw.Mode
	e.Dir = raw.Dir
	e.ModTime = time.Time{}
	if t, err := time.Parse(time.RFC3339, raw.ModTime); err == nil {
		e.ModTime = t
	}
	return nil
}

// permBits maps the nine rwx characters of a FileMode string, in order, to
// their permission bits.
var permBits = [9]os.FileMode{0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001}

// FileMode converts the Mode string back to an os.FileMode. Unknown type
// characters are ignored.
func (e Entry) FileMode() os.FileMode {
	var mode os.FileMode
	s := e.Mode
	if len(s) > 0 {
		switch s[0] {
		case 'd':
			mode |= os.ModeDir
		case 'L':
			mode |= os.ModeSymlink
		case 'p':
			mode |= os.ModeNamedPipe
		case 'S':
			mode |= os.ModeSocket
		case 'D':
			mode |= os.ModeDevice
		case 'c':
			mode |= os.ModeCharDevice
		case 'u':
			mode |= os.ModeSetuid
		case 'g':
			mode |= os.ModeSetgid
		case 't':
			mode |= os.ModeSticky
		}
	}
	if len(s) >= 10 {
		for i, bit := range permBits {
			if s[i+1] != '-' {
				mode |= bit
			}
		}
	}
	return mode
}

// Files performs file operations for one session on one server. The zero
// namespace means the API's default namespace.
type Files struct {
	c         *Client
	token     string
	namespace string
	server    string
}

// Files returns a file API bound to a session token, namespace and server.
func (c *Client) Files(token, namespace, server string) *Files {
	return &Files{c: c, token: token, namespace: namespace, server: server}
}

func (f *Files) endpoint(op string) string {
	return "/servers/" + url.PathEscape(f.server) + "/files/" + op
}

// query adds the namespace, when set, to q and returns it.
func (f *Files) query(q url.Values) url.Values {
	if q == nil {
		q = url.Values{}
	}
	if f.namespace != "" {
		q.Set("namespace", f.namespace)
	}
	return q
}

// List returns the entries of a directory.
func (f *Files) List(ctx context.Context, path string) ([]Entry, error) {
	var out []Entry
	q := f.query(url.Values{"path": {path}})
	if err := f.c.callJSON(ctx, "list", http.MethodGet, f.endpoint("list"), f.token, q, nil, &out, maxListBody); err != nil {
		return nil, err
	}
	return out, nil
}

// Stat returns one entry. A missing path maps to ErrNotFound.
func (f *Files) Stat(ctx context.Context, path string) (Entry, error) {
	var out Entry
	q := f.query(url.Values{"path": {path}})
	if err := f.c.callJSON(ctx, "stat", http.MethodGet, f.endpoint("stat"), f.token, q, nil, &out, maxListBody); err != nil {
		return Entry{}, err
	}
	return out, nil
}

// Download returns the file body from offset onward. The caller closes it.
// An offset at or past the end maps to ErrBadOffset. A server that ignores
// the Range header is handled by discarding the first offset bytes.
func (f *Files) Download(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, &Error{Op: "download", Msg: "negative offset", Err: ErrBadOffset}
	}
	h := http.Header{}
	if offset > 0 {
		h.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	resp, err := f.c.send(ctx, call{
		op:       "download",
		method:   http.MethodGet,
		endpoint: f.endpoint("download"),
		token:    f.token,
		query:    f.query(url.Values{"path": {path}}),
		header:   h,
		hc:       f.c.streamHC,
		length:   -1,
	})
	if err != nil {
		return nil, err
	}
	if offset > 0 && resp.StatusCode == http.StatusOK {
		if _, err := io.CopyN(io.Discard, resp.Body, offset); err != nil {
			_ = resp.Body.Close()
			return nil, &Error{Op: "download", Status: resp.StatusCode, Msg: "body shorter than offset", Err: ErrFailure}
		}
	}
	return resp.Body, nil
}

// plainReader hides any Len or Seek method so net/http does not infer a
// content length from the body. Stream sets the length explicitly.
type plainReader struct{ r io.Reader }

func (p plainReader) Read(b []byte) (int, error) { return p.r.Read(b) }

// Stream replaces the file from offset onward with body. offset 0 creates or
// replaces the file. A negative contentLength means the length is unknown and
// the body is sent chunked.
func (f *Files) Stream(ctx context.Context, path string, offset int64, body io.Reader, contentLength int64) error {
	if offset < 0 {
		return &Error{Op: "stream", Msg: "negative offset", Err: ErrBadOffset}
	}
	length := int64(-1)
	if contentLength >= 0 {
		length = contentLength
	}
	q := f.query(url.Values{"path": {path}, "offset": {strconv.FormatInt(offset, 10)}})
	resp, err := f.c.send(ctx, call{
		op:          "stream",
		method:      http.MethodPut,
		endpoint:    f.endpoint("stream"),
		token:       f.token,
		query:       q,
		body:        plainReader{r: body},
		length:      length,
		contentType: "application/octet-stream",
		hc:          f.c.streamHC,
	})
	if err != nil {
		return err
	}
	return drainClose(resp)
}

// Rename moves from to to. overwrite replaces an existing target; without it
// an existing target maps to ErrExists.
func (f *Files) Rename(ctx context.Context, from, to string, overwrite bool) error {
	in := struct {
		From      string `json:"from"`
		To        string `json:"to"`
		Overwrite bool   `json:"overwrite"`
	}{From: from, To: to, Overwrite: overwrite}
	return f.c.exec(ctx, "rename", http.MethodPost, f.endpoint("rename"), f.token, f.query(nil), in)
}

// Mkdir creates a directory and its parents. An existing directory is not an
// error.
func (f *Files) Mkdir(ctx context.Context, path string) error {
	return f.c.exec(ctx, "mkdir", http.MethodPost, f.endpoint("mkdir"), f.token, f.query(url.Values{"path": {path}}), nil)
}

// Delete removes one file or an empty directory. It never recurses.
func (f *Files) Delete(ctx context.Context, path string) error {
	return f.c.exec(ctx, "delete", http.MethodDelete, f.endpoint("delete"), f.token, f.query(url.Values{"path": {path}}), nil)
}

// call describes one HTTP request.
type call struct {
	op          string
	method      string
	endpoint    string
	token       string
	query       url.Values
	header      http.Header
	body        io.Reader
	length      int64 // with a body: exact length, or -1 for chunked
	contentType string
	hc          *http.Client
}

// send performs the request. It returns the response only for a 2xx status;
// any other status becomes an *Error and the body is consumed.
func (c *Client) send(ctx context.Context, cl call) (*http.Response, error) {
	u := c.baseURL + cl.endpoint
	if len(cl.query) > 0 {
		u += "?" + cl.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, cl.method, u, cl.body)
	if err != nil {
		return nil, fmt.Errorf("apiclient: %s: build request: %w", cl.op, err)
	}
	if cl.body != nil {
		req.ContentLength = cl.length
	}
	req.Header.Set("User-Agent", c.userAgent)
	if cl.token != "" {
		req.Header.Set("Authorization", "Bearer "+cl.token)
	}
	if cl.contentType != "" {
		req.Header.Set("Content-Type", cl.contentType)
	}
	for k, vs := range cl.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := cl.hc.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("apiclient: %s: %w", cl.op, ctxErr)
		}
		return nil, &Error{Op: cl.op, Msg: err.Error(), Err: ErrUnavailable}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
	return nil, &Error{
		Status: resp.StatusCode,
		Op:     cl.op,
		Msg:    trimMessage(snippet),
		Err:    statusSentinel(resp.StatusCode),
	}
}

// callJSON sends a request, optionally with a JSON body, and decodes a JSON
// response into out when out is not nil.
func (c *Client) callJSON(ctx context.Context, op, method, endpoint, token string, q url.Values, in, out any, limit int64) error {
	var body io.Reader
	length := int64(-1)
	contentType := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("apiclient: %s: encode request: %w", op, err)
		}
		body = bytes.NewReader(b)
		length = int64(len(b))
		contentType = "application/json"
	}
	resp, err := c.send(ctx, call{
		op:          op,
		method:      method,
		endpoint:    endpoint,
		token:       token,
		query:       q,
		body:        body,
		length:      length,
		contentType: contentType,
		hc:          c.hc,
	})
	if err != nil {
		return err
	}
	if out == nil {
		return drainClose(resp)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(out); err != nil {
		return &Error{Op: op, Status: resp.StatusCode, Msg: "invalid response body", Err: ErrFailure}
	}
	return nil
}

// exec sends a request whose response body is not used.
func (c *Client) exec(ctx context.Context, op, method, endpoint, token string, q url.Values, in any) error {
	if in == nil {
		resp, err := c.send(ctx, call{op: op, method: method, endpoint: endpoint, token: token, query: q, hc: c.hc})
		if err != nil {
			return err
		}
		return drainClose(resp)
	}
	return c.callJSON(ctx, op, method, endpoint, token, q, in, nil, 0)
}

// drainClose discards a small part of the body and closes it so the
// connection can be reused.
func drainClose(resp *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	return resp.Body.Close()
}

// statusSentinel maps a non-2xx HTTP status to its failure class.
func statusSentinel(code int) error {
	switch code {
	case http.StatusBadRequest:
		return ErrBadRequest
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrPermission
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrExists
	case http.StatusRequestEntityTooLarge:
		return ErrTooLarge
	case http.StatusRequestedRangeNotSatisfiable:
		return ErrBadOffset
	case http.StatusTooManyRequests:
		return ErrBusy
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return ErrUnavailable
	case http.StatusInsufficientStorage:
		return ErrNoSpace
	default:
		return ErrFailure
	}
}

// trimMessage returns the body as a short, valid UTF-8 message.
func trimMessage(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > maxMessageLen {
		s = s[:maxMessageLen]
	}
	return strings.ToValidUTF8(s, "")
}
