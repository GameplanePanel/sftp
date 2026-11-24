package apiclient

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestNewRequiresHTTPSByDefault(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://gameplane-api.gameplane.svc"}); err == nil {
		t.Fatal("New accepted an http base URL without AllowInsecureHTTP")
	}
	c, err := New(Config{BaseURL: "http://gameplane-api.gameplane.svc", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("New with AllowInsecureHTTP: %v", err)
	}
	if c.baseURL != "http://gameplane-api.gameplane.svc" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

// A redirect from the API is never followed: the login body and the bearer
// token must not be re-sent to another URL.
func TestClientRefusesRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caPEM := filepath.Join(dir, "ca.pem")
	var bundle []byte
	for _, s := range []*httptest.Server{srv, target} {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})...)
	}
	if err := os.WriteFile(caPEM, bundle, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := New(Config{BaseURL: srv.URL, CAFile: caPEM, ServiceToken: testServiceToken})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := c.Login(ctx, LoginRequest{Username: "alice", Password: "pw"}); !errors.Is(err, ErrFailure) {
		t.Errorf("Login through a redirect = %v, want ErrFailure", err)
	}
	if _, err := c.Servers(ctx, "gpsftp_x"); !errors.Is(err, ErrFailure) {
		t.Errorf("Servers through a redirect = %v, want ErrFailure", err)
	}
	if _, err := c.Files("gpsftp_x", "", "survival").Download(ctx, "/a", 0); !errors.Is(err, ErrFailure) {
		t.Errorf("Download through a redirect = %v, want ErrFailure", err)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("redirect target received %d requests, want 0", n)
	}
}
