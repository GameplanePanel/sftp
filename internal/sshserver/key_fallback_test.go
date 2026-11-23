package sshserver

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
)

// keyRefusingAPI refuses every public-key login and accepts passwords, like a
// user whose client offers a key that is not registered in the panel.
type keyRefusingAPI struct{ fakeAPI }

func (k *keyRefusingAPI) Login(ctx context.Context, r apiclient.LoginRequest) (apiclient.Session, error) {
	if r.PublicKey != "" {
		k.mu.Lock()
		k.logins = append(k.logins, r)
		k.mu.Unlock()
		return apiclient.Session{}, apiclient.ErrUnauthorized
	}
	return k.fakeAPI.Login(ctx, r)
}

// A key the API refuses fails only that authentication attempt: the client
// goes on to the password and the session works. Before, the SSH layer
// accepted the key, the API refused it after the handshake and the server
// closed the connection, so OpenSSH never asked for the password.
func TestRefusedKeyFallsBackToPassword(t *testing.T) {
	api := &keyRefusingAPI{}
	srv, err := New(Config{
		HostKeys:      []ssh.Signer{newEd25519Signer(t)},
		CheckInterval: time.Hour,
		Logger:        slog.New(slog.DiscardHandler),
	}, api, testHandlers)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
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

	c, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User:            "valgul",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newEd25519Signer(t)), ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with an unregistered key then a password: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := readRoot(c); err != nil {
		t.Fatalf("sftp after password fallback: %v", err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.logins) != 2 || api.logins[0].PublicKey == "" || api.logins[1].Password != "pw" {
		t.Fatalf("logins = %+v, want the key refused, then the password", api.logins)
	}
}
