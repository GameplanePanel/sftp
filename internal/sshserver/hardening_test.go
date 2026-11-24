package sshserver

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/ssh"
)

// A connection may hold at most maxSessionChannels session channels; one
// more is rejected before it is accepted.
func TestSessionChannelCapRejectsExtraChannels(t *testing.T) {
	h := newHarness(t, nil, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	for i := range maxSessionChannels {
		ch, reqs, err := c.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("channel %d: %v", i+1, err)
		}
		go ssh.DiscardRequests(reqs)
		t.Cleanup(func() { _ = ch.Close() })
	}
	_, _, err := c.OpenChannel("session", nil)
	var open *ssh.OpenChannelError
	if !errors.As(err, &open) || open.Reason != ssh.ResourceShortage {
		t.Fatalf("channel over the cap: err %v, want a ResourceShortage rejection", err)
	}
}

// A slot is freed when a channel ends, so a client can open a new one later.
func TestSessionChannelCapFreesSlots(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.LoginTimeout = 100 * time.Millisecond }, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	for range maxSessionChannels {
		_, reqs, err := c.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		go ssh.DiscardRequests(reqs)
	}
	// Both channels time out without starting SFTP and are closed, which
	// frees their slots.
	eventually(t, "a channel slot to be freed", func() bool {
		ch, reqs, err := c.OpenChannel("session", nil)
		if err != nil {
			return false
		}
		go ssh.DiscardRequests(reqs)
		_ = ch.Close()
		return true
	})
}

// A session channel that never asks for the SFTP subsystem is closed after
// LoginTimeout.
func TestSessionChannelWithoutSFTPIsClosed(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.LoginTimeout = 100 * time.Millisecond }, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	done := make(chan error, 1)
	go func() {
		_, err := ch.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read on an idle channel returned data, want the channel closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle session channel was not closed")
	}
}

// The SFTP subsystem started in time keeps working past LoginTimeout.
func TestSFTPChannelOutlivesInitDeadline(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.LoginTimeout = 100 * time.Millisecond }, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	sc, err := sftp.NewClient(c)
	if err != nil {
		t.Fatalf("sftp: %v", err)
	}
	defer func() { _ = sc.Close() }()
	time.Sleep(300 * time.Millisecond)
	if _, err := sc.ReadDir("/"); err != nil {
		t.Fatalf("sftp after the init deadline: %v", err)
	}
}

// When every session check fails, a connection is closed once the API has
// not confirmed its session for RevalidateWithin (fail closed).
func TestUnconfirmedSessionIsClosed(t *testing.T) {
	api := &fakeAPI{checkErr: errors.New("api down")}
	h := newHarness(t, func(c *Config) {
		c.CheckInterval = 20 * time.Millisecond
		c.RevalidateWithin = 150 * time.Millisecond
	}, api)
	c := h.mustDial("alice", ssh.Password("pw"))
	waitClosed(t, c)
	if got := testutil.ToFloat64(h.metrics.stale); got != 1 {
		t.Fatalf("unconfirmed_closed_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.revokes); got != 0 {
		t.Fatalf("revoked_total = %v, want 0", got)
	}
}

// Successful checks keep confirming the session, so the connection outlives
// RevalidateWithin.
func TestConfirmedSessionOutlivesRevalidateWindow(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.CheckInterval = 20 * time.Millisecond
		c.RevalidateWithin = 150 * time.Millisecond
	}, &fakeAPI{})
	c := h.mustDial("alice", ssh.Password("pw"))
	time.Sleep(500 * time.Millisecond)
	if err := readRoot(c); err != nil {
		t.Fatalf("connection dropped although every check succeeded: %v", err)
	}
	if got := testutil.ToFloat64(h.metrics.stale); got != 0 {
		t.Fatalf("unconfirmed_closed_total = %v, want 0", got)
	}
}

// A login whose session has already expired is refused.
func TestExpiredSessionAtLoginIsRefused(t *testing.T) {
	api := &fakeAPI{expiresIn: -time.Hour}
	h := newHarness(t, nil, api)
	// Authentication itself succeeds at the API; the server refuses the
	// expired session right after the handshake, so no SFTP is ever served.
	if c, err := h.dialErr("alice", ssh.Password("pw")); err == nil {
		defer func() { _ = c.Close() }()
		if err := readRoot(c); err == nil {
			t.Fatal("expired session served SFTP")
		}
	}
	// Either way the server ends the unused API session.
	eventually(t, "the expired session to be ended at the API", func() bool {
		return slices.Contains(api.endedTokens(), "gpsftp_test_1")
	})
	if got := testutil.ToFloat64(h.metrics.sessions); got != 0 {
		t.Fatalf("session gauge = %v, want 0", got)
	}
}

// Revoke closes the connection that holds the token at once.
func TestRevokeClosesConnection(t *testing.T) {
	api := &fakeAPI{}
	srv, err := New(Config{HostKeys: []ssh.Signer{newEd25519Signer(t)}, CheckInterval: time.Hour}, api, testHandlers)
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
		<-done
	})
	h := &harness{t: t, addr: l.Addr().String(), api: api}
	c := h.mustDial("alice", ssh.Password("pw"))
	if err := readRoot(c); err != nil {
		t.Fatalf("sftp: %v", err)
	}
	srv.Revoke("gpsftp_unknown") // unknown tokens are ignored
	srv.Revoke("gpsftp_test_1")
	waitClosed(t, c)
}

// One source IP may hold at most MaxPreAuthPerIP connections before
// authentication; the next one is closed at once.
func TestPreAuthPerIPCap(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxPreAuthPerIP = 1 }, &fakeAPI{})
	first := rawBanner(t, h.addr)
	second, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := second.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if n, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("over-cap connection read %d bytes, err %v; want it closed", n, err)
	}
	_ = first.Close()
	eventually(t, "the per-IP slot to be freed", func() bool {
		c, err := h.dialErr("alice", ssh.Password("pw"))
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
}

func TestNegativeRevalidateAndPerIPCapAreRefused(t *testing.T) {
	key := newEd25519Signer(t)
	for name, cfg := range map[string]Config{
		"revalidate": {HostKeys: []ssh.Signer{key}, RevalidateWithin: -time.Second},
		"per ip":     {HostKeys: []ssh.Signer{key}, MaxPreAuthPerIP: -1},
	} {
		if _, err := New(cfg, &fakeAPI{}, testHandlers); err == nil {
			t.Errorf("%s: New accepted a negative value", name)
		}
	}
}

func TestSourceIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7:51234":  "203.0.113.7",
		"[2001:db8::1]:2222": "2001:db8::1",
	} {
		addr, err := net.ResolveTCPAddr("tcp", in)
		if err != nil {
			t.Fatalf("resolve %s: %v", in, err)
		}
		if got := sourceIP(addr); got != want {
			t.Errorf("sourceIP(%s) = %q, want %q", in, got, want)
		}
	}
	if got := sourceIP(nil); got != "" {
		t.Errorf("sourceIP(nil) = %q", got)
	}
	if got := sourceIP(&net.UnixAddr{Name: "sock", Net: "unix"}); got != "sock" {
		t.Errorf("sourceIP(unix) = %q", got)
	}
}
