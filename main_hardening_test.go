package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeHostKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	p := filepath.Join(dir, "host_key")
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return p
}

func writeToken(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("gpsftps_test\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return p
}

func TestParseServeConfigAllowInsecureAPI(t *testing.T) {
	c, err := parseServeConfig(nil, envFunc(fullServeEnv()), io.Discard)
	if err != nil || c.AllowInsecureAPI {
		t.Fatalf("default = %v, %v; want false", c.AllowInsecureAPI, err)
	}
	c, err = parseServeConfig(nil, envFunc(withEnv(fullServeEnv(), envAllowInsecureAPI, "true")), io.Discard)
	if err != nil || !c.AllowInsecureAPI {
		t.Fatalf("env = %v, %v; want true", c.AllowInsecureAPI, err)
	}
	c, err = parseServeConfig([]string{"--allow-insecure-api=false"}, envFunc(withEnv(fullServeEnv(), envAllowInsecureAPI, "true")), io.Discard)
	if err != nil || c.AllowInsecureAPI {
		t.Fatalf("flag = %v, %v; want false", c.AllowInsecureAPI, err)
	}
	if _, err := parseServeConfig(nil, envFunc(withEnv(fullServeEnv(), envAllowInsecureAPI, "maybe")), io.Discard); err == nil {
		t.Fatal("bad boolean accepted")
	}
}

func TestParseServeConfigMaxPreAuthPerIP(t *testing.T) {
	c, err := parseServeConfig(nil, envFunc(fullServeEnv()), io.Discard)
	if err != nil || c.MaxPreAuthPerIP != defaultMaxPreAuthPerIP {
		t.Fatalf("default = %d, %v; want %d", c.MaxPreAuthPerIP, err, defaultMaxPreAuthPerIP)
	}
	c, err = parseServeConfig([]string{"--max-preauth-per-ip=3"}, envFunc(withEnv(fullServeEnv(), envMaxPreAuthPerIP, "5")), io.Discard)
	if err != nil || c.MaxPreAuthPerIP != 3 {
		t.Fatalf("flag = %d, %v; want 3", c.MaxPreAuthPerIP, err)
	}
	for _, v := range []string{"0", "lots"} {
		if _, err := parseServeConfig(nil, envFunc(withEnv(fullServeEnv(), envMaxPreAuthPerIP, v)), io.Discard); err == nil {
			t.Errorf("per-IP cap %q accepted", v)
		}
	}
}

func TestDefaultMetricsAddrIsLoopback(t *testing.T) {
	if !strings.HasPrefix(defaultMetricsAddr, "127.0.0.1:") {
		t.Fatalf("default metrics address %q is not loopback-only", defaultMetricsAddr)
	}
}

// serve refuses a plain-HTTP API URL unless it is explicitly allowed.
func TestServeRefusesHTTPAPIURL(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		envHostKey:     writeHostKey(t, dir),
		envAPIURL:      "http://api.example",
		envSvcAuthFile: writeToken(t, dir),
		envListen:      "127.0.0.1:0",
		envMetricsAddr: "",
	}
	var errOut bytes.Buffer
	err := runServe(nil, envFunc(env), &errOut)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("runServe with an http API URL = %v, want an https error", err)
	}
}
