package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out); err != nil {
		t.Fatalf("run version: %v", err)
	}
	if got := out.String(); got != Version+"\n" {
		t.Fatalf("version output = %q, want %q", got, Version+"\n")
	}
}

func TestRunRejectsUnknownSubcommands(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"version", "extra"}} {
		if err := run(args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Fatalf("run(%q) = %v, want errUsage", args, err)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestRunVersionWriteError(t *testing.T) {
	if err := run([]string{"version"}, failingWriter{}); err == nil {
		t.Fatal("want an error when the output cannot be written")
	}
}

func TestExitCode(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := exitCode([]string{"version"}, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("exitCode(version) = %d, stderr %q", code, errOut.String())
	}
	out.Reset()
	if code := exitCode([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("exitCode(bogus) = %d, want 2", code)
	}
	if got := errOut.String(); got != errUsage.Error()+"\n" {
		t.Fatalf("stderr = %q, want usage", got)
	}
}

func TestExitCodeServeWithoutRequiredFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := exitCode([]string{"serve"}, &out, &errOut); code != 2 {
		t.Fatalf("exitCode(serve) = %d, want 2", code)
	}
	if errOut.Len() == 0 {
		t.Fatal("no error printed for serve without required flags")
	}
}

func fullServeEnv() map[string]string {
	return map[string]string{
		envHostKey:          "/keys",
		envAPIURL:           "https://api.example",
		envServiceTokenFile: "/token",
	}
}

func envFunc(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestParseServeConfigDefaults(t *testing.T) {
	c, err := parseServeConfig(nil, envFunc(fullServeEnv()), io.Discard)
	if err != nil {
		t.Fatalf("parseServeConfig: %v", err)
	}
	if c.Listen != defaultListen || c.IdleTimeout != defaultIdleTimeout ||
		c.MaxSessionsPerUser != defaultMaxSessionsPerUser || c.MaxTransfersPerUser != defaultMaxTransfersPerUser ||
		c.MetricsAddr != defaultMetricsAddr || c.HostKeyPath != "/keys" || c.APIURL != "https://api.example" ||
		c.ServiceTokenFile != "/token" || c.CAFile != "" {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestParseServeConfigEnvAndFlagPrecedence(t *testing.T) {
	env := fullServeEnv()
	env[envIdleTimeout] = "3m"
	env[envMaxSessionsPerUser] = "7"
	env[envMaxTransfersPerUser] = "9"
	env[envListen] = ":4000"
	env[envMetricsAddr] = ":9999"
	c, err := parseServeConfig(nil, envFunc(env), io.Discard)
	if err != nil {
		t.Fatalf("env: %v", err)
	}
	if c.IdleTimeout != 3*time.Minute || c.MaxSessionsPerUser != 7 || c.MaxTransfersPerUser != 9 ||
		c.Listen != ":4000" || c.MetricsAddr != ":9999" {
		t.Fatalf("env values = %+v", c)
	}
	c, err = parseServeConfig([]string{
		"--idle-timeout", "1m", "--max-sessions-per-user", "2", "--max-transfers-per-user", "3",
		"--listen", ":5000", "--metrics-addr", "", "--ca-file", "/ca.pem",
	}, envFunc(env), io.Discard)
	if err != nil {
		t.Fatalf("flags: %v", err)
	}
	if c.IdleTimeout != time.Minute || c.MaxSessionsPerUser != 2 || c.MaxTransfersPerUser != 3 ||
		c.Listen != ":5000" || c.MetricsAddr != "" || c.CAFile != "/ca.pem" {
		t.Fatalf("flag values = %+v", c)
	}
}

func TestParseServeConfigRejectsBadInput(t *testing.T) {
	cases := map[string]struct {
		args []string
		env  map[string]string
	}{
		"missing host key":  {nil, map[string]string{envAPIURL: "x", envServiceTokenFile: "y"}},
		"missing api url":   {nil, map[string]string{envHostKey: "x", envServiceTokenFile: "y"}},
		"missing token":     {nil, map[string]string{envHostKey: "x", envAPIURL: "y"}},
		"bad idle env":      {nil, withEnv(fullServeEnv(), envIdleTimeout, "soon")},
		"bad sessions env":  {nil, withEnv(fullServeEnv(), envMaxSessionsPerUser, "many")},
		"bad transfers env": {nil, withEnv(fullServeEnv(), envMaxTransfersPerUser, "x")},
		"zero idle":         {[]string{"--idle-timeout", "0"}, fullServeEnv()},
		"zero sessions":     {[]string{"--max-sessions-per-user", "0"}, fullServeEnv()},
		"zero transfers":    {[]string{"--max-transfers-per-user", "0"}, fullServeEnv()},
		"unknown flag":      {[]string{"--nope"}, fullServeEnv()},
		"extra argument":    {[]string{"extra"}, fullServeEnv()},
	}
	for name, tc := range cases {
		if _, err := parseServeConfig(tc.args, envFunc(tc.env), io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func withEnv(env map[string]string, k, v string) map[string]string {
	env[k] = v
	return env
}

func TestParseServeConfigDefaultNamespace(t *testing.T) {
	c, err := parseServeConfig(nil, envFunc(fullServeEnv()), io.Discard)
	if err != nil || c.DefaultNamespace != "gameplane-games" {
		t.Fatalf("default namespace = %q, %v; want gameplane-games", c.DefaultNamespace, err)
	}
	env := fullServeEnv()
	env[envDefaultNamespace] = "from-env"
	c, err = parseServeConfig(nil, envFunc(env), io.Discard)
	if err != nil || c.DefaultNamespace != "from-env" {
		t.Fatalf("env namespace = %q, %v", c.DefaultNamespace, err)
	}
	c, err = parseServeConfig([]string{"--default-namespace", "from-flag"}, envFunc(env), io.Discard)
	if err != nil || c.DefaultNamespace != "from-flag" {
		t.Fatalf("flag namespace = %q, %v", c.DefaultNamespace, err)
	}
}
