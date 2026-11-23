package main

import (
	"bytes"
	"errors"
	"testing"
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
	for _, args := range [][]string{nil, {"serve"}, {"version", "extra"}} {
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
