package vfs

import (
	"errors"
	"testing"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// A server the API marks read-only refuses an upload when the file is opened,
// and refuses mkdir, before any change reaches the API. A writable server and
// one without a write decision still accept writes.
func TestReadOnlyServerRefusesWritesAtOpen(t *testing.T) {
	no, yes := false, true
	servers := []apiclient.ServerRef{
		{Namespace: testNS, Server: "survival", Write: &no},
		{Namespace: testNS, Server: "creative", Write: &yes},
		{Namespace: otherNS, Server: "modded"},
	}
	fx := newFixture(t, nil, Options{}, servers)

	if _, err := fx.fs.Filewrite(openReq("/survival/denied.txt", fxfWrite|fxfCreat|fxfTrunc)); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("open for write on read-only server: err = %v, want permission denied", err)
	}
	if err := fx.fs.Filecmd(opReq("Mkdir", "/survival/denied")); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("mkdir on read-only server: err = %v, want permission denied", err)
	}
	if fx.api.has(testNS, "survival", "/denied.txt") || fx.api.has(testNS, "survival", "/denied") {
		t.Fatalf("read-only server changed")
	}
	if got := fx.api.snapshot().streamQueries; len(got) != 0 {
		t.Fatalf("read-only open reached the stream route: %v", got)
	}

	for _, p := range []string{"/creative/ok.txt", "/_namespaces/" + otherNS + "/modded/ok.txt"} {
		w, err := fx.fs.Filewrite(openReq(p, fxfWrite|fxfCreat|fxfTrunc))
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		closeOrFail(t, w)
	}
}

// A per-server login reads the same decision from the inventory.
func TestTargetLoginReadOnlyRefusesWritesAtOpen(t *testing.T) {
	no := false
	servers := []apiclient.ServerRef{{Namespace: testNS, Server: "survival", Write: &no}}
	fx := newFixture(t, &apiclient.Target{Namespace: testNS, Server: "survival"}, Options{}, servers)
	if _, err := fx.fs.Filewrite(openReq("/denied.txt", fxfWrite|fxfCreat|fxfTrunc)); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("target login open for write: err = %v, want permission denied", err)
	}
}
