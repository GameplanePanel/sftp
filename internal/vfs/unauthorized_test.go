package vfs

import (
	"errors"
	"testing"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// A 401 from the API on a file request reports the session as refused, so
// the server can close the connection at once. Other errors do not.
func TestFailReportsUnauthorized(t *testing.T) {
	calls := 0
	f := New(nil, apiclient.Session{Token: testToken, User: "alice"}, Options{OnUnauthorized: func() { calls++ }})
	if err := f.fail("list", &apiclient.Error{Op: "list", Status: 404, Err: apiclient.ErrNotFound}); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("not found mapped to %v", err)
	}
	if calls != 0 {
		t.Fatalf("OnUnauthorized called %d times for a 404", calls)
	}
	if err := f.fail("list", &apiclient.Error{Op: "list", Status: 401, Err: apiclient.ErrUnauthorized}); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("unauthorized mapped to %v", err)
	}
	if calls != 1 {
		t.Fatalf("OnUnauthorized called %d times for a 401, want 1", calls)
	}
	// Without a hook a 401 is only mapped.
	if err := New(nil, apiclient.Session{Token: testToken}, Options{}).fail("list", apiclient.ErrUnauthorized); !errors.Is(err, sftp.ErrSSHFxPermissionDenied) {
		t.Fatalf("unauthorized without hook mapped to %v", err)
	}
}
