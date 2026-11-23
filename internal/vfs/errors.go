package vfs

import (
	"context"
	"errors"
	"fmt"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// statusErrors lists the SFTP status errors that pass through toSFTP
// unchanged. Anything else coming out of the API client is mapped.
var statusErrors = []error{
	sftp.ErrSSHFxEOF,
	sftp.ErrSSHFxNoSuchFile,
	sftp.ErrSSHFxPermissionDenied,
	sftp.ErrSSHFxFailure,
	sftp.ErrSSHFxBadMessage,
	sftp.ErrSSHFxConnectionLost,
	sftp.ErrSSHFxOpUnsupported,
}

// toSFTP maps an error from the API client or the context to the SFTP status
// the client sees. Messages are fixed strings so no URL, token or body text
// reaches the client; the real error is logged by the caller at debug level.
func toSFTP(err error) error {
	if err == nil {
		return nil
	}
	for _, s := range statusErrors {
		if errors.Is(err, s) {
			return err
		}
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return sftp.ErrSSHFxConnectionLost
	case errors.Is(err, apiclient.ErrNotFound):
		return sftp.ErrSSHFxNoSuchFile
	case errors.Is(err, apiclient.ErrPermission),
		errors.Is(err, apiclient.ErrUnauthorized),
		errors.Is(err, apiclient.ErrBadRequest):
		return sftp.ErrSSHFxPermissionDenied
	case errors.Is(err, apiclient.ErrExists):
		return failure("file exists")
	case errors.Is(err, apiclient.ErrNoSpace):
		return failure("no space left on server")
	case errors.Is(err, apiclient.ErrTooLarge):
		return failure("file too large")
	case errors.Is(err, apiclient.ErrBadOffset):
		return failure("bad offset")
	case errors.Is(err, apiclient.ErrBusy):
		return failure("server busy, try again")
	case errors.Is(err, apiclient.ErrUnavailable):
		return failure("server not available, try again")
	default:
		return sftp.ErrSSHFxFailure
	}
}

// failure returns a generic failure status carrying msg. pkg/sftp sends the
// error text to the client, so msg must be a fixed, non-sensitive string.
func failure(msg string) error {
	return fmt.Errorf("%s: %w", msg, sftp.ErrSSHFxFailure)
}

// fail maps err for the client and logs the original at debug level. op names
// the operation for the log line only.
func (f *FS) fail(op string, err error) error {
	if err == nil {
		return nil
	}
	f.log.Debug("sftp operation failed", "op", op, "user", f.user, "err", err.Error())
	return toSFTP(err)
}
