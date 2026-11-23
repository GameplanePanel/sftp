package vfs

import (
	"context"
	"errors"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/pkg/sftp"
)

// Filelist serves List (directory listing) and Stat requests. Readlink is not
// supported.
func (f *FS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	ctx := r.Context()
	switch r.Method {
	case "List":
		loc, err := f.resolve(ctx, r.Filepath)
		if err != nil {
			return nil, err
		}
		infos, err := f.listLocation(ctx, loc)
		if err != nil {
			return nil, err
		}
		return infosToLister(infos), nil
	case "Stat":
		return f.stat(ctx, r.Filepath)
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

// Lstat answers Lstat requests. Symlinks are reported as themselves, which is
// what the API's stat does.
func (f *FS) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return f.stat(r.Context(), r.Filepath)
}

// stat returns a one-entry lister for p.
func (f *FS) stat(ctx context.Context, p string) (sftp.ListerAt, error) {
	loc, err := f.resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	info, err := f.statLocation(ctx, loc)
	if err != nil {
		return nil, err
	}
	return listerAt{info}, nil
}

// Filecmd handles Setstat, Rename, Mkdir, Rmdir and Remove. Link, Symlink and
// Readlink are refused.
func (f *FS) Filecmd(r *sftp.Request) error {
	ctx := r.Context()
	switch r.Method {
	case "Setstat":
		return f.setstat(ctx, r)
	case "Rename":
		return f.rename(ctx, r.Filepath, r.Target, false)
	case "Mkdir":
		return f.mkdir(ctx, r.Filepath)
	case "Rmdir":
		return f.rmdir(ctx, r.Filepath)
	case "Remove":
		return f.remove(ctx, r.Filepath)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

// PosixRename implements sftp.PosixRenameFileCmder. The POSIX extension
// replaces an existing target.
func (f *FS) PosixRename(r *sftp.Request) error {
	return f.rename(r.Context(), r.Filepath, r.Target, true)
}

// setstat accepts mode and time changes as no-ops, after checking the path
// exists. Owner changes are refused, and so is truncation through attributes.
func (f *FS) setstat(ctx context.Context, r *sftp.Request) error {
	loc, err := f.resolve(ctx, r.Filepath)
	if err != nil {
		return err
	}
	flags := r.AttrFlags()
	if flags.UidGid {
		return sftp.ErrSSHFxPermissionDenied
	}
	if flags.Size {
		return sftp.ErrSSHFxOpUnsupported
	}
	if loc.virtual() {
		return nil
	}
	if _, err := f.filesFor(loc).Stat(ctx, loc.rest); err != nil {
		return f.fail("setstat", err)
	}
	return nil
}

// rename moves from to to inside one server. Virtual nodes and the server root
// are refused, and so is a move between servers.
func (f *FS) rename(ctx context.Context, from, to string, overwrite bool) error {
	src, err := f.resolveWrite(ctx, from)
	if err != nil {
		return err
	}
	dst, err := f.resolveWrite(ctx, to)
	if err != nil {
		return err
	}
	if !src.sameServer(dst) {
		return sftp.ErrSSHFxOpUnsupported
	}
	return f.fail("rename", f.filesFor(src).Rename(ctx, src.rest, dst.rest, overwrite))
}

// mkdir creates a directory. An existing path, file or directory, is an error.
func (f *FS) mkdir(ctx context.Context, p string) error {
	loc, err := f.resolveWrite(ctx, p)
	if err != nil {
		return err
	}
	files := f.filesFor(loc)
	_, err = files.Stat(ctx, loc.rest)
	switch {
	case err == nil:
		return failure("file exists")
	case !errors.Is(err, apiclient.ErrNotFound):
		return f.fail("mkdir", err)
	}
	return f.fail("mkdir", files.Mkdir(ctx, loc.rest))
}

// rmdir removes an empty directory. A non-empty directory fails, because the
// API delete is never recursive.
func (f *FS) rmdir(ctx context.Context, p string) error {
	loc, err := f.resolveWrite(ctx, p)
	if err != nil {
		return err
	}
	files := f.filesFor(loc)
	e, err := files.Stat(ctx, loc.rest)
	if err != nil {
		return f.fail("rmdir", err)
	}
	if !e.Dir {
		return failure("not a directory")
	}
	return f.fail("rmdir", files.Delete(ctx, loc.rest))
}

// remove deletes a file. A directory is refused; use Rmdir for those.
func (f *FS) remove(ctx context.Context, p string) error {
	loc, err := f.resolveWrite(ctx, p)
	if err != nil {
		return err
	}
	files := f.filesFor(loc)
	e, err := files.Stat(ctx, loc.rest)
	if err != nil {
		return f.fail("remove", err)
	}
	if e.Dir {
		return failure("is a directory")
	}
	return f.fail("remove", files.Delete(ctx, loc.rest))
}
